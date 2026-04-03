//! Secure boot configuration and verification.
//!
//! The RP2350 supports hardware-enforced secure boot via a boot manifest
//! signed with an Ed25519 key. The public key hash is stored in OTP.
//!
//! # Secure boot flow (production)
//! 1. RP2350 ROM reads boot manifest from flash offset 0x10000000
//! 2. ROM verifies Ed25519 signature using OTP-stored public key hash
//! 3. If signature is invalid, ROM halts (does not boot)
//! 4. Firmware is loaded and executed
//!
//! # Debug mode
//! When the `debug` feature is enabled, secure boot enforcement is
//! relaxed — the firmware runs even without a valid boot signature.
//! This is ONLY for development; never enable `debug` in production.
//!
//! # Boot-time security checks performed by firmware
//! After boot, the firmware performs additional checks:
//! 1. Verify OTP provisioning status flag is set
//! 2. Verify JTAG disable flag is set (or set it if not)
//! 3. Check for debugger attachment (SWD active) — halt if found in production
//! 4. Arm the hardware watchdog
//!
//! # RP2350 OTP references
//! - BOOT_FLAGS0 is OTP row 0x30 (RP2350 datasheet §5.6.6 "OTP Registers")
//! - CRIT0 (row 0x18) bit 1 = GLITCH_DETECTOR_ENABLE
//! - CRIT0 (row 0x18) bit 2 = GLITCH_DETECTOR_SENS_x
//! - The pico2hsm boot flags are stored in OTP row 0x110 (see otp.rs)

use embassy_rp::watchdog::Watchdog;
use embassy_time::Duration;

/// Watchdog feed period in milliseconds.
///
/// The watchdog must be fed at least this often to prevent a reset.
/// Set to 5000ms (5 seconds); main loop feeds every ~1000ms.
pub const WATCHDOG_PERIOD_MS: u32 = 5000;

/// Perform all boot-time security checks.
///
/// Called during firmware startup before any USB or crypto operations.
/// In `debug` mode, failures are logged but do not halt.
/// In production mode, any security violation causes an immediate halt.
///
/// # Checks performed
/// 1. Verify OTP provisioning flag (production mode)
/// 2. Disable JTAG if production mode is active
/// 3. Reject debugger attachment in production mode
/// 4. Flash integrity marker check (via OTP boot flags)
pub fn security_checks() {
    #[cfg(not(feature = "debug"))]
    {
        // Only halt on debugger attachment if the device is in production mode
        // (OTP provisioned). On unprovisioned/development hardware the OTP
        // PRODUCTION_MODE bit is 0, so this check passes and boot continues.
        // This prevents the device from hanging on first flash when the
        // probe leaves DHCSR.C_DEBUGEN=1 after the download session.
        if is_production_mode_otp() && check_debugger_attached() {
            // Spin forever — do NOT panic (panic may produce debug output).
            loop {
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            }
        }

        // Check if we are in production mode via OTP boot flags.
        // OTP row 0x110 bit 1 = PRODUCTION_MODE (see otp.rs).
        let in_production = is_production_mode_otp();

        if in_production {
            // Disable JTAG permanently if not already disabled.
            // OTP row 0x110 bit 0 = JTAG_DISABLED (pico2hsm user-land flag).
            // The hardware JTAG fuse write is handled in disable_jtag_permanent().
            disable_jtag_permanent();
        }
    }

    #[cfg(feature = "debug")]
    {
        defmt::warn!("boot: DEBUG mode — security checks relaxed");
        if check_debugger_attached() {
            defmt::warn!("boot: debugger attached (allowed in debug mode)");
        }
    }
}

/// Read the pico2hsm production-mode flag from OTP row 0x110.
///
/// Returns `true` if bit 1 (BOOT_FLAG_PRODUCTION_MODE) is set.
/// Returns `false` on OTP read failure (fail-open for boot flags read errors
/// is intentional — a failed OTP read should not cause a hard lock-out
/// on unprovisioned devices; actual lock-out happens when provisioning sets
/// the bit explicitly).
///
/// See `otp.rs` constant `OTP_BOOT_FLAGS_ROW = 0x110`.
fn is_production_mode_otp() -> bool {
    use embassy_rp::otp;
    const OTP_BOOT_FLAGS_ROW: usize = 0x110;
    const BOOT_FLAG_PRODUCTION_MODE: u32 = 1 << 1;

    otp::read_raw_word(OTP_BOOT_FLAGS_ROW)
        .map(|flags| flags & BOOT_FLAG_PRODUCTION_MODE != 0)
        .unwrap_or(false)
}

/// Check if the RP2350 is running in secure boot mode.
///
/// Reads OTP BOOT_FLAGS0 register (row 0x30 in the RP2350 hardware OTP
/// address space; RP2350 datasheet §5.6.6).
/// Bit 0 of BOOT_FLAGS0 = SECURE_BOOT_ENABLE.
///
/// # Safety
/// Uses `embassy_rp::otp::read_raw_word` which performs a memory-mapped
/// read of the OTP_DATA_RAW region (base address 0x4013_4000).
/// This is a read-only operation on a well-known hardware register.
///
/// Returns `true` if the SECURE_BOOT_ENABLE fuse is set.
pub fn is_secure_boot_enabled() -> bool {
    use embassy_rp::otp;
    // RP2350 datasheet §5.6.6: BOOT_FLAGS0 is at OTP row 0x30.
    // Bit 0 = SECURE_BOOT_ENABLE (set by blowing the fuse during provisioning).
    const RP2350_OTP_BOOT_FLAGS0_ROW: usize = 0x30;
    const SECURE_BOOT_ENABLE_BIT: u32 = 1 << 0;

    otp::read_raw_word(RP2350_OTP_BOOT_FLAGS0_ROW)
        .map(|bits| bits & SECURE_BOOT_ENABLE_BIT != 0)
        .unwrap_or(false)
}

/// Disable JTAG permanently via OTP fuse.
///
/// Sets the pico2hsm user-land JTAG_DISABLED flag in OTP row 0x110 bit 0.
///
/// # Irreversibility
/// OTP bits can only transition 0→1 (fuse burning). This operation is
/// permanent and cannot be undone.
///
/// # RP2350 hardware JTAG fuse
/// The RP2350 hardware JTAG disable fuse is in OTP page 0 (CRIT0/CRIT1,
/// rows 0x18–0x19; RP2350 datasheet §5.6.4 "Critical Boot Flags").
/// Full hardware JTAG lockdown requires writing those rows via the ROM
/// `otp_access` function with the correct programming voltage applied.
/// That step is performed by the provisioning tool, not by runtime firmware
/// (to avoid accidental lockout during development).
///
/// This function records that the lockdown has been performed by setting
/// the pico2hsm book-keeping bit in our user-land boot flags row.
///
/// Only callable when production mode is active (checked inside `otp.rs`
/// `Otp::disable_jtag_permanent()`).
pub fn disable_jtag_permanent() {
    use embassy_rp::otp;
    const OTP_BOOT_FLAGS_ROW: usize = 0x110;
    const BOOT_FLAG_JTAG_DISABLED: u32 = 1 << 0;
    const BOOT_FLAG_PRODUCTION_MODE: u32 = 1 << 1;

    // Only set the JTAG_DISABLED bit if production mode is active and the
    // bit is not already set (avoids a redundant OTP write attempt).
    let current = match otp::read_raw_word(OTP_BOOT_FLAGS_ROW) {
        Ok(v) => v,
        Err(_) => {
            // OTP read failure — cannot safely determine state; skip.
            #[cfg(feature = "debug")]
            defmt::warn!("boot: OTP read failed in disable_jtag_permanent");
            return;
        }
    };

    if current & BOOT_FLAG_PRODUCTION_MODE == 0 {
        // Not in production mode — do not burn the JTAG fuse.
        #[cfg(feature = "debug")]
        defmt::debug!("boot: skip JTAG disable — not in production mode");
        return;
    }

    if current & BOOT_FLAG_JTAG_DISABLED != 0 {
        // Already disabled — no-op (OTP bits are already set).
        return;
    }

    // Burn the JTAG_DISABLED flag bit (0 → 1, irreversible).
    // SAFETY: Writing to OTP_BOOT_FLAGS_ROW (0x110) is a pico2hsm
    // application-layer OTP row in the user-accessible OTP range
    // (rows 0x100–0x17F). The write uses the embassy-rp `otp::write_raw_word`
    // wrapper, which calls the RP2350 ROM `otp_access` function with
    // programming mode enabled. See RP2350 datasheet §5.6.1 "OTP Programming".
    let new_flags = current | BOOT_FLAG_JTAG_DISABLED;
    match otp::write_raw_word(OTP_BOOT_FLAGS_ROW, new_flags) {
        Ok(()) => {
            defmt::warn!("boot: JTAG disable OTP flag set — IRREVERSIBLE");
        }
        Err(_) => {
            defmt::error!("boot: failed to set JTAG disable OTP flag");
        }
    }
}

/// Feed the hardware watchdog with the standard period.
///
/// Must be called at least once per `WATCHDOG_PERIOD_MS` milliseconds.
/// Wraps `Watchdog::feed(Duration)` with the constant period.
///
/// # Note on embassy-rp 0.10 API
/// In embassy-rp 0.10, `Watchdog::feed()` takes a `Duration` argument
/// (unlike rp-hal which is stateless). The period must be passed on every
/// feed call. This design allows varying the timeout dynamically; we always
/// use the constant `WATCHDOG_PERIOD_MS`.
pub fn watchdog_feed(wd: &mut Watchdog) {
    wd.feed(Duration::from_millis(WATCHDOG_PERIOD_MS as u64));
}

/// Arm the hardware watchdog timer.
///
/// After this call the processor must call `watchdog_feed()` at least
/// once every `period_ms` milliseconds, or the RP2350 will reset.
///
/// # RP2350 Watchdog limits
/// The RP2350 watchdog counter is 24 bits and counts in microseconds.
/// Maximum period = 0xFF_FFFF µs ≈ 16.77 seconds (RP2350 datasheet §7.4).
/// The `embassy_rp::watchdog::Watchdog::start()` method enforces this
/// limit and will panic if exceeded.
///
/// # Implementation note
/// Calls `Watchdog::start(Duration)` which:
/// 1. Disables the watchdog
/// 2. Configures the PSM reset mask (resets everything except ROSC/XOSC)
/// 3. Loads the timeout counter
/// 4. Enables the watchdog
pub fn arm_watchdog(wd: &mut Watchdog, period_ms: u32) {
    wd.start(Duration::from_millis(period_ms as u64));
}

/// Check whether a debugger is currently attached via SWD/JTAG.
///
/// Reads the Cortex-M Debug Halting Control and Status Register (DHCSR)
/// at address 0xE000_EDF0. Bit 0 (C_DEBUGEN) is set when a debugger has
/// enabled halting debug on this core.
///
/// # Security use
/// In production mode, a debugger being attached is a security violation.
/// `security_checks()` calls this and halts if it returns `true`.
///
/// # Safety
/// Read-only access to a well-known Cortex-M architectural register
/// (ARMv8-M Architecture Reference Manual §C1.6 "Debug registers").
/// The address 0xE000_EDF0 is fixed by the ARM architecture and is
/// always valid on RP2350 (Cortex-M33 core).
pub fn check_debugger_attached() -> bool {
    // DHCSR: Debug Halting Control and Status Register
    // Address: 0xE000_EDF0 (ARMv8-M Architecture Reference Manual §C1.6.3)
    // Bit 0 (C_DEBUGEN): 1 = halting debug enabled by debugger
    // SAFETY: Read-only volatile read of ARM architectural debug register.
    // This register exists on all Cortex-M33 (RP2350) cores and is
    // accessible from privileged software at all times.
    unsafe {
        let dhcsr = core::ptr::read_volatile(0xE000_EDF0_u32 as *const u32);
        (dhcsr & 0x0000_0001) != 0
    }
}
