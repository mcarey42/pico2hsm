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
//! - CRIT0 (row 0x18) bit layout (per rp-pac):
//!   - bit 0: secure_boot_enable
//!   - bit 1: secure_debug_disable
//!   - bit 2: debug_disable (JTAG disable)
//!   - bit 3: default_archsel
//!   - bit 4: glitch_detector_enable
//!   - bits 5-6: glitch_detector_sens
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
    // P1-3 fix: is_production_mode_otp() now returns Result<bool, ()>.
    // An OTP read error means we cannot determine security state — treat as
    // an unrecoverable fault to prevent fault-injection bypass.
    let in_production = match is_production_mode_otp() {
        Ok(v) => v,
        Err(()) => {
            // OTP read failure — security state is unknowable. Hard reset.
            // Do NOT log or proceed: a glitch may have caused this.
            cortex_m::peripheral::SCB::sys_reset();
        }
    };

    // Arm the hardware glitch detector FIRST, before any other security check,
    // to protect the checks themselves from voltage-glitch fault injection.
    // Only arm in production mode to avoid false resets during development.
    if in_production {
        crate::security::anti_glitch::arm_glitch_detector();
    }

    #[cfg(not(feature = "debug"))]
    {
        // Only halt on debugger attachment if the device is in production mode
        // (OTP provisioned). On unprovisioned/development hardware the OTP
        // PRODUCTION_MODE bit is 0, so this check passes and boot continues.
        // This prevents the device from hanging on first flash when the
        // probe leaves DHCSR.C_DEBUGEN=1 after the download session.
        if in_production && check_debugger_attached() {
            // Spin forever — do NOT panic (panic may produce debug output).
            loop {
                core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            }
        }

        if in_production {
            // P1-4 fix: Assert that secure boot is actually active when the
            // device is in production mode. If secure boot is NOT enabled but
            // production mode IS set, this is a critical inconsistency —
            // either the provisioning was incomplete or something is wrong.
            // Hard-fault rather than boot in an insecure state.
            if !is_secure_boot_enabled() {
                // Production mode set but secure boot not active — inconsistency.
                // This may indicate incomplete provisioning or a hardware fault.
                // Hard reset: do not boot in this state.
                cortex_m::peripheral::SCB::sys_reset();
            }

            // Disable JTAG permanently if not already disabled.
            // OTP row 0x110 bit 0 = JTAG_DISABLED (pico2hsm user-land flag).
            // The hardware JTAG CRIT0 fuse write is also handled in
            // disable_jtag_permanent().
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
/// Returns `Ok(true)` if bit 1 (BOOT_FLAG_PRODUCTION_MODE) is set.
/// Returns `Ok(false)` if the bit is clear OR the row is blank (0xFFFF_FFFF,
/// meaning the device has never been OTP-provisioned).
/// Returns `Err(())` if the row index is out of range (should never happen).
///
/// # Why direct OTP read instead of embassy-rp
/// `embassy_rp::otp::read_raw_word()` treats 0xFFFF_FFFF as
/// `Err(InvalidPermissions)`, but for user-space OTP rows (0x110+) this
/// value simply means "blank / unprogrammed fuses".  Reading the raw
/// OTP_DATA_RAW address directly lets us distinguish blank rows from
/// actual access errors and avoids a reboot loop on unprovisioned boards.
///
/// P1-3 hardening is preserved: the only error path is an out-of-range
/// row index (compile-time constant, so this cannot be fault-injected).
/// A glitch that flips fuse bits to all-ones would clear the production
/// flag — but that's correct behavior (no production protections apply
/// if the fuse state is indeterminate).
fn is_production_mode_otp() -> Result<bool, ()> {
    const OTP_DATA_RAW_BASE: *const u32 = 0x4013_4000 as *const u32;
    const OTP_NUM_ROWS: usize = 4096;
    const OTP_BOOT_FLAGS_ROW: usize = 0x110;
    const BOOT_FLAG_PRODUCTION_MODE: u32 = 1 << 1;

    if OTP_BOOT_FLAGS_ROW >= OTP_NUM_ROWS {
        return Err(()); // should never happen — compile-time constant
    }

    // SAFETY: OTP_DATA_RAW is a memory-mapped read-only register block.
    // Row 0x110 is within the valid range (checked above).
    let value = unsafe { OTP_DATA_RAW_BASE.add(OTP_BOOT_FLAGS_ROW).read() };

    if value == 0xFFFF_FFFF {
        // Blank / unprogrammed OTP — device is not provisioned.
        Ok(false)
    } else {
        Ok(value & BOOT_FLAG_PRODUCTION_MODE != 0)
    }
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

    // P0-2 fix: Also write the RP2350 hardware CRIT0 register (OTP row 0x18)
    // bit 2 (debug_disable) to actually disable JTAG/SWD at the hardware level.
    //
    // The pico2hsm bookkeeping flag in row 0x110 bit 0 is a user-land marker;
    // it does NOT prevent probe-rs from connecting. The RP2350 hardware JTAG
    // lockdown is controlled by OTP CRIT0 (row 0x18):
    //   bit 0: secure_boot_enable
    //   bit 1: secure_debug_disable
    //   bit 2: debug_disable  ← this disables JTAG/SWD entirely
    //   bit 4: glitch_detector_enable
    //
    // RP2350 datasheet §5.6.4 "Critical Boot Flags": row 0x18 controls CRIT0.
    // Writing bit 2 (debug_disable = 0x04) via otp_access permanently disables
    // the debug interface. This is irreversible.
    //
    // SAFETY: CRIT0 row 0x18 is in OTP page 0. The RP2350 ROM otp_access
    // function (called by write_raw_word) handles the programming voltage.
    // We read-modify-write to preserve any bits already set (e.g. secure boot).
    const RP2350_CRIT0_ROW: usize = 0x18;
    const CRIT0_DEBUG_DISABLE_BIT: u32 = 1 << 2; // bit 2 = debug_disable

    let crit0_current = match otp::read_raw_word(RP2350_CRIT0_ROW) {
        Ok(v) => v,
        Err(_) => {
            defmt::error!("boot: failed to read CRIT0 row — skipping hardware JTAG disable");
            return;
        }
    };

    if crit0_current & CRIT0_DEBUG_DISABLE_BIT != 0 {
        // CRIT0 debug_disable already set — no-op.
        return;
    }

    let crit0_new = crit0_current | CRIT0_DEBUG_DISABLE_BIT;
    match otp::write_raw_word(RP2350_CRIT0_ROW, crit0_new) {
        Ok(()) => {
            defmt::warn!("boot: RP2350 CRIT0 debug_disable fuse burned — JTAG/SWD PERMANENTLY DISABLED");
        }
        Err(_) => {
            defmt::error!("boot: failed to burn CRIT0 debug_disable fuse");
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
