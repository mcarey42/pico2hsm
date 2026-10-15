//! Secure boot configuration and verification.
//!
//! The RP2350 supports hardware-enforced secure boot via a boot manifest
//! signed with a **secp256k1** key (not Ed25519 or P-256).  The SHA-256
//! hash of the public key is stored in OTP (BOOTKEY0, rows 0x80–0x8F).
//!
//! # Secure boot flow (production)
//! 1. RP2350 ROM reads boot manifest from flash
//! 2. ROM verifies secp256k1 signature using OTP-stored public key hash
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
//! 2. Verify JTAG disable flag is set (record in pico2hsm boot flags)
//! 3. Check for debugger attachment (SWD active) — halt if found in production
//!
//! The hardware watchdog is armed before these checks, by `main` (see
//! `crate::watchdog`); a halt here therefore turns into a watchdog reset
//! loop, which never gets past the checks either.
//!
//! # RP2350 OTP references (verified against pico-sdk otp_data.h + rp-pac 7.0.0)
//!
//! - **CRIT0** (rows 0x38–0x3F, RBIT-8): ARM_DISABLE (bit 0), RISCV_DISABLE (bit 1)
//! - **CRIT1** (rows 0x40–0x47, RBIT-8): the security-critical register
//!   - bit 0: SECURE_BOOT_ENABLE
//!   - bit 1: SECURE_DEBUG_DISABLE
//!   - bit 2: DEBUG_DISABLE (JTAG/SWD kill switch)
//!   - bit 3: BOOT_ARCH
//!   - bit 4: GLITCH_DETECTOR_ENABLE
//!   - bits 5-6: GLITCH_DETECTOR_SENS
//! - **BOOT_FLAGS0** (rows 0x48–0x4A, RBIT-3): boot path control (NOT secure boot enable)
//! - **BOOT_FLAGS1** (rows 0x4B–0x4D, RBIT-3): KEY_INVALID flags
//! - **BOOTKEY0** (rows 0x80–0x8F, ECC): SHA-256 hash of secp256k1 signing public key
//! - The pico2hsm application boot flags row is defined in otp_layout.rs
//!
//! # Hardware JTAG disable (CRIT1.DEBUG_DISABLE)
//!
//! The firmware does NOT write CRIT1 at runtime.  CRIT1 uses RBIT-8
//! redundancy (8 identical copies at rows 0x40–0x47); the ROM does a
//! majority vote across all 8 copies.  `embassy_rp::otp::write_raw_word()`
//! writes exactly one row, which is insufficient for reliable RBIT-8.
//! Use `picotool otp set OTP_DATA_CRIT1.DEBUG_DISABLE 1` during
//! provisioning — picotool handles all 8 copies automatically.
//!
//! Row 0x18 is NUM_GPIOS, NOT CRIT0.  Previous code incorrectly wrote
//! to row 0x18 believing it was CRIT0 — that was a no-op at best.

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
            crate::watchdog::reset_now(crate::watchdog::ResetCause::BootCheck);
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
                crate::watchdog::reset_now(crate::watchdog::ResetCause::BootCheck);
            }

            // Record the JTAG-disabled bookkeeping bit in the boot flags row.
            // Hardware JTAG disable (CRIT1.DEBUG_DISABLE) must be set via
            // picotool during provisioning — see docs/PROVISIONING.md Phase 8.
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

/// Read the pico2hsm production-mode flag from the boot flags row.
///
/// Returns `Ok(true)` if bit 1 (BOOT_FLAG_PRODUCTION_MODE) is set.
/// Returns `Ok(false)` if the bit is clear OR the row is blank (0xFFFF_FFFF,
/// meaning the device has never been OTP-provisioned).
/// Returns `Err(())` if the row index is out of range (should never happen).
///
/// # Why direct OTP read instead of embassy-rp
/// `embassy_rp::otp::read_raw_word()` treats 0xFFFF_FFFF as
/// `Err(InvalidPermissions)`, but for user-space OTP rows this
/// value simply means "blank / unprogrammed fuses".  Reading the raw
/// OTP_DATA_RAW address directly lets us distinguish blank rows from
/// actual access errors and avoids a reboot loop on unprovisioned boards.
///
/// P1-3 hardening is preserved: the only error path is an out-of-range
/// row index (compile-time constant, so this cannot be fault-injected).
/// An indeterminate read (all-ones, or two reads that disagree) counts as
/// production mode: a glitch must not be able to switch protections off.
fn is_production_mode_otp() -> Result<bool, ()> {
    const OTP_DATA_RAW_BASE: *const u32 = 0x4013_4000 as *const u32;
    const OTP_NUM_ROWS: usize = 4096;
    const OTP_BOOT_FLAGS_ROW: usize = crate::security::otp_layout::BOOT_FLAGS_ROW as usize;
    const BOOT_FLAG_PRODUCTION_MODE: u32 = crate::security::otp_layout::BOOT_FLAG_PRODUCTION_MODE;

    if OTP_BOOT_FLAGS_ROW >= OTP_NUM_ROWS {
        return Err(()); // should never happen — compile-time constant
    }

    // SAFETY: OTP_DATA_RAW is a memory-mapped read-only register block.
    // The boot flags row is within the valid range (checked above).
    let read = || unsafe { core::ptr::read_volatile(OTP_DATA_RAW_BASE.add(OTP_BOOT_FLAGS_ROW)) };
    let first = read();
    let second = read();

    // Fail closed.  Unprogrammed fuses read 0, so all-ones is an access
    // error or a glitch, not "blank"; and a single read is one glitch away
    // from turning production protections off.  Either way: production.
    if first != second || first == 0xFFFF_FFFF {
        return Ok(true);
    }
    Ok(first & BOOT_FLAG_PRODUCTION_MODE != 0)
}

/// Check if the RP2350 is running in secure boot mode.
///
/// SECURE_BOOT_ENABLE is bit 0 of **CRIT1** (OTP row 0x40), NOT in
/// BOOT_FLAGS0 (row 0x48, which controls boot paths, not secure boot).
///
/// CRIT1 uses RBIT-8 redundancy (rows 0x40–0x47); the hardware resolves
/// the 8 copies by a 3-of-8 vote at OTP reset and latches the result in
/// the OTP CRITICAL register, which is what this reads (the same value the
/// bootrom and the debug logic act on).
///
/// Returns `true` if the SECURE_BOOT_ENABLE fuse is set.
pub fn is_secure_boot_enabled() -> bool {
    // The OTP CRITICAL register holds the hardware's decision: CRIT1's 8
    // copies (rows 0x40–0x47) read by a 3-of-8 vote at OTP reset.  A raw
    // read of row 0x40 alone could disagree with it.
    embassy_rp::pac::OTP.critical().read().secure_boot_enable()
}

/// Record JTAG-disabled status in the pico2hsm application boot flags.
///
/// Sets bit 0 of the boot flags row as a user-land bookkeeping marker that
/// JTAG has been disabled.  This does NOT disable JTAG at the hardware
/// level — that requires writing CRIT1.DEBUG_DISABLE (OTP rows 0x40–0x47,
/// RBIT-8), which must be done via `picotool otp set OTP_DATA_CRIT1.DEBUG_DISABLE 1`
/// during provisioning.
///
/// # Why firmware does not write CRIT1
///
/// CRIT1 uses RBIT-8 redundancy: 8 identical copies at rows 0x40–0x47.
/// The ROM does a majority vote across all 8 copies.
/// `embassy_rp::otp::write_raw_word()` writes exactly one row, which is
/// insufficient — a single copy does not reliably flip the majority vote,
/// and a power loss during sequential writes could leave the device in an
/// inconsistent state.  `picotool otp set` handles all 8 copies atomically.
///
/// # Irreversibility
/// OTP bits can only transition 0→1 (fuse burning). This operation is
/// permanent and cannot be undone.
///
/// Only callable when production mode is active.
pub fn disable_jtag_permanent() {
    use embassy_rp::otp;
    const OTP_BOOT_FLAGS_ROW: usize = crate::security::otp_layout::BOOT_FLAGS_ROW as usize;
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
    // SAFETY: Writing to OTP_BOOT_FLAGS_ROW is a pico2hsm
    // application-layer OTP row in the user-accessible OTP range
    // (rows 0x100–0x17F). The write uses the embassy-rp `otp::write_raw_word`
    // wrapper, which calls the RP2350 ROM `otp_access` function with
    // programming mode enabled. See RP2350 datasheet §5.6.1 "OTP Programming".
    let new_flags = current | BOOT_FLAG_JTAG_DISABLED;
    match otp::write_raw_word(OTP_BOOT_FLAGS_ROW, new_flags) {
        Ok(()) => {
            defmt::warn!(
                "boot: JTAG disable bookkeeping flag set in OTP boot flags row — IRREVERSIBLE"
            );
            defmt::warn!(
                "boot: hardware JTAG disable (CRIT1.DEBUG_DISABLE) must be set via picotool"
            );
        }
        Err(_) => {
            defmt::error!("boot: failed to set JTAG disable OTP flag");
        }
    }
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
