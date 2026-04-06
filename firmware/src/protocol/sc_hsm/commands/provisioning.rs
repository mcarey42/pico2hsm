//! Provisioning command handlers (INS = 0xF0–0xF3).
//!
//! These commands manage the device's OTP-based provisioning state:
//! - GET STATUS (0xF0): Read provisioning/security flags (no auth required)
//! - SET PRODUCTION MODE (0xF1): Permanently set production mode flag (SO-PIN)
//! - LOCK OTP ROWS (0xF2): Lock OTP rows (not yet implemented)
//! - WRITE CRIT0 (0xF3): Permanently program RP2350 CRIT0 OTP row (SO-PIN)
//!
//! # Security model
//! All mutating operations (0xF1–0xF3) require SO-PIN authentication.
//! Operations 0xF1 and 0xF3 are IRREVERSIBLE — they burn OTP fuses that
//! cannot be cleared once set.
//!
//! # Core1 constraint
//! These handlers run on core1 via the dispatcher. They MUST NOT call defmt
//! (core1 defmt deadlock — see CLAUDE.md).

use heapless::Vec;
use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_SECURITY_STATUS,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for GET PROVISIONING STATUS.
pub const INS_PROV_GET_STATUS: u8 = 0xF0;

/// INS byte for SET PRODUCTION MODE (irreversible).
pub const INS_PROV_SET_PRODUCTION: u8 = 0xF1;

/// INS byte for LOCK OTP ROWS (not yet implemented).
pub const INS_PROV_LOCK_OTP_ROWS: u8 = 0xF2;

/// INS byte for WRITE CRIT0 (irreversible).
pub const INS_PROV_WRITE_CRIT0: u8 = 0xF3;

// SW constants not defined in pico2hsm_core::apdu:
/// Incorrect parameters P1-P2 (ISO 7816-4).
const SW_WRONG_P1P2: u16 = 0x6A86;
/// Internal error / no precise diagnosis.
const SW_INTERNAL_ERROR: u16 = 0x6F00;

// OTP constants (must match otp.rs).
const OTP_BOOT_FLAGS_ROW: usize = 0x110;
const BOOT_FLAG_PRODUCTION_MODE: u32 = 1 << 1;

/// Handle GET PROVISIONING STATUS (INS=0xF0).
///
/// Returns a TLV structure describing the device's current provisioning and
/// security state. No authentication is required — all returned information
/// is non-sensitive (it reveals whether security features are enabled, not
/// any key material or secrets).
///
/// Response TLV:
/// ```text
/// 6F [len]
///   80 01 [production_mode: 0|1]
///   81 01 [jtag_sw_flag: 0|1]         -- OTP row 0x110 bit 0
///   82 01 [otp_rows_locked: 0|1]      -- STUB: always 0
///   83 01 [secure_boot_enabled: 0|1]  -- BOOT_FLAGS0 row 0x30 bit 0
///   84 01 [glitch_detector_armed: 0|1]
/// ```
pub fn handle_get_status(_state: &mut ScHsmState, _cmd: &ApduCommand<'_>) -> ApduResponse {
    // Read production mode flag from OTP.
    let production_mode: u8 = {
        #[cfg(target_arch = "arm")]
        {
            embassy_rp::otp::read_raw_word(OTP_BOOT_FLAGS_ROW)
                .map(|flags| if flags & BOOT_FLAG_PRODUCTION_MODE != 0 { 1 } else { 0 })
                .unwrap_or(0)
        }
        #[cfg(not(target_arch = "arm"))]
        { 0 }
    };

    // Read JTAG SW flag (bit 0 of OTP row 0x110).
    let jtag_sw_flag: u8 = {
        #[cfg(target_arch = "arm")]
        {
            embassy_rp::otp::read_raw_word(OTP_BOOT_FLAGS_ROW)
                .map(|flags| if flags & (1 << 0) != 0 { 1 } else { 0 })
                .unwrap_or(0)
        }
        #[cfg(not(target_arch = "arm"))]
        { 0 }
    };

    // OTP row locking: not yet implemented, always report 0.
    let otp_rows_locked: u8 = 0;

    // Secure boot enabled (BOOT_FLAGS0 row 0x30 bit 0).
    let secure_boot_enabled: u8 = {
        #[cfg(target_arch = "arm")]
        {
            if crate::security::boot::is_secure_boot_enabled() { 1 } else { 0 }
        }
        #[cfg(not(target_arch = "arm"))]
        { 0 }
    };

    // Glitch detector armed status.
    let glitch_detector_armed: u8 = {
        #[cfg(target_arch = "arm")]
        {
            if crate::security::anti_glitch::is_glitch_detector_armed() { 1 } else { 0 }
        }
        #[cfg(not(target_arch = "arm"))]
        { 0 }
    };

    // Build TLV response: 6F [len] 80 01 xx 81 01 xx 82 01 xx 83 01 xx 84 01 xx
    // Inner length = 5 * 3 = 15 bytes
    let inner_len: u8 = 15;
    let mut resp: Vec<u8, 32> = Vec::new();
    let _ = resp.push(0x6F);
    let _ = resp.push(inner_len);

    let _ = resp.push(0x80);
    let _ = resp.push(0x01);
    let _ = resp.push(production_mode);

    let _ = resp.push(0x81);
    let _ = resp.push(0x01);
    let _ = resp.push(jtag_sw_flag);

    let _ = resp.push(0x82);
    let _ = resp.push(0x01);
    let _ = resp.push(otp_rows_locked);

    let _ = resp.push(0x83);
    let _ = resp.push(0x01);
    let _ = resp.push(secure_boot_enabled);

    let _ = resp.push(0x84);
    let _ = resp.push(0x01);
    let _ = resp.push(glitch_detector_armed);

    ApduResponse::ok(&resp)
}

// ─────────────────────────────────────────────────────────────────────────────
// SET PRODUCTION MODE (INS=0xF1)
// ─────────────────────────────────────────────────────────────────────────────

/// Handle SET PRODUCTION MODE (INS=0xF1).
///
/// # IRREVERSIBLE
/// This permanently sets OTP bit 1 of row 0x110. Once set, the device will
/// auto-disable JTAG on every subsequent boot and reject debugger connections.
/// This operation cannot be reversed.
///
/// # Prerequisites
/// - SO-PIN must be verified (returns SW 6982 if not).
/// - Key material must already be provisioned in OTP rows 0x100+. If the
///   first ECC word at row 0x100 reads as 0, returns SW 6985 (conditions
///   not satisfied). This prevents setting production mode before key
///   material is provisioned, which would make `write_storage_key_material()`
///   permanently unreachable (MEDIUM-2 security audit finding).
pub fn handle_set_production_mode(state: &mut ScHsmState, _cmd: &ApduCommand<'_>) -> ApduResponse {
    if !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // MEDIUM-2: Check that key material is already provisioned before allowing
    // production mode. Reading OTP row 0x100 (first ECC word of storage key).
    // If it reads as 0, key material has not been provisioned yet.
    #[cfg(target_arch = "arm")]
    {
        match embassy_rp::otp::read_ecc_word(0x100) {
            Ok(0) => {
                // Key material not provisioned — refuse to set production mode.
                return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
            }
            Ok(_) => {
                // Key material is present — proceed.
            }
            Err(_) => {
                // OTP read error — cannot verify key material. Refuse.
                return ApduResponse::err(SW_INTERNAL_ERROR);
            }
        }
    }

    #[cfg(target_arch = "arm")]
    {
        let mut otp = crate::security::otp::Otp::new();
        match otp.set_production_mode() {
            Ok(()) => ApduResponse::ok(&[]),
            Err(_) => ApduResponse::err(SW_INTERNAL_ERROR),
        }
    }

    #[cfg(not(target_arch = "arm"))]
    {
        // Host-side tests: not supported.
        ApduResponse::err(SW_INS_NOT_SUPPORTED)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LOCK OTP ROWS (INS=0xF2)
// ─────────────────────────────────────────────────────────────────────────────

/// Handle LOCK OTP ROWS (INS=0xF2).
///
/// Not yet implemented. OTP row locking requires PAC access to the
/// OTP_DATA_RAW permission bits, which is not yet exposed by embassy-rp.
/// Returns SW 6D00 (INS not supported) with a clear indication that this
/// is a known limitation.
pub fn handle_lock_otp_rows(state: &mut ScHsmState, _cmd: &ApduCommand<'_>) -> ApduResponse {
    if !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // Require production mode before allowing row locking.
    #[cfg(target_arch = "arm")]
    {
        let flags = embassy_rp::otp::read_raw_word(OTP_BOOT_FLAGS_ROW).unwrap_or(0);
        if flags & BOOT_FLAG_PRODUCTION_MODE == 0 {
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    // LOCK_OTP_ROWS: OTP row locking not yet implemented
    // (requires PAC OTP_DATA_RAW permission bits).
    ApduResponse::err(SW_INS_NOT_SUPPORTED)
}

// ─────────────────────────────────────────────────────────────────────────────
// WRITE CRIT0 (INS=0xF3)
// ─────────────────────────────────────────────────────────────────────────────

/// Handle WRITE CRIT0 (INS=0xF3).
///
/// # IRREVERSIBLE
/// This permanently programs the RP2350 CRIT0 OTP row (row 0x18).
///
/// Sets:
/// - bit 2: debug_disable (hardware JTAG disable)
/// - bit 4: glitch_detector_enable
/// - bits 5-6: glitch_detector_sens = 3 (maximum sensitivity)
///
/// These bits CANNOT be cleared once set. The device will reject JTAG/SWD
/// connections on all subsequent boots and will automatically arm the
/// hardware glitch detector at maximum sensitivity from the OTP defaults.
///
/// Does NOT set:
/// - bit 0: secure_boot_enable (separate provisioning concern)
/// - bit 1: secure_debug_disable (separate provisioning concern)
///
/// # Double confirmation (MEDIUM-3 security audit finding)
/// Both P1=0xC1 and P2=0xC2 must be set simultaneously as a double-
/// confirmation against accidental invocation. Any other P1/P2 values
/// return SW 6A86 (incorrect P1/P2).
///
/// # Prerequisites
/// - SO-PIN must be verified (SW 6982 if not)
/// - Production mode must be set in OTP (SW 6985 if not)
///
/// # CRIT0 bit layout (per rp-pac, row 0x18)
/// - bit 0: secure_boot_enable
/// - bit 1: secure_debug_disable
/// - bit 2: debug_disable (JTAG disable) <-- SET
/// - bit 3: default_archsel
/// - bit 4: glitch_detector_enable       <-- SET
/// - bits 5-6: glitch_detector_sens      <-- SET to 3 (max)
///
/// Value to OR in: (1 << 2) | (1 << 4) | (3 << 5) = 0x74
pub fn handle_write_crit0(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    if !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // Require production mode.
    #[cfg(target_arch = "arm")]
    {
        let flags = embassy_rp::otp::read_raw_word(OTP_BOOT_FLAGS_ROW).unwrap_or(0);
        if flags & BOOT_FLAG_PRODUCTION_MODE == 0 {
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    // MEDIUM-3: Double confirmation — P1=0xC1 and P2=0xC2 required.
    // Both P1=0xC1 and P2=0xC2 must be set simultaneously as a double-
    // confirmation against accidental invocation.
    if cmd.p1 != 0xC1 || cmd.p2 != 0xC2 {
        return ApduResponse::err(SW_WRONG_P1P2);
    }

    #[cfg(target_arch = "arm")]
    {
        // CRIT0 OTP row address.
        const CRIT0_ROW: usize = 0x18;

        // Bits to set:
        //   bit 2:   debug_disable (JTAG disable)
        //   bit 4:   glitch_detector_enable
        //   bits 5-6: glitch_detector_sens = 3 (max)
        // Value: (1 << 2) | (1 << 4) | (3 << 5) = 0x04 | 0x10 | 0x60 = 0x74
        const CRIT0_BITS: u32 = 0x74;

        // Read current CRIT0 value (OTP bits are additive — can only set, never clear).
        let current = match embassy_rp::otp::read_raw_word(CRIT0_ROW) {
            Ok(v) => v,
            Err(_) => return ApduResponse::err(SW_INTERNAL_ERROR),
        };

        let new_value = current | CRIT0_BITS;

        match embassy_rp::otp::write_raw_word(CRIT0_ROW, new_value) {
            Ok(()) => ApduResponse::ok(&[]),
            Err(_) => ApduResponse::err(SW_INTERNAL_ERROR),
        }
    }

    #[cfg(not(target_arch = "arm"))]
    {
        // Host-side tests: not supported.
        ApduResponse::err(SW_INS_NOT_SUPPORTED)
    }
}
