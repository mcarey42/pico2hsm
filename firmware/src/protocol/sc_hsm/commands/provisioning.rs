//! Provisioning command handlers (INS = 0xF0–0xF3).
//!
//! These commands manage the device's OTP-based provisioning state:
//! - GET STATUS (0xF0): Read provisioning/security flags (no auth required)
//! - SET PRODUCTION MODE (0xF1): Permanently set production mode flag (SO-PIN)
//! - LOCK OTP ROWS (0xF2): Lock OTP rows (not yet implemented)
//! - WRITE CRIT1 (0xF3): Disabled — use `picotool otp set OTP_DATA_CRIT1.*`
//!
//! # Security model
//! All mutating operations (0xF1–0xF3) require SO-PIN authentication.
//! Operation 0xF1 is IRREVERSIBLE — it burns OTP fuses that cannot be cleared.
//!
//! # CRIT1 (hardware JTAG disable, secure boot, glitch detector)
//! CRIT1 uses RBIT-8 redundancy (8 identical copies at OTP rows 0x40–0x47).
//! The ROM does a majority vote across all copies.  `embassy_rp::otp::write_raw_word()`
//! writes exactly one row — insufficient for reliable RBIT-8 programming.
//! Use `picotool otp set OTP_DATA_CRIT1.DEBUG_DISABLE 1` which writes all
//! 8 copies automatically.  INS=0xF3 is reserved but returns SW 6D00.
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

/// INS byte for WRITE CRIT1 (disabled — use picotool instead).
pub const INS_PROV_WRITE_CRIT1: u8 = 0xF3;

// SW constants not defined in pico2hsm_core::apdu:
/// Incorrect parameters P1-P2 (ISO 7816-4).
const SW_WRONG_P1P2: u16 = 0x6A86;
/// Internal error / no precise diagnosis.
const SW_INTERNAL_ERROR: u16 = 0x6F00;

use crate::security::otp_layout::BOOT_FLAG_PRODUCTION_MODE;
const OTP_BOOT_FLAGS_ROW: usize = crate::security::otp_layout::BOOT_FLAGS_ROW as usize;

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
///   81 01 [jtag_sw_flag: 0|1]         -- boot flags row, bit 0
///   82 01 [otp_rows_locked: 0|1]      -- key page read-locked this boot
///   83 01 [secure_boot_enabled: 0|1]  -- CRIT1 row 0x40 bit 0
///   84 01 [glitch_detector_armed: 0|1]
/// ```
pub fn handle_get_status(_state: &mut ScHsmState, _cmd: &ApduCommand<'_>) -> ApduResponse {
    // Read production mode flag from OTP.
    let production_mode: u8 = {
        #[cfg(target_arch = "arm")]
        {
            embassy_rp::otp::read_raw_word(OTP_BOOT_FLAGS_ROW)
                .map(|flags| {
                    if flags & BOOT_FLAG_PRODUCTION_MODE != 0 {
                        1
                    } else {
                        0
                    }
                })
                .unwrap_or(0)
        }
        #[cfg(not(target_arch = "arm"))]
        {
            0
        }
    };

    // Read JTAG SW flag (bit 0 of the boot flags row).
    let jtag_sw_flag: u8 = {
        #[cfg(target_arch = "arm")]
        {
            embassy_rp::otp::read_raw_word(OTP_BOOT_FLAGS_ROW)
                .map(|flags| if flags & (1 << 0) != 0 { 1 } else { 0 })
                .unwrap_or(0)
        }
        #[cfg(not(target_arch = "arm"))]
        {
            0
        }
    };

    // Key page read lock (applied at boot on provisioned devices).
    let otp_rows_locked: u8 = {
        #[cfg(target_arch = "arm")]
        {
            crate::security::otp::key_page_locked() as u8
        }
        #[cfg(not(target_arch = "arm"))]
        {
            0
        }
    };

    // Secure boot enabled (CRIT1 row 0x40 bit 0).
    let secure_boot_enabled: u8 = {
        #[cfg(target_arch = "arm")]
        {
            if crate::security::boot::is_secure_boot_enabled() {
                1
            } else {
                0
            }
        }
        #[cfg(not(target_arch = "arm"))]
        {
            0
        }
    };

    // Glitch detector armed status.
    let glitch_detector_armed: u8 = {
        #[cfg(target_arch = "arm")]
        {
            if crate::security::anti_glitch::is_glitch_detector_armed() {
                1
            } else {
                0
            }
        }
        #[cfg(not(target_arch = "arm"))]
        {
            0
        }
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
/// This permanently sets bit 1 of the OTP boot flags row. Once set, the device will
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
// WRITE CRIT1 (INS=0xF3) — DISABLED
// ─────────────────────────────────────────────────────────────────────────────

/// Handle WRITE CRIT1 (INS=0xF3) — **DISABLED**.
///
/// CRIT1 (OTP rows 0x40–0x47) uses RBIT-8 redundancy: 8 identical copies.
/// The ROM does a majority vote across all copies to determine the value.
/// `embassy_rp::otp::write_raw_word()` writes exactly ONE row, which is
/// insufficient for reliable RBIT-8 programming — a power loss mid-sequence
/// could leave the device with inconsistent redundancy state.
///
/// Use `picotool otp set OTP_DATA_CRIT1.*` during provisioning instead:
/// ```text
/// picotool otp set OTP_DATA_CRIT1.DEBUG_DISABLE 1
/// picotool otp set OTP_DATA_CRIT1.SECURE_DEBUG_DISABLE 1
/// picotool otp set OTP_DATA_CRIT1.GLITCH_DETECTOR_ENABLE 1
/// picotool otp set OTP_DATA_CRIT1.GLITCH_DETECTOR_SENS 3
/// picotool otp set OTP_DATA_CRIT1.SECURE_BOOT_ENABLE 1
/// ```
///
/// picotool writes all 8 RBIT-8 copies automatically.
///
/// # CRIT1 bit layout (rows 0x40–0x47, RBIT-8)
/// Verified against pico-sdk `otp_data.h` and rp-pac 7.0.0:
/// - bit 0: SECURE_BOOT_ENABLE
/// - bit 1: SECURE_DEBUG_DISABLE
/// - bit 2: DEBUG_DISABLE (JTAG/SWD kill switch)
/// - bit 3: BOOT_ARCH
/// - bit 4: GLITCH_DETECTOR_ENABLE
/// - bits 5-6: GLITCH_DETECTOR_SENS
///
/// # Note on CRIT0 (rows 0x38–0x3F)
/// CRIT0 only contains ARM_DISABLE (bit 0) and RISCV_DISABLE (bit 1).
/// It has nothing to do with secure boot, JTAG, or glitch detection.
/// Row 0x18 is NUM_GPIOS — previous code incorrectly wrote there.
pub fn handle_write_crit1(_state: &mut ScHsmState, _cmd: &ApduCommand<'_>) -> ApduResponse {
    // INS=0xF3 is reserved but disabled.  CRIT1 must be programmed via
    // picotool during provisioning (handles RBIT-8 automatically).
    ApduResponse::err(SW_INS_NOT_SUPPORTED)
}
