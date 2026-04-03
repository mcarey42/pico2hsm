//! EXTRAS command handler (INS = 0x54).
//!
//! Additional cryptographic primitives dispatched by P1 sub-command:
//! - P1=0x01: HKDF-Extract
//! - P1=0x02: HKDF-Expand
//! - P1=0x03: PBKDF2-SHA256
//! - P1=0x04: X9.63-KDF
//! - P1=0x05: AES-CMAC
//! - P1=0x06: HMAC-SHA256

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for EXTRAS.
pub const INS_EXTRAS: u8 = 0x54;

/// Handle an EXTRAS APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication for cryptographic operations
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    match cmd.p1 {
        0x01 => {
            // HKDF-Extract
            // TODO (Agent 7): call crypto::kdf::hkdf_extract(...)
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        0x02 => {
            // HKDF-Expand
            // TODO (Agent 7): call crypto::kdf::hkdf_expand(...)
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        0x03 => {
            // PBKDF2-SHA256
            // TODO (Agent 7): call crypto::kdf::pbkdf2(...)
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        0x04 => {
            // X9.63-KDF
            // TODO (Agent 7): call crypto::kdf::x963_kdf(...)
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        0x05 => {
            // AES-CMAC
            // TODO (Agent 7): call crypto::symmetric::cmac(...)
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        0x06 => {
            // HMAC-SHA256
            // TODO (Agent 7): call crypto::kdf::hmac_sha256(...)
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        _ => ApduResponse::err(SW_WRONG_DATA),
    }
}
