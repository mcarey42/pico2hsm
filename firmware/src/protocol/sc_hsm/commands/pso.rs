//! PERFORM SECURITY OPERATION command handler (INS = 0x2A).
//!
//! Multipurpose command used for cryptographic operations configured by
//! the preceding MSE SET command.
//!
//! - P1=0x9E, P2=0x9A: Compute Digital Signature (same as INS=0x68)
//! - P1=0x80, P2=0x86: Decipher (same as INS=0x62)
//! - P1=0x8E, P2=0x80: Compute Cryptographic Checksum (MAC)
//! - P1=0x86, P2=0x80: Verify Cryptographic Checksum

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for PERFORM SECURITY OPERATION.
pub const INS_PSO: u8 = 0x2A;

/// Handle a PERFORM SECURITY OPERATION APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    match (cmd.p1, cmd.p2) {
        // PSO: Compute Digital Signature — delegate to sign semantics
        (0x9E, 0x9A) => {
            // Require MSE SET
            if state.current_key_id.is_none() || state.current_algo.is_none() {
                return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
            }
            // TODO (Agent 7): call key_management::sign(...)
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        // PSO: Decipher
        (0x80, 0x86) => {
            if state.current_key_id.is_none() || state.current_algo.is_none() {
                return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
            }
            // TODO (Agent 7): call key_management::decrypt(...)
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        // PSO: Compute Cryptographic Checksum (MAC)
        (0x8E, 0x80) => {
            // TODO (Agent 7): compute CMAC/HMAC
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        // PSO: Verify Cryptographic Checksum
        (0x86, 0x80) => {
            // TODO (Agent 7): verify CMAC/HMAC
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        _ => ApduResponse::err(SW_WRONG_DATA),
    }
}
