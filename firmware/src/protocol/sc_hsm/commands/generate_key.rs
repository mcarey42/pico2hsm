//! GENERATE SYMMETRIC KEY command handler (INS = 0x48).
//!
//! Generates a symmetric key (AES-128/192/256) using the on-chip TRNG
//! and stores it in the keystore.
//!
//! # Command data
//! - P1: key ID (0x01–0xFE)
//! - P2: 0x00
//! - Data: Key algorithm tag:
//!   - 0x82: AES-128
//!   - 0x83: AES-192
//!   - 0x84: AES-256

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for GENERATE SYMMETRIC KEY.
pub const INS_GENERATE_KEY: u8 = 0x48;

/// Handle a GENERATE SYMMETRIC KEY APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let key_id = cmd.p1;
    if key_id == 0x00 || key_id == 0xFF {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Data field must contain the algorithm tag
    let algo_tag = cmd.data.first().copied();
    match algo_tag {
        Some(0x82) | Some(0x83) | Some(0x84) => {}
        _ => return ApduResponse::err(SW_WRONG_DATA),
    }

    // TODO (Agent 7): call key_management::generate_symmetric_key(key_id, algo_tag)
    ApduResponse::err(SW_INS_NOT_SUPPORTED)
}
