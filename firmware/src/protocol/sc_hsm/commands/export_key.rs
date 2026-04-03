//! EXPORT KEY command handler (INS = 0x34).
//!
//! Exports a key object wrapped under the DKEK for HSM-to-HSM backup.
//! This command does NOT export plaintext key material.
//!
//! Requires active PIN session. Keys marked with NO-EXPORT flag are rejected.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for EXPORT KEY.
pub const INS_EXPORT_KEY: u8 = 0x34;

/// Handle an EXPORT KEY APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let key_id = cmd.p1;
    if key_id == 0x00 || key_id == 0xFF {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // TODO (Agent 7): wrap key under DKEK, return blob.
    ApduResponse::err(SW_INS_NOT_SUPPORTED)
}
