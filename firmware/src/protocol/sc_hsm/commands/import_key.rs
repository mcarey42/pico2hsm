//! IMPORT KEY command handler (INS = 0x58, P2 = 0x93).
//!
//! Imports a wrapped (encrypted) key object from the host. The key is
//! encrypted under a DKEK share.
//!
//! # Command data
//! Wrapped key blob in SC-HSM wrap format.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for IMPORT KEY.
pub const INS_IMPORT_KEY: u8 = 0x58;

/// P2 value for key import operation.
pub const P2_IMPORT: u8 = 0x93;

/// Handle an IMPORT KEY APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let key_id = cmd.p1;
    if key_id == 0x00 || key_id == 0xFF {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // TODO (Agent 7): unwrap key blob under DKEK, store to keystore.
    ApduResponse::err(SW_INS_NOT_SUPPORTED)
}
