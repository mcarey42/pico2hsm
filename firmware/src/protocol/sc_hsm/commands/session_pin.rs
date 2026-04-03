//! SESSION PIN command handler (INS = 0x26).
//!
//! Creates a one-time session PIN for a single operation without exposing
//! the full User PIN.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_SECURITY_STATUS,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for SESSION PIN.
pub const INS_SESSION_PIN: u8 = 0x26;

/// Handle a SESSION PIN APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN or SO-PIN to create a session PIN
    if !state.pin_verified && !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // TODO (Agent 7): generate session PIN, store with expiry.
    ApduResponse::err(SW_INS_NOT_SUPPORTED)
}
