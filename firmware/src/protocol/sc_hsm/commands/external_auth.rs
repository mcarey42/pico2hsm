//! EXTERNAL AUTHENTICATE command handler (INS = 0x82).
//!
//! Authenticates an external entity (host application) to the HSM using
//! a challenge-response mechanism. The host signs the challenge returned
//! by GET CHALLENGE using a key known to both parties.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_SECURITY_STATUS,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for EXTERNAL AUTHENTICATE.
pub const INS_EXTERNAL_AUTH: u8 = 0x82;

/// Handle an EXTERNAL AUTHENTICATE APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // A challenge must have been issued previously via GET CHALLENGE
    if state.challenge.is_none() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // TODO (Agent 7): verify cryptogram over stored challenge using device auth key.
    // Clear challenge after use (prevents replay).
    state.challenge = None;
    ApduResponse::err(SW_INS_NOT_SUPPORTED)
}
