//! GENERAL AUTHENTICATE command handler (INS = 0x86).
//!
//! Multi-step authentication mechanism used for:
//! - Mutual authentication between HSM and host application
//! - Establishing secure messaging sessions
//! - PIN-encrypted session key agreement
//!
//! Uses a dynamic authentication template (0x7C tag) in both command and
//! response data fields to carry challenge/response values across steps.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_SECURITY_STATUS,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for GENERAL AUTHENTICATE.
pub const INS_GENERAL_AUTH: u8 = 0x86;

/// Handle a GENERAL AUTHENTICATE APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication for most GENERAL AUTHENTICATE uses
    if !state.pin_verified && !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // TODO (Agent 7): implement multi-step auth state machine using 0x7C template.
    ApduResponse::err(SW_INS_NOT_SUPPORTED)
}
