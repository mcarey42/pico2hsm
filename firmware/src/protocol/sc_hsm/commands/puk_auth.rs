//! PUK AUTHENTICATE command handler (INS = 0x28).
//!
//! Authenticates using the PUK (PIN Unblocking Key) to unlock the device
//! after all User PIN retry attempts have been exhausted.

use subtle::ConstantTimeEq;

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_AUTH_BLOCKED, SW_CONDITIONS_NOT_SATISFIED,
    SW_INS_NOT_SUPPORTED, SW_SECURITY_STATUS, SW_WRONG_LENGTH, SW_OK,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for PUK AUTHENTICATE.
pub const INS_PUK_AUTH: u8 = 0x28;

/// Handle a PUK AUTHENTICATE APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    let puk = cmd.data;
    if puk.len() < 8 || puk.len() > 16 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }

    // TODO (Agent 7): constant-time PUK comparison, retry counter management.
    // Currently no PUK stored — return security status.
    ApduResponse::err(SW_INS_NOT_SUPPORTED)
}
