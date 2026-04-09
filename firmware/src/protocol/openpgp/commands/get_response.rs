//! GET RESPONSE command handler (INS = 0xC0) for OpenPGP.
//!
//! Returns the next chunk of a previously buffered large response.
//! Used when a command response exceeds Le (e.g. RSA public key from GENERATE KEY PAIR).
//!
//! The response is stored in `OpenPgpState::last_response` with an offset pointer
//! `last_response_offset`. SW=61xx indicates more data is available.

use pico2hsm_core::apdu::{ApduCommand, ApduResponse};

use crate::protocol::openpgp::OpenPgpState;

/// INS byte for GET RESPONSE.
pub const INS_GET_RESPONSE: u8 = 0xC0;

/// Handle GET RESPONSE: return next chunk from `last_response`.
///
/// `le` from the APDU command: `None` = return all remaining, `Some(0)` = 256 bytes,
/// `Some(n)` = n bytes.
pub fn handle(state: &mut OpenPgpState, cmd: &ApduCommand<'_>) -> ApduResponse {
    let offset = state.last_response_offset;
    let remaining = state.last_response.len().saturating_sub(offset);
    if remaining == 0 {
        return ApduResponse::ok(&[]); // nothing pending
    }

    let chunk_len = match cmd.le {
        None => remaining,
        Some(0) => remaining.min(256),
        Some(n) => remaining.min(n as usize),
    };

    let chunk = &state.last_response[offset..offset + chunk_len];
    let mut resp = ApduResponse::ok(chunk);
    state.last_response_offset += chunk_len;
    let new_remaining = state.last_response.len().saturating_sub(state.last_response_offset);
    if new_remaining > 0 {
        let xx = new_remaining.min(0xFF) as u8;
        resp.sw = 0x6100 | (xx as u16);
    } else {
        state.last_response.clear();
        state.last_response_offset = 0;
    }
    resp
}
