//! RESET RETRY COUNTER command handler (INS = 0x2C) for OpenPGP.
//!
//! Unblocks PW1 (user PIN) using PW3 (admin PIN) authority.
//!
//! P1=0x00, P2=0x81: reset PW1 retry counter to maximum (3); requires PW3 verified.
//! P1=0x02, P2=0x81: reset PW1 retry counter AND set new PW1 value; requires PW3 verified.
//!                   Data = new PW1 bytes (min 6, max 127).

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_SECURITY_STATUS, SW_WRONG_DATA, SW_WRONG_LENGTH,
};

use crate::protocol::openpgp::{OpenPgpState, PW1_MAX_RETRIES};

/// INS byte for RESET RETRY COUNTER.
pub const INS_RESET_RETRY_COUNTER: u8 = 0x2C;

/// Handle RESET RETRY COUNTER and persist updated PW1 state to flash.
pub fn handle_with_store(
    state: &mut OpenPgpState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    let resp = handle(state, cmd);
    if resp.sw == 0x9000 {
        crate::protocol::openpgp::OpenPgp::save_pw1_to_store(state, store);
    }
    resp
}

/// Handle a RESET RETRY COUNTER APDU command.
pub fn handle(state: &mut OpenPgpState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Only P2=0x81 is defined (PW1)
    if cmd.p2 != 0x81 {
        return ApduResponse::err(0x6A86); // incorrect P2
    }

    // Requires PW3 (admin) to be verified
    if !state.pw3_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    match cmd.p1 {
        // P1=0x00: reset PW1 retry counter only (no data required)
        0x00 => {
            if !cmd.data.is_empty() {
                return ApduResponse::err(SW_WRONG_DATA);
            }
            state.pw1_retries = PW1_MAX_RETRIES;
            // Reset the verification flags since PW1 was blocked
            state.pw1_verified_sign = false;
            state.pw1_verified_other = false;
            ApduResponse::ok(&[])
        }

        // P1=0x02: reset PW1 retry counter AND set new PW1 value
        0x02 => {
            // Data is new PW1 bytes
            if cmd.data.len() < 6 || cmd.data.len() > 127 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.pw1_hash = Some(OpenPgpState::hash_pin(cmd.data));
            state.pw1_retries = PW1_MAX_RETRIES;
            state.pw1_verified_sign = false;
            state.pw1_verified_other = false;
            ApduResponse::ok(&[])
        }

        _ => ApduResponse::err(SW_WRONG_DATA),
    }
}
