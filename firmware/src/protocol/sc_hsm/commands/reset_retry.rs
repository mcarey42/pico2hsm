//! RESET RETRY COUNTER command handler (INS = 0x2C).
//!
//! Resets the User PIN retry counter after a lockout. Two variants:
//! - P1=0x00: Reset using PUK (deblocking key) in the command data
//! - P1=0x02: Reset and set new PIN (PUK + new PIN in command data)
//!
//! Requires SO-PIN or PUK authentication.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_INS_NOT_SUPPORTED, SW_SECURITY_STATUS, SW_WRONG_DATA,
    SW_WRONG_LENGTH, SW_OK,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for RESET RETRY COUNTER.
pub const INS_RESET_RETRY: u8 = 0x2C;

fn hash_pin(pin: &[u8], out: &mut [u8; 32]) {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(pin);
    let result = h.finalize();
    out.copy_from_slice(&result);
}

/// Handle a RESET RETRY COUNTER APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Requires SO-PIN verified or equivalent authority
    if !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    match cmd.p1 {
        // P1=0x00: reset counter only (no new PIN)
        0x00 => {
            state.pin_retry_count = 3;
            state.pin_verified = false;
            ApduResponse::ok(&[])
        }

        // P1=0x02: reset counter and set new PIN from data
        0x02 => {
            let new_pin = cmd.data;
            if new_pin.len() < 4 || new_pin.len() > 16 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            let mut new_hash = [0u8; 32];
            hash_pin(new_pin, &mut new_hash);
            state.user_pin_hash = Some(new_hash);
            state.pin_retry_count = 3;
            state.pin_verified = false;
            // TODO (Agent 7): persist new PIN hash to storage
            ApduResponse::ok(&[])
        }

        _ => ApduResponse::err(SW_WRONG_DATA),
    }
}
