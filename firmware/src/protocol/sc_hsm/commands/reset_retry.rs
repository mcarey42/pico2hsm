//! RESET RETRY COUNTER command handler (INS = 0x2C).
//!
//! Resets the User PIN retry counter after a lockout. Two variants:
//! - P1=0x00: Reset using PUK (deblocking key) in the command data
//! - P1=0x02: Reset and set new PIN (PUK + new PIN in command data)
//!
//! Requires SO-PIN or PUK authentication.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_INS_NOT_SUPPORTED, SW_OK, SW_SECURITY_STATUS, SW_WRONG_DATA,
    SW_WRONG_LENGTH,
};

use crate::protocol::sc_hsm::ScHsmState;
use crate::security::pin::PinState;

/// INS byte for RESET RETRY COUNTER.
pub const INS_RESET_RETRY: u8 = 0x2C;

/// Generate 16 random bytes for a new PIN salt.
fn gen_salt() -> [u8; 16] {
    use crate::protocol::sc_hsm::FwRng;
    use rand_core::RngCore;
    let mut rng = FwRng;
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    salt
}

/// Compute PBKDF2-HMAC-SHA256 of `pin` using `salt`.
fn hash_pin_pbkdf2(pin: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    PinState::hash_pin(pin, b"pico2hsm-device", salt)
}

/// Handle a RESET RETRY COUNTER APDU command with flash persistence.
pub fn handle_with_store(
    state: &mut ScHsmState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    let before = (state.user_pin_salt, state.user_pin_hash);
    let resp = handle(state, cmd);
    if resp.sw == pico2hsm_core::apdu::SW_OK
        && crate::protocol::sc_hsm::ScHsm::save_pin_to_store(state, store).is_err()
    {
        // Keep RAM what flash holds: no new PIN that a reboot would
        // silently undo, and the counters as the log has them.
        (state.user_pin_salt, state.user_pin_hash) = before;
        crate::protocol::sc_hsm::ScHsm::reload_counters(state, store);
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    }
    resp
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
            state.session_pin = None; // stood in for the old PIN
            ApduResponse::ok(&[])
        }

        // P1=0x02: reset counter and set new PIN from data
        0x02 => {
            let new_pin = cmd.data;
            if new_pin.len() < super::verify::MIN_PIN_LEN || new_pin.len() > 16 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            // Generate a fresh salt and compute PBKDF2 hash (P1-1 fix).
            let new_salt = gen_salt();
            state.user_pin_salt = new_salt;
            state.user_pin_hash = Some(hash_pin_pbkdf2(new_pin, &new_salt));
            state.pin_retry_count = 3;
            state.pin_verified = false;
            state.session_pin = None; // stood in for the old PIN
            ApduResponse::ok(&[])
        }

        _ => ApduResponse::err(SW_WRONG_DATA),
    }
}
