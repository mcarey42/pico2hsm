//! CHANGE REFERENCE DATA command handler (INS = 0x24).
//!
//! Changes the User PIN or SO-PIN. The command data field contains the
//! old PIN followed by the new PIN. Uses BER-TLV tags 0x80 (old) and 0x81
//! (new), or can be provided as concatenated old||new with Lc = len_old + len_new
//! when P1=0x00.
//!
//! Requires the current PIN to be correct before accepting the new PIN.
//! PIN length constraints: minimum 4 bytes, maximum 16 bytes.

use subtle::ConstantTimeEq;

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_AUTH_BLOCKED, SW_OK, SW_SECURITY_STATUS, SW_WRONG_DATA,
    SW_WRONG_LENGTH,
};

use super::verify::{P2_SO_PIN, P2_USER_PIN};
use crate::protocol::sc_hsm::ScHsmState;
use crate::security::pin::PinState;

/// INS byte for CHANGE REFERENCE DATA.
pub const INS_CHANGE_PIN: u8 = 0x24;

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

/// Verify `pin` against `stored` using PBKDF2 (constant time).
fn verify_pin_pbkdf2(pin: &[u8], salt: &[u8; 16], stored: &[u8; 32]) -> bool {
    let computed = PinState::hash_pin(pin, b"pico2hsm-device", salt);
    computed.ct_eq(stored).into()
}

fn find_tlv<'a>(data: &'a [u8], tag: u8) -> Option<&'a [u8]> {
    let mut i = 0;
    while i + 1 < data.len() {
        let t = data[i];
        i += 1;
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() {
            return None;
        }
        if t == tag {
            return Some(&data[i..i + len]);
        }
        i += len;
    }
    None
}

/// Handle a CHANGE REFERENCE DATA APDU command with flash persistence.
pub fn handle_with_store(
    state: &mut ScHsmState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    let resp = handle(state, cmd);
    if resp.sw == SW_OK {
        crate::protocol::sc_hsm::ScHsm::save_pin_to_store(state, store);
    }
    resp
}

/// Handle a CHANGE REFERENCE DATA APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // P1=0x00: old||new concatenated (no TLV)
    // P1=0x01: TLV-encoded
    // P2 selects which PIN reference

    let (old_pin, new_pin) = if cmd.p1 == 0x01 {
        // TLV encoding
        let old = match find_tlv(cmd.data, 0x80) {
            Some(v) => v,
            None => return ApduResponse::err(SW_WRONG_DATA),
        };
        let new = match find_tlv(cmd.data, 0x81) {
            Some(v) => v,
            None => return ApduResponse::err(SW_WRONG_DATA),
        };
        (old, new)
    } else if cmd.p1 == 0x00 {
        // Concatenated — split at midpoint (must be even length with known old-pin len)
        // SC-HSM typically uses 6 bytes for old + new; accept TLV or equal-split.
        // Fall back: each half equal
        let half = cmd.data.len() / 2;
        if half == 0 {
            return ApduResponse::err(SW_WRONG_DATA);
        }
        (&cmd.data[..half], &cmd.data[half..])
    } else {
        return ApduResponse::err(SW_WRONG_DATA);
    };

    if new_pin.len() < 4 || new_pin.len() > 16 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }

    match cmd.p2 {
        P2_USER_PIN => {
            if state.pin_retry_count == 0 {
                return ApduResponse::err(SW_AUTH_BLOCKED);
            }
            let stored = match &state.user_pin_hash {
                Some(h) => *h,
                None => return ApduResponse::err(SW_SECURITY_STATUS),
            };
            let old_salt = state.user_pin_salt;
            if !verify_pin_pbkdf2(old_pin, &old_salt, &stored) {
                state.pin_verified = false;
                state.pin_retry_count = state.pin_retry_count.saturating_sub(1);
                if state.pin_retry_count == 0 {
                    return ApduResponse::err(SW_AUTH_BLOCKED);
                }
                return ApduResponse::err(0x63C0 | (state.pin_retry_count as u16 & 0x0F));
            }
            // Generate a fresh salt for the new PIN.
            let new_salt = gen_salt();
            state.user_pin_salt = new_salt;
            state.user_pin_hash = Some(hash_pin_pbkdf2(new_pin, &new_salt));
            state.pin_retry_count = 3;
            state.pin_verified = false; // require re-verify after change
            ApduResponse::ok(&[])
        }

        P2_SO_PIN => {
            if state.so_pin_retry_count == 0 {
                return ApduResponse::err(SW_AUTH_BLOCKED);
            }
            let stored = match &state.so_pin_hash {
                Some(h) => *h,
                None => return ApduResponse::err(SW_SECURITY_STATUS),
            };
            let old_salt = state.so_pin_salt;
            if !verify_pin_pbkdf2(old_pin, &old_salt, &stored) {
                state.so_pin_verified = false;
                state.so_pin_retry_count = state.so_pin_retry_count.saturating_sub(1);
                if state.so_pin_retry_count == 0 {
                    return ApduResponse::err(SW_AUTH_BLOCKED);
                }
                return ApduResponse::err(0x63C0 | (state.so_pin_retry_count as u16 & 0x0F));
            }
            // Generate a fresh salt for the new SO-PIN.
            let new_salt = gen_salt();
            state.so_pin_salt = new_salt;
            state.so_pin_hash = Some(hash_pin_pbkdf2(new_pin, &new_salt));
            state.so_pin_retry_count = 5;
            state.so_pin_verified = false;
            ApduResponse::ok(&[])
        }

        _ => ApduResponse::err(SW_WRONG_DATA),
    }
}
