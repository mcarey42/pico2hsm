//! CHANGE REFERENCE DATA command handler (INS = 0x24) for OpenPGP.
//!
//! Changes PW1 (P2=0x81) or PW3 (P2=0x83).
//! Data format: old PIN bytes immediately followed by new PIN bytes.
//! The card must determine the split point using the known old PIN length
//! (from verification) — but since we don't know the old PIN length, the
//! spec says we use the minimum lengths: PW1 min=6, PW3 min=8.
//!
//! In practice, GnuPG sends the old PIN length known to the user, so the
//! split is: data[0..old_len] = old PIN, data[old_len..] = new PIN.
//! We verify the old PIN by trying all valid split points.

use subtle::ConstantTimeEq;

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_AUTH_BLOCKED, SW_WRONG_DATA, SW_WRONG_LENGTH,
};

use crate::protocol::openpgp::OpenPgpState;

/// INS byte for CHANGE REFERENCE DATA.
pub const INS_CHANGE_PIN: u8 = 0x24;

/// Build a retry-count status word.
fn sw_retry(remaining: u8) -> u16 {
    0x63C0 | (remaining as u16 & 0x0F)
}

/// Handle a CHANGE REFERENCE DATA APDU command.
pub fn handle(state: &mut OpenPgpState, cmd: &ApduCommand<'_>) -> ApduResponse {
    if cmd.p1 != 0x00 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    match cmd.p2 {
        // Change PW1
        0x81 => {
            if state.pw1_retries == 0 {
                return ApduResponse::err(SW_AUTH_BLOCKED);
            }

            let stored = match &state.pw1_hash {
                Some(h) => *h,
                None => return ApduResponse::err(SW_AUTH_BLOCKED),
            };

            // Try split points: old PIN from 6..data.len()-6 bytes
            // (new PIN must also be at least 6 bytes)
            let min_old = 6usize;
            let min_new = 6usize;
            if cmd.data.len() < min_old + min_new {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }

            let max_old = cmd.data.len() - min_new;
            for split in min_old..=max_old {
                let old_pin = &cmd.data[..split];
                let computed = OpenPgpState::hash_pin(old_pin);
                if bool::from(computed.ct_eq(&stored)) {
                    let new_pin = &cmd.data[split..];
                    if new_pin.len() < min_new || new_pin.len() > 127 {
                        return ApduResponse::err(SW_WRONG_LENGTH);
                    }
                    state.pw1_hash = Some(OpenPgpState::hash_pin(new_pin));
                    state.pw1_retries = crate::protocol::openpgp::PW1_MAX_RETRIES;
                    return ApduResponse::ok(&[]);
                }
            }

            // No valid split found — old PIN is wrong
            state.pw1_retries = state.pw1_retries.saturating_sub(1);
            if state.pw1_retries == 0 {
                ApduResponse::err(SW_AUTH_BLOCKED)
            } else {
                ApduResponse::err(sw_retry(state.pw1_retries))
            }
        }

        // Change PW3
        0x83 => {
            if state.pw3_retries == 0 {
                return ApduResponse::err(SW_AUTH_BLOCKED);
            }

            let stored = match &state.pw3_hash {
                Some(h) => *h,
                None => return ApduResponse::err(SW_AUTH_BLOCKED),
            };

            let min_old = 8usize;
            let min_new = 8usize;
            if cmd.data.len() < min_old + min_new {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }

            let max_old = cmd.data.len() - min_new;
            for split in min_old..=max_old {
                let old_pin = &cmd.data[..split];
                let computed = OpenPgpState::hash_pin(old_pin);
                if bool::from(computed.ct_eq(&stored)) {
                    let new_pin = &cmd.data[split..];
                    if new_pin.len() < min_new || new_pin.len() > 127 {
                        return ApduResponse::err(SW_WRONG_LENGTH);
                    }
                    state.pw3_hash = Some(OpenPgpState::hash_pin(new_pin));
                    state.pw3_retries = crate::protocol::openpgp::PW3_MAX_RETRIES;
                    return ApduResponse::ok(&[]);
                }
            }

            state.pw3_retries = state.pw3_retries.saturating_sub(1);
            if state.pw3_retries == 0 {
                ApduResponse::err(SW_AUTH_BLOCKED)
            } else {
                ApduResponse::err(sw_retry(state.pw3_retries))
            }
        }

        _ => ApduResponse::err(0x6A86), // Incorrect P2
    }
}
