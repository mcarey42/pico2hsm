//! VERIFY command handler (INS = 0x20) for OpenPGP.
//!
//! Verifies PW1 (P2=0x81 for signing, P2=0x82 for other) or PW3 (P2=0x83).
//! Empty data returns retry count as SW=0x63CX.
//! P1=0xFF resets the verified status without presenting a PIN.

use subtle::ConstantTimeEq;

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_AUTH_BLOCKED, SW_OK, SW_WRONG_DATA, SW_WRONG_LENGTH,
};

use crate::protocol::openpgp::OpenPgpState;

/// INS byte for VERIFY.
pub const INS_VERIFY: u8 = 0x20;

/// Build a retry-count status word: 0x63C0 | remaining.
fn sw_retry(remaining: u8) -> u16 {
    0x63C0 | (remaining as u16 & 0x0F)
}

/// Verify a PIN hash in constant time.
fn verify_pin_hash(pin: &[u8], stored_hash: &[u8; 32]) -> bool {
    let computed = OpenPgpState::hash_pin(pin);
    computed.ct_eq(stored_hash).into()
}

/// Handle VERIFY and persist PW1 or PW3 state to flash on retry counter change.
pub fn handle_with_store(
    state: &mut OpenPgpState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    let pw1_retries_before = state.pw1_retries;
    let pw3_retries_before = state.pw3_retries;
    let resp = handle(state, cmd);

    // Save PW1 state if retry counter changed or verification succeeded.
    if state.pw1_retries != pw1_retries_before
        || state.pw1_verified_sign
        || state.pw1_verified_other
    {
        crate::protocol::openpgp::OpenPgp::save_pw1_to_store(state, store);
    }
    // Save PW3 state if retry counter changed or verification succeeded.
    if state.pw3_retries != pw3_retries_before || state.pw3_verified {
        crate::protocol::openpgp::OpenPgp::save_pw3_to_store(state, store);
    }

    resp
}

/// Handle a VERIFY APDU command.
pub fn handle(state: &mut OpenPgpState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // P1=0xFF: reset verification status
    if cmd.p1 == 0xFF {
        match cmd.p2 {
            0x81 => {
                state.pw1_verified_sign = false;
                return ApduResponse::ok(&[]);
            }
            0x82 => {
                state.pw1_verified_other = false;
                return ApduResponse::ok(&[]);
            }
            0x83 => {
                state.pw3_verified = false;
                return ApduResponse::ok(&[]);
            }
            _ => return ApduResponse::err(0x6A86), // incorrect P2
        }
    }

    if cmd.p1 != 0x00 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    match cmd.p2 {
        // PW1 for signing (mode 81)
        0x81 => {
            // Empty data = query retry count
            if cmd.data.is_empty() {
                if state.pw1_retries == 0 {
                    return ApduResponse::err(SW_AUTH_BLOCKED);
                }
                if state.pw1_verified_sign {
                    return ApduResponse::ok(&[]);
                }
                return ApduResponse::err(sw_retry(state.pw1_retries));
            }

            // Check length (PW1 min 6, max 127 per spec, but we cap at 127)
            if cmd.data.len() < 6 || cmd.data.len() > 127 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }

            if state.pw1_retries == 0 {
                return ApduResponse::err(SW_AUTH_BLOCKED);
            }

            let stored = match &state.pw1_hash {
                Some(h) => *h,
                None => return ApduResponse::err(SW_AUTH_BLOCKED),
            };

            if verify_pin_hash(cmd.data, &stored) {
                state.pw1_verified_sign = true;
                state.pw1_retries = crate::protocol::openpgp::PW1_MAX_RETRIES;
                ApduResponse::ok(&[])
            } else {
                state.pw1_verified_sign = false;
                state.pw1_retries = state.pw1_retries.saturating_sub(1);
                if state.pw1_retries == 0 {
                    ApduResponse::err(SW_AUTH_BLOCKED)
                } else {
                    ApduResponse::err(sw_retry(state.pw1_retries))
                }
            }
        }

        // PW1 for other operations (mode 82)
        0x82 => {
            if cmd.data.is_empty() {
                if state.pw1_retries == 0 {
                    return ApduResponse::err(SW_AUTH_BLOCKED);
                }
                if state.pw1_verified_other {
                    return ApduResponse::ok(&[]);
                }
                return ApduResponse::err(sw_retry(state.pw1_retries));
            }

            if cmd.data.len() < 6 || cmd.data.len() > 127 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }

            if state.pw1_retries == 0 {
                return ApduResponse::err(SW_AUTH_BLOCKED);
            }

            let stored = match &state.pw1_hash {
                Some(h) => *h,
                None => return ApduResponse::err(SW_AUTH_BLOCKED),
            };

            if verify_pin_hash(cmd.data, &stored) {
                state.pw1_verified_other = true;
                state.pw1_retries = crate::protocol::openpgp::PW1_MAX_RETRIES;
                ApduResponse::ok(&[])
            } else {
                state.pw1_verified_other = false;
                state.pw1_retries = state.pw1_retries.saturating_sub(1);
                if state.pw1_retries == 0 {
                    ApduResponse::err(SW_AUTH_BLOCKED)
                } else {
                    ApduResponse::err(sw_retry(state.pw1_retries))
                }
            }
        }

        // PW3 (Admin PIN)
        0x83 => {
            if cmd.data.is_empty() {
                if state.pw3_retries == 0 {
                    return ApduResponse::err(SW_AUTH_BLOCKED);
                }
                if state.pw3_verified {
                    return ApduResponse::ok(&[]);
                }
                return ApduResponse::err(sw_retry(state.pw3_retries));
            }

            if cmd.data.len() < 8 || cmd.data.len() > 127 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }

            if state.pw3_retries == 0 {
                return ApduResponse::err(SW_AUTH_BLOCKED);
            }

            let stored = match &state.pw3_hash {
                Some(h) => *h,
                None => return ApduResponse::err(SW_AUTH_BLOCKED),
            };

            if verify_pin_hash(cmd.data, &stored) {
                state.pw3_verified = true;
                state.pw3_retries = crate::protocol::openpgp::PW3_MAX_RETRIES;
                ApduResponse::ok(&[])
            } else {
                state.pw3_verified = false;
                state.pw3_retries = state.pw3_retries.saturating_sub(1);
                if state.pw3_retries == 0 {
                    ApduResponse::err(SW_AUTH_BLOCKED)
                } else {
                    ApduResponse::err(sw_retry(state.pw3_retries))
                }
            }
        }

        _ => ApduResponse::err(0x6A86), // Incorrect P2
    }
}
