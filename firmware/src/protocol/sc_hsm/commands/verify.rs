//! VERIFY command handler (INS = 0x20).
//!
//! Verifies the User PIN (P2 = 0x81) or SO-PIN (P2 = 0x88). On success,
//! opens a PIN-authenticated session. On failure, decrements the retry
//! counter. When the retry counter reaches zero, the PIN is blocked
//! and further VERIFY attempts return SW=0x6983 (AUTH BLOCKED).
//!
//! VERIFY with empty data field returns the remaining retry count in SW2
//! (SW = 0x63CX where X = remaining retries).

use subtle::ConstantTimeEq;

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_AUTH_BLOCKED, SW_SECURITY_STATUS, SW_WRONG_DATA,
    SW_WRONG_LENGTH, SW_OK,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for VERIFY.
pub const INS_VERIFY: u8 = 0x20;

/// P2 value for User PIN.
pub const P2_USER_PIN: u8 = 0x81;

/// P2 value for SO-PIN (Security Officer PIN).
pub const P2_SO_PIN: u8 = 0x88;

/// Build a retry-count status word: 0x63C0 | remaining.
fn sw_retry(remaining: u8) -> u16 {
    0x63C0 | (remaining as u16 & 0x0F)
}

/// Compute SHA-256 of `pin` and compare with `stored_hash` in constant time.
fn verify_pin_hash(pin: &[u8], stored_hash: &[u8; 32]) -> bool {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(pin);
    let computed = h.finalize();
    // Constant-time compare
    computed.as_slice().ct_eq(stored_hash).into()
}

/// Handle a VERIFY APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    if cmd.p1 != 0x00 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    match cmd.p2 {
        P2_USER_PIN => {
            // Empty data = query retry count
            if cmd.data.is_empty() {
                if state.pin_retry_count == 0 {
                    return ApduResponse::err(SW_AUTH_BLOCKED);
                }
                return ApduResponse::err(sw_retry(state.pin_retry_count));
            }

            let pin = cmd.data;
            if pin.len() < 4 || pin.len() > 16 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }

            // If blocked
            if state.pin_retry_count == 0 {
                return ApduResponse::err(SW_AUTH_BLOCKED);
            }

            let stored = match &state.user_pin_hash {
                Some(h) => *h,
                None => return ApduResponse::err(SW_SECURITY_STATUS),
            };

            if verify_pin_hash(pin, &stored) {
                state.pin_verified = true;
                state.pin_retry_count = 3;
                ApduResponse::ok(&[])
            } else {
                state.pin_verified = false;
                state.pin_retry_count = state.pin_retry_count.saturating_sub(1);
                if state.pin_retry_count == 0 {
                    ApduResponse::err(SW_AUTH_BLOCKED)
                } else {
                    ApduResponse::err(sw_retry(state.pin_retry_count))
                }
            }
        }

        P2_SO_PIN => {
            // Empty data = query retry count
            if cmd.data.is_empty() {
                if state.so_pin_retry_count == 0 {
                    return ApduResponse::err(SW_AUTH_BLOCKED);
                }
                return ApduResponse::err(sw_retry(state.so_pin_retry_count));
            }

            let pin = cmd.data;
            if pin.len() < 6 || pin.len() > 16 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }

            if state.so_pin_retry_count == 0 {
                return ApduResponse::err(SW_AUTH_BLOCKED);
            }

            let stored = match &state.so_pin_hash {
                Some(h) => *h,
                None => return ApduResponse::err(SW_SECURITY_STATUS),
            };

            if verify_pin_hash(pin, &stored) {
                state.so_pin_verified = true;
                state.so_pin_retry_count = 5;
                ApduResponse::ok(&[])
            } else {
                state.so_pin_verified = false;
                state.so_pin_retry_count = state.so_pin_retry_count.saturating_sub(1);
                if state.so_pin_retry_count == 0 {
                    ApduResponse::err(SW_AUTH_BLOCKED)
                } else {
                    ApduResponse::err(sw_retry(state.so_pin_retry_count))
                }
            }
        }

        _ => {
            // Unknown PIN reference (e.g. P2=0x85, device key reference used by
            // sc_pkcs15emu_sc_hsm_init for a status query).  Return
            // "referenced data not found" (SW=0x6A88) so OpenSC maps this to
            // SC_ERROR_DATA_OBJECT_NOT_FOUND and skips the PIN gracefully,
            // rather than SW_WRONG_DATA (0x6A80) which maps to -1205 and
            // causes sc_pkcs15emu_sc_hsm_add_prkd to abort with a fatal error.
            ApduResponse::err(0x6A88)
        }
    }
}
