//! EXTERNAL AUTHENTICATE command handler (INS = 0x82).
//!
//! Authenticates an external entity (host application) to the HSM using
//! a challenge-response mechanism. The host signs the challenge returned
//! by GET CHALLENGE using a key known to both parties.

use subtle::ConstantTimeEq;

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_AUTH_BLOCKED, SW_CONDITIONS_NOT_SATISFIED, SW_OK,
    SW_SECURITY_STATUS, SW_WRONG_LENGTH,
};

use crate::protocol::sc_hsm::ScHsmState;
use crate::security::anti_glitch::{double_check, DoubleCheckResult};

/// INS byte for EXTERNAL AUTHENTICATE.
pub const INS_EXTERNAL_AUTH: u8 = 0x82;

/// Build a retry-count status word: 0x63C0 | remaining.
fn sw_retry(remaining: u8) -> u16 {
    0x63C0 | (remaining as u16 & 0x0F)
}

/// Handle an EXTERNAL AUTHENTICATE APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Empty data = query remaining retry count (P1-5).
    if cmd.data.is_empty() {
        if state.ext_auth_retry_count == 0 {
            return ApduResponse::err(SW_AUTH_BLOCKED);
        }
        return ApduResponse::err(sw_retry(state.ext_auth_retry_count));
    }

    // Check retry counter before processing (P1-5: brute-force lockout).
    if state.ext_auth_retry_count == 0 {
        return ApduResponse::err(SW_AUTH_BLOCKED);
    }

    // A challenge must have been issued previously via GET CHALLENGE.
    if state.challenge.is_none() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Retrieve and clear the challenge (replay prevention — always cleared).
    let challenge_bytes = state.challenge.take().unwrap();

    // SO PIN hash must be set to perform authentication.
    let so_pin_hash = match state.so_pin_hash {
        Some(ref h) => *h,
        None => {
            return ApduResponse::err(SW_SECURITY_STATUS);
        }
    };

    // Response must be exactly 32 bytes (HMAC-SHA256 output).
    if cmd.data.len() != 32 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }

    // Compute expected HMAC-SHA256(so_pin_hash, challenge).
    let expected = crate::crypto::kdf::hmac_sha256(&so_pin_hash, &challenge_bytes);

    // Constant-time comparison to prevent timing attacks.
    let ok1 = expected.ct_eq(cmd.data).into();
    // Double-check evaluation for fault injection resistance (P1-2).
    let ok2 = crate::crypto::kdf::hmac_sha256(&so_pin_hash, &challenge_bytes).ct_eq(cmd.data).into();
    if double_check(ok1, ok2) == DoubleCheckResult::Mismatch {
        // Possible fault injection — decrement counter and refuse.
        state.ext_auth_retry_count = state.ext_auth_retry_count.saturating_sub(1);
        state.so_pin_verified = false;
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    if ok1 {
        state.so_pin_verified = true;
        state.ext_auth_retry_count = 5; // Reset on success.
        ApduResponse::ok(&[])
    } else {
        // Wrong cryptogram — decrement retry counter (P1-5).
        state.ext_auth_retry_count = state.ext_auth_retry_count.saturating_sub(1);
        state.so_pin_verified = false;
        if state.ext_auth_retry_count == 0 {
            ApduResponse::err(SW_AUTH_BLOCKED)
        } else {
            ApduResponse::err(sw_retry(state.ext_auth_retry_count))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sc_hsm::ScHsmState;
    use pico2hsm_core::apdu::ApduCommand;

    fn make_cmd<'a>(data: &'a [u8]) -> ApduCommand<'a> {
        ApduCommand {
            cla: 0x00,
            ins: INS_EXTERNAL_AUTH,
            p1: 0x00,
            p2: 0x00,
            data,
            le: None,
        }
    }

    #[test]
    fn test_ext_auth_no_challenge() {
        let mut state = ScHsmState::new();
        // No challenge set
        assert!(state.challenge.is_none());
        let cmd = make_cmd(&[0u8; 32]);
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_ext_auth_no_so_pin_hash() {
        let mut state = ScHsmState::new();
        state.challenge = Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        // No so_pin_hash set
        assert!(state.so_pin_hash.is_none());
        let cmd = make_cmd(&[0u8; 32]);
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_SECURITY_STATUS);
        // Challenge must be cleared after attempt
        assert!(state.challenge.is_none());
    }

    #[test]
    fn test_ext_auth_wrong_length() {
        let mut state = ScHsmState::new();
        state.challenge = Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        state.so_pin_hash = Some([0xABu8; 32]);
        // Only 16 bytes instead of required 32
        let cmd = make_cmd(&[0u8; 16]);
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_WRONG_LENGTH);
        // Challenge must be cleared after attempt
        assert!(state.challenge.is_none());
    }

    #[test]
    fn test_ext_auth_wrong_cryptogram() {
        let mut state = ScHsmState::new();
        state.challenge = Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        state.so_pin_hash = Some([0xABu8; 32]);
        // 32 bytes but all wrong
        let cmd = make_cmd(&[0xFFu8; 32]);
        let resp = handle(&mut state, &cmd);
        // Wrong cryptogram now returns retry count SW (P1-5: brute-force lockout).
        // Initial retry count is 5, so after one failure it returns 63C4 (4 remaining).
        assert_eq!(resp.sw, 0x63C4);
        // Retry counter decremented.
        assert_eq!(state.ext_auth_retry_count, 4);
        // so_pin_verified must remain false
        assert!(!state.so_pin_verified);
    }

    #[test]
    fn test_ext_auth_correct_cryptogram() {
        let mut state = ScHsmState::new();
        let key = [0xABu8; 32]; // so_pin_hash
        let challenge = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        state.challenge = Some(challenge);
        state.so_pin_hash = Some(key);

        // Compute expected response the same way the device does
        let expected = crate::crypto::kdf::hmac_sha256(&key, &challenge);

        let cmd = make_cmd(&expected);
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_OK);
        assert!(state.so_pin_verified);
    }
}
