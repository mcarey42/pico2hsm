//! PUK AUTHENTICATE command handler (INS = 0x28).
//!
//! Authenticates using the PUK (PIN Unblocking Key) to unlock the device
//! after all User PIN retry attempts have been exhausted.

use subtle::ConstantTimeEq;

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_AUTH_BLOCKED, SW_CONDITIONS_NOT_SATISFIED, SW_OK, SW_WRONG_LENGTH,
};

use crate::protocol::sc_hsm::ScHsmState;
use crate::security::pin::PinState;

/// INS byte for PUK AUTHENTICATE.
pub const INS_PUK_AUTH: u8 = 0x28;

/// Compute PBKDF2-HMAC-SHA256 of `puk` using `salt` (P1-1 fix).
fn hash_puk_pbkdf2(puk: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    PinState::hash_puk(puk, b"pico2hsm-device", salt)
}

/// Handle a PUK AUTHENTICATE APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    let puk = cmd.data;
    if puk.len() < 8 || puk.len() > 16 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }

    // No PUK configured.
    let stored_hash = match state.puk_hash {
        Some(h) => h,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // PUK is blocked.
    if state.puk_retry_count == 0 {
        return ApduResponse::err(SW_AUTH_BLOCKED);
    }

    // Compute PBKDF2 of the submitted PUK and compare (P1-1 fix).
    let computed = hash_puk_pbkdf2(puk, &state.puk_salt);

    // Constant-time compare.
    let matches: bool = computed.ct_eq(&stored_hash).into();

    if matches {
        state.puk_retry_count = 10;
        state.pin_retry_count = 3;
        state.pin_verified = true;
        ApduResponse::ok(&[])
    } else {
        state.puk_retry_count = state.puk_retry_count.saturating_sub(1);
        if state.puk_retry_count == 0 {
            ApduResponse::err(SW_AUTH_BLOCKED)
        } else {
            ApduResponse::err(0x63C0 | (state.puk_retry_count as u16 & 0x0F))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sc_hsm::ScHsmState;
    use pico2hsm_core::apdu::{
        SW_AUTH_BLOCKED, SW_CONDITIONS_NOT_SATISFIED, SW_OK, SW_WRONG_LENGTH,
    };

    /// Build a PUK AUTHENTICATE APDU.
    fn make_puk_apdu(puk: &[u8]) -> heapless::Vec<u8, 32> {
        let mut apdu: heapless::Vec<u8, 32> = heapless::Vec::new();
        let _ = apdu.extend_from_slice(&[0x00, INS_PUK_AUTH, 0x00, 0x00]);
        let _ = apdu.push(puk.len() as u8);
        let _ = apdu.extend_from_slice(puk);
        apdu
    }

    /// Create a state with a stored PUK hash for the given PUK bytes (using PBKDF2).
    fn make_state_with_puk(puk: &[u8]) -> ScHsmState {
        let salt = [0xBBu8; 16]; // deterministic test salt
        let mut state = ScHsmState::new();
        state.puk_salt = salt;
        state.puk_hash = Some(hash_puk_pbkdf2(puk, &salt));
        state
    }

    #[test]
    fn test_puk_auth_wrong_length() {
        let mut state = ScHsmState::new();
        // PUK shorter than 8 bytes -> SW_WRONG_LENGTH
        let apdu = make_puk_apdu(&[0x01, 0x02, 0x03]);
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &cmd);
        let sw = resp.sw;
        assert_eq!(sw, SW_WRONG_LENGTH);
    }

    #[test]
    fn test_puk_auth_no_puk_configured() {
        let mut state = ScHsmState::new();
        // puk_hash is None
        let apdu = make_puk_apdu(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &cmd);
        let sw = resp.sw;
        assert_eq!(sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_puk_auth_blocked() {
        let puk = b"MYPUK123";
        let mut state = make_state_with_puk(puk);
        state.puk_retry_count = 0;

        let apdu = make_puk_apdu(puk);
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &cmd);
        let sw = resp.sw;
        assert_eq!(sw, SW_AUTH_BLOCKED);
    }

    #[test]
    fn test_puk_auth_wrong_puk_decrements_counter() {
        let puk = b"MYPUK123";
        let mut state = make_state_with_puk(puk);
        let initial_count = state.puk_retry_count;

        let wrong_puk = b"WRONGPUK";
        let apdu = make_puk_apdu(wrong_puk);
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &cmd);
        let sw = resp.sw;

        // Should return retry count SW and decrement counter.
        assert_ne!(sw, SW_OK);
        assert_eq!(state.puk_retry_count, initial_count - 1);
        // SW should encode remaining retries: 0x63C0 | remaining
        assert_eq!(sw, 0x63C0 | (state.puk_retry_count as u16 & 0x0F));
    }

    #[test]
    fn test_puk_auth_correct_puk_unblocks_pin() {
        let puk = b"MYPUK123";
        let mut state = make_state_with_puk(puk);
        // Simulate a blocked user PIN.
        state.pin_retry_count = 0;
        state.pin_verified = false;

        let apdu = make_puk_apdu(puk);
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &cmd);
        let sw = resp.sw;

        assert_eq!(sw, SW_OK);
        assert_eq!(state.pin_retry_count, 3);
        assert!(state.pin_verified);
    }

    #[test]
    fn test_puk_auth_correct_puk_resets_puk_counter() {
        let puk = b"MYPUK123";
        let mut state = make_state_with_puk(puk);
        // Simulate some failed attempts.
        state.puk_retry_count = 5;

        let apdu = make_puk_apdu(puk);
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &cmd);
        let sw = resp.sw;

        assert_eq!(sw, SW_OK);
        assert_eq!(state.puk_retry_count, 10);
    }

    #[test]
    fn test_puk_auth_lockout_at_zero() {
        let puk = b"MYPUK123";
        let mut state = make_state_with_puk(puk);
        let wrong_puk = b"WRONGPUK";

        // Submit wrong PUK until counter reaches 0.
        loop {
            let apdu = make_puk_apdu(wrong_puk);
            let cmd = ApduCommand::parse(&apdu).unwrap();
            let resp = handle(&mut state, &cmd);
            let sw = resp.sw;
            if sw == SW_AUTH_BLOCKED {
                break;
            }
            assert_eq!(state.puk_retry_count, sw as u8 & 0x0F);
        }
        assert_eq!(state.puk_retry_count, 0);

        // Now even with the correct PUK it should still be blocked.
        let apdu = make_puk_apdu(puk);
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &cmd);
        let sw = resp.sw;
        assert_eq!(sw, SW_AUTH_BLOCKED);
    }
}
