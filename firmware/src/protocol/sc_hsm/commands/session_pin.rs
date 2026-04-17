//! SESSION PIN command handler (INS = 0x26).
//!
//! Creates a one-time session PIN for a single operation without exposing
//! the full User PIN. Generates 8 random bytes, stores them in `state.session_pin`,
//! and returns them to the host. The host may then use them exactly once via
//! VERIFY with P2=0x82 to authenticate.

use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_OK, SW_SECURITY_STATUS};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for SESSION PIN.
pub const INS_SESSION_PIN: u8 = 0x26;

/// Handle a SESSION PIN APDU command.
pub fn handle(state: &mut ScHsmState, _cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN or SO-PIN to create a session PIN
    if !state.pin_verified && !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // Generate 8 random bytes
    let mut buf = [0u8; 8];
    #[cfg(target_arch = "arm")]
    {
        let _ = crate::crypto::rng::fill_random(&mut buf);
    }
    #[cfg(not(target_arch = "arm"))]
    {
        use core::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0xc0ffee1234567890u64);
        let v = CTR
            .fetch_add(0x6c62272e07bb0142u64, Ordering::Relaxed)
            .wrapping_mul(0x94d049bb133111ebu64)
            ^ 0xbf58476d1ce4e5b9u64;
        buf.copy_from_slice(&v.to_le_bytes());
    }

    // Store in state
    state.session_pin = Some(buf);

    // Return the 8 bytes to host
    ApduResponse::ok(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico2hsm_core::apdu::{ApduCommand, SW_OK, SW_SECURITY_STATUS};

    fn make_state() -> ScHsmState {
        ScHsmState::new()
    }

    fn make_cmd() -> [u8; 5] {
        // CLA=0x80 INS=0x26 P1=0x00 P2=0x00 Le=0x00
        [0x80, INS_SESSION_PIN, 0x00, 0x00, 0x00]
    }

    #[test]
    fn test_session_pin_requires_auth() {
        let mut state = make_state();
        // No PIN verified
        let apdu = make_cmd();
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &cmd);
        let sw = resp.sw;
        assert_eq!(sw, SW_SECURITY_STATUS);
    }

    #[test]
    fn test_session_pin_generates_8_bytes() {
        let mut state = make_state();
        state.pin_verified = true;
        let apdu = make_cmd();
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &cmd);
        let sw = resp.sw;
        assert_eq!(sw, SW_OK);
        assert_eq!(resp.data.len(), 8);
    }

    #[test]
    fn test_session_pin_stores_in_state() {
        let mut state = make_state();
        state.pin_verified = true;
        let apdu = make_cmd();
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let _resp = handle(&mut state, &cmd);
        assert!(state.session_pin.is_some());
    }

    #[test]
    fn test_session_pin_multiple_calls_change_value() {
        let mut state = make_state();
        state.pin_verified = true;
        let apdu = make_cmd();

        let cmd1 = ApduCommand::parse(&apdu).unwrap();
        let resp1 = handle(&mut state, &cmd1);
        let pin1 = state.session_pin.unwrap();

        let cmd2 = ApduCommand::parse(&apdu).unwrap();
        let resp2 = handle(&mut state, &cmd2);
        let pin2 = state.session_pin.unwrap();

        // PRNG should advance; the two 8-byte values must differ
        assert_ne!(pin1, pin2, "consecutive session PINs should differ");
        // Both responses should be SW_OK
        let sw1 = resp1.sw;
        let sw2 = resp2.sw;
        assert_eq!(sw1, SW_OK);
        assert_eq!(sw2, SW_OK);
    }
}
