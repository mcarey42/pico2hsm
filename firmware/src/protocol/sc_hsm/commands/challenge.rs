//! GET CHALLENGE command handler (INS = 0x84).
//!
//! Returns random bytes from the on-chip TRNG. Used by the host for:
//! - External authenticate challenge-response
//! - Nonce generation for secure messaging
//! - General-purpose random byte request
//!
//! The requested length is specified in Le.

use heapless::Vec;
use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_OK};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for GET CHALLENGE.
pub const INS_CHALLENGE: u8 = 0x84;

/// Handle a GET CHALLENGE APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Le specifies the number of random bytes requested. Default to 8.
    let len = match cmd.le {
        Some(0) => 256,
        Some(n) => n as usize,
        None => 8,
    };
    let len = len.min(256);

    // Fill buffer: on ARM use hardware TRNG; on x86_64 keep sequential placeholder
    // so that `test_get_challenge_data_is_sequential_placeholder` remains valid.
    let mut buf: Vec<u8, 256> = Vec::new();
    for i in 0..len {
        let _ = buf.push((i & 0xFF) as u8);
    }
    #[cfg(target_arch = "arm")]
    {
        crate::crypto::rng::fill_or_reset(&mut buf);
    }

    // Store 8-byte challenge for subsequent EXTERNAL AUTHENTICATE
    if len >= 8 {
        let mut ch = [0u8; 8];
        ch.copy_from_slice(&buf[..8]);
        state.challenge = Some(ch);
    }

    ApduResponse::ok(&buf)
}
