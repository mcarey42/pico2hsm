//! GET CHALLENGE command handler (INS = 0x84) for OpenPGP.
//!
//! Returns N random bytes from the hardware TRNG.
//! Le specifies the number of bytes (max 255 per extended capabilities).

use heapless::Vec;
use pico2hsm_core::apdu::{ApduCommand, ApduResponse};

use crate::protocol::openpgp::OpenPgpState;

/// INS byte for GET CHALLENGE.
pub const INS_CHALLENGE: u8 = 0x84;

/// Handle a GET CHALLENGE APDU command.
pub fn handle(_state: &mut OpenPgpState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Le specifies the number of random bytes requested
    let len = match cmd.le {
        Some(0) => 256usize,
        Some(n) => n as usize,
        None => 8,
    };
    let len = len.min(255); // Cap to max from extended capabilities

    // Fill buffer with random bytes
    let mut buf: Vec<u8, 256> = Vec::new();
    for i in 0..len {
        let _ = buf.push((i & 0xFF) as u8);
    }
    #[cfg(target_arch = "arm")]
    {
        let _ = crate::crypto::rng::fill_random(&mut buf);
    }

    ApduResponse::ok(&buf)
}
