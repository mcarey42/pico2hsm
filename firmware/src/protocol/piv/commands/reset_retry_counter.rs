//! RESET RETRY COUNTER command handler (INS = 0x2C) for PIV.
//!
//! Resets the PIN using the PUK, simultaneously setting a new PIN value.
//!
//! # Command format
//! - CLA=0x00, INS=0x2C, P1=0x00, P2=0x80
//! - Data: <PUK, 8 bytes padded> + <new PIN, 8 bytes padded> = 16 bytes

use pico2hsm_core::apdu::{ApduCommand, ApduResponse};

use crate::protocol::piv::PivState;

/// INS byte for RESET RETRY COUNTER.
pub const INS_RESET_RETRY_COUNTER: u8 = 0x2C;

/// Strip 0xFF padding from the end of a PIV PIN/PUK buffer.
fn strip_pin_padding(padded: &[u8]) -> &[u8] {
    let mut end = padded.len();
    while end > 0 && padded[end - 1] == 0xFF {
        end -= 1;
    }
    &padded[..end]
}

/// Build a retry-count status word: 0x63C0 | remaining.
fn sw_retry(remaining: u8) -> u16 {
    0x63C0 | (remaining as u16 & 0x0F)
}

/// Handle a RESET RETRY COUNTER APDU command.
pub fn handle(state: &mut PivState, cmd: &ApduCommand<'_>) -> ApduResponse {
    if cmd.p1 != 0x00 {
        return ApduResponse::err(0x6A86);
    }

    if cmd.p2 != 0x80 {
        return ApduResponse::err(0x6A86);
    }

    // Data must be exactly 16 bytes: PUK (8) + new PIN (8)
    if cmd.data.len() != 16 {
        return ApduResponse::err(0x6700); // wrong length
    }

    let puk = strip_pin_padding(&cmd.data[..8]);
    let new_pin = strip_pin_padding(&cmd.data[8..16]);

    // Generate new salt for the PIN
    let mut new_salt = [0u8; 16];
    fill_random_bytes(&mut new_salt);

    match state
        .pin_state
        .unblock_pin(puk, new_pin, &state.device_id, new_salt)
    {
        Ok(()) => {
            state.pin_verified = false; // Reset session auth after unblock
            ApduResponse::ok(&[])
        }
        Err(crate::security::pin::PinError::PukLocked) => {
            ApduResponse::err(0x6983) // PUK blocked
        }
        Err(crate::security::pin::PinError::WrongCurrentPin) => {
            if state.pin_state.puk_blocked {
                ApduResponse::err(0x6983)
            } else {
                ApduResponse::err(sw_retry(state.pin_state.puk_retries_remaining))
            }
        }
        Err(crate::security::pin::PinError::InvalidLength)
        | Err(crate::security::pin::PinError::NewPinInvalidLength) => ApduResponse::err(0x6700),
        Err(_) => ApduResponse::err(0x6985),
    }
}

/// Fill buffer with random bytes.
fn fill_random_bytes(buf: &mut [u8]) {
    #[cfg(target_arch = "arm")]
    {
        crate::crypto::rng::fill_or_reset(buf);
    }
    #[cfg(not(target_arch = "arm"))]
    {
        use core::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0xcafe_d00d_1234_5678_u64);
        for chunk in buf.chunks_mut(8) {
            let v = CTR
                .fetch_add(0x6c62272e07bb0142u64, Ordering::Relaxed)
                .wrapping_mul(0x94d049bb133111ebu64)
                ^ 0xbf58476d1ce4e5b9u64;
            let vb = v.to_le_bytes();
            chunk.copy_from_slice(&vb[..chunk.len()]);
        }
    }
}
