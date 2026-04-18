//! CHANGE REFERENCE DATA command handler (INS = 0x24) for PIV.
//!
//! Changes the PIV PIN or PUK. Requires knowledge of the current value.
//!
//! # Command format
//! - CLA=0x00, INS=0x24, P1=0x00, P2=0x80 (PIN) or 0x81 (PUK)
//! - Data: <old value, 8 bytes padded> + <new value, 8 bytes padded> = 16 bytes

use pico2hsm_core::apdu::{ApduCommand, ApduResponse};

use crate::protocol::piv::PivState;

/// INS byte for CHANGE REFERENCE DATA.
pub const INS_CHANGE_REFERENCE_DATA: u8 = 0x24;

/// Strip 0xFF padding from the end of a PIV PIN buffer.
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

/// Handle CHANGE REFERENCE DATA and persist updated PIN/PUK state to flash.
pub fn handle_with_store(
    state: &mut PivState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    let resp = handle(state, cmd);
    if resp.sw == 0x9000 {
        crate::protocol::piv::Piv::save_pin_to_store(state, store);
    }
    resp
}

/// Handle a CHANGE REFERENCE DATA APDU command.
pub fn handle(state: &mut PivState, cmd: &ApduCommand<'_>) -> ApduResponse {
    if cmd.p1 != 0x00 {
        return ApduResponse::err(0x6A86);
    }

    match cmd.p2 {
        0x80 => handle_change_pin(state, cmd),
        0x81 => handle_change_puk(state, cmd),
        _ => ApduResponse::err(0x6A86),
    }
}

fn handle_change_pin(state: &mut PivState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Data must be exactly 16 bytes: old PIN (8) + new PIN (8)
    if cmd.data.len() != 16 {
        return ApduResponse::err(0x6700); // wrong length
    }

    if state.pin_state.pin_blocked {
        return ApduResponse::err(0x6983); // blocked
    }

    let old_pin = strip_pin_padding(&cmd.data[..8]);
    let new_pin = strip_pin_padding(&cmd.data[8..16]);

    // FIPS 201-2 §2.4.3: PIV PIN must contain only numeric digits (0x30–0x39).
    if old_pin.iter().any(|&b| !(0x30..=0x39).contains(&b))
        || new_pin.iter().any(|&b| !(0x30..=0x39).contains(&b))
    {
        return ApduResponse::err(0x6A80); // wrong data — non-digit byte
    }

    // Generate new salt
    let mut new_salt = [0u8; 16];
    fill_random_bytes(&mut new_salt);

    match state
        .pin_state
        .change_pin(old_pin, new_pin, &state.device_id, new_salt)
    {
        Ok(()) => ApduResponse::ok(&[]),
        Err(crate::security::pin::PinError::Locked) => ApduResponse::err(0x6983),
        Err(crate::security::pin::PinError::WrongCurrentPin) => {
            ApduResponse::err(sw_retry(state.pin_state.pin_retries_remaining))
        }
        Err(crate::security::pin::PinError::InvalidLength)
        | Err(crate::security::pin::PinError::NewPinInvalidLength) => ApduResponse::err(0x6700),
        Err(_) => ApduResponse::err(0x6985),
    }
}

fn handle_change_puk(state: &mut PivState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Data must be exactly 16 bytes: old PUK (8) + new PUK (8)
    if cmd.data.len() != 16 {
        return ApduResponse::err(0x6700);
    }

    if state.pin_state.puk_blocked {
        return ApduResponse::err(0x6983);
    }

    let old_puk = strip_pin_padding(&cmd.data[..8]);
    let new_puk = strip_pin_padding(&cmd.data[8..16]);

    // PUK change: verify old PUK, then update PUK hash
    // Use the PUK hash verification directly
    let old_puk_hash = crate::security::pin::PinState::hash_puk(
        old_puk,
        &state.device_id,
        &state.pin_state.puk_salt,
    );

    use subtle::ConstantTimeEq;
    if !bool::from(old_puk_hash.ct_eq(&state.pin_state.puk_hash)) {
        state.pin_state.puk_retries_remaining =
            state.pin_state.puk_retries_remaining.saturating_sub(1);
        if state.pin_state.puk_retries_remaining == 0 {
            state.pin_state.puk_blocked = true;
            return ApduResponse::err(0x6983);
        }
        return ApduResponse::err(sw_retry(state.pin_state.puk_retries_remaining));
    }

    // Old PUK correct - update PUK hash
    let mut new_salt = [0u8; 16];
    fill_random_bytes(&mut new_salt);

    state.pin_state.puk_salt = new_salt;
    state.pin_state.puk_hash =
        crate::security::pin::PinState::hash_puk(new_puk, &state.device_id, &new_salt);
    state.pin_state.puk_retries_remaining = crate::security::pin::MAX_PUK_RETRIES;
    state.pin_state.puk_blocked = false;

    ApduResponse::ok(&[])
}

/// Fill buffer with random bytes.
fn fill_random_bytes(buf: &mut [u8]) {
    #[cfg(target_arch = "arm")]
    {
        let _ = crate::crypto::rng::fill_random(buf);
    }
    #[cfg(not(target_arch = "arm"))]
    {
        use core::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0xdead_beef_cafe_babe_u64);
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
