//! GENERATE SYMMETRIC KEY command handler (INS = 0x48).
//!
//! Generates a symmetric key (AES-128/192/256) using the on-chip TRNG
//! and stores it in the in-memory keystore and flash.
//!
//! # Command format
//! - P1: key ID (0x01–0xFE)
//! - P2: 0x00
//! - Data: one-byte algorithm tag:
//!   - 0x82: AES-128 (16 bytes)
//!   - 0x83: AES-192 (24 bytes)
//!   - 0x84: AES-256 (32 bytes)

use pico2hsm_core::{
    apdu::{ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_OK, SW_SECURITY_STATUS, SW_WRONG_DATA},
    key::{AppletId, KeyId},
};

use crate::protocol::sc_hsm::{InMemorySymKey, ScHsmState};
use crate::security::key_management::{AlgorithmId, KeyObject, KeyType};

/// INS byte for GENERATE SYMMETRIC KEY.
pub const INS_GENERATE_KEY: u8 = 0x48;

/// Handle a GENERATE SYMMETRIC KEY APDU command.
pub fn handle(
    state: &mut ScHsmState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let key_id_proto = cmd.p1;
    if key_id_proto == 0x00 || key_id_proto == 0xFF {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Data field must contain the algorithm tag
    let algo_tag = match cmd.data.first().copied() {
        Some(t @ (0x82 | 0x83 | 0x84)) => t,
        _ => return ApduResponse::err(SW_WRONG_DATA),
    };

    let key_len: usize = match algo_tag {
        0x82 => 16,
        0x83 => 24,
        0x84 => 32,
        _ => unreachable!(),
    };

    // Generate random key bytes
    let mut key_buf = [0u8; 32];
    {
        #[cfg(target_arch = "arm")]
        {
            if crate::crypto::rng::fill_random(&mut key_buf[..key_len]).is_err() {
                return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        #[cfg(not(target_arch = "arm"))]
        {
            use core::sync::atomic::{AtomicU64, Ordering};
            static CTR: AtomicU64 = AtomicU64::new(0xdeadbeefcafe1234u64);
            for chunk in key_buf[..key_len].chunks_mut(8) {
                let v = CTR
                    .fetch_add(0x6c62272e07bb0142u64, Ordering::Relaxed)
                    .wrapping_mul(0x94d049bb133111ebu64)
                    ^ 0xbf58476d1ce4e5b9u64;
                let vb = v.to_le_bytes();
                chunk.copy_from_slice(&vb[..chunk.len()]);
            }
        }
    }

    let full_key_id = KeyId::sc_hsm(0, key_id_proto).0;
    let algo = AlgorithmId::AesGcm; // canonical AES algorithm tag for storage

    // Build in-memory symmetric key entry (replace any existing slot)
    let mut raw_key: heapless::Vec<u8, 32> = heapless::Vec::new();
    raw_key.extend_from_slice(&key_buf[..key_len]).ok();

    // Replace existing entry with same key_id, or push a new one
    let existing = state.sym_keys.iter_mut().find(|k| k.key_id == full_key_id);
    if let Some(slot) = existing {
        slot.raw_key = raw_key.clone();
    } else if state.sym_keys.push(InMemorySymKey { key_id: full_key_id, raw_key: raw_key.clone() }).is_err() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Persist to flash: build a KeyObject
    let mut obj = KeyObject::new(KeyType::Aes, full_key_id, AppletId::ScHsm, algo);
    obj.private_key.extend_from_slice(&key_buf[..key_len]).ok();

    if store.save_key(&obj).is_err() {
        // Flash write failed — remove from in-memory store to keep consistency
        state.sym_keys.retain(|k| k.key_id != full_key_id);
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    ApduResponse::ok(&[])
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pico2hsm_core::apdu::ApduCommand;
    use crate::protocol::sc_hsm::ScHsmState;
    use crate::storage::NullKeyStore;

    fn make_state_authed() -> ScHsmState {
        let mut s = ScHsmState::new();
        s.pin_verified = true;
        s.initialized = true;
        s
    }

    fn gen_key_cmd(key_id: u8, algo_tag: u8) -> [u8; 6] {
        [0x00, INS_GENERATE_KEY, key_id, 0x00, 0x01, algo_tag]
    }

    #[test]
    fn test_generate_key_requires_pin() {
        let mut state = ScHsmState::new();
        let mut store = NullKeyStore;
        let raw = gen_key_cmd(0x01, 0x84);
        let cmd = ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_SECURITY_STATUS);
    }

    #[test]
    fn test_generate_key_wrong_algo() {
        let mut state = make_state_authed();
        let mut store = NullKeyStore;
        let raw = gen_key_cmd(0x01, 0x99);
        let cmd = ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_WRONG_DATA);
    }

    #[test]
    fn test_generate_key_aes128() {
        let mut state = make_state_authed();
        let mut store = NullKeyStore;
        let raw = gen_key_cmd(0x01, 0x82);
        let cmd = ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_OK);
        let full_id = KeyId::sc_hsm(0, 0x01).0;
        let sk = state.sym_keys.iter().find(|k| k.key_id == full_id).unwrap();
        assert_eq!(sk.raw_key.len(), 16);
    }

    #[test]
    fn test_generate_key_aes256() {
        let mut state = make_state_authed();
        let mut store = NullKeyStore;
        let raw = gen_key_cmd(0x05, 0x84);
        let cmd = ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_OK);
        let full_id = KeyId::sc_hsm(0, 0x05).0;
        let sk = state.sym_keys.iter().find(|k| k.key_id == full_id).unwrap();
        assert_eq!(sk.raw_key.len(), 32);
    }

    #[test]
    fn test_generate_key_replaces_existing() {
        let mut state = make_state_authed();
        let mut store = NullKeyStore;
        let raw = gen_key_cmd(0x02, 0x84);
        let cmd = ApduCommand::parse(&raw).unwrap();
        handle(&mut state, &mut store, &cmd);
        let key1 = {
            let full_id = KeyId::sc_hsm(0, 0x02).0;
            state.sym_keys.iter().find(|k| k.key_id == full_id).unwrap().raw_key.clone()
        };
        // Generate again — should replace, not duplicate
        let cmd2 = ApduCommand::parse(&raw).unwrap();
        handle(&mut state, &mut store, &cmd2);
        let full_id = KeyId::sc_hsm(0, 0x02).0;
        assert_eq!(state.sym_keys.iter().filter(|k| k.key_id == full_id).count(), 1);
        let key2 = state.sym_keys.iter().find(|k| k.key_id == full_id).unwrap().raw_key.clone();
        // Keys should differ (PRNG advances)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_generate_key_invalid_id() {
        let mut state = make_state_authed();
        let mut store = NullKeyStore;
        // key_id 0x00 is invalid
        let raw = gen_key_cmd(0x00, 0x84);
        let cmd = ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_WRONG_DATA);
    }
}
