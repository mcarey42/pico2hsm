//! GENERATE SYMMETRIC KEY command handler (INS = 0x48).
//!
//! Generates a symmetric key (AES-128/192/256) using the on-chip TRNG
//! and stores it in the in-memory keystore and flash.
//!
//! # Command format
//! - P1: key ID (0x01–0xFE)
//! - SmartCard-HSM form: P2 = B0 / B1 / B2 (AES-128 / 192 / 256), data =
//!   optional key attributes (`90` use counter, `91` algorithm list, `92`
//!   key domain; see `key_policy`).
//! - pico2hsm legacy form: P2 = 00, data = one-byte size tag 0x82 / 0x83 /
//!   0x84 (AES-128 / 192 / 256), then the same optional attributes.

use pico2hsm_core::{
    apdu::{
        ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_OK, SW_SECURITY_STATUS,
        SW_WRONG_DATA,
    },
    key::{AppletId, KeyId},
};

use crate::protocol::sc_hsm::{KeyMeta, ScHsmState};
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

    // Key size and the key attributes (tags 90/91/92):
    // - SmartCard-HSM: P2 = B0/B1/B2 (AES-128/192/256), data = attributes;
    // - pico2hsm legacy: P2 = 00, data = 82/83/84 then attributes.
    let (key_len, attrs): (usize, &[u8]) = match cmd.p2 {
        0xB0 => (16, cmd.data),
        0xB1 => (24, cmd.data),
        0xB2 => (32, cmd.data),
        _ => match cmd.data.split_first() {
            Some((0x82, rest)) => (16, rest),
            Some((0x83, rest)) => (24, rest),
            Some((0x84, rest)) => (32, rest),
            _ => return ApduResponse::err(SW_WRONG_DATA),
        },
    };
    let policy = match crate::security::key_policy::KeyPolicy::from_creation_tlvs(attrs) {
        Ok(p) => p,
        Err(sw) => return ApduResponse::err(sw),
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

    // Determine the AES key type for metadata.
    let aes_key_type = match key_len {
        16 => pico2hsm_core::key::KeyType::Aes128,
        24 => pico2hsm_core::key::KeyType::Aes192,
        32 => pico2hsm_core::key::KeyType::Aes256,
        _ => unreachable!(),
    };

    // Persist to flash: build a KeyObject
    let mut obj = KeyObject::new(KeyType::Aes, full_key_id, AppletId::ScHsm, algo);
    obj.key_domain = policy.domain.unwrap_or(0);
    obj.policy = policy;
    let copied = obj.private_key.extend_from_slice(&key_buf[..key_len]);
    zeroize::Zeroize::zeroize(&mut key_buf);
    if copied.is_err() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Storage errors fail closed.
    if store.save_key(&obj).is_err() {
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    }

    // Update key_index metadata (replace any existing entry).
    state.key_index.retain(|m| m.key_id != full_key_id);
    let _ = state.key_index.push(KeyMeta {
        key_id: full_key_id,
        key_type: aes_key_type as u8,
        algo: algo as u8,
        key_flags: 0,
    });

    ApduResponse::ok(&[])
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sc_hsm::ScHsmState;
    use crate::storage::NullKeyStore;
    use pico2hsm_core::apdu::ApduCommand;

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
        let meta = state
            .key_index
            .iter()
            .find(|m| m.key_id == full_id)
            .unwrap();
        assert_eq!(meta.key_type, pico2hsm_core::key::KeyType::Aes128 as u8);
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
        let meta = state
            .key_index
            .iter()
            .find(|m| m.key_id == full_id)
            .unwrap();
        assert_eq!(meta.key_type, pico2hsm_core::key::KeyType::Aes256 as u8);
    }

    #[test]
    fn test_generate_key_replaces_existing() {
        let mut state = make_state_authed();
        let mut store = NullKeyStore;
        let raw = gen_key_cmd(0x02, 0x84);
        let cmd = ApduCommand::parse(&raw).unwrap();
        handle(&mut state, &mut store, &cmd);
        let full_id = KeyId::sc_hsm(0, 0x02).0;
        assert_eq!(
            state
                .key_index
                .iter()
                .filter(|m| m.key_id == full_id)
                .count(),
            1
        );

        // Generate again — should replace, not duplicate
        let cmd2 = ApduCommand::parse(&raw).unwrap();
        handle(&mut state, &mut store, &cmd2);
        assert_eq!(
            state
                .key_index
                .iter()
                .filter(|m| m.key_id == full_id)
                .count(),
            1
        );
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
