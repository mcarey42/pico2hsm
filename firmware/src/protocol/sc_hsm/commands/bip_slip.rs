//! BIP32/SLIP-0010 HD KEY DERIVE command handler (INS = 0x60).
//!
//! Derives a child key from a stored BIP32 master key using BIP32 or SLIP-0010.
//!
//! # Command data
//! - P1: source master key ID
//! - P2: flags (bit 0 = store derived key, bit 1 = return public key)
//! - Data: derivation path (sequence of 4-byte index values, MSB = hardened)

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND, SW_SECURITY_STATUS,
    SW_WRONG_DATA,
};
use pico2hsm_core::key::{KeyId, KeyMaterial, KeyType};

use crate::protocol::sc_hsm::ScHsmState;
use crate::storage::KeyStore;

/// INS byte for BIP32/SLIP-0010 HD KEY DERIVE.
pub const INS_BIP_SLIP: u8 = 0x60;

/// Convert a `KeyType` discriminant (u8) back to the enum variant.
fn key_type_from_u8(v: u8) -> Option<KeyType> {
    // Discriminant order matches the enum declaration in pico2hsm-core/src/key.rs.
    match v {
        0 => Some(KeyType::RsaPrivate2048),
        1 => Some(KeyType::RsaPrivate4096),
        2 => Some(KeyType::EcPrivateP256),
        3 => Some(KeyType::EcPrivateP384),
        4 => Some(KeyType::EcPrivateP521),
        5 => Some(KeyType::EcPrivateK256),
        6 => Some(KeyType::EcPrivateBrainpoolP256),
        7 => Some(KeyType::EcPrivateBrainpoolP384),
        8 => Some(KeyType::EcPrivateBrainpoolP512),
        9 => Some(KeyType::Aes128),
        10 => Some(KeyType::Aes192),
        11 => Some(KeyType::Aes256),
        12 => Some(KeyType::Bip32Master),
        13 => Some(KeyType::Ed25519),
        14 => Some(KeyType::X25519),
        15 => Some(KeyType::RsaPrivate3072),
        16 => Some(KeyType::EfFile),
        _ => None,
    }
}

/// Handle a BIP32/SLIP-0010 HD KEY DERIVE APDU command.
pub fn handle(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let master_key_id = cmd.p1;

    // Derivation path must be a multiple of 4 bytes
    if cmd.data.len() % 4 != 0 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Locate the master key via key_index metadata + flash store
    let full_key_id = KeyId::sc_hsm(0, master_key_id).0;

    let meta = match state.key_index.iter().find(|m| m.key_id == full_key_id) {
        Some(m) => *m,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    let key_obj = match store.fetch_key(KeyId(full_key_id)) {
        Ok(Some(obj)) => obj,
        _ => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // The response is a private key (the child, or the master itself for an
    // empty path), so this is an export: honour NO_EXPORT, and never hand
    // back the master key.
    if key_obj.key_flags & super::export_key::NO_EXPORT_BIT != 0 {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }
    if cmd.data.is_empty() {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    let key_type = match key_type_from_u8(meta.key_type) {
        Some(kt) => kt,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    let raw_key = {
        let mut v = crate::security::zeroize::WipeOnDrop::<66>::new();
        if v.extend_from_slice(&key_obj.private_key).is_err() {
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
        v
    };

    // BIP32 master keys must be exactly 64 bytes (key || chain_code)
    if raw_key.len() != 64 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Parse the derivation path
    let mut path: heapless::Vec<u32, 16> = heapless::Vec::new();
    for chunk in cmd.data.chunks(4) {
        let index = u32::from_be_bytes(chunk.try_into().unwrap());
        if path.push(index).is_err() {
            return ApduResponse::err(SW_WRONG_DATA);
        }
    }

    // Build a KeyMaterial for the master key
    let mut master_raw: heapless::Vec<u8, { pico2hsm_core::key::MAX_KEY_BYTES }> =
        heapless::Vec::new();
    if master_raw.extend_from_slice(&raw_key).is_err() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    let master = KeyMaterial {
        key_type,
        key_id: KeyId(full_key_id),
        raw: master_raw,
    };

    // Dispatch to BIP32 or SLIP-0010 based on key type
    let derived = match key_type {
        KeyType::Bip32Master | KeyType::EcPrivateK256 => {
            crate::crypto::kdf::bip32_derive(&master, &path)
        }
        KeyType::EcPrivateP256 => crate::crypto::kdf::slip10_derive(&master, &path),
        _ => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    match derived {
        Ok(km) => ApduResponse::ok(&km.raw),
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pico2hsm_core::{
        apdu::{SW_FILE_NOT_FOUND, SW_OK, SW_SECURITY_STATUS, SW_WRONG_DATA},
        error::HsmError,
        key::{AppletId, KeyId, KeyType as CoreKeyType},
    };

    use crate::protocol::sc_hsm::{KeyMeta, ScHsmState};
    use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};
    use crate::storage::KeyStore;

    struct TestStore {
        keys: heapless::Vec<KeyObject, 4>,
    }
    impl TestStore {
        fn new() -> Self {
            TestStore {
                keys: heapless::Vec::new(),
            }
        }
    }
    impl KeyStore for TestStore {
        fn save_key(&mut self, obj: &KeyObject) -> Result<(), HsmError> {
            self.keys.retain(|k| k.key_id != obj.key_id);
            let mut copy = KeyObject::new(obj.key_type, obj.key_id, obj.owner, obj.algorithm);
            copy.key_flags = obj.key_flags;
            let _ = copy.private_key.extend_from_slice(&obj.private_key);
            let _ = copy.public_key.extend_from_slice(&obj.public_key);
            let _ = self.keys.push(copy);
            Ok(())
        }
        fn fetch_key(&mut self, key_id: KeyId) -> Result<Option<KeyObject>, HsmError> {
            if let Some(obj) = self.keys.iter().find(|k| k.key_id == key_id.0) {
                let mut copy = KeyObject::new(obj.key_type, obj.key_id, obj.owner, obj.algorithm);
                copy.key_flags = obj.key_flags;
                let _ = copy.private_key.extend_from_slice(&obj.private_key);
                let _ = copy.public_key.extend_from_slice(&obj.public_key);
                return Ok(Some(copy));
            }
            Ok(None)
        }
        fn erase_key(&mut self, key_id: KeyId) -> Result<(), HsmError> {
            self.keys.retain(|k| k.key_id != key_id.0);
            Ok(())
        }
        fn wipe_all(&mut self) -> Result<(), HsmError> {
            self.keys.clear();
            Ok(())
        }
        fn wipe_by_owner(&mut self, _: AppletId) -> Result<(), HsmError> {
            Ok(())
        }
        fn enumerate_keys(&self) -> heapless::Vec<KeyId, 64> {
            heapless::Vec::new()
        }
        fn for_each_key(&self, _f: &mut dyn FnMut(KeyId)) {}
    }

    /// Build a minimal APDU raw buffer: [CLA, INS, P1, P2, Lc, data...]
    fn make_apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> heapless::Vec<u8, 256> {
        let mut v: heapless::Vec<u8, 256> = heapless::Vec::new();
        v.push(0x00).unwrap(); // CLA
        v.push(ins).unwrap(); // INS
        v.push(p1).unwrap(); // P1
        v.push(p2).unwrap(); // P2
        v.push(data.len() as u8).unwrap(); // Lc
        v.extend_from_slice(data).unwrap();
        v
    }

    /// Build a BIP/SLIP APDU with a given master key ID and path bytes.
    fn bip_apdu(master_id: u8, path_bytes: &[u8]) -> heapless::Vec<u8, 256> {
        make_apdu(INS_BIP_SLIP, master_id, 0x00, path_bytes)
    }

    /// Encode a derivation path (slice of u32) as big-endian bytes.
    fn encode_path(path: &[u32]) -> heapless::Vec<u8, 64> {
        let mut v: heapless::Vec<u8, 64> = heapless::Vec::new();
        for &index in path {
            v.extend_from_slice(&index.to_be_bytes()).unwrap();
        }
        v
    }

    /// Build a state + store with a BIP32 master key (64 bytes = key || chain).
    fn make_state_with_bip32_master(
        key_proto_ref: u8,
        key_bytes: &[u8],
    ) -> (ScHsmState, TestStore) {
        let mut state = ScHsmState::new();
        state.pin_verified = true;

        let full_key_id = KeyId::sc_hsm(0, key_proto_ref).0;

        // Add metadata to key_index
        state
            .key_index
            .push(KeyMeta {
                key_id: full_key_id,
                key_type: CoreKeyType::Bip32Master as u8,
                algo: 0x00,
                key_flags: 0,
            })
            .unwrap();

        // Add key material to store
        let mut store = TestStore::new();
        let mut obj = KeyObject::new(
            KmType::Ec,
            full_key_id,
            AppletId::ScHsm,
            AlgorithmId::EcdsaP256,
        );
        let _ = obj.private_key.extend_from_slice(key_bytes);
        let _ = store.keys.push(obj);

        (state, store)
    }

    /// SLIP-0010 test vector 1 master (seed = 000102030405060708090a0b0c0d0e0f)
    fn slip10_tv1_master() -> ([u8; 32], [u8; 32]) {
        let master_key =
            hex::decode("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
                .unwrap();
        let master_chain =
            hex::decode("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508")
                .unwrap();
        let mut k = [0u8; 32];
        let mut c = [0u8; 32];
        k.copy_from_slice(&master_key);
        c.copy_from_slice(&master_chain);
        (k, c)
    }

    fn make_state_tv1(proto_ref: u8) -> (ScHsmState, TestStore) {
        let (k, c) = slip10_tv1_master();
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&k);
        combined[32..].copy_from_slice(&c);
        make_state_with_bip32_master(proto_ref, &combined)
    }

    // -----------------------------------------------------------------------
    // Error path tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_bip_slip_requires_pin() {
        let mut state = ScHsmState::new();
        let mut store = TestStore::new();
        // pin_verified = false (default)
        let raw = bip_apdu(0x01, &[]);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_SECURITY_STATUS);
    }

    #[test]
    fn test_bip_slip_wrong_data_len() {
        let (k, c) = slip10_tv1_master();
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&k);
        combined[32..].copy_from_slice(&c);
        let (mut state, mut store) = make_state_with_bip32_master(0x01, &combined);

        // 3 bytes — not a multiple of 4
        let raw = bip_apdu(0x01, &[0x80, 0x00, 0x00]);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_WRONG_DATA);
    }

    #[test]
    fn test_bip_slip_key_not_found() {
        let mut state = ScHsmState::new();
        let mut store = TestStore::new();
        state.pin_verified = true;
        // No key in state — P1=0x01 references nothing
        let raw = bip_apdu(0x01, &[]);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_FILE_NOT_FOUND);
    }

    #[test]
    fn test_bip_slip_wrong_key_length() {
        let mut state = ScHsmState::new();
        state.pin_verified = true;

        let full_key_id = KeyId::sc_hsm(0, 0x01).0;
        // Store only 32 bytes (wrong — BIP32 master must be 64 bytes)
        state
            .key_index
            .push(KeyMeta {
                key_id: full_key_id,
                key_type: CoreKeyType::Bip32Master as u8,
                algo: 0x00,
                key_flags: 0,
            })
            .unwrap();

        let mut store = TestStore::new();
        let mut obj = KeyObject::new(
            KmType::Ec,
            full_key_id,
            AppletId::ScHsm,
            AlgorithmId::EcdsaP256,
        );
        for i in 0..32u8 {
            let _ = obj.private_key.push(i);
        }
        let _ = store.keys.push(obj);

        let raw = bip_apdu(0x01, &[]);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_WRONG_DATA);
    }

    // -----------------------------------------------------------------------
    // Success path tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_bip_slip_empty_path_refused() {
        // An empty path would return the master private key itself.
        let (mut state, mut store) = make_state_tv1(0x01);
        let raw = bip_apdu(0x01, &[]);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_WRONG_DATA);
        assert!(resp.data.is_empty());
    }

    #[test]
    fn test_bip_slip_honours_no_export() {
        let (mut state, mut store) = make_state_tv1(0x01);
        for k in store.keys.iter_mut() {
            k.key_flags |= super::super::export_key::NO_EXPORT_BIT;
        }
        let raw = bip_apdu(0x01, &0x8000_0000u32.to_be_bytes());
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
        assert!(resp.data.is_empty());
    }

    #[test]
    fn test_bip_slip_hardened_child() {
        // SLIP-0010 test vector 1: m/0'
        // Expected child_key   = edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
        // Expected child_chain = 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
        let (mut state, mut store) = make_state_tv1(0x01);

        let path_bytes = encode_path(&[0x8000_0000u32]);
        let raw = bip_apdu(0x01, &path_bytes);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(resp.sw, SW_OK, "expected SW_OK");
        assert_eq!(resp.data.len(), 64);

        let expected_key =
            hex::decode("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")
                .unwrap();
        let expected_chain =
            hex::decode("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141")
                .unwrap();

        assert_eq!(
            &resp.data[..32],
            expected_key.as_slice(),
            "child key mismatch"
        );
        assert_eq!(
            &resp.data[32..],
            expected_chain.as_slice(),
            "child chain mismatch"
        );
    }

    #[test]
    fn test_bip_slip_multi_hop() {
        // SLIP-0010 test vector 1: m/0'/1
        // Expected child_key   = 3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368
        // Expected child_chain = 2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19
        let (mut state, mut store) = make_state_tv1(0x01);

        let path_bytes = encode_path(&[0x8000_0000u32, 1u32]);
        let raw = bip_apdu(0x01, &path_bytes);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(resp.sw, SW_OK, "expected SW_OK");
        assert_eq!(resp.data.len(), 64);

        let expected_key =
            hex::decode("3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368")
                .unwrap();
        let expected_chain =
            hex::decode("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19")
                .unwrap();

        assert_eq!(
            &resp.data[..32],
            expected_key.as_slice(),
            "child key mismatch (m/0'/1)"
        );
        assert_eq!(
            &resp.data[32..],
            expected_chain.as_slice(),
            "child chain mismatch (m/0'/1)"
        );
    }
}
