//! DERIVE ASYMMETRIC KEY command handler (INS = 0x62, P1 = 0x01, P2 = 0x00).
//!
//! Note: INS=0x62 is shared with DECIPHER. Routing (in `ScHsm`) needs both
//! bytes: P1=0x01 **and** P2=0x00 → this handler; anything else → DECIPHER
//! (decrypt.rs), whose P1 is the key slot and P2 a non-zero algorithm code.
//!
//! Derives a new asymmetric key pair from a stored master key using
//! a KDF-based deterministic derivation (X9.63 or HKDF).

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND, SW_SECURITY_STATUS,
    SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::ScHsmState;
use crate::storage::KeyStore;

/// INS byte for DERIVE ASYMMETRIC KEY (shared with DECIPHER).
pub const INS_DERIVE_ASYM: u8 = 0x62;

/// P1 value that selects DERIVE ASYMMETRIC over DECIPHER.
pub const P1_DERIVE: u8 = 0x01;

/// Handle a DERIVE ASYMMETRIC KEY APDU command.
pub fn handle(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let source_key_id = match state.current_key_id {
        Some(k) => k,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    let full_key_id = pico2hsm_core::key::KeyId::sc_hsm(0, source_key_id).0;

    // Check metadata index for the key
    let _meta = match state.key_index.iter().find(|m| m.key_id == full_key_id) {
        Some(m) => *m,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // Load key material from flash
    let mut key_obj = match store.fetch_key(pico2hsm_core::key::KeyId(full_key_id)) {
        Ok(Some(obj)) => obj,
        _ => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Use private_key bytes (works for both EC and symmetric keys)
    let mut key_bytes = crate::security::zeroize::WipeOnDrop::<66>::new();
    if key_bytes.extend_from_slice(&key_obj.private_key).is_err() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // HKDF output from a stored key has no SmartCard-HSM algorithm ID
    // (CardContact's EC derive stores a new key, AES derive uses its own
    // KDF): only a key without an algorithm list may be used; the use
    // counter applies.
    if let Err(sw) = crate::security::key_policy::authorize_use(store, &mut key_obj, None) {
        return ApduResponse::err(sw);
    }

    let mut output = [0u8; 32];
    match crate::crypto::kdf::hkdf_sha256(&[], &key_bytes, cmd.data, &mut output) {
        Ok(()) => ApduResponse::ok(&output),
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
        apdu::{SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND, SW_OK, SW_SECURITY_STATUS},
        key::{AppletId, KeyId},
    };

    use crate::protocol::sc_hsm::{KeyMeta, ScHsmState};
    use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};

    /// Test key store that holds a single KeyObject and returns it on fetch_key.
    struct TestStore {
        obj: Option<KeyObject>,
    }

    impl TestStore {
        fn new(obj: KeyObject) -> Self {
            Self { obj: Some(obj) }
        }
        fn empty() -> Self {
            Self { obj: None }
        }
    }

    impl crate::storage::KeyStore for TestStore {
        fn save_key(&mut self, _: &KeyObject) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn fetch_key(
            &mut self,
            key_id: KeyId,
        ) -> Result<Option<KeyObject>, pico2hsm_core::error::HsmError> {
            if let Some(ref obj) = self.obj {
                if obj.key_id == key_id.0 {
                    // Clone the KeyObject fields manually
                    let mut clone =
                        KeyObject::new(obj.key_type, obj.key_id, obj.owner, obj.algorithm);
                    clone.key_flags = obj.key_flags;
                    let _ = clone.private_key.extend_from_slice(&obj.private_key);
                    let _ = clone.public_key.extend_from_slice(&obj.public_key);
                    return Ok(Some(clone));
                }
            }
            Ok(None)
        }
        fn erase_key(&mut self, _: KeyId) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn wipe_all(&mut self) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn wipe_by_owner(&mut self, _: AppletId) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn enumerate_keys(&self) -> heapless::Vec<KeyId, 64> {
            heapless::Vec::new()
        }
        fn for_each_key(&self, _f: &mut dyn FnMut(KeyId)) {}
    }

    /// Build a minimal APDU raw buffer: [CLA, INS, P1, P2, Lc, data...]
    fn make_apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> heapless::Vec<u8, 128> {
        let mut v: heapless::Vec<u8, 128> = heapless::Vec::new();
        v.push(0x00).unwrap(); // CLA
        v.push(ins).unwrap(); // INS
        v.push(p1).unwrap(); // P1
        v.push(p2).unwrap(); // P2
        v.push(data.len() as u8).unwrap(); // Lc
        v.extend_from_slice(data).unwrap();
        v
    }

    fn derive_apdu(info: &[u8]) -> heapless::Vec<u8, 128> {
        make_apdu(INS_DERIVE_ASYM, P1_DERIVE, 0x00, info)
    }

    fn make_state_and_store_with_ec_key(key_proto_ref: u8) -> (ScHsmState, TestStore) {
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        state.current_key_id = Some(key_proto_ref);

        let full_key_id = KeyId::sc_hsm(0, key_proto_ref).0;

        // Push metadata into key_index
        let meta = KeyMeta {
            key_id: full_key_id,
            key_type: 0,
            algo: 0x13,
            key_flags: 0,
        };
        state.key_index.push(meta).unwrap();

        // Create a KeyObject with fake EC private key
        let mut key_obj = KeyObject::new(
            KmType::Ec,
            full_key_id,
            AppletId::ScHsm,
            AlgorithmId::EcdsaP256,
        );
        for i in 0..32u8 {
            let _ = key_obj.private_key.push(i + 1);
        }

        (state, TestStore::new(key_obj))
    }

    fn make_state_and_store_with_sym_key(key_proto_ref: u8) -> (ScHsmState, TestStore) {
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        state.current_key_id = Some(key_proto_ref);

        let full_key_id = KeyId::sc_hsm(0, key_proto_ref).0;

        // Push metadata into key_index
        let meta = KeyMeta {
            key_id: full_key_id,
            key_type: 0,
            algo: 0x60,
            key_flags: 0,
        };
        state.key_index.push(meta).unwrap();

        // Create a KeyObject with fake AES-256 key
        let mut key_obj = KeyObject::new(
            KmType::Aes,
            full_key_id,
            AppletId::ScHsm,
            AlgorithmId::AesCbc,
        );
        for i in 0..32u8 {
            let _ = key_obj.private_key.push(0xA0 ^ i);
        }

        (state, TestStore::new(key_obj))
    }

    #[test]
    fn test_derive_requires_pin() {
        let mut state = ScHsmState::new();
        let mut store = TestStore::empty();
        // pin_verified = false (default)
        state.current_key_id = Some(0x01);
        let raw = derive_apdu(b"test-info");
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_SECURITY_STATUS);
    }

    #[test]
    fn test_derive_no_mse_key_id() {
        let mut state = ScHsmState::new();
        let mut store = TestStore::empty();
        state.pin_verified = true;
        // current_key_id = None (default)
        let raw = derive_apdu(b"test-info");
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_derive_key_not_found() {
        let mut state = ScHsmState::new();
        let mut store = TestStore::empty();
        state.pin_verified = true;
        state.current_key_id = Some(0x01);
        // No key in key_index or store
        let raw = derive_apdu(b"test-info");
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_FILE_NOT_FOUND);
    }

    #[test]
    fn test_derive_ec_key_returns_32_bytes() {
        let (mut state, mut store) = make_state_and_store_with_ec_key(0x01);
        let raw = derive_apdu(b"app-context");
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_OK);
        assert_eq!(resp.data.len(), 32, "derived output must be 32 bytes");
    }

    #[test]
    fn test_derive_sym_key_returns_32_bytes() {
        let (mut state, mut store) = make_state_and_store_with_sym_key(0x02);
        let raw = derive_apdu(b"sym-context");
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_OK);
        assert_eq!(resp.data.len(), 32, "derived output must be 32 bytes");
    }

    #[test]
    fn test_derive_different_info_different_output() {
        let (mut state1, mut store1) = make_state_and_store_with_ec_key(0x01);
        let (mut state2, mut store2) = make_state_and_store_with_ec_key(0x01);

        let raw1 = derive_apdu(b"context-A");
        let raw2 = derive_apdu(b"context-B");

        let cmd1 = pico2hsm_core::apdu::ApduCommand::parse(&raw1).unwrap();
        let cmd2 = pico2hsm_core::apdu::ApduCommand::parse(&raw2).unwrap();

        let resp1 = handle(&mut state1, &mut store1, &cmd1);
        let resp2 = handle(&mut state2, &mut store2, &cmd2);

        assert_eq!(resp1.sw, SW_OK);
        assert_eq!(resp2.sw, SW_OK);
        assert_ne!(
            resp1.data, resp2.data,
            "different info bytes must produce different derived output"
        );
    }
}
