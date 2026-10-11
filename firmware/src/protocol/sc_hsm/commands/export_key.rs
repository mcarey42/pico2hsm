//! EXPORT KEY / WRAP KEY command handler (INS = 0x72).
//!
//! Exports a key object wrapped under the DKEK for HSM-to-HSM backup.
//! This command does NOT export plaintext key material.
//!
//! sc-hsm-tool sends: `80 72 <key_ref> 92 00` (P1=key_ref, P2=0x92).
//!
//! Requires active PIN session. Keys marked with NO-EXPORT flag are rejected.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND, SW_SECURITY_STATUS,
    SW_WRONG_DATA,
};
use pico2hsm_core::key::KeyId;

use crate::protocol::sc_hsm::{FwRng, ScHsmState};
use crate::storage::KeyStore;

/// INS byte for EXPORT KEY (WRAP KEY).
///
/// sc-hsm-tool `--wrap-key` sends INS=0x72; the old INS=0x34 was a
/// pico2hsm-internal value that no host tool ever used.
pub const INS_EXPORT_KEY: u8 = 0x72;

/// Key flag bit: if set, EXPORT KEY must reject wrapping this key.
///
/// SC-HSM GENERATE KEY PAIR TLV tag 0xD4 carries the key access conditions.
/// Bit layout: 0=ALLOW_SIGN, 1=ALLOW_DECRYPT, 2=ALLOW_DERIVE, 3=NO_EXPORT.
pub const NO_EXPORT_BIT: u8 = 0x08;

/// Handle an EXPORT KEY APDU command.
pub fn handle(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let full_key_id_logged = KeyId::sc_hsm(0, cmd.p1);
    crate::cdc_log!("SC-HSM EXPORT KEY key=0x{:08x}", full_key_id_logged.0);

    // Require DKEK ready
    if !state.dkek.is_ready() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    let key_ref = cmd.p1;
    if key_ref == 0x00 || key_ref == 0xFF {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    let full_key_id = KeyId::sc_hsm(0, key_ref);

    // Look up metadata from key_index, then load key material from flash.
    let meta = match state.key_index.iter().find(|m| m.key_id == full_key_id.0) {
        Some(m) => *m,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    let key_obj = match store.fetch_key(full_key_id) {
        Ok(Some(obj)) => obj,
        _ => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    let mut private_key_bytes: heapless::Vec<u8, 2400> = heapless::Vec::new();
    let _ = private_key_bytes.extend_from_slice(&key_obj.private_key);
    let algo_byte = meta.algo;
    let key_flags = meta.key_flags;

    // Enforce NO_EXPORT flag: reject wrapping if the key was generated with
    // the NO_EXPORT bit set in its key access conditions (TLV tag 0xD4).
    if key_flags & NO_EXPORT_BIT != 0 {
        crate::cdc_log!(
            "SC-HSM EXPORT KEY rejected: NO_EXPORT flag set (flags=0x{:02x})",
            key_flags
        );
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Wrap key under DKEK.
    let mut rng = FwRng;
    match state
        .dkek
        .wrap(&private_key_bytes, algo_byte, key_flags, &mut rng)
    {
        Ok(wrapped) => ApduResponse::ok(&wrapped),
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sc_hsm::{KeyMeta, ScHsmState};
    use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};
    use crate::storage::KeyStore;
    use pico2hsm_core::apdu::{ApduCommand, SW_OK};
    use pico2hsm_core::error::HsmError;
    use pico2hsm_core::key::{AppletId, KeyId, KeyType as CoreKeyType};

    struct TestStore {
        keys: heapless::Vec<KeyObject, 4>,
    }
    impl TestStore {
        fn new() -> Self {
            TestStore {
                keys: heapless::Vec::new(),
            }
        }
        fn add_key(&mut self, key_id: u32, algo: AlgorithmId, key_flags: u8, private_key: &[u8]) {
            let mut obj = KeyObject::new(KmType::Ec, key_id, AppletId::ScHsm, algo);
            obj.key_flags = key_flags;
            let _ = obj.private_key.extend_from_slice(private_key);
            let _ = self.keys.push(obj);
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

    /// Create a state with DKEK ready (single share of all-0xAA).
    fn state_with_dkek() -> ScHsmState {
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        state.dkek_shares_required = 1;
        state.dkek.init_shares(1);
        let share = [0xAAu8; 32];
        state.dkek.import_share_raw(&share).unwrap();
        state
    }

    fn make_cmd<'a>(p1: u8, p2: u8, data: &'a [u8]) -> ApduCommand<'a> {
        ApduCommand {
            cla: 0x80,
            ins: INS_EXPORT_KEY,
            p1,
            p2,
            data,
            le: None,
        }
    }

    #[test]
    fn test_export_key_with_dkek_and_in_memory_key() {
        let mut state = state_with_dkek();

        // Insert a P-256 EC key at key_ref=0x01 in key_index + store.
        let key_id = KeyId::sc_hsm(0, 0x01);
        let _ = state.key_index.push(KeyMeta {
            key_id: key_id.0,
            key_type: CoreKeyType::EcPrivateP256 as u8,
            algo: 0x13,      // ECDSA P-256
            key_flags: 0x00, // exportable
        });
        let mut store = TestStore::new();
        store.add_key(key_id.0, AlgorithmId::EcdsaP256, 0x00, &[0x42u8; 32]);

        let cmd = make_cmd(0x01, 0x92, &[]);
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(resp.sw, SW_OK, "expected SW_OK for valid export");
        // Wrapped blob: KCV(8) + IV(16) + ciphertext (>= 16 bytes).
        assert!(
            resp.data.len() >= 40,
            "wrapped blob too short: {}",
            resp.data.len()
        );
    }

    #[test]
    fn test_export_key_without_dkek_returns_conditions_not_satisfied() {
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        // DKEK is NOT initialized.

        // Insert a key so the key-not-found path is not hit.
        let key_id = KeyId::sc_hsm(0, 0x01);
        let _ = state.key_index.push(KeyMeta {
            key_id: key_id.0,
            key_type: CoreKeyType::EcPrivateP256 as u8,
            algo: 0x13,
            key_flags: 0x00,
        });

        let cmd = make_cmd(0x01, 0x92, &[]);
        let mut store = TestStore::new();
        store.add_key(key_id.0, AlgorithmId::EcdsaP256, 0x00, &[0x42u8; 32]);
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_export_key_nonexistent_returns_file_not_found() {
        let mut state = state_with_dkek();
        // No keys in state — key_ref 0x01 does not exist.

        let cmd = make_cmd(0x01, 0x92, &[]);
        let mut store = TestStore::new();
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(resp.sw, SW_FILE_NOT_FOUND);
    }

    #[test]
    fn test_export_key_rejects_no_export_flag() {
        let mut state = state_with_dkek();

        // Insert a P-256 EC key at key_ref=0x02 with NO_EXPORT flag set.
        let key_id = KeyId::sc_hsm(0, 0x02);
        let _ = state.key_index.push(KeyMeta {
            key_id: key_id.0,
            key_type: CoreKeyType::EcPrivateP256 as u8,
            algo: 0x13,               // ECDSA P-256
            key_flags: NO_EXPORT_BIT, // 0x08 = NO_EXPORT
        });
        let mut store = TestStore::new();
        store.add_key(
            key_id.0,
            AlgorithmId::EcdsaP256,
            NO_EXPORT_BIT,
            &[0x42u8; 32],
        );

        let cmd = make_cmd(0x02, 0x92, &[]);
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(
            resp.sw, SW_CONDITIONS_NOT_SATISFIED,
            "EXPORT KEY must reject keys with NO_EXPORT flag"
        );
    }

    #[test]
    fn test_export_key_allows_exportable_key_with_other_flags() {
        let mut state = state_with_dkek();

        // Insert a key with ALLOW_SIGN + ALLOW_DECRYPT set but NOT NO_EXPORT.
        let key_id = KeyId::sc_hsm(0, 0x03);
        let _ = state.key_index.push(KeyMeta {
            key_id: key_id.0,
            key_type: CoreKeyType::EcPrivateP256 as u8,
            algo: 0x13,
            key_flags: 0x03, // ALLOW_SIGN | ALLOW_DECRYPT, no NO_EXPORT
        });
        let mut store = TestStore::new();
        store.add_key(key_id.0, AlgorithmId::EcdsaP256, 0x03, &[0x42u8; 32]);

        let cmd = make_cmd(0x03, 0x92, &[]);
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(
            resp.sw, SW_OK,
            "EXPORT KEY must allow keys without NO_EXPORT flag"
        );
    }
}
