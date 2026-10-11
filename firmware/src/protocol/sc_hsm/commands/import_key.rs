//! IMPORT KEY / UNWRAP KEY command handler (INS = 0x74, P2 = 0x93).
//!
//! Imports a wrapped (encrypted) key object from the host. The key is
//! encrypted under a DKEK share.
//!
//! sc-hsm-tool sends: `80 74 <target_key_ref> 93 <len> <wrapped_blob>`.
//!
//! # Command data
//! A SmartCard-HSM (CardContact) key blob (`security::key_blob`,
//! docs/SC_HSM_APDU_REFERENCE.md).  The pico2hsm version-2/3 blobs of the
//! previous release are still accepted, deprecated, for one release.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FUNC_NOT_SUPPORTED,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};
use pico2hsm_core::key::{AppletId, KeyId};

use crate::protocol::sc_hsm::{KeyMeta, ScHsmState};
use crate::security::dkek::DkekError;
use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};
use crate::storage::KeyStore;

/// INS byte for IMPORT KEY (UNWRAP KEY).
///
/// sc-hsm-tool `--unwrap-key` sends INS=0x74; the old INS=0x58 collided
/// with LIST KEYS and required a P2-based split in the dispatch table.
pub const INS_IMPORT_KEY: u8 = 0x74;

/// P2 value for key import operation.
pub const P2_IMPORT: u8 = 0x93;

/// Handle an IMPORT KEY APDU command.
pub fn handle(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // Require DKEK ready
    if !state.dkek.is_ready() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    let key_ref = cmd.p1;
    if key_ref == 0x00 || key_ref == 0xFF {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // The blob can arrive two ways:
    //   A) Inline in cmd.data (direct / test path)
    //   B) Written to EF 0x2F10 by a preceding WRITE DATA (sc-hsm-tool standard path)
    //
    // The standard sc-hsm-tool protocol (card-sc-hsm.c sc_hsm_unwrap_key) always
    // uses path B: it calls sc_hsm_write_ef(card, 0x2F10, …) then sends IMPORT KEY
    // as a Case-1 APDU with no inline data.  We must support both paths.

    // Copy blob into a local buffer so we can later mutate state.
    let blob_data: heapless::Vec<u8, { crate::security::dkek::WRAP_MAX_BLOB }> =
        if !cmd.data.is_empty() {
            let mut v: heapless::Vec<u8, { crate::security::dkek::WRAP_MAX_BLOB }> =
                heapless::Vec::new();
            if v.extend_from_slice(cmd.data).is_err() {
                return ApduResponse::err(SW_WRONG_DATA);
            }
            v
        } else {
            // Standard sc-hsm-tool protocol: host wrote the blob to EF 0x2F10 first,
            // then sends IMPORT KEY as Case-1 APDU (no inline data).
            // EF 0x2F10 is stored via write_data; read from ef_cache first,
            // then fall back to flash via cross-core fetch_key RPC.
            let ef_key_id = KeyId::sc_hsm_ef(0, 0x2F, 0x10);
            if let Some(data) = state.ef_cache_get(ef_key_id.0) {
                if !data.is_empty() {
                    let mut v: heapless::Vec<u8, { crate::security::dkek::WRAP_MAX_BLOB }> =
                        heapless::Vec::new();
                    if v.extend_from_slice(data).is_err() {
                        return ApduResponse::err(SW_WRONG_DATA);
                    }
                    v
                } else {
                    return ApduResponse::err(SW_WRONG_DATA);
                }
            } else if let Ok(Some(obj)) = store.fetch_key(ef_key_id) {
                if !obj.private_key.is_empty() {
                    state.ef_cache_put(ef_key_id.0, &obj.private_key);
                    let mut v: heapless::Vec<u8, { crate::security::dkek::WRAP_MAX_BLOB }> =
                        heapless::Vec::new();
                    if v.extend_from_slice(&obj.private_key).is_err() {
                        return ApduResponse::err(SW_WRONG_DATA);
                    }
                    v
                } else {
                    return ApduResponse::err(SW_WRONG_DATA);
                }
            } else {
                return ApduResponse::err(SW_WRONG_DATA);
            }
        };

    // Unwrap the blob under the DKEK into a new key object: a SmartCard-HSM
    // (CardContact) key blob, or — deprecated, this release only — a
    // pico2hsm version-2/3 blob.  The blob is authenticated before anything
    // in it is decrypted or parsed; all such failures are one SW (6A80,
    // which sc-hsm-tool reports as "Wrapped key does not match DKEK").
    let full_key_id = KeyId::sc_hsm(0, key_ref);
    let mut key_obj = KeyObject::new(
        KmType::Generic,
        full_key_id.0,
        AppletId::ScHsm,
        AlgorithmId::AesGcm,
    );
    let unwrapped = match state.dkek.unwrap(&blob_data, &mut key_obj) {
        Ok(u) => u,
        // Authentic, but a key this firmware cannot hold (brainpool,
        // Curve25519, RSA in a build without `rsa`).
        Err(DkekError::UnsupportedKey) => return ApduResponse::err(SW_FUNC_NOT_SUPPORTED),
        Err(_) => return ApduResponse::err(SW_WRONG_DATA),
    };
    if unwrapped.legacy {
        crate::cdc_log!("SC-HSM IMPORT KEY: deprecated pico2hsm blob format (v2/v3)");
    }
    let algo_id = unwrapped.decoded.meta_algo;
    let key_flags = unwrapped.key_flags;

    // Clear EF 0x2F10 now that we have consumed the blob.
    let ef_key_id_2f10 = KeyId::sc_hsm_ef(0, 0x2F, 0x10);
    if cmd.data.is_empty() && store.erase_key(ef_key_id_2f10).is_err() {
        // Fail closed: RAM and flash stay consistent, nothing imported.
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    }
    state.key_index.retain(|m| m.key_id != ef_key_id_2f10.0);
    state.ef_cache_remove(ef_key_id_2f10.0);

    key_obj.key_domain = key_obj.policy.domain.unwrap_or(0);

    // Persist to flash; an import that is not stored did not happen.
    if store.save_key(&key_obj).is_err() {
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    }
    state.generation = state.generation.wrapping_add(1);

    // Store metadata in key_index (replacing any existing entry with the same ID).
    state.key_index.retain(|m| m.key_id != full_key_id.0);
    let _ = state.key_index.push(KeyMeta {
        key_id: full_key_id.0,
        key_type: unwrapped.decoded.core_type as u8,
        algo: algo_id,
        key_flags,
    });

    crate::cdc_log!(
        "SC-HSM IMPORT KEY done key=0x{:08x} algo=0x{:02x}",
        full_key_id.0,
        algo_id
    );
    ApduResponse::ok(&[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sc_hsm::{FwRng, ScHsmState};
    use crate::storage::KeyStore;
    use pico2hsm_core::apdu::{ApduCommand, SW_OK};
    use pico2hsm_core::error::HsmError;
    use pico2hsm_core::key::{KeyId, KeyType as CoreKeyType};

    struct NullStore;
    impl KeyStore for NullStore {
        fn save_key(
            &mut self,
            _: &crate::security::key_management::KeyObject,
        ) -> Result<(), HsmError> {
            Ok(())
        }
        fn fetch_key(
            &mut self,
            _: KeyId,
        ) -> Result<Option<crate::security::key_management::KeyObject>, HsmError> {
            Ok(None)
        }
        fn erase_key(&mut self, _: KeyId) -> Result<(), HsmError> {
            Ok(())
        }
        fn wipe_all(&mut self) -> Result<(), HsmError> {
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

    /// Wrap a known key so we have a valid blob for import tests.
    fn wrap_test_key(
        state: &ScHsmState,
        private_key: &[u8],
        algo: u8,
    ) -> heapless::Vec<u8, { crate::security::dkek::WRAP_MAX_BLOB }> {
        let mut rng = FwRng;
        let mut key = KeyObject::new(
            KmType::Ec,
            0,
            AppletId::ScHsm,
            AlgorithmId::from_u8(algo).unwrap(),
        );
        key.private_key.extend_from_slice(private_key).unwrap();
        state.dkek.wrap(&key, 0x01, &mut rng).unwrap()
    }

    /// A blob in the deprecated pico2hsm format (version 2).
    fn wrap_legacy_key(
        state: &ScHsmState,
        material: &[u8],
        algo: u8,
    ) -> heapless::Vec<u8, { crate::security::dkek::WRAP_MAX_BLOB }> {
        let mut rng = FwRng;
        let none = crate::security::key_policy::KeyPolicy::default();
        state
            .dkek
            .wrap_legacy(material, algo, 0x01, &none, &mut rng)
            .unwrap()
    }

    fn make_cmd<'a>(p1: u8, p2: u8, data: &'a [u8]) -> ApduCommand<'a> {
        ApduCommand {
            cla: 0x80,
            ins: INS_IMPORT_KEY,
            p1,
            p2,
            data,
            le: None,
        }
    }

    #[test]
    fn test_import_valid_wrapped_key_succeeds() {
        let mut state = state_with_dkek();
        let private_key = [0x42u8; 32];
        let wrapped = wrap_test_key(&state, &private_key, 0x13); // ECDSA P-256

        let cmd = make_cmd(0x01, P2_IMPORT, &wrapped);
        let mut store = NullStore;
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(resp.sw, SW_OK, "expected SW_OK for valid import");
        // Verify the key metadata was added to key_index.
        let found = state
            .key_index
            .iter()
            .find(|m| m.key_id == KeyId::sc_hsm(0, 0x01).0);
        assert!(found.is_some(), "imported key should be in key_index");
        let meta = found.unwrap();
        assert_eq!(meta.algo, 0x13);
    }

    #[test]
    fn test_import_oversized_ec_key_rejected() {
        // An authenticated blob whose "P-256 key" is 100 bytes used to be
        // stored and then panic core1 on the fixed 66-byte copy at use.
        let mut state = state_with_dkek();
        let wrapped = wrap_legacy_key(&state, &[0x42u8; 100], 0x13);
        let cmd = make_cmd(0x01, P2_IMPORT, &wrapped);
        let resp = handle(&mut state, &mut NullStore, &cmd);
        assert_eq!(resp.sw, SW_WRONG_DATA);
        assert!(!state
            .key_index
            .iter()
            .any(|m| m.key_id == KeyId::sc_hsm(0, 0x01).0));
    }

    #[test]
    fn test_import_legacy_v2_blob_still_accepted() {
        let mut state = state_with_dkek();
        let wrapped = wrap_legacy_key(&state, &[0x42u8; 32], 0x13);
        let resp = handle(
            &mut state,
            &mut NullStore,
            &make_cmd(0x02, P2_IMPORT, &wrapped),
        );
        assert_eq!(resp.sw, SW_OK);
        let meta = state
            .key_index
            .iter()
            .find(|m| m.key_id == KeyId::sc_hsm(0, 0x02).0)
            .copied()
            .unwrap();
        assert_eq!((meta.algo, meta.key_flags), (0x13, 0x01));
    }

    #[test]
    fn test_import_keeps_policy_and_flags() {
        let mut state = state_with_dkek();
        let mut key = KeyObject::new(KmType::Ec, 0, AppletId::ScHsm, AlgorithmId::EcdsaP256);
        key.private_key.extend_from_slice(&[0x42u8; 32]).unwrap();
        key.policy.algorithms.extend_from_slice(&[0x73]).unwrap();
        let wrapped = state.dkek.wrap(&key, 0x02, &mut FwRng).unwrap();
        struct Keep(Option<KeyObject>);
        impl KeyStore for Keep {
            fn save_key(&mut self, o: &KeyObject) -> Result<(), HsmError> {
                let mut c = KeyObject::new(o.key_type, o.key_id, o.owner, o.algorithm);
                c.policy = o.policy.clone();
                c.key_flags = o.key_flags;
                c.public_key.extend_from_slice(&o.public_key).unwrap();
                self.0 = Some(c);
                Ok(())
            }
            fn fetch_key(&mut self, _: KeyId) -> Result<Option<KeyObject>, HsmError> {
                Ok(None)
            }
            fn erase_key(&mut self, _: KeyId) -> Result<(), HsmError> {
                Ok(())
            }
            fn wipe_all(&mut self) -> Result<(), HsmError> {
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
        let mut store = Keep(None);
        let resp = handle(&mut state, &mut store, &make_cmd(0x03, P2_IMPORT, &wrapped));
        assert_eq!(resp.sw, SW_OK);
        let saved = store.0.unwrap();
        assert_eq!(&saved.policy.algorithms[..], &[0x73]);
        assert_eq!(saved.key_flags, 0x02);
        assert_eq!(saved.public_key.len(), 65);
    }

    #[test]
    fn test_import_bad_kcv_returns_wrong_data() {
        let mut state = state_with_dkek();
        let private_key = [0x42u8; 32];
        let mut wrapped = wrap_test_key(&state, &private_key, 0x13);

        // Corrupt the KCV (first 8 bytes).
        wrapped[0] ^= 0xFF;
        wrapped[1] ^= 0xFF;

        let cmd = make_cmd(0x01, P2_IMPORT, &wrapped);
        let mut store = NullStore;
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(resp.sw, SW_WRONG_DATA, "corrupted KCV should fail");
    }

    #[test]
    fn test_import_without_dkek_returns_conditions_not_satisfied() {
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        // DKEK not initialized.

        let fake_blob = [0u8; 48]; // Minimum size blob (won't matter, DKEK check is first).
        let cmd = make_cmd(0x01, P2_IMPORT, &fake_blob);
        let mut store = NullStore;
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_import_empty_data_no_ef_returns_wrong_data() {
        // Empty cmd.data with no EF 0x2F10 in state → SW_WRONG_DATA.
        let mut state = state_with_dkek();

        let cmd = make_cmd(0x01, P2_IMPORT, &[]);
        let mut store = NullStore;
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(
            resp.sw, SW_WRONG_DATA,
            "empty data with no EF 0x2F10 should fail"
        );
    }

    /// A store that holds one EF 0x2F10 blob for testing the standard import path.
    struct EfStore {
        ef_data: Option<heapless::Vec<u8, { crate::security::dkek::WRAP_MAX_BLOB }>>,
    }
    impl KeyStore for EfStore {
        fn save_key(
            &mut self,
            obj: &crate::security::key_management::KeyObject,
        ) -> Result<(), HsmError> {
            // Store EF 0x2F10 data
            let ef_key_id = KeyId::sc_hsm_ef(0, 0x2F, 0x10).0;
            if obj.key_id == ef_key_id {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(&obj.private_key);
                self.ef_data = Some(v);
            }
            Ok(())
        }
        fn fetch_key(
            &mut self,
            kid: KeyId,
        ) -> Result<Option<crate::security::key_management::KeyObject>, HsmError> {
            let ef_key_id = KeyId::sc_hsm_ef(0, 0x2F, 0x10);
            if kid == ef_key_id {
                if let Some(ref data) = self.ef_data {
                    let mut obj = crate::security::key_management::KeyObject::new(
                        crate::security::key_management::KeyType::Generic,
                        ef_key_id.0,
                        AppletId::ScHsm,
                        crate::security::key_management::AlgorithmId::EcdsaP256,
                    );
                    let _ = obj.private_key.extend_from_slice(data);
                    return Ok(Some(obj));
                }
            }
            Ok(None)
        }
        fn erase_key(&mut self, kid: KeyId) -> Result<(), HsmError> {
            let ef_key_id = KeyId::sc_hsm_ef(0, 0x2F, 0x10);
            if kid == ef_key_id {
                self.ef_data = None;
            }
            Ok(())
        }
        fn wipe_all(&mut self) -> Result<(), HsmError> {
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

    #[test]
    fn test_import_via_ef_0x2f10_succeeds() {
        // Standard sc-hsm-tool path: blob written to EF 0x2F10 first, then Case-1 IMPORT KEY.
        let mut state = state_with_dkek();
        let private_key = [0x42u8; 32];
        let wrapped = wrap_test_key(&state, &private_key, 0x13); // ECDSA P-256

        // Populate EF 0x2F10 via ef_cache (import handler reads from cache,
        // not store.fetch_key, since FlashQueueKeyStore returns None).
        let ef_key_id = KeyId::sc_hsm_ef(0, 0x2F, 0x10);
        state.ef_cache_put(ef_key_id.0, &wrapped);
        let mut store = EfStore { ef_data: None };

        // Also add the EF metadata to key_index so import can find it.
        let ef_meta = crate::protocol::sc_hsm::KeyMeta {
            key_id: ef_key_id.0,
            key_type: 16, // EfFile
            algo: 0,
            key_flags: 0,
        };
        let _ = state.key_index.push(ef_meta);

        // Case-1 IMPORT KEY (no inline data) — standard sc-hsm-tool protocol.
        let cmd = make_cmd(0x01, P2_IMPORT, &[]);
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(resp.sw, SW_OK, "EF 0x2F10 path should succeed");
        // EF 0x2F10 must be cleared from ef_cache after import.
        assert!(
            state.ef_cache_get(ef_key_id.0).is_none(),
            "EF 0x2F10 should be cleared from ef_cache after import"
        );
        // Key metadata must be in the key_index.
        let found = state
            .key_index
            .iter()
            .find(|m| m.key_id == KeyId::sc_hsm(0, 0x01).0);
        assert!(found.is_some(), "imported key should be in key_index");
        assert_eq!(found.unwrap().algo, 0x13);
    }
}
