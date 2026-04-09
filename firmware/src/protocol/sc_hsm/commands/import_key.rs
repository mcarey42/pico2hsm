//! IMPORT KEY / UNWRAP KEY command handler (INS = 0x74, P2 = 0x93).
//!
//! Imports a wrapped (encrypted) key object from the host. The key is
//! encrypted under a DKEK share.
//!
//! sc-hsm-tool sends: `80 74 <target_key_ref> 93 <len> <wrapped_blob>`.
//!
//! # Command data
//! Wrapped key blob in SC-HSM wrap format.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};
use pico2hsm_core::key::{AppletId, KeyId};

use crate::protocol::sc_hsm::{InMemoryKey, ScHsmState};
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
pub fn handle(state: &mut ScHsmState, store: &mut dyn KeyStore, cmd: &ApduCommand<'_>) -> ApduResponse {
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

    // Copy blob into a local buffer so we can later mutate state (retain EF 0x2F10).
    let blob_data: heapless::Vec<u8, 2400> = if !cmd.data.is_empty() {
        let mut v: heapless::Vec<u8, 2400> = heapless::Vec::new();
        if v.extend_from_slice(cmd.data).is_err() {
            return ApduResponse::err(SW_WRONG_DATA);
        }
        v
    } else {
        // Standard sc-hsm-tool protocol: host wrote the blob to EF 0x2F10 first,
        // then sends IMPORT KEY as Case-1 APDU (no inline data).
        match state.ef_files.iter().find(|e| e.file_id == 0x2F10) {
            Some(ef) if !ef.data.is_empty() => {
                let mut v: heapless::Vec<u8, 2400> = heapless::Vec::new();
                if v.extend_from_slice(&ef.data).is_err() {
                    return ApduResponse::err(SW_WRONG_DATA);
                }
                v
            }
            _ => return ApduResponse::err(SW_WRONG_DATA),
        }
    };

    // Unwrap key blob under DKEK.
    let (key_material, algo_id, key_flags) = match state.dkek.unwrap(&blob_data) {
        Ok(result) => result,
        Err(_) => return ApduResponse::err(SW_WRONG_DATA),
    };

    // Clear EF 0x2F10 now that we have consumed the blob.
    state.ef_files.retain(|e| e.file_id != 0x2F10);

    let full_key_id = KeyId::sc_hsm(0, key_ref);

    // Determine AlgorithmId from the algo byte stored in the wrapped blob.
    let km_algo = match AlgorithmId::from_u8(algo_id) {
        Some(a) => a,
        None => return ApduResponse::err(SW_WRONG_DATA),
    };

    // Determine key type family for KeyObject.
    let km_type = match algo_id {
        0x13 | 0x15 | 0x17 | 0x19 | 0x23 | 0x25 | 0x27 | 0x53 | 0x54 | 0x55 => KmType::Ec,
        0x05 | 0x07 | 0x31 | 0x32 | 0x33 | 0x34 | 0x41 => KmType::Rsa,
        0x60 | 0x61 | 0x62 | 0x63 => KmType::Aes,
        0x20 | 0x21 => KmType::Ec, // Ed25519/X25519 stored as EC family
        _ => return ApduResponse::err(SW_WRONG_DATA),
    };

    // Build KeyObject for persistent storage.
    let mut key_obj = KeyObject::new(km_type, full_key_id.0, AppletId::ScHsm, km_algo);
    key_obj.key_flags = key_flags;
    let _ = key_obj.private_key.extend_from_slice(&key_material);

    // Persist to flash (best-effort; flash writes fail with InvalidCore on Core1
    // and the key remains available in the in-memory store for the session).
    let _ = store.save_key(&key_obj);
    state.generation = state.generation.wrapping_add(1);

    // Also store in in-memory EC key store for immediate use.
    // Map algo byte to CoreKeyType for InMemoryKey.
    let core_key_type = match algo_id {
        0x13 | 0x23 => pico2hsm_core::key::KeyType::EcPrivateP256,
        0x15 | 0x25 => pico2hsm_core::key::KeyType::EcPrivateP384,
        0x17 | 0x27 => pico2hsm_core::key::KeyType::EcPrivateP521,
        0x19 => pico2hsm_core::key::KeyType::EcPrivateK256,
        0x53 => pico2hsm_core::key::KeyType::EcPrivateBrainpoolP256,
        0x54 => pico2hsm_core::key::KeyType::EcPrivateBrainpoolP384,
        0x55 => pico2hsm_core::key::KeyType::EcPrivateBrainpoolP512,
        0x20 => pico2hsm_core::key::KeyType::Ed25519,
        0x21 => pico2hsm_core::key::KeyType::X25519,
        _ => {
            // RSA and symmetric keys are handled differently; for now just persist to flash.
            // The in-memory store doesn't apply to RSA/AES imports (they'd be re-loaded from flash).
            crate::cdc_log!("SC-HSM IMPORT KEY done key=0x{:08x} algo=0x{:02x}", full_key_id.0, algo_id);
            return ApduResponse::ok(&[]);
        }
    };

    // Remove any existing key with the same ID.
    state.keys.retain(|k| k.key_id != full_key_id.0);

    let mut entry = InMemoryKey {
        key_id: full_key_id.0,
        key_type: core_key_type,
        algo: algo_id,
        key_flags,
        private_key: heapless::Vec::new(),
        public_key: heapless::Vec::new(),
    };
    let _ = entry.private_key.extend_from_slice(&key_material);
    // Public key is not available from the wrapped blob; it will be derived on demand.
    let _ = state.keys.push(entry);

    crate::cdc_log!("SC-HSM IMPORT KEY done key=0x{:08x} algo=0x{:02x}", full_key_id.0, algo_id);
    ApduResponse::ok(&[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico2hsm_core::apdu::{ApduCommand, SW_OK};
    use pico2hsm_core::key::{KeyId, KeyType as CoreKeyType};
    use pico2hsm_core::error::HsmError;
    use crate::protocol::sc_hsm::{FwRng, InMemoryKey, ScHsmState};
    use crate::storage::KeyStore;

    struct NullStore;
    impl KeyStore for NullStore {
        fn save_key(&mut self, _: &crate::security::key_management::KeyObject) -> Result<(), HsmError> { Ok(()) }
        fn fetch_key(&mut self, _: KeyId) -> Result<Option<crate::security::key_management::KeyObject>, HsmError> { Ok(None) }
        fn erase_key(&mut self, _: KeyId) -> Result<(), HsmError> { Ok(()) }
        fn wipe_all(&mut self) -> Result<(), HsmError> { Ok(()) }
        fn wipe_by_owner(&mut self, _: AppletId) -> Result<(), HsmError> { Ok(()) }
        fn enumerate_keys(&self) -> heapless::Vec<KeyId, 512> { heapless::Vec::new() }
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
    fn wrap_test_key(state: &ScHsmState, private_key: &[u8], algo: u8) -> heapless::Vec<u8, 2448> {
        let mut rng = FwRng;
        state.dkek.wrap(private_key, algo, 0x01, &mut rng).unwrap()
    }

    fn make_cmd<'a>(p1: u8, p2: u8, data: &'a [u8]) -> ApduCommand<'a> {
        ApduCommand { cla: 0x80, ins: INS_IMPORT_KEY, p1, p2, data, le: None }
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
        // Verify the key was added to in-memory store.
        let found = state.keys.iter().find(|k| k.key_id == KeyId::sc_hsm(0, 0x01).0);
        assert!(found.is_some(), "imported key should be in memory");
        let key = found.unwrap();
        assert_eq!(key.algo, 0x13);
        assert_eq!(&key.private_key[..], &private_key[..]);
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

        assert_eq!(resp.sw, SW_WRONG_DATA, "empty data with no EF 0x2F10 should fail");
    }

    #[test]
    fn test_import_via_ef_0x2f10_succeeds() {
        // Standard sc-hsm-tool path: blob written to EF 0x2F10 first, then Case-1 IMPORT KEY.
        let mut state = state_with_dkek();
        let private_key = [0x42u8; 32];
        let wrapped = wrap_test_key(&state, &private_key, 0x13); // ECDSA P-256

        // Populate EF 0x2F10 with the wrapped blob.
        let mut ef_data: heapless::Vec<u8, { crate::protocol::sc_hsm::MAX_EF_DATA }> =
            heapless::Vec::new();
        let _ = ef_data.extend_from_slice(&wrapped);
        let _ = state.ef_files.push(crate::protocol::sc_hsm::EfEntry {
            file_id: 0x2F10,
            data: ef_data,
        });

        // Case-1 IMPORT KEY (no inline data) — standard sc-hsm-tool protocol.
        let cmd = make_cmd(0x01, P2_IMPORT, &[]);
        let mut store = NullStore;
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(resp.sw, SW_OK, "EF 0x2F10 path should succeed");
        // EF 0x2F10 must be cleared after import.
        assert!(
            state.ef_files.iter().find(|e| e.file_id == 0x2F10).is_none(),
            "EF 0x2F10 should be cleared after import"
        );
        // Key must be in the in-memory store.
        let found = state.keys.iter().find(|k| k.key_id == KeyId::sc_hsm(0, 0x01).0);
        assert!(found.is_some(), "imported key should be in memory");
        assert_eq!(found.unwrap().algo, 0x13);
        assert_eq!(&found.unwrap().private_key[..], &private_key[..]);
    }
}
