//! EXPORT KEY / WRAP KEY command handler (INS = 0x72).
//!
//! Exports a key object wrapped under the DKEK for HSM-to-HSM backup.
//! This command does NOT export plaintext key material.
//!
//! sc-hsm-tool sends: `80 72 <key_ref> 92 00` (P1=key_ref, P2=0x92).
//!
//! Requires active PIN session. Keys marked with NO-EXPORT flag are rejected.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};
use pico2hsm_core::key::KeyId;

use crate::protocol::sc_hsm::{FwRng, ScHsmState};
use crate::storage::KeyStore;

/// INS byte for EXPORT KEY (WRAP KEY).
///
/// sc-hsm-tool `--wrap-key` sends INS=0x72; the old INS=0x34 was a
/// pico2hsm-internal value that no host tool ever used.
pub const INS_EXPORT_KEY: u8 = 0x72;

/// Handle an EXPORT KEY APDU command.
pub fn handle(state: &mut ScHsmState, store: &mut dyn KeyStore, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let full_key_id_logged = pico2hsm_core::key::KeyId::sc_hsm(0, cmd.p1);
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

    // Try to load key from persistent store first, then fall back to in-memory.
    let (private_key_bytes, algo_byte) = match store.fetch_key(full_key_id) {
        Ok(Some(key_obj)) => {
            // Got a key from flash. Extract private key and algorithm byte.
            let algo = key_obj.algorithm as u8;
            let mut priv_data: heapless::Vec<u8, 2400> = heapless::Vec::new();
            let _ = priv_data.extend_from_slice(&key_obj.private_key);
            (priv_data, algo)
        }
        _ => {
            // Fall back to in-memory key lookup (EC keys).
            if let Some(key) = state.keys.iter().find(|k| k.key_id == full_key_id.0) {
                let mut priv_data: heapless::Vec<u8, 2400> = heapless::Vec::new();
                let _ = priv_data.extend_from_slice(&key.private_key);
                (priv_data, key.algo)
            } else {
                // Try RSA keys.
                #[cfg(feature = "rsa")]
                {
                    if let Some(rsa_key) = state.rsa_keys.iter().find(|k| k.key_id == full_key_id.0) {
                        let mut priv_data: heapless::Vec<u8, 2400> = heapless::Vec::new();
                        let _ = priv_data.extend_from_slice(&rsa_key.private_key_der);
                        (priv_data, rsa_key.algo)
                    } else {
                        return ApduResponse::err(SW_FILE_NOT_FOUND);
                    }
                }
                #[cfg(not(feature = "rsa"))]
                {
                    return ApduResponse::err(SW_FILE_NOT_FOUND);
                }
            }
        }
    };

    // Wrap key under DKEK.
    let mut rng = FwRng;
    match state.dkek.wrap(&private_key_bytes, algo_byte, 0x01, &mut rng) {
        Ok(wrapped) => ApduResponse::ok(&wrapped),
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico2hsm_core::apdu::{ApduCommand, SW_OK};
    use pico2hsm_core::key::{AppletId, KeyId, KeyType as CoreKeyType};
    use crate::protocol::sc_hsm::{InMemoryKey, ScHsmState};
    use crate::storage::KeyStore;
    use pico2hsm_core::error::HsmError;

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

    fn make_cmd<'a>(p1: u8, p2: u8, data: &'a [u8]) -> ApduCommand<'a> {
        ApduCommand { cla: 0x80, ins: INS_EXPORT_KEY, p1, p2, data, le: None }
    }

    #[test]
    fn test_export_key_with_dkek_and_in_memory_key() {
        let mut state = state_with_dkek();

        // Insert a P-256 EC key at key_ref=0x01.
        let key_id = KeyId::sc_hsm(0, 0x01);
        let mut entry = InMemoryKey {
            key_id: key_id.0,
            key_type: CoreKeyType::EcPrivateP256,
            algo: 0x13, // ECDSA P-256
            private_key: heapless::Vec::new(),
            public_key: heapless::Vec::new(),
        };
        // 32-byte fake private key scalar.
        let _ = entry.private_key.extend_from_slice(&[0x42u8; 32]);
        let _ = state.keys.push(entry);

        let cmd = make_cmd(0x01, 0x92, &[]);
        let mut store = NullStore;
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(resp.sw, SW_OK, "expected SW_OK for valid export");
        // Wrapped blob: KCV(8) + IV(16) + ciphertext (>= 16 bytes).
        assert!(resp.data.len() >= 40, "wrapped blob too short: {}", resp.data.len());
    }

    #[test]
    fn test_export_key_without_dkek_returns_conditions_not_satisfied() {
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        // DKEK is NOT initialized.

        // Insert a key so the key-not-found path is not hit.
        let key_id = KeyId::sc_hsm(0, 0x01);
        let mut entry = InMemoryKey {
            key_id: key_id.0,
            key_type: CoreKeyType::EcPrivateP256,
            algo: 0x13,
            private_key: heapless::Vec::new(),
            public_key: heapless::Vec::new(),
        };
        let _ = entry.private_key.extend_from_slice(&[0x42u8; 32]);
        let _ = state.keys.push(entry);

        let cmd = make_cmd(0x01, 0x92, &[]);
        let mut store = NullStore;
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_export_key_nonexistent_returns_file_not_found() {
        let mut state = state_with_dkek();
        // No keys in state — key_ref 0x01 does not exist.

        let cmd = make_cmd(0x01, 0x92, &[]);
        let mut store = NullStore;
        let resp = handle(&mut state, &mut store, &cmd);

        assert_eq!(resp.sw, SW_FILE_NOT_FOUND);
    }
}
