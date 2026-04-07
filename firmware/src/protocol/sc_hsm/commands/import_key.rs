//! IMPORT KEY command handler (INS = 0x58, P2 = 0x93).
//!
//! Imports a wrapped (encrypted) key object from the host. The key is
//! encrypted under a DKEK share.
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

/// INS byte for IMPORT KEY.
pub const INS_IMPORT_KEY: u8 = 0x58;

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

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Unwrap key blob under DKEK.
    let (key_material, algo_id, _key_flags) = match state.dkek.unwrap(cmd.data) {
        Ok(result) => result,
        Err(_) => return ApduResponse::err(SW_WRONG_DATA),
    };

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
    let _ = key_obj.private_key.extend_from_slice(&key_material);

    // Persist to flash.
    if store.save_key(&key_obj).is_err() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

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
            return ApduResponse::ok(&[]);
        }
    };

    // Remove any existing key with the same ID.
    state.keys.retain(|k| k.key_id != full_key_id.0);

    let mut entry = InMemoryKey {
        key_id: full_key_id.0,
        key_type: core_key_type,
        algo: algo_id,
        private_key: heapless::Vec::new(),
        public_key: heapless::Vec::new(),
    };
    let _ = entry.private_key.extend_from_slice(&key_material);
    // Public key is not available from the wrapped blob; it will be derived on demand.
    let _ = state.keys.push(entry);

    ApduResponse::ok(&[])
}
