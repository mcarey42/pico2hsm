//! UPDATE BINARY command handler (INS = 0xD6).
//!
//! Writes bytes to the currently selected EF in the virtual filesystem.
//! Used by sc_hsm_update_ef (pkcs15init) after CREATE FILE to store
//! key certificate data (CE xx files) and similar EF data.
//!
//! P1/P2 encode the write offset (big-endian); only offset 0 is supported.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND, SW_SECURITY_STATUS,
};
use pico2hsm_core::key::{AppletId, KeyId};

use crate::protocol::sc_hsm::{KeyMeta, ScHsmState};
use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};
use crate::storage::KeyStore;

/// INS byte for UPDATE BINARY.
pub const INS_UPDATE_BINARY: u8 = 0xD6;

/// Handle an UPDATE BINARY APDU command.
pub fn handle(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    if !state.pin_verified && !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // The file to write is the currently selected EF (set by the preceding CREATE FILE or SELECT).
    let file_id = match state.current_file {
        Some(id) => id,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    let file_id_hi = (file_id >> 8) as u8;
    let file_id_lo = (file_id & 0xFF) as u8;
    let Some(key_id) = KeyId::sc_hsm_ef_checked(0, file_id_hi, file_id_lo) else {
        return ApduResponse::err(SW_FILE_NOT_FOUND);
    };

    // Check if the EF already exists in key_index — if so, erase and rewrite.
    let exists = state
        .key_index
        .iter()
        .any(|m| m.key_type == 16 && m.key_id == key_id.0);
    if exists {
        let _ = store.erase_key(key_id);
    }

    // Create a KeyObject with EF data in private_key field.
    let mut key_obj = KeyObject::new(
        KmType::Generic,
        key_id.0,
        AppletId::ScHsm,
        AlgorithmId::AesGcm,
    );
    let _ = key_obj.private_key.extend_from_slice(cmd.data);

    match store.save_key(&key_obj) {
        Ok(()) => {
            // Update ef_cache so READ BINARY can serve this data.
            state.ef_cache_put(key_id.0, cmd.data);
            if !exists {
                let file_id_hi = (file_id >> 8) as u8;
                let meta = KeyMeta {
                    key_id: key_id.0,
                    key_type: 16,     // EfFile
                    algo: file_id_hi, // high byte of file_id
                    key_flags: 0,
                };
                let _ = state.key_index.push(meta);
            }
            ApduResponse::ok(&[])
        }
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}
