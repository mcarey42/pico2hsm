//! DELETE FILE command handler (INS = 0xE4).
//!
//! Deletes a key object or EF from the in-memory store.
//! Requires an active User PIN or SO-PIN session.
//!
//! # Command format
//! - P1=0x02, P2=0x00: 2-byte file ID in data field
//! - P1=0x00, P2=0x00: delete currently selected file
//!
//! Returns SW_FILE_NOT_FOUND (6A82) if the file does not exist.
//! (sc_hsm_update_ef checks for SC_SUCCESS specifically, so a NOT_FOUND
//! response from DELETE is treated as an error by pkcs15init. The SELECT
//! step before DELETE already guards against deleting non-existent files.)

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_FILE_NOT_FOUND, SW_OK, SW_SECURITY_STATUS, SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for DELETE FILE.
pub const INS_DELETE_FILE: u8 = 0xE4;

/// Handle a DELETE FILE APDU command.
pub fn handle(state: &mut ScHsmState, store: &mut dyn crate::storage::KeyStore, cmd: &ApduCommand<'_>) -> ApduResponse {
    if !state.pin_verified && !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let file_id: u16 = match cmd.p1 {
        0x02 => {
            if cmd.data.len() < 2 {
                return ApduResponse::err(SW_WRONG_DATA);
            }
            (cmd.data[0] as u16) << 8 | (cmd.data[1] as u16)
        }
        0x00 => match state.current_file {
            Some(id) => id,
            None => return ApduResponse::err(SW_FILE_NOT_FOUND),
        },
        _ => return ApduResponse::err(SW_WRONG_DATA),
    };

    let hi = file_id >> 8;
    let key_id_proto = (file_id & 0xFF) as u8;
    let full_key_id = pico2hsm_core::key::KeyId::sc_hsm(0, key_id_proto).0; // u32 internal ID

    let before = state.ef_files.len();
    state.ef_files.retain(|e| e.file_id != file_id);
    let deleted_ef = state.ef_files.len() < before;

    // C4 xx: also remove the key entry itself
    let mut deleted_key = if hi == 0xC4 {
        let before_keys = state.keys.len();
        state.keys.retain(|k| k.key_id != full_key_id);
        state.keys.len() < before_keys
    } else {
        false
    };

    // Also remove from RSA key store (fixes RSA deletion bug).
    #[cfg(feature = "rsa")]
    if hi == 0xC4 {
        let before_rsa = state.rsa_keys.len();
        state.rsa_keys.retain(|k| k.key_id != full_key_id);
        if state.rsa_keys.len() < before_rsa {
            deleted_key = true;
        }
    }

    // Erase from flash (best-effort; do not fail APDU on flash error).
    if deleted_key {
        let _ = store.erase_key(pico2hsm_core::key::KeyId(full_key_id));
        state.generation = state.generation.wrapping_add(1);
    }

    if deleted_ef || deleted_key {
        ApduResponse::ok(&[])
    } else {
        ApduResponse::err(SW_FILE_NOT_FOUND)
    }
}
