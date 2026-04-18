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
pub fn handle(
    state: &mut ScHsmState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
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

    // Remove from key_index: check for both crypto keys and EfFile entries.
    let before_idx = state.key_index.len();

    if hi == 0xCE {
        // CE xx EF files: look up by EfFile KeyId encoding.
        let ef_key_id = pico2hsm_core::key::KeyId::sc_hsm_ef(0, hi as u8, key_id_proto).0;
        state
            .key_index
            .retain(|m| !(m.key_type == 16 && m.key_id == ef_key_id));
        // Erase from flash and clear cache.
        if state.key_index.len() < before_idx {
            let _ = store.erase_key(pico2hsm_core::key::KeyId(ef_key_id));
            state.ef_cache_remove(ef_key_id);
        }
    } else {
        // C4/CC xx crypto key entries.
        state.key_index.retain(|m| m.key_id != full_key_id);
        // Erase from flash.
        if state.key_index.len() < before_idx {
            let _ = store.erase_key(pico2hsm_core::key::KeyId(full_key_id));
            state.generation = state.generation.wrapping_add(1);
        }
    }

    let deleted = state.key_index.len() < before_idx;

    if deleted {
        ApduResponse::ok(&[])
    } else {
        ApduResponse::err(SW_FILE_NOT_FOUND)
    }
}
