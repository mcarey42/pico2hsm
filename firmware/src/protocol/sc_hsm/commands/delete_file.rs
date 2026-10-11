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

/// File-ID high byte of key objects (OpenSC `KEY_PREFIX`).
pub const KEY_PREFIX: u8 = 0xCC;

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

    let hi = (file_id >> 8) as u8;
    let lo = (file_id & 0xFF) as u8;

    // Remove from key_index: check for both crypto keys and EfFile entries.
    let before_idx = state.key_index.len();

    if hi == KEY_PREFIX {
        // CC xx: the private/secret key itself (OpenSC KEY_PREFIX).
        if lo >= crate::protocol::sc_hsm::RESERVED_KEY_REF_MIN {
            return ApduResponse::err(SW_FILE_NOT_FOUND);
        }
        let full_key_id = pico2hsm_core::key::KeyId::sc_hsm(0, lo).0;
        let present = state.key_index.iter().any(|m| m.key_id == full_key_id);
        // Erase from flash first: an entry dropped from RAM but still in
        // flash would come back after a reset.
        if present {
            if store
                .erase_key(pico2hsm_core::key::KeyId(full_key_id))
                .is_err()
            {
                return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
            }
            state.key_index.retain(|m| m.key_id != full_key_id);
        }
    } else {
        // Any other FID is an EF stored under its full file ID — C4 (PrKD),
        // CD/CF (data objects), CE/CA (certificates), 2F xx.  These used to
        // be mapped to key slot xx: deleting a PrKD deleted the key.
        let Some(ef_key_id) = pico2hsm_core::key::KeyId::sc_hsm_ef_checked(0, hi, lo) else {
            return ApduResponse::err(SW_FILE_NOT_FOUND);
        };
        let ef_key_id = ef_key_id.0;
        let present = state
            .key_index
            .iter()
            .any(|m| m.key_type == 16 && m.key_id == ef_key_id);
        if present {
            if store
                .erase_key(pico2hsm_core::key::KeyId(ef_key_id))
                .is_err()
            {
                return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
            }
            state
                .key_index
                .retain(|m| !(m.key_type == 16 && m.key_id == ef_key_id));
            state.ef_cache_remove(ef_key_id);
        }
    }

    let deleted = state.key_index.len() < before_idx;

    if deleted {
        ApduResponse::ok(&[])
    } else {
        ApduResponse::err(SW_FILE_NOT_FOUND)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sc_hsm::KeyMeta;
    use pico2hsm_core::key::KeyId;

    fn meta(key_id: u32, key_type: u8) -> KeyMeta {
        KeyMeta {
            key_id,
            key_type,
            algo: 0,
            key_flags: 0,
        }
    }

    #[test]
    fn deleting_prkd_keeps_the_key() {
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        let key = KeyId::sc_hsm(0, 0x05).0;
        let prkd = KeyId::sc_hsm_ef(0, 0xC4, 0x05).0;
        state.key_index.push(meta(key, 1)).unwrap();
        state.key_index.push(meta(prkd, 16)).unwrap();
        let mut store = crate::storage::NullKeyStore;

        let apdu = [0x00, 0xE4, 0x02, 0x00, 0x02, 0xC4, 0x05];
        let cmd = ApduCommand::parse(&apdu).unwrap();
        assert_eq!(handle(&mut state, &mut store, &cmd).sw, SW_OK);
        assert!(state.key_index.iter().any(|m| m.key_id == key), "key kept");
        assert!(!state.key_index.iter().any(|m| m.key_id == prkd));

        let apdu = [0x00, 0xE4, 0x02, 0x00, 0x02, 0xCC, 0x05];
        let cmd = ApduCommand::parse(&apdu).unwrap();
        assert_eq!(handle(&mut state, &mut store, &cmd).sw, SW_OK);
        assert!(state.key_index.is_empty());
    }
}
