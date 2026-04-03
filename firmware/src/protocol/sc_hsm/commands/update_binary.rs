//! UPDATE BINARY command handler (INS = 0xD6).
//!
//! Writes bytes to the currently selected EF in the virtual filesystem.
//! Used by sc_hsm_update_ef (pkcs15init) after CREATE FILE to store
//! key certificate data (CE xx files) and similar EF data.
//!
//! P1/P2 encode the write offset (big-endian); only offset 0 is supported.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND,
    SW_SECURITY_STATUS,
};

use crate::protocol::sc_hsm::{EfEntry, ScHsmState};

/// INS byte for UPDATE BINARY.
pub const INS_UPDATE_BINARY: u8 = 0xD6;

/// Handle an UPDATE BINARY APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    if !state.pin_verified && !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // The file to write is the currently selected EF (set by the preceding CREATE FILE or SELECT).
    let file_id = match state.current_file {
        Some(id) => id,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // If the file already exists in ef_files, overwrite it.
    if let Some(entry) = state.ef_files.iter_mut().find(|e| e.file_id == file_id) {
        entry.data.clear();
        let _ = entry.data.extend_from_slice(cmd.data);
        return ApduResponse::ok(&[]);
    }

    // Create a new EF entry.
    let mut data_buf: heapless::Vec<u8, { crate::protocol::sc_hsm::MAX_EF_DATA }> =
        heapless::Vec::new();
    let _ = data_buf.extend_from_slice(cmd.data);
    let entry = EfEntry { file_id, data: data_buf };
    match state.ef_files.push(entry) {
        Ok(()) => ApduResponse::ok(&[]),
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}
