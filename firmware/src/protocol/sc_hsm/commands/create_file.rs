//! CREATE FILE command handler (INS = 0xE0).
//!
//! Called by sc_hsm_update_ef (pkcs15init/pkcs15-sc-hsm.c) to create a new
//! transparent EF before writing data via UPDATE BINARY (0xD6).
//!
//! OpenSC sends: `00 E0 00 00 02 <fid_hi> <fid_lo>`
//! The 2-byte data field is the new file identifier.

use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_SECURITY_STATUS, SW_WRONG_DATA};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for CREATE FILE.
pub const INS_CREATE_FILE: u8 = 0xE0;

/// Handle a CREATE FILE APDU command.
///
/// We only record the file ID as the current selected file.
/// The actual EF entry is created lazily by UPDATE BINARY.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    if !state.pin_verified && !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    if cmd.data.len() < 2 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    let file_id: u16 = (cmd.data[0] as u16) << 8 | (cmd.data[1] as u16);
    state.current_file = Some(file_id);

    ApduResponse::ok(&[])
}
