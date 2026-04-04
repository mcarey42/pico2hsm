//! WRITE DATA command handler (INS = 0xD7).
//!
//! SC-HSM-specific command that stores an arbitrary data file identified by
//! the P1||P2 file identifier. Used by sc-hsm-tool during initialization to
//! write device certificate data (e.g. EF.C.DevAut at 0x2F03) and by
//! pkcs11-tool / pkcs15-init to store key descriptors (C4xx PRKD) and
//! EE certificates (CExx CVC).
//!
//! # Command data format
//!
//! ALL WRITE DATA APDUs (regardless of P1P2) carry TLV-encoded data:
//!
//!   `54 02 <off_hi> <off_lo>  53 <len> <payload>`
//!
//! where `<len>` is a BER-TLV length (1-, 2- or 3-byte).
//!
//! # Write target determination
//!
//! - **P1P2 ≠ 0x0000**: Write `payload` to the file at `fid = P1||P2` at
//!   `offset`.  Updates both `current_file` and `write_target_file = fid`.
//!
//! - **P1P2 = 0x0000**: Write `payload` to `current_file` at `offset`.
//!   Does NOT change `current_file` or `write_target_file`.
//!
//! # Security
//! Requires an active User PIN or SO-PIN session.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_OK, SW_SECURITY_STATUS,
    SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::{EfEntry, ScHsmState};

/// INS byte for WRITE DATA (SC-HSM extension).
pub const INS_WRITE_DATA: u8 = 0xD7;

/// Parse a BER-TLV length from `data[pos..]`.
/// Returns `(length, new_pos)` or `None` if malformed.
fn parse_ber_len(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    if pos >= data.len() {
        return None;
    }
    let b = data[pos];
    if b < 0x80 {
        Some((b as usize, pos + 1))
    } else if b == 0x81 {
        if pos + 1 >= data.len() {
            return None;
        }
        Some((data[pos + 1] as usize, pos + 2))
    } else if b == 0x82 {
        if pos + 2 >= data.len() {
            return None;
        }
        let len = (data[pos + 1] as usize) << 8 | (data[pos + 2] as usize);
        Some((len, pos + 3))
    } else {
        None // lengths > 65535 not needed here
    }
}

/// Parse the TLV payload from WRITE DATA command data:
///   `54 02 <off_hi> <off_lo>  53 <BER-len> <payload>`
/// Returns `(offset, payload)` or `None` on malformed input.
fn parse_write_tlv(data: &[u8]) -> Option<(usize, &[u8])> {
    // 54 02 off_hi off_lo
    if data.len() < 4 || data[0] != 0x54 || data[1] != 0x02 {
        return None;
    }
    let offset = (data[2] as usize) << 8 | (data[3] as usize);

    // 53 <len> <payload>
    if data.len() < 5 || data[4] != 0x53 {
        return None;
    }
    let (payload_len, payload_start) = parse_ber_len(data, 5)?;
    if data.len() < payload_start + payload_len {
        return None;
    }
    Some((offset, &data[payload_start..payload_start + payload_len]))
}

/// Handle a WRITE DATA APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Security requirement: reject if no PIN session is active.
    if !state.pin_verified && !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let file_id: u16 = (cmd.p1 as u16) << 8 | (cmd.p2 as u16);

    // Parse TLV data to get the write offset and payload.
    let (offset, payload) = match parse_write_tlv(cmd.data) {
        Some(v) => v,
        None => return ApduResponse::err(SW_WRONG_DATA),
    };

    // Determine the target file.
    let target_fid: u16 = if file_id != 0x0000 {
        // Addressed write: update both current_file and write_target_file.
        state.current_file = Some(file_id);
        state.write_target_file = Some(file_id);
        file_id
    } else {
        // Implicit write: use the currently selected file.
        match state.current_file {
            Some(fid) => fid,
            None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
        }
    };

    write_at_offset(state, target_fid, offset, payload)
}

/// Write `payload` to `file_id` at `offset` (create if needed).
fn write_at_offset(
    state: &mut ScHsmState,
    file_id: u16,
    offset: usize,
    payload: &[u8],
) -> ApduResponse {
    if let Some(entry) = state.ef_files.iter_mut().find(|e| e.file_id == file_id) {
        if offset == 0 {
            entry.data.clear();
        } else {
            // Pad with zeros up to offset if file is shorter.
            while entry.data.len() < offset {
                let _ = entry.data.push(0x00);
            }
            entry.data.truncate(offset);
        }
        let _ = entry.data.extend_from_slice(payload);
        return ApduResponse::ok(&[]);
    }

    // New entry: offset must be 0 for a fresh file.
    if offset != 0 {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }
    let mut data_buf: heapless::Vec<u8, { crate::protocol::sc_hsm::MAX_EF_DATA }> =
        heapless::Vec::new();
    let _ = data_buf.extend_from_slice(payload);
    let entry = EfEntry { file_id, data: data_buf };
    match state.ef_files.push(entry) {
        Ok(()) => ApduResponse::ok(&[]),
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}
