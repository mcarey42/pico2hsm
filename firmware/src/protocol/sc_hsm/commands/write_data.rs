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
use pico2hsm_core::key::{AppletId, KeyId};

use crate::protocol::sc_hsm::{KeyMeta, ScHsmState};
use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};
use crate::storage::KeyStore;

/// Not enough memory space in the file (ISO 7816-4).
const SW_WRONG_LENGTH_EF: u16 = 0x6A84;

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
pub fn handle(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
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

    write_at_offset(state, store, target_fid, offset, payload)
}

/// Write `payload` to `file_id` at `offset` (create if needed).
/// Persists to flash via `store` and updates `state.key_index` + `ef_cache`.
fn write_at_offset(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    file_id: u16,
    offset: usize,
    payload: &[u8],
) -> ApduResponse {
    let file_id_hi = (file_id >> 8) as u8;
    let file_id_lo = (file_id & 0xFF) as u8;
    let Some(key_id) = KeyId::sc_hsm_ef_checked(0, file_id_hi, file_id_lo) else {
        return ApduResponse::err(pico2hsm_core::apdu::SW_FILE_NOT_FOUND);
    };

    // Check if this EF already exists in key_index.
    let exists = state
        .key_index
        .iter()
        .any(|m| m.key_type == 16 && m.key_id == key_id.0);

    // Build the complete data buffer by combining existing data with
    // the new payload at the given offset.
    let mut data_buf: heapless::Vec<u8, 4096> = heapless::Vec::new();
    if exists && offset > 0 {
        // Need existing data for offset writes — try ef_cache first,
        // then fall back to flash via cross-core fetch_key RPC.
        // A read failure must fail the write, not zero-fill the file.
        if let Some(existing) = state.ef_cache_get(key_id.0) {
            let _ = data_buf.extend_from_slice(existing);
        } else {
            match store.fetch_key(key_id) {
                Ok(Some(obj)) => {
                    let _ = data_buf.extend_from_slice(&obj.private_key);
                }
                _ => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
            }
        }
        if offset > data_buf.capacity() {
            return ApduResponse::err(SW_WRONG_LENGTH_EF);
        }
        // Pad with zeros up to offset if shorter.
        data_buf.resize(offset, 0x00).ok();
    }
    // Never store a silently truncated file (it would still answer 9000).
    if data_buf.extend_from_slice(payload).is_err() {
        return ApduResponse::err(SW_WRONG_LENGTH_EF);
    }

    if !exists && offset != 0 {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    let mut key_obj = KeyObject::new(
        KmType::Generic,
        key_id.0,
        AppletId::ScHsm,
        AlgorithmId::AesGcm,
    );
    if key_obj.private_key.extend_from_slice(&data_buf).is_err() {
        return ApduResponse::err(SW_WRONG_LENGTH_EF);
    }
    match store.save_key(&key_obj) {
        Ok(()) => {
            // Update the in-memory EF cache so READ BINARY can serve
            // this data back without hitting flash.
            state.ef_cache_put(key_id.0, &data_buf);

            if !exists {
                let meta = KeyMeta {
                    key_id: key_id.0,
                    key_type: 16,     // EfFile
                    algo: file_id_hi, // high byte of file_id, used by list_keys to filter CE entries
                    key_flags: 0,
                };
                let _ = state.key_index.push(meta);
            }
            ApduResponse::ok(&[])
        }
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}
