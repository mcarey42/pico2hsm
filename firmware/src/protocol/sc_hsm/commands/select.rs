//! SELECT command handler (INS = 0xA4) — within SC-HSM protocol context.
//!
//! When the SC-HSM protocol is active, SELECT by file ID (P1=0x00/0x01/0x02)
//! selects a PKCS#15 EF or DF within the virtual filesystem.
//!
//! SELECT by AID (P1=0x04) is handled by the dispatcher BEFORE this handler
//! is called. If it reaches here with P1=0x04, it was not intercepted (should
//! not normally happen, but handle gracefully).

use heapless::Vec;
use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_FILE_NOT_FOUND, SW_OK};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for SELECT.
pub const INS_SELECT: u8 = 0xA4;

/// P2 value meaning "do not return FCI" (ISO 7816-4 §7.1.1).
const P2_NO_FCI: u8 = 0x0C;

/// Build a minimal FCP (File Control Parameters, tag 0x62) response for a
/// transparent EF. The file size is set to `size` bytes.
///
/// Format returned:
/// ```text
/// 62 0B
///   80 02 <size_hi> <size_lo>   -- number of data bytes in the EF
///   82 01 01                    -- file descriptor: transparent EF
///   83 02 <fid_hi>  <fid_lo>    -- file identifier
/// ```
fn build_fcp(fid: u16, size: u16) -> Vec<u8, 16> {
    let mut fci: Vec<u8, 16> = Vec::new();
    let _ = fci.extend_from_slice(&[
        0x62,
        0x0B, // FCP template, 11 bytes content
        0x80,
        0x02,
        (size >> 8) as u8,
        (size & 0xFF) as u8, // file size
        0x82,
        0x01,
        0x01, // transparent EF
        0x83,
        0x02,
        (fid >> 8) as u8,
        (fid & 0xFF) as u8, // file ID
    ]);
    fci
}

/// Return a SELECT response for `fid`.  When `want_fci` is true (P2 ≠ 0x0C),
/// a minimal FCP is included so OpenSC can create a valid `sc_file_t`.
/// Returns `None` if the file is not found, `Some(response)` on success.
fn select_fid(fid: u16, want_fci: bool) -> Option<ApduResponse> {
    // Known static file sizes (0 = empty; 0x0200 = placeholder for dynamic files)
    let size: u16 = match fid {
        0x3F00 => 0,      // MF — DF, no data size
        0x5015 => 0,      // DF.CIA — DF
        0x2F00 => 19,     // EF.DIR
        0x2F02 => 0x0200, // EF.C_DevAut — device cert stub
        0x2F03 => 0x0200, // EF.TokenInfo — written by sc-hsm-tool during INITIALIZE
        0x5031 => 24,     // EF.ODF
        0x5032 => 42,     // EF.TokenInfo
        0xC000 => 40,     // EF.AODF
        0xC100 => 0,      // EF.PrKDF — always empty for SC-HSM
        0xC200 => 0,      // EF.PuKDF — empty initially
        _ => {
            // Dynamic EF ranges: key descriptors (C4xx), key blobs (CCxx), certs (CExx)
            let hi = fid >> 8;
            if hi == 0xC4 || hi == 0xCC || hi == 0xCE {
                0x0400 // 1024 — must cover largest EC CVC (~700 B for P-521)
            } else {
                return None;
            }
        }
    };

    let resp = if want_fci {
        let fcp = build_fcp(fid, size);
        ApduResponse::ok(&fcp)
    } else {
        ApduResponse::ok(&[])
    };
    Some(resp)
}

/// Handle a SELECT APDU command within the SC-HSM context.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    let want_fci = cmd.p2 != P2_NO_FCI;

    let fid: u16 = match cmd.p1 {
        // SELECT by file ID (child of current DF) or from MF/parent
        0x00..=0x02 => {
            if cmd.data.len() >= 2 {
                (cmd.data[0] as u16) << 8 | (cmd.data[1] as u16)
            } else if cmd.data.is_empty() {
                0x3F00 // Select MF
            } else {
                return ApduResponse::err(SW_FILE_NOT_FOUND);
            }
        }

        // SELECT by path from MF (P1=0x08) or current DF (P1=0x09):
        // path is 2-N bytes; last 2 bytes are the leaf file ID.
        0x08 | 0x09 => {
            let path_len = cmd.data.len();
            if path_len < 2 {
                return ApduResponse::err(SW_FILE_NOT_FOUND);
            }
            (cmd.data[path_len - 2] as u16) << 8 | (cmd.data[path_len - 1] as u16)
        }

        // SELECT by AID — dispatcher should have intercepted this, but handle gracefully
        0x04 if cmd.data == crate::protocol::sc_hsm::SC_HSM_AID => {
            return ApduResponse::ok(&[]);
        }

        _ => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // For dynamic EF ranges, verify the file actually exists before claiming success.
    // sc_hsm_update_ef relies on FILE_NOT_FOUND to decide whether to create a new file.
    let hi = fid >> 8;
    if hi == 0xCE {
        // EE certificate files exist only if written via WRITE DATA.
        let file_id_lo = (fid & 0xFF) as u8;
        let ef_key_id = pico2hsm_core::key::KeyId::sc_hsm_ef(0, hi as u8, file_id_lo).0;
        if !state
            .key_index
            .iter()
            .any(|m| m.key_type == 16 && m.key_id == ef_key_id)
        {
            return ApduResponse::err(SW_FILE_NOT_FOUND);
        }
    }
    if hi == 0xCC {
        // Key blob files exist when the corresponding key is in the keystore.
        let key_id_proto = (fid & 0xFF) as u8;
        let full_key_id = pico2hsm_core::key::KeyId::sc_hsm(0, key_id_proto).0;
        let exists = state
            .key_index
            .iter()
            .any(|m| m.key_id == full_key_id && m.key_type != 16);
        if !exists {
            return ApduResponse::err(SW_FILE_NOT_FOUND);
        }
    }
    if hi == 0xC4 {
        // PRKD files exist if:
        // - a key with this key_id is in key_index (dynamically built), OR
        // - the file was written via WRITE DATA and is in key_index as EfFile.
        let key_id_proto = (fid & 0xFF) as u8;
        let full_key_id = pico2hsm_core::key::KeyId::sc_hsm(0, key_id_proto).0;
        let in_keys = state
            .key_index
            .iter()
            .any(|m| m.key_id == full_key_id && m.key_type != 16);
        let file_id_lo = (fid & 0xFF) as u8;
        let ef_key_id = pico2hsm_core::key::KeyId::sc_hsm_ef(0, hi as u8, file_id_lo).0;
        let in_ef = state
            .key_index
            .iter()
            .any(|m| m.key_type == 16 && m.key_id == ef_key_id);
        if !in_keys && !in_ef {
            return ApduResponse::err(SW_FILE_NOT_FOUND);
        }
    }

    match select_fid(fid, want_fci) {
        Some(resp) => {
            // Update the currently selected file so READ BINARY ODD (B1) knows which file to read.
            state.current_file = Some(fid);
            resp
        }
        None => ApduResponse::err(SW_FILE_NOT_FOUND),
    }
}
