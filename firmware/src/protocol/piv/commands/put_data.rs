//! PUT DATA command handler (INS = 0xDB) for PIV.
//!
//! Stores PIV data objects (certificates, CHUID, CCC, etc.) into the
//! in-memory data object store. Requires management key authentication.
//!
//! # Command format
//! ```text
//! 00 DB 3F FF <Lc>
//!   5C <tag_len> <object_tag_bytes>
//!   53 <content_len> <object_content>
//! ```

use pico2hsm_core::apdu::{ApduCommand, ApduResponse};

use crate::protocol::piv::{PivDataObject, PivState, MAX_PIV_DATA_SIZE};

/// INS byte for PUT DATA.
pub const INS_PUT_DATA: u8 = 0xDB;

/// PUT DATA with persistence: the object is written to flash, so PIV
/// certificates, CHUID etc. survive a reset.  A failed write restores the
/// previous object in RAM and returns 6581.
pub fn handle_with_store(
    state: &mut PivState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    let Some(tag_low) = object_tag_low(cmd.data) else {
        return handle(state, cmd);
    };
    if !state.mgmt_key_authenticated {
        return handle(state, cmd);
    }
    let previous = state
        .data_objects
        .iter()
        .find(|o| o.tag_low == tag_low)
        .cloned();
    // RAM holds a few objects as a cache; flash holds them all (GET DATA
    // reads through).  Make room by evicting the oldest cached object —
    // it is already on flash.
    let mut evicted = None;
    if previous.is_none() && state.data_objects.is_full() {
        evicted = Some(state.data_objects.remove(0));
    }
    let resp = handle(state, cmd);
    let saved = if resp.sw != pico2hsm_core::apdu::SW_OK {
        Ok(())
    } else {
        let kid = crate::protocol::piv::Piv::piv_data_object_key_id(tag_low);
        match state.data_objects.iter().find(|o| o.tag_low == tag_low) {
            Some(o) => crate::protocol::piv::Piv::save_data_object_to_store(o, store),
            // `53 00`: deleted — remove it from flash too.
            None => match store.fetch_key(kid) {
                Ok(None) => Ok(()),
                Ok(Some(_)) => store.erase_key(kid),
                Err(e) => Err(e),
            },
        }
    };
    if resp.sw != pico2hsm_core::apdu::SW_OK || saved.is_err() {
        state.data_objects.retain(|o| o.tag_low != tag_low);
        for old in [previous, evicted].into_iter().flatten() {
            let _ = state.data_objects.push(old);
        }
        if saved.is_err() {
            return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
        }
    }
    resp
}

/// The stored-object tag (low byte) a GET/PUT DATA body names:
/// `5C 03 5F C1 xx` or `5C 01 7E` (discovery object).
pub fn object_tag_low(data: &[u8]) -> Option<u8> {
    match data {
        [0x5C, 0x03, 0x5F, 0xC1, low, ..] => Some(*low),
        [0x5C, 0x01, 0x7E, ..] => Some(0x7E),
        _ => None,
    }
}

/// Handle a PUT DATA APDU command.
pub fn handle(state: &mut PivState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // P1=0x3F, P2=0xFF
    if cmd.p1 != 0x3F || cmd.p2 != 0xFF {
        return ApduResponse::err(0x6A86);
    }

    // Require management key authentication
    if !state.mgmt_key_authenticated {
        return ApduResponse::err(0x6982); // security status not satisfied
    }

    let data = cmd.data;
    if data.len() < 3 {
        return ApduResponse::err(0x6A80);
    }

    // Parse 5C tag (object identifier)
    if data[0] != 0x5C {
        return ApduResponse::err(0x6A80);
    }
    let tag_len = data[1] as usize;
    if data.len() < 2 + tag_len {
        return ApduResponse::err(0x6A80);
    }
    let tag_bytes = &data[2..2 + tag_len];

    // Determine tag_low for storage
    let tag_low = match tag_bytes {
        [0x5F, 0xC1, low] => *low,
        [0x7E] => 0x7E,
        _ => return ApduResponse::err(0x6A82), // unrecognised tag
    };

    // Parse 53 tag (content)
    let rest = &data[2 + tag_len..];
    if rest.is_empty() || rest[0] != 0x53 {
        return ApduResponse::err(0x6A80);
    }

    // BER length decode
    let (content_len, content_start) = if rest.len() < 2 {
        return ApduResponse::err(0x6A80);
    } else if rest[1] < 0x80 {
        (rest[1] as usize, 2)
    } else if rest[1] == 0x81 && rest.len() >= 3 {
        (rest[2] as usize, 3)
    } else if rest[1] == 0x82 && rest.len() >= 4 {
        (((rest[2] as usize) << 8) | rest[3] as usize, 4)
    } else {
        return ApduResponse::err(0x6A80);
    };

    if rest.len() < content_start + content_len {
        return ApduResponse::err(0x6A80);
    }

    let content = &rest[content_start..content_start + content_len];

    // `53 00` deletes the object (ykman, yubico-piv-tool).
    if content.is_empty() {
        state.data_objects.retain(|o| o.tag_low != tag_low);
        return ApduResponse::ok(&[]);
    }

    // Build the complete stored object (including the 53 wrapper) so GET
    // DATA can return it directly.  The wrapper counts against the capacity:
    // refuse rather than silently truncate the object.
    let mut obj_data = heapless::Vec::<u8, MAX_PIV_DATA_SIZE>::new();
    let header: &[u8] = if content_len < 128 {
        &[0x53, content_len as u8]
    } else if content_len < 256 {
        &[0x53, 0x81, content_len as u8]
    } else {
        &[
            0x53,
            0x82,
            (content_len >> 8) as u8,
            (content_len & 0xFF) as u8,
        ]
    };
    if obj_data.extend_from_slice(header).is_err() || obj_data.extend_from_slice(content).is_err() {
        return ApduResponse::err(0x6A84); // not enough memory
    }

    // Remove existing object with this tag
    state.data_objects.retain(|o| o.tag_low != tag_low);

    // Store new object
    let entry = PivDataObject {
        tag_low,
        data: obj_data,
    };
    if state.data_objects.push(entry).is_err() {
        return ApduResponse::err(0x6A84); // not enough memory
    }

    ApduResponse::ok(&[])
}
