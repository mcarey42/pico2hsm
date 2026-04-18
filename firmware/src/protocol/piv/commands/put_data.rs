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

    if content.len() > MAX_PIV_DATA_SIZE {
        return ApduResponse::err(0x6A84); // not enough memory
    }

    // Build the complete stored object (including the 53 wrapper)
    let mut obj_data = heapless::Vec::<u8, MAX_PIV_DATA_SIZE>::new();
    // Store the raw 53-wrapped content so GET DATA can return it directly
    let _ = obj_data.push(0x53);
    if content_len < 128 {
        let _ = obj_data.push(content_len as u8);
    } else if content_len < 256 {
        let _ = obj_data.push(0x81);
        let _ = obj_data.push(content_len as u8);
    } else {
        let _ = obj_data.push(0x82);
        let _ = obj_data.push((content_len >> 8) as u8);
        let _ = obj_data.push((content_len & 0xFF) as u8);
    }
    let _ = obj_data.extend_from_slice(content);

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
