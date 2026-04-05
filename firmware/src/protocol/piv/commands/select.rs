//! SELECT command handler (INS = 0xA4) for PIV.
//!
//! Returns an Application Property Template (tag 0x61) containing the PIV AID
//! and an application label "PIV". This is the minimal conformant response
//! per NIST SP 800-73-4 Section 3.1.

use pico2hsm_core::apdu::{ApduCommand, ApduResponse};

use crate::protocol::piv::PIV_AID;

/// INS byte for SELECT.
pub const INS_SELECT: u8 = 0xA4;

/// Handle a SELECT APDU for the PIV applet.
///
/// Returns the Application Property Template (tag 0x61):
/// ```text
/// 61 11
///   4F 0B A0 00 00 03 08 00 00 10 00 01 00   -- AID
///   50 03 50 49 56                             -- Label "PIV"
/// ```
pub fn handle(cmd: &ApduCommand<'_>) -> ApduResponse {
    // SELECT by AID: P1=0x04, P2=0x00
    if cmd.p1 != 0x04 || cmd.p2 != 0x00 {
        return ApduResponse::err(0x6A86); // incorrect P1/P2
    }

    // Build Application Property Template (tag 0x61)
    let label = b"PIV";
    let aid_tlv_len = 2 + PIV_AID.len(); // 4F + len + AID
    let label_tlv_len = 2 + label.len(); // 50 + len + label
    let inner_len = aid_tlv_len + label_tlv_len;

    let mut resp = heapless::Vec::<u8, 64>::new();
    let _ = resp.push(0x61);
    let _ = resp.push(inner_len as u8);

    // 4F: AID
    let _ = resp.push(0x4F);
    let _ = resp.push(PIV_AID.len() as u8);
    let _ = resp.extend_from_slice(PIV_AID);

    // 50: Application Label
    let _ = resp.push(0x50);
    let _ = resp.push(label.len() as u8);
    let _ = resp.extend_from_slice(label);

    ApduResponse::ok(&resp)
}
