//! SELECT command handler (INS = 0xA4) for OpenPGP.
//!
//! Returns FCI containing the full AID and version information.
//! Resets all PIN verification state on SELECT.

use heapless::Vec;
use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_FILE_NOT_FOUND};

use crate::protocol::openpgp::{openpgp_aid, OpenPgpState, OPENPGP_AID_PREFIX};

/// INS byte for SELECT.
pub const INS_SELECT: u8 = 0xA4;

/// Handle a SELECT APDU command.
pub fn handle(state: &mut OpenPgpState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Verify AID prefix match
    if cmd.data.len() < OPENPGP_AID_PREFIX.len()
        || &cmd.data[..OPENPGP_AID_PREFIX.len()] != OPENPGP_AID_PREFIX
    {
        return ApduResponse::err(SW_FILE_NOT_FOUND);
    }

    // Reset security state on SELECT (ISO 7816-4 requirement)
    state.reset_security_state();

    // Build FCI: 6F [ 84 [AID] A5 [ 9F6E [version] ] ]
    let aid = &openpgp_aid();
    // Version data: OpenPGP card version 3.4
    let version: &[u8] = &[0x03, 0x04, 0x00, 0x00];

    // A5 inner: 9F 6E 04 <version 4 bytes> = 7 bytes
    let a5_inner_len: u8 = 2 + 1 + version.len() as u8; // tag(2) + len(1) + data(4) = 7
                                                        // 6F inner: 84 TLV + A5 TLV
    let outer_len: u8 = (2 + aid.len() as u8) + (2 + a5_inner_len);

    let mut fci: Vec<u8, 48> = Vec::new();
    let _ = fci.push(0x6F);
    let _ = fci.push(outer_len);

    // 84: DF name (AID)
    let _ = fci.push(0x84);
    let _ = fci.push(aid.len() as u8);
    let _ = fci.extend_from_slice(aid);

    // A5: proprietary — contains 9F6E version TLV
    let _ = fci.push(0xA5);
    let _ = fci.push(a5_inner_len);
    let _ = fci.push(0x9F);
    let _ = fci.push(0x6E);
    let _ = fci.push(version.len() as u8);
    let _ = fci.extend_from_slice(version);

    ApduResponse::ok(&fci)
}
