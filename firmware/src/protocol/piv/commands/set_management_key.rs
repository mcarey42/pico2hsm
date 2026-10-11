//! SET MANAGEMENT KEY (INS = 0xFF) for PIV — Yubico extension.
//!
//! `00 FF FF FF 1B 03 9B 18 <24-byte 3DES key>` (P2=0xFE "touch required"
//! is accepted and treated the same).  This is the command `ykman piv
//! access change-management-key` and `yubico-piv-tool -a set-mgm-key` send.
//!
//! Requires prior management-key mutual authentication (GENERAL
//! AUTHENTICATE, slot 9B).  Without it the factory default key — public in
//! NIST SP 800-73 test vectors — would protect key generation and PUT DATA
//! forever.

use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_SECURITY_STATUS, SW_WRONG_DATA};

use crate::protocol::piv::PivState;

/// INS byte for SET MANAGEMENT KEY.
pub const INS_SET_MGMT_KEY: u8 = 0xFF;

/// Parse and apply the new management key (RAM only; the caller persists).
pub fn handle(state: &mut PivState, cmd: &ApduCommand<'_>) -> ApduResponse {
    if cmd.p1 != 0xFF || !matches!(cmd.p2, 0xFF | 0xFE) {
        return ApduResponse::err(0x6A86);
    }
    if !state.mgmt_key_authenticated {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }
    // 03 (3DES) || 9B (key reference) || 18 (length 24) || key
    let key = match cmd.data {
        [0x03, 0x9B, 0x18, key @ ..] if key.len() == 24 => key,
        _ => return ApduResponse::err(SW_WRONG_DATA),
    };
    state.mgmt_key.copy_from_slice(key);
    ApduResponse::ok(&[])
}
