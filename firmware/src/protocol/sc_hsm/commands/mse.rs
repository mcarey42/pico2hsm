//! MANAGE SECURITY ENVIRONMENT command handler (INS = 0x22).
//!
//! Configures the security environment (cryptographic context) for a
//! subsequent cryptographic operation command (SIGN, DECRYPT, CIPHER_SYM,
//! PSO, etc.).
//!
//! # Operations
//! - P1=0x41, P2=0xA4: SET for Computation (select key for signing)
//! - P1=0x41, P2=0xB8: SET for Decipherment (select key for decrypt)
//! - P1=0x41, P2=0xB4: SET for Confidentiality (select key for SM)
//! - P1=0xF3, P2=0x03: RESTORE SE#3 (restore to default)
//!
//! # Command data TLV
//! - Tag 0x80: Algorithm OID / mechanism identifier byte
//! - Tag 0x84: Key reference (key ID byte)

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_OK, SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::{ScHsmState, SeOperation};

/// INS byte for MANAGE SECURITY ENVIRONMENT.
pub const INS_MSE: u8 = 0x22;

fn find_tlv<'a>(data: &'a [u8], tag: u8) -> Option<&'a [u8]> {
    let mut i = 0;
    while i + 1 < data.len() {
        let t = data[i];
        i += 1;
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() {
            return None;
        }
        if t == tag {
            return Some(&data[i..i + len]);
        }
        i += len;
    }
    None
}

/// Handle a MANAGE SECURITY ENVIRONMENT APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    match (cmd.p1, cmd.p2) {
        // SET for Computation (sign)
        (0x41, 0xA4) => parse_and_set_se(state, cmd.data, SeOperation::Computation),
        // SET for Decipherment
        (0x41, 0xB8) => parse_and_set_se(state, cmd.data, SeOperation::Decipherment),
        // SET for Confidentiality / SM
        (0x41, 0xB4) => parse_and_set_se(state, cmd.data, SeOperation::Confidentiality),
        // RESTORE SE#3 — reset to default state
        (0xF3, 0x03) => {
            state.current_key_id = None;
            state.current_algo = None;
            state.current_se_op = None;
            ApduResponse::ok(&[])
        }
        _ => ApduResponse::err(SW_WRONG_DATA),
    }
}

fn parse_and_set_se(state: &mut ScHsmState, data: &[u8], op: SeOperation) -> ApduResponse {
    // Tag 0x84: key reference (1 byte key ID)
    let key_id = find_tlv(data, 0x84).and_then(|v| v.first().copied());
    // Tag 0x80: algorithm identifier (1 byte)
    let algo = find_tlv(data, 0x80).and_then(|v| v.first().copied());

    // At least one of key_id or algo should be present
    if key_id.is_none() && algo.is_none() {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    if let Some(kid) = key_id {
        state.current_key_id = Some(kid);
    }
    if let Some(a) = algo {
        state.current_algo = Some(a);
    }
    state.current_se_op = Some(op);

    ApduResponse::ok(&[])
}
