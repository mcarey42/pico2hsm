//! GENERATE KEY PAIR command handler (INS = 0x47) for PIV.
//!
//! Generates an asymmetric key pair in a PIV key slot.
//! Requires prior management key authentication.
//!
//! # Command format
//! - CLA=0x00, INS=0x47, P1=0x00, P2=key reference (0x9A/9C/9D/9E)
//! - Data: AC <len> 80 01 <alg_id>
//!
//! # Response format
//! For ECC keys:
//! ```text
//! 7F49 <len>
//!   86 <point_len> <uncompressed_point>  -- 04 || X || Y
//! ```

use pico2hsm_core::{
    apdu::{ApduCommand, ApduResponse},
    key::{KeyId, KeyType as CoreKeyType},
};

use crate::protocol::piv::{PivState, InMemoryPivKey};
use crate::protocol::sc_hsm::FwRng;

/// INS byte for GENERATE KEY PAIR.
pub const INS_GENERATE_KEYPAIR: u8 = 0x47;

/// PIV algorithm ID for ECC P-256.
const ALG_ECC_P256: u8 = 0x11;
/// PIV algorithm ID for ECC P-384.
const ALG_ECC_P384: u8 = 0x14;

/// Valid PIV key slot references.
fn is_valid_key_ref(key_ref: u8) -> bool {
    matches!(key_ref, 0x9A | 0x9C | 0x9D | 0x9E)
}

/// Map key reference to slot index (0-3).
fn key_ref_to_slot(key_ref: u8) -> Option<usize> {
    match key_ref {
        0x9A => Some(0),
        0x9C => Some(1),
        0x9D => Some(2),
        0x9E => Some(3),
        _ => None,
    }
}

/// Handle a GENERATE KEY PAIR APDU command.
pub fn handle(state: &mut PivState, cmd: &ApduCommand<'_>) -> ApduResponse {
    let key_ref = cmd.p2;

    // Validate P1
    if cmd.p1 != 0x00 {
        return ApduResponse::err(0x6A86);
    }

    // Validate key reference
    if !is_valid_key_ref(key_ref) {
        return ApduResponse::err(0x6A86); // incorrect P2
    }

    // Require management key authentication
    if !state.mgmt_key_authenticated {
        return ApduResponse::err(0x6982); // security status not satisfied
    }

    // Parse the Cryptographic Algorithm Identifier Template (tag 0xAC)
    let alg_id = match parse_keygen_template(cmd.data) {
        Some(a) => a,
        None => return ApduResponse::err(0x6A80), // incorrect data
    };

    // Map PIV algorithm ID to core key type
    let key_type = match alg_id {
        ALG_ECC_P256 => CoreKeyType::EcPrivateP256,
        ALG_ECC_P384 => CoreKeyType::EcPrivateP384,
        _ => return ApduResponse::err(0x6A81), // function not supported
    };

    // Generate the key pair
    let mut rng = FwRng;
    let keypair = match crate::crypto::asymmetric::generate_ec_keypair(key_type, &mut rng) {
        Ok(kp) => kp,
        Err(_) => return ApduResponse::err(0x6985), // conditions not satisfied
    };

    // Store in the in-memory key table, replacing any existing key in this slot
    let _slot_idx = key_ref_to_slot(key_ref).unwrap();
    let key_id = KeyId::piv(key_ref);

    // Remove existing key for this slot if any
    state.keys.retain(|k| k.key_id != key_id.0);

    // Push new key
    let mut entry = InMemoryPivKey {
        key_id: key_id.0,
        key_type,
        alg_id,
        private_key: heapless::Vec::new(),
        public_key: heapless::Vec::new(),
    };
    let _ = entry.private_key.extend_from_slice(&keypair.private_key);
    let _ = entry.public_key.extend_from_slice(&keypair.public_key);

    if state.keys.push(entry).is_err() {
        return ApduResponse::err(0x6A84); // not enough memory
    }

    // Build response: 7F49 <len> 86 <point_len> <point>
    let pub_key_bytes = &keypair.public_key;
    let mut resp = heapless::Vec::<u8, 256>::new();

    // 7F49 tag (2-byte tag)
    let _ = resp.push(0x7F);
    let _ = resp.push(0x49);

    // Inner content: 86 <len> <point>
    let inner_len = 2 + pub_key_bytes.len(); // tag(1) + len(1) + data

    // Use BER-TLV length encoding for 7F49
    if inner_len < 128 {
        let _ = resp.push(inner_len as u8);
    } else {
        let _ = resp.push(0x81);
        let _ = resp.push(inner_len as u8);
    }

    // 86: uncompressed EC point
    let _ = resp.push(0x86);
    if pub_key_bytes.len() < 128 {
        let _ = resp.push(pub_key_bytes.len() as u8);
    } else {
        let _ = resp.push(0x81);
        let _ = resp.push(pub_key_bytes.len() as u8);
    }
    let _ = resp.extend_from_slice(pub_key_bytes);

    ApduResponse::ok(&resp)
}

/// Parse the AC template to extract the algorithm ID.
///
/// Expected format: AC <len> 80 01 <alg_id> [optional policy tags...]
fn parse_keygen_template(data: &[u8]) -> Option<u8> {
    if data.len() < 5 {
        return None;
    }

    // Must start with AC tag
    if data[0] != 0xAC {
        return None;
    }

    let ac_len = data[1] as usize;
    if data.len() < 2 + ac_len {
        return None;
    }

    // Search for tag 0x80 (algorithm identifier) in the template
    let mut pos = 2;
    while pos + 2 <= 2 + ac_len {
        let tag = data[pos];
        let len = data[pos + 1] as usize;
        if tag == 0x80 && len == 1 && pos + 2 < data.len() {
            return Some(data[pos + 2]);
        }
        pos += 2 + len;
    }

    None
}
