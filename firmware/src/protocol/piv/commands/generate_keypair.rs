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
    crate::cdc_log!("PIV GENERATE KEY PAIR start slot=0x{:02x}", cmd.p2);
    let key_ref = cmd.p2;

    // Validate P1
    if cmd.p1 != 0x00 {
        return ApduResponse::err(0x6A86);
    }

    // Validate key reference
    if !is_valid_key_ref(key_ref) {
        return ApduResponse::err(0x6A86); // incorrect P2
    }

    // Require management key authentication OR PIN verification.
    if !state.mgmt_key_authenticated && !state.pin_verified {
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

    // Build response per NIST SP 800-73-4 Part 2 Table 3.3-1:
    //   7C [len]  Dynamic Authentication Template
    //     7F49 [len]  Public Key
    //       86 [len]  EC Point (uncompressed)
    let pub_key_bytes = &keypair.public_key;

    // Build inner 7F49 content: 86 <len> <point>
    let mut inner_7f49 = heapless::Vec::<u8, 128>::new();
    let _ = inner_7f49.push(0x86);
    if pub_key_bytes.len() < 128 {
        let _ = inner_7f49.push(pub_key_bytes.len() as u8);
    } else {
        let _ = inner_7f49.push(0x81);
        let _ = inner_7f49.push(pub_key_bytes.len() as u8);
    }
    let _ = inner_7f49.extend_from_slice(pub_key_bytes);

    // Build 7F49 TLV: 7F 49 <len> <inner>
    let mut tag_7f49 = heapless::Vec::<u8, 160>::new();
    let _ = tag_7f49.push(0x7F);
    let _ = tag_7f49.push(0x49);
    if inner_7f49.len() < 128 {
        let _ = tag_7f49.push(inner_7f49.len() as u8);
    } else {
        let _ = tag_7f49.push(0x81);
        let _ = tag_7f49.push(inner_7f49.len() as u8);
    }
    let _ = tag_7f49.extend_from_slice(&inner_7f49);

    // Wrap in 7C Dynamic Authentication Template
    let mut resp = heapless::Vec::<u8, 256>::new();
    let _ = resp.push(0x7C);
    if tag_7f49.len() < 128 {
        let _ = resp.push(tag_7f49.len() as u8);
    } else {
        let _ = resp.push(0x81);
        let _ = resp.push(tag_7f49.len() as u8);
    }
    let _ = resp.extend_from_slice(&tag_7f49);

    crate::cdc_log!("PIV GENERATE KEY PAIR done key=0x{:08x} algo=0x{:02x}", key_id.0, alg_id);
    ApduResponse::ok(&resp)
}

/// Handle GENERATE KEY PAIR and persist the result to flash.
pub fn handle_with_store(
    state: &mut PivState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    let resp = handle(state, cmd);

    // Only persist on success (SW=9000).
    if resp.sw == 0x9000 {
        let key_ref = cmd.p2;
        let key_id = KeyId::piv(key_ref);

        if let Some(entry) = state.keys.iter().find(|k| k.key_id == key_id.0) {
            use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
            use pico2hsm_core::key::AppletId;

            let algorithm = match entry.key_type {
                CoreKeyType::EcPrivateP256 => AlgorithmId::EcdsaP256,
                CoreKeyType::EcPrivateP384 => AlgorithmId::EcdsaP384,
                _ => return resp,
            };

            let mut obj = KeyObject {
                key_type: KmKeyType::Ec,
                key_id: key_id.0,
                owner: AppletId::Piv,
                algorithm,
                key_domain: 0,
                use_count: 0,
                generation: 0,
                key_flags: 0,
                timestamp_ms: 0,
                private_key: heapless::Vec::new(),
                public_key: heapless::Vec::new(),
            };
            let _ = obj.private_key.extend_from_slice(&entry.private_key);
            let _ = obj.public_key.extend_from_slice(&entry.public_key);
            let _ = store.save_key(&obj);
        }
    }

    resp
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
