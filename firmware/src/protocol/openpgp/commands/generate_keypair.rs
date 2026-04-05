//! GENERATE ASYMMETRIC KEY PAIR command handler (INS = 0x47) for OpenPGP.
//!
//! P1=0x80: generate new key pair (requires PW3 verified)
//! P1=0x81: read back existing public key (no auth required)
//! Data: CRT template tag (B6=SIG, B8=DEC, A4=AUTH) followed by 0x00
//!
//! Response: 7F49 [ 86 [point_len] <uncompressed_point> ]

use pico2hsm_core::{
    apdu::{
        ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_SECURITY_STATUS,
        SW_WRONG_DATA,
    },
    key::KeyType,
};

use crate::protocol::openpgp::OpenPgpState;

/// INS byte for GENERATE KEY PAIR.
pub const INS_GENERATE_KEYPAIR: u8 = 0x47;

/// Map algorithm attributes to a KeyType for keygen.
fn algo_attrs_to_key_type(attrs: &[u8]) -> Option<KeyType> {
    if attrs.is_empty() {
        return None;
    }
    let algo_id = attrs[0];
    let oid = &attrs[1..];

    match algo_id {
        // ECDSA (0x13) or ECDH (0x12)
        0x12 | 0x13 => {
            // P-256: 2A 86 48 CE 3D 03 01 07
            if oid.starts_with(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]) {
                Some(KeyType::EcPrivateP256)
            }
            // P-384: 2B 81 04 00 22
            else if oid.starts_with(&[0x2B, 0x81, 0x04, 0x00, 0x22]) {
                Some(KeyType::EcPrivateP384)
            }
            // P-521: 2B 81 04 00 23
            else if oid.starts_with(&[0x2B, 0x81, 0x04, 0x00, 0x23]) {
                Some(KeyType::EcPrivateP521)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Handle a GENERATE ASYMMETRIC KEY PAIR APDU command.
pub fn handle(state: &mut OpenPgpState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Parse CRT template tag from data
    if cmd.data.len() < 2 {
        return ApduResponse::err(SW_WRONG_DATA);
    }
    let crt_tag = cmd.data[0];

    // Determine which slot
    let (priv_slot, pub_slot, key_type_slot, algo_attrs) = match crt_tag {
        0xB6 => (
            &mut state.sig_private as *mut _,
            &mut state.sig_public as *mut _,
            &mut state.sig_key_type as *mut _,
            state.algo_sig.clone(),
        ),
        0xB8 => (
            &mut state.dec_private as *mut _,
            &mut state.dec_public as *mut _,
            &mut state.dec_key_type as *mut _,
            state.algo_dec.clone(),
        ),
        0xA4 => (
            &mut state.auth_private as *mut _,
            &mut state.auth_public as *mut _,
            &mut state.auth_key_type as *mut _,
            state.algo_auth.clone(),
        ),
        _ => return ApduResponse::err(SW_WRONG_DATA),
    };

    match cmd.p1 {
        // P1=0x80: generate new key pair
        0x80 => {
            if !state.pw3_verified {
                return ApduResponse::err(SW_SECURITY_STATUS);
            }

            let key_type = match algo_attrs_to_key_type(&algo_attrs) {
                Some(kt) => kt,
                None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
            };

            // Generate key pair using the crypto module
            let mut rng = crate::protocol::sc_hsm::FwRng;
            let pair = match crate::crypto::asymmetric::generate_ec_keypair(key_type, &mut rng) {
                Ok(p) => p,
                Err(_) => return ApduResponse::err(0x6F00), // generation failed
            };

            // Store key material (SAFETY: raw pointers are valid since we
            // have &mut state above; the borrow checker can't see through
            // the raw-pointer indirection but we know the slots are disjoint.)
            unsafe {
                let mut priv_vec: heapless::Vec<u8, 66> = heapless::Vec::new();
                let _ = priv_vec.extend_from_slice(&pair.private_key);
                *priv_slot = Some(priv_vec);

                let mut pub_vec: heapless::Vec<u8, 133> = heapless::Vec::new();
                let _ = pub_vec.extend_from_slice(&pair.public_key);
                *pub_slot = Some(pub_vec);

                *key_type_slot = Some(key_type);
            }

            // Build response: 7F49 [ 86 [point_len] <public_point> ]
            build_pubkey_response(&pair.public_key)
        }

        // P1=0x81: read existing public key
        0x81 => {
            let pub_key = unsafe { &*pub_slot };
            match pub_key {
                Some(pk) => build_pubkey_response(pk),
                None => ApduResponse::err(0x6A88), // no key present
            }
        }

        _ => ApduResponse::err(SW_WRONG_DATA),
    }
}

/// Build the public key response TLV: 7F49 [ 86 [len] <point> ]
fn build_pubkey_response(public_key: &[u8]) -> ApduResponse {
    let mut resp = heapless::Vec::<u8, 256>::new();

    // 86 TLV
    let tag86_len = 1 + len_bytes_count(public_key.len()) + public_key.len();

    // 7F49 tag + length
    let _ = resp.push(0x7F);
    let _ = resp.push(0x49);
    push_ber_length(&mut resp, tag86_len);

    // 86 tag
    let _ = resp.push(0x86);
    push_ber_length(&mut resp, public_key.len());
    let _ = resp.extend_from_slice(public_key);

    ApduResponse::ok(&resp)
}

/// Count how many bytes a BER length encoding takes.
fn len_bytes_count(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len < 0x100 {
        2
    } else {
        3
    }
}

/// Push a BER-TLV length field.
fn push_ber_length(buf: &mut heapless::Vec<u8, 256>, len: usize) {
    if len < 0x80 {
        let _ = buf.push(len as u8);
    } else if len < 0x100 {
        let _ = buf.push(0x81);
        let _ = buf.push(len as u8);
    } else {
        let _ = buf.push(0x82);
        let _ = buf.push((len >> 8) as u8);
        let _ = buf.push((len & 0xFF) as u8);
    }
}
