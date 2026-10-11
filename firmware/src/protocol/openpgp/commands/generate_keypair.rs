//! GENERATE ASYMMETRIC KEY PAIR command handler (INS = 0x47) for OpenPGP.
//!
//! P1=0x80: generate new key pair (requires PW3 verified)
//! P1=0x81: read back existing public key (no auth required)
//! Data: CRT template tag (B6=SIG, B8=DEC, A4=AUTH) followed by 0x00
//!
//! Response: 7F49 [ 86 [point_len] <uncompressed_point> ]

use pico2hsm_core::{
    apdu::{
        ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_SECURITY_STATUS, SW_WRONG_DATA,
    },
    key::KeyType,
};

use crate::protocol::openpgp::OpenPgpState;

/// INS byte for GENERATE KEY PAIR.
pub const INS_GENERATE_KEYPAIR: u8 = 0x47;

/// Resolve an ECDH OID that wasn't matched by the NIST P-curve checks.
/// Returns Some(X25519) for the X25519 OID when the feature is enabled.
fn ecdh_oid_to_key_type(_oid: &[u8]) -> Option<KeyType> {
    #[cfg(feature = "applet-openpgp-curve25519")]
    {
        // X25519 OID: 1.3.6.1.4.1.3029.1.5.1 = 2B 06 01 04 01 97 55 01 05 01
        if _oid.starts_with(&[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]) {
            return Some(KeyType::X25519);
        }
    }
    None
}

/// Map algorithm attributes to a KeyType for keygen.
fn algo_attrs_to_key_type(attrs: &[u8]) -> Option<KeyType> {
    if attrs.is_empty() {
        return None;
    }
    let algo_id = attrs[0];
    let oid = &attrs[1..];

    match algo_id {
        // ECDSA (0x13)
        0x13 => {
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
        // ECDH (0x12)
        0x12 => {
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
                // X25519: 2B 06 01 04 01 97 55 01 05 01
                ecdh_oid_to_key_type(oid)
            }
        }
        // EdDSA (0x16) — Ed25519
        #[cfg(feature = "applet-openpgp-curve25519")]
        0x16 => {
            // Ed25519 OID: 2B 06 01 04 01 DA 47 0F 01
            if oid.starts_with(&[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]) {
                Some(KeyType::Ed25519)
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
            crate::cdc_log!("OpenPGP GENERATE KEY PAIR start slot=0x{:02x}", crt_tag);
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
                crate::protocol::openpgp::set_key(&mut *priv_slot, &pair.private_key);

                let mut pub_vec: heapless::Vec<u8, 133> = heapless::Vec::new();
                let _ = pub_vec.extend_from_slice(&pair.public_key);
                *pub_slot = Some(pub_vec);

                *key_type_slot = Some(key_type);
            }

            // Build response: 7F49 [ 86 [point_len] <public_point> ]
            crate::cdc_log!("OpenPGP GENERATE KEY PAIR done slot=0x{:02x}", crt_tag);
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

/// Handle GENERATE KEY PAIR and persist the result to flash.
pub fn handle_with_store(
    state: &mut OpenPgpState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    let resp = handle(state, cmd);

    // Only persist new key generation (P1=0x80) on success.
    if cmd.p1 != 0x80 || resp.sw != 0x9000 {
        return resp;
    }

    if cmd.data.is_empty() {
        return resp;
    }
    let crt_tag = cmd.data[0];

    use crate::protocol::openpgp::{SLOT_AUTH, SLOT_DEC, SLOT_SIG};
    use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
    use pico2hsm_core::key::{AppletId, KeyId, KeyType as CoreKeyType};

    let (slot, priv_opt, pub_opt, key_type_opt) = match crt_tag {
        0xB6 => (
            SLOT_SIG,
            &state.sig_private,
            &state.sig_public,
            &state.sig_key_type,
        ),
        0xB8 => (
            SLOT_DEC,
            &state.dec_private,
            &state.dec_public,
            &state.dec_key_type,
        ),
        0xA4 => (
            SLOT_AUTH,
            &state.auth_private,
            &state.auth_public,
            &state.auth_key_type,
        ),
        _ => return resp,
    };

    let (priv_bytes, pub_bytes, key_type) = match (priv_opt, pub_opt, key_type_opt) {
        (Some(pr), Some(pu), Some(kt)) => (pr, pu, kt),
        _ => return resp,
    };

    let algorithm = match key_type {
        CoreKeyType::EcPrivateP256 => match crt_tag {
            0xB8 => AlgorithmId::EcdhP256,
            _ => AlgorithmId::EcdsaP256,
        },
        CoreKeyType::EcPrivateP384 => match crt_tag {
            0xB8 => AlgorithmId::EcdhP384,
            _ => AlgorithmId::EcdsaP384,
        },
        CoreKeyType::EcPrivateP521 => match crt_tag {
            0xB8 => AlgorithmId::EcdhP521,
            _ => AlgorithmId::EcdsaP521,
        },
        #[cfg(feature = "applet-openpgp-curve25519")]
        CoreKeyType::Ed25519 => AlgorithmId::Ed25519,
        #[cfg(feature = "applet-openpgp-curve25519")]
        CoreKeyType::X25519 => AlgorithmId::X25519,
        _ => return resp,
    };

    let key_id = KeyId::openpgp(slot);
    let mut obj = KeyObject {
        key_type: KmKeyType::Ec,
        key_id: key_id.0,
        owner: AppletId::OpenPgp,
        algorithm,
        key_domain: 0,
        use_count: 0,
        generation: 0,
        key_flags: 0,
        timestamp_ms: 0,
        private_key: heapless::Vec::new(),
        public_key: heapless::Vec::new(),
    };
    let _ = obj.private_key.extend_from_slice(priv_bytes);
    let _ = obj.public_key.extend_from_slice(pub_bytes);
    if store.save_key(&obj).is_err() {
        // The key was generated into RAM; drop it so RAM matches flash.
        let (private, public) = match slot {
            SLOT_SIG => (&mut state.sig_private, &mut state.sig_public),
            SLOT_DEC => (&mut state.dec_private, &mut state.dec_public),
            _ => (&mut state.auth_private, &mut state.auth_public),
        };
        crate::protocol::openpgp::wipe_key(private);
        *public = None;
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    }

    resp
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
