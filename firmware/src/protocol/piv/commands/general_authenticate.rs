//! GENERAL AUTHENTICATE command handler (INS = 0x87) for PIV.
//!
//! Handles:
//! - Asymmetric sign/decrypt with slots 9A, 9C, 9D, 9E
//! - 3DES mutual authentication with management key (slot 9B)
//! - Random challenge generation

use pico2hsm_core::{
    apdu::{ApduCommand, ApduResponse},
    key::{KeyId, KeyType as CoreKeyType},
};

use crate::protocol::piv::PivState;
use crate::protocol::sc_hsm::FwRng;

/// INS byte for GENERAL AUTHENTICATE.
pub const INS_GENERAL_AUTHENTICATE: u8 = 0x87;

/// PIV algorithm IDs.
const ALG_3DES: u8 = 0x03;
const ALG_ECC_P256: u8 = 0x11;
const ALG_ECC_P384: u8 = 0x14;

/// Handle a GENERAL AUTHENTICATE APDU command (non-store path).
pub fn handle(state: &mut PivState, cmd: &ApduCommand<'_>) -> ApduResponse {
    let mut null_store = crate::storage::NullKeyStore;
    handle_with_store(state, &mut null_store, cmd)
}

/// Handle a GENERAL AUTHENTICATE APDU command with access to persistent storage.
pub fn handle_with_store(state: &mut PivState, store: &mut dyn crate::storage::KeyStore, cmd: &ApduCommand<'_>) -> ApduResponse {
    let alg_id = cmd.p1;
    let key_ref = cmd.p2;

    // Parse the Dynamic Authentication Template (tag 0x7C)
    let data = cmd.data;
    if data.len() < 4 || data[0] != 0x7C {
        return ApduResponse::err(0x6A80); // incorrect data
    }

    // BER length decode for 7C
    let (dat_len, dat_start) = ber_length(&data[1..]);
    if dat_start == 0 {
        return ApduResponse::err(0x6A80);
    }
    let dat_offset = 1 + dat_start;
    let inner = &data[dat_offset..data.len().min(dat_offset + dat_len)];

    match key_ref {
        0x9B => handle_mgmt_auth(state, alg_id, inner),
        0x9A | 0x9C | 0x9D | 0x9E => handle_asymmetric_auth(state, store, alg_id, key_ref, inner),
        0x82..=0x95 => ApduResponse::err(0x6A86), // retired slots: incorrect parameters
        _ => ApduResponse::err(0x6A86), // incorrect P2
    }
}

/// Handle management key mutual authentication (3DES, slot 0x9B).
///
/// Two-round protocol:
/// 1. Host requests witness: inner = `80 00` -> card returns `7C { 80 <enc_nonce> }`
/// 2. Host responds: inner = `80 <decrypted_witness> 81 <host_challenge>`
///    -> card returns `7C { 82 <enc_host_challenge> }`
fn handle_mgmt_auth(state: &mut PivState, alg_id: u8, inner: &[u8]) -> ApduResponse {
    if alg_id != ALG_3DES {
        return ApduResponse::err(0x6A86); // only 3DES supported for 9B
    }

    // Parse inner tags
    let tags = parse_dat_tags(inner);

    // Case 1: Request witness — inner contains tag 0x80 with empty value
    if let Some(witness_val) = tags.tag_80 {
        if witness_val.is_empty() && tags.tag_81.is_none() {
            // Generate 8-byte random nonce
            let mut nonce = [0u8; 8];
            fill_random_bytes(&mut nonce);

            // Store the plaintext nonce for later verification
            state.mgmt_challenge = Some(nonce);

            // Encrypt the nonce with the management key using 3DES-ECB
            let encrypted = match tdes_encrypt_ecb(&state.mgmt_key, &nonce) {
                Some(e) => e,
                None => return ApduResponse::err(0x6985),
            };

            // Build response: 7C { 80 08 <encrypted> }
            let mut resp = heapless::Vec::<u8, 32>::new();
            let _ = resp.push(0x7C);
            let _ = resp.push(10); // 80 + 08 + 8 bytes
            let _ = resp.push(0x80);
            let _ = resp.push(8);
            let _ = resp.extend_from_slice(&encrypted);

            return ApduResponse::ok(&resp);
        }

        // Case 2: Host returns decrypted witness + host challenge
        if let (Some(witness), Some(challenge)) = (tags.tag_80, tags.tag_81) {
            if witness.len() != 8 || challenge.len() != 8 {
                return ApduResponse::err(0x6A80);
            }

            // Verify the witness matches our stored nonce
            let stored_nonce = match state.mgmt_challenge.take() {
                Some(n) => n,
                None => return ApduResponse::err(0x6985), // no pending challenge
            };

            // The host should have decrypted our encrypted nonce to get the plaintext back.
            // Compare the decrypted witness with our original nonce.
            if !constant_time_eq(witness, &stored_nonce) {
                state.mgmt_key_authenticated = false;
                return ApduResponse::err(0x6982); // security status not satisfied
            }

            // Host witness verified. Now encrypt the host's challenge.
            let enc_response = match tdes_encrypt_ecb(&state.mgmt_key, challenge) {
                Some(e) => e,
                None => return ApduResponse::err(0x6985),
            };

            state.mgmt_key_authenticated = true;

            // Build response: 7C { 82 08 <enc_host_challenge> }
            let mut resp = heapless::Vec::<u8, 32>::new();
            let _ = resp.push(0x7C);
            let _ = resp.push(10);
            let _ = resp.push(0x82);
            let _ = resp.push(8);
            let _ = resp.extend_from_slice(&enc_response);

            return ApduResponse::ok(&resp);
        }
    }

    // Case: Request random challenge (tag 0x81 empty)
    if let Some(challenge_val) = tags.tag_81 {
        if challenge_val.is_empty() && tags.tag_80.is_none() {
            // Generate random bytes
            let mut random = [0u8; 8];
            fill_random_bytes(&mut random);

            let mut resp = heapless::Vec::<u8, 32>::new();
            let _ = resp.push(0x7C);
            let _ = resp.push(10);
            let _ = resp.push(0x81);
            let _ = resp.push(8);
            let _ = resp.extend_from_slice(&random);

            return ApduResponse::ok(&resp);
        }
    }

    ApduResponse::err(0x6A80) // incorrect data
}

/// Handle asymmetric authentication (sign/decrypt with 9A/9C/9D/9E).
///
/// Command: 7C { 82 00, 81 <hash> }
/// Response: 7C { 82 <signature> }
fn handle_asymmetric_auth(
    state: &mut PivState,
    store: &mut dyn crate::storage::KeyStore,
    alg_id: u8,
    key_ref: u8,
    inner: &[u8],
) -> ApduResponse {
    // Check PIN requirement based on slot
    match key_ref {
        0x9E => {} // Card Authentication — no PIN required
        0x9C => {
            // Digital Signature — PIN always required (every use)
            if !state.pin_verified {
                return ApduResponse::err(0x6982);
            }
        }
        0x9A | 0x9D => {
            // Authentication / Key Management — PIN once per session
            if !state.pin_verified {
                return ApduResponse::err(0x6982);
            }
        }
        _ => return ApduResponse::err(0x6A86),
    }

    // Determine key type from algorithm
    let key_type = match alg_id {
        ALG_ECC_P256 => CoreKeyType::EcPrivateP256,
        ALG_ECC_P384 => CoreKeyType::EcPrivateP384,
        _ => return ApduResponse::err(0x6A86), // unsupported algorithm
    };

    // Parse inner tags
    let tags = parse_dat_tags(inner);

    // For signing: expect tag 82 (empty = compute response) and tag 81 (input data)
    if let Some(input) = tags.tag_81 {
        if tags.tag_82_empty {
            // Look up the key from flash via store.
            let piv_key_id = KeyId::piv(key_ref);

            // Verify key exists in key_index.
            let meta = match state.key_index.iter().find(|m| m.key_id == piv_key_id.0) {
                Some(m) => m,
                None => return ApduResponse::err(0x6A88), // reference data not found
            };

            // Verify key type matches.
            if meta.key_type != key_type as u8 {
                return ApduResponse::err(0x6A80);
            }

            // Fetch key material from flash.
            let key_obj = match store.fetch_key(piv_key_id) {
                Ok(Some(obj)) => obj,
                _ => return ApduResponse::err(0x6A88), // reference data not found
            };

            // Copy private key to stack buffer
            let mut priv_buf = [0u8; 66];
            let priv_len = key_obj.private_key.len();
            priv_buf[..priv_len].copy_from_slice(&key_obj.private_key);

            // Sign with ECDSA. Input is the raw hash digest.
            let mut rng = FwRng;
            let sig = match crate::crypto::asymmetric::ecdsa_sign(
                key_type,
                &priv_buf[..priv_len],
                input,
                &mut rng,
            ) {
                Ok(s) => s,
                Err(_) => return ApduResponse::err(0x6985),
            };

            // Build response: 7C { 82 <sig_len> <signature> }
            let mut resp = heapless::Vec::<u8, 256>::new();
            let _ = resp.push(0x7C);
            let sig_inner_len = 2 + sig.len(); // tag(1) + len(1+) + data
            if sig_inner_len < 128 {
                let _ = resp.push(sig_inner_len as u8);
            } else {
                let _ = resp.push(0x81);
                let _ = resp.push(sig_inner_len as u8);
            }
            let _ = resp.push(0x82);
            if sig.len() < 128 {
                let _ = resp.push(sig.len() as u8);
            } else {
                let _ = resp.push(0x81);
                let _ = resp.push(sig.len() as u8);
            }
            let _ = resp.extend_from_slice(&sig);

            // NIST SP 800-73-4 Part 2 §3.3.2 — PIN Always for slot 9C:
            // clear pin_verified after each successful Digital Signature use.
            if key_ref == 0x9C {
                state.pin_verified = false;
            }

            return ApduResponse::ok(&resp);
        }
    }

    ApduResponse::err(0x6A80) // incorrect data
}

// ---------------------------------------------------------------------------
// Parsed DAT tags
// ---------------------------------------------------------------------------

struct DatTags<'a> {
    tag_80: Option<&'a [u8]>,  // Witness
    tag_81: Option<&'a [u8]>,  // Challenge
    tag_82_empty: bool,        // Response (empty = request)
}

/// Parse the inner tags of a Dynamic Authentication Template.
fn parse_dat_tags(data: &[u8]) -> DatTags<'_> {
    let mut tags = DatTags {
        tag_80: None,
        tag_81: None,
        tag_82_empty: false,
    };

    let mut pos = 0;
    while pos < data.len() {
        if pos + 1 >= data.len() {
            break;
        }
        let tag = data[pos];
        let len = data[pos + 1] as usize;
        pos += 2;

        match tag {
            0x80 => {
                if len == 0 {
                    tags.tag_80 = Some(&[]);
                } else if pos + len <= data.len() {
                    tags.tag_80 = Some(&data[pos..pos + len]);
                }
            }
            0x81 => {
                if len == 0 {
                    tags.tag_81 = Some(&[]);
                } else if pos + len <= data.len() {
                    tags.tag_81 = Some(&data[pos..pos + len]);
                }
            }
            0x82 => {
                if len == 0 {
                    tags.tag_82_empty = true;
                }
            }
            _ => {} // skip unknown tags
        }
        pos += len;
    }

    tags
}

// ---------------------------------------------------------------------------
// 3DES helpers
// ---------------------------------------------------------------------------

/// Encrypt an 8-byte block with 3DES-ECB (three-key, 24-byte key).
#[cfg(feature = "applet-piv")]
fn tdes_encrypt_ecb(key: &[u8; 24], block: &[u8]) -> Option<[u8; 8]> {
    use cipher::BlockEncrypt;
    use cipher::KeyInit;
    use des::TdesEde3;

    if block.len() != 8 {
        return None;
    }

    let cipher = TdesEde3::new(key.into());
    let mut output = [0u8; 8];
    output.copy_from_slice(block);
    let block_ref = cipher::Block::<TdesEde3>::from_mut_slice(&mut output);
    cipher.encrypt_block(block_ref);
    Some(output)
}

/// Stub for non-PIV builds.
#[cfg(not(feature = "applet-piv"))]
fn tdes_encrypt_ecb(_key: &[u8; 24], _block: &[u8]) -> Option<[u8; 8]> {
    None
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Fill buffer with random bytes.
fn fill_random_bytes(buf: &mut [u8]) {
    #[cfg(target_arch = "arm")]
    {
        let _ = crate::crypto::rng::fill_random(buf);
    }
    #[cfg(not(target_arch = "arm"))]
    {
        use core::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0x9e3779b97f4a7c15u64);
        for chunk in buf.chunks_mut(8) {
            let v = CTR
                .fetch_add(0x6c62272e07bb0142u64, Ordering::Relaxed)
                .wrapping_mul(0x94d049bb133111ebu64)
                ^ 0xbf58476d1ce4e5b9u64;
            let vb = v.to_le_bytes();
            chunk.copy_from_slice(&vb[..chunk.len()]);
        }
    }
}

/// Constant-time comparison of two byte slices.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Decode a BER-TLV length field. Returns (length, bytes_consumed).
fn ber_length(data: &[u8]) -> (usize, usize) {
    if data.is_empty() {
        return (0, 0);
    }
    if data[0] < 0x80 {
        (data[0] as usize, 1)
    } else if data[0] == 0x81 && data.len() >= 2 {
        (data[1] as usize, 2)
    } else if data[0] == 0x82 && data.len() >= 3 {
        (((data[1] as usize) << 8) | data[2] as usize, 3)
    } else {
        (0, 0)
    }
}
