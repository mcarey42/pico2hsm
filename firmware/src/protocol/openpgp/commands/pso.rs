//! PSO (Perform Security Operation) command handler (INS = 0x2A) for OpenPGP.
//!
//! Two sub-commands:
//! - PSO:CDS (P1=0x9E, P2=0x9A) — Compute Digital Signature using SIG key
//! - PSO:DECIPHER (P1=0x80, P2=0x86) — ECDH key agreement using DEC key
//!
//! PSO:CDS requires PW1 verified in mode 81 (mode 82 does not sign).
//! After PSO:CDS the mode-81 verification is used up unless PW1 status
//! byte 1 (DO C4) is 01; the signature counter (DO 93) is persisted first.
//!
//! PSO:DECIPHER requires PW1 verified with mode 82.
//! Input for ECDH: A6 [ 7F49 [ 86 [len] <04 X Y> ] ]

use pico2hsm_core::{
    apdu::{
        ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_SECURITY_STATUS, SW_WRONG_DATA,
    },
    key::KeyType,
};

use crate::protocol::openpgp::OpenPgpState;

/// INS byte for PSO (Perform Security Operation).
pub const INS_PSO: u8 = 0x2A;

/// Handle a PSO APDU command.
pub fn handle(state: &mut OpenPgpState, cmd: &ApduCommand<'_>) -> ApduResponse {
    match (cmd.p1, cmd.p2) {
        // PSO:CDS — Compute Digital Signature
        (0x9E, 0x9A) => handle_cds(state, cmd),
        // PSO:DECIPHER — ECDH key agreement
        (0x80, 0x86) => handle_decipher(state, cmd),
        _ => ApduResponse::err(SW_WRONG_DATA),
    }
}

/// After a signature: count it (DO 93, saturating at 3 bytes) and, when
/// PW1 status byte 1 is 00 (C4), use up the mode-81 verification — one
/// signature per VERIFY (OpenPGP Card 3.4 §4.4.3.6, §7.2.10).
fn count_signature(state: &mut OpenPgpState) {
    state.sig_counter = (state.sig_counter + 1).min(super::put_data::SIG_COUNTER_MAX);
    if state.pw1_status == 0x00 {
        state.pw1_verified_sign = false;
    }
}

/// PSO with the keystore: a PSO:CDS signature is returned only once the
/// incremented signature counter is on flash (6581 otherwise, and the
/// signature is dropped), so a reset can never roll the counter back
/// below the signatures that left the card.
pub fn handle_with_store(
    state: &mut OpenPgpState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    if (cmd.p1, cmd.p2) != (0x9E, 0x9A) {
        return handle(state, cmd);
    }
    let before = state.sig_counter;
    let resp = handle_cds(state, cmd);
    if resp.sw == pico2hsm_core::apdu::SW_OK
        && super::put_data::save_sig_counter(state, store).is_err()
    {
        state.sig_counter = before;
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    }
    resp
}

/// Handle PSO:CDS — sign with the SIG key.
fn handle_cds(state: &mut OpenPgpState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Signing needs PW1 mode 81 (OpenPGP Card 3.4 §7.2.10); mode 82 covers
    // decipher/authenticate only and must not authorise signatures.
    if !state.pw1_verified_sign {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // Retrieve SIG key
    let priv_key = match &state.sig_private {
        Some(k) => k,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    let key_type = match state.sig_key_type {
        Some(kt) => kt,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Copy private key to local buffer
    let priv_len = priv_key.len();
    let Some(priv_buf) = crate::security::zeroize::key_buf::<66>(priv_key) else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };

    // Sign: input is the pre-hashed digest (raw hash bytes, no DigestInfo for ECC)

    // Ed25519 path: sign directly with ed25519-dalek (returns raw 64-byte r||s)
    #[cfg(feature = "applet-openpgp-curve25519")]
    if key_type == KeyType::Ed25519 {
        let raw_sig = match crate::crypto::asymmetric::ed25519_sign(&priv_buf[..priv_len], cmd.data)
        {
            Ok(s) => s,
            Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
        };

        count_signature(state);

        return ApduResponse::ok(&raw_sig);
    }

    let mut rng = crate::protocol::sc_hsm::FwRng;
    let der_sig = match crate::crypto::asymmetric::ecdsa_sign(
        key_type,
        &priv_buf[..priv_len],
        cmd.data,
        &mut rng,
    ) {
        Ok(s) => s,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Convert DER signature to raw r||s (OpenPGP returns raw, not DER)
    let raw_sig = match der_to_raw_rs(&der_sig, key_type) {
        Some(s) => s,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    count_signature(state);

    ApduResponse::ok(&raw_sig)
}

/// Handle PSO:DECIPHER — ECDH with the DEC key.
fn handle_decipher(state: &mut OpenPgpState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Requires PW1 mode 82
    if !state.pw1_verified_other {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // Retrieve DEC key
    let priv_key = match &state.dec_private {
        Some(k) => k,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    let key_type = match state.dec_key_type {
        Some(kt) => kt,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Copy private key
    let priv_len = priv_key.len();
    let Some(priv_buf) = crate::security::zeroize::key_buf::<66>(priv_key) else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };

    // X25519 path: peer key is 32 bytes, shared secret is 32 bytes
    #[cfg(feature = "applet-openpgp-curve25519")]
    if key_type == KeyType::X25519 {
        let peer_pubkey = match parse_ecdh_input(cmd.data) {
            Some(pk) => pk,
            None => return ApduResponse::err(SW_WRONG_DATA),
        };
        if peer_pubkey.len() != 32 {
            return ApduResponse::err(SW_WRONG_DATA);
        }
        let shared =
            match crate::crypto::asymmetric::x25519_ecdh(&priv_buf[..priv_len], peer_pubkey) {
                Ok(s) => s,
                Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
            };
        return ApduResponse::ok(&shared);
    }

    // Parse ECDH input: A6 [ 7F49 [ 86 [len] <peer_public_point> ] ]
    // Or simpler: just extract the peer public key from the TLV structure
    let peer_pubkey = match parse_ecdh_input(cmd.data) {
        Some(pk) => pk,
        None => return ApduResponse::err(SW_WRONG_DATA),
    };

    // Perform ECDH
    let shared_secret =
        match crate::crypto::asymmetric::ecdh_agree(key_type, &priv_buf[..priv_len], peer_pubkey) {
            Ok(s) => s,
            Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
        };

    ApduResponse::ok(&shared_secret)
}

/// Parse ECDH input from PSO:DECIPHER data.
///
/// Required format per OpenPGP Card spec §8.2.1:
///   A6 [len] 7F49 [len] 86 [len] <point>
///
/// Returns the peer public key point (including 04 prefix for ECDH, or
/// raw 32 bytes for X25519). Returns `None` if the A6 wrapper is absent or
/// the TLV structure is malformed — callers return SW=6A80 (wrong data).
fn parse_ecdh_input(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() {
        return None;
    }

    // Require A6 tag — no fallback per spec §8.2.1
    if data[0] != 0xA6 {
        return None;
    }

    // Parse A6 TLV
    let (a6_content, _) = parse_tlv_content(&data[1..])?;

    // Look for 7F49 tag inside
    if a6_content.len() >= 2 && a6_content[0] == 0x7F && a6_content[1] == 0x49 {
        let (inner_content, _) = parse_tlv_content(&a6_content[2..])?;

        // Look for 86 tag
        if !inner_content.is_empty() && inner_content[0] == 0x86 {
            let (point, _) = parse_tlv_content(&inner_content[1..])?;
            return Some(point);
        }
    }

    None
}

/// Convert a DER-encoded ECDSA signature to raw r||s format.
///
/// DER: 30 [len] 02 [r_len] <r_bytes> 02 [s_len] <s_bytes>
/// Raw: r (field_size bytes, zero-padded) || s (field_size bytes, zero-padded)
pub fn der_to_raw_rs(der: &[u8], key_type: KeyType) -> Option<heapless::Vec<u8, 132>> {
    let field_size = match key_type {
        KeyType::EcPrivateP256 | KeyType::EcPrivateK256 => 32,
        KeyType::EcPrivateP384 => 48,
        KeyType::EcPrivateP521 => 66,
        _ => return None,
    };

    // Parse outer SEQUENCE
    if der.len() < 2 || der[0] != 0x30 {
        return None;
    }
    let (_, seq_hdr) = parse_der_length(&der[1..])?;
    let inner = &der[1 + seq_hdr..];

    // Parse r INTEGER
    if inner.is_empty() || inner[0] != 0x02 {
        return None;
    }
    let (r_len, r_hdr) = parse_der_length(&inner[1..])?;
    let r_start = 1 + r_hdr;
    if inner.len() < r_start + r_len {
        return None;
    }
    let r_bytes = &inner[r_start..r_start + r_len];

    // Parse s INTEGER
    let s_pos = r_start + r_len;
    if s_pos >= inner.len() || inner[s_pos] != 0x02 {
        return None;
    }
    let (s_len, s_hdr) = parse_der_length(&inner[s_pos + 1..])?;
    let s_start = s_pos + 1 + s_hdr;
    if inner.len() < s_start + s_len {
        return None;
    }
    let s_bytes = &inner[s_start..s_start + s_len];

    // Convert to fixed-width, zero-padded
    let mut out = heapless::Vec::<u8, 132>::new();
    pad_integer(&mut out, r_bytes, field_size);
    pad_integer(&mut out, s_bytes, field_size);

    Some(out)
}

/// Zero-pad (or trim leading zeros from) a DER integer to exactly `field_size` bytes.
fn pad_integer(out: &mut heapless::Vec<u8, 132>, bytes: &[u8], field_size: usize) {
    // DER integers may have a leading 0x00 if the high bit is set
    let trimmed = if !bytes.is_empty() && bytes[0] == 0x00 && bytes.len() > field_size {
        &bytes[1..]
    } else {
        bytes
    };

    // Zero-pad on the left if shorter than field_size
    if trimmed.len() < field_size {
        let pad = field_size - trimmed.len();
        for _ in 0..pad {
            let _ = out.push(0x00);
        }
    }
    let _ = out.extend_from_slice(trimmed);
}

/// Parse a DER length byte(s). Returns (length_value, header_bytes_consumed).
fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        Some((data[0] as usize, 1))
    } else if data[0] == 0x81 && data.len() >= 2 {
        Some((data[1] as usize, 2))
    } else if data[0] == 0x82 && data.len() >= 3 {
        Some((((data[1] as usize) << 8) | data[2] as usize, 3))
    } else {
        None
    }
}

/// Parse a BER-TLV length and return (content slice, remaining slice).
fn parse_tlv_content(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.is_empty() {
        return None;
    }

    let (len, hdr_len) = if data[0] < 0x80 {
        (data[0] as usize, 1)
    } else if data[0] == 0x81 && data.len() >= 2 {
        (data[1] as usize, 2)
    } else if data[0] == 0x82 && data.len() >= 3 {
        (((data[1] as usize) << 8) | data[2] as usize, 3)
    } else {
        return None;
    };

    let total = hdr_len + len;
    if data.len() < total {
        return None;
    }

    Some((&data[hdr_len..total], &data[total..]))
}
