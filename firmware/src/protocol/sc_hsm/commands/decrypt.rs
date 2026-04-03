//! DECIPHER command handler (INS = 0x62, P1 = 0x00).
//!
//! For EC key agreement (ECDH) algorithms, the command data contains the
//! peer's uncompressed public key point (`04 || X || Y`). The response is
//! `04 || X-coordinate` (raw X prefixed with `0x04`) when invoked via
//! OpenSC's `ALGO_EC_DH` (P2=0x80), which OpenSC then strips to get the
//! field-size X-coordinate. For explicit ECDH algo codes (0x23/0x25/0x27/0x29)
//! the raw X-coordinate is returned directly.
//!
//! SC-HSM AlgorithmId bytes for ECDH:
//! - `0x23` — ECDH P-256
//! - `0x25` — ECDH P-384
//! - `0x27` — ECDH P-521
//! - `0x29` — ECDH K-256 (secp256k1)
//! - `0x80` — ALGO_EC_DH (generic OpenSC code, response prefixed with `0x04`)
//!
//! RSA decryption is not yet implemented (requires an allocator).

use pico2hsm_core::{
    apdu::{
        ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND,
        SW_INS_NOT_SUPPORTED, SW_SECURITY_STATUS,
    },
    key::KeyType,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for DECIPHER.
pub const INS_DECRYPT: u8 = 0x62;

/// Map an explicit ECDH AlgorithmId byte to the expected `KeyType`.
///
/// Returns `None` for unknown or non-ECDH algorithm codes, including the
/// generic 0x80 "EC decipher" code that OpenSC sends — in that case the
/// caller must infer the key type from the stored key record instead.
fn algo_to_key_type(algo: u8) -> Option<KeyType> {
    match algo {
        0x23 => Some(KeyType::EcPrivateP256),
        0x25 => Some(KeyType::EcPrivateP384),
        0x27 => Some(KeyType::EcPrivateP521),
        0x29 => Some(KeyType::EcPrivateK256),
        _ => None,
    }
}

/// Returns true if the given `KeyType` is an EC private key usable for ECDH.
fn is_ec_private(kt: KeyType) -> bool {
    matches!(
        kt,
        KeyType::EcPrivateP256
            | KeyType::EcPrivateP384
            | KeyType::EcPrivateP521
            | KeyType::EcPrivateK256
    )
}

/// Handle a DECIPHER APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // SC-HSM encodes the key reference in P1 and the algorithm in P2 directly
    // in the DECIPHER APDU (no preceding MSE SET required).
    let key_id = cmd.p1;
    let algo = cmd.p2;

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Look up the key first — needed whether or not the algo byte is explicit.
    let key = match state.keys.iter().find(|k| k.key_id == key_id) {
        Some(k) => k,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // Resolve the key type:
    // - If the algo byte maps to an explicit ECDH algorithm (0x23/0x25/0x27/0x29),
    //   validate it matches the stored key.
    // - If the algo byte is 0x80 (OpenSC's ALGO_EC_DH), infer the key type from
    //   the stored key record directly.
    // - Anything else is unsupported.
    let key_type = if let Some(expected) = algo_to_key_type(algo) {
        if key.key_type != expected {
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
        expected
    } else if algo == 0x80 && is_ec_private(key.key_type) {
        key.key_type
    } else {
        return ApduResponse::err(SW_INS_NOT_SUPPORTED);
    };

    // When OpenSC sends ALGO_EC_DH (P2=0x80) it expects the response to be
    // prefixed with a `0x04` uncompressed-point marker byte, which it then
    // strips internally (card-sc-hsm.c:sc_hsm_decipher → ALGO_EC_DH branch).
    // Explicit ECDH algo codes (0x23/0x25/0x27/0x29) are returned as raw bytes.
    let needs_04_prefix = algo == 0x80;

    let mut priv_buf = [0u8; 66];
    let priv_len = key.private_key.len();
    priv_buf[..priv_len].copy_from_slice(&key.private_key);

    let shared = match crate::crypto::asymmetric::ecdh_agree(
        key_type,
        &priv_buf[..priv_len],
        cmd.data,
    ) {
        Ok(s) => s,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    if needs_04_prefix {
        // Prepend 0x04 so OpenSC can strip it and get the exact field-size
        // X-coordinate (32, 48, or 66 bytes depending on curve).
        let mut resp: heapless::Vec<u8, 67> = heapless::Vec::new();
        let _ = resp.push(0x04);
        let _ = resp.extend_from_slice(&shared);
        ApduResponse::ok(&resp)
    } else {
        ApduResponse::ok(&shared)
    }
}
