//! DECIPHER command handler (INS = 0x62, P1 = key slot, P2 = algorithm).
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
use crate::storage::KeyStore;

/// INS byte for DECIPHER.
pub const INS_DECRYPT: u8 = 0x62;

/// Map the stored keygen algorithm byte to the core `KeyType` for EC keys.
fn meta_algo_to_ec_key_type(algo: u8) -> Option<KeyType> {
    match algo {
        0x13 | 0x23 => Some(KeyType::EcPrivateP256),
        0x15 | 0x25 => Some(KeyType::EcPrivateP384),
        0x17 | 0x27 => Some(KeyType::EcPrivateP521),
        0x19 | 0x29 => Some(KeyType::EcPrivateK256),
        _ => None,
    }
}

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
pub fn handle(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // SC-HSM encodes the key reference in P1 and the algorithm in P2 directly
    // in the DECIPHER APDU (no preceding MSE SET required).
    let key_id = cmd.p1; // u8 protocol key reference
    let full_key_id = pico2hsm_core::key::KeyId::sc_hsm(0, key_id).0; // u32 internal ID
    let algo = cmd.p2;

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // ---- RSA decryption (feature-gated) — checked BEFORE EC key lookup ------
    // 0x21 = ALGO_RSA_DECRYPT: OpenSC sends ciphertext; card returns c^d mod n
    //        (raw, no padding removal). OpenSC strips PKCS#1v1.5 or OAEP in software.
    //        OpenSC uses P2=0x21 for BOTH CKM_RSA_PKCS and CKM_RSA_PKCS_OAEP.
    // 0x22 = ALGO_RSA_OAEP (used by some OpenSC versions): same raw op.
    #[cfg(feature = "rsa")]
    match algo {
        0x21 | 0x22 => {
            use crate::crypto::asymmetric::rsa_private_raw;

            // Check metadata index for the key
            let _meta = match state.key_index.iter().find(|m| m.key_id == full_key_id) {
                Some(m) => *m,
                None => return ApduResponse::err(SW_FILE_NOT_FOUND),
            };

            // Load key material from flash
            let key_obj = match store.fetch_key(pico2hsm_core::key::KeyId(full_key_id)) {
                Ok(Some(obj)) => obj,
                _ => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
            };

            // RSA-2048 PKCS#1 DER is ≤1200 bytes; RSA-4096 is ≤2400 bytes.
            let der_len = key_obj.private_key.len();
            let Some(der_buf) = crate::security::zeroize::key_buf::<2400>(&key_obj.private_key)
            else {
                return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
            };

            // Raw RSA: result = ciphertext^d mod n. OpenSC handles all unpadding.
            return match rsa_private_raw(&der_buf[..der_len], cmd.data) {
                Ok(p) => ApduResponse::ok(&p),
                Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
            };
        }
        _ => {}
    }

    // ---- ECDH path — EC key lookup ------------------------------------------
    // Check metadata index for the EC key. RSA keys (handled above) never reach here.
    let meta = match state.key_index.iter().find(|m| m.key_id == full_key_id) {
        Some(m) => *m,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // Resolve the core KeyType from meta.algo (set at keygen time).
    let stored_key_type = match meta_algo_to_ec_key_type(meta.algo) {
        Some(kt) => kt,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // ---- ECDH path ----------------------------------------------------------
    // Resolve the key type:
    // - If the algo byte maps to an explicit ECDH algorithm (0x23/0x25/0x27/0x29),
    //   validate it matches the stored key.
    // - If the algo byte is 0x80 (OpenSC's ALGO_EC_DH), infer the key type from
    //   the stored key metadata directly.
    // - Anything else is unsupported.
    let key_type = if let Some(expected) = algo_to_key_type(algo) {
        if stored_key_type != expected {
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
        expected
    } else if algo == 0x80 && is_ec_private(stored_key_type) {
        stored_key_type
    } else {
        return ApduResponse::err(SW_INS_NOT_SUPPORTED);
    };

    // When OpenSC sends ALGO_EC_DH (P2=0x80) it expects the response to be
    // prefixed with a `0x04` uncompressed-point marker byte, which it then
    // strips internally (card-sc-hsm.c:sc_hsm_decipher → ALGO_EC_DH branch).
    // Explicit ECDH algo codes (0x23/0x25/0x27/0x29) are returned as raw bytes.
    let needs_04_prefix = algo == 0x80;

    // Load key material from flash
    let key_obj = match store.fetch_key(pico2hsm_core::key::KeyId(full_key_id)) {
        Ok(Some(obj)) => obj,
        _ => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    let priv_len = key_obj.private_key.len();
    let Some(priv_buf) = crate::security::zeroize::key_buf::<66>(&key_obj.private_key) else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };

    let shared =
        match crate::crypto::asymmetric::ecdh_agree(key_type, &priv_buf[..priv_len], cmd.data) {
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
