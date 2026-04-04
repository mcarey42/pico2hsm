//! PERFORM SECURITY OPERATION command handler (INS = 0x2A).
//!
//! Multipurpose command used for cryptographic operations configured by
//! the preceding MSE SET command.
//!
//! - P1=0x9E, P2=0x9A: Compute Digital Signature (same as INS=0x68)
//! - P1=0x80, P2=0x86: Decipher (same as INS=0x62)
//! - P1=0x8E, P2=0x80: Compute Cryptographic Checksum (MAC)
//! - P1=0x86, P2=0x80: Verify Cryptographic Checksum

use sha2::Digest as _;

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND,
    SW_INS_NOT_SUPPORTED, SW_SECURITY_STATUS, SW_WRONG_DATA,
};
use pico2hsm_core::key::KeyType;

use crate::protocol::sc_hsm::{FwRng, ScHsmState};

/// INS byte for PERFORM SECURITY OPERATION.
pub const INS_PSO: u8 = 0x2A;

/// Handle a PERFORM SECURITY OPERATION APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    match (cmd.p1, cmd.p2) {
        // PSO: Compute Digital Signature — key/algo from MSE SET state
        (0x9E, 0x9A) => pso_compute_digital_signature(state, cmd),
        // PSO: Decipher — key/algo from MSE SET state
        (0x80, 0x86) => pso_decipher(state, cmd),
        // PSO: Compute Cryptographic Checksum (MAC)
        (0x8E, 0x80) => {
            // TODO (Agent 7): compute CMAC/HMAC
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        // PSO: Verify Cryptographic Checksum
        (0x86, 0x80) => {
            // TODO (Agent 7): verify CMAC/HMAC
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        _ => ApduResponse::err(SW_WRONG_DATA),
    }
}

/// PSO Compute Digital Signature (P1=0x9E, P2=0x9A).
///
/// Delegates to the same ECDSA / RSA signing paths as INS=0x68 (sign.rs),
/// but reads key_id and algo from the security environment set by MSE SET.
fn pso_compute_digital_signature(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require MSE SET to have configured key and algorithm
    let key_id = match state.current_key_id {
        Some(id) => id,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };
    let algo = match state.current_algo {
        Some(a) => a,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // ---- RSA signing (feature-gated) ----------------------------------------
    // RSA algorithm codes (from OpenSC card-sc-hsm.h):
    //   0x20 = ALGO_RSA_RAW     — input is already PKCS#1-padded; raw RSA op
    //   0x31 = ALGO_RSA_PKCS1_SHA256, 0x32 = SHA384, 0x33 = SHA512
    //   0x34 = RSA-PSS SHA-256 (internal), 0x40 = ALGO_RSA_PSS — pre-hashed (32 B)
    #[cfg(feature = "rsa")]
    match algo {
        0x20 | 0x31 | 0x32 | 0x33 | 0x34 | 0x40 => {
            use crate::crypto::asymmetric::{HashAlgorithm, rsa_private_raw, rsa_sign_pkcs1v15, rsa_sign_pss};

            let rsa_key = match state.rsa_keys.iter().find(|k| k.key_id == key_id) {
                Some(k) => k,
                None => return ApduResponse::err(SW_FILE_NOT_FOUND),
            };

            // Copy private key DER to a local stack buffer to release the borrow on state.
            // RSA-2048 PKCS#1 DER is ≤1200 bytes; RSA-4096 is ≤2400 bytes.
            let mut der_buf = [0u8; 2400];
            let der_len = rsa_key.private_key_der.len();
            let key_type = rsa_key.key_type;
            der_buf[..der_len].copy_from_slice(&rsa_key.private_key_der);

            let sig = match algo {
                0x20 => {
                    // ALGO_RSA_RAW: OpenSC pre-padded the data (PKCS#1 v1.5 block, 256 B).
                    // Card performs raw RSA private key op: sig = input^d mod n.
                    match rsa_private_raw(&der_buf[..der_len], cmd.data) {
                        Ok(s) => s,
                        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
                    }
                }
                0x34 | 0x40 => {
                    // RSA-PSS: data is pre-hashed (32 bytes SHA-256). Card applies PSS + signs.
                    match rsa_sign_pss(
                        key_type,
                        &der_buf[..der_len],
                        cmd.data,
                        HashAlgorithm::Sha256,
                        32,
                        &mut FwRng,
                    ) {
                        Ok(s) => s,
                        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
                    }
                }
                _ => {
                    let hash_algo = match algo {
                        0x31 => HashAlgorithm::Sha256,
                        0x32 => HashAlgorithm::Sha384,
                        0x33 => HashAlgorithm::Sha512,
                        _    => return ApduResponse::err(SW_INS_NOT_SUPPORTED),
                    };
                    match rsa_sign_pkcs1v15(
                        key_type,
                        &der_buf[..der_len],
                        cmd.data,
                        hash_algo,
                        &mut FwRng,
                    ) {
                        Ok(s) => s,
                        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
                    }
                }
            };

            return ApduResponse::ok(&sig);
        }
        _ => {}
    }

    // ---- ECDSA path ---------------------------------------------------------
    // 0x13/0x15/0x17/0x19/0x70 = pre-hashed path: command data is already the digest.
    // 0x71–0x75 = card-hash path (OpenSC SC-HSM ALGO_EC_SHA* codes): command data
    //             is the raw message; the card must compute the hash before signing.
    match algo {
        0x13 | 0x15 | 0x17 | 0x19 | 0x70 | 0x71 | 0x72 | 0x73 | 0x74 | 0x75 => {}
        _ => return ApduResponse::err(SW_INS_NOT_SUPPORTED),
    }

    // Look up the key in the in-memory store
    let key = match state.keys.iter().find(|k| k.key_id == key_id) {
        Some(k) => k,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    let key_type = key.key_type;
    // Copy private key bytes to a local buffer to avoid holding reference into `state`
    let mut priv_buf = [0u8; 66];
    let priv_len = key.private_key.len();
    priv_buf[..priv_len].copy_from_slice(&key.private_key);

    // For card-hash algorithms (0x71–0x75) the host sends the raw message;
    // we must hash it here before passing to the sign_prehash primitive.
    // Use a fixed-size stack buffer large enough for SHA-512 (64 bytes).
    let mut hash_buf = [0u8; 64];
    let hash: &[u8] = match algo {
        0x71 => {
            // ALGO_EC_SHA1: SHA-1
            let digest = crate::crypto::symmetric::sha1(cmd.data);
            hash_buf[..20].copy_from_slice(&digest);
            &hash_buf[..20]
        }
        0x72 => {
            // ALGO_EC_SHA224: SHA-224
            let digest = sha2::Sha224::digest(cmd.data);
            hash_buf[..28].copy_from_slice(&digest);
            &hash_buf[..28]
        }
        0x73 => {
            // ALGO_EC_SHA256: SHA-256
            let digest = sha2::Sha256::digest(cmd.data);
            hash_buf[..32].copy_from_slice(&digest);
            &hash_buf[..32]
        }
        0x74 => {
            // ALGO_EC_SHA384: SHA-384
            let digest = sha2::Sha384::digest(cmd.data);
            hash_buf[..48].copy_from_slice(&digest);
            &hash_buf[..48]
        }
        0x75 => {
            // ALGO_EC_SHA512: SHA-512
            let digest = sha2::Sha512::digest(cmd.data);
            hash_buf[..64].copy_from_slice(&digest);
            &hash_buf[..64]
        }
        _ => {
            // 0x13/0x15/0x17/0x19/0x70: data is already the digest
            cmd.data
        }
    };

    let sig = match crate::crypto::asymmetric::ecdsa_sign(
        key_type,
        &priv_buf[..priv_len],
        hash,
        &mut FwRng,
    ) {
        Ok(s) => s,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    ApduResponse::ok(&sig)
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

/// PSO Decipher (P1=0x80, P2=0x86).
///
/// Delegates to the same ECDH / RSA decryption paths as INS=0x62 (decrypt.rs),
/// but reads key_id and algo from the security environment set by MSE SET.
fn pso_decipher(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require MSE SET to have configured key and algorithm
    let key_id = match state.current_key_id {
        Some(id) => id,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };
    let algo = match state.current_algo {
        Some(a) => a,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

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

            let rsa_key = match state.rsa_keys.iter().find(|k| k.key_id == key_id) {
                Some(k) => k,
                None => return ApduResponse::err(SW_FILE_NOT_FOUND),
            };

            // RSA-2048 PKCS#1 DER is ≤1200 bytes; RSA-4096 is ≤2400 bytes.
            let mut der_buf = [0u8; 2400];
            let der_len = rsa_key.private_key_der.len();
            der_buf[..der_len].copy_from_slice(&rsa_key.private_key_der);

            // Raw RSA: result = ciphertext^d mod n. OpenSC handles all unpadding.
            return match rsa_private_raw(&der_buf[..der_len], cmd.data) {
                Ok(p) => ApduResponse::ok(&p),
                Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
            };
        }
        _ => {}
    }

    // ---- ECDH path — EC key lookup ------------------------------------------
    // Look up the EC key. RSA keys (handled above) never reach here.
    let key = match state.keys.iter().find(|k| k.key_id == key_id) {
        Some(k) => k,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // ---- ECDH path ----------------------------------------------------------
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

    // When OpenSC sends ALGO_EC_DH (algo=0x80) it expects the response to be
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
