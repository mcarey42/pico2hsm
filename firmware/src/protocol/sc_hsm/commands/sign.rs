//! COMPUTE DIGITAL SIGNATURE command handler (INS = 0x68).
//!
//! Computes an ECDSA signature using the private key selected by the
//! preceding MSE SET command.
//!
//! Two algorithm families are supported:
//! - **0x13/0x15/0x17/0x19/0x70** (pre-hashed path): command data is already
//!   the message digest; passed directly to the signing primitive.
//! - **0x71–0x75** (OpenSC SC-HSM card-hash path, per card-sc-hsm.h):
//!   command data is the raw message; the card computes the hash.
//!   0x71 → SHA-1, 0x72 → SHA-224, 0x73 → SHA-256, 0x74 → SHA-384, 0x75 → SHA-512.
//!
//! Algo codes from the OpenSC SC-HSM driver header (card-sc-hsm.h):
//!   ALGO_EC_RAW    = 0x70
//!   ALGO_EC_SHA1   = 0x71
//!   ALGO_EC_SHA224 = 0x72
//!   ALGO_EC_SHA256 = 0x73
//!   ALGO_EC_SHA384 = 0x74
//!   ALGO_EC_SHA512 = 0x75

use sha2::Digest as _;

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND,
    SW_INS_NOT_SUPPORTED, SW_SECURITY_STATUS,
};

use crate::protocol::sc_hsm::{FwRng, ScHsmState};

/// INS byte for COMPUTE DIGITAL SIGNATURE.
pub const INS_SIGN: u8 = 0x68;

/// Handle a COMPUTE DIGITAL SIGNATURE APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // SC-HSM encodes the key reference in P1 and the algorithm in P2 directly
    // in the SIGN APDU (no preceding MSE SET required).
    let key_id = cmd.p1;
    let algo = cmd.p2;

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // ---- RSA signing (feature-gated) ----------------------------------------
    // RSA algorithm codes (from OpenSC card-sc-hsm.h):
    //   0x20 = ALGO_RSA_RAW     — input is already PKCS#1-padded (256 B); raw RSA op
    //   0x31 = ALGO_RSA_PKCS1_SHA256, 0x32 = SHA384, 0x33 = SHA512
    //   0x34 = RSA-PSS SHA-256 (internal), 0x40 = ALGO_RSA_PSS — pre-hashed (32 B)
    // For 0x20 the host has already applied padding; the card performs c = m^d mod n.
    // For 0x40 the host sends the SHA-256 digest; the card applies PSS and signs.
    #[cfg(feature = "rsa")]
    match algo {
        0x20 | 0x31 | 0x32 | 0x33 | 0x34 | 0x40 => {
            use crate::crypto::asymmetric::{HashAlgorithm, rsa_private_raw, rsa_sign_pkcs1v15, rsa_sign_pss};

            // Look up the RSA key
            let rsa_key = match state.rsa_keys.iter().find(|k| k.key_id == key_id) {
                Some(k) => k,
                None => return ApduResponse::err(SW_FILE_NOT_FOUND),
            };

            // Copy private key DER to a local stack buffer to release the borrow on state.
            // RSA-2048 PKCS#1 DER is ≤1200 bytes.
            let mut der_buf = [0u8; 1200];
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
