//! COMPUTE DIGITAL SIGNATURE command handler (INS = 0x68).
//!
//! P1 = key reference, P2 = SmartCard-HSM algorithm ID (OpenSC
//! card-sc-hsm.h, the CardContact IDs):
//!
//! | P2          | Operation                                                |
//! |-------------|----------------------------------------------------------|
//! | `20`        | RSA, input already padded (raw private-key operation)    |
//! | `31`–`35`   | RSA PKCS#1 v1.5, card hashes the input with SHA-1/224/256/384/512 |
//! | `40`        | RSA-PSS, input is a SHA-256 digest (other hashes: no)    |
//! | `70`        | ECDSA, input is the hash                                 |
//! | `71`–`75`   | ECDSA, card hashes the input with SHA-1/224/256/384/512  |
//! | `13 15 17 19` | pico2hsm extension: ECDSA, input is the hash           |
//!
//! The key's usage policy (tag 91 algorithm list, tag 90 use counter) is
//! checked against P2, and a use spent, right before the private-key
//! operation (`key_policy::authorize_use`).

use sha2::Digest as _;

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND,
    SW_INS_NOT_SUPPORTED, SW_SECURITY_STATUS, SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::{FwRng, ScHsmState};
use crate::security::key_policy::authorize_use;
use crate::storage::KeyStore;

/// INS byte for COMPUTE DIGITAL SIGNATURE.
pub const INS_SIGN: u8 = 0x68;

/// Map the stored keygen algorithm byte to the core `KeyType` for EC keys.
///
/// `meta.algo` is set at keygen time and encodes the curve:
/// 0x13/0x23 → P-256, 0x15/0x25 → P-384, 0x17/0x27 → P-521, 0x19/0x29 → K-256.
pub(crate) fn meta_algo_to_ec_key_type(algo: u8) -> Option<pico2hsm_core::key::KeyType> {
    use pico2hsm_core::key::KeyType;
    match algo {
        0x13 | 0x23 => Some(KeyType::EcPrivateP256),
        0x15 | 0x25 => Some(KeyType::EcPrivateP384),
        0x17 | 0x27 => Some(KeyType::EcPrivateP521),
        0x19 | 0x29 => Some(KeyType::EcPrivateK256),
        _ => None,
    }
}

/// Hash `data` as the card-hash algorithms `x1`–`x5` require (SHA-1,
/// SHA-224, SHA-256, SHA-384, SHA-512 by the low nibble).
fn card_hash(low_nibble: u8, data: &[u8], out: &mut [u8; 64]) -> Option<usize> {
    let n = match low_nibble {
        1 => {
            out[..20].copy_from_slice(&crate::crypto::symmetric::sha1(data));
            20
        }
        2 => {
            out[..28].copy_from_slice(&sha2::Sha224::digest(data));
            28
        }
        3 => {
            out[..32].copy_from_slice(&sha2::Sha256::digest(data));
            32
        }
        4 => {
            out[..48].copy_from_slice(&sha2::Sha384::digest(data));
            48
        }
        5 => {
            out[..64].copy_from_slice(&sha2::Sha512::digest(data));
            64
        }
        _ => return None,
    };
    Some(n)
}

/// Handle a COMPUTE DIGITAL SIGNATURE APDU command.
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
    // in the SIGN APDU (no preceding MSE SET required).
    compute_signature(state, store, cmd.p1, cmd.p2, cmd.data)
}

/// Sign `data` with key `key_ref` and SmartCard-HSM algorithm `algo`
/// (COMPUTE DIGITAL SIGNATURE and PSO:CDS).  The caller checked the PIN.
pub(crate) fn compute_signature(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    key_ref: u8,
    algo: u8,
    data: &[u8],
) -> ApduResponse {
    let full_key_id = pico2hsm_core::key::KeyId::sc_hsm(0, key_ref).0; // u32 internal ID

    if data.is_empty() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    #[cfg(feature = "rsa")]
    if matches!(algo, 0x20 | 0x31..=0x35 | 0x40) {
        return rsa_sign(state, store, full_key_id, algo, data);
    }

    // ---- ECDSA path ---------------------------------------------------------
    // 0x13/0x15/0x17/0x19/0x70 = pre-hashed path: command data is already the digest.
    // 0x71–0x75 = card-hash path: command data is the raw message.
    match algo {
        0x13 | 0x15 | 0x17 | 0x19 | 0x70..=0x75 => {}
        _ => return ApduResponse::err(SW_INS_NOT_SUPPORTED),
    }

    // Check metadata index for the key
    let meta = match state.key_index.iter().find(|m| m.key_id == full_key_id) {
        Some(m) => *m,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // Resolve the core KeyType from the stored keygen algorithm byte.
    // The sign-time algo (0x70-0x75) doesn't encode the curve; use meta.algo.
    let key_type = match meta_algo_to_ec_key_type(meta.algo) {
        Some(kt) => kt,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Load key material from flash
    let mut key_obj = match store.fetch_key(pico2hsm_core::key::KeyId(full_key_id)) {
        Ok(Some(obj)) => obj,
        _ => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Copy private key bytes to a local buffer
    let priv_len = key_obj.private_key.len();
    let Some(priv_buf) = crate::security::zeroize::key_buf::<66>(&key_obj.private_key) else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };

    // For card-hash algorithms (0x71–0x75) the host sends the raw message.
    let mut hash_buf = [0u8; 64];
    let hash: &[u8] = if (0x71..=0x75).contains(&algo) {
        match card_hash(algo & 0x0F, data, &mut hash_buf) {
            Some(n) => &hash_buf[..n],
            None => return ApduResponse::err(SW_INS_NOT_SUPPORTED),
        }
    } else {
        data
    };

    // Policy: algorithm allowed, one use spent — last check before signing.
    // The pico2hsm per-curve codes 13/15/17/19 are the same operation as
    // CardContact's ALGO_EC_RAW (70) and are checked as 70: the list holds
    // CardContact IDs only, and 13..19 mean nothing (or something else)
    // there.
    let policy_algo = match algo {
        0x13 | 0x15 | 0x17 | 0x19 => crate::security::key_policy::ALGO_EC_RAW,
        a => a,
    };
    if let Err(sw) = authorize_use(store, &mut key_obj, Some(policy_algo)) {
        return ApduResponse::err(sw);
    }

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

/// RSA signature (`20`, `31`–`35`, `40`).
#[cfg(feature = "rsa")]
fn rsa_sign(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    full_key_id: u32,
    algo: u8,
    data: &[u8],
) -> ApduResponse {
    use crate::crypto::asymmetric::{
        rsa_private_raw, rsa_sign_pkcs1v15, rsa_sign_pss, HashAlgorithm,
    };
    use crate::security::key_management::KeyType as KmType;

    // Check metadata index for the key
    let meta = match state.key_index.iter().find(|m| m.key_id == full_key_id) {
        Some(m) => *m,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // Load key material from flash
    let mut key_obj = match store.fetch_key(pico2hsm_core::key::KeyId(full_key_id)) {
        Ok(Some(obj)) => obj,
        _ => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };
    // An RSA algorithm on any other key is refused before it costs a use.
    if key_obj.key_type != KmType::Rsa {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Infer the core KeyType from the stored keygen algo byte
    let key_type = match meta.algo {
        0x05 => pico2hsm_core::key::KeyType::RsaPrivate2048,
        0x06 => pico2hsm_core::key::KeyType::RsaPrivate3072,
        0x07 => pico2hsm_core::key::KeyType::RsaPrivate4096,
        _ => match key_obj.private_key.len() {
            n if n <= 1200 => pico2hsm_core::key::KeyType::RsaPrivate2048,
            n if n <= 1800 => pico2hsm_core::key::KeyType::RsaPrivate3072,
            _ => pico2hsm_core::key::KeyType::RsaPrivate4096,
        },
    };

    // Card-hash algorithms: hash first, so a bad request costs no use.
    let mut hash_buf = [0u8; 64];
    let digest_len = if (0x31..=0x35).contains(&algo) {
        match card_hash(algo & 0x0F, data, &mut hash_buf) {
            Some(n) => n,
            None => return ApduResponse::err(SW_INS_NOT_SUPPORTED),
        }
    } else {
        0
    };
    // RSA-PSS takes a SHA-256 digest (the only PSS hash implemented).
    if algo == 0x40 && data.len() != 32 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    let der_len = key_obj.private_key.len();
    let Some(der_buf) = crate::security::zeroize::key_buf::<2400>(&key_obj.private_key) else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };

    if let Err(sw) = authorize_use(store, &mut key_obj, Some(algo)) {
        return ApduResponse::err(sw);
    }

    let sig = match algo {
        // ALGO_RSA_RAW: the host padded the input; sig = input^d mod n.
        0x20 => rsa_private_raw(&der_buf[..der_len], data),
        // ALGO_RSA_PSS: input is the SHA-256 digest; card pads and signs.
        0x40 => rsa_sign_pss(
            key_type,
            &der_buf[..der_len],
            data,
            HashAlgorithm::Sha256,
            32,
            &mut FwRng,
        ),
        // ALGO_RSA_PKCS1_SHA*: the card hashed the input above.
        _ => {
            let hash_algo = match algo {
                0x31 => HashAlgorithm::Sha1,
                0x32 => HashAlgorithm::Sha224,
                0x33 => HashAlgorithm::Sha256,
                0x34 => HashAlgorithm::Sha384,
                _ => HashAlgorithm::Sha512,
            };
            rsa_sign_pkcs1v15(
                key_type,
                &der_buf[..der_len],
                &hash_buf[..digest_len],
                hash_algo,
                &mut FwRng,
            )
        }
    };
    match sig {
        Ok(s) => ApduResponse::ok(&s),
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}
