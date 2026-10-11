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
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_DATA_INVALID, SW_FILE_NOT_FOUND,
    SW_INS_NOT_SUPPORTED, SW_OK, SW_SECURITY_STATUS, SW_WRONG_DATA, SW_WRONG_LENGTH,
};
use pico2hsm_core::key::{KeyId, KeyMaterial, KeyType};

use crate::protocol::sc_hsm::{FwRng, ScHsmState};
use crate::storage::KeyStore;

/// INS byte for PERFORM SECURITY OPERATION.
pub const INS_PSO: u8 = 0x2A;

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

/// Handle a PERFORM SECURITY OPERATION APDU command.
pub fn handle(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    match (cmd.p1, cmd.p2) {
        // PSO: Compute Digital Signature — key/algo from MSE SET state
        (0x9E, 0x9A) => pso_compute_digital_signature(state, store, cmd),
        // PSO: Decipher — key/algo from MSE SET state
        (0x80, 0x86) => pso_decipher(state, store, cmd),
        // PSO: Compute Cryptographic Checksum (AES-CMAC or HMAC-SHA256)
        (0x8E, 0x80) => pso_compute_checksum(state, store, cmd),
        // PSO: Verify Cryptographic Checksum
        (0x86, 0x80) => pso_verify_checksum(state, store, cmd),
        _ => ApduResponse::err(SW_WRONG_DATA),
    }
}

/// PSO Compute Digital Signature (P1=0x9E, P2=0x9A).
///
/// Delegates to the same ECDSA / RSA signing paths as INS=0x68 (sign.rs),
/// but reads key_id and algo from the security environment set by MSE SET.
fn pso_compute_digital_signature(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    // Require MSE SET to have configured key and algorithm
    let key_id_proto = match state.current_key_id {
        Some(id) => id,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };
    let key_id = KeyId::sc_hsm(0, key_id_proto).0; // u32 internal ID
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
            use crate::crypto::asymmetric::{
                rsa_private_raw, rsa_sign_pkcs1v15, rsa_sign_pss, HashAlgorithm,
            };

            // Check metadata index for the key
            let rsa_meta = match state.key_index.iter().find(|m| m.key_id == key_id) {
                Some(m) => *m,
                None => return ApduResponse::err(SW_FILE_NOT_FOUND),
            };

            // Load key material from flash
            let key_obj = match store.fetch_key(KeyId(key_id)) {
                Ok(Some(obj)) => obj,
                _ => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
            };

            // Infer the core KeyType from the stored keygen algo byte
            let key_type = match rsa_meta.algo {
                0x05 => KeyType::RsaPrivate2048,
                0x06 => KeyType::RsaPrivate3072,
                0x07 => KeyType::RsaPrivate4096,
                _ => match key_obj.private_key.len() {
                    n if n <= 1200 => KeyType::RsaPrivate2048,
                    n if n <= 1800 => KeyType::RsaPrivate3072,
                    _ => KeyType::RsaPrivate4096,
                },
            };
            let der_len = key_obj.private_key.len();
            let Some(der_buf) = crate::security::zeroize::key_buf::<2400>(&key_obj.private_key)
            else {
                return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
            };

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
                        _ => return ApduResponse::err(SW_INS_NOT_SUPPORTED),
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

    // Check metadata index for the key
    let meta = match state.key_index.iter().find(|m| m.key_id == key_id) {
        Some(m) => *m,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // Resolve the core KeyType from the stored keygen algorithm byte.
    let key_type = match meta_algo_to_ec_key_type(meta.algo) {
        Some(kt) => kt,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Load key material from flash
    let key_obj = match store.fetch_key(KeyId(key_id)) {
        Ok(Some(obj)) => obj,
        _ => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Copy private key bytes to a local buffer
    let priv_len = key_obj.private_key.len();
    let Some(priv_buf) = crate::security::zeroize::key_buf::<66>(&key_obj.private_key) else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };

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
fn pso_decipher(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    // Require MSE SET to have configured key and algorithm
    let key_id_proto = match state.current_key_id {
        Some(id) => id,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };
    let key_id = KeyId::sc_hsm(0, key_id_proto).0; // u32 internal ID
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

            // Check metadata index for the key
            let _rsa_meta = match state.key_index.iter().find(|m| m.key_id == key_id) {
                Some(m) => *m,
                None => return ApduResponse::err(SW_FILE_NOT_FOUND),
            };

            // Load key material from flash
            let key_obj = match store.fetch_key(KeyId(key_id)) {
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
    let meta = match state.key_index.iter().find(|m| m.key_id == key_id) {
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

    // When OpenSC sends ALGO_EC_DH (algo=0x80) it expects the response to be
    // prefixed with a `0x04` uncompressed-point marker byte, which it then
    // strips internally (card-sc-hsm.c:sc_hsm_decipher → ALGO_EC_DH branch).
    // Explicit ECDH algo codes (0x23/0x25/0x27/0x29) are returned as raw bytes.
    let needs_04_prefix = algo == 0x80;

    // Load key material from flash
    let key_obj = match store.fetch_key(KeyId(key_id)) {
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

// ---------------------------------------------------------------------------
// PSO Compute / Verify Cryptographic Checksum helpers
// ---------------------------------------------------------------------------

/// The selected key as symmetric key bytes, wiped on drop.  Only AES keys
/// of 16/24/32 bytes: copying any other key into a 32-byte buffer used to
/// fail silently, leaving an *empty* HMAC key — publicly computable tags.
fn sym_key(
    key_obj: &crate::security::key_management::KeyObject,
) -> Option<crate::security::zeroize::WipeOnDrop<32>> {
    use crate::security::key_management::KeyType as KmType;
    if !matches!(key_obj.key_type, KmType::Aes)
        || !matches!(key_obj.private_key.len(), 16 | 24 | 32)
    {
        return None;
    }
    let mut k = crate::security::zeroize::WipeOnDrop::new();
    k.0.extend_from_slice(&key_obj.private_key).ok()?;
    Some(k)
}

/// Build a `KeyMaterial` from raw symmetric key bytes.
fn make_sym_key_material(key_id: u32, raw: &[u8]) -> Option<KeyMaterial> {
    use pico2hsm_core::key::KeyType as Kt;
    let key_type = match raw.len() {
        16 => Kt::Aes128,
        24 => Kt::Aes192,
        32 => Kt::Aes256,
        _ => return None,
    };
    let mut km_raw: heapless::Vec<u8, { pico2hsm_core::key::MAX_KEY_BYTES }> = heapless::Vec::new();
    km_raw.extend_from_slice(raw).ok()?;
    Some(KeyMaterial {
        key_type,
        key_id: KeyId(key_id),
        raw: km_raw,
    })
}

/// PSO Compute Cryptographic Checksum (P1=0x8E, P2=0x80).
///
/// Uses the symmetric key selected by the preceding MSE SET.
/// - AES key (16/24/32 B) → AES-CMAC, returns 16-byte tag
/// - Any other size → error
///
/// If `current_algo` is `0xA0` (HMAC-SHA256 indicator), HMAC-SHA256 is used
/// instead and returns a 32-byte tag.
fn pso_compute_checksum(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    let key_id_proto = match state.current_key_id {
        Some(id) => id,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };
    let full_key_id = KeyId::sc_hsm(0, key_id_proto).0;

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Check metadata index for the key
    let _meta = match state.key_index.iter().find(|m| m.key_id == full_key_id) {
        Some(m) => *m,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // Load key material from flash
    let key_obj = match store.fetch_key(KeyId(full_key_id)) {
        Ok(Some(obj)) => obj,
        _ => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    let Some(raw_key) = sym_key(&key_obj) else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };
    let raw_key: &[u8] = &raw_key.0;

    // Determine MAC algorithm from current_algo:
    // 0xA0 = HMAC-SHA256; anything else (or None) defaults to AES-CMAC.
    let use_hmac = state.current_algo == Some(0xA0);

    if use_hmac {
        let tag = crate::crypto::kdf::hmac_sha256(raw_key, cmd.data);
        ApduResponse::ok(&tag)
    } else {
        let km = match make_sym_key_material(full_key_id, raw_key) {
            Some(k) => k,
            None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
        };
        match crate::crypto::symmetric::aes_cmac(&km, cmd.data) {
            Ok(tag) => ApduResponse::ok(&tag),
            Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
        }
    }
}

/// PSO Verify Cryptographic Checksum (P1=0x86, P2=0x80).
///
/// Wire format: `[message || tag]`
/// - AES-CMAC: tag is 16 bytes
/// - HMAC-SHA256: tag is 32 bytes (if `current_algo == 0xA0`)
///
/// Returns SW_OK if the tag matches, SW_DATA_INVALID otherwise.
fn pso_verify_checksum(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    let key_id_proto = match state.current_key_id {
        Some(id) => id,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };
    let full_key_id = KeyId::sc_hsm(0, key_id_proto).0;

    // Check metadata index for the key
    let _meta = match state.key_index.iter().find(|m| m.key_id == full_key_id) {
        Some(m) => *m,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // Load key material from flash
    let key_obj = match store.fetch_key(KeyId(full_key_id)) {
        Ok(Some(obj)) => obj,
        _ => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    let Some(raw_key) = sym_key(&key_obj) else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };
    let raw_key: &[u8] = &raw_key.0;

    let use_hmac = state.current_algo == Some(0xA0);
    let tag_len: usize = if use_hmac { 32 } else { 16 };

    if cmd.data.len() < tag_len {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }

    let msg_len = cmd.data.len() - tag_len;
    let message = &cmd.data[..msg_len];
    let expected_tag = &cmd.data[msg_len..];

    if use_hmac {
        let computed = crate::crypto::kdf::hmac_sha256(raw_key, message);
        if bool::from(subtle::ConstantTimeEq::ct_eq(
            computed.as_ref(),
            expected_tag,
        )) {
            ApduResponse::ok(&[])
        } else {
            ApduResponse::err(SW_DATA_INVALID)
        }
    } else {
        let expected: [u8; 16] = match expected_tag.try_into() {
            Ok(a) => a,
            Err(_) => return ApduResponse::err(SW_WRONG_LENGTH),
        };
        match crate::crypto::symmetric::aes_cmac_verify(raw_key, message, &expected) {
            Ok(true) => ApduResponse::ok(&[]),
            Ok(false) => ApduResponse::err(SW_DATA_INVALID),
            Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
        }
    }
}

// ---------------------------------------------------------------------------
// Host-side unit tests (cargo test --target x86_64-unknown-linux-gnu)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pico2hsm_core::key::{AppletId, KeyType as CoreKeyType};
    use rand_core::RngCore;

    use crate::crypto::asymmetric::generate_ec_keypair;
    use crate::protocol::sc_hsm::{KeyMeta, ScHsmState};
    use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};

    /// Test key store that holds a single KeyObject and returns it on fetch_key.
    struct TestStore {
        obj: Option<KeyObject>,
    }

    impl TestStore {
        fn new(obj: KeyObject) -> Self {
            Self { obj: Some(obj) }
        }
        fn empty() -> Self {
            Self { obj: None }
        }
    }

    impl crate::storage::KeyStore for TestStore {
        fn save_key(&mut self, _: &KeyObject) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn fetch_key(
            &mut self,
            key_id: KeyId,
        ) -> Result<Option<KeyObject>, pico2hsm_core::error::HsmError> {
            if let Some(ref obj) = self.obj {
                if obj.key_id == key_id.0 {
                    let mut clone =
                        KeyObject::new(obj.key_type, obj.key_id, obj.owner, obj.algorithm);
                    clone.key_flags = obj.key_flags;
                    let _ = clone.private_key.extend_from_slice(&obj.private_key);
                    let _ = clone.public_key.extend_from_slice(&obj.public_key);
                    return Ok(Some(clone));
                }
            }
            Ok(None)
        }
        fn erase_key(&mut self, _: KeyId) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn wipe_all(&mut self) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn wipe_by_owner(&mut self, _: AppletId) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn enumerate_keys(&self) -> heapless::Vec<KeyId, 64> {
            heapless::Vec::new()
        }
        fn for_each_key(&self, _f: &mut dyn FnMut(KeyId)) {}
    }

    // A simple counter-hash PRNG adequate for tests (no hardware RNG needed).
    struct CounterRng(u64);

    impl RngCore for CounterRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }

        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15u64);
                let v = self.0.wrapping_mul(0x6c62272e07bb0142u64) ^ 0xbf58476d1ce4e5b9u64;
                let vb = v.to_le_bytes();
                chunk.copy_from_slice(&vb[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for CounterRng {}

    // Helper to build an ApduCommand with data using the raw-byte parse path.
    fn make_cmd_with_data<'a>(
        buf: &'a mut heapless::Vec<u8, 512>,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> ApduCommand<'a> {
        buf.clear();
        let _ = buf.push(0x00);
        let _ = buf.push(INS_PSO);
        let _ = buf.push(p1);
        let _ = buf.push(p2);
        let _ = buf.push(data.len() as u8);
        let _ = buf.extend_from_slice(data);
        ApduCommand::parse(buf).unwrap()
    }

    /// Create a state+store with an EC key for PSO tests.
    fn make_ec_state_and_store(key_proto_ref: u8, algo: u8) -> (ScHsmState, TestStore) {
        let mut rng = CounterRng(algo as u64);
        let kp = generate_ec_keypair(CoreKeyType::EcPrivateP256, &mut rng).expect("P-256 keygen");

        let full_key_id = pico2hsm_core::key::KeyId::sc_hsm(0, key_proto_ref).0;

        let mut state = ScHsmState::new();
        state.pin_verified = true;
        state.current_key_id = Some(key_proto_ref);
        state.current_algo = Some(algo);

        let meta = KeyMeta {
            key_id: full_key_id,
            key_type: 0,
            algo: 0x13,
            key_flags: 0,
        };
        state.key_index.push(meta).unwrap();

        let mut key_obj = KeyObject::new(
            KmType::Ec,
            full_key_id,
            AppletId::ScHsm,
            AlgorithmId::EcdsaP256,
        );
        let _ = key_obj.private_key.extend_from_slice(&kp.private_key);
        let _ = key_obj.public_key.extend_from_slice(&kp.public_key);

        (state, TestStore::new(key_obj))
    }

    /// Create a state+store with a symmetric key for PSO checksum tests.
    fn make_sym_state_and_store(key_bytes: &[u8]) -> (ScHsmState, TestStore) {
        let full_id = pico2hsm_core::key::KeyId::sc_hsm(0, 0x10).0;

        let mut state = ScHsmState::new();
        state.pin_verified = true;
        state.current_key_id = Some(0x10);
        state.current_algo = Some(0x61); // AES-CBC → default to CMAC

        let meta = KeyMeta {
            key_id: full_id,
            key_type: 0,
            algo: 0x61,
            key_flags: 0,
        };
        state.key_index.push(meta).unwrap();

        let mut key_obj =
            KeyObject::new(KmType::Aes, full_id, AppletId::ScHsm, AlgorithmId::AesCbc);
        let _ = key_obj.private_key.extend_from_slice(key_bytes);

        (state, TestStore::new(key_obj))
    }

    #[test]
    fn test_pso_cds_requires_pin() {
        let mut state = ScHsmState::new();
        let mut store = TestStore::empty();
        let data = [0xABu8; 32];
        let mut buf: heapless::Vec<u8, 512> = heapless::Vec::new();
        let cmd = make_cmd_with_data(&mut buf, 0x9E, 0x9A, &data);
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_SECURITY_STATUS);
        assert!(resp.data.is_empty());
    }

    #[test]
    fn test_pso_cds_requires_mse() {
        let mut state = ScHsmState::new();
        let mut store = TestStore::empty();
        state.pin_verified = true;
        let data = [0xABu8; 32];
        let mut buf: heapless::Vec<u8, 512> = heapless::Vec::new();
        let cmd = make_cmd_with_data(&mut buf, 0x9E, 0x9A, &data);
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_pso_cds_p256_ecdsa() {
        let (mut state, mut store) = make_ec_state_and_store(0x01, 0x13);

        let hash = [0xAAu8; 32];
        let mut buf: heapless::Vec<u8, 512> = heapless::Vec::new();
        let cmd = make_cmd_with_data(&mut buf, 0x9E, 0x9A, &hash);
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_OK);
        assert!(!resp.data.is_empty());
    }

    #[test]
    fn test_pso_cds_p256_card_hash() {
        let (mut state, mut store) = make_ec_state_and_store(0x01, 0x73);

        let message = b"hello pico2hsm test message";
        let mut buf: heapless::Vec<u8, 512> = heapless::Vec::new();
        let cmd = make_cmd_with_data(&mut buf, 0x9E, 0x9A, message);
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_OK);
        assert!(!resp.data.is_empty());
    }

    #[test]
    fn test_pso_decipher_ecdh_p256() {
        let mut rng = CounterRng(3);

        let alice =
            generate_ec_keypair(CoreKeyType::EcPrivateP256, &mut rng).expect("Alice keygen");
        let bob = generate_ec_keypair(CoreKeyType::EcPrivateP256, &mut rng).expect("Bob keygen");

        let full_key_id = pico2hsm_core::key::KeyId::sc_hsm(0, 0x01).0;

        let mut state = ScHsmState::new();
        state.pin_verified = true;
        state.current_key_id = Some(0x01);
        state.current_algo = Some(0x80);

        // Use algo 0x13 (P-256 keygen algo) in metadata so meta_algo_to_ec_key_type works
        let meta = KeyMeta {
            key_id: full_key_id,
            key_type: 0,
            algo: 0x13,
            key_flags: 0,
        };
        state.key_index.push(meta).unwrap();

        let mut key_obj = KeyObject::new(
            KmType::Ec,
            full_key_id,
            AppletId::ScHsm,
            AlgorithmId::EcdsaP256,
        );
        let _ = key_obj.private_key.extend_from_slice(&alice.private_key);
        let _ = key_obj.public_key.extend_from_slice(&alice.public_key);
        let mut store = TestStore::new(key_obj);

        let peer_pub = bob.public_key.clone();
        assert_eq!(peer_pub[0], 0x04);
        assert_eq!(peer_pub.len(), 65);

        let mut buf: heapless::Vec<u8, 512> = heapless::Vec::new();
        let cmd = make_cmd_with_data(&mut buf, 0x80, 0x86, &peer_pub);
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_OK);
        assert!(!resp.data.is_empty());
        assert_eq!(resp.data[0], 0x04);
    }

    #[test]
    fn test_pso_unknown_operation() {
        let mut state = ScHsmState::new();
        let mut store = TestStore::empty();
        state.pin_verified = true;
        state.current_key_id = Some(0x01);
        state.current_algo = Some(0x13);

        let data = [0x01u8; 4];
        let mut buf: heapless::Vec<u8, 512> = heapless::Vec::new();
        let cmd = make_cmd_with_data(&mut buf, 0x01, 0x02, &data);
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_WRONG_DATA);
    }

    // -----------------------------------------------------------------------
    // PSO Compute / Verify Cryptographic Checksum tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_pso_ccc_aes_cmac_produces_16_bytes() {
        let key = [0x2bu8; 32];
        let (mut state, mut store) = make_sym_state_and_store(&key);
        let message = b"hello world";
        let mut buf: heapless::Vec<u8, 512> = heapless::Vec::new();
        let cmd = make_cmd_with_data(&mut buf, 0x8E, 0x80, message);
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_OK);
        assert_eq!(resp.data.len(), 16);
    }

    #[test]
    fn test_pso_ccc_cmac_then_verify_round_trip() {
        let key = [0x42u8; 32];
        let (mut state, mut store) = make_sym_state_and_store(&key);
        let message = b"round trip test";

        // Compute tag
        let mut buf: heapless::Vec<u8, 512> = heapless::Vec::new();
        let cmd = make_cmd_with_data(&mut buf, 0x8E, 0x80, message);
        let resp_compute = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp_compute.sw, pico2hsm_core::apdu::SW_OK);
        let tag = resp_compute.data.clone();
        assert_eq!(tag.len(), 16);

        // Verify: message || tag
        let mut verify_data: heapless::Vec<u8, 512> = heapless::Vec::new();
        verify_data.extend_from_slice(message).unwrap();
        verify_data.extend_from_slice(&tag).unwrap();
        let mut buf2: heapless::Vec<u8, 512> = heapless::Vec::new();
        let cmd2 = make_cmd_with_data(&mut buf2, 0x86, 0x80, &verify_data);
        let resp_verify = handle(&mut state, &mut store, &cmd2);
        assert_eq!(resp_verify.sw, pico2hsm_core::apdu::SW_OK);
    }

    #[test]
    fn test_pso_vcc_bad_tag_rejected() {
        let key = [0x11u8; 32];
        let (mut state, mut store) = make_sym_state_and_store(&key);
        let message = b"tamper test";

        // Wrong tag (all zeros)
        let mut verify_data: heapless::Vec<u8, 512> = heapless::Vec::new();
        verify_data.extend_from_slice(message).unwrap();
        verify_data.extend_from_slice(&[0u8; 16]).unwrap();

        let mut buf: heapless::Vec<u8, 512> = heapless::Vec::new();
        let cmd = make_cmd_with_data(&mut buf, 0x86, 0x80, &verify_data);
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_DATA_INVALID);
    }

    #[test]
    fn test_pso_ccc_requires_mse_key() {
        let mut state = ScHsmState::new();
        let mut store = TestStore::empty();
        state.pin_verified = true;
        // No current_key_id set
        let message = b"no key";
        let mut buf: heapless::Vec<u8, 512> = heapless::Vec::new();
        let cmd = make_cmd_with_data(&mut buf, 0x8E, 0x80, message);
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_pso_ccc_hmac_sha256_produces_32_bytes() {
        let key = [0x77u8; 32];
        let (mut state, mut store) = make_sym_state_and_store(&key);
        state.current_algo = Some(0xA0); // HMAC-SHA256
        let message = b"hmac test message";
        let mut buf: heapless::Vec<u8, 512> = heapless::Vec::new();
        let cmd = make_cmd_with_data(&mut buf, 0x8E, 0x80, message);
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_OK);
        assert_eq!(resp.data.len(), 32);
    }

    #[test]
    fn test_pso_vcc_hmac_round_trip() {
        let key = [0x99u8; 32];
        let (mut state, mut store) = make_sym_state_and_store(&key);
        state.current_algo = Some(0xA0);
        let message = b"hmac verify test";

        // Compute
        let mut buf: heapless::Vec<u8, 512> = heapless::Vec::new();
        let cmd = make_cmd_with_data(&mut buf, 0x8E, 0x80, message);
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, pico2hsm_core::apdu::SW_OK);
        let tag = resp.data.clone();
        assert_eq!(tag.len(), 32);

        // Verify
        let mut verify_data: heapless::Vec<u8, 512> = heapless::Vec::new();
        verify_data.extend_from_slice(message).unwrap();
        verify_data.extend_from_slice(&tag).unwrap();
        let mut buf2: heapless::Vec<u8, 512> = heapless::Vec::new();
        let cmd2 = make_cmd_with_data(&mut buf2, 0x86, 0x80, &verify_data);
        let resp2 = handle(&mut state, &mut store, &cmd2);
        assert_eq!(resp2.sw, pico2hsm_core::apdu::SW_OK);
    }
}
