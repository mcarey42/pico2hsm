//! Key management — SC-HSM key object format, wrap/unwrap, per-key KEK derivation.
//!
//! # Key object on-storage format
//! Each key is stored as an AES-256-GCM encrypted blob at logical address
//! `0xCC00 + key_id` (managed by the storage layer). The blob layout is:
//!
//! ```text
//! [4]   magic            b"P2KY"
//! [1]   key_type         KeyType repr (0x01–0x04)
//! [1]   key_id           0x01–0xFF
//! [1]   algorithm        AlgorithmId repr
//! [1]   key_size_bytes   raw private key length
//! [1]   key_domain       domain tag (0 = default)
//! [4]   use_count        big-endian u32
//! [N]   private_key      raw private key scalar / symmetric key
//! [2]   pub_len          big-endian u16 (0 if no public key)
//! [M]   public_key       raw public key bytes (may be 0 bytes)
//! ---  (all fields above are plaintext that becomes AAD for GCM)
//! [16]  GCM tag          appended by AES-256-GCM encrypt
//! [12]  nonce            appended after tag
//! ```
//!
//! The per-key encryption key (KEK) is derived from the Storage Master Key (SMK):
//! ```text
//! KEK = HKDF-SHA256(ikm=SMK, salt=[], info=b"pico2hsm-keyobj-v1" || [key_id], len=32)
//! ```
//!
//! # DKEK key-wrap format
//! When exporting a key wrapped under the DKEK for HSM-to-HSM transfer:
//! ```text
//! nonce(12) || AES-256-GCM(key=DKEK, nonce, aad=device_id, plaintext=key_payload) || tag(16)
//! ```
//! where `key_payload = key_type(1) || key_size_be(2) || private_key || padding_to_8`

#![allow(dead_code)]

use core::convert::TryInto;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use aes_gcm::{
    aead::{AeadInPlace, KeyInit as GcmKeyInit},
    Aes256Gcm,
    Nonce as GcmNonce,
    Tag as GcmTag,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic header for stored key blobs.
pub const KEY_MAGIC: [u8; 4] = *b"P2KY";

/// Maximum number of key slots (key_id 0x01–0xFF).
pub const MAX_KEYS: usize = 255;

/// AES-256-GCM nonce size.
const NONCE_SIZE: usize = 12;

/// AES-256-GCM tag size.
const TAG_SIZE: usize = 16;

/// HKDF info prefix for per-key KEK derivation.
const KEK_INFO_PREFIX: &[u8] = b"pico2hsm-keyobj-v1";

/// Maximum private key size (enough for RSA-4096 PKCS#1 DER ≈ 2350 bytes,
/// but capped at 512 for no_std stack use; RSA is feature-gated).
pub const MAX_PRIVATE_KEY_SIZE: usize = 512;

/// Maximum public key size (uncompressed P-521 point = 133 bytes; allow 512).
pub const MAX_PUBLIC_KEY_SIZE: usize = 512;

// ---------------------------------------------------------------------------
// KeyType
// ---------------------------------------------------------------------------

/// Key algorithm family tag stored in every key blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyType {
    Rsa     = 0x01,
    Ec      = 0x02,
    Aes     = 0x03,
    Generic = 0x04,
}

impl KeyType {
    /// Try to parse a `KeyType` from its byte representation.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(KeyType::Rsa),
            0x02 => Some(KeyType::Ec),
            0x03 => Some(KeyType::Aes),
            0x04 => Some(KeyType::Generic),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// AlgorithmId
// ---------------------------------------------------------------------------

/// SC-HSM algorithm identifier.  Values match the SC-HSM spec AlgorithmID list
/// (subset implemented here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlgorithmId {
    // EC signatures
    EcdsaP256            = 0x13,
    EcdsaP384            = 0x15,
    EcdsaP521            = 0x17,
    EcdsaK256            = 0x19,
    EcdsaBrainpool256    = 0x53,
    EcdsaBrainpool384    = 0x54,
    EcdsaBrainpool512    = 0x55,
    // EC key agreement
    EcdhP256             = 0x23,
    EcdhP384             = 0x25,
    EcdhP521             = 0x27,
    // RSA signatures
    RsaPkcs1Sha256       = 0x31,
    RsaPkcs1Sha384       = 0x32,
    RsaPkcs1Sha512       = 0x33,
    RsaPss               = 0x34,
    RsaDecrypt           = 0x41,
    // Symmetric
    AesEcb               = 0x60,
    AesCbc               = 0x61,
    AesCtr               = 0x62,
    AesGcm               = 0x63,
}

impl AlgorithmId {
    /// Try to parse an `AlgorithmId` from its byte representation.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x13 => Some(AlgorithmId::EcdsaP256),
            0x15 => Some(AlgorithmId::EcdsaP384),
            0x17 => Some(AlgorithmId::EcdsaP521),
            0x19 => Some(AlgorithmId::EcdsaK256),
            0x53 => Some(AlgorithmId::EcdsaBrainpool256),
            0x54 => Some(AlgorithmId::EcdsaBrainpool384),
            0x55 => Some(AlgorithmId::EcdsaBrainpool512),
            0x23 => Some(AlgorithmId::EcdhP256),
            0x25 => Some(AlgorithmId::EcdhP384),
            0x27 => Some(AlgorithmId::EcdhP521),
            0x31 => Some(AlgorithmId::RsaPkcs1Sha256),
            0x32 => Some(AlgorithmId::RsaPkcs1Sha384),
            0x33 => Some(AlgorithmId::RsaPkcs1Sha512),
            0x34 => Some(AlgorithmId::RsaPss),
            0x41 => Some(AlgorithmId::RsaDecrypt),
            0x60 => Some(AlgorithmId::AesEcb),
            0x61 => Some(AlgorithmId::AesCbc),
            0x62 => Some(AlgorithmId::AesCtr),
            0x63 => Some(AlgorithmId::AesGcm),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// KeyError
// ---------------------------------------------------------------------------

/// Errors returned by key management operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// Input blob is too short or structurally invalid.
    InvalidFormat,
    /// Magic header mismatch.
    BadMagic,
    /// Unrecognised key_type byte.
    UnknownKeyType,
    /// Unrecognised algorithm byte.
    UnknownAlgorithm,
    /// Key material exceeds the maximum supported size.
    KeyTooLarge,
    /// AES-GCM encryption failed.
    EncryptFailure,
    /// AES-GCM authentication tag mismatch on decrypt.
    DecryptFailure,
    /// HKDF derivation failed.
    KdfFailure,
    /// Output buffer is too small.
    BufferTooSmall,
    /// DKEK is not available.
    NoDkek,
}

// ---------------------------------------------------------------------------
// KeyObject
// ---------------------------------------------------------------------------

/// An in-memory key object (decrypted, sensitive).
///
/// All fields containing secret material implement `Zeroize` and the struct
/// is wrapped in `Zeroizing` at call sites where it leaves a function.
pub struct KeyObject {
    pub key_type:    KeyType,
    pub key_id:      u8,
    pub algorithm:   AlgorithmId,
    pub key_domain:  u8,
    pub use_count:   u32,
    /// Raw private key scalar or symmetric key bytes (zeroized on drop).
    pub private_key: heapless::Vec<u8, MAX_PRIVATE_KEY_SIZE>,
    /// Optional raw public key (uncompressed EC point, or RSA public key DER).
    pub public_key:  heapless::Vec<u8, MAX_PUBLIC_KEY_SIZE>,
}

impl Zeroize for KeyObject {
    fn zeroize(&mut self) {
        self.private_key.zeroize();
        self.public_key.zeroize();
        self.use_count = 0;
        self.key_id = 0;
        self.key_domain = 0;
    }
}

impl Drop for KeyObject {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl KeyObject {
    /// Create a new `KeyObject` with empty key material.
    pub fn new(
        key_type:  KeyType,
        key_id:    u8,
        algorithm: AlgorithmId,
    ) -> Self {
        KeyObject {
            key_type,
            key_id,
            algorithm,
            key_domain: 0,
            use_count: 0,
            private_key: heapless::Vec::new(),
            public_key: heapless::Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Serialise plaintext header (used as AAD and as start of the blob)
    // -----------------------------------------------------------------------

    /// Serialise the fixed metadata header into `buf` (AAD portion).
    ///
    /// Layout: magic(4) | key_type(1) | key_id(1) | algorithm(1) |
    ///         key_size(1) | key_domain(1) | use_count(4)
    fn write_header(&self, buf: &mut [u8; 13]) {
        buf[0..4].copy_from_slice(&KEY_MAGIC);
        buf[4] = self.key_type as u8;
        buf[5] = self.key_id;
        buf[6] = self.algorithm as u8;
        buf[7] = self.private_key.len() as u8;
        buf[8] = self.key_domain;
        let uc = self.use_count.to_be_bytes();
        buf[9..13].copy_from_slice(&uc);
    }

    // -----------------------------------------------------------------------
    // Encrypt — produce on-storage blob
    // -----------------------------------------------------------------------

    /// Encrypt this key object into a storage blob.
    ///
    /// The returned buffer contains:
    /// `header(13) || priv_key(N) || pub_len(2) || pub_key(M) || tag(16) || nonce(12)`
    ///
    /// where `header` also acts as the GCM AAD so any tampering with metadata
    /// is detected on decryption.
    pub fn encrypt(
        &self,
        smk: &[u8; 32],
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<heapless::Vec<u8, 1200>, KeyError> {
        // Derive per-key encryption key.
        let kek = derive_key_encryption_key(smk, self.key_id)?;

        // Build AAD = header bytes.
        let mut header = [0u8; 13];
        self.write_header(&mut header);

        // Build plaintext = priv_key || pub_len(2) || pub_key
        // Max size: 512 priv + 2 + 512 pub = 1026 bytes
        let priv_len = self.private_key.len();
        let pub_len  = self.public_key.len();
        let pt_len   = priv_len + 2 + pub_len;
        if pt_len > 1026 {
            return Err(KeyError::KeyTooLarge);
        }

        // GCM payload buffer (plaintext → ciphertext in-place)
        let mut ct_buf: heapless::Vec<u8, 1200> = heapless::Vec::new();
        // Start with the header (will be included in the blob, not in GCM input)
        ct_buf.extend_from_slice(&header).map_err(|_| KeyError::BufferTooSmall)?;
        ct_buf.extend_from_slice(&self.private_key).map_err(|_| KeyError::BufferTooSmall)?;
        let pub_len_bytes = (pub_len as u16).to_be_bytes();
        ct_buf.extend_from_slice(&pub_len_bytes).map_err(|_| KeyError::BufferTooSmall)?;
        ct_buf.extend_from_slice(&self.public_key).map_err(|_| KeyError::BufferTooSmall)?;

        // Encrypt the payload portion (everything after the header) in-place.
        let cipher = Aes256Gcm::new_from_slice(&*kek)
            .map_err(|_| KeyError::EncryptFailure)?;
        let nonce_arr = GcmNonce::from_slice(nonce);

        // payload slice starts after the 13-byte header
        let tag = cipher
            .encrypt_in_place_detached(nonce_arr, &header, &mut ct_buf.as_mut_slice()[13..])
            .map_err(|_| KeyError::EncryptFailure)?;

        // Append tag then nonce.
        ct_buf.extend_from_slice(tag.as_slice()).map_err(|_| KeyError::BufferTooSmall)?;
        ct_buf.extend_from_slice(nonce).map_err(|_| KeyError::BufferTooSmall)?;

        Ok(ct_buf)
    }

    // -----------------------------------------------------------------------
    // Decrypt — reconstruct from storage blob
    // -----------------------------------------------------------------------

    /// Decrypt a storage blob and reconstruct the `KeyObject`.
    ///
    /// `blob` must be the exact bytes returned by [`KeyObject::encrypt`].
    pub fn decrypt(blob: &[u8], key_id: u8, smk: &[u8; 32]) -> Result<Self, KeyError> {
        // Minimum: header(13) + tag(16) + nonce(12) = 41 bytes
        if blob.len() < 41 {
            return Err(KeyError::InvalidFormat);
        }

        // Extract nonce and tag from the end.
        let blob_len = blob.len();
        let nonce_start = blob_len - NONCE_SIZE;
        let tag_start   = nonce_start - TAG_SIZE;

        let nonce: &[u8; 12] = blob[nonce_start..].try_into()
            .map_err(|_| KeyError::InvalidFormat)?;
        let tag_bytes: &[u8; 16] = blob[tag_start..nonce_start].try_into()
            .map_err(|_| KeyError::InvalidFormat)?;

        // The header is the first 13 bytes (also AAD).
        let header: &[u8; 13] = blob[..13].try_into()
            .map_err(|_| KeyError::InvalidFormat)?;

        // Validate magic.
        if !bool::from(header[0..4].ct_eq(&KEY_MAGIC)) {
            return Err(KeyError::BadMagic);
        }

        // Parse header fields.
        let kt   = KeyType::from_u8(header[4]).ok_or(KeyError::UnknownKeyType)?;
        let kid  = header[5];
        let algo = AlgorithmId::from_u8(header[6]).ok_or(KeyError::UnknownAlgorithm)?;
        let priv_size = header[7] as usize;
        let domain    = header[8];
        let use_count = u32::from_be_bytes(header[9..13].try_into().unwrap());

        // Sanity: the key_id in the blob must match the requested key_id.
        if kid != key_id {
            return Err(KeyError::InvalidFormat);
        }

        // Derive per-key encryption key.
        let kek = derive_key_encryption_key(smk, key_id)?;

        // Decrypt the payload portion (between header and tag).
        let ct_payload = &blob[13..tag_start];
        if ct_payload.len() < priv_size + 2 {
            return Err(KeyError::InvalidFormat);
        }

        // Copy into a mutable buffer for in-place decryption.
        let mut pt_buf = Zeroizing::new([0u8; 1200]);
        if ct_payload.len() > 1200 {
            return Err(KeyError::KeyTooLarge);
        }
        pt_buf[..ct_payload.len()].copy_from_slice(ct_payload);

        let cipher = Aes256Gcm::new_from_slice(&*kek)
            .map_err(|_| KeyError::DecryptFailure)?;
        let nonce_arr = GcmNonce::from_slice(nonce);
        let tag_val   = GcmTag::clone_from_slice(tag_bytes);

        cipher
            .decrypt_in_place_detached(
                nonce_arr,
                header,
                &mut pt_buf[..ct_payload.len()],
                &tag_val,
            )
            .map_err(|_| KeyError::DecryptFailure)?;

        // Parse plaintext: priv_key || pub_len(2) || pub_key
        if ct_payload.len() < priv_size + 2 {
            return Err(KeyError::InvalidFormat);
        }
        let pub_len = u16::from_be_bytes(
            pt_buf[priv_size..priv_size + 2].try_into().unwrap()
        ) as usize;
        let total_needed = priv_size + 2 + pub_len;
        if ct_payload.len() < total_needed {
            return Err(KeyError::InvalidFormat);
        }

        let mut obj = KeyObject {
            key_type: kt,
            key_id: kid,
            algorithm: algo,
            key_domain: domain,
            use_count,
            private_key: heapless::Vec::new(),
            public_key: heapless::Vec::new(),
        };

        obj.private_key
            .extend_from_slice(&pt_buf[..priv_size])
            .map_err(|_| KeyError::KeyTooLarge)?;
        obj.public_key
            .extend_from_slice(&pt_buf[priv_size + 2..priv_size + 2 + pub_len])
            .map_err(|_| KeyError::KeyTooLarge)?;

        Ok(obj)
    }

    // -----------------------------------------------------------------------
    // DKEK wrap — HSM-to-HSM export
    // -----------------------------------------------------------------------

    /// Wrap this key under the DKEK for HSM-to-HSM export.
    ///
    /// Output format: `nonce(12) || ciphertext || tag(16)`
    /// AAD: `SHA-256(device_id)`
    pub fn wrap_dkek(
        &self,
        dkek:      &[u8; 32],
        device_id: &[u8],
        nonce:     &[u8; NONCE_SIZE],
    ) -> Result<heapless::Vec<u8, 1200>, KeyError> {
        // Compute AAD = SHA-256(device_id)
        let aad: [u8; 32] = Sha256::digest(device_id).into();

        // Build plaintext payload: key_type(1) || key_size_be(2) || private_key || padding
        let priv_len = self.private_key.len();
        let payload_len_before_pad = 1 + 2 + priv_len;
        let pad = if payload_len_before_pad % 8 == 0 {
            0
        } else {
            8 - (payload_len_before_pad % 8)
        };
        let payload_len = payload_len_before_pad + pad;

        if payload_len > 1024 {
            return Err(KeyError::KeyTooLarge);
        }

        // Build plaintext into a Zeroizing buffer.
        let mut pt = Zeroizing::new([0u8; 1024]);
        pt[0] = self.key_type as u8;
        let ks = (priv_len as u16).to_be_bytes();
        pt[1..3].copy_from_slice(&ks);
        pt[3..3 + priv_len].copy_from_slice(&self.private_key);
        // Padding bytes are already 0 (zero-filled).

        let cipher = Aes256Gcm::new_from_slice(dkek)
            .map_err(|_| KeyError::EncryptFailure)?;
        let nonce_arr = GcmNonce::from_slice(nonce);

        // Copy plaintext into output buffer (nonce first)
        let mut out: heapless::Vec<u8, 1200> = heapless::Vec::new();
        out.extend_from_slice(nonce).map_err(|_| KeyError::BufferTooSmall)?;
        out.extend_from_slice(&pt[..payload_len]).map_err(|_| KeyError::BufferTooSmall)?;

        let tag = cipher
            .encrypt_in_place_detached(
                nonce_arr,
                &aad,
                &mut out.as_mut_slice()[NONCE_SIZE..NONCE_SIZE + payload_len],
            )
            .map_err(|_| KeyError::EncryptFailure)?;

        out.extend_from_slice(tag.as_slice()).map_err(|_| KeyError::BufferTooSmall)?;

        Ok(out)
    }

    // -----------------------------------------------------------------------
    // DKEK unwrap — HSM-to-HSM import
    // -----------------------------------------------------------------------

    /// Unwrap a DKEK-wrapped blob from another HSM.
    ///
    /// `blob` must be `nonce(12) || ciphertext || tag(16)`.
    /// The unwrapped key's `key_id` and `algorithm` must be set by the caller
    /// after this call since they are not encoded in the DKEK payload by design
    /// (the importing HSM assigns a new key_id).
    pub fn unwrap_dkek(
        blob:      &[u8],
        dkek:      &[u8; 32],
        device_id: &[u8],
        key_id:    u8,
        algorithm: AlgorithmId,
    ) -> Result<Self, KeyError> {
        // blob = nonce(12) || ciphertext || tag(16)
        if blob.len() < NONCE_SIZE + TAG_SIZE + 3 {
            return Err(KeyError::InvalidFormat);
        }

        let nonce: &[u8; 12] = blob[..NONCE_SIZE].try_into()
            .map_err(|_| KeyError::InvalidFormat)?;
        let ct_end = blob.len() - TAG_SIZE;
        let tag_bytes: &[u8; 16] = blob[ct_end..].try_into()
            .map_err(|_| KeyError::InvalidFormat)?;
        let ct = &blob[NONCE_SIZE..ct_end];

        if ct.len() > 1024 {
            return Err(KeyError::KeyTooLarge);
        }

        let aad: [u8; 32] = Sha256::digest(device_id).into();

        let mut pt = Zeroizing::new([0u8; 1024]);
        pt[..ct.len()].copy_from_slice(ct);

        let cipher = Aes256Gcm::new_from_slice(dkek)
            .map_err(|_| KeyError::DecryptFailure)?;
        let nonce_arr = GcmNonce::from_slice(nonce);
        let tag_val   = GcmTag::clone_from_slice(tag_bytes);

        cipher
            .decrypt_in_place_detached(nonce_arr, &aad, &mut pt[..ct.len()], &tag_val)
            .map_err(|_| KeyError::DecryptFailure)?;

        // Parse payload: key_type(1) || key_size_be(2) || private_key || padding
        let raw_kt  = KeyType::from_u8(pt[0]).ok_or(KeyError::UnknownKeyType)?;
        let key_sz  = u16::from_be_bytes([pt[1], pt[2]]) as usize;
        if 3 + key_sz > ct.len() {
            return Err(KeyError::InvalidFormat);
        }

        let mut obj = KeyObject {
            key_type:   raw_kt,
            key_id,
            algorithm,
            key_domain: 0,
            use_count:  0,
            private_key: heapless::Vec::new(),
            public_key: heapless::Vec::new(),
        };

        obj.private_key
            .extend_from_slice(&pt[3..3 + key_sz])
            .map_err(|_| KeyError::KeyTooLarge)?;

        Ok(obj)
    }
}

// ---------------------------------------------------------------------------
// Per-key KEK derivation
// ---------------------------------------------------------------------------

/// Derive the per-key encryption key (KEK) from the Storage Master Key (SMK).
///
/// `HKDF-SHA256(ikm=SMK, salt=[], info=b"pico2hsm-keyobj-v1" || [key_id], len=32)`
///
/// The returned key is wrapped in `Zeroizing` to ensure it is cleared from
/// memory when it goes out of scope.
pub fn derive_key_encryption_key(
    smk:    &[u8; 32],
    key_id: u8,
) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    // Build info = KEK_INFO_PREFIX || key_id
    let mut info = [0u8; KEK_INFO_PREFIX.len() + 1];
    info[..KEK_INFO_PREFIX.len()].copy_from_slice(KEK_INFO_PREFIX);
    info[KEK_INFO_PREFIX.len()] = key_id;

    let hkdf = Hkdf::<Sha256>::new(None, smk);
    let mut kek = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, kek.as_mut())
        .map_err(|_| KeyError::KdfFailure)?;

    Ok(kek)
}

// ---------------------------------------------------------------------------
// KeyDomain
// ---------------------------------------------------------------------------

/// A key domain groups keys that share a lifecycle and DKEK binding.
///
/// Domains allow multiple independent security environments on one HSM
/// (e.g. separate customer tenants), each with its own key rotation policy.
#[derive(Debug, Clone, Copy)]
pub struct KeyDomain {
    /// Domain identifier (0 = default domain).
    pub id: u8,
    /// Cumulative use count across all keys in this domain.
    pub use_count: u32,
    /// After how many operations a rotation hint is issued (0 = never).
    pub rotation_threshold: u32,
    /// Whether keys in this domain are exportable under the DKEK.
    pub dkek_domain: bool,
}

impl KeyDomain {
    /// Create a new domain with default settings.
    pub fn new(id: u8) -> Self {
        KeyDomain {
            id,
            use_count: 0,
            rotation_threshold: 0,
            dkek_domain: false,
        }
    }

    /// Increment the use counter. Returns `true` if rotation threshold reached.
    pub fn record_use(&mut self) -> bool {
        self.use_count = self.use_count.saturating_add(1);
        self.rotation_threshold > 0 && self.use_count >= self.rotation_threshold
    }

    /// Reset the use counter (called after key rotation is complete).
    pub fn reset_use_count(&mut self) {
        self.use_count = 0;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Produce a deterministic fake SMK for testing.
    fn test_smk() -> [u8; 32] {
        let mut smk = [0u8; 32];
        for (i, b) in smk.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(7);
        }
        smk
    }

    /// Produce a deterministic fake nonce for testing.
    fn test_nonce() -> [u8; 12] {
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
    }

    #[test]
    fn test_kek_derivation_deterministic() {
        let smk = test_smk();
        let kek1 = derive_key_encryption_key(&smk, 0x01).unwrap();
        let kek2 = derive_key_encryption_key(&smk, 0x01).unwrap();
        assert_eq!(*kek1, *kek2, "KEK derivation must be deterministic");
    }

    #[test]
    fn test_kek_different_per_key_id() {
        let smk = test_smk();
        let kek1 = derive_key_encryption_key(&smk, 0x01).unwrap();
        let kek2 = derive_key_encryption_key(&smk, 0x02).unwrap();
        assert_ne!(*kek1, *kek2, "Different key_ids must produce different KEKs");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_ec() {
        let smk = test_smk();
        let nonce = test_nonce();

        let mut obj = KeyObject::new(KeyType::Ec, 0x01, AlgorithmId::EcdsaP256);
        // Fake 32-byte P-256 private key scalar.
        obj.private_key.extend_from_slice(&[0x42u8; 32]).unwrap();
        // Fake 65-byte uncompressed P-256 public key.
        obj.public_key.extend_from_slice(&[0x04u8; 65]).unwrap();

        let blob = obj.encrypt(&smk, &nonce).unwrap();
        let recovered = KeyObject::decrypt(&blob, 0x01, &smk).unwrap();

        assert_eq!(recovered.key_type, KeyType::Ec);
        assert_eq!(recovered.key_id, 0x01);
        assert_eq!(recovered.algorithm, AlgorithmId::EcdsaP256);
        assert_eq!(recovered.private_key.as_slice(), &[0x42u8; 32]);
        assert_eq!(recovered.public_key.as_slice(), &[0x04u8; 65]);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_aes() {
        let smk = test_smk();
        let nonce = test_nonce();

        let mut obj = KeyObject::new(KeyType::Aes, 0x10, AlgorithmId::AesGcm);
        obj.private_key.extend_from_slice(&[0xBEu8; 32]).unwrap();

        let blob = obj.encrypt(&smk, &nonce).unwrap();
        let recovered = KeyObject::decrypt(&blob, 0x10, &smk).unwrap();

        assert_eq!(recovered.algorithm, AlgorithmId::AesGcm);
        assert_eq!(recovered.private_key.as_slice(), &[0xBEu8; 32]);
        assert_eq!(recovered.public_key.len(), 0);
    }

    #[test]
    fn test_decrypt_wrong_key_id_fails() {
        let smk = test_smk();
        let nonce = test_nonce();

        let mut obj = KeyObject::new(KeyType::Aes, 0x05, AlgorithmId::AesCbc);
        obj.private_key.extend_from_slice(&[0x11u8; 16]).unwrap();

        let blob = obj.encrypt(&smk, &nonce).unwrap();
        // Decrypt claiming a different key_id — should fail on authentication tag.
        let result = KeyObject::decrypt(&blob, 0x06, &smk);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_blob_fails() {
        let smk = test_smk();
        let nonce = test_nonce();

        let mut obj = KeyObject::new(KeyType::Ec, 0x02, AlgorithmId::EcdsaP384);
        obj.private_key.extend_from_slice(&[0xFFu8; 48]).unwrap();

        let mut blob = obj.encrypt(&smk, &nonce).unwrap();
        // Tamper with the ciphertext body.
        blob[20] ^= 0xFF;
        let result = KeyObject::decrypt(&blob, 0x02, &smk);
        assert!(matches!(result, Err(KeyError::DecryptFailure)));
    }

    #[test]
    fn test_dkek_wrap_unwrap_roundtrip() {
        let dkek = [0xDEu8; 32];
        let device_id = b"pico2hsm-test-device-id";
        let nonce = test_nonce();

        let mut obj = KeyObject::new(KeyType::Ec, 0x03, AlgorithmId::EcdhP256);
        obj.private_key.extend_from_slice(&[0xABu8; 32]).unwrap();

        let wrapped = obj.wrap_dkek(&dkek, device_id, &nonce).unwrap();
        let recovered = KeyObject::unwrap_dkek(
            &wrapped, &dkek, device_id, 0x07, AlgorithmId::EcdhP256,
        ).unwrap();

        assert_eq!(recovered.private_key.as_slice(), &[0xABu8; 32]);
        assert_eq!(recovered.key_id, 0x07);
    }

    #[test]
    fn test_dkek_wrap_wrong_device_id_fails() {
        let dkek = [0xDEu8; 32];
        let nonce = test_nonce();

        let mut obj = KeyObject::new(KeyType::Aes, 0x01, AlgorithmId::AesGcm);
        obj.private_key.extend_from_slice(&[0x99u8; 32]).unwrap();

        let wrapped = obj.wrap_dkek(&dkek, b"device-A", &nonce).unwrap();
        let result = KeyObject::unwrap_dkek(&wrapped, &dkek, b"device-B", 0x01, AlgorithmId::AesGcm);
        assert!(matches!(result, Err(KeyError::DecryptFailure)));
    }

    #[test]
    fn test_key_domain_rotation_threshold() {
        let mut domain = KeyDomain::new(0);
        domain.rotation_threshold = 3;
        assert!(!domain.record_use());
        assert!(!domain.record_use());
        assert!(domain.record_use()); // third use triggers rotation hint
        domain.reset_use_count();
        assert!(!domain.record_use()); // reset clears counter
    }
}
