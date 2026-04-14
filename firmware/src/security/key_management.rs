//! Key management — SC-HSM key object format, wrap/unwrap, per-key KEK derivation.
//!
//! # Key object on-storage format (P2K4)
//! Each key is stored as an AES-256-GCM encrypted blob at logical address
//! `0xCC00 + key_id` (managed by the storage layer). The blob layout is:
//!
//! ```text
//! [4]   magic            b"P2K4"  (was b"P2K3" before key_flags field)
//! [1]   key_type         KeyType repr (0x01-0x04)
//! [4]   key_id           little-endian u32 (partition|applet|reserved|proto_ref)
//! [1]   algorithm        AlgorithmId repr
//! [1]   key_size_bytes   raw private key length
//! [1]   key_domain       domain tag (0 = default)
//! [4]   use_count        big-endian u32
//! [4]   generation       big-endian u32 (new in P2K3; 0 for P2K2 blobs)
//! [1]   key_flags        key access conditions (new in P2K4; 0 for P2K3/P2K2 blobs)
//! [N]   private_key      raw private key scalar / symmetric key
//! [2]   pub_len          big-endian u16 (0 if no public key)
//! [M]   public_key       raw public key bytes (may be 0 bytes)
//! ---  (header = first 21 bytes, used as GCM AAD; payload encrypted in-place)
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

use pico2hsm_core::key::AppletId;

use aes_gcm::{
    aead::{AeadInPlace, KeyInit as GcmKeyInit},
    Aes256Gcm,
    Nonce as GcmNonce,
    Tag as GcmTag,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic header for stored key blobs (v4: added key_flags byte).
///
/// History:
///   - `P2K2` — original u32 key ID format (no generation counter).
///   - `P2K3` — added 4-byte `generation` field after `use_count` (20-byte header).
///   - `P2K4` — added 1-byte `key_flags` after `generation` (21-byte header).
///
/// Data written with `P2K2` or `P2K3` is handled by backward-compat logic in
/// `decrypt()` (missing fields default to 0). Firmware that writes `P2K4`
/// cannot be read by older builds — re-INITIALIZE required after upgrade.
///
/// **AAD migration**: each magic version uses a different header size as GCM AAD,
/// so blobs written with one magic cannot be decrypted using another magic's
/// header size. The `decrypt()` function selects the correct AAD size based on
/// the magic it finds.
pub const KEY_MAGIC: [u8; 4] = *b"P2K4";

/// Legacy magic header (v2) — accepted on read with generation=0, key_flags=0.
pub const KEY_MAGIC_V2: [u8; 4] = *b"P2K2";

/// Legacy magic header (v3) — accepted on read with key_flags=0.
pub const KEY_MAGIC_V3: [u8; 4] = *b"P2K3";

/// Maximum number of key slots (key_id 0x01–0xFF).
pub const MAX_KEYS: usize = 255;

/// AES-256-GCM nonce size.
const NONCE_SIZE: usize = 12;

/// AES-256-GCM tag size.
const TAG_SIZE: usize = 16;

/// HKDF info prefix for per-key KEK derivation.
const KEK_INFO_PREFIX: &[u8] = b"pico2hsm-keyobj-v1";

/// P2K4 header size.
const P2K4_HEADER_SIZE: usize = 21;

/// Maximum plaintext payload inside a P2K4 encrypted blob.
///
/// Layout: `[opt 2-byte priv_len] || priv_key || pub_len(2) || pub_key`.
/// The 2-byte priv_len prefix is added when `priv_key.len() > 255` (RSA).
pub const MAX_PLAINTEXT_SIZE: usize = 2 + MAX_PRIVATE_KEY_SIZE + 2 + MAX_PUBLIC_KEY_SIZE;

/// Maximum encrypted blob size (P2K4 format).
///
/// header(21) + MAX_PLAINTEXT_SIZE + tag(16) + nonce(12).
pub const MAX_BLOB_SIZE: usize = P2K4_HEADER_SIZE + MAX_PLAINTEXT_SIZE + TAG_SIZE + NONCE_SIZE;

/// Maximum DKEK-wrapped payload: key_type(1) + key_size(2) + priv_key + padding(≤7).
const DKEK_MAX_PAYLOAD: usize = 1 + 2 + MAX_PRIVATE_KEY_SIZE + 7;

/// Maximum DKEK-wrapped blob: nonce(12) + payload + tag(16).
const DKEK_MAX_BLOB: usize = NONCE_SIZE + DKEK_MAX_PAYLOAD + TAG_SIZE;

/// Maximum private key size.
///
/// RSA-2048 PKCS#1 DER private keys are ~1192 bytes; RSA-4096 are ~2350 bytes.
/// Sized to 2400 bytes to cover both RSA key sizes and all EC curves.
#[cfg(feature = "rsa")]
pub const MAX_PRIVATE_KEY_SIZE: usize = 2400;
#[cfg(not(feature = "rsa"))]
pub const MAX_PRIVATE_KEY_SIZE: usize = 512;

/// Maximum public key size.
///
/// Uncompressed P-521 point = 133 bytes.  RSA-4096 public key blob layout is
/// `[2 BE mod_len] || modulus (512 B) || exponent (≤4 B)` = 518 bytes.
pub const MAX_PUBLIC_KEY_SIZE: usize = 520;

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
    // Curve25519
    Ed25519              = 0x20,
    X25519               = 0x21,
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
            0x20 => Some(AlgorithmId::Ed25519),
            0x21 => Some(AlgorithmId::X25519),
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
    /// Full u32 internal key ID (structured: partition | applet | reserved | proto_ref).
    pub key_id:      u32,
    /// Owning applet.
    pub owner:       AppletId,
    pub algorithm:   AlgorithmId,
    pub key_domain:  u8,
    pub use_count:   u32,
    /// Monotonically increasing generation counter.
    ///
    /// Incremented on every `save_key` call. Starts at 1 on first write.
    /// Used by the DKEK sync protocol to detect stale replicas.
    /// Blobs written with the old `P2K2` magic will deserialize with
    /// `generation = 0`.
    pub generation:  u32,
    /// Key access conditions byte (SC-HSM TLV tag 0xD4).
    ///
    /// Bit layout: 0=ALLOW_SIGN, 1=ALLOW_DECRYPT, 2=ALLOW_DERIVE, 3=NO_EXPORT.
    /// Default 0x00 = all operations allowed, exportable.
    /// Persisted in flash since P2K4; older blobs (P2K2/P2K3) default to 0.
    pub key_flags:   u8,
    /// Daemon-assigned HLC timestamp (ms since epoch), 0 for legacy/locally-generated keys.
    pub timestamp_ms: u64,
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
        self.generation = 0;
        self.key_flags = 0;
        self.timestamp_ms = 0;
        self.key_id = 0;
        self.owner.zeroize();
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
        key_id:    u32,
        owner:     AppletId,
        algorithm: AlgorithmId,
    ) -> Self {
        KeyObject {
            key_type,
            key_id,
            owner,
            algorithm,
            key_domain: 0,
            use_count: 0,
            generation: 0,
            key_flags: 0,
            timestamp_ms: 0,
            private_key: heapless::Vec::new(),
            public_key: heapless::Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Serialise plaintext header (used as AAD and as start of the blob)
    // -----------------------------------------------------------------------

    /// Serialise the fixed metadata header into `buf` (AAD portion).
    ///
    /// Layout (21 bytes, P2K4):
    ///   magic(4) | key_type(1) | key_id(4) | algorithm(1) |
    ///   key_size(1) | key_domain(1) | use_count(4) | generation(4) | key_flags(1)
    fn write_header(&self, buf: &mut [u8; 21]) {
        buf[0..4].copy_from_slice(&KEY_MAGIC);
        buf[4] = self.key_type as u8;
        buf[5..9].copy_from_slice(&self.key_id.to_le_bytes());
        buf[9] = self.algorithm as u8;
        // For EC keys (≤255 bytes) store the exact length.
        // For RSA keys (>255 bytes) store 0 as a sentinel; the actual
        // length is prepended as a 2-byte LE value in the plaintext.
        buf[10] = if self.private_key.len() > 255 { 0 } else { self.private_key.len() as u8 };
        buf[11] = self.key_domain;
        buf[12..16].copy_from_slice(&self.use_count.to_be_bytes());
        buf[16..20].copy_from_slice(&self.generation.to_be_bytes());
        buf[20] = self.key_flags;
    }

    // -----------------------------------------------------------------------
    // Encrypt — produce on-storage blob
    // -----------------------------------------------------------------------

    /// Encrypt this key object into a storage blob.
    ///
    /// The returned buffer contains:
    /// `header(21) || priv_key(N) || pub_len(2) || pub_key(M) || tag(16) || nonce(12)`
    ///
    /// where `header` also acts as the GCM AAD so any tampering with metadata
    /// is detected on decryption.
    pub fn encrypt(
        &self,
        smk: &[u8; 32],
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<heapless::Vec<u8, MAX_BLOB_SIZE>, KeyError> {
        // Derive per-key encryption key using the low-byte proto_ref.
        let kek = derive_key_encryption_key(smk, (self.key_id & 0xFF) as u8)?;

        // Build AAD = header bytes.
        let mut header = [0u8; P2K4_HEADER_SIZE];
        self.write_header(&mut header);

        // Build plaintext:
        //   EC  keys (priv ≤ 255): priv_key || pub_len(2) || pub_key
        //   RSA keys (priv > 255): priv_len_le16(2) || priv_key || pub_len(2) || pub_key
        let priv_len = self.private_key.len();
        let pub_len  = self.public_key.len();
        let inline_len = priv_len > 255;
        let prefix_len = if inline_len { 2 } else { 0 };
        let pt_len = prefix_len + priv_len + 2 + pub_len;
        if pt_len > MAX_PLAINTEXT_SIZE {
            return Err(KeyError::KeyTooLarge);
        }

        // GCM payload buffer (plaintext -> ciphertext in-place)
        let mut ct_buf: heapless::Vec<u8, MAX_BLOB_SIZE> = heapless::Vec::new();
        // Start with the header (included in blob, used as GCM AAD)
        ct_buf.extend_from_slice(&header).map_err(|_| KeyError::BufferTooSmall)?;
        // For RSA: prepend 2-byte LE private key length
        if inline_len {
            ct_buf.extend_from_slice(&(priv_len as u16).to_le_bytes()).map_err(|_| KeyError::BufferTooSmall)?;
        }
        ct_buf.extend_from_slice(&self.private_key).map_err(|_| KeyError::BufferTooSmall)?;
        let pub_len_bytes = (pub_len as u16).to_be_bytes();
        ct_buf.extend_from_slice(&pub_len_bytes).map_err(|_| KeyError::BufferTooSmall)?;
        ct_buf.extend_from_slice(&self.public_key).map_err(|_| KeyError::BufferTooSmall)?;

        // Encrypt the payload portion (everything after the header) in-place.
        let cipher = Aes256Gcm::new_from_slice(&*kek)
            .map_err(|_| KeyError::EncryptFailure)?;
        let nonce_arr = GcmNonce::from_slice(nonce);

        let tag = cipher
            .encrypt_in_place_detached(nonce_arr, &header, &mut ct_buf.as_mut_slice()[P2K4_HEADER_SIZE..])
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
    /// `key_id` is the full u32 internal key ID; the low byte (proto_ref) is
    /// used for KEK derivation and must match the blob header.
    ///
    /// Supports `P2K4` (21-byte header with key_flags), `P2K3` (20-byte header
    /// with generation, key_flags defaults to 0), and the legacy `P2K2`
    /// (16-byte header, generation and key_flags default to 0).
    pub fn decrypt(blob: &[u8], key_id: u32, smk: &[u8; 32]) -> Result<Self, KeyError> {
        // Minimum: header(16) + tag(16) + nonce(12) = 44 bytes (P2K2 minimum)
        if blob.len() < 44 {
            return Err(KeyError::InvalidFormat);
        }

        // Determine header version from the magic bytes.
        let is_v4 = bool::from(blob[0..4].ct_eq(&KEY_MAGIC));
        let is_v3 = bool::from(blob[0..4].ct_eq(&KEY_MAGIC_V3));
        let is_v2 = bool::from(blob[0..4].ct_eq(&KEY_MAGIC_V2));
        if !is_v4 && !is_v3 && !is_v2 {
            return Err(KeyError::BadMagic);
        }
        let header_size: usize = if is_v4 { 21 } else if is_v3 { 20 } else { 16 };

        if blob.len() < header_size + TAG_SIZE + NONCE_SIZE {
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

        // The header is the first `header_size` bytes (also AAD).
        let header = &blob[..header_size];

        // Parse common header fields (same layout for bytes 0..16).
        let kt   = KeyType::from_u8(header[4]).ok_or(KeyError::UnknownKeyType)?;
        let stored_key_id = u32::from_le_bytes(header[5..9].try_into().unwrap());
        let algo = AlgorithmId::from_u8(header[9]).ok_or(KeyError::UnknownAlgorithm)?;
        let priv_size = header[10] as usize;
        let domain    = header[11];
        let use_count = u32::from_be_bytes(header[12..16].try_into().unwrap());

        // Parse generation (P2K3/P2K4; defaults to 0 for P2K2 blobs).
        let generation = if is_v4 || is_v3 {
            u32::from_be_bytes(header[16..20].try_into().unwrap())
        } else {
            0
        };

        // Parse key_flags (P2K4 only; defaults to 0 for P2K2/P2K3 blobs).
        let key_flags = if is_v4 { header[20] } else { 0 };

        // Sanity: the key_id in the blob must match the requested key_id.
        if stored_key_id != key_id {
            return Err(KeyError::InvalidFormat);
        }

        // Derive per-key encryption key using the low-byte proto_ref.
        let kek = derive_key_encryption_key(smk, (key_id & 0xFF) as u8)?;

        // Decrypt the payload portion (between header and tag).
        let ct_payload = &blob[header_size..tag_start];

        // Copy into a mutable buffer for in-place decryption.
        let mut pt_buf = Zeroizing::new([0u8; MAX_PLAINTEXT_SIZE]);
        if ct_payload.len() > MAX_PLAINTEXT_SIZE {
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

        // Parse plaintext.  Two layouts depending on priv_size sentinel:
        //   priv_size > 0 (EC):  priv_key(priv_size) || pub_len(2) || pub_key
        //   priv_size == 0 (RSA): priv_len_le16(2) || priv_key || pub_len(2) || pub_key
        let (priv_offset, priv_size) = if priv_size == 0 {
            // RSA: read actual private key length from first 2 bytes.
            if ct_payload.len() < 4 {
                return Err(KeyError::InvalidFormat);
            }
            let len = u16::from_le_bytes(pt_buf[0..2].try_into().unwrap()) as usize;
            (2usize, len)
        } else {
            (0usize, priv_size)
        };

        if ct_payload.len() < priv_offset + priv_size + 2 {
            return Err(KeyError::InvalidFormat);
        }
        let pub_len = u16::from_be_bytes(
            pt_buf[priv_offset + priv_size..priv_offset + priv_size + 2].try_into().unwrap()
        ) as usize;
        let total_needed = priv_offset + priv_size + 2 + pub_len;
        if ct_payload.len() < total_needed {
            return Err(KeyError::InvalidFormat);
        }

        // Determine owner from applet byte (bits 23-16) of key_id.
        let owner = match ((key_id >> 16) & 0xFF) as u8 {
            0x01 => AppletId::Piv,
            0x02 => AppletId::OpenPgp,
            _ => AppletId::ScHsm,
        };

        let mut obj = KeyObject {
            key_type: kt,
            key_id,
            owner,
            algorithm: algo,
            key_domain: domain,
            use_count,
            generation,
            key_flags,
            timestamp_ms: 0,
            private_key: heapless::Vec::new(),
            public_key: heapless::Vec::new(),
        };

        obj.private_key
            .extend_from_slice(&pt_buf[priv_offset..priv_offset + priv_size])
            .map_err(|_| KeyError::KeyTooLarge)?;
        obj.public_key
            .extend_from_slice(&pt_buf[priv_offset + priv_size + 2..priv_offset + priv_size + 2 + pub_len])
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
    ) -> Result<heapless::Vec<u8, DKEK_MAX_BLOB>, KeyError> {
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

        if payload_len > DKEK_MAX_PAYLOAD {
            return Err(KeyError::KeyTooLarge);
        }

        // Build plaintext into a Zeroizing buffer.
        let mut pt = Zeroizing::new([0u8; DKEK_MAX_PAYLOAD]);
        pt[0] = self.key_type as u8;
        let ks = (priv_len as u16).to_be_bytes();
        pt[1..3].copy_from_slice(&ks);
        pt[3..3 + priv_len].copy_from_slice(&self.private_key);
        // Padding bytes are already 0 (zero-filled).

        let cipher = Aes256Gcm::new_from_slice(dkek)
            .map_err(|_| KeyError::EncryptFailure)?;
        let nonce_arr = GcmNonce::from_slice(nonce);

        // Copy plaintext into output buffer (nonce first)
        let mut out: heapless::Vec<u8, DKEK_MAX_BLOB> = heapless::Vec::new();
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
        key_id:    u32,
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

        if ct.len() > DKEK_MAX_PAYLOAD {
            return Err(KeyError::KeyTooLarge);
        }

        let aad: [u8; 32] = Sha256::digest(device_id).into();

        let mut pt = Zeroizing::new([0u8; DKEK_MAX_PAYLOAD]);
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

        // Determine owner from applet byte (bits 23-16) of key_id.
        let owner = match ((key_id >> 16) & 0xFF) as u8 {
            0x01 => AppletId::Piv,
            0x02 => AppletId::OpenPgp,
            _ => AppletId::ScHsm,
        };

        let mut obj = KeyObject {
            key_type:   raw_kt,
            key_id,
            owner,
            algorithm,
            key_domain: 0,
            use_count:  0,
            generation: 0,
            key_flags:  0,
            timestamp_ms: 0,
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
        use pico2hsm_core::key::AppletId;
        let smk = test_smk();
        let nonce = test_nonce();

        let mut obj = KeyObject::new(KeyType::Ec, 0x00000001u32, AppletId::ScHsm, AlgorithmId::EcdsaP256);
        obj.generation = 42;
        // Fake 32-byte P-256 private key scalar.
        obj.private_key.extend_from_slice(&[0x42u8; 32]).unwrap();
        // Fake 65-byte uncompressed P-256 public key.
        obj.public_key.extend_from_slice(&[0x04u8; 65]).unwrap();

        let blob = obj.encrypt(&smk, &nonce).unwrap();
        let recovered = KeyObject::decrypt(&blob, 0x00000001u32, &smk).unwrap();

        assert_eq!(recovered.key_type, KeyType::Ec);
        assert_eq!(recovered.key_id, 0x00000001u32);
        assert_eq!(recovered.algorithm, AlgorithmId::EcdsaP256);
        assert_eq!(recovered.private_key.as_slice(), &[0x42u8; 32]);
        assert_eq!(recovered.public_key.as_slice(), &[0x04u8; 65]);
        assert_eq!(recovered.generation, 42);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_aes() {
        use pico2hsm_core::key::AppletId;
        let smk = test_smk();
        let nonce = test_nonce();

        let mut obj = KeyObject::new(KeyType::Aes, 0x00000010u32, AppletId::ScHsm, AlgorithmId::AesGcm);
        obj.private_key.extend_from_slice(&[0xBEu8; 32]).unwrap();

        let blob = obj.encrypt(&smk, &nonce).unwrap();
        let recovered = KeyObject::decrypt(&blob, 0x00000010u32, &smk).unwrap();

        assert_eq!(recovered.algorithm, AlgorithmId::AesGcm);
        assert_eq!(recovered.private_key.as_slice(), &[0xBEu8; 32]);
        assert_eq!(recovered.public_key.len(), 0);
    }

    #[test]
    fn test_decrypt_wrong_key_id_fails() {
        use pico2hsm_core::key::AppletId;
        let smk = test_smk();
        let nonce = test_nonce();

        let mut obj = KeyObject::new(KeyType::Aes, 0x00000005u32, AppletId::ScHsm, AlgorithmId::AesCbc);
        obj.private_key.extend_from_slice(&[0x11u8; 16]).unwrap();

        let blob = obj.encrypt(&smk, &nonce).unwrap();
        // Decrypt claiming a different key_id — should fail on authentication tag.
        let result = KeyObject::decrypt(&blob, 0x00000006u32, &smk);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_blob_fails() {
        use pico2hsm_core::key::AppletId;
        let smk = test_smk();
        let nonce = test_nonce();

        let mut obj = KeyObject::new(KeyType::Ec, 0x00000002u32, AppletId::ScHsm, AlgorithmId::EcdsaP384);
        obj.private_key.extend_from_slice(&[0xFFu8; 48]).unwrap();

        let mut blob = obj.encrypt(&smk, &nonce).unwrap();
        // Tamper with the ciphertext body.
        blob[20] ^= 0xFF;
        let result = KeyObject::decrypt(&blob, 0x00000002u32, &smk);
        assert!(matches!(result, Err(KeyError::DecryptFailure)));
    }

    #[test]
    fn test_dkek_wrap_unwrap_roundtrip() {
        use pico2hsm_core::key::AppletId;
        let dkek = [0xDEu8; 32];
        let device_id = b"pico2hsm-test-device-id";
        let nonce = test_nonce();

        let mut obj = KeyObject::new(KeyType::Ec, 0x00000003u32, AppletId::ScHsm, AlgorithmId::EcdhP256);
        obj.private_key.extend_from_slice(&[0xABu8; 32]).unwrap();

        let wrapped = obj.wrap_dkek(&dkek, device_id, &nonce).unwrap();
        let recovered = KeyObject::unwrap_dkek(
            &wrapped, &dkek, device_id, 0x00000007u32, AlgorithmId::EcdhP256,
        ).unwrap();

        assert_eq!(recovered.private_key.as_slice(), &[0xABu8; 32]);
        assert_eq!(recovered.key_id, 0x00000007u32);
    }

    #[test]
    fn test_dkek_wrap_wrong_device_id_fails() {
        use pico2hsm_core::key::AppletId;
        let dkek = [0xDEu8; 32];
        let nonce = test_nonce();

        let mut obj = KeyObject::new(KeyType::Aes, 0x00000001u32, AppletId::ScHsm, AlgorithmId::AesGcm);
        obj.private_key.extend_from_slice(&[0x99u8; 32]).unwrap();

        let wrapped = obj.wrap_dkek(&dkek, b"device-A", &nonce).unwrap();
        let result = KeyObject::unwrap_dkek(&wrapped, &dkek, b"device-B", 0x00000001u32, AlgorithmId::AesGcm);
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
