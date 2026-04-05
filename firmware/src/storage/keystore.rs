//! Key store abstraction — encrypted persist/load/erase for `KeyObject`.
//!
//! # Roles
//! - [`KeyStore`] trait — the interface command handlers use. Implementations
//!   handle encryption and decryption internally; no raw SMK is ever visible to
//!   command handlers.
//! - [`FlashKeyStore`] — concrete implementation wrapping `StorageManager` plus
//!   the Storage Master Key (SMK). Uses AES-256-GCM (via `KeyObject::encrypt`)
//!   and BLAKE2s-256 integrity (via `compute_plaintext_blake2s`).
//! - [`NullKeyStore`] — no-op implementation for host-side (x86_64) unit tests.
//!
//! # Nonce generation
//! Each call to `save_key` generates a fresh 12-byte AES-GCM nonce from the
//! RP2350 hardware TRNG via `crate::crypto::rng::fill_random`. The nonce is
//! NOT stored separately — it is appended by `KeyObject::encrypt` inside the
//! ciphertext blob (see `key_management.rs` for the exact blob layout).

use heapless::Vec;
use pico2hsm_core::{
    error::HsmError,
    key::{AppletId, KeyId},
};

use crate::security::key_management::KeyObject;

// ARM-only imports used by FlashKeyStore.
#[cfg(target_arch = "arm")]
use pico2hsm_core::{
    error::{CryptoError, StorageError},
    key::KeyType as CoreKeyType,
};
#[cfg(target_arch = "arm")]
use zeroize::Zeroizing;
#[cfg(target_arch = "arm")]
use pico2hsm_core::flash::FlashChip;
#[cfg(target_arch = "arm")]
use crate::security::key_management::AlgorithmId;
#[cfg(target_arch = "arm")]
use crate::storage::StorageManager;
#[cfg(target_arch = "arm")]
use crate::storage::integrity::compute_plaintext_blake2s;

// ─── KeyStore trait ───────────────────────────────────────────────────────────

/// Persistent key storage interface for APDU command handlers.
///
/// Implementations handle encryption/decryption internally.
/// Command handlers receive `&mut dyn KeyStore` and never touch raw SMK.
pub trait KeyStore {
    /// Encrypt and persist a key object to flash.
    fn save_key(&mut self, obj: &KeyObject) -> Result<(), HsmError>;

    /// Load and decrypt a key by ID. Returns `Ok(None)` if not found.
    fn fetch_key(&mut self, key_id: KeyId) -> Result<Option<KeyObject>, HsmError>;

    /// Delete a key from persistent storage.
    fn erase_key(&mut self, key_id: KeyId) -> Result<(), HsmError>;

    /// Wipe ALL keys. Called by INITIALIZE only.
    fn wipe_all(&mut self) -> Result<(), HsmError>;

    /// Wipe only keys owned by the given applet. Called by applet INITIALIZE.
    fn wipe_by_owner(&mut self, owner: AppletId) -> Result<(), HsmError>;

    /// List all key IDs currently in persistent storage.
    fn enumerate_keys(&self) -> Vec<KeyId, 512>;
}

// ─── FlashKeyStore<Chip> ──────────────────────────────────────────────────────

/// Concrete key store backed by a `StorageManager<Chip>` and protected by the
/// Storage Master Key (`smk`).
#[cfg(target_arch = "arm")]
pub struct FlashKeyStore<Chip: FlashChip> {
    storage: StorageManager<Chip>,
    smk: Zeroizing<[u8; 32]>,
}

#[cfg(target_arch = "arm")]
impl<Chip: FlashChip> FlashKeyStore<Chip> {
    /// Construct a new `FlashKeyStore`.
    ///
    /// `storage` should already have chips added via `KeyFilesystem::add_chip`.
    /// Call [`init`] before any key operations.
    pub fn new(storage: StorageManager<Chip>, smk: Zeroizing<[u8; 32]>) -> Self {
        FlashKeyStore { storage, smk }
    }

    /// Initialise: scan chips, load directory, run WAL recovery.
    pub fn init(&mut self) -> Result<(), StorageError> {
        self.storage.init()
    }
}

#[cfg(target_arch = "arm")]
impl<Chip: FlashChip> KeyStore for FlashKeyStore<Chip> {
    fn save_key(&mut self, obj: &KeyObject) -> Result<(), HsmError> {
        // --- 1. Generate a fresh 12-byte nonce from the hardware TRNG. ---
        let mut nonce = [0u8; 12];
        crate::crypto::rng::fill_random(&mut nonce)
            .map_err(HsmError::Crypto)?;

        // --- 2. Encrypt the key object. ---
        let blob = obj
            .encrypt(&self.smk, &nonce)
            .map_err(|_| HsmError::Crypto(CryptoError::EncryptFailure))?;

        // --- 3. Compute BLAKE2s-256 of the plaintext for integrity. ---
        // The plaintext that is hashed is the raw private key material.
        // This lets the storage layer verify integrity after decryption
        // without re-deriving the KEK.
        let hash = compute_plaintext_blake2s(&obj.private_key);

        // --- 4. Map AlgorithmId → core KeyType. ---
        let core_key_type = algo_to_core_key_type(obj.algorithm);

        // --- 5. Write to flash. ---
        self.storage
            .write_key(KeyId(obj.key_id), core_key_type, &blob, &hash)
            .map_err(HsmError::Storage)
    }

    fn fetch_key(&mut self, key_id: KeyId) -> Result<Option<KeyObject>, HsmError> {
        // Check whether the key exists in the directory first so we can
        // return Ok(None) cleanly instead of propagating a ReadError.
        let key_ids = self.storage.list_keys();
        if !key_ids.iter().any(|k| k.0 == key_id.0) {
            return Ok(None);
        }

        let blob = self
            .storage
            .read_key(key_id)
            .map_err(HsmError::Storage)?;

        // Pass the u32 key_id to decrypt — decrypt uses the low byte for KEK derivation.
        let obj = KeyObject::decrypt(&blob, key_id.0, &self.smk)
            .map_err(|_| HsmError::Crypto(CryptoError::DecryptFailure))?;

        Ok(Some(obj))
    }

    fn erase_key(&mut self, key_id: KeyId) -> Result<(), HsmError> {
        self.storage
            .delete_key(key_id)
            .map_err(HsmError::Storage)
    }

    fn wipe_all(&mut self) -> Result<(), HsmError> {
        self.storage.wipe_all().map_err(HsmError::Storage)
    }

    fn wipe_by_owner(&mut self, owner: AppletId) -> Result<(), HsmError> {
        let keys = self.storage.list_keys();
        for k in keys {
            if ((k.0 >> 16) & 0xFF) as u8 == owner as u8 {
                self.storage.delete_key(k).map_err(HsmError::Storage)?;
            }
        }
        Ok(())
    }

    fn enumerate_keys(&self) -> Vec<KeyId, 512> {
        self.storage.list_keys()
    }
}

// ─── NullKeyStore (host-side tests) ──────────────────────────────────────────

/// No-op key store for host-side (x86_64) unit tests.
///
/// All operations succeed immediately without touching any flash.
#[cfg(not(target_arch = "arm"))]
pub struct NullKeyStore;

#[cfg(not(target_arch = "arm"))]
impl KeyStore for NullKeyStore {
    fn save_key(&mut self, _: &KeyObject) -> Result<(), HsmError> {
        Ok(())
    }

    fn fetch_key(&mut self, _: KeyId) -> Result<Option<KeyObject>, HsmError> {
        Ok(None)
    }

    fn erase_key(&mut self, _: KeyId) -> Result<(), HsmError> {
        Ok(())
    }

    fn wipe_all(&mut self) -> Result<(), HsmError> {
        Ok(())
    }

    fn wipe_by_owner(&mut self, _: AppletId) -> Result<(), HsmError> {
        Ok(())
    }

    fn enumerate_keys(&self) -> Vec<KeyId, 512> {
        Vec::new()
    }
}

// ─── Helper: AlgorithmId → core KeyType ──────────────────────────────────────

/// Map a `security::key_management::AlgorithmId` to the `pico2hsm_core::key::KeyType`
/// used by the storage layer.
#[cfg(target_arch = "arm")]
fn algo_to_core_key_type(algo: AlgorithmId) -> CoreKeyType {
    match algo {
        // EC curves
        AlgorithmId::EcdsaP256 | AlgorithmId::EcdhP256 => CoreKeyType::EcPrivateP256,
        AlgorithmId::EcdsaP384 | AlgorithmId::EcdhP384 => CoreKeyType::EcPrivateP384,
        AlgorithmId::EcdsaP521 | AlgorithmId::EcdhP521 => CoreKeyType::EcPrivateP521,
        AlgorithmId::EcdsaK256 => CoreKeyType::EcPrivateK256,
        AlgorithmId::EcdsaBrainpool256 => CoreKeyType::EcPrivateBrainpoolP256,
        AlgorithmId::EcdsaBrainpool384 => CoreKeyType::EcPrivateBrainpoolP384,
        AlgorithmId::EcdsaBrainpool512 => CoreKeyType::EcPrivateBrainpoolP512,
        // RSA
        AlgorithmId::RsaPkcs1Sha256
        | AlgorithmId::RsaPkcs1Sha384
        | AlgorithmId::RsaPkcs1Sha512
        | AlgorithmId::RsaPss
        | AlgorithmId::RsaDecrypt => CoreKeyType::RsaPrivate2048,
        // AES / symmetric
        AlgorithmId::AesEcb
        | AlgorithmId::AesCbc
        | AlgorithmId::AesCtr
        | AlgorithmId::AesGcm => CoreKeyType::Aes256,
    }
}
