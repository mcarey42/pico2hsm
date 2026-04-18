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
use crate::security::key_management::AlgorithmId;
#[cfg(target_arch = "arm")]
use crate::storage::integrity::compute_plaintext_blake2s;
#[cfg(target_arch = "arm")]
use crate::storage::StorageManager;
#[cfg(target_arch = "arm")]
use pico2hsm_core::flash::FlashChip;
#[cfg(target_arch = "arm")]
use pico2hsm_core::{
    error::{CryptoError, StorageError},
    key::KeyType as CoreKeyType,
};
#[cfg(target_arch = "arm")]
use zeroize::Zeroizing;

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
    ///
    /// Returns a fixed-capacity vector of up to 64 key IDs.  Most devices
    /// will have far fewer than 64 keys; the previous 512-entry capacity
    /// wasted 2 KB of stack on every call.
    fn enumerate_keys(&self) -> Vec<KeyId, 64>;

    /// Invoke `f` for each key ID in persistent storage.
    ///
    /// Preferred over `enumerate_keys()` when the caller only needs to
    /// iterate — avoids allocating even the 64-entry Vec on the stack.
    /// Uses `&mut dyn FnMut` instead of `impl FnMut` for dyn-compatibility.
    fn for_each_key(&self, f: &mut dyn FnMut(KeyId));
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
        // --- 0. Increment the generation counter before writing. ---
        // We cannot mutate `obj` (it's a shared reference), so we clone the
        // relevant fields into a local copy with generation bumped.
        let mut obj_copy = KeyObject::new(obj.key_type, obj.key_id, obj.owner, obj.algorithm);
        obj_copy.key_domain = obj.key_domain;
        obj_copy.use_count = obj.use_count;
        obj_copy.generation = obj.generation.saturating_add(1);
        obj_copy.key_flags = obj.key_flags;
        obj_copy
            .private_key
            .extend_from_slice(&obj.private_key)
            .map_err(|_| HsmError::Crypto(CryptoError::EncryptFailure))?;
        obj_copy
            .public_key
            .extend_from_slice(&obj.public_key)
            .map_err(|_| HsmError::Crypto(CryptoError::EncryptFailure))?;

        // --- 1. Generate a fresh 12-byte nonce from the hardware TRNG. ---
        let mut nonce = [0u8; 12];
        crate::crypto::rng::fill_random(&mut nonce).map_err(HsmError::Crypto)?;

        // --- 2. Encrypt the key object (with bumped generation). ---
        let blob = obj_copy
            .encrypt(&self.smk, &nonce)
            .map_err(|_| HsmError::Crypto(CryptoError::EncryptFailure))?;

        // --- 3. Compute BLAKE2s-256 of the plaintext for integrity. ---
        // The plaintext that is hashed is the raw private key material.
        // This lets the storage layer verify integrity after decryption
        // without re-deriving the KEK.
        let hash = compute_plaintext_blake2s(&obj_copy.private_key);

        // --- 4. Map AlgorithmId -> core KeyType. ---
        let core_key_type = algo_to_core_key_type(obj_copy.algorithm);

        // --- 5. Write to flash. ---
        let result = self
            .storage
            .write_key(KeyId(obj_copy.key_id), core_key_type, &blob, &hash)
            .map_err(HsmError::Storage);
        if result.is_ok() {
            crate::cdc_log!("FLASH save key=0x{:08x} ok", obj_copy.key_id);
        }
        result
    }

    fn fetch_key(&mut self, key_id: KeyId) -> Result<Option<KeyObject>, HsmError> {
        // Check whether the key exists in the directory first so we can
        // return Ok(None) cleanly instead of propagating a ReadError.
        if !self.storage.key_exists(key_id) {
            return Ok(None);
        }

        let blob = self.storage.read_key(key_id).map_err(HsmError::Storage)?;

        // Pass the u32 key_id to decrypt — decrypt uses the low byte for KEK derivation.
        let obj = KeyObject::decrypt(&blob, key_id.0, &self.smk)
            .map_err(|_| HsmError::Crypto(CryptoError::DecryptFailure))?;

        Ok(Some(obj))
    }

    fn erase_key(&mut self, key_id: KeyId) -> Result<(), HsmError> {
        let result = self.storage.delete_key(key_id).map_err(HsmError::Storage);
        if result.is_ok() {
            crate::cdc_log!("FLASH erase key=0x{:08x} ok", key_id.0);
        }
        result
    }

    fn wipe_all(&mut self) -> Result<(), HsmError> {
        crate::cdc_log!("FLASH wipe_all start");
        let result = self.storage.wipe_all().map_err(HsmError::Storage);
        crate::cdc_log!("FLASH wipe_all done");
        result
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

    fn enumerate_keys(&self) -> Vec<KeyId, 64> {
        let mut out = Vec::new();
        self.storage.for_each_key(&mut |kid| {
            let _ = out.push(kid);
        });
        out
    }

    fn for_each_key(&self, f: &mut dyn FnMut(KeyId)) {
        self.storage.for_each_key(f);
    }
}

// ─── NullKeyStore (host-side tests) ──────────────────────────────────────────

/// No-op key store for host-side (x86_64) unit tests.
///
/// All operations succeed immediately without touching any flash.
pub struct NullKeyStore;

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

    fn enumerate_keys(&self) -> Vec<KeyId, 64> {
        Vec::new()
    }

    fn for_each_key(&self, _f: &mut dyn FnMut(KeyId)) {
        // No keys in the null store.
    }
}

// ─── HybridKeyStore<P, S> — RAID-1 mirror (primary flash + secondary SD) ─────

/// RAID-1 keystore that mirrors writes between a primary store (flash) and a
/// secondary store (SD card).
///
/// **Write**: primary first, then secondary. If primary succeeds but secondary
/// fails, the write is considered successful but the mirror is marked degraded.
///
/// **Read**: primary first. If primary fails or key is not found, falls back to
/// secondary and attempts a best-effort write-back to primary.
///
/// **Wipe**: both stores. Only a primary wipe failure is propagated.
///
/// **Enumerate**: delegates to primary (authoritative).
pub struct HybridKeyStore<P: KeyStore, S: KeyStore> {
    primary: P,
    secondary: S,
    /// `true` when the SD mirror is stale (a secondary write has failed).
    degraded: bool,
    /// `true` when the primary flash has experienced a read or write error.
    /// Flash errors are fatal — the HSM cannot safely operate.
    flash_error: bool,
}

impl<P: KeyStore, S: KeyStore> HybridKeyStore<P, S> {
    /// Create a new hybrid keystore with the given primary and secondary stores.
    pub fn new(primary: P, secondary: S) -> Self {
        HybridKeyStore {
            primary,
            secondary,
            degraded: false,
            flash_error: false,
        }
    }

    /// `true` when the SD mirror is stale (a secondary write failed).
    /// Clears automatically after a successful resync.
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// `true` when the primary flash has NOT experienced a read or write error.
    /// Flash errors are fatal — the HSM cannot safely operate without its
    /// primary store.
    pub fn is_flash_healthy(&self) -> bool {
        !self.flash_error
    }

    /// Attempt to resync all keys from primary to secondary.
    ///
    /// Enumerates all key IDs from primary, reads each key, and writes it to
    /// secondary. If any key fails to sync, returns `Err` but continues
    /// syncing the remaining keys.
    pub fn resync(&mut self) -> Result<(), HsmError> {
        crate::cdc_log!("HYBRID resync start");
        // Collect key IDs first (we need &mut self for fetch_key below).
        let key_ids = self.primary.enumerate_keys();
        let mut any_failed = false;

        for key_id in key_ids.iter() {
            match self.primary.fetch_key(*key_id) {
                Ok(Some(obj)) => {
                    if self.secondary.save_key(&obj).is_err() {
                        #[cfg(target_arch = "arm")]
                        defmt::warn!("HybridKeyStore: resync failed for key 0x{:08x}", key_id.0);
                        any_failed = true;
                    }
                }
                Ok(None) => {
                    // Key vanished between enumerate and fetch — skip.
                }
                Err(_) => {
                    #[cfg(target_arch = "arm")]
                    defmt::warn!(
                        "HybridKeyStore: resync read failed for key 0x{:08x}",
                        key_id.0
                    );
                    self.flash_error = true;
                    any_failed = true;
                }
            }
        }

        if any_failed {
            crate::cdc_warn!("HYBRID resync partial fail");
            Err(HsmError::Storage(
                pico2hsm_core::error::StorageError::WriteError,
            ))
        } else {
            self.degraded = false;
            self.flash_error = false;
            crate::cdc_log!("HYBRID resync ok");
            Ok(())
        }
    }

    /// Poll for SD card recovery. Call this periodically (e.g. every few
    /// seconds from the core1 dispatcher idle loop).
    ///
    /// If currently degraded, attempts a probe read on the secondary store.
    /// If that succeeds, triggers a full resync. If resync succeeds, clears
    /// the degraded flag.
    ///
    /// If not degraded, this is a no-op.
    pub fn poll_recovery(&mut self) -> Result<(), HsmError> {
        if !self.degraded {
            return Ok(());
        }

        // Probe the secondary by iterating keys — this exercises the SD
        // card read path without writing. If the card is removed or broken,
        // for_each_key will typically iterate nothing or the underlying
        // driver will error (caught by the resync attempt below).
        self.secondary.for_each_key(&mut |_| {});

        // Attempt a full resync. If it succeeds, degraded is cleared inside resync().
        match self.resync() {
            Ok(()) => {
                #[cfg(target_arch = "arm")]
                defmt::info!("HybridKeyStore: SD card recovered — resync complete");
                crate::cdc_log!("HYBRID SD recovered, resync ok");
                Ok(())
            }
            Err(e) => {
                // Still degraded — SD is not back yet.
                self.degraded = true;
                Err(e)
            }
        }
    }

    /// Mutable reference to the primary store (for init, etc.).
    pub fn primary_mut(&mut self) -> &mut P {
        &mut self.primary
    }

    /// Mutable reference to the secondary store (for init, etc.).
    pub fn secondary_mut(&mut self) -> &mut S {
        &mut self.secondary
    }
}

impl<P: KeyStore, S: KeyStore> KeyStore for HybridKeyStore<P, S> {
    fn save_key(&mut self, obj: &KeyObject) -> Result<(), HsmError> {
        // Write to primary first — primary failure is fatal.
        if let Err(e) = self.primary.save_key(obj) {
            self.flash_error = true;
            return Err(e);
        }

        // Write to secondary — failure is non-fatal but marks degraded.
        if let Err(_e) = self.secondary.save_key(obj) {
            #[cfg(target_arch = "arm")]
            defmt::warn!("HybridKeyStore: secondary write failed — marking degraded");
            crate::cdc_warn!(
                "HYBRID secondary write failed key=0x{:08x} — degraded",
                obj.key_id
            );
            self.degraded = true;
        } else if self.degraded {
            // Secondary write succeeded while degraded — trigger full resync.
            #[cfg(target_arch = "arm")]
            defmt::info!("HybridKeyStore: secondary write OK while degraded — triggering resync");
            let _ = self.resync();
        }

        crate::cdc_log!("HYBRID save key=0x{:08x} ok", obj.key_id);
        Ok(())
    }

    fn fetch_key(&mut self, key_id: KeyId) -> Result<Option<KeyObject>, HsmError> {
        // Try primary first.
        match self.primary.fetch_key(key_id) {
            Ok(Some(obj)) => return Ok(Some(obj)),
            Ok(None) => {
                // Key not found in primary — fall through to secondary.
            }
            Err(_) => {
                // Primary read error — flag it, fall through to secondary.
                self.flash_error = true;
                #[cfg(target_arch = "arm")]
                defmt::warn!("HybridKeyStore: primary read error for key 0x{:08x}, falling back to secondary", key_id.0);
                crate::cdc_warn!(
                    "HYBRID primary miss key=0x{:08x}, trying secondary",
                    key_id.0
                );
            }
        }

        // Fall back to secondary.
        match self.secondary.fetch_key(key_id) {
            Ok(Some(obj)) => {
                // Resync: best-effort write-back to primary.
                if let Err(_e) = self.primary.save_key(&obj) {
                    #[cfg(target_arch = "arm")]
                    defmt::warn!(
                        "HybridKeyStore: write-back to primary failed for key 0x{:08x}",
                        key_id.0
                    );
                    // Don't propagate — we have the key from secondary.
                }
                Ok(Some(obj))
            }
            Ok(None) => Ok(None),
            Err(_) => {
                #[cfg(target_arch = "arm")]
                defmt::warn!(
                    "HybridKeyStore: secondary read also failed for key 0x{:08x}",
                    key_id.0
                );
                // Both stores failed — key is gone.
                Ok(None)
            }
        }
    }

    fn erase_key(&mut self, key_id: KeyId) -> Result<(), HsmError> {
        // Erase from primary — failure is fatal.
        if let Err(e) = self.primary.erase_key(key_id) {
            self.flash_error = true;
            return Err(e);
        }

        // Erase from secondary — failure is non-fatal.
        if let Err(_e) = self.secondary.erase_key(key_id) {
            #[cfg(target_arch = "arm")]
            defmt::warn!(
                "HybridKeyStore: secondary erase failed for key 0x{:08x}",
                key_id.0
            );
            self.degraded = true;
        }

        crate::cdc_log!("HYBRID erase key=0x{:08x} ok", key_id.0);
        Ok(())
    }

    fn wipe_all(&mut self) -> Result<(), HsmError> {
        crate::cdc_log!("HYBRID wipe_all start");
        // Wipe primary — failure is fatal.
        if let Err(e) = self.primary.wipe_all() {
            self.flash_error = true;
            return Err(e);
        }
        // Primary wipe succeeded — primary flash is healthy.
        self.flash_error = false;

        // Wipe secondary — failure is non-fatal.
        if let Err(_e) = self.secondary.wipe_all() {
            #[cfg(target_arch = "arm")]
            defmt::warn!("HybridKeyStore: secondary wipe_all failed — marking degraded");
            self.degraded = true;
        }

        crate::cdc_log!("HYBRID wipe_all done");
        Ok(())
    }

    fn wipe_by_owner(&mut self, owner: AppletId) -> Result<(), HsmError> {
        // Wipe primary — failure is fatal.
        if let Err(e) = self.primary.wipe_by_owner(owner) {
            self.flash_error = true;
            return Err(e);
        }
        // Primary wipe succeeded — primary flash is healthy.
        self.flash_error = false;

        // Wipe secondary — failure is non-fatal.
        if let Err(_e) = self.secondary.wipe_by_owner(owner) {
            #[cfg(target_arch = "arm")]
            defmt::warn!("HybridKeyStore: secondary wipe_by_owner failed — marking degraded");
            self.degraded = true;
        }

        Ok(())
    }

    fn enumerate_keys(&self) -> Vec<KeyId, 64> {
        // Primary is authoritative.
        self.primary.enumerate_keys()
    }

    fn for_each_key(&self, f: &mut dyn FnMut(KeyId)) {
        // Primary is authoritative.
        self.primary.for_each_key(f);
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
        AlgorithmId::AesEcb | AlgorithmId::AesCbc | AlgorithmId::AesCtr | AlgorithmId::AesGcm => {
            CoreKeyType::Aes256
        }
        // Curve25519
        AlgorithmId::Ed25519 => CoreKeyType::Ed25519,
        AlgorithmId::X25519 => CoreKeyType::X25519,
    }
}
