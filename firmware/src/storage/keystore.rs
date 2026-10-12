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
    error::{HsmError, StorageError},
    key::{AppletId, KeyId},
};

use crate::security::key_management::KeyObject;
use crate::storage::retry_counter::{CounterState, Credential, RetryCounterBackend};

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
use pico2hsm_core::{error::CryptoError, key::KeyType as CoreKeyType};
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

    /// The credential retry-counter store (see `storage::retry_counter`),
    /// or `None` if this store has none.  Without one every credential
    /// check fails closed (6581) and credentials load blocked.
    fn retry_counters(&mut self) -> Option<&mut dyn RetryCounterBackend> {
        None
    }

    /// The RSA key pool region (see `storage::rsa_pool`), or `None` if this
    /// store has none: GENERATE then always generates live.
    #[cfg(feature = "rsa")]
    fn rsa_pool(&mut self) -> Option<&mut dyn crate::storage::rsa_pool::PoolBackend> {
        None
    }
}

// ─── FlashKeyStore<Chip> ──────────────────────────────────────────────────────

/// Concrete key store backed by a `StorageManager<Chip>` and protected by the
/// Storage Master Key (`smk`).
///
/// With no storage key (unprovisioned release build) every save and fetch
/// fails with `StorageError::NoStorageKey` instead of using a public key.
#[cfg(target_arch = "arm")]
pub struct FlashKeyStore<Chip: FlashChip> {
    storage: StorageManager<Chip>,
    smk: Option<Zeroizing<[u8; 32]>>,
    /// Retry-counter log on internal flash (every board, SD ones included).
    counters: Option<crate::storage::BoardCounterLog>,
    /// RSA key pool region on internal flash (every board).
    #[cfg(feature = "rsa")]
    pool: Option<crate::storage::BoardPoolRegion>,
}

#[cfg(target_arch = "arm")]
impl<Chip: FlashChip> FlashKeyStore<Chip> {
    /// Construct a new `FlashKeyStore`.
    ///
    /// `storage` should already have chips added via `KeyFilesystem::add_chip`.
    /// Call [`init`] before any key operations.
    pub fn new(storage: StorageManager<Chip>, smk: Option<Zeroizing<[u8; 32]>>) -> Self {
        FlashKeyStore {
            storage,
            smk,
            counters: None,
            #[cfg(feature = "rsa")]
            pool: None,
        }
    }

    /// Attach the retry-counter log (before the first key load).
    pub fn attach_retry_counters(&mut self, log: crate::storage::BoardCounterLog) {
        self.counters = Some(log);
    }

    /// Attach the RSA key pool region (boot, core0).
    #[cfg(feature = "rsa")]
    pub fn attach_rsa_pool(&mut self, region: crate::storage::BoardPoolRegion) {
        self.pool = Some(region);
    }

    /// The pool region and the storage key, or why there is none.
    #[cfg(feature = "rsa")]
    fn pool_and_key(
        &mut self,
    ) -> Result<(&mut crate::storage::BoardPoolRegion, &[u8; 32]), HsmError> {
        let smk = self
            .smk
            .as_deref()
            .ok_or(HsmError::Storage(StorageError::NoStorageKey))?;
        let pool = self
            .pool
            .as_mut()
            .ok_or(HsmError::Storage(StorageError::NotFormatted))?;
        Ok((pool, smk))
    }

    /// One bounded step of `wipe_by_owner`: erase at most `max` of the
    /// owner's objects; `Ok(true)` if more remain.
    pub fn wipe_by_owner_step(&mut self, owner: AppletId, max: usize) -> Result<bool, HsmError> {
        self.storage
            .delete_where_step(&|k: KeyId| ((k.0 >> 16) & 0xFF) as u8 == owner as u8, max)
            .map_err(HsmError::Storage)
    }

    fn smk(&self) -> Result<&[u8; 32], HsmError> {
        self.smk
            .as_deref()
            .ok_or(HsmError::Storage(StorageError::NoStorageKey))
    }

    /// Initialise: scan chips, load directory, run WAL recovery.
    pub fn init(&mut self) -> Result<(), StorageError> {
        self.storage.init()
    }
}

#[cfg(target_arch = "arm")]
impl<Chip: FlashChip> KeyStore for FlashKeyStore<Chip> {
    fn save_key(&mut self, obj: &KeyObject) -> Result<(), HsmError> {
        self.smk()?;
        // --- 0. The stored copy carries the next generation number. ---
        // --- 1. Generate a fresh 12-byte nonce from the hardware TRNG. ---
        let mut nonce = [0u8; 12];
        crate::crypto::rng::fill_random(&mut nonce).map_err(HsmError::Crypto)?;

        // --- 2. Encrypt the key object (with bumped generation). ---
        let blob = obj
            .encrypt_with_generation(self.smk()?, &nonce, obj.generation.saturating_add(1))
            .map_err(|_| HsmError::Crypto(CryptoError::EncryptFailure))?;

        // --- 3. Compute BLAKE2s-256 of the plaintext for integrity. ---
        // The plaintext that is hashed is the raw private key material.
        // This lets the storage layer verify integrity after decryption
        // without re-deriving the KEK.
        let hash = compute_plaintext_blake2s(&obj.private_key);

        // --- 4. Map AlgorithmId -> core KeyType. ---
        let core_key_type = algo_to_core_key_type(obj.algorithm);

        // --- 5. Write to flash. ---
        let result = self
            .storage
            .write_key(KeyId(obj.key_id), core_key_type, &blob, &hash)
            .map_err(HsmError::Storage);
        if result.is_ok() {
            crate::cdc_log!("FLASH save key=0x{:08x} ok", obj.key_id);
        }
        result
    }

    fn fetch_key(&mut self, key_id: KeyId) -> Result<Option<KeyObject>, HsmError> {
        // Check whether the key exists in the directory first so we can
        // return Ok(None) cleanly instead of propagating a ReadError.
        if !self.storage.key_exists(key_id) {
            return Ok(None);
        }
        self.smk()?;
        // Each load is a read + AES-GCM decrypt (tens of ms in debug
        // builds); a full keystore load at boot / reload must keep the
        // hardware watchdog fed (core0) or the heartbeat moving (core1).
        crate::watchdog::progress();

        let blob = self.storage.read_key(key_id).map_err(HsmError::Storage)?;

        // Pass the u32 key_id to decrypt — decrypt uses the low byte for KEK derivation.
        let obj = KeyObject::decrypt(&blob, key_id.0, self.smk()?)
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
        self.storage
            .delete_where(&|k: KeyId| ((k.0 >> 16) & 0xFF) as u8 == owner as u8)
            .map_err(HsmError::Storage)
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

    fn retry_counters(&mut self) -> Option<&mut dyn RetryCounterBackend> {
        self.counters
            .as_mut()
            .map(|c| c as &mut dyn RetryCounterBackend)
    }

    #[cfg(feature = "rsa")]
    fn rsa_pool(&mut self) -> Option<&mut dyn crate::storage::rsa_pool::PoolBackend> {
        // Without a storage key the pool could not encrypt: no pool.
        if self.pool.is_none() || self.smk.is_none() {
            return None;
        }
        Some(self)
    }
}

/// The pool on internal flash, encrypted under the storage key.  Writes,
/// takes and erases program internal flash, so they must run on core0
/// (core1 reaches them through `FlashOp`s); reads are XIP and work on
/// either core.
#[cfg(all(target_arch = "arm", feature = "rsa"))]
impl<Chip: FlashChip> crate::storage::rsa_pool::PoolBackend for FlashKeyStore<Chip> {
    fn pool_slots(
        &mut self,
    ) -> Result<
        [crate::storage::rsa_pool::SlotState; crate::storage::rsa_pool::POOL_SLOTS],
        StorageError,
    > {
        match self.pool.as_ref() {
            Some(p) => p.slots(),
            None => Err(StorageError::NotFormatted),
        }
    }

    fn pool_put(
        &mut self,
        slot: u8,
        class: crate::storage::rsa_pool::SizeClass,
        birth: u32,
        seq: u32,
        obj: &KeyObject,
    ) -> Result<(), HsmError> {
        let mut nonce = [0u8; 12];
        crate::crypto::rng::fill_random(&mut nonce).map_err(HsmError::Crypto)?;
        let (pool, smk) = self.pool_and_key()?;
        pool.put_key(smk, &nonce, slot, class, birth, seq, obj)
    }

    fn pool_get(&mut self, slot: u8) -> Result<KeyObject, HsmError> {
        let (pool, smk) = self.pool_and_key()?;
        pool.get_key(smk, slot)
    }

    fn pool_take(&mut self, slot: u8) -> Result<(), HsmError> {
        let (pool, _) = self.pool_and_key()?;
        pool.take(slot).map_err(HsmError::Storage)
    }

    fn pool_erase(&mut self, slot: u8) -> Result<(), HsmError> {
        let (pool, _) = self.pool_and_key()?;
        pool.erase(slot).map_err(HsmError::Storage)
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

    fn retry_counters(&mut self) -> Option<&mut dyn RetryCounterBackend> {
        Some(self)
    }
}

/// The null store keeps no counters either: reads find no entry, writes
/// succeed without effect.
impl RetryCounterBackend for NullKeyStore {
    fn get(&mut self, _: Credential) -> Result<Option<CounterState>, StorageError> {
        Ok(None)
    }
    fn put(&mut self, _: Credential, _: CounterState) -> Result<(), StorageError> {
        Ok(())
    }
    fn needs_migration(&mut self) -> bool {
        false
    }
    fn format(&mut self, _: &[(Credential, CounterState)]) -> Result<(), StorageError> {
        Ok(())
    }
    fn lamport(&mut self) -> Result<u64, StorageError> {
        Ok(0)
    }
    fn put_lamport(&mut self, _: u64) -> Result<(), StorageError> {
        Ok(())
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
            Err(HsmError::Storage(StorageError::WriteError))
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

    fn retry_counters(&mut self) -> Option<&mut dyn RetryCounterBackend> {
        // The counters are never mirrored to a removable card.
        self.primary.retry_counters()
    }

    #[cfg(feature = "rsa")]
    fn rsa_pool(&mut self) -> Option<&mut dyn crate::storage::rsa_pool::PoolBackend> {
        // Internal flash only, like the counters.
        self.primary.rsa_pool()
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
