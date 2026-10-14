//! Key store abstraction — encrypted persist/load/erase for `KeyObject`.
//!
//! # Roles
//! - [`KeyStore`] trait — the interface command handlers use. Implementations
//!   handle encryption and decryption internally; no raw SMK is ever visible to
//!   command handlers.
//! - [`FlashKeyStoreV2`](super::keystore_v2::FlashKeyStoreV2) — the device
//!   store (Storage V2).
//! - [`NullKeyStore`] — no-op implementation for host-side (x86_64) unit tests.
//!

use heapless::Vec;
use pico2hsm_core::{
    error::{HsmError, StorageError},
    key::{AppletId, KeyId},
};

use crate::security::key_management::KeyObject;
use crate::storage::retry_counter::{CounterState, Credential, RetryCounterBackend};

// ─── SO-PIN and recovery types ────────────────────────────────────────────────

/// The SC-HSM SO-PIN as stored: its salt and PBKDF2 hash.
#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SoPin {
    pub salt: [u8; 16],
    pub hash: [u8; 32],
}

impl core::fmt::Debug for SoPin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SoPin(..)")
    }
}

/// Where a store keeps the SC-HSM SO-PIN (see [`KeyStore::so_pin_home`]).
#[derive(Debug, PartialEq, Eq)]
pub enum SoPinHome {
    /// In the SC-HSM PIN record.
    Record,
    /// In the binding block: the SO-PIN, or `None` if none is set (or the
    /// store has no valid binding).
    Binding(Option<SoPin>),
}

/// The store's state as STORE STATUS reports it (STORAGE_V2 §9.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreReport {
    /// [`StoreState`] as a byte.
    pub state: StoreState,
    /// Why a refused store was refused (`Refusal` code, 0 otherwise).
    pub reason: u8,
    /// Journal records the anchor counts that the store does not hold
    /// (refused or degraded); what ACCEPT STORE would give up.
    pub lost: u64,
    /// The mounted state's newest journal seq (0 when not mounted).
    pub head: u64,
}

/// Coarse store state (STORE STATUS byte).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreState {
    /// Mounted read-write.
    Up = 0,
    /// Mounted read-only by OPEN DEGRADED.
    Degraded = 1,
    /// Refused next to a valid binding: OPEN DEGRADED, ACCEPT STORE or
    /// FORMAT STORE.
    Refused = 2,
    /// No 2.0 store (a 1.x keystore, a card formatted elsewhere) or a
    /// binding that does not verify: FORMAT STORE only.
    NeedsFormat = 3,
    /// No storage key, or not initialised.
    Down = 4,
}

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

    /// FORMAT STORE (STORAGE_V2 §8.3): replace the store with a new, empty
    /// one — every key of every applet is gone.  `so_pin_verified`: the
    /// SC-HSM SO-PIN was verified this session; without it the store only
    /// formats if it is not up (refused, no verifiable binding, R9).
    fn format_store(&mut self, so_pin_verified: bool) -> Result<(), HsmError> {
        let _ = so_pin_verified;
        Err(HsmError::Storage(StorageError::WriteError))
    }

    /// Where the SC-HSM SO-PIN lives (STORAGE_V2 §8.1).  Stores with a
    /// binding block keep it there, so it works while the store itself is
    /// refused (recovery needs it); stores without one keep it in the
    /// SC-HSM PIN record.
    fn so_pin_home(&self) -> SoPinHome {
        SoPinHome::Record
    }

    /// Replace the SO-PIN in the binding (`None`: none set).  Only for
    /// stores whose [`Self::so_pin_home`] is the binding.
    fn set_binding_so_pin(&mut self, so: Option<&SoPin>) -> Result<(), HsmError> {
        let _ = so;
        Err(HsmError::Storage(StorageError::WriteError))
    }

    /// SC-HSM INITIALIZE's wipe: SC-HSM's keys and domain records go, and
    /// the new SO-PIN goes into the same binding write as SC-HSM's new
    /// epoch, so the old keys never stand next to the new SO-PIN (R10).  A
    /// cut leaves the old keys and SO-PIN, or no keys and either SO-PIN
    /// (before the binding write, the next mount finishes the rotation
    /// with the old one); re-INITIALIZE with that SO-PIN recovers.  Stores
    /// without a binding: only the wipe.
    fn reset_sc_hsm(&mut self, so: &SoPin) -> Result<(), HsmError> {
        let _ = so;
        self.wipe_by_owner(AppletId::ScHsm)
    }

    /// Where the store stands, for STORE STATUS and the recovery commands
    /// (STORAGE_V2 §9.3).  `None`: this store has no such state.
    fn store_report(&self) -> Option<StoreReport> {
        None
    }

    /// OPEN DEGRADED (§9.3): mount a refused store read-only, as far as it
    /// verifies.  Needs the SO-PIN.
    fn open_degraded(&mut self, so_pin_verified: bool) -> Result<(), HsmError> {
        let _ = so_pin_verified;
        Err(HsmError::Storage(StorageError::WriteError))
    }

    /// ACCEPT STORE (§16 OD-1, R2): make the state OPEN DEGRADED mounted
    /// the store's new, read-write state.  `lost` must be the number of
    /// records STORE STATUS reported missing.  Needs the SO-PIN.
    fn accept_store(&mut self, so_pin_verified: bool, lost: u64) -> Result<(), HsmError> {
        let _ = (so_pin_verified, lost);
        Err(HsmError::Storage(StorageError::WriteError))
    }

    /// The RSA key pool region (see `storage::rsa_pool`), or `None` if this
    /// store has none: GENERATE then always generates live.
    #[cfg(feature = "rsa")]
    fn rsa_pool(&mut self) -> Option<&mut dyn crate::storage::rsa_pool::PoolBackend> {
        None
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
