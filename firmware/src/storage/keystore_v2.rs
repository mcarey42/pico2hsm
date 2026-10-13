//! The Storage V2 key store: [`KeyStore`] over the V2 engine
//! ([`store_v2`](super::store_v2)), the binding block and the counter-log
//! anchor (docs/STORAGE_V2.md §4–§9).
//!
//! Objects are [`KeyObject`] blobs sealed under
//! `K_obj = HKDF(SMK, store_id, E_group, key_id)` with the V2 object header
//! (store, key ID, seq, metadata) as AAD prefix and a fresh TRNG nonce.
//!
//! # Cores
//! The binding block and the counter log are on internal flash, which only
//! core0 can write.  On QMI boards every write runs on core0 already
//! (`FlashOp`).  On SD-card boards key writes run on core1: their anchor
//! update goes to core0 through the [`Hooks::put_anchor`] hook, and the
//! operations that write the binding (group wipes, formats) are sent to
//! core0 whole.

use heapless::Vec;
use pico2hsm_core::error::{CryptoError, HsmError, StorageError};
use pico2hsm_core::key::{AppletId, KeyId};
use zeroize::Zeroizing;

use super::binding::{derive_k_bind, BindState, Binding, BindingRing, Scan};
use super::retry_counter::{Anchor, CounterFlash, RetryCounterBackend};
use super::store_v2::{
    derive_k_idx, derive_k_obj, group_of, object_header, Env, Fetched, FormatAuth, Meta, MountInfo,
    Refusal, Store, StoreFlash, MAX_OBJECT_BLOB,
};
use super::KeyStore;
use crate::security::key_management::{KeyObject, MAX_BLOB_SIZE};

/// Where the store stands (shown on the display; FORMAT STORE decides on
/// it, R9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreStatus {
    /// Not initialised yet.
    Down,
    /// Mounted read-write.
    Up,
    /// Mounted read-only (OPEN DEGRADED).
    Degraded,
    /// Refused: why (§9).
    Refused(Refusal),
    /// The binding block exists but does not verify (another SMK, e.g. after
    /// OTP provisioning; damage).
    BindingUnverifiable,
    /// No binding block next to a non-blank region (a 1.x keystore, a card
    /// formatted elsewhere): only FORMAT STORE goes on.
    NeedsFormat,
    /// No storage key (unprovisioned release build).
    NoKey,
}

/// Internal-flash writes core1 cannot do itself.
#[derive(Clone, Copy)]
pub struct Hooks {
    /// Write the anchor from core1 (a `FlashOp` round trip to core0).
    pub put_anchor: fn(Anchor) -> Result<(), StorageError>,
}

/// Whether this runs on core1.
fn on_core1() -> bool {
    #[cfg(target_arch = "arm")]
    {
        embassy_rp::pac::SIO.cpuid().read() == 1
    }
    #[cfg(not(target_arch = "arm"))]
    {
        false
    }
}

/// The V2 key store.
pub struct FlashKeyStoreV2<F: StoreFlash, B: CounterFlash, L: RetryCounterBackend> {
    store: Store<F>,
    smk: Option<Zeroizing<[u8; 32]>>,
    binding_ring: Option<BindingRing<B>>,
    binding: Option<Binding>,
    counters: Option<L>,
    hooks: Option<Hooks>,
    status: StoreStatus,
    #[cfg(all(target_arch = "arm", feature = "rsa"))]
    pool: Option<crate::storage::BoardPoolRegion>,
}

/// The anchor through the counter log, or core0 when on core1.
struct AnchorEnv<'a, L: RetryCounterBackend> {
    log: Option<&'a mut L>,
    hooks: Option<Hooks>,
}

impl<L: RetryCounterBackend> Env for AnchorEnv<'_, L> {
    fn anchor(&mut self) -> Result<Option<Anchor>, StorageError> {
        match self.log.as_mut() {
            Some(l) => l.anchor(),
            None => Err(StorageError::NotFormatted),
        }
    }
    fn put_anchor(&mut self, a: Anchor) -> Result<(), StorageError> {
        if on_core1() {
            if let Some(h) = self.hooks {
                return (h.put_anchor)(a);
            }
        }
        match self.log.as_mut() {
            Some(l) => l.put_anchor(a),
            None => Err(StorageError::NotFormatted),
        }
    }
}

fn fill_random(b: &mut [u8]) -> Result<(), StorageError> {
    #[cfg(target_arch = "arm")]
    {
        crate::crypto::rng::fill_random(b).map_err(|_| StorageError::WriteError)
    }
    #[cfg(not(target_arch = "arm"))]
    {
        // No TRNG on the host: fail closed (nothing is written).
        let _ = b;
        Err(StorageError::WriteError)
    }
}

fn random<const N: usize>() -> Result<[u8; N], StorageError> {
    let mut b = [0u8; N];
    fill_random(&mut b)?;
    Ok(b)
}

impl<F: StoreFlash, B: CounterFlash, L: RetryCounterBackend> FlashKeyStoreV2<F, B, L> {
    /// A store over `flash`; [`Self::init`] mounts it.
    pub fn new(flash: F, smk: Option<Zeroizing<[u8; 32]>>) -> Self {
        FlashKeyStoreV2 {
            store: Store::new(flash),
            smk,
            binding_ring: None,
            binding: None,
            counters: None,
            hooks: None,
            status: StoreStatus::Down,
            #[cfg(all(target_arch = "arm", feature = "rsa"))]
            pool: None,
        }
    }

    /// Attach the counter log (before [`Self::init`]).
    pub fn attach_retry_counters(&mut self, log: L) {
        self.counters = Some(log);
    }

    /// Attach the binding ring region (before [`Self::init`]).
    pub fn attach_binding(&mut self, flash: B, sectors: u32) -> Result<(), StorageError> {
        let Some(smk) = self.smk.as_deref() else {
            return Err(StorageError::NoStorageKey);
        };
        let k_bind = derive_k_bind(smk);
        let (ring, scan) = BindingRing::open(flash, sectors, &k_bind)?;
        self.binding_ring = Some(ring);
        match scan {
            Scan::Blank => self.binding = None,
            Scan::Unverifiable => {
                self.binding = None;
                self.status = StoreStatus::BindingUnverifiable;
            }
            Scan::Valid(b) => self.binding = Some(b),
        }
        Ok(())
    }

    /// Hooks for core1 (SD-card boards).
    pub fn set_hooks(&mut self, hooks: Hooks) {
        self.hooks = Some(hooks);
    }

    /// Attach the RSA key pool region (boot, core0).
    #[cfg(all(target_arch = "arm", feature = "rsa"))]
    pub fn attach_rsa_pool(&mut self, region: crate::storage::BoardPoolRegion) {
        self.pool = Some(region);
    }

    /// Where the store stands.
    pub fn status(&self) -> StoreStatus {
        self.status
    }

    /// The counter log (core0 runs `FlashOp::PutAnchor` on it).
    pub fn counter_log(&mut self) -> Option<&mut L> {
        self.counters.as_mut()
    }

    fn smk(&self) -> Result<&[u8; 32], HsmError> {
        self.smk
            .as_deref()
            .ok_or(HsmError::Storage(StorageError::NoStorageKey))
    }

    fn mount_info(&self, b: &Binding) -> Result<MountInfo, StorageError> {
        let smk = self.smk.as_deref().ok_or(StorageError::NoStorageKey)?;
        Ok(MountInfo {
            store_id: b.store_id,
            format_gen: b.format_gen,
            k_idx: derive_k_idx(smk, &b.store_id, &b.e_store),
            group_gen: b.group_gen,
        })
    }

    fn write_binding(&mut self, b: &mut Binding) -> Result<(), StorageError> {
        let smk = self.smk.as_deref().ok_or(StorageError::NoStorageKey)?;
        let k_bind = derive_k_bind(smk);
        let ring = self
            .binding_ring
            .as_mut()
            .ok_or(StorageError::NotFormatted)?;
        ring.write(b, &k_bind)
    }

    /// Boot (core0, before the first key load): mount, finishing an
    /// interrupted format or epoch rotation; format a first-boot device
    /// (no binding, blank journal ring).  Anything else is refused and
    /// nothing is written (§8.3).
    pub fn init(&mut self) -> Result<(), StorageError> {
        if self.smk.is_none() {
            self.status = StoreStatus::NoKey;
            return Err(StorageError::NoStorageKey);
        }
        if self.status == StoreStatus::BindingUnverifiable {
            return Err(StorageError::IntegrityFailure);
        }
        let r = match self.binding.as_ref().map(|b| b.state) {
            None => {
                if self.store.is_blank()? {
                    // First boot; the engine also checks there is no anchor.
                    self.format_new(None, FormatAuth::first_boot())
                } else {
                    self.status = StoreStatus::NeedsFormat;
                    Err(StorageError::NotFormatted)
                }
            }
            Some(BindState::Formatting) => self.finish_format(FormatAuth::resume_formatting(true)),
            Some(BindState::Active) => self.mount(),
            Some(BindState::Reindexing) => {
                // ACCEPT STORE is not implemented yet: fail closed.
                self.status = StoreStatus::Refused(Refusal::Corrupt("re-index pending"));
                Err(StorageError::IntegrityFailure)
            }
        };
        if let Some(ring) = self.binding_ring.as_mut() {
            let _ = ring.tidy();
        }
        r
    }

    fn mount(&mut self) -> Result<(), StorageError> {
        for _ in 0..4 {
            let b = self.binding.as_ref().ok_or(StorageError::NotFormatted)?;
            let info = self.mount_info(b)?;
            let mut env = AnchorEnv {
                log: self.counters.as_mut(),
                hooks: None,
            };
            match self.store.mount(info, &mut env) {
                Ok(()) => {
                    self.status = StoreStatus::Up;
                    return Ok(());
                }
                Err(Refusal::PendingRotation { group, gen }) => {
                    // A cut between a WIPE_OWNER and its binding write:
                    // finish the rotation, then mount again (§6, R7).
                    let mut nb = self.binding.clone().ok_or(StorageError::NotFormatted)?;
                    nb.e_group[group as usize] = random()?;
                    nb.group_gen[group as usize] = gen;
                    self.write_binding(&mut nb)?;
                    self.binding = Some(nb);
                }
                Err(e) => {
                    self.status = StoreStatus::Refused(e);
                    return Err(StorageError::IntegrityFailure);
                }
            }
        }
        Err(StorageError::IntegrityFailure)
    }

    /// A new store: new identity and epochs (§8.3), binding FORMATTING,
    /// the journal, the anchor, binding ACTIVE, mount.  `so_verifier`
    /// carries an existing SO-PIN verifier forward (R9).
    fn format_new(
        &mut self,
        carry: Option<&Binding>,
        auth: FormatAuth,
    ) -> Result<(), StorageError> {
        let mut b = Binding {
            state: BindState::Formatting,
            store_id: random()?,
            format_gen: carry
                .or(self.binding.as_ref())
                .map_or(1, |o| o.format_gen.wrapping_add(1).max(1)),
            e_store: random()?,
            e_group: [random()?, random()?, random()?],
            group_gen: [0; 3],
            ..Binding::default()
        };
        if let Some(o) = carry {
            b.so_salt = o.so_salt;
            b.so_verifier = o.so_verifier;
        }
        // A first boot must still pass the engine's check (no anchor, blank
        // ring) before anything is written.
        if matches!(auth_kind(&auth), AuthKind::FirstBoot) {
            let mut env = AnchorEnv {
                log: self.counters.as_mut(),
                hooks: None,
            };
            if env.anchor()?.is_some() {
                self.status = StoreStatus::NeedsFormat;
                return Err(StorageError::IntegrityFailure);
            }
        }
        // Step 1: the old binding (and with it the old epochs) is replaced.
        self.write_binding(&mut b)?;
        self.binding = Some(b);
        self.finish_format(Some(auth))
    }

    /// Steps 2–4 of a format (§8.3), resumable from a FORMATTING binding.
    fn finish_format(&mut self, auth: Option<FormatAuth>) -> Result<(), StorageError> {
        let auth = auth.ok_or(StorageError::IntegrityFailure)?;
        let b = self.binding.as_ref().ok_or(StorageError::NotFormatted)?;
        if b.state != BindState::Formatting {
            return Err(StorageError::IntegrityFailure);
        }
        let info = self.mount_info(b)?;
        // The binding is now FORMATTING with a new store_id: the engine's
        // first-boot check would see the anchor of the previous store (if
        // any) — resuming a recorded format is what this is.
        let auth = match auth_kind(&auth) {
            AuthKind::FirstBoot => {
                FormatAuth::resume_formatting(true).ok_or(StorageError::IntegrityFailure)?
            }
            _ => auth,
        };
        {
            let mut env = AnchorEnv {
                log: self.counters.as_mut(),
                hooks: None,
            };
            self.store.format(info, &mut env, auth)?;
        }
        let mut nb = self.binding.clone().ok_or(StorageError::NotFormatted)?;
        nb.state = BindState::Active;
        self.write_binding(&mut nb)?;
        self.binding = Some(nb);
        self.mount()
    }

    /// FORMAT STORE (§8.3, R9): a new, empty store; every key of every
    /// applet is gone.  The caller has checked the SO-PIN, or that the
    /// store is refused or has no verifiable binding.  Core0 only.
    pub fn format_store_now(&mut self, so_pin_verified: bool) -> Result<(), HsmError> {
        self.smk()?;
        let auth = FormatAuth::format_store(so_pin_verified || self.format_needs_no_pin())
            .ok_or(HsmError::Storage(StorageError::IntegrityFailure))?;
        let carry = self.binding.clone();
        self.store.unmount();
        self.status = StoreStatus::Down;
        self.format_new(carry.as_ref(), auth)
            .map_err(HsmError::Storage)
    }

    /// Whether a PIN-less FORMAT STORE is allowed (R9): only when there is
    /// no valid binding — a 1.x keystore or a store formatted elsewhere
    /// (`NeedsFormat`), or a binding that does not verify under this SMK.
    /// A store that is merely refused next to a valid binding (a missing
    /// or rolled-back card, damage) keeps its binding: formatting it would
    /// destroy the epochs the real card needs, so it takes the SO-PIN.
    /// (Until the SO-PIN verifier moves into the binding, phase 4, such a
    /// store fails closed.)
    pub fn format_needs_no_pin(&self) -> bool {
        matches!(self.status, StoreStatus::NeedsFormat | StoreStatus::BindingUnverifiable)
            && self.binding.is_none()
    }

    /// Wipe one group: one record, the binding with its new epoch, the
    /// group's sectors.  Core0 only (writes the binding).
    fn wipe_group(&mut self, group: usize) -> Result<(), HsmError> {
        let mut nb = self
            .binding
            .clone()
            .ok_or(HsmError::Storage(StorageError::NotFormatted))?;
        let smk = self.smk()?;
        let k_bind = derive_k_bind(smk);
        let ring = self
            .binding_ring
            .as_mut()
            .ok_or(HsmError::Storage(StorageError::NotFormatted))?;
        let mut env = AnchorEnv {
            log: self.counters.as_mut(),
            hooks: self.hooks,
        };
        let mut rotated = false;
        let r = self.store.wipe_group(&mut env, group, &mut |gen| {
            nb.e_group[group] = random()?;
            nb.group_gen[group] = gen;
            ring.write(&mut nb, &k_bind)?;
            rotated = true;
            Ok(())
        });
        if rotated {
            self.binding = Some(nb);
        }
        r.map_err(HsmError::Storage)
    }

    /// One step of `wipe_by_owner` (kept for the core0 `FlashOp`s): the
    /// whole wipe is one step.  `Ok(false)`: nothing more to do.
    pub fn wipe_by_owner_step(&mut self, owner: AppletId, _max: usize) -> Result<bool, HsmError> {
        KeyStore::wipe_by_owner(self, owner)?;
        Ok(false)
    }

    /// Live objects and free data sectors (display).
    pub fn key_count(&self) -> usize {
        self.store.len()
    }
}

enum AuthKind {
    FirstBoot,
    Other,
}

/// What kind of format authorisation this is (first boot needs the extra
/// no-anchor check before the binding is written).
fn auth_kind(a: &FormatAuth) -> AuthKind {
    if a.is_first_boot() {
        AuthKind::FirstBoot
    } else {
        AuthKind::Other
    }
}

fn applet_group(owner: AppletId) -> usize {
    match owner {
        AppletId::Piv => 1,
        AppletId::OpenPgp => 2,
        _ => 0,
    }
}

impl<F: StoreFlash, B: CounterFlash, L: RetryCounterBackend> KeyStore for FlashKeyStoreV2<F, B, L> {
    fn save_key(&mut self, obj: &KeyObject) -> Result<(), HsmError> {
        let smk = self.smk()?;
        let b = self
            .binding
            .as_ref()
            .ok_or(HsmError::Storage(StorageError::NotFormatted))?;
        let sid = b.store_id;
        let k_obj = derive_k_obj(smk, &sid, &b.e_group[group_of(obj.key_id)], obj.key_id);
        let meta = Meta {
            key_type: obj.key_type as u8,
            algo: obj.algorithm as u8,
            flags: obj.key_flags,
        };
        let mut env = AnchorEnv {
            log: self.counters.as_mut(),
            hooks: self.hooks,
        };
        let key_id = obj.key_id;
        let mut seal = |seq: u64, out: &mut [u8]| -> Result<usize, StorageError> {
            let mut nonce = [0u8; 12];
            fill_random(&mut nonce)?;
            let aad = object_header(&sid, key_id, seq, meta, 0);
            let blob = obj
                .seal(&k_obj, &aad, &nonce, obj.generation.saturating_add(1))
                .map_err(|_| StorageError::WriteError)?;
            if blob.len() > out.len() {
                return Err(StorageError::WriteError);
            }
            out[..blob.len()].copy_from_slice(&blob);
            Ok(blob.len())
        };
        let r = self.store.put(&mut env, key_id, meta, &mut seal);
        if r.is_ok() {
            crate::cdc_log!("FLASH save key=0x{:08x} ok", key_id);
        }
        r.map_err(HsmError::Storage)
    }

    fn fetch_key(&mut self, key_id: KeyId) -> Result<Option<KeyObject>, HsmError> {
        let smk = self.smk()?;
        let b = self
            .binding
            .as_ref()
            .ok_or(HsmError::Storage(StorageError::NotFormatted))?;
        crate::watchdog::progress();
        let mut blob: Vec<u8, MAX_BLOB_SIZE> = Vec::new();
        let _ = blob.resize(MAX_BLOB_SIZE.min(MAX_OBJECT_BLOB), 0);
        let (meta, seq, len) = match self
            .store
            .fetch_into(key_id.0, &mut blob)
            .map_err(HsmError::Storage)?
        {
            Fetched::Missing => return Ok(None),
            Fetched::Found { meta, seq, len } => (meta, seq, len),
        };
        let k_obj = derive_k_obj(smk, &b.store_id, &b.e_group[group_of(key_id.0)], key_id.0);
        let aad = object_header(&b.store_id, key_id.0, seq, meta, 0);
        let obj = KeyObject::open(&blob[..len], key_id.0, &k_obj, &aad);
        zeroize::Zeroize::zeroize(&mut blob[..]);
        obj.map(Some)
            .map_err(|_| HsmError::Crypto(CryptoError::DecryptFailure))
    }

    fn erase_key(&mut self, key_id: KeyId) -> Result<(), HsmError> {
        let mut env = AnchorEnv {
            log: self.counters.as_mut(),
            hooks: self.hooks,
        };
        let r = self
            .store
            .delete(&mut env, key_id.0)
            .map_err(HsmError::Storage);
        if r.is_ok() {
            crate::cdc_log!("FLASH erase key=0x{:08x} ok", key_id.0);
        }
        r
    }

    fn wipe_all(&mut self) -> Result<(), HsmError> {
        for g in 0..3 {
            self.wipe_group(g)?;
        }
        Ok(())
    }

    fn wipe_by_owner(&mut self, owner: AppletId) -> Result<(), HsmError> {
        self.wipe_group(applet_group(owner))
    }

    fn enumerate_keys(&self) -> Vec<KeyId, 64> {
        let mut out = Vec::new();
        let _ = self.store.for_each(&mut |e| {
            let _ = out.push(KeyId(e.key_id));
        });
        out
    }

    fn for_each_key(&self, f: &mut dyn FnMut(KeyId)) {
        let _ = self.store.for_each(&mut |e| f(KeyId(e.key_id)));
    }

    fn retry_counters(&mut self) -> Option<&mut dyn RetryCounterBackend> {
        self.counters
            .as_mut()
            .map(|c| c as &mut dyn RetryCounterBackend)
    }

    fn format_store(&mut self, so_pin_verified: bool) -> Result<(), HsmError> {
        self.format_store_now(so_pin_verified)
    }

    #[cfg(feature = "rsa")]
    fn rsa_pool(&mut self) -> Option<&mut dyn crate::storage::rsa_pool::PoolBackend> {
        #[cfg(target_arch = "arm")]
        {
            if self.pool.is_none() || self.smk.is_none() {
                return None;
            }
            Some(self)
        }
        #[cfg(not(target_arch = "arm"))]
        {
            None
        }
    }
}

/// The pool on internal flash, as for the 1.x store.
#[cfg(all(target_arch = "arm", feature = "rsa"))]
impl<F: StoreFlash, B: CounterFlash, L: RetryCounterBackend> crate::storage::rsa_pool::PoolBackend
    for FlashKeyStoreV2<F, B, L>
{
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
        let smk = self
            .smk
            .as_deref()
            .ok_or(HsmError::Storage(StorageError::NoStorageKey))?;
        let pool = self
            .pool
            .as_mut()
            .ok_or(HsmError::Storage(StorageError::NotFormatted))?;
        pool.put_key(smk, &nonce, slot, class, birth, seq, obj)
    }

    fn pool_get(&mut self, slot: u8) -> Result<KeyObject, HsmError> {
        let smk = self
            .smk
            .as_deref()
            .ok_or(HsmError::Storage(StorageError::NoStorageKey))?;
        let pool = self
            .pool
            .as_mut()
            .ok_or(HsmError::Storage(StorageError::NotFormatted))?;
        pool.get_key(smk, slot)
    }

    fn pool_take(&mut self, slot: u8) -> Result<(), HsmError> {
        let pool = self
            .pool
            .as_mut()
            .ok_or(HsmError::Storage(StorageError::NotFormatted))?;
        pool.take(slot).map_err(HsmError::Storage)
    }

    fn pool_erase(&mut self, slot: u8) -> Result<(), HsmError> {
        let pool = self
            .pool
            .as_mut()
            .ok_or(HsmError::Storage(StorageError::NotFormatted))?;
        pool.erase(slot).map_err(HsmError::Storage)
    }
}
