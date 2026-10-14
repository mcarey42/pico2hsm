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
//! update goes to core0 through the [`Hooks::put_anchor`] hook.  Group
//! wipes and formats run there too (their SD writes take seconds, and
//! core0 must keep the CCID time extensions going); each binding-ring
//! erase or program they make goes to core0 (`RoutedBindingFlash`).

use heapless::Vec;
use pico2hsm_core::error::{CryptoError, HsmError, StorageError};
use pico2hsm_core::key::{AppletId, KeyId};
use zeroize::Zeroizing;

use super::binding::{
    derive_k_bind, open_so_pin, seal_so_pin, BindState, Binding, BindingRing, Scan,
};
use super::keystore::{SoPin, SoPinHome, StoreReport, StoreState};
use super::retry_counter::{Anchor, CounterFlash, RetryCounterBackend};
use super::store_v2::{
    derive_k_idx, derive_k_obj, group_of, object_header, DegradedAuth, Env, Fetched, FormatAuth,
    Meta, MountInfo, Refusal, Store, StoreFlash, MAX_OBJECT_BLOB,
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
    /// Mounted read-only by OPEN DEGRADED: why it had been refused, and
    /// how many records the anchor counts beyond the state mounted.
    Degraded { was: Refusal, lost: u64 },
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
    #[cfg(all(not(target_arch = "arm"), test))]
    {
        // Host tests: a counter-driven stand-in (distinct, never secret).
        tests::fill(b);
        Ok(())
    }
    #[cfg(all(not(target_arch = "arm"), not(test)))]
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
            Some(BindState::Reindexing) => self.finish_reindex(),
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
                hooks: self.hooks,
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
                hooks: self.hooks,
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
    /// store is refused or has no verifiable binding.  Either core: on
    /// core1 (SD boards) the binding and anchor writes go to core0
    /// (`RoutedBindingFlash`, [`Hooks`]).
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

    /// Whether a PIN-less FORMAT STORE is allowed (R9): when there is no
    /// valid binding — a 1.x keystore or a store formatted elsewhere
    /// (`NeedsFormat`), or a binding that does not verify under this SMK —
    /// or when the store is refused and its binding holds no SO-PIN (there
    /// is none to ask for, and nothing else would ever get the device
    /// going again).  A refused store with an SO-PIN (a missing or
    /// rolled-back card, damage) keeps its binding without it: formatting
    /// would destroy the epochs the real card needs.
    pub fn format_needs_no_pin(&self) -> bool {
        match self.status {
            StoreStatus::NeedsFormat | StoreStatus::BindingUnverifiable => self.binding.is_none(),
            StoreStatus::Refused(_) => self
                .binding
                .as_ref()
                .is_some_and(|b| b.so_verifier == [0; 32]),
            _ => false,
        }
    }

    /// Wipe one group: one record, the binding with its new epoch (and,
    /// for SC-HSM INITIALIZE, its new SO-PIN: R10), the group's sectors.
    /// Either core (see `format_store_now`).
    fn wipe_group(&mut self, group: usize, so: Option<&SoPin>) -> Result<(), HsmError> {
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
        if let Some(so) = so {
            nb.so_salt = so.salt;
            nb.so_verifier = seal_so_pin(&k_bind, &so.salt, &so.hash);
        }
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

    /// OPEN DEGRADED (§9.3): mount a refused store read-only, as far as it
    /// verifies.  Only a store refused next to a valid binding; nothing is
    /// written (the caller records the event in the counter log first).
    /// Either core: reads only.
    pub fn open_degraded_now(&mut self, so_pin_verified: bool) -> Result<(), HsmError> {
        let StoreStatus::Refused(was) = self.status else {
            return Err(HsmError::Storage(StorageError::IntegrityFailure));
        };
        let auth = DegradedAuth::so_pin_verified(so_pin_verified)
            .ok_or(HsmError::Storage(StorageError::IntegrityFailure))?;
        let b = self
            .binding
            .as_ref()
            .ok_or(HsmError::Storage(StorageError::NotFormatted))?;
        let info = self.mount_info(b).map_err(HsmError::Storage)?;
        let format_gen = b.format_gen as u16;
        let mut env = AnchorEnv {
            log: self.counters.as_mut(),
            hooks: self.hooks,
        };
        let anchored = env
            .anchor()
            .ok()
            .flatten()
            .filter(|a| a.format_gen == format_gen)
            .map(|a| a.head_seq);
        if self.store.mount_degraded(info, &mut env, auth).is_err() {
            return Err(HsmError::Storage(StorageError::IntegrityFailure));
        }
        let head = self.store.next_seq().unwrap_or(1) - 1;
        self.status = StoreStatus::Degraded {
            was,
            lost: anchored.map_or(0, |a| a.saturating_sub(head)),
        };
        Ok(())
    }

    /// ACCEPT STORE (§16 OD-1, R2): make the state OPEN DEGRADED mounted
    /// the store's new, read-write state.  Only after OPEN DEGRADED of a
    /// store refused as behind its anchor or damaged (never another store,
    /// a lost anchor or binding), with `lost` the count STORE STATUS
    /// reported.  A re-index, not a lowered anchor: a new `E_store` and
    /// `format_gen + 1` (same store and group epochs), a fresh ring whose
    /// CHECKPOINT is above both the old anchor and the accepted head, so no
    /// seq is ever reused under one store and epoch.  Resumable from the
    /// binding's REINDEXING state.  Either core (as `format_store_now`).
    pub fn accept_store_now(&mut self, so_pin_verified: bool, lost: u64) -> Result<(), HsmError> {
        let refuse = || HsmError::Storage(StorageError::IntegrityFailure);
        if !so_pin_verified {
            return Err(refuse());
        }
        let StoreStatus::Degraded { was, lost: l } = self.status else {
            return Err(refuse());
        };
        if !matches!(was, Refusal::BehindAnchor(_) | Refusal::Corrupt(_)) || lost != l {
            return Err(refuse());
        }
        let smk = *self.smk()?;
        let b = self.binding.clone().ok_or_else(refuse)?;
        let mut env = AnchorEnv {
            log: self.counters.as_mut(),
            hooks: self.hooks,
        };
        let anchored = env
            .anchor()
            .map_err(HsmError::Storage)?
            .filter(|a| a.format_gen == b.format_gen as u16)
            .map(|a| a.head_seq)
            .ok_or_else(refuse)?;
        let head = self.store.next_seq().ok_or_else(refuse)? - 1;
        let seq = anchored.max(head) + 2;
        if seq > crate::storage::retry_counter::ANCHOR_SEQ_MAX {
            return Err(refuse());
        }
        // Step 1: the accepted index, under the new key.
        let e_store: [u8; 32] = random().map_err(HsmError::Storage)?;
        let k_idx = derive_k_idx(&smk, &b.store_id, &e_store);
        self.store
            .reindex_snapshot(&k_idx, seq)
            .map_err(HsmError::Storage)?;
        // Step 2: the binding names the new key; the old one (and with it
        // the old journal) is gone from here on.
        let mut nb = b.clone();
        nb.state = BindState::Reindexing;
        nb.e_store = e_store;
        nb.format_gen = b.format_gen.wrapping_add(1).max(1);
        self.write_binding(&mut nb).map_err(HsmError::Storage)?;
        self.binding = Some(nb);
        self.store.unmount();
        self.finish_reindex().map_err(HsmError::Storage)
    }

    /// Steps 3–5 of ACCEPT STORE, resumable from a REINDEXING binding: the
    /// ring, the anchor, the binding ACTIVE, mount.
    fn finish_reindex(&mut self) -> Result<(), StorageError> {
        let b = self.binding.as_ref().ok_or(StorageError::NotFormatted)?;
        if b.state != BindState::Reindexing {
            return Err(StorageError::IntegrityFailure);
        }
        let info = self.mount_info(b)?;
        {
            let mut env = AnchorEnv {
                log: self.counters.as_mut(),
                hooks: self.hooks,
            };
            if let Err(e) = self.store.finish_reindex(info, &mut env) {
                self.status = StoreStatus::Refused(Refusal::Corrupt("re-index"));
                return Err(e);
            }
        }
        let mut nb = self.binding.clone().ok_or(StorageError::NotFormatted)?;
        nb.state = BindState::Active;
        self.write_binding(&mut nb)?;
        self.binding = Some(nb);
        self.mount()
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

/// A [`Refusal`] as STORE STATUS reports it.
pub fn refusal_code(r: Refusal) -> u8 {
    match r {
        Refusal::Blank => 1,
        Refusal::WrongStore => 2,
        Refusal::NoAnchor => 3,
        Refusal::BehindAnchor(_) => 4,
        Refusal::Corrupt(_) => 5,
        Refusal::PendingRotation { .. } => 6,
        Refusal::Io => 7,
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
        // A new SC-HSM object past the SC-HSM index's capacity would be
        // stored yet unreachable (the index is in RAM, 340 entries): refuse
        // it, as the 1.x directory did.  Updates always go through.
        if (obj.key_id >> 16) & 0xFF == 0
            && self
                .store
                .lookup(obj.key_id)
                .map_err(HsmError::Storage)?
                .is_none()
        {
            let mut sc_hsm = 0usize;
            let _ = self.store.for_each(&mut |e| {
                if (e.key_id >> 16) & 0xFF == 0 {
                    sc_hsm += 1;
                }
            });
            if sc_hsm >= crate::protocol::sc_hsm::MAX_KEY_INDEX {
                return Err(HsmError::Storage(StorageError::KeystoreFull));
            }
        }
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
            self.wipe_group(g, None)?;
        }
        Ok(())
    }

    fn wipe_by_owner(&mut self, owner: AppletId) -> Result<(), HsmError> {
        self.wipe_group(applet_group(owner), None)
    }

    fn so_pin_home(&self) -> SoPinHome {
        let (Some(smk), Some(b)) = (self.smk.as_deref(), self.binding.as_ref()) else {
            return SoPinHome::Binding(None);
        };
        let k_bind = derive_k_bind(smk);
        SoPinHome::Binding(open_so_pin(&k_bind, b).map(|hash| SoPin {
            salt: b.so_salt,
            hash: *hash,
        }))
    }

    fn set_binding_so_pin(&mut self, so: Option<&SoPin>) -> Result<(), HsmError> {
        let smk = self.smk()?;
        let k_bind = derive_k_bind(smk);
        let mut nb = self
            .binding
            .clone()
            .ok_or(HsmError::Storage(StorageError::NotFormatted))?;
        match so {
            Some(so) => {
                nb.so_salt = so.salt;
                nb.so_verifier = seal_so_pin(&k_bind, &so.salt, &so.hash);
            }
            None => {
                nb.so_salt = [0; 16];
                nb.so_verifier = [0; 32];
            }
        }
        self.write_binding(&mut nb).map_err(HsmError::Storage)?;
        self.binding = Some(nb);
        Ok(())
    }

    fn reset_sc_hsm(&mut self, so: &SoPin) -> Result<(), HsmError> {
        self.wipe_group(applet_group(AppletId::ScHsm), Some(so))
    }

    fn store_report(&self) -> Option<StoreReport> {
        let (state, why, lost) = match self.status {
            StoreStatus::Up => (StoreState::Up, None, 0),
            StoreStatus::Degraded { was, lost } => (StoreState::Degraded, Some(was), lost),
            StoreStatus::Refused(r) => {
                let lost = match r {
                    Refusal::BehindAnchor(n) => n,
                    _ => 0,
                };
                (StoreState::Refused, Some(r), lost)
            }
            StoreStatus::BindingUnverifiable | StoreStatus::NeedsFormat => {
                (StoreState::NeedsFormat, None, 0)
            }
            StoreStatus::Down | StoreStatus::NoKey => (StoreState::Down, None, 0),
        };
        Some(StoreReport {
            state,
            reason: why.map_or(0, refusal_code),
            lost,
            head: self.store.next_seq().map_or(0, |n| n - 1),
        })
    }

    fn open_degraded(&mut self, so_pin_verified: bool) -> Result<(), HsmError> {
        self.open_degraded_now(so_pin_verified)
    }

    fn accept_store(&mut self, so_pin_verified: bool, lost: u64) -> Result<(), HsmError> {
        self.accept_store_now(so_pin_verified, lost)
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

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use crate::security::key_management::{AlgorithmId, KeyType};
    use crate::storage::retry_counter::CounterLog;
    use crate::storage::store_v2::Media;
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::vec;
    use std::vec::Vec;

    static CTR: AtomicU64 = AtomicU64::new(1);

    /// Host stand-in for the TRNG: distinct values, nothing secret.
    pub(crate) fn fill(b: &mut [u8]) {
        for chunk in b.chunks_mut(8) {
            let v = CTR
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15);
            chunk.copy_from_slice(&v.to_le_bytes()[..chunk.len()]);
        }
    }

    const SS: usize = 4096;

    std::thread_local! {
        /// Flash operations left before a power cut (`None`: no cut), over
        /// every region; `DEAD` once it struck.
        static BUDGET: core::cell::Cell<Option<usize>> = const { core::cell::Cell::new(None) };
        static DEAD: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
        pub(crate) static OPS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }

    /// Spend one operation; `false`: the power is gone (a program then
    /// leaves half its bytes).
    fn op() -> bool {
        if DEAD.get() {
            return false;
        }
        OPS.set(OPS.get() + 1);
        match BUDGET.get() {
            Some(0) => {
                DEAD.set(true);
                false
            }
            Some(n) => {
                BUDGET.set(Some(n - 1));
                true
            }
            None => true,
        }
    }

    pub(crate) fn cut_after(n: Option<usize>) {
        BUDGET.set(n);
        DEAD.set(false);
        OPS.set(0);
    }

    /// NOR flash for every region (keystore, binding ring, counter log).
    #[derive(Clone)]
    pub(crate) struct Nor {
        pub mem: Vec<u8>,
        /// An SD card: whole 512-byte blocks, written over (not ANDed).
        sd: bool,
    }

    impl Nor {
        fn new(sectors: usize) -> Self {
            Nor {
                mem: vec![0xFF; sectors * SS],
                sd: false,
            }
        }
        fn rd(&self, offset: u32, buf: &mut [u8]) {
            let o = offset as usize;
            buf.copy_from_slice(&self.mem[o..o + buf.len()]);
        }
        fn pr(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError> {
            let live = op();
            let n = if live { data.len() } else { data.len() / 2 };
            if self.sd {
                assert!(offset % 512 == 0 && data.len() % 512 == 0);
                let n = n / 512 * 512;
                self.mem[offset as usize..offset as usize + n].copy_from_slice(&data[..n]);
            } else {
                for (i, &d) in data[..n].iter().enumerate() {
                    self.mem[offset as usize + i] &= d;
                }
            }
            live.then_some(()).ok_or(StorageError::WriteError)
        }
        fn er(&mut self, sector: u32) -> Result<(), StorageError> {
            if !op() {
                return Err(StorageError::EraseError);
            }
            let s = sector as usize * SS;
            self.mem[s..s + SS].fill(0xFF);
            Ok(())
        }
    }

    impl StoreFlash for Nor {
        fn media(&self) -> Media {
            if self.sd {
                Media::Sd
            } else {
                Media::Nor
            }
        }
        fn sectors(&self) -> u32 {
            (self.mem.len() / SS) as u32
        }
        fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), StorageError> {
            self.rd(offset, buf);
            Ok(())
        }
        fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError> {
            self.pr(offset, data)
        }
        fn erase_sector(&mut self, sector: u32) -> Result<(), StorageError> {
            self.er(sector)
        }
    }

    impl CounterFlash for Nor {
        fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), StorageError> {
            self.rd(offset, buf);
            Ok(())
        }
        fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError> {
            self.pr(offset, data)
        }
        fn erase_sector(&mut self, sector: u32) -> Result<(), StorageError> {
            self.er(sector)
        }
    }

    pub(crate) type Ks = FlashKeyStoreV2<Nor, Nor, CounterLog<Nor>>;

    /// A device's three internal regions, between boots.
    #[derive(Clone)]
    pub(crate) struct Dev {
        pub store: Nor,
        pub bind: Nor,
        pub log: Nor,
    }

    const SMK: [u8; 32] = [5; 32];

    impl Dev {
        pub(crate) fn new() -> Self {
            Dev {
                store: Nor::new(96),
                bind: Nor::new(8),
                log: Nor::new(16),
            }
        }

        /// The same with the keystore on an SD card.
        pub(crate) fn new_sd() -> Self {
            let mut d = Dev::new();
            d.store = Nor::new(160);
            d.store.sd = true;
            d
        }

        /// Boot: open the log (formatting a blank one), the binding, init.
        pub(crate) fn boot(&self) -> (Ks, Result<(), StorageError>) {
            let mut log = CounterLog::open(self.log.clone(), 16);
            if self.log.mem.iter().all(|&b| b == 0xFF) {
                log.format(&[]).unwrap();
            }
            let mut ks = Ks::new(self.store.clone(), Some(Zeroizing::new(SMK)));
            ks.attach_retry_counters(log);
            ks.attach_binding(self.bind.clone(), 8).unwrap();
            let r = ks.init();
            (ks, r)
        }

        /// Boot as the firmware does: the counter log as found (a blank
        /// one stays unformatted; only the PIN-record migration, which
        /// needs a mounted store, seeds it).
        pub(crate) fn boot_unseeded(&self) -> (Ks, Result<(), StorageError>) {
            let log = CounterLog::open(self.log.clone(), 16);
            let mut ks = Ks::new(self.store.clone(), Some(Zeroizing::new(SMK)));
            ks.attach_retry_counters(log);
            ks.attach_binding(self.bind.clone(), 8).unwrap();
            let r = ks.init();
            (ks, r)
        }

        /// The regions as `ks` left them.
        pub(crate) fn of(ks: &mut Ks) -> Self {
            Dev {
                store: ks.store.flash_mut().clone(),
                bind: ks.binding_ring.as_mut().unwrap().flash_mut().clone(),
                log: ks.counters.as_mut().unwrap().flash_mut().clone(),
            }
        }
    }

    pub(crate) fn key(id: u32, tag: u8) -> KeyObject {
        let owner = match (id >> 16) & 0xFF {
            1 => AppletId::Piv,
            2 => AppletId::OpenPgp,
            _ => AppletId::ScHsm,
        };
        let mut k = KeyObject::new(KeyType::Generic, id, owner, AlgorithmId::AesGcm);
        let _ = k.private_key.extend_from_slice(&[tag; 16]);
        k
    }

    pub(crate) fn tag(ks: &mut Ks, id: u32) -> Option<u8> {
        ks.fetch_key(KeyId(id)).unwrap().map(|k| k.private_key[0])
    }

    pub(crate) fn so(n: u8) -> SoPin {
        SoPin {
            salt: [n; 16],
            hash: [n ^ 0x5A; 32],
        }
    }

    fn so_of(ks: &Ks) -> Option<SoPin> {
        match ks.so_pin_home() {
            SoPinHome::Binding(s) => s,
            SoPinHome::Record => panic!("V2 keeps the SO-PIN in the binding"),
        }
    }

    #[test]
    fn first_boot_formats_with_no_so_pin() {
        let (ks, r) = Dev::new().boot();
        r.unwrap();
        assert_eq!(ks.status(), StoreStatus::Up);
        assert_eq!(so_of(&ks), None);
    }

    /// A factory-fresh device: nothing on flash, the counter log included.
    #[test]
    fn first_boot_formats_with_a_blank_counter_log() {
        let (mut ks, r) = Dev::new().boot_unseeded();
        r.unwrap();
        assert_eq!(ks.status(), StoreStatus::Up);
        ks.save_key(&key(7, 7)).unwrap();
        let (mut ks, r) = Dev::of(&mut ks).boot_unseeded();
        r.unwrap();
        assert_eq!(tag(&mut ks, 7), Some(7));
    }

    /// A 1.x keystore on a board whose counter log was never written (no
    /// version-1 log to migrate either): FORMAT STORE still works.
    #[test]
    fn format_store_over_a_1x_keystore_with_a_blank_counter_log() {
        let mut d = Dev::new();
        d.store.mem[..64].fill(0x12);
        let (mut ks, r) = d.boot_unseeded();
        assert!(r.is_err());
        assert_eq!(ks.status(), StoreStatus::NeedsFormat);
        assert!(ks.format_needs_no_pin());
        ks.format_store(false).unwrap();
        assert_eq!(ks.status(), StoreStatus::Up);
        ks.save_key(&key(7, 7)).unwrap();
        let (mut ks, r) = Dev::of(&mut ks).boot_unseeded();
        r.unwrap();
        assert_eq!(tag(&mut ks, 7), Some(7));
    }

    #[test]
    fn reset_sc_hsm_sets_the_so_pin_and_wipes_only_sc_hsm() {
        let (mut ks, r) = Dev::new().boot();
        r.unwrap();
        ks.save_key(&key(0x0000_0001, 1)).unwrap();
        ks.save_key(&key(0x0001_009A, 2)).unwrap();
        ks.reset_sc_hsm(&so(7)).unwrap();
        assert_eq!(tag(&mut ks, 0x0000_0001), None);
        assert_eq!(tag(&mut ks, 0x0001_009A), Some(2));
        assert_eq!(so_of(&ks), Some(so(7)));
        // It survives a reboot.
        let (mut ks2, r) = Dev::of(&mut ks).boot();
        r.unwrap();
        assert_eq!(so_of(&ks2), Some(so(7)));
        assert_eq!(tag(&mut ks2, 0x0001_009A), Some(2));
    }

    #[test]
    fn the_so_pin_is_not_on_flash_in_the_clear() {
        let (mut ks, r) = Dev::new().boot();
        r.unwrap();
        ks.reset_sc_hsm(&so(7)).unwrap();
        let d = Dev::of(&mut ks);
        let hash = so(7).hash;
        for region in [&d.store.mem, &d.bind.mem, &d.log.mem] {
            assert!(!region.windows(32).any(|w| w == hash));
        }
    }

    #[test]
    fn set_binding_so_pin_replaces_and_clears() {
        let (mut ks, r) = Dev::new().boot();
        r.unwrap();
        ks.set_binding_so_pin(Some(&so(1))).unwrap();
        assert_eq!(so_of(&ks), Some(so(1)));
        ks.set_binding_so_pin(Some(&so(2))).unwrap();
        let (mut ks, _) = Dev::of(&mut ks).boot();
        assert_eq!(so_of(&ks), Some(so(2)));
        ks.set_binding_so_pin(None).unwrap();
        assert_eq!(so_of(&ks), None);
    }

    /// A store rolled back to an older image: refused, the SO-PIN still
    /// readable, a PIN-less FORMAT STORE refused while one is set.
    #[test]
    fn a_refused_store_keeps_its_so_pin() {
        let (mut ks, r) = Dev::new().boot();
        r.unwrap();
        ks.reset_sc_hsm(&so(3)).unwrap();
        ks.save_key(&key(0x0000_0001, 1)).unwrap();
        let old = Dev::of(&mut ks).store;
        ks.save_key(&key(0x0000_0002, 2)).unwrap();
        let mut d = Dev::of(&mut ks);
        d.store = old;
        let (mut ks, r) = d.boot();
        assert!(r.is_err());
        assert!(matches!(
            ks.status(),
            StoreStatus::Refused(Refusal::BehindAnchor(1))
        ));
        assert_eq!(so_of(&ks), Some(so(3)));
        assert!(!ks.format_needs_no_pin());
        assert!(ks.format_store(false).is_err());
        // Without an SO-PIN there is nothing to ask for.
        ks.set_binding_so_pin(None).unwrap();
        assert!(ks.format_needs_no_pin());
    }

    #[test]
    fn format_store_carries_the_so_pin_forward() {
        let (mut ks, r) = Dev::new().boot();
        r.unwrap();
        ks.reset_sc_hsm(&so(4)).unwrap();
        ks.save_key(&key(0x0002_0001, 9)).unwrap();
        ks.format_store(true).unwrap();
        assert_eq!(tag(&mut ks, 0x0002_0001), None);
        let (ks, r) = Dev::of(&mut ks).boot();
        r.unwrap();
        assert_eq!(so_of(&ks), Some(so(4)));
    }
}

#[cfg(test)]
mod accept_tests {
    use super::tests::*;
    use super::*;

    /// A device whose store lost its last `n` commits (one key, 7, stays).
    fn rolled_back(n: u32) -> Dev {
        rolled_back_on(Dev::new(), n)
    }

    fn rolled_back_on(dev: Dev, n: u32) -> Dev {
        let (mut ks, r) = dev.boot();
        r.unwrap();
        ks.reset_sc_hsm(&so(1)).unwrap();
        ks.save_key(&key(7, 7)).unwrap();
        ks.save_key(&key(0x0001_0005, 5)).unwrap();
        let old = Dev::of(&mut ks).store;
        for i in 0..n {
            ks.save_key(&key(0x10 + i, 9)).unwrap();
        }
        let mut d = Dev::of(&mut ks);
        d.store = old;
        d
    }

    fn degraded(d: &Dev) -> Ks {
        let (mut ks, r) = d.boot();
        assert!(r.is_err());
        ks.open_degraded_now(true).unwrap();
        ks
    }

    fn accepted_state(ks: &mut Ks) {
        assert_eq!(ks.status(), StoreStatus::Up);
        assert_eq!(tag(ks, 7), Some(7));
        assert_eq!(tag(ks, 0x0001_0005), Some(5));
        assert_eq!(tag(ks, 0x10), None);
    }

    #[test]
    fn accept_store_makes_the_degraded_state_the_store() {
        let mut ks = degraded(&rolled_back(3));
        assert!(matches!(
            ks.status(),
            StoreStatus::Degraded {
                lost: 3,
                was: Refusal::BehindAnchor(3)
            }
        ));
        let head = ks.store_report().unwrap().head;
        ks.accept_store_now(true, 3).unwrap();
        accepted_state(&mut ks);
        // New seqs run above the old anchor (head + 3): never reused (R2).
        assert!(ks.store_report().unwrap().head > head + 3);
        // Read-write again, and it survives a reboot.
        ks.save_key(&key(8, 8)).unwrap();
        let (mut ks, r) = Dev::of(&mut ks).boot();
        r.unwrap();
        accepted_state(&mut ks);
        assert_eq!(tag(&mut ks, 8), Some(8));
        assert_eq!(so_pin_of(&ks), Some(so(1)), "the binding keeps the SO-PIN");
    }

    fn so_pin_of(ks: &Ks) -> Option<SoPin> {
        match ks.so_pin_home() {
            SoPinHome::Binding(s) => s,
            SoPinHome::Record => None,
        }
    }

    #[test]
    fn accept_store_is_guarded() {
        let d = rolled_back(2);
        // Not before OPEN DEGRADED.
        let (mut ks, _) = d.boot();
        assert!(ks.accept_store_now(true, 2).is_err());
        let mut ks = degraded(&d);
        assert!(ks.accept_store_now(false, 2).is_err(), "SO-PIN");
        assert!(ks.accept_store_now(true, 1).is_err(), "the count shown");
        assert!(matches!(ks.status(), StoreStatus::Degraded { .. }));
        // Not for a store whose anchor is gone.
        let mut d2 = d.clone();
        d2.log = Dev::new().log;
        let (mut ks2, _) = d2.boot();
        assert!(matches!(
            ks2.status(),
            StoreStatus::Refused(Refusal::NoAnchor)
        ));
        ks2.open_degraded_now(true).unwrap();
        assert!(ks2.accept_store_now(true, 0).is_err());
    }

    /// A power cut at every flash operation of ACCEPT STORE: the next boot
    /// finds the store refused as before (and the re-index can be run
    /// again) or up with exactly the accepted state.
    #[test]
    fn accept_store_survives_a_cut_anywhere() {
        cut_sweep(rolled_back(2));
    }

    #[test]
    fn accept_store_survives_a_cut_anywhere_on_sd() {
        cut_sweep(rolled_back_on(Dev::new_sd(), 2));
    }

    fn cut_sweep(d: Dev) {
        let mut ks = degraded(&d);
        cut_after(None);
        ks.accept_store_now(true, 2).unwrap();
        let total = OPS.get();
        assert!(total > 10, "{total} operations");
        let (mut retried, mut resumed) = (0, 0);
        for budget in 0..total {
            let mut ks = degraded(&d);
            cut_after(Some(budget));
            // A cut in the last step (erasing the binding ring's old copy,
            // best effort: boot tidies it) still reports success.
            let _ = ks.accept_store_now(true, 2);
            cut_after(None);
            let after = Dev::of(&mut ks);
            let reindexing = ks.binding.as_ref().map(|b| b.state) == Some(BindState::Reindexing);
            let (mut ks, r) = after.boot();
            if reindexing && r.is_ok() {
                resumed += 1;
            }
            if r.is_err() {
                retried += 1;
                assert!(
                    matches!(ks.status(), StoreStatus::Refused(_)),
                    "cut at {budget}: {:?}",
                    ks.status()
                );
                ks.open_degraded_now(true).unwrap();
                let lost = ks.store_report().unwrap().lost;
                ks.accept_store_now(true, lost)
                    .unwrap_or_else(|e| panic!("cut at {budget}: retry {e:?}"));
            }
            accepted_state(&mut ks);
            ks.save_key(&key(9, 9)).unwrap();
            let (mut ks, r) = Dev::of(&mut ks).boot();
            r.unwrap_or_else(|e| panic!("cut at {budget}: {e:?}"));
            assert_eq!(tag(&mut ks, 9), Some(9));
        }
        // Both ways back were taken: refused (cut before the binding named
        // the new key) and resumed at boot from REINDEXING.
        assert!(
            retried > 0 && resumed > 0,
            "{retried} retried, {resumed} resumed"
        );
    }
}
