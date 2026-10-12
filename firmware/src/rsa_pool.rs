//! RSA key pool — pre-generated keys, filled and rotated in idle time.
//!
//! Core1 runs [`Engine::background_step`] between APDUs: a bounded slice
//! of the sliced generator (`crypto::rsa_keygen`) or one flash operation
//! on the pool region (`storage::rsa_pool`).  SC-HSM GENERATE KEY PAIR for
//! RSA-2048/3072/4096 takes a pooled key first ([`Engine::issue`]) and
//! generates live only when the pool has none.
//!
//! # Policy
//! - **Depth**: per size, [`PoolConfig::depth`] keys (default 4 × 2048,
//!   2 × 3072, 2 × 4096; at most [`MAX_DEPTH`] each).  The region has a
//!   sector per possible key.
//! - **Age**: the *pool clock* counts minutes of powered-on time; there is
//!   no RTC, so time with the device unplugged does not count.  The clock
//!   is persisted every [`CLOCK_PERSIST_MIN`] minutes (and every key
//!   records its birth time), so at most that much is lost per power cut.
//! - **Rotation / age-out** (default on): a pooled key whose age reaches
//!   [`PoolConfig::max_age_min`] is erased and replaced; GENERATE never
//!   issues a key past that age.  Default 4 hours of powered-on time.
//!   Each slot is then erased about once per `max_age` — at the 1-hour
//!   minimum, 24 erases a day, 100 000 cycles take more than 11 years of
//!   continuous power; at the default, more than 45.
//! - **Issue**: the *newest* in-age key of the size, so a flash image taken
//!   earlier is least likely to hold the key that gets issued.  The slot is
//!   marked taken on flash before the key leaves this module; it is then a
//!   normal key, stored by the GENERATE handler exactly like a fresh one.
//! - **Off**: turning the pool off erases every pooled key.  INITIALIZE
//!   (a trust reset) erases them as well; the configuration itself, the
//!   clock and the sequence number survive.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use pico2hsm_core::error::{HsmError, StorageError};
use pico2hsm_core::key::KeyType as CoreKeyType;
use rand_core::RngCore;
use zeroize::Zeroize;

use crate::crypto::asymmetric::RsaKeyPair;
use crate::crypto::rsa_keygen::{Budget, KeyGen, Poll};
use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};
use crate::storage::retry_counter::ValueId;
use crate::storage::rsa_pool::{pool_key_id, SizeClass, SlotState, MAX_DEPTH, POOL_SLOTS};
use crate::storage::KeyStore;

/// Smallest configurable maximum age (minutes): bounds flash wear.
pub const MIN_MAX_AGE_MIN: u32 = 60;
/// Largest configurable maximum age (minutes): one year.
pub const MAX_MAX_AGE_MIN: u32 = 365 * 24 * 60;
/// How often the pool clock is persisted (minutes).
pub const CLOCK_PERSIST_MIN: u64 = 10;
/// Failed pool writes in a row before background filling stops until
/// the next boot (a worn or failing region must not be hammered).
const MAX_WRITE_FAILURES: u8 = 3;

/// Pool settings (persisted in the counter log, `ValueId::PoolConfig`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolConfig {
    /// Pre-generate keys at all.
    pub enabled: bool,
    /// Rotate pooled keys and never issue one older than `max_age_min`.
    pub rotate: bool,
    /// Maximum age of a pooled key, in minutes of powered-on time.
    pub max_age_min: u32,
    /// Keys kept per size (RSA-2048, -3072, -4096).
    pub depth: [u8; 3],
}

impl PoolConfig {
    /// The factory setting.
    pub const DEFAULT: PoolConfig = PoolConfig {
        enabled: true,
        rotate: true,
        max_age_min: 4 * 60,
        depth: [4, 2, 2],
    };

    const F_ENABLED: u8 = 0x01;
    const F_ROTATE: u8 = 0x02;

    /// Flags byte (bit 0 enabled, bit 1 rotation / age-out).
    pub fn flags(&self) -> u8 {
        (if self.enabled { Self::F_ENABLED } else { 0 })
            | (if self.rotate { Self::F_ROTATE } else { 0 })
    }

    /// Persisted form: `flags | d2048 << 8 | d3072 << 16 | d4096 << 24 |
    /// max_age_min << 32`.
    pub fn encode(&self) -> u64 {
        u64::from(self.flags())
            | u64::from(self.depth[0]) << 8
            | u64::from(self.depth[1]) << 16
            | u64::from(self.depth[2]) << 24
            | u64::from(self.max_age_min) << 32
    }

    /// Parse and validate the persisted form.
    pub fn decode(v: u64) -> Option<Self> {
        Self::from_parts(
            v as u8,
            (v >> 32) as u32,
            [(v >> 8) as u8, (v >> 16) as u8, (v >> 24) as u8],
        )
    }

    /// Build and validate a configuration (also the APDU's data).
    pub fn from_parts(flags: u8, max_age_min: u32, depth: [u8; 3]) -> Option<Self> {
        if flags & !(Self::F_ENABLED | Self::F_ROTATE) != 0
            || !(MIN_MAX_AGE_MIN..=MAX_MAX_AGE_MIN).contains(&max_age_min)
            || depth.iter().any(|&d| d > MAX_DEPTH)
        {
            return None;
        }
        Some(PoolConfig {
            enabled: flags & Self::F_ENABLED != 0,
            rotate: flags & Self::F_ROTATE != 0,
            max_age_min,
            depth,
        })
    }

    /// Wire form for the status / config APDUs:
    /// `flags(1) max_age_min(4, BE) depth(3)`.
    pub fn to_bytes(&self) -> [u8; 8] {
        let a = self.max_age_min.to_be_bytes();
        [
            self.flags(),
            a[0],
            a[1],
            a[2],
            a[3],
            self.depth[0],
            self.depth[1],
            self.depth[2],
        ]
    }

    /// Parse the wire form.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != 8 {
            return None;
        }
        Self::from_parts(
            b[0],
            u32::from_be_bytes([b[1], b[2], b[3], b[4]]),
            [b[5], b[6], b[7]],
        )
    }
}

/// What [`Engine::background_step`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activity {
    /// Nothing to do: core1 may sleep.
    Idle,
    /// Did some work (a generator slice or one flash operation).
    Worked,
}

/// Why GENERATE could not get a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IssueError {
    /// Flash would not take the "taken" mark, or the pool is unreadable:
    /// fail closed (6581).
    Storage,
    /// Live generation failed (self-checks or the FIPS iteration limit).
    Generation,
    /// Not a pooled size, or the generator is not available.
    Unsupported,
}

/// Pool status (no PIN; see the status APDU in `extras`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolStatus {
    pub config: PoolConfig,
    /// Issuable (valid, in-age) keys per size.
    pub ready: [u8; 3],
    /// Size being generated (bits), 0 if none.
    pub generating_bits: u16,
    /// The pool clock (minutes of powered-on time).
    pub clock_min: u64,
    /// Sequence number of the newest pooled key.
    pub seq: u32,
    /// Keys written to the pool since boot.
    pub generated: u32,
    /// Keys retired by age since boot.
    pub rotated: u32,
    /// Pooled keys issued since boot.
    pub issued: u32,
    /// Keys generated live (pool empty / off) since boot.
    pub live: u32,
    /// Bit 0: RNG ready; bit 1: pool region present; bit 2: background
    /// filling stopped after write failures.
    pub health: u8,
}

/// The pool's RAM state (about 10 KB, all in the generator).
pub struct Engine {
    pub kg: KeyGen,
    /// The size the generator works on, if any.
    gen_class: Option<SizeClass>,
    /// Config and clock loaded from the store.
    loaded: bool,
    config: PoolConfig,
    /// Pool clock at `uptime_at_load`.
    clock_base: u64,
    uptime_at_load: u64,
    persisted_clock: u64,
    seq: u32,
    persisted_seq: u32,
    rng_ok: bool,
    write_failures: u8,
    generated: u32,
    rotated: u32,
    issued: u32,
    live: u32,
}

impl Engine {
    /// A fresh engine (fits a `static`).
    pub const fn new() -> Self {
        Engine {
            kg: KeyGen::new(),
            gen_class: None,
            loaded: false,
            config: PoolConfig::DEFAULT,
            clock_base: 0,
            uptime_at_load: 0,
            persisted_clock: 0,
            seq: 0,
            persisted_seq: 0,
            rng_ok: false,
            write_failures: 0,
            generated: 0,
            rotated: 0,
            issued: 0,
            live: 0,
        }
    }

    /// Background generation may start: the boot RNG reseed succeeded.
    pub fn set_rng_ok(&mut self, ok: bool) {
        self.rng_ok = ok;
    }

    /// Forget the loaded state (tests: simulate a reboot).
    pub fn reboot(&mut self) {
        self.kg.reset();
        *self = Engine {
            rng_ok: self.rng_ok,
            ..Engine::new()
        };
    }

    fn now(&self, uptime_min: u64) -> u64 {
        self.clock_base + uptime_min.saturating_sub(self.uptime_at_load)
    }

    /// Load config, clock and sequence number (first use after boot).
    fn load(&mut self, store: &mut dyn KeyStore, uptime_min: u64) {
        let mut cfg = None;
        let mut clock = 0;
        let mut seq = 0;
        if let Some(log) = store.retry_counters() {
            cfg = log
                .value(ValueId::PoolConfig)
                .ok()
                .flatten()
                .and_then(PoolConfig::decode);
            clock = log.value(ValueId::PoolClock).ok().flatten().unwrap_or(0);
            seq = log.value(ValueId::PoolSeq).ok().flatten().unwrap_or(0) as u32;
        }
        self.persisted_clock = clock;
        self.persisted_seq = seq;
        if let Some(pool) = store.rsa_pool() {
            if let Ok(slots) = pool.pool_slots() {
                for s in slots {
                    if let SlotState::Valid { birth, seq: s, .. } = s {
                        clock = clock.max(u64::from(birth));
                        seq = seq.max(s);
                    }
                }
            }
        }
        self.config = cfg.unwrap_or(PoolConfig::DEFAULT);
        self.clock_base = clock;
        self.uptime_at_load = uptime_min;
        self.seq = seq;
        self.loaded = true;
    }

    fn ensure_loaded(&mut self, store: &mut dyn KeyStore, uptime_min: u64) {
        if !self.loaded {
            self.load(store, uptime_min);
        }
    }

    /// The current configuration.
    pub fn config(&mut self, store: &mut dyn KeyStore, uptime_min: u64) -> PoolConfig {
        self.ensure_loaded(store, uptime_min);
        self.config
    }

    fn age(&self, now: u64, birth: u32) -> u64 {
        now.saturating_sub(u64::from(birth))
    }

    fn in_age(&self, now: u64, birth: u32) -> bool {
        !self.config.rotate || self.age(now, birth) < u64::from(self.config.max_age_min)
    }

    /// One slice of idle-time work.  Does at most one flash operation or
    /// one budgeted generator slice.
    pub fn background_step(
        &mut self,
        store: &mut dyn KeyStore,
        rng: &mut dyn RngCore,
        uptime_min: u64,
        budget: &mut dyn Budget,
    ) -> Activity {
        if !self.rng_ok {
            return Activity::Idle;
        }
        if !self.loaded {
            self.load(store, uptime_min);
            return Activity::Worked;
        }
        let now = self.now(uptime_min);
        let slots = match store.rsa_pool().map(|p| p.pool_slots()) {
            Some(Ok(s)) => s,
            _ => return Activity::Idle,
        };
        let erase = |store: &mut dyn KeyStore, i: usize| {
            store
                .rsa_pool()
                .is_some_and(|p| p.pool_erase(i as u8).is_ok())
        };

        // Off: erase whatever is left (the config APDU already did; this
        // is the backstop after a failed erase or a reboot mid-wipe).
        if !self.config.enabled {
            if self.gen_class.take().is_some() {
                self.kg.reset();
            }
            if let Some(i) = slots.iter().position(|s| *s != SlotState::Blank) {
                erase(store, i);
                return Activity::Worked;
            }
            return Activity::Idle;
        }
        if self.write_failures >= MAX_WRITE_FAILURES {
            return Activity::Idle;
        }

        // Taken or torn slots: erase (wipes the issued key's pool copy).
        if let Some(i) = slots.iter().position(|s| s.needs_erase()) {
            erase(store, i);
            return Activity::Worked;
        }

        // Per size: too many (depth lowered) or too old → retire the oldest.
        for class in SizeClass::ALL {
            let mut count = 0;
            let mut oldest: Option<(usize, u32, u32)> = None;
            for (i, s) in slots.iter().enumerate() {
                if let SlotState::Valid {
                    class: c,
                    birth,
                    seq,
                } = *s
                {
                    if c == class {
                        count += 1;
                        if oldest.map_or(true, |(_, b, q)| (birth, seq) < (b, q)) {
                            oldest = Some((i, birth, seq));
                        }
                    }
                }
            }
            let Some((i, birth, _)) = oldest else {
                continue;
            };
            let too_many = count > self.config.depth[class as usize];
            let too_old = self.config.rotate && !self.in_age(now, birth);
            if too_many || too_old {
                if erase(store, i) && too_old && !too_many {
                    self.rotated += 1;
                }
                return Activity::Worked;
            }
        }

        // Persist the clock (and sequence number) now and then.
        if now >= self.persisted_clock + CLOCK_PERSIST_MIN || self.seq > self.persisted_seq {
            if let Some(log) = store.retry_counters() {
                let ok_c = log.put_value(ValueId::PoolClock, now).is_ok();
                let ok_s = log.put_value(ValueId::PoolSeq, u64::from(self.seq)).is_ok();
                if ok_c {
                    self.persisted_clock = now;
                }
                if ok_s {
                    self.persisted_seq = self.seq;
                }
                if ok_c || ok_s {
                    return Activity::Worked;
                }
            }
            // No log (or it failed): keep going; births still carry time.
            self.persisted_clock = now;
            self.persisted_seq = self.seq;
        }

        // What to make next: the size furthest below its depth.
        let mut want: Option<(SizeClass, u32)> = None;
        for class in SizeClass::ALL {
            let depth = u32::from(self.config.depth[class as usize]);
            if depth == 0 {
                continue;
            }
            let count = slots
                .iter()
                .filter(|s| matches!(s, SlotState::Valid { class: c, .. } if *c == class))
                .count() as u32;
            if count >= depth {
                continue;
            }
            // Fill ratio in 1/1000ths; the smaller size wins a tie.
            let ratio = count * 1000 / depth;
            if want.map_or(true, |(_, r)| ratio < r) {
                want = Some((class, ratio));
            }
        }
        let Some((class, _)) = want else {
            if self.gen_class.take().is_some() {
                self.kg.reset();
            }
            return Activity::Idle;
        };
        if self.gen_class != Some(class) || !(self.kg.is_busy() || self.kg.is_ready()) {
            self.kg.start(class.bits());
            self.gen_class = Some(class);
        }
        match self.kg.step(rng, budget) {
            Poll::Pending => Activity::Worked,
            Poll::Failed | Poll::Idle => {
                self.kg.reset();
                self.gen_class = None;
                Activity::Worked
            }
            Poll::Ready => {
                let Some(slot) = slots.iter().position(|s| *s == SlotState::Blank) else {
                    // No blank slot (all erases failing): try later.
                    return Activity::Worked;
                };
                let seq = self.seq.wrapping_add(1);
                let birth = now.min(u64::from(u32::MAX)) as u32;
                let result = match self.pooled_object(slot as u8, class, seq) {
                    Some(obj) => match store.rsa_pool() {
                        Some(p) => p.pool_put(slot as u8, class, birth, seq, &obj),
                        None => Err(HsmError::Storage(StorageError::NotFormatted)),
                    },
                    None => Err(HsmError::InvalidInput),
                };
                self.kg.reset();
                self.gen_class = None;
                match result {
                    Ok(()) => {
                        self.seq = seq;
                        self.generated += 1;
                        self.write_failures = 0;
                    }
                    Err(_) => self.write_failures += 1,
                }
                Activity::Worked
            }
        }
    }

    /// The generator's key as a pooled `KeyObject` (same layout as a
    /// generated SC-HSM key: PKCS#1 DER private key; public key
    /// `len(2, BE) || modulus || exponent`).
    fn pooled_object(&self, slot: u8, class: SizeClass, seq: u32) -> Option<KeyObject> {
        let mut obj = KeyObject::new(
            KmType::Rsa,
            pool_key_id(slot, class),
            pico2hsm_core::key::AppletId::ScHsm,
            AlgorithmId::RsaDecrypt,
        );
        obj.generation = seq;
        self.kg.write_der(&mut obj.private_key).ok()?;
        let mut modulus: heapless::Vec<u8, 512> = heapless::Vec::new();
        self.kg.write_modulus(&mut modulus).ok()?;
        let len = modulus.len() as u16;
        obj.public_key.extend_from_slice(&len.to_be_bytes()).ok()?;
        obj.public_key.extend_from_slice(&modulus).ok()?;
        obj.public_key
            .extend_from_slice(&crate::crypto::rsa_keygen::E.to_be_bytes()[1..])
            .ok()?;
        Some(obj)
    }

    /// A key for GENERATE, written into `out`: the newest in-age pooled key
    /// of the size, marked taken on flash before this returns; else a live
    /// one (the sliced generator run to completion — `live_budget` keeps
    /// the heartbeat up).  `out` is the caller's, so the key exists once on
    /// the core1 stack.
    pub fn issue(
        &mut self,
        store: &mut dyn KeyStore,
        key_type: CoreKeyType,
        rng: &mut dyn RngCore,
        uptime_min: u64,
        live_budget: &mut dyn Budget,
        out: &mut RsaKeyPair,
    ) -> Result<(), IssueError> {
        let class = SizeClass::of_key_type(key_type).ok_or(IssueError::Unsupported)?;
        self.ensure_loaded(store, uptime_min);
        let now = self.now(uptime_min);
        if self.config.enabled {
            if let Some(pool) = store.rsa_pool() {
                if self.take_pooled(pool, class, now, out)? {
                    self.issued += 1;
                    return Ok(());
                }
            }
        }
        self.generate_live(class, rng, live_budget, out)?;
        self.live += 1;
        Ok(())
    }

    /// Live generation (continues the background key if it is this size).
    #[inline(never)]
    fn generate_live(
        &mut self,
        class: SizeClass,
        rng: &mut dyn RngCore,
        live_budget: &mut dyn Budget,
        out: &mut RsaKeyPair,
    ) -> Result<(), IssueError> {
        if self.gen_class != Some(class) || !(self.kg.is_busy() || self.kg.is_ready()) {
            self.kg.start(class.bits());
            self.gen_class = Some(class);
        }
        let mut tries = 0;
        loop {
            match self.kg.step(rng, live_budget) {
                Poll::Ready => break,
                Poll::Pending => continue,
                Poll::Failed | Poll::Idle => {
                    tries += 1;
                    if tries >= 2 {
                        self.kg.reset();
                        self.gen_class = None;
                        return Err(IssueError::Generation);
                    }
                    self.kg.start(class.bits());
                }
            }
        }
        out.key_type = class.key_type();
        let ok = self.kg.write_der(&mut out.private_key_der).is_ok()
            && self.kg.write_modulus(&mut out.modulus).is_ok();
        self.kg.reset();
        self.gen_class = None;
        if ok && complete_pair(out) {
            Ok(())
        } else {
            out.zeroize();
            Err(IssueError::Generation)
        }
    }

    /// Take the newest usable pooled key of `class` into `out`.
    #[inline(never)]
    fn take_pooled(
        &mut self,
        pool: &mut dyn crate::storage::rsa_pool::PoolBackend,
        class: SizeClass,
        now: u64,
        out: &mut RsaKeyPair,
    ) -> Result<bool, IssueError> {
        for _ in 0..POOL_SLOTS {
            let Ok(slots) = pool.pool_slots() else {
                return Ok(false);
            };
            // Newest first.
            let mut best: Option<(usize, u32, u32)> = None;
            for (i, s) in slots.iter().enumerate() {
                if let SlotState::Valid {
                    class: c,
                    birth,
                    seq,
                } = *s
                {
                    if c == class
                        && self.in_age(now, birth)
                        && best.map_or(true, |(_, b, q)| (birth, seq) > (b, q))
                    {
                        best = Some((i, birth, seq));
                    }
                }
            }
            let Some((slot, _, _)) = best else {
                return Ok(false);
            };
            let slot = slot as u8;
            let usable = match pool.pool_get(slot) {
                Ok(mut obj) => {
                    let ok = pair_from_object(class.key_type(), &obj, out);
                    obj.zeroize();
                    ok
                }
                Err(_) => false,
            };
            if usable {
                // On flash before the key leaves: a power cut can waste it,
                // never issue it twice.
                if pool.pool_take(slot).is_err() {
                    out.zeroize();
                    return Err(IssueError::Storage);
                }
                return Ok(true);
            }
            // Unusable (corrupt, wrong key): retire it, try the next.
            out.zeroize();
            if pool.pool_erase(slot).is_err() && pool.pool_take(slot).is_err() {
                return Err(IssueError::Storage);
            }
        }
        Ok(false)
    }

    /// Change the configuration (SO-PIN checked by the caller).  Persisted
    /// first; turning the pool off then erases every pooled key.
    pub fn set_config(
        &mut self,
        store: &mut dyn KeyStore,
        cfg: PoolConfig,
        uptime_min: u64,
    ) -> Result<(), HsmError> {
        self.ensure_loaded(store, uptime_min);
        let log = store
            .retry_counters()
            .ok_or(HsmError::Storage(StorageError::NotFormatted))?;
        log.put_value(ValueId::PoolConfig, cfg.encode())
            .map_err(HsmError::Storage)?;
        self.config = cfg;
        self.write_failures = 0;
        if !cfg.enabled {
            self.wipe(store)?;
        }
        Ok(())
    }

    /// Erase every pooled key and drop the key in progress (pool off,
    /// INITIALIZE).  The config, clock and sequence number stay.
    pub fn wipe(&mut self, store: &mut dyn KeyStore) -> Result<(), HsmError> {
        self.kg.reset();
        self.gen_class = None;
        let Some(pool) = store.rsa_pool() else {
            return Ok(());
        };
        let slots = pool.pool_slots().map_err(HsmError::Storage)?;
        let mut result = Ok(());
        for (i, s) in slots.iter().enumerate() {
            if *s != SlotState::Blank {
                if let Err(e) = pool.pool_erase(i as u8) {
                    result = Err(e);
                }
            }
        }
        result
    }

    /// Status for the no-PIN status APDU.
    pub fn status(&mut self, store: &mut dyn KeyStore, uptime_min: u64) -> PoolStatus {
        self.ensure_loaded(store, uptime_min);
        let now = self.now(uptime_min);
        let mut ready = [0u8; 3];
        let mut present = false;
        if let Some(pool) = store.rsa_pool() {
            if let Ok(slots) = pool.pool_slots() {
                present = true;
                for s in slots {
                    if let SlotState::Valid { class, birth, .. } = s {
                        if self.config.enabled && self.in_age(now, birth) {
                            ready[class as usize] += 1;
                        }
                    }
                }
            }
        }
        let generating_bits = if self.kg.is_busy() {
            self.kg.nlen() as u16
        } else {
            0
        };
        PoolStatus {
            config: self.config,
            ready,
            generating_bits,
            clock_min: now,
            seq: self.seq,
            generated: self.generated,
            rotated: self.rotated,
            issued: self.issued,
            live: self.live,
            health: u8::from(self.rng_ok)
                | (u8::from(present) << 1)
                | (u8::from(self.write_failures >= MAX_WRITE_FAILURES) << 2),
        }
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

/// Fill in `out.public_key_der` and `out.exponent` for the DER key and
/// modulus already in `out`, after the `rsa` crate (an independent
/// big-integer implementation) has parsed and validated the key: `n = p·q`,
/// `d·e ≡ 1 (mod p−1, q−1)`, size, exponent, and the modulus matches.
fn complete_pair(out: &mut RsaKeyPair) -> bool {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    let Some(class) = SizeClass::of_key_type(out.key_type) else {
        return false;
    };
    let ok = match rsa::RsaPrivateKey::from_pkcs1_der(&out.private_key_der) {
        Ok(key) => {
            key.n().bits() == class.bits() as usize
                && key.e() == &rsa::BigUint::from(crate::crypto::rsa_keygen::E)
                && key.n().to_bytes_be() == out.modulus.as_slice()
        }
        Err(_) => false,
    };
    if !ok {
        return false;
    }
    out.exponent.clear();
    out.public_key_der.clear();
    out.exponent
        .extend_from_slice(&crate::crypto::rsa_keygen::E.to_be_bytes()[1..])
        .is_ok()
        && crate::crypto::asymmetric::build_pkcs1_pub_der(
            &out.modulus,
            &out.exponent,
            &mut out.public_key_der,
        )
        .is_ok()
}

/// A pooled `KeyObject` into `out` (validated as in [`complete_pair`]).
fn pair_from_object(key_type: CoreKeyType, obj: &KeyObject, out: &mut RsaKeyPair) -> bool {
    let pk = &obj.public_key;
    if pk.len() < 2 {
        return false;
    }
    let len = usize::from(u16::from_be_bytes([pk[0], pk[1]]));
    let (Some(modulus), Some(exp)) = (pk.get(2..2 + len), pk.get(2 + len..)) else {
        return false;
    };
    if exp != &crate::crypto::rsa_keygen::E.to_be_bytes()[1..] {
        return false;
    }
    out.key_type = key_type;
    out.private_key_der.clear();
    out.modulus.clear();
    if out
        .private_key_der
        .extend_from_slice(&obj.private_key)
        .is_err()
        || out.modulus.extend_from_slice(modulus).is_err()
    {
        return false;
    }
    complete_pair(out)
}

/// An empty key pair to fill.
pub fn empty_pair(key_type: CoreKeyType) -> RsaKeyPair {
    RsaKeyPair {
        key_type,
        private_key_der: heapless::Vec::new(),
        public_key_der: heapless::Vec::new(),
        modulus: heapless::Vec::new(),
        exponent: heapless::Vec::new(),
    }
}

// ─── The engine core1 uses ───────────────────────────────────────────────────

/// Never yields; bumps the watchdog heartbeat every unit (live keygen in an
/// APDU: core0's stall detector sees progress, no suppression needed).
pub struct Heartbeat;

impl Budget for Heartbeat {
    fn should_yield(&mut self) -> bool {
        crate::WATCHDOG_HEARTBEAT.fetch_add(1, Ordering::Relaxed);
        false
    }
}

/// The global engine (core1 only; the flag catches re-entry, and lets
/// parallel host tests take turns).
pub struct EngineCell {
    busy: AtomicBool,
    engine: UnsafeCell<Engine>,
}

// SAFETY: access only through `with_engine`, which hands out the `&mut`
// to one caller at a time (the `busy` flag).
unsafe impl Sync for EngineCell {}

/// The pool engine.
pub static ENGINE: EngineCell = EngineCell {
    busy: AtomicBool::new(false),
    engine: UnsafeCell::new(Engine::new()),
};

/// Run `f` with exclusive access to the engine.  On the device only core1
/// uses it, one call at a time, so this never waits; host tests running in
/// parallel take turns.
pub fn with_engine<R>(f: impl FnOnce(&mut Engine) -> R) -> R {
    while ENGINE
        .busy
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: the flag gives this call exclusive access.
    let r = f(unsafe { &mut *ENGINE.engine.get() });
    ENGINE.busy.store(false, Ordering::Release);
    r
}

/// Minutes of uptime (0 on the host).
pub fn uptime_min() -> u64 {
    u64::from(crate::uptime_secs()) / 60
}

/// One slice of idle-time work (core1, between APDUs).
pub fn background(store: &mut dyn KeyStore, budget: &mut dyn Budget) -> Activity {
    let up = uptime_min();
    with_engine(|e| e.background_step(store, &mut crate::protocol::sc_hsm::FwRng, up, budget))
}

/// The GENERATE path: a key for `key_type` from the pool or made live,
/// into `out`.
pub fn obtain(
    store: &mut dyn KeyStore,
    key_type: CoreKeyType,
    rng: &mut dyn RngCore,
    out: &mut RsaKeyPair,
) -> Result<(), IssueError> {
    let up = uptime_min();
    with_engine(|e| e.issue(store, key_type, rng, up, &mut Heartbeat, out))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::crypto::rsa_keygen::{Units, Unlimited};
    use crate::security::key_management::KeyObject;
    use crate::storage::retry_counter::{MemCounters, RetryCounterBackend};
    use crate::storage::rsa_pool::{MemPool, PoolBackend};
    use pico2hsm_core::key::{AppletId, KeyId};
    use std::boxed::Box;

    /// SplitMix64 test DRBG.
    struct TestRng(u64);
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn fill_bytes(&mut self, d: &mut [u8]) {
            for c in d.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                c.copy_from_slice(&v[..c.len()]);
            }
        }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(d);
            Ok(())
        }
    }

    /// Key store with a simulated pool region and counter log.
    struct Store {
        pool: MemPool,
        counters: MemCounters,
        has_pool: bool,
        /// Keys saved through `save_key`: (key_id, generation, use_count,
        /// private key, public key).
        saved: std::vec::Vec<(u32, u32, u32, std::vec::Vec<u8>, std::vec::Vec<u8>)>,
    }

    impl Store {
        fn new() -> Self {
            Store {
                pool: MemPool::new(),
                counters: MemCounters::default(),
                has_pool: true,
                saved: std::vec::Vec::new(),
            }
        }
        fn slots(&mut self) -> [SlotState; POOL_SLOTS] {
            self.pool.pool_slots().unwrap()
        }
        fn count(&mut self, class: SizeClass) -> usize {
            self.slots()
                .iter()
                .filter(|s| matches!(s, SlotState::Valid { class: c, .. } if *c == class))
                .count()
        }
    }

    impl KeyStore for Store {
        fn save_key(&mut self, o: &KeyObject) -> Result<(), HsmError> {
            self.saved.push((
                o.key_id,
                o.generation,
                o.use_count,
                o.private_key.to_vec(),
                o.public_key.to_vec(),
            ));
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
        fn enumerate_keys(&self) -> heapless::Vec<KeyId, 64> {
            heapless::Vec::new()
        }
        fn for_each_key(&self, _: &mut dyn FnMut(KeyId)) {}
        fn retry_counters(&mut self) -> Option<&mut dyn RetryCounterBackend> {
            Some(&mut self.counters)
        }
        fn rsa_pool(&mut self) -> Option<&mut dyn PoolBackend> {
            if self.has_pool {
                Some(&mut self.pool)
            } else {
                None
            }
        }
    }

    /// Small, fast config for most tests: 2048-bit only.
    fn small_cfg() -> PoolConfig {
        PoolConfig {
            depth: [2, 0, 0],
            ..PoolConfig::DEFAULT
        }
    }

    fn issue(
        e: &mut Engine,
        s: &mut Store,
        kt: CoreKeyType,
        rng: &mut TestRng,
        up: u64,
    ) -> Result<RsaKeyPair, IssueError> {
        let mut out = empty_pair(kt);
        e.issue(s, kt, rng, up, &mut Unlimited, &mut out)?;
        Ok(out)
    }

    fn engine() -> Box<Engine> {
        let mut e = Box::new(Engine::new());
        e.set_rng_ok(true);
        e
    }

    /// Run background steps until idle (bounded).
    fn settle(e: &mut Engine, s: &mut Store, rng: &mut TestRng, up: u64, slice: u32) -> u32 {
        for n in 0..200_000 {
            if e.background_step(s, rng, up, &mut Units(slice)) == Activity::Idle {
                return n;
            }
        }
        panic!("pool never settled");
    }

    /// SC-HSM GENERATE KEY PAIR (RSA-2048) through the real handler takes
    /// the newest pooled key, marks it taken, and stores it as a fresh key.
    #[test]
    fn sc_hsm_generate_issues_the_newest_pooled_key() {
        use crate::protocol::sc_hsm::ScHsm;
        let mut s = Store::new();
        let mut rng = TestRng(21);
        let newest = with_engine(|e| {
            e.reboot();
            e.set_rng_ok(true);
            e.set_config(&mut s, small_cfg(), 0).unwrap();
            settle(e, &mut s, &mut rng, 0, 5000);
            let slots = s.slots();
            let (_, slot) = slots
                .iter()
                .enumerate()
                .filter_map(|(i, x)| match x {
                    SlotState::Valid { seq, .. } => Some((*seq, i)),
                    _ => None,
                })
                .max()
                .unwrap();
            slot
        });
        let pooled = s.pool.pool_get(newest as u8).unwrap();
        let pooled_pub = pooled.public_key.to_vec();
        let pooled_der = pooled.private_key.to_vec();
        drop(pooled);

        let mut hsm = ScHsm::new();
        hsm.state.initialized = true;
        hsm.state.pin_verified = true;
        // OpenSC's RSA-2048 request: CPI 0, modulus size in 7F49.
        let data = [
            0x5F, 0x29, 0x01, 0x00, 0x7F, 0x49, 0x04, 0x02, 0x02, 0x08, 0x00,
        ];
        let mut a = std::vec![0x00, 0x46, 0x05, 0x00, data.len() as u8];
        a.extend_from_slice(&data);
        let r = hsm.process_apdu_with_store(&a, &mut s);
        assert_eq!(&r[r.len() - 2..], &[0x90, 0x00]);
        // The CVC carries the pooled modulus.
        let modulus = &pooled_pub[2..2 + 256];
        assert!(r.windows(256).any(|w| w == modulus));
        // Taken on flash; stored under the requested reference exactly as
        // a fresh key (same private / public encoding, counters at zero).
        assert_eq!(s.slots()[newest], SlotState::Taken);
        let (kid, generation, uses, der, public) = s.saved.last().unwrap().clone();
        assert_eq!(kid, pico2hsm_core::key::KeyId::sc_hsm(0, 5).0);
        assert_eq!((generation, uses), (0, 0));
        assert_eq!(der, pooled_der);
        assert_eq!(public, pooled_pub);
        // Numbered like any keygen.
        assert_eq!(s.counters.lamport, 1);
        with_engine(|e| assert_eq!(e.status(&mut s, 0).issued, 1));
    }

    #[test]
    fn config_round_trips_and_validates() {
        let c = PoolConfig::DEFAULT;
        assert_eq!(PoolConfig::decode(c.encode()), Some(c));
        assert_eq!(PoolConfig::from_bytes(&c.to_bytes()), Some(c));
        assert_eq!(PoolConfig::from_bytes(&[0x04, 0, 0, 0, 60, 1, 1, 1]), None);
        assert_eq!(PoolConfig::from_bytes(&[0x03, 0, 0, 0, 59, 1, 1, 1]), None);
        assert_eq!(PoolConfig::from_bytes(&[0x03, 0, 0, 0, 60, 5, 1, 1]), None);
        assert_eq!(PoolConfig::from_bytes(&[0x03, 0, 0, 0, 60, 1, 1]), None);
        let off = PoolConfig::from_bytes(&[0x00, 0, 0, 0x01, 0x00, 0, 0, 0]).unwrap();
        assert!(!off.enabled && !off.rotate);
    }

    #[test]
    fn waits_for_the_rng() {
        let mut e = Box::new(Engine::new());
        let mut s = Store::new();
        let mut rng = TestRng(1);
        assert_eq!(
            e.background_step(&mut s, &mut rng, 0, &mut Unlimited),
            Activity::Idle
        );
    }

    #[test]
    fn fills_to_depth_then_idles_and_issues_newest_first() {
        let mut e = engine();
        let mut s = Store::new();
        let mut rng = TestRng(2);
        e.set_config(&mut s, small_cfg(), 0).unwrap();
        settle(&mut e, &mut s, &mut rng, 0, 5000);
        assert_eq!(s.count(SizeClass::R2048), 2);
        assert_eq!(s.count(SizeClass::R4096), 0);
        let st = e.status(&mut s, 0);
        assert_eq!(st.ready, [2, 0, 0]);
        assert_eq!(st.generated, 2);
        // Issue: the newest (highest seq) slot is taken on flash first.
        let newest = s
            .slots()
            .iter()
            .enumerate()
            .filter_map(|(i, x)| match x {
                SlotState::Valid { seq, .. } => Some((*seq, i)),
                _ => None,
            })
            .max()
            .unwrap()
            .1;
        let pair = issue(&mut e, &mut s, CoreKeyType::RsaPrivate2048, &mut rng, 0).unwrap();
        assert_eq!(pair.modulus.len(), 256);
        assert_eq!(s.slots()[newest], SlotState::Taken);
        assert_eq!(e.status(&mut s, 0).issued, 1);
        // The background erases the taken slot and refills.
        settle(&mut e, &mut s, &mut rng, 0, 5000);
        assert_eq!(s.count(SizeClass::R2048), 2);
        assert!(!s.slots().contains(&SlotState::Taken));
    }

    #[test]
    fn issued_key_signs_and_verifies() {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        use rsa::signature::{SignatureEncoding, Signer, Verifier};
        let mut e = engine();
        let mut s = Store::new();
        let mut rng = TestRng(3);
        e.set_config(&mut s, small_cfg(), 0).unwrap();
        settle(&mut e, &mut s, &mut rng, 0, 5000);
        let pair = issue(&mut e, &mut s, CoreKeyType::RsaPrivate2048, &mut rng, 0).unwrap();
        // Sign through the firmware's own path, verify with the public key.
        use sha2::Digest;
        let hash = sha2::Sha256::digest(b"pool");
        let sig = crate::crypto::asymmetric::rsa_sign_pkcs1v15(
            CoreKeyType::RsaPrivate2048,
            &pair.private_key_der,
            &hash,
            crate::crypto::asymmetric::HashAlgorithm::Sha256,
            &mut rng,
        )
        .unwrap();
        let key = rsa::RsaPrivateKey::from_pkcs1_der(&pair.private_key_der).unwrap();
        key.to_public_key()
            .verify(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &hash, &sig)
            .unwrap();
        use rsa::traits::PublicKeyParts;
        assert_eq!(key.n().to_bytes_be(), pair.modulus.to_vec());
    }

    #[test]
    fn a_key_is_never_issued_twice_even_across_power_cuts() {
        let mut e = engine();
        let mut s = Store::new();
        let mut rng = TestRng(4);
        e.set_config(&mut s, small_cfg(), 0).unwrap();
        settle(&mut e, &mut s, &mut rng, 0, 5000);
        let mut seen = std::collections::HashSet::new();
        for round in 0..6 {
            // Cut power right after a take, at every point the take can be
            // interrupted: the key is either still pooled (and was not
            // returned) or taken for good.
            s.pool.region.flash_mut().program_budget = Some(round % 3);
            let r = issue(&mut e, &mut s, CoreKeyType::RsaPrivate2048, &mut rng, 0);
            s.pool.reboot();
            e.reboot();
            match r {
                Ok(p) => assert!(seen.insert(p.modulus.to_vec()), "issued twice"),
                Err(err) => assert_eq!(err, IssueError::Storage),
            }
            // Whatever is still Valid on flash was never returned.
            for i in 0..POOL_SLOTS {
                if matches!(s.slots()[i], SlotState::Valid { .. }) {
                    let obj = s.pool.pool_get(i as u8).unwrap();
                    let mut m = empty_pair(CoreKeyType::RsaPrivate2048);
                    assert!(pair_from_object(CoreKeyType::RsaPrivate2048, &obj, &mut m));
                    assert!(!seen.contains(&m.modulus.to_vec()));
                }
            }
            settle(&mut e, &mut s, &mut rng, 0, 5000);
        }
        assert!(seen.len() >= 3);
    }

    #[test]
    fn take_failure_fails_closed() {
        let mut e = engine();
        let mut s = Store::new();
        let mut rng = TestRng(5);
        e.set_config(&mut s, small_cfg(), 0).unwrap();
        settle(&mut e, &mut s, &mut rng, 0, 5000);
        s.pool.fail_take = true;
        assert_eq!(
            issue(&mut e, &mut s, CoreKeyType::RsaPrivate2048, &mut rng, 0).err(),
            Some(IssueError::Storage)
        );
        assert_eq!(s.count(SizeClass::R2048), 2);
    }

    #[test]
    fn empty_pool_falls_back_to_live_generation() {
        let mut e = engine();
        let mut s = Store::new();
        let mut rng = TestRng(6);
        e.set_config(&mut s, small_cfg(), 0).unwrap();
        // Nothing generated yet: live.
        let p = issue(&mut e, &mut s, CoreKeyType::RsaPrivate2048, &mut rng, 0).unwrap();
        assert_eq!(p.modulus.len(), 256);
        assert_eq!(e.status(&mut s, 0).live, 1);
        // No pool region at all: live too.
        s.has_pool = false;
        assert!(issue(&mut e, &mut s, CoreKeyType::RsaPrivate2048, &mut rng, 0).is_ok());
        // Not a pooled size.
        assert_eq!(
            issue(&mut e, &mut s, CoreKeyType::EcPrivateP256, &mut rng, 0).err(),
            Some(IssueError::Unsupported)
        );
    }

    #[test]
    fn live_generation_continues_the_background_key() {
        let mut e = engine();
        let mut s = Store::new();
        let mut rng = TestRng(7);
        e.set_config(&mut s, small_cfg(), 0).unwrap();
        // Part of a 2048-bit key in the background...
        for _ in 0..20 {
            e.background_step(&mut s, &mut rng, 0, &mut Units(500));
        }
        assert!(e.kg.is_busy());
        let units_before = e.kg.stats.units;
        assert!(units_before > 0);
        // ... the pool is still empty, GENERATE finishes that key.
        issue(&mut e, &mut s, CoreKeyType::RsaPrivate2048, &mut rng, 0).unwrap();
        assert!(!e.kg.is_busy());
    }

    #[test]
    fn rotation_retires_old_keys_and_never_issues_them() {
        let mut e = engine();
        let mut s = Store::new();
        let mut rng = TestRng(8);
        let cfg = PoolConfig {
            max_age_min: 60,
            ..small_cfg()
        };
        e.set_config(&mut s, cfg, 0).unwrap();
        settle(&mut e, &mut s, &mut rng, 0, 5000);
        let before: std::vec::Vec<_> = s.slots().to_vec();
        // 59 minutes: still in age.
        assert_eq!(e.status(&mut s, 59).ready, [2, 0, 0]);
        // 61 minutes: out of age — not issuable, and rotated away.
        assert_eq!(e.status(&mut s, 61).ready, [0, 0, 0]);
        let n = settle(&mut e, &mut s, &mut rng, 61, 5000);
        assert!(n > 0);
        assert_eq!(e.status(&mut s, 61).ready, [2, 0, 0]);
        assert!(e.status(&mut s, 61).rotated >= 2);
        for (i, st) in s.slots().iter().enumerate() {
            if let SlotState::Valid { birth, .. } = st {
                assert!(*birth >= 61, "slot {i} still holds an old key");
            }
        }
        assert_ne!(before, s.slots().to_vec());
        // Age-out without rotation: an over-age key is still not issued
        // when rotation is on but has not run yet.
        let p = issue(&mut e, &mut s, CoreKeyType::RsaPrivate2048, &mut rng, 200).unwrap();
        assert_eq!(e.status(&mut s, 200).live, 1);
        assert_eq!(p.modulus.len(), 256);
    }

    #[test]
    fn rotation_off_keeps_keys() {
        let mut e = engine();
        let mut s = Store::new();
        let mut rng = TestRng(9);
        let cfg = PoolConfig {
            rotate: false,
            ..small_cfg()
        };
        e.set_config(&mut s, cfg, 0).unwrap();
        settle(&mut e, &mut s, &mut rng, 0, 5000);
        let before = s.slots();
        // Only the clock is persisted.
        assert!(settle(&mut e, &mut s, &mut rng, 100_000, 5000) <= 1);
        assert_eq!(before, s.slots());
        assert_eq!(e.status(&mut s, 100_000).ready, [2, 0, 0]);
    }

    #[test]
    fn clock_survives_reboots() {
        let mut e = engine();
        let mut s = Store::new();
        let mut rng = TestRng(10);
        e.set_config(
            &mut s,
            PoolConfig {
                max_age_min: 60,
                ..small_cfg()
            },
            0,
        )
        .unwrap();
        settle(&mut e, &mut s, &mut rng, 0, 5000);
        // 40 powered-on minutes, then a reboot (uptime restarts at 0).
        settle(&mut e, &mut s, &mut rng, 40, 5000);
        e.reboot();
        assert_eq!(e.status(&mut s, 0).clock_min, 40);
        // 25 more minutes after the reboot: 65 > 60, the keys age out.
        assert_eq!(e.status(&mut s, 25).ready, [0, 0, 0]);
    }

    #[test]
    fn turning_the_pool_off_wipes_it_and_keygen_still_works() {
        let mut e = engine();
        let mut s = Store::new();
        let mut rng = TestRng(11);
        e.set_config(&mut s, small_cfg(), 0).unwrap();
        settle(&mut e, &mut s, &mut rng, 0, 5000);
        assert_eq!(s.count(SizeClass::R2048), 2);
        let off = PoolConfig {
            enabled: false,
            ..small_cfg()
        };
        e.set_config(&mut s, off, 0).unwrap();
        assert_eq!(s.slots(), [SlotState::Blank; POOL_SLOTS]);
        assert_eq!(settle(&mut e, &mut s, &mut rng, 0, 5000), 0);
        assert_eq!(s.slots(), [SlotState::Blank; POOL_SLOTS]);
        // Persisted: after a reboot the pool stays off.
        e.reboot();
        assert!(!e.config(&mut s, 0).enabled);
        assert_eq!(settle(&mut e, &mut s, &mut rng, 0, 5000), 0);
        assert_eq!(s.slots(), [SlotState::Blank; POOL_SLOTS]);
        // Live keygen still works.
        assert!(issue(&mut e, &mut s, CoreKeyType::RsaPrivate2048, &mut rng, 0).is_ok());
        // Config write failure: refused, nothing changes.
        s.counters.fail_values = true;
        assert!(e.set_config(&mut s, small_cfg(), 0).is_err());
        assert!(!e.config(&mut s, 0).enabled);
    }

    #[test]
    fn lower_depth_trims_and_wipe_clears() {
        let mut e = engine();
        let mut s = Store::new();
        let mut rng = TestRng(12);
        e.set_config(
            &mut s,
            PoolConfig {
                depth: [3, 0, 0],
                ..PoolConfig::DEFAULT
            },
            0,
        )
        .unwrap();
        settle(&mut e, &mut s, &mut rng, 0, 5000);
        assert_eq!(s.count(SizeClass::R2048), 3);
        e.set_config(
            &mut s,
            PoolConfig {
                depth: [1, 0, 0],
                ..PoolConfig::DEFAULT
            },
            0,
        )
        .unwrap();
        settle(&mut e, &mut s, &mut rng, 0, 5000);
        assert_eq!(s.count(SizeClass::R2048), 1);
        e.wipe(&mut s).unwrap();
        assert_eq!(s.slots(), [SlotState::Blank; POOL_SLOTS]);
    }

    #[test]
    fn interrupted_background_key_is_the_same_key() {
        // Slicing at every unit vs. large slices: identical pooled moduli.
        let run = |slice: u32| {
            let mut e = engine();
            let mut s = Store::new();
            let mut rng = TestRng(13);
            e.set_config(
                &mut s,
                PoolConfig {
                    depth: [1, 0, 0],
                    ..PoolConfig::DEFAULT
                },
                0,
            )
            .unwrap();
            settle(&mut e, &mut s, &mut rng, 0, slice);
            let slot = s
                .slots()
                .iter()
                .position(|x| matches!(x, SlotState::Valid { .. }))
                .unwrap();
            s.pool.pool_get(slot as u8).unwrap().public_key.to_vec()
        };
        assert_eq!(run(1), run(1_000_000));
    }

    #[test]
    fn a_reset_mid_generation_recovers() {
        let mut e = engine();
        let mut s = Store::new();
        let mut rng = TestRng(14);
        e.set_config(&mut s, small_cfg(), 0).unwrap();
        for _ in 0..50 {
            e.background_step(&mut s, &mut rng, 0, &mut Units(300));
        }
        // Power cut: RAM progress lost, flash consistent.
        s.pool.reboot();
        e.reboot();
        settle(&mut e, &mut s, &mut rng, 0, 5000);
        assert_eq!(s.count(SizeClass::R2048), 2);
    }

    #[test]
    fn corrupt_pooled_key_is_retired_not_issued() {
        let mut e = engine();
        let mut s = Store::new();
        let mut rng = TestRng(15);
        e.set_config(&mut s, small_cfg(), 0).unwrap();
        settle(&mut e, &mut s, &mut rng, 0, 5000);
        // Corrupt the ciphertext of every pooled key but keep the CRC
        // consistent: decryption (GCM) must catch it.
        let sector = crate::storage::flash_layout::SECTOR as usize;
        for i in 0..POOL_SLOTS {
            if matches!(s.slots()[i], SlotState::Valid { .. }) {
                let data = &mut s.pool.region.flash_mut().data;
                data[i * sector + 100] ^= 0x01;
                // Recompute the slot CRC.
                let len = u16::from_le_bytes([data[i * sector + 6], data[i * sector + 7]]) as usize;
                let mut h = crc32fast::Hasher::new();
                h.update(&data[i * sector..i * sector + 16]);
                h.update(&data[i * sector + 32..i * sector + 32 + len]);
                let c = h.finalize().to_le_bytes();
                data[i * sector + 16..i * sector + 20].copy_from_slice(&c);
            }
        }
        s.pool.reboot();
        e.reboot();
        let p = issue(&mut e, &mut s, CoreKeyType::RsaPrivate2048, &mut rng, 0).unwrap();
        let st = e.status(&mut s, 0);
        assert_eq!((st.issued, st.live), (0, 1));
        assert_eq!(p.modulus.len(), 256);
        assert_eq!(s.count(SizeClass::R2048), 0);
    }
}
