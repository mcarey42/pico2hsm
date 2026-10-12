//! Credential retry counters — an append-only log in dedicated flash sectors.
//!
//! # Why a separate store
//! Every credential check spends a retry on flash *before* comparing (see
//! `with_persisted_attempt` in each applet), and a success restores it.
//! When the counters lived in the PIN records, each of those writes re-saved
//! a keystore object and rewrote a keystore directory copy: about 100k
//! VERIFYs wore the directory sectors out (audit R2-4).  Here a failed
//! attempt programs one 16-byte record into an erased slot (NOR
//! program-without-erase, 1→0 only); a success programs one more.  A sector
//! is erased only when it is full.
//!
//! # Counter model
//! Per credential the log keeps a [`CounterState`]:
//!
//! ```text
//! remaining = allowance − (failures_total − failures_at_reset)
//! ```
//!
//! `failures_total` only ever grows.  A success, CHANGE, unblock or applet
//! reset never lowers it: it records `failures_at_reset = failures_total`
//! and a fresh `allowance`.  That split is what lets a later firmware back
//! `failures_total` with an OTP unary counter (see [`RetryCounterBackend`]),
//! after which restoring an old flash image can only *reduce* the
//! remaining tries.
//!
//! # On-flash format (version 1)
//! The region is [`flash_layout::RETRY_COUNTER_SECTORS`] sectors of 256
//! slots × 16 bytes.  Slot 0 of a sector is its header; slots 1–255 hold
//! records.  Erased flash reads 0xFF; a slot that is all 0xFF is free.
//!
//! ```text
//! header  [0..4] "P2RC"  [4..8] seq (u32 LE)  [8] version (1)
//!         [9..12] 0x00   [12..16] CRC-32 of [0..12]
//! record  [0] 0x52 'R'   [1] credential id    [2] allowance
//!         [3] 0x00       [4..8] failures_total (u32 LE)
//!         [8..12] failures_at_reset (u32 LE)
//!         [12..16] CRC-32 of (seq LE || [0..12])
//! ```
//!
//! A second record kind holds the domain **Lamport counter** (cluster plan
//! V3 §6.1), the `u64` that numbers every local change:
//!
//! ```text
//! lamport [0] 0x4C 'L'   [1] counter id (1)   [2..4] 0x00
//!         [4..12] value (u64 LE)
//!         [12..16] CRC-32 of (seq LE || [0..12])
//! ```
//!
//! It never goes down ([`RetryCounterBackend::put_lamport`] refuses a lower
//! value) and is carried over when a full sector is rotated, exactly like
//! the credential states.  Firmware from before the counter skips these
//! records (unknown tag) and drops them at its next rotation, which only a
//! downgrade can cause (rollback is out of scope, plan §2).
//!
//! The same record layout, with other counter ids, holds the RSA key
//! pool's device values ([`ValueId`]): its clock and sequence number
//! (monotonic, like the Lamport counter) and its configuration (not
//! monotonic).  Firmware that only knows id 1 skips them.
//!
//! Records carry absolute values, so the last valid record per credential
//! is its state and a duplicated record is harmless.  The record CRC is
//! bound to the sector's sequence number.  The active sector is the one
//! with the highest valid header `seq`; records are appended at the slot
//! after the last non-0xFF one.
//!
//! # Power-cut safety
//! - A torn record fails its CRC and is skipped (its slot is never reused);
//!   the credential keeps its previous state.  A failure is recorded
//!   *before* the compare, so a cut while recording it means no compare
//!   happened; a cut while recording a success costs the user a try.
//! - When the active sector is full, the current states are written to the
//!   next sector (erased first, checked blank) and its header — the commit
//!   — is programmed *last*.  Until the header is valid that sector is
//!   ignored and the old, full sector stays authoritative.  The active
//!   sector is never erased, and a failed commit retries with a higher
//!   `seq` in another sector.
//!
//! # Migration
//! A region with no valid header at all is *unformatted*.  At boot the
//! dispatcher seeds it once from the retry counts in the existing PIN
//! records (`Dispatcher::migrate_retry_counters`), then zeroes those counts
//! in the records.  From then on the log is authoritative: a credential
//! whose PIN record exists but which has no counter entry loads blocked.

use pico2hsm_core::error::{HsmError, StorageError};

use crate::storage::KeyStore;

// ─── Credentials ─────────────────────────────────────────────────────────────

/// A credential whose retry counter lives in the log.  The discriminant is
/// its on-flash id and must never change.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credential {
    /// SC-HSM user PIN.
    ScHsmUserPin = 0x01,
    /// SC-HSM SO-PIN (also authorises re-INITIALIZE).
    ScHsmSoPin = 0x02,
    /// SC-HSM PUK.
    ScHsmPuk = 0x03,
    /// PIV PIN.
    PivPin = 0x11,
    /// PIV PUK.
    PivPuk = 0x12,
    /// OpenPGP PW1 (user).
    OpenPgpPw1 = 0x21,
    /// OpenPGP PW3 (admin).
    OpenPgpPw3 = 0x22,
}

/// Capacity of the in-RAM index (one slot per known credential).
pub const MAX_CREDENTIALS: usize = 8;

impl Credential {
    /// Every credential, in index order.
    pub const ALL: [Credential; 7] = [
        Credential::ScHsmUserPin,
        Credential::ScHsmSoPin,
        Credential::ScHsmPuk,
        Credential::PivPin,
        Credential::PivPuk,
        Credential::OpenPgpPw1,
        Credential::OpenPgpPw3,
    ];

    /// The credential with on-flash id `id`.
    pub fn from_id(id: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|c| *c as u8 == id)
    }

    /// Position in [`Self::ALL`] (the in-RAM index slot).
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|c| *c == self).unwrap_or(0)
    }
}

const _: () = assert!(Credential::ALL.len() <= MAX_CREDENTIALS);

// ─── Counter state ───────────────────────────────────────────────────────────

/// One credential's counter (see the module docs for the model).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CounterState {
    /// Failed attempts ever recorded.  Monotonic.
    pub failures_total: u32,
    /// `failures_total` at the last success / change / unblock / reset.
    pub failures_at_reset: u32,
    /// Tries granted at that reset.
    pub allowance: u8,
}

impl CounterState {
    /// A credential nobody has tried yet, with `allowance` tries.
    pub const fn fresh(allowance: u8) -> Self {
        CounterState {
            failures_total: 0,
            failures_at_reset: 0,
            allowance,
        }
    }

    /// Tries left: `allowance − (failures_total − failures_at_reset)`,
    /// never negative.  A snapshot above the total cannot be produced by
    /// this firmware; it reads as blocked rather than as extra tries.
    pub fn remaining(&self) -> u8 {
        let Some(spent) = self.failures_total.checked_sub(self.failures_at_reset) else {
            return 0;
        };
        u32::from(self.allowance).saturating_sub(spent) as u8
    }

    /// The state after one more failed attempt (`None` on counter overflow,
    /// which callers treat as a storage failure: fail closed).
    pub fn after_failure(&self) -> Option<Self> {
        Some(CounterState {
            failures_total: self.failures_total.checked_add(1)?,
            ..*self
        })
    }

    /// The state with `remaining` tries left from now on.
    pub fn after_reset(&self, remaining: u8) -> Self {
        CounterState {
            failures_total: self.failures_total,
            failures_at_reset: self.failures_total,
            allowance: remaining,
        }
    }
}

// ─── Backend boundary ────────────────────────────────────────────────────────

/// Where credential counter states are kept.
///
/// Today: [`CounterLog`] on internal flash.  This is also the seam for a
/// rollback-resistant backend: an OTP unary counter per credential would
/// hold `failures_total` (OTP bits can only be burned, never cleared),
/// while `failures_at_reset` and `allowance` stay in this flash log.  Such
/// a backend would wrap `CounterLog`: `put` burns OTP bits up to the new
/// `failures_total` *before* writing the flash record, and `get` reports
/// `failures_total = max(flash, otp)`.  Restoring an old flash image then
/// brings back an old `failures_at_reset` against a total that kept
/// growing, so `remaining` can only go down.  Callers need no change.
pub trait RetryCounterBackend {
    /// The credential's state; `Ok(None)` if the log has no entry for it.
    fn get(&mut self, cred: Credential) -> Result<Option<CounterState>, StorageError>;

    /// Durably record `state` for `cred`.  Refuses to lower
    /// `failures_total`.  Returns only once the record is on flash.
    fn put(&mut self, cred: Credential, state: CounterState) -> Result<(), StorageError>;

    /// The log holds no valid sector yet (first boot after the upgrade, or
    /// a blank device): [`Self::format`] must seed it.
    fn needs_migration(&mut self) -> bool;

    /// Initialise an unformatted log with `seeds` (migration only).
    fn format(&mut self, seeds: &[(Credential, CounterState)]) -> Result<(), StorageError>;

    /// The persisted domain Lamport counter (0 if never written).
    fn lamport(&mut self) -> Result<u64, StorageError>;

    /// Durably set the Lamport counter to `value`.  Refuses to lower it
    /// (`IntegrityFailure`); writing the current value is a no-op.
    /// Returns only once the record is on flash.
    fn put_lamport(&mut self, value: u64) -> Result<(), StorageError>;

    /// A persisted device value (`Ok(None)`: never written).  Backends
    /// without value records report `NotFormatted`.
    fn value(&mut self, id: ValueId) -> Result<Option<u64>, StorageError> {
        let _ = id;
        Err(StorageError::NotFormatted)
    }

    /// Durably set a device value.  Monotonic ids ([`ValueId::monotonic`])
    /// refuse a lower value (`IntegrityFailure`); writing the current
    /// value is a no-op.  Returns only once the record is on flash.
    fn put_value(&mut self, id: ValueId, value: u64) -> Result<(), StorageError> {
        let _ = (id, value);
        Err(StorageError::WriteError)
    }
}

/// A 64-bit device value kept in the log next to the Lamport counter.
/// The discriminant is the record's counter id and must never change.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueId {
    /// The domain Lamport counter (also [`RetryCounterBackend::lamport`]).
    Lamport = 0x01,
    /// RSA key pool clock: minutes of powered-on pool time (monotonic).
    PoolClock = 0x02,
    /// RSA key pool configuration (`rsa_pool::PoolConfig`, not monotonic).
    PoolConfig = 0x03,
    /// RSA key pool sequence number of the last pooled key (monotonic).
    PoolSeq = 0x04,
}

/// Number of [`ValueId`]s (the in-RAM value table).
pub const MAX_VALUES: usize = 4;

impl ValueId {
    /// Every value, in table order (`id − 1`).
    pub const ALL: [ValueId; MAX_VALUES] = [
        ValueId::Lamport,
        ValueId::PoolClock,
        ValueId::PoolConfig,
        ValueId::PoolSeq,
    ];

    /// The value with record id `id`.
    pub fn from_id(id: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|v| *v as u8 == id)
    }

    /// Slot in the in-RAM table.
    pub fn index(self) -> usize {
        self as usize - 1
    }

    /// Whether the value may only grow.
    pub fn monotonic(self) -> bool {
        !matches!(self, ValueId::PoolConfig)
    }
}

// ─── Applet-facing helpers ───────────────────────────────────────────────────

fn backend(store: &mut dyn KeyStore) -> Result<&mut dyn RetryCounterBackend, HsmError> {
    store
        .retry_counters()
        .ok_or(HsmError::Storage(StorageError::NotFormatted))
}

/// Tries left for `cred`, or `Ok(None)` if the log has no entry for it.
pub fn remaining(store: &mut dyn KeyStore, cred: Credential) -> Result<Option<u8>, HsmError> {
    Ok(backend(store)?.get(cred)?.map(|s| s.remaining()))
}

/// Tries left for `cred` as an applet should load them:
/// - the log's entry if there is one;
/// - `fresh` if there is none and no credential record exists (a fresh,
///   never-used applet);
/// - otherwise 0 — a record without a counter entry after migration, or an
///   unreadable log, fails closed.
pub fn load(store: &mut dyn KeyStore, cred: Credential, record_exists: bool, fresh: u8) -> u8 {
    match remaining(store, cred) {
        Ok(Some(n)) => n,
        Ok(None) if !record_exists => fresh,
        _ => 0,
    }
}

/// Spend one try of `cred` before its credential is compared.
///
/// Returns the tries that were available *before* this attempt; 0 means
/// blocked and nothing was written (the caller must not compare).
/// Otherwise the failure is on flash when this returns.  A credential the
/// log does not know yet starts from `current` (the applet's RAM count).
pub fn spend(store: &mut dyn KeyStore, cred: Credential, current: u8) -> Result<u8, HsmError> {
    let log = backend(store)?;
    let state = log.get(cred)?.unwrap_or(CounterState::fresh(current));
    let available = state.remaining();
    if available == 0 {
        return Ok(0);
    }
    let spent = state
        .after_failure()
        .ok_or(HsmError::Storage(StorageError::WriteError))?;
    log.put(cred, spent)?;
    Ok(available)
}

/// Durably set `cred` to `remaining` tries (success, change, unblock or
/// reset).  Writes nothing if the log already says so.
pub fn set(store: &mut dyn KeyStore, cred: Credential, remaining: u8) -> Result<(), HsmError> {
    let log = backend(store)?;
    let current = log.get(cred)?;
    if current.map(|s| s.remaining()) == Some(remaining) {
        return Ok(());
    }
    log.put(cred, current.unwrap_or_default().after_reset(remaining))?;
    Ok(())
}

/// The persisted domain Lamport counter (cluster plan V3 §6.1).
pub fn lamport(store: &mut dyn KeyStore) -> Result<u64, HsmError> {
    Ok(backend(store)?.lamport()?)
}

/// Number a local change: `max(counter, seen) + 1`, durably on flash
/// *before* this returns, so the change it numbers can only follow it.
/// `seen` is the highest version observed in a record from another member
/// (0 until records are imported, P3).  Overflow fails closed.
pub fn advance_lamport(store: &mut dyn KeyStore, seen: u64) -> Result<u64, HsmError> {
    let log = backend(store)?;
    let next = log
        .lamport()?
        .max(seen)
        .checked_add(1)
        .ok_or(HsmError::Storage(StorageError::WriteError))?;
    log.put_lamport(next)?;
    Ok(next)
}

// ─── Flash access ────────────────────────────────────────────────────────────

/// Raw access to the counter region.  Offsets are relative to its start.
pub trait CounterFlash {
    /// Read `buf.len()` bytes at `offset`.
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), StorageError>;
    /// Program `data` at `offset` without erasing (bits only go 1→0).
    fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError>;
    /// Erase sector `sector` of the region to 0xFF.
    fn erase_sector(&mut self, sector: u32) -> Result<(), StorageError>;
}

/// Bytes per slot (header or record).
pub const SLOT_SIZE: usize = 16;
/// Slots per 4 KiB sector (slot 0 is the header).
pub const SLOTS_PER_SECTOR: u16 = (pico2hsm_core::flash::SECTOR_SIZE / SLOT_SIZE) as u16;

const HEADER_MAGIC: [u8; 4] = *b"P2RC";
const FORMAT_VERSION: u8 = 1;
const RECORD_TAG: u8 = 0x52;
/// Tag of a Lamport-counter / device-value record.
const LAMPORT_TAG: u8 = 0x4C;
/// Program attempts (each in a new slot) before a write is reported failed.
const WRITE_ATTEMPTS: usize = 3;

fn crc(seq: Option<u32>, body: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    if let Some(seq) = seq {
        h.update(&seq.to_le_bytes());
    }
    h.update(body);
    h.finalize()
}

fn encode_header(seq: u32) -> [u8; SLOT_SIZE] {
    let mut b = [0u8; SLOT_SIZE];
    b[0..4].copy_from_slice(&HEADER_MAGIC);
    b[4..8].copy_from_slice(&seq.to_le_bytes());
    b[8] = FORMAT_VERSION;
    let c = crc(None, &b[0..12]);
    b[12..16].copy_from_slice(&c.to_le_bytes());
    b
}

fn decode_header(b: &[u8; SLOT_SIZE]) -> Option<u32> {
    let ok = b[0..4] == HEADER_MAGIC
        && b[8] == FORMAT_VERSION
        && b[12..16] == crc(None, &b[0..12]).to_le_bytes();
    ok.then(|| u32::from_le_bytes([b[4], b[5], b[6], b[7]]))
}

fn encode_record(seq: u32, cred: Credential, s: &CounterState) -> [u8; SLOT_SIZE] {
    let mut b = [0u8; SLOT_SIZE];
    b[0] = RECORD_TAG;
    b[1] = cred as u8;
    b[2] = s.allowance;
    b[4..8].copy_from_slice(&s.failures_total.to_le_bytes());
    b[8..12].copy_from_slice(&s.failures_at_reset.to_le_bytes());
    let c = crc(Some(seq), &b[0..12]);
    b[12..16].copy_from_slice(&c.to_le_bytes());
    b
}

fn decode_record(seq: u32, b: &[u8; SLOT_SIZE]) -> Option<(Credential, CounterState)> {
    if b[0] != RECORD_TAG || b[12..16] != crc(Some(seq), &b[0..12]).to_le_bytes() {
        return None;
    }
    let word = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    let state = CounterState {
        failures_total: word(4),
        failures_at_reset: word(8),
        allowance: b[2],
    };
    Some((Credential::from_id(b[1])?, state))
}

fn encode_value(seq: u32, id: ValueId, value: u64) -> [u8; SLOT_SIZE] {
    let mut b = [0u8; SLOT_SIZE];
    b[0] = LAMPORT_TAG;
    b[1] = id as u8;
    b[4..12].copy_from_slice(&value.to_le_bytes());
    let c = crc(Some(seq), &b[0..12]);
    b[12..16].copy_from_slice(&c.to_le_bytes());
    b
}

fn decode_value(seq: u32, b: &[u8; SLOT_SIZE]) -> Option<(ValueId, u64)> {
    if b[0] != LAMPORT_TAG || b[12..16] != crc(Some(seq), &b[0..12]).to_le_bytes() {
        return None;
    }
    let id = ValueId::from_id(b[1])?;
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[4..12]);
    Some((id, u64::from_le_bytes(v)))
}

/// The values carried by a sector rotation.
type Values = [Option<u64>; MAX_VALUES];

fn is_erased(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0xFF)
}

// ─── CounterLog ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LogState {
    /// No sector has a valid header.
    Unformatted,
    /// `sector` (header `seq`) is current; `head` is its next free slot.
    Active { sector: u32, seq: u32, head: u16 },
    /// The region could not be read at boot: every access fails closed.
    Failed,
}

/// The append-only retry-counter log over a [`CounterFlash`] region.
///
/// The index of current states is kept in RAM (a few dozen bytes); no
/// sector buffer is ever held, all flash access is slot-sized.
pub struct CounterLog<F: CounterFlash> {
    flash: F,
    sectors: u32,
    state: LogState,
    /// Next header `seq` to commit (above every one ever seen or tried).
    next_seq: u32,
    entries: [Option<CounterState>; MAX_CREDENTIALS],
    /// Device values by `ValueId::index` (`None`: never written); index 0
    /// is the domain Lamport counter.
    values: Values,
}

impl<F: CounterFlash> CounterLog<F> {
    /// Scan the region (`sectors` ≥ 2 sectors) and build the index.
    pub fn open(flash: F, sectors: u32) -> Self {
        let mut log = CounterLog {
            flash,
            sectors,
            state: LogState::Failed,
            next_seq: 1,
            entries: [None; MAX_CREDENTIALS],
            values: [None; MAX_VALUES],
        };
        log.state = log.scan().unwrap_or(LogState::Failed);
        log
    }

    /// The underlying flash (tests inspect it).
    pub fn flash_mut(&mut self) -> &mut F {
        &mut self.flash
    }

    fn slot_offset(sector: u32, slot: u16) -> u32 {
        sector * pico2hsm_core::flash::SECTOR_SIZE as u32 + u32::from(slot) * SLOT_SIZE as u32
    }

    fn read_slot(&mut self, sector: u32, slot: u16) -> Result<[u8; SLOT_SIZE], StorageError> {
        let mut b = [0u8; SLOT_SIZE];
        self.flash.read(Self::slot_offset(sector, slot), &mut b)?;
        Ok(b)
    }

    fn scan(&mut self) -> Result<LogState, StorageError> {
        let mut best: Option<(u32, u32)> = None;
        for sector in 0..self.sectors {
            if let Some(seq) = decode_header(&self.read_slot(sector, 0)?) {
                self.next_seq = self.next_seq.max(seq.saturating_add(1));
                if best.map_or(true, |(_, s)| seq > s) {
                    best = Some((sector, seq));
                }
            }
        }
        let Some((sector, seq)) = best else {
            return Ok(LogState::Unformatted);
        };
        let mut head = 1;
        for slot in 1..SLOTS_PER_SECTOR {
            let b = self.read_slot(sector, slot)?;
            if is_erased(&b) {
                continue;
            }
            head = slot + 1;
            if let Some((cred, state)) = decode_record(seq, &b) {
                self.entries[cred.index()] = Some(state);
            } else if let Some((id, v)) = decode_value(seq, &b) {
                // Monotonic values: a torn-then-rewritten history can only
                // hold them in increasing order, but never trust that.
                // Others: the last record wins.
                let slot = &mut self.values[id.index()];
                *slot = Some(match *slot {
                    Some(old) if id.monotonic() => old.max(v),
                    _ => v,
                });
            }
        }
        Ok(LogState::Active { sector, seq, head })
    }

    /// Program `data` into one slot and read it back.
    fn program_slot(
        &mut self,
        sector: u32,
        slot: u16,
        data: &[u8; SLOT_SIZE],
    ) -> Result<(), StorageError> {
        self.flash.program(Self::slot_offset(sector, slot), data)?;
        if self.read_slot(sector, slot)? == *data {
            Ok(())
        } else {
            Err(StorageError::WriteError)
        }
    }

    /// Write `entries` into a freshly erased `sector` and commit it with a
    /// header carrying `seq`.  Returns the next free slot.
    fn write_sector(
        &mut self,
        sector: u32,
        seq: u32,
        entries: &[Option<CounterState>; MAX_CREDENTIALS],
        values: &Values,
    ) -> Result<u16, StorageError> {
        self.flash.erase_sector(sector)?;
        for slot in 0..SLOTS_PER_SECTOR {
            if !is_erased(&self.read_slot(sector, slot)?) {
                return Err(StorageError::EraseError);
            }
        }
        let mut slot = 1;
        for cred in Credential::ALL {
            if let Some(state) = entries[cred.index()] {
                self.program_slot(sector, slot, &encode_record(seq, cred, &state))?;
                slot += 1;
            }
        }
        for id in ValueId::ALL {
            if let Some(v) = values[id.index()] {
                self.program_slot(sector, slot, &encode_value(seq, id, v))?;
                slot += 1;
            }
        }
        // The commit point: until this header reads back valid, the sector
        // is ignored and the previous one stays authoritative.
        self.program_slot(sector, 0, &encode_header(seq))?;
        Ok(slot)
    }

    /// Commit `entries` to a sector other than `avoid`, trying each in turn.
    fn commit(
        &mut self,
        avoid: Option<u32>,
        entries: &[Option<CounterState>; MAX_CREDENTIALS],
        values: &Values,
    ) -> Result<(), StorageError> {
        let start = avoid.map_or(0, |a| a + 1);
        let mut last = Err(StorageError::WriteError);
        for k in 0..self.sectors {
            let sector = (start + k) % self.sectors;
            if Some(sector) == avoid {
                continue;
            }
            // A failed attempt may still have left a (possibly valid)
            // header behind: never reuse its seq.
            let seq = self.next_seq;
            self.next_seq = seq.checked_add(1).ok_or(StorageError::WriteError)?;
            match self.write_sector(sector, seq, entries, values) {
                Ok(head) => {
                    self.entries = *entries;
                    self.values = *values;
                    self.state = LogState::Active { sector, seq, head };
                    return Ok(());
                }
                Err(e) => last = Err(e),
            }
        }
        last
    }
}

impl<F: CounterFlash> RetryCounterBackend for CounterLog<F> {
    fn get(&mut self, cred: Credential) -> Result<Option<CounterState>, StorageError> {
        match self.state {
            LogState::Active { .. } => Ok(self.entries[cred.index()]),
            LogState::Unformatted => Err(StorageError::NotFormatted),
            LogState::Failed => Err(StorageError::ReadError),
        }
    }

    fn put(&mut self, cred: Credential, new: CounterState) -> Result<(), StorageError> {
        let i = cred.index();
        if let Some(old) = self.entries[i] {
            if new.failures_total < old.failures_total {
                return Err(StorageError::IntegrityFailure);
            }
            if new == old && matches!(self.state, LogState::Active { .. }) {
                return Ok(());
            }
        }
        let mut attempts = 0;
        loop {
            let LogState::Active { sector, seq, head } = self.state else {
                return Err(match self.state {
                    LogState::Unformatted => StorageError::NotFormatted,
                    _ => StorageError::ReadError,
                });
            };
            if head >= SLOTS_PER_SECTOR {
                // Full: carry every state, the new one included, over to
                // the next sector.
                let mut entries = self.entries;
                entries[i] = Some(new);
                let values = self.values;
                return self.commit(Some(sector), &entries, &values);
            }
            // Whatever happens, this slot is used up (a torn write leaves
            // it neither erased nor valid).
            self.state = LogState::Active {
                sector,
                seq,
                head: head + 1,
            };
            match self.program_slot(sector, head, &encode_record(seq, cred, &new)) {
                Ok(()) => {
                    self.entries[i] = Some(new);
                    return Ok(());
                }
                Err(e) => {
                    attempts += 1;
                    if attempts >= WRITE_ATTEMPTS {
                        return Err(e);
                    }
                }
            }
        }
    }

    fn needs_migration(&mut self) -> bool {
        self.state == LogState::Unformatted
    }

    fn format(&mut self, seeds: &[(Credential, CounterState)]) -> Result<(), StorageError> {
        if self.state != LogState::Unformatted {
            return Err(StorageError::WriteError);
        }
        let mut entries = [None; MAX_CREDENTIALS];
        for (cred, state) in seeds {
            entries[cred.index()] = Some(*state);
        }
        self.commit(None, &entries, &[None; MAX_VALUES])
    }

    fn lamport(&mut self) -> Result<u64, StorageError> {
        Ok(self.value(ValueId::Lamport)?.unwrap_or(0))
    }

    fn put_lamport(&mut self, value: u64) -> Result<(), StorageError> {
        self.put_value(ValueId::Lamport, value)
    }

    fn value(&mut self, id: ValueId) -> Result<Option<u64>, StorageError> {
        match self.state {
            LogState::Active { .. } => Ok(self.values[id.index()]),
            LogState::Unformatted => Err(StorageError::NotFormatted),
            LogState::Failed => Err(StorageError::ReadError),
        }
    }

    fn put_value(&mut self, id: ValueId, value: u64) -> Result<(), StorageError> {
        if let Some(old) = self.values[id.index()] {
            if id.monotonic() && value < old {
                return Err(StorageError::IntegrityFailure);
            }
            if value == old && matches!(self.state, LogState::Active { .. }) {
                return Ok(());
            }
        }
        let mut attempts = 0;
        loop {
            let LogState::Active { sector, seq, head } = self.state else {
                return Err(match self.state {
                    LogState::Unformatted => StorageError::NotFormatted,
                    _ => StorageError::ReadError,
                });
            };
            if head >= SLOTS_PER_SECTOR {
                let entries = self.entries;
                let mut values = self.values;
                values[id.index()] = Some(value);
                return self.commit(Some(sector), &entries, &values);
            }
            self.state = LogState::Active {
                sector,
                seq,
                head: head + 1,
            };
            match self.program_slot(sector, head, &encode_value(seq, id, value)) {
                Ok(()) => {
                    self.values[id.index()] = Some(value);
                    return Ok(());
                }
                Err(e) => {
                    attempts += 1;
                    if attempts >= WRITE_ATTEMPTS {
                        return Err(e);
                    }
                }
            }
        }
    }
}

// ─── In-memory backend (host tests) ──────────────────────────────────────────

/// A RAM-only [`RetryCounterBackend`] for host-side tests of the applets.
#[derive(Clone, Debug, Default)]
pub struct MemCounters {
    /// Current states, by `Credential::index`.
    pub entries: [Option<CounterState>; MAX_CREDENTIALS],
    /// Every successful `put`, in order.
    pub puts: heapless::Vec<(Credential, CounterState), 64>,
    /// Fail the `put` with this index (0-based, counting attempts).
    pub fail_put: Option<usize>,
    /// Fail every `put` from now on.
    pub fail_all: bool,
    /// `put` attempts so far.
    pub attempts: usize,
    /// Report "not yet formatted" until `format` is called.
    pub unformatted: bool,
    /// The Lamport counter.
    pub lamport: u64,
    /// Fail every `put_lamport`.
    pub fail_lamport: bool,
    /// Device values other than the Lamport counter, by `ValueId::index`.
    pub values: [Option<u64>; MAX_VALUES],
    /// Fail every `put_value` (other than the Lamport counter).
    pub fail_values: bool,
}

impl MemCounters {
    /// Current remaining tries of `cred` (`None` if no entry).
    pub fn remaining(&self, cred: Credential) -> Option<u8> {
        self.entries[cred.index()].map(|s| s.remaining())
    }
}

impl RetryCounterBackend for MemCounters {
    fn get(&mut self, cred: Credential) -> Result<Option<CounterState>, StorageError> {
        if self.unformatted {
            return Err(StorageError::NotFormatted);
        }
        Ok(self.entries[cred.index()])
    }

    fn put(&mut self, cred: Credential, state: CounterState) -> Result<(), StorageError> {
        let attempt = self.attempts;
        self.attempts += 1;
        if self.unformatted || self.fail_all || self.fail_put == Some(attempt) {
            return Err(StorageError::WriteError);
        }
        if let Some(old) = self.entries[cred.index()] {
            if state.failures_total < old.failures_total {
                return Err(StorageError::IntegrityFailure);
            }
        }
        self.entries[cred.index()] = Some(state);
        let _ = self.puts.push((cred, state));
        Ok(())
    }

    fn needs_migration(&mut self) -> bool {
        self.unformatted
    }

    fn format(&mut self, seeds: &[(Credential, CounterState)]) -> Result<(), StorageError> {
        if !self.unformatted {
            return Err(StorageError::WriteError);
        }
        for (cred, state) in seeds {
            self.entries[cred.index()] = Some(*state);
        }
        self.unformatted = false;
        Ok(())
    }

    fn lamport(&mut self) -> Result<u64, StorageError> {
        if self.unformatted {
            return Err(StorageError::NotFormatted);
        }
        Ok(self.lamport)
    }

    fn put_lamport(&mut self, value: u64) -> Result<(), StorageError> {
        if self.unformatted || self.fail_lamport {
            return Err(StorageError::WriteError);
        }
        if value < self.lamport {
            return Err(StorageError::IntegrityFailure);
        }
        self.lamport = value;
        Ok(())
    }

    fn value(&mut self, id: ValueId) -> Result<Option<u64>, StorageError> {
        if self.unformatted {
            return Err(StorageError::NotFormatted);
        }
        if id == ValueId::Lamport {
            return Ok(Some(self.lamport));
        }
        Ok(self.values[id.index()])
    }

    fn put_value(&mut self, id: ValueId, value: u64) -> Result<(), StorageError> {
        if id == ValueId::Lamport {
            return self.put_lamport(value);
        }
        if self.unformatted || self.fail_values {
            return Err(StorageError::WriteError);
        }
        if let Some(old) = self.values[id.index()] {
            if id.monotonic() && value < old {
                return Err(StorageError::IntegrityFailure);
            }
        }
        self.values[id.index()] = Some(value);
        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use pico2hsm_core::flash::SECTOR_SIZE;
    use std::vec;
    use std::vec::Vec;

    const SECTORS: u32 = 4;

    /// NOR flash simulator: program ANDs bits in, erase sets 0xFF.  It can
    /// cut power after a number of programmed bytes / erases, leaving the
    /// interrupted operation half done.
    #[derive(Clone)]
    struct SimFlash {
        mem: Vec<u8>,
        /// Bytes that may still be programmed before the power is cut.
        program_budget: Option<usize>,
        /// Erases allowed before the power is cut (mid-erase).
        erase_budget: Option<usize>,
        erases: Vec<u32>,
        programs: usize,
        dead: bool,
        /// Slot offsets whose programming silently does nothing.
        stuck: Vec<u32>,
    }

    impl SimFlash {
        fn new() -> Self {
            SimFlash {
                mem: vec![0xFF; SECTORS as usize * SECTOR_SIZE],
                program_budget: None,
                erase_budget: None,
                erases: Vec::new(),
                programs: 0,
                dead: false,
                stuck: Vec::new(),
            }
        }
        /// Power back on: same contents, no fault armed.
        fn reboot(&self) -> Self {
            SimFlash {
                program_budget: None,
                erase_budget: None,
                dead: false,
                ..self.clone()
            }
        }
    }

    impl CounterFlash for SimFlash {
        fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), StorageError> {
            let o = offset as usize;
            buf.copy_from_slice(&self.mem[o..o + buf.len()]);
            Ok(())
        }
        fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError> {
            if self.dead {
                return Err(StorageError::WriteError);
            }
            self.programs += 1;
            if self.stuck.contains(&offset) {
                return Ok(());
            }
            for (i, &d) in data.iter().enumerate() {
                if let Some(b) = self.program_budget.as_mut() {
                    if *b == 0 {
                        self.dead = true;
                        return Err(StorageError::WriteError);
                    }
                    *b -= 1;
                }
                self.mem[offset as usize + i] &= d;
            }
            Ok(())
        }
        fn erase_sector(&mut self, sector: u32) -> Result<(), StorageError> {
            if self.dead {
                return Err(StorageError::EraseError);
            }
            let start = sector as usize * SECTOR_SIZE;
            if let Some(b) = self.erase_budget.as_mut() {
                if *b == 0 {
                    // Cut mid-erase: only the first half came back to 0xFF.
                    self.mem[start..start + SECTOR_SIZE / 2].fill(0xFF);
                    self.dead = true;
                    return Err(StorageError::EraseError);
                }
                *b -= 1;
            }
            self.erases.push(sector);
            self.mem[start..start + SECTOR_SIZE].fill(0xFF);
            Ok(())
        }
    }

    fn open(flash: SimFlash) -> CounterLog<SimFlash> {
        CounterLog::open(flash, SECTORS)
    }

    fn formatted() -> CounterLog<SimFlash> {
        let mut log = open(SimFlash::new());
        assert!(log.needs_migration());
        log.format(&[]).unwrap();
        log
    }

    fn reopen(log: &mut CounterLog<SimFlash>) -> CounterLog<SimFlash> {
        open(log.flash_mut().reboot())
    }

    const PIN: Credential = Credential::ScHsmUserPin;

    // ── Counter model ───────────────────────────────────────────────────

    #[test]
    fn remaining_is_allowance_minus_failures_since_reset() {
        let s = CounterState::fresh(3);
        assert_eq!(s.remaining(), 3);
        let s = s.after_failure().unwrap().after_failure().unwrap();
        assert_eq!((s.failures_total, s.remaining()), (2, 1));
        let s = s.after_failure().unwrap().after_failure().unwrap();
        assert_eq!(s.remaining(), 0, "never below zero");
        let r = s.after_reset(3);
        assert_eq!(
            (r.failures_total, r.failures_at_reset, r.remaining()),
            (4, 4, 3),
            "a reset keeps the total, moves the snapshot"
        );
        assert_eq!(r.after_failure().unwrap().remaining(), 2);
        assert_eq!(r.after_reset(0).remaining(), 0, "reset to blocked");
    }

    #[test]
    fn rolled_back_snapshot_only_reduces_remaining() {
        // The OTP-backed model: the total comes from OTP and keeps growing;
        // an old flash image brings back an old snapshot.
        let old_flash = CounterState {
            failures_total: 10,
            failures_at_reset: 10,
            allowance: 3,
        };
        let otp_total = 12;
        let restored = CounterState {
            failures_total: otp_total,
            ..old_flash
        };
        assert_eq!(restored.remaining(), 1);
        assert!(restored.remaining() <= old_flash.remaining());
    }

    #[test]
    fn snapshot_above_total_reads_blocked() {
        let s = CounterState {
            failures_total: 1,
            failures_at_reset: 2,
            allowance: 3,
        };
        assert_eq!(s.remaining(), 0);
    }

    #[test]
    fn total_overflow_fails_closed() {
        let s = CounterState {
            failures_total: u32::MAX,
            failures_at_reset: u32::MAX,
            allowance: 3,
        };
        assert_eq!(s.after_failure(), None);
    }

    // ── Lamport counter ─────────────────────────────────────────────────

    #[test]
    fn lamport_persists_and_never_goes_down() {
        let mut log = formatted();
        assert_eq!(log.lamport(), Ok(0));
        log.put_lamport(5).unwrap();
        log.put(PIN, CounterState::fresh(3)).unwrap();
        log.put_lamport(7).unwrap();
        assert_eq!(log.put_lamport(6), Err(StorageError::IntegrityFailure));
        let mut again = reopen(&mut log);
        assert_eq!(again.lamport(), Ok(7));
        assert_eq!(again.get(PIN), Ok(Some(CounterState::fresh(3))));
        let programs = again.flash_mut().programs;
        again.put_lamport(7).unwrap();
        assert_eq!(again.flash_mut().programs, programs, "same value: no write");
    }

    #[test]
    fn lamport_survives_sector_rotation() {
        let mut log = formatted();
        log.put(PIN, CounterState::fresh(3)).unwrap();
        // Several sectors' worth of increments.
        for v in 1..=(3 * u64::from(SLOTS_PER_SECTOR)) {
            log.put_lamport(v).unwrap();
        }
        let n = 3 * u64::from(SLOTS_PER_SECTOR);
        let mut again = reopen(&mut log);
        assert_eq!(again.lamport(), Ok(n));
        assert_eq!(again.get(PIN), Ok(Some(CounterState::fresh(3))));
        // A credential write that rotates keeps the counter too.
        for _ in 0..SLOTS_PER_SECTOR {
            let s = again.get(PIN).unwrap().unwrap().after_reset(3);
            again.put(PIN, s.after_failure().unwrap()).unwrap();
        }
        assert_eq!(reopen(&mut again).lamport(), Ok(n));
    }

    #[test]
    fn torn_lamport_record_keeps_the_previous_value() {
        let mut log = formatted();
        log.put_lamport(3).unwrap();
        log.flash_mut().program_budget = Some(5);
        assert!(log.put_lamport(4).is_err());
        assert_eq!(reopen(&mut log).lamport(), Ok(3));
    }

    #[test]
    fn device_values_persist_rotate_and_keep_their_rules() {
        let mut log = formatted();
        log.put(PIN, CounterState::fresh(3)).unwrap();
        assert_eq!(log.value(ValueId::PoolClock), Ok(None));
        log.put_value(ValueId::PoolClock, 10).unwrap();
        log.put_value(ValueId::PoolConfig, 0xAB).unwrap();
        log.put_value(ValueId::PoolConfig, 0x01).unwrap(); // not monotonic
        assert_eq!(
            log.put_value(ValueId::PoolClock, 9),
            Err(StorageError::IntegrityFailure)
        );
        log.put_lamport(4).unwrap();
        assert_eq!(log.value(ValueId::Lamport), Ok(Some(4)));
        let mut again = reopen(&mut log);
        assert_eq!(again.value(ValueId::PoolClock), Ok(Some(10)));
        assert_eq!(again.value(ValueId::PoolConfig), Ok(Some(0x01)));
        // Carried over by sector rotations.
        for i in 0..(2 * SLOTS_PER_SECTOR as u64) {
            again.put_value(ValueId::PoolClock, 11 + i).unwrap();
        }
        let mut third = reopen(&mut again);
        assert_eq!(
            third.value(ValueId::PoolClock),
            Ok(Some(10 + 2 * SLOTS_PER_SECTOR as u64))
        );
        assert_eq!(third.value(ValueId::PoolConfig), Ok(Some(0x01)));
        assert_eq!(third.lamport(), Ok(4));
        assert_eq!(third.get(PIN), Ok(Some(CounterState::fresh(3))));
    }

    #[test]
    fn unknown_value_ids_are_skipped() {
        let mut log = formatted();
        let LogState::Active { sector, seq, head } = log.state else {
            panic!()
        };
        let mut rec = encode_value(seq, ValueId::PoolClock, 5);
        rec[1] = 0x7F;
        let c = crc(Some(seq), &rec[0..12]);
        rec[12..16].copy_from_slice(&c.to_le_bytes());
        log.program_slot(sector, head, &rec).unwrap();
        let mut again = reopen(&mut log);
        assert_eq!(again.value(ValueId::PoolClock), Ok(None));
        assert_eq!(again.lamport(), Ok(0));
    }

    #[test]
    fn unformatted_log_has_no_counter() {
        let mut log = open(SimFlash::new());
        assert_eq!(log.lamport(), Err(StorageError::NotFormatted));
        assert_eq!(log.put_lamport(1), Err(StorageError::NotFormatted));
    }

    // ── Log format ──────────────────────────────────────────────────────

    #[test]
    fn records_round_trip() {
        let s = CounterState {
            failures_total: 0x0102_0304,
            failures_at_reset: 0x0A0B_0C0D,
            allowance: 7,
        };
        let r = encode_record(9, Credential::PivPuk, &s);
        assert_eq!(decode_record(9, &r), Some((Credential::PivPuk, s)));
        assert_eq!(decode_record(10, &r), None, "bound to the sector seq");
        assert_eq!(decode_header(&encode_header(42)), Some(42));
    }

    #[test]
    fn blank_region_needs_migration_and_refuses_access() {
        let mut log = open(SimFlash::new());
        assert!(log.needs_migration());
        assert_eq!(log.get(PIN), Err(StorageError::NotFormatted));
        assert!(log.put(PIN, CounterState::fresh(3)).is_err());
    }

    #[test]
    fn garbage_region_is_unformatted_not_trusted() {
        let mut flash = SimFlash::new();
        for (i, b) in flash.mem.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        let mut log = open(flash);
        assert!(log.needs_migration());
        log.format(&[(PIN, CounterState::fresh(2))]).unwrap();
        assert_eq!(reopen(&mut log).get(PIN), Ok(Some(CounterState::fresh(2))));
    }

    #[test]
    fn append_and_scan() {
        let mut log = formatted();
        assert_eq!(log.get(PIN), Ok(None));
        let mut s = CounterState::fresh(3);
        log.put(PIN, s).unwrap();
        s = s.after_failure().unwrap();
        log.put(PIN, s).unwrap();
        log.put(Credential::OpenPgpPw3, CounterState::fresh(3))
            .unwrap();
        let mut again = reopen(&mut log);
        assert_eq!(again.get(PIN), Ok(Some(s)));
        assert_eq!(
            again.get(Credential::OpenPgpPw3),
            Ok(Some(CounterState::fresh(3)))
        );
        assert_eq!(again.get(Credential::PivPin), Ok(None));
    }

    #[test]
    fn a_failure_costs_one_program_and_no_erase() {
        let mut log = formatted();
        log.put(PIN, CounterState::fresh(3)).unwrap();
        let (programs, erases) = (log.flash.programs, log.flash.erases.len());
        let s = log.get(PIN).unwrap().unwrap().after_failure().unwrap();
        log.put(PIN, s).unwrap();
        assert_eq!(log.flash.programs, programs + 1);
        assert_eq!(log.flash.erases.len(), erases);
    }

    #[test]
    fn unchanged_state_writes_nothing() {
        let mut log = formatted();
        log.put(PIN, CounterState::fresh(3)).unwrap();
        let programs = log.flash.programs;
        log.put(PIN, CounterState::fresh(3)).unwrap();
        assert_eq!(log.flash.programs, programs);
    }

    #[test]
    fn failures_total_never_goes_down() {
        let mut log = formatted();
        let s = CounterState::fresh(3).after_failure().unwrap();
        log.put(PIN, s).unwrap();
        assert_eq!(
            log.put(PIN, CounterState::fresh(3)),
            Err(StorageError::IntegrityFailure)
        );
        assert_eq!(log.get(PIN), Ok(Some(s)));
    }

    #[test]
    fn full_sector_rotates_and_compacts() {
        let mut log = formatted();
        let mut s = CounterState::fresh(3);
        log.put(Credential::PivPin, CounterState::fresh(5)).unwrap();
        // Enough appends to fill several sectors.
        for i in 0..(3 * SLOTS_PER_SECTOR as u32) {
            s = if i % 2 == 0 {
                s.after_failure().unwrap()
            } else {
                s.after_reset(3)
            };
            log.put(PIN, s).unwrap();
        }
        assert!(log.flash.erases.len() >= 3, "rotated through sectors");
        let LogState::Active { head, .. } = log.state else {
            panic!("not active");
        };
        assert!(head < SLOTS_PER_SECTOR);
        let mut again = reopen(&mut log);
        assert_eq!(again.get(PIN), Ok(Some(s)));
        assert_eq!(
            again.get(Credential::PivPin),
            Ok(Some(CounterState::fresh(5))),
            "carried over by compaction"
        );
    }

    #[test]
    fn active_sector_is_never_erased() {
        let mut log = formatted();
        let mut s = CounterState::fresh(3);
        let mut rotations = 0;
        for _ in 0..(5 * SLOTS_PER_SECTOR as u32) {
            let LogState::Active { sector: active, .. } = log.state else {
                panic!("not active");
            };
            let erases = log.flash.erases.len();
            s = s.after_failure().unwrap();
            log.put(PIN, s).unwrap();
            for e in &log.flash.erases[erases..] {
                assert_ne!(*e, active, "erased the current sector");
                rotations += 1;
            }
        }
        assert!(rotations >= 4);
    }

    #[test]
    fn torn_record_is_skipped_and_its_slot_not_reused() {
        let mut log = formatted();
        let s1 = CounterState::fresh(3);
        log.put(PIN, s1).unwrap();
        // Power cut 5 bytes into the next record.
        log.flash.program_budget = Some(5);
        let s2 = s1.after_failure().unwrap();
        assert!(log.put(PIN, s2).is_err());
        let mut again = reopen(&mut log);
        assert_eq!(again.get(PIN), Ok(Some(s1)), "previous state survives");
        // The next append goes after the torn slot and is readable.
        again.put(PIN, s2).unwrap();
        assert_eq!(reopen(&mut again).get(PIN), Ok(Some(s2)));
    }

    #[test]
    fn power_cut_at_every_byte_of_a_failure_never_gains_a_try() {
        // Cut the power after every possible number of programmed bytes
        // while a failed attempt is being recorded: after reboot the
        // credential has either the old count (and the compare never ran)
        // or the spent one — never more.
        for budget in 0..=SLOT_SIZE {
            let mut log = formatted();
            log.put(PIN, CounterState::fresh(3)).unwrap();
            log.flash.program_budget = Some(budget);
            let spent = CounterState::fresh(3).after_failure().unwrap();
            let wrote = log.put(PIN, spent).is_ok();
            let after = reopen(&mut log).get(PIN).unwrap().unwrap();
            if wrote {
                assert_eq!(after, spent, "budget {budget}");
            } else {
                assert!(after == spent || after.remaining() == 3, "budget {budget}");
            }
            assert!(after.remaining() <= 3);
        }
    }

    /// Fill the active sector so that the next put compacts.
    fn fill_sector(log: &mut CounterLog<SimFlash>, s: &mut CounterState) {
        loop {
            let LogState::Active { head, .. } = log.state else {
                panic!()
            };
            if head >= SLOTS_PER_SECTOR {
                return;
            }
            *s = s.after_failure().unwrap().after_reset(3);
            log.put(PIN, *s).unwrap();
        }
    }

    #[test]
    fn power_cut_during_compaction_keeps_old_sector() {
        // Cut at every program step of a compaction: before its header is
        // valid the old (full) sector is still current; afterwards the new
        // one holds every state.
        for budget in 0..(4 * SLOT_SIZE) {
            let mut log = formatted();
            log.put(Credential::PivPuk, CounterState::fresh(3)).unwrap();
            let mut s = CounterState::fresh(3);
            fill_sector(&mut log, &mut s);
            let old = s;
            let new = s.after_failure().unwrap();
            log.flash.program_budget = Some(budget);
            let wrote = log.put(PIN, new).is_ok();
            let mut again = reopen(&mut log);
            let got = again.get(PIN).unwrap().unwrap();
            assert!(got == old || got == new, "budget {budget}");
            if wrote {
                assert_eq!(got, new);
            }
            assert_eq!(
                again.get(Credential::PivPuk),
                Ok(Some(CounterState::fresh(3))),
                "budget {budget}"
            );
            // The log keeps working after the cut.
            let next = got.after_failure().unwrap();
            again.put(PIN, next).unwrap();
            assert_eq!(reopen(&mut again).get(PIN), Ok(Some(next)));
        }
    }

    #[test]
    fn power_cut_mid_erase_keeps_old_sector() {
        let mut log = formatted();
        let mut s = CounterState::fresh(3);
        fill_sector(&mut log, &mut s);
        log.flash.erase_budget = Some(0);
        assert!(log.put(PIN, s.after_failure().unwrap()).is_err());
        let mut again = reopen(&mut log);
        assert_eq!(again.get(PIN), Ok(Some(s)));
        let next = s.after_failure().unwrap();
        again.put(PIN, next).unwrap();
        assert_eq!(reopen(&mut again).get(PIN), Ok(Some(next)));
    }

    #[test]
    fn power_cut_during_format_leaves_it_unformatted() {
        for budget in 0..(3 * SLOT_SIZE) {
            let mut flash = SimFlash::new();
            flash.program_budget = Some(budget);
            let mut log = open(flash);
            let seeds = [
                (PIN, CounterState::fresh(1)),
                (Credential::ScHsmSoPin, CounterState::fresh(4)),
            ];
            let ok = log.format(&seeds).is_ok();
            let mut again = reopen(&mut log);
            if ok {
                assert_eq!(again.get(PIN), Ok(Some(CounterState::fresh(1))));
            } else {
                // Either nothing committed (migrate again next boot) or
                // the whole seed set did.
                match again.get(PIN) {
                    Err(StorageError::NotFormatted) => assert!(again.needs_migration()),
                    Ok(Some(s)) => {
                        assert_eq!(s, CounterState::fresh(1));
                        assert_eq!(
                            again.get(Credential::ScHsmSoPin),
                            Ok(Some(CounterState::fresh(4)))
                        );
                    }
                    other => panic!("budget {budget}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn failed_verify_moves_to_the_next_slot() {
        let mut log = formatted();
        log.put(PIN, CounterState::fresh(3)).unwrap();
        let LogState::Active { sector, head, .. } = log.state else {
            panic!()
        };
        // The next slot doesn't take the write.
        let bad = CounterLog::<SimFlash>::slot_offset(sector, head);
        log.flash.stuck.push(bad);
        let s = CounterState::fresh(3).after_failure().unwrap();
        log.put(PIN, s).unwrap();
        assert_eq!(reopen(&mut log).get(PIN), Ok(Some(s)));
    }

    #[test]
    fn worn_sector_is_skipped_by_compaction() {
        let mut log = formatted();
        let mut s = CounterState::fresh(3);
        fill_sector(&mut log, &mut s);
        let LogState::Active { sector, .. } = log.state else {
            panic!()
        };
        // The next sector's header slot never programs.
        let next = (sector + 1) % SECTORS;
        let bad = CounterLog::<SimFlash>::slot_offset(next, 0);
        log.flash.stuck.push(bad);
        let n = s.after_failure().unwrap();
        log.put(PIN, n).unwrap();
        let LogState::Active { sector: now, .. } = log.state else {
            panic!()
        };
        assert_ne!(now, next);
        assert_eq!(reopen(&mut log).get(PIN), Ok(Some(n)));
    }

    #[test]
    fn highest_seq_wins_across_sectors() {
        let mut log = formatted();
        let mut s = CounterState::fresh(3);
        fill_sector(&mut log, &mut s);
        let n = s.after_failure().unwrap();
        log.put(PIN, n).unwrap();
        // Both the full old sector and the new one have valid headers.
        let headers = (0..SECTORS)
            .filter(|&k| decode_header(&log.read_slot(k, 0).unwrap()).is_some())
            .count();
        assert_eq!(headers, 2);
        assert_eq!(reopen(&mut log).get(PIN), Ok(Some(n)));
    }

    // ── Helpers over a KeyStore ─────────────────────────────────────────

    #[test]
    fn spend_and_set_through_a_store() {
        let mut store = crate::storage::NullKeyStore;
        // NullKeyStore keeps no counters: every read says "no entry".
        assert_eq!(remaining(&mut store, PIN), Ok(None));
        let mut mem = MemCounterStore::default();
        assert_eq!(spend(&mut mem, PIN, 3), Ok(3));
        assert_eq!(remaining(&mut mem, PIN), Ok(Some(2)));
        set(&mut mem, PIN, 3).unwrap();
        assert_eq!(remaining(&mut mem, PIN), Ok(Some(3)));
        let puts = mem.counters.puts.len();
        set(&mut mem, PIN, 3).unwrap();
        assert_eq!(mem.counters.puts.len(), puts, "no-op when unchanged");
        // Blocked: nothing written, nothing to compare.
        set(&mut mem, PIN, 0).unwrap();
        let puts = mem.counters.puts.len();
        assert_eq!(spend(&mut mem, PIN, 3), Ok(0));
        assert_eq!(mem.counters.puts.len(), puts);
    }

    #[test]
    fn load_fails_closed_without_an_entry() {
        let mut mem = MemCounterStore::default();
        assert_eq!(load(&mut mem, PIN, false, 3), 3, "fresh applet");
        assert_eq!(load(&mut mem, PIN, true, 3), 0, "record but no counter");
        mem.counters.unformatted = true;
        assert_eq!(load(&mut mem, PIN, false, 3), 0, "log not migrated");
        mem.counters.unformatted = false;
        set(&mut mem, PIN, 2).unwrap();
        assert_eq!(load(&mut mem, PIN, true, 3), 2);
    }

    /// A store with nothing but counters.
    #[derive(Default)]
    struct MemCounterStore {
        counters: MemCounters,
    }

    impl KeyStore for MemCounterStore {
        fn save_key(
            &mut self,
            _: &crate::security::key_management::KeyObject,
        ) -> Result<(), HsmError> {
            Ok(())
        }
        fn fetch_key(
            &mut self,
            _: pico2hsm_core::key::KeyId,
        ) -> Result<Option<crate::security::key_management::KeyObject>, HsmError> {
            Ok(None)
        }
        fn erase_key(&mut self, _: pico2hsm_core::key::KeyId) -> Result<(), HsmError> {
            Ok(())
        }
        fn wipe_all(&mut self) -> Result<(), HsmError> {
            Ok(())
        }
        fn wipe_by_owner(&mut self, _: pico2hsm_core::key::AppletId) -> Result<(), HsmError> {
            Ok(())
        }
        fn enumerate_keys(&self) -> heapless::Vec<pico2hsm_core::key::KeyId, 64> {
            heapless::Vec::new()
        }
        fn for_each_key(&self, _: &mut dyn FnMut(pico2hsm_core::key::KeyId)) {}
        fn retry_counters(&mut self) -> Option<&mut dyn RetryCounterBackend> {
            Some(&mut self.counters)
        }
    }
}
