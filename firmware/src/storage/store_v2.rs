//! Storage V2 keystore engine: journal, snapshots, lookup, allocation
//! (docs/STORAGE_V2.md §5–§9, with the second-pass fixes of §18).
//!
//! The engine stores opaque, already-encrypted object blobs under 32-bit key
//! IDs.  It owns the keystore region (QMI flash or the SD card): a journal
//! ring at its start, then data sectors (objects and index snapshots).
//! Everything that steers the store is MACed under `K_idx`; the binding
//! block and the counter-log anchor live elsewhere (internal flash) and
//! reach the engine through [`MountInfo`] and [`Env`].
//!
//! Layout of the region, in 4 KiB sectors:
//!
//! ```text
//! sector 0 .. ring      journal ring (16 on NOR, 64 on SD)
//! sector ring .. end    data: objects (one sector each) and snapshots
//! ```
//!
//! # Journal
//! Ring sector: a 32-byte header `"P2J2" | store_id | ring_seq | mac8`, then
//! records.  On NOR flash 127 records of 32 bytes; on SD one record per
//! 512-byte block (blocks 1–7; block 0 is the header), so a block holding a
//! committed record is never written again (§6.4).  Record:
//!
//! ```text
//! kind u8 | count u8 | rsv u16 | key_id u32 | sector u32 | seq u64 | aux u32 | mac8
//! ```
//!
//! `mac8 = HMAC(K_idx, store_id ‖ ring_seq ‖ slot ‖ record[0..24])[0..8]`:
//! a record moved to another slot or sector fails.  From the newest
//! CHECKPOINT to the head the seqs run on without a gap, with only VOID
//! slots (all zero) between records.
//!
//! # Snapshots
//! A CHECKPOINT points at a chain of snapshot sectors holding every live
//! entry sorted by key ID (168 per sector, 24 bytes each), each sector
//! MACed with the store, the as-of seq, its index and the chain length.
//! Lookup: the tail since the checkpoint (in RAM), then the snapshot through
//! a fence table (first key ID per snapshot sector).
//!
//! # Objects
//! One sector each: a 40-byte header (`"P2O2" | store_id | key_id | seq |
//! type | algo | flags | rsv | blob_len | rsv`), then the sealed blob.  The
//! header is the AAD prefix the caller seals with (see
//! [`object_header`]), so an object only opens as the version the index
//! names.

use core::cell::RefCell;

use pico2hsm_core::error::StorageError;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::kdf::{hkdf_sha256, hmac_sha256};
use crate::storage::retry_counter::Anchor;

// ─── Geometry ────────────────────────────────────────────────────────────────

/// Bytes per sector (erase unit on NOR, 8 blocks on SD).
pub const SECTOR: u32 = 4096;
const SD_BLOCK: u32 = 512;

/// The keystore medium: decides the journal geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Media {
    /// NOR flash (QMI): program-without-erase, 1→0 only.
    Nor,
    /// SD card over SPI: whole 512-byte blocks.
    Sd,
}

/// Raw access to the keystore region.  Offsets are region-relative.
pub trait StoreFlash {
    /// The medium.
    fn media(&self) -> Media;
    /// Sectors in the region.
    fn sectors(&self) -> u32;
    /// Read `buf.len()` bytes at `offset`.
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), StorageError>;
    /// NOR: program `data` (bits 1→0).  SD: write whole blocks (`offset`
    /// and `data.len()` multiples of 512).
    fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError>;
    /// Bring a sector back to all 0xFF.
    fn erase_sector(&mut self, sector: u32) -> Result<(), StorageError>;
    /// SD: wait until the card is no longer busy and check its status
    /// (CMD13) — the anchor never gets ahead of what the card accepted.
    fn sync(&mut self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Geo {
    media: Media,
    ring: u32,
    slots: u16,
    stride: u32,
    threshold: usize,
    data_end: u32,
}

impl Geo {
    fn of(media: Media, sectors: u32) -> Self {
        match media {
            Media::Nor => Geo {
                media,
                ring: 16,
                slots: 127,
                stride: 32,
                threshold: 128,
                data_end: sectors,
            },
            Media::Sd => Geo {
                media,
                ring: 64,
                slots: 7,
                stride: SD_BLOCK,
                threshold: 64,
                data_end: sectors,
            },
        }
    }
    fn slot_offset(&self, pos: u32, slot: u16) -> u32 {
        pos * SECTOR + self.stride * (u32::from(slot) + 1)
    }
    fn global(&self, pos: u32, slot: u16) -> u16 {
        (pos * u32::from(self.slots) + u32::from(slot)) as u16
    }
    fn split(&self, global: u16) -> (u32, u16) {
        (
            u32::from(global) / u32::from(self.slots),
            global % self.slots,
        )
    }
}

/// Most data sectors the bitmap tracks (16 MiB of keystore).
pub const MAX_DATA_SECTORS: usize = 4096;
/// Most snapshot sectors (168 entries each).
pub const MAX_SNAPSHOT_SECTORS: usize = 32;
/// Entries per snapshot sector.
pub const SNAP_PER_SECTOR: usize = (SECTOR as usize - SNAP_HEADER) / SNAP_ENTRY;
const SNAP_HEADER: usize = 64;
const SNAP_ENTRY: usize = 24;
/// Bytes of an object sector header (the AAD prefix).
pub const OBJECT_HEADER: usize = 40;
/// Largest object blob.
pub const MAX_OBJECT_BLOB: usize = SECTOR as usize - OBJECT_HEADER;
/// Journal slots a PUT must leave writable (a DELETE, a CHECKPOINT and a
/// mount VOID always fit, §6.2).
const SLOT_RESERVE: u32 = 4;
/// Retries of a record append in fresh slots (R3).
const APPEND_ATTEMPTS: usize = 3;
/// Tail records kept in RAM (threshold plus a margin for a checkpoint that
/// keeps failing; past it, writes are refused until one succeeds).
const MAX_TAIL: usize = 160;

// ─── Keys and identities ─────────────────────────────────────────────────────

/// Group of a key ID by its applet byte (STORAGE_V2 §4): 0 SC-HSM and
/// domain records, 1 PIV, 2 OpenPGP.
pub fn group_of(key_id: u32) -> usize {
    match (key_id >> 16) & 0xFF {
        0x01 => 1,
        0x02 => 2,
        _ => 0,
    }
}

/// `K_idx = HKDF(SMK, "pico2hsm-idx-v2" ‖ store_id ‖ E_store)`.
pub fn derive_k_idx(
    smk: &[u8; 32],
    store_id: &[u8; 16],
    e_store: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut info = [0u8; 15 + 16 + 32];
    info[..15].copy_from_slice(b"pico2hsm-idx-v2");
    info[15..31].copy_from_slice(store_id);
    info[31..].copy_from_slice(e_store);
    let mut k = Zeroizing::new([0u8; 32]);
    let _ = hkdf_sha256(&[], smk, &info, &mut k[..]);
    k
}

/// `K_obj = HKDF(SMK, "pico2hsm-obj-v2" ‖ store_id ‖ E_group ‖ key_id BE)`:
/// the full 32-bit key ID, applet and partition bytes included.
pub fn derive_k_obj(
    smk: &[u8; 32],
    store_id: &[u8; 16],
    e_group: &[u8; 32],
    key_id: u32,
) -> Zeroizing<[u8; 32]> {
    let mut info = [0u8; 15 + 16 + 32 + 4];
    info[..15].copy_from_slice(b"pico2hsm-obj-v2");
    info[15..31].copy_from_slice(store_id);
    info[31..63].copy_from_slice(e_group);
    info[63..].copy_from_slice(&key_id.to_be_bytes());
    let mut k = Zeroizing::new([0u8; 32]);
    let _ = hkdf_sha256(&[], smk, &info, &mut k[..]);
    k
}

/// Non-secret metadata kept in the index (LIST KEYS never decrypts).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    pub key_type: u8,
    pub algo: u8,
    pub flags: u8,
}

/// The object header for `key_id` at `seq` — the AAD prefix the blob is
/// sealed with and checked against on fetch.
pub fn object_header(
    store_id: &[u8; 16],
    key_id: u32,
    seq: u64,
    meta: Meta,
    blob_len: u16,
) -> [u8; OBJECT_HEADER] {
    let mut h = [0u8; OBJECT_HEADER];
    h[0..4].copy_from_slice(b"P2O2");
    h[4..20].copy_from_slice(store_id);
    h[20..24].copy_from_slice(&key_id.to_le_bytes());
    h[24..32].copy_from_slice(&seq.to_le_bytes());
    h[32] = meta.key_type;
    h[33] = meta.algo;
    h[34] = meta.flags;
    h[36..38].copy_from_slice(&blob_len.to_le_bytes());
    h
}

/// Why a format is allowed (§8.3: nothing else formats).  The engine
/// checks [`FormatAuth::first_boot`] itself (blank ring, no anchor); the
/// other two record the caller's decision at every call site.
pub struct FormatAuth(FormatWhy);

#[derive(Clone, Copy, PartialEq, Eq)]
enum FormatWhy {
    FirstBoot,
    Resume,
    Command,
}

impl FormatAuth {
    /// First boot: refused by [`Store::format`] unless the journal ring is
    /// blank and the counter log holds no anchor.
    pub fn first_boot() -> Self {
        FormatAuth(FormatWhy::FirstBoot)
    }
    /// Resume an interrupted format: the binding block is in FORMATTING
    /// (same store_id, §8.3).
    pub fn resume_formatting(binding_is_formatting: bool) -> Option<Self> {
        binding_is_formatting.then_some(FormatAuth(FormatWhy::Resume))
    }
    /// FORMAT STORE: the SO-PIN was verified, or the store is refused and
    /// has no verifiable binding (R9).
    pub fn format_store(authorized: bool) -> Option<Self> {
        authorized.then_some(FormatAuth(FormatWhy::Command))
    }
    /// Whether this is the first-boot authorisation.
    pub fn is_first_boot(&self) -> bool {
        self.0 == FormatWhy::FirstBoot
    }
}

/// Proof that the SO-PIN was verified, for OPEN DEGRADED (§9.3): without
/// the gate, corrupting one record could bring a deleted key back.
pub struct DegradedAuth(());

impl DegradedAuth {
    /// After a successful SO-PIN verification.
    pub fn so_pin_verified(verified: bool) -> Option<Self> {
        verified.then_some(DegradedAuth(()))
    }
}

/// What the binding block says about the store (STORAGE_V2 §8.1).
pub struct MountInfo {
    pub store_id: [u8; 16],
    /// The binding's `format_gen` (the anchor holds its low 16 bits).
    pub format_gen: u32,
    pub k_idx: Zeroizing<[u8; 32]>,
    /// Epoch generation per group in the binding.
    pub group_gen: [u32; 3],
}

/// Where the engine keeps its anchor and gets randomness.
pub trait Env {
    fn anchor(&mut self) -> Result<Option<Anchor>, StorageError>;
    fn put_anchor(&mut self, a: Anchor) -> Result<(), StorageError>;
}

// ─── Records ─────────────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Put = 1,
    Delete = 2,
    Wipe = 3,
    Checkpoint = 4,
}

impl Kind {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Kind::Put),
            2 => Some(Kind::Delete),
            3 => Some(Kind::Wipe),
            4 => Some(Kind::Checkpoint),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rec {
    kind: Kind,
    count: u8,
    key_id: u32,
    sector: u32,
    seq: u64,
    aux: u32,
}

impl Rec {
    fn body(&self) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[0] = self.kind as u8;
        b[1] = self.count;
        b[4..8].copy_from_slice(&self.key_id.to_le_bytes());
        b[8..12].copy_from_slice(&self.sector.to_le_bytes());
        b[12..20].copy_from_slice(&self.seq.to_le_bytes());
        b[20..24].copy_from_slice(&self.aux.to_le_bytes());
        b
    }
    fn parse(b: &[u8; 24]) -> Option<Self> {
        let u32_at = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&b[12..20]);
        Some(Rec {
            kind: Kind::from_u8(b[0])?,
            count: b[1],
            key_id: u32_at(4),
            sector: u32_at(8),
            seq: u64::from_le_bytes(seq),
            aux: u32_at(20),
        })
    }
    fn meta(&self) -> Meta {
        Meta {
            key_type: self.aux as u8,
            algo: (self.aux >> 8) as u8,
            flags: (self.aux >> 16) as u8,
        }
    }
}

fn meta_aux(m: Meta) -> u32 {
    u32::from(m.key_type) | u32::from(m.algo) << 8 | u32::from(m.flags) << 16
}

fn record_mac(
    k: &[u8; 32],
    store_id: &[u8; 16],
    ring_seq: u32,
    global: u16,
    body: &[u8; 24],
) -> [u8; 8] {
    let mut m = [0u8; 16 + 4 + 2 + 24];
    m[..16].copy_from_slice(store_id);
    m[16..20].copy_from_slice(&ring_seq.to_le_bytes());
    m[20..22].copy_from_slice(&global.to_le_bytes());
    m[22..].copy_from_slice(body);
    let full = hmac_sha256(k, &m);
    let mut out = [0u8; 8];
    out.copy_from_slice(&full[..8]);
    out
}

fn ring_header(k: &[u8; 32], store_id: &[u8; 16], ring_seq: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0..4].copy_from_slice(b"P2J2");
    h[4..20].copy_from_slice(store_id);
    h[20..24].copy_from_slice(&ring_seq.to_le_bytes());
    let mac = hmac_sha256(k, &h[..24]);
    h[24..32].copy_from_slice(&mac[..8]);
    h
}

/// What a slot holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    Blank,
    Void,
    Record(Rec),
    Garbage,
}

// ─── Snapshot entries ────────────────────────────────────────────────────────

/// One live object in the index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub key_id: u32,
    pub sector: u32,
    pub seq: u64,
    pub meta: Meta,
}

impl Entry {
    fn encode(&self, out: &mut [u8]) {
        out[0..4].copy_from_slice(&self.key_id.to_le_bytes());
        out[4..8].copy_from_slice(&self.sector.to_le_bytes());
        out[8..16].copy_from_slice(&self.seq.to_le_bytes());
        out[16] = self.meta.key_type;
        out[17] = self.meta.algo;
        out[18] = self.meta.flags;
        out[19..24].fill(0);
    }
    fn decode(b: &[u8]) -> Self {
        let u32_at = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&b[8..16]);
        Entry {
            key_id: u32_at(0),
            sector: u32_at(4),
            seq: u64::from_le_bytes(seq),
            meta: Meta {
                key_type: b[16],
                algo: b[17],
                flags: b[18],
            },
        }
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────────

/// Why a store was not mounted (the display shows these; §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The region holds no journal at all (blank ring).
    Blank,
    /// A ring header of another store (another device's card, a store from
    /// before a format) or an unverifiable one.
    WrongStore,
    /// The binding is active but the counter log has no anchor for it.
    NoAnchor,
    /// The journal's head is behind the anchor (rollback, lost SD writes)
    /// by this many records, or not where the anchor says.
    BehindAnchor(u64),
    /// Structural damage: MAC, contiguity, chain, impossible pointer.
    Corrupt(&'static str),
    /// A WIPE_OWNER whose epoch generation the binding does not have yet
    /// (a cut between the record and the binding write): the caller writes
    /// the binding with this group's new epoch and generation, then mounts
    /// again (§6, R7).
    PendingRotation { group: u8, gen: u32 },
    /// The region could not be read.
    Io,
}

// ─── The engine ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default)]
struct Checkpoint {
    seq: u64,
    first: u32,
    count: u8,
    hash: [u8; 8],
}

/// A tail record kept in RAM (since the newest checkpoint).
#[derive(Clone, Copy, Debug)]
struct Tail {
    rec: Rec,
}

/// Mounted-store state.
struct Mounted {
    store_id: [u8; 16],
    format_gen: u32,
    k_idx: Zeroizing<[u8; 32]>,
    group_gen: [u32; 3],
    /// The head sector's ring position and ring_seq.
    head_pos: u32,
    head_ring_seq: u32,
    /// Next slot to program in the head sector (== slots: full).
    next_slot: u16,
    /// The newest record's seq and global slot.
    head_seq: u64,
    head_global: u16,
    checkpoint: Checkpoint,
    /// Global slot of the newest CHECKPOINT record.
    checkpoint_global: u16,
    snapshot: heapless::Vec<u32, MAX_SNAPSHOT_SECTORS>,
    /// First key ID per snapshot sector.
    fence: heapless::Vec<u32, MAX_SNAPSHOT_SECTORS>,
    snapshot_entries: usize,
    tail: heapless::Vec<Tail, MAX_TAIL>,
    bitmap: [u8; MAX_DATA_SECTORS / 8],
    /// An anchor write failed after its commit: no commit until it is
    /// brought forward (§8.2).
    commit_blocked: bool,
    /// A VOID could not be programmed: no commit until remount (R3).
    poisoned: bool,
    /// Mounted read-only (OPEN DEGRADED, §9.3).
    read_only: bool,
}

/// The Storage V2 engine over one keystore region.
pub struct Store<F: StoreFlash> {
    flash: RefCell<F>,
    geo: Geo,
    m: Option<Mounted>,
    /// Sector buffers (in the store, so in BSS, never on the core1 stack):
    /// `buf` for objects and the snapshot being written, `buf2` for the
    /// old snapshot sector being merged.
    buf: RefCell<[u8; SECTOR as usize]>,
    buf2: [u8; SECTOR as usize],
}

/// Seals an object blob for a given seq into the buffer, returning its
/// length (see [`Store::put`]).
pub type Sealer<'a> = dyn FnMut(u64, &mut [u8]) -> Result<usize, StorageError> + 'a;

/// Outcome of [`Store::fetch_into`].
pub enum Fetched {
    /// Not in the store.
    Missing,
    /// The object: its metadata, seq, and blob length in the caller's buffer.
    Found { meta: Meta, seq: u64, len: usize },
}

impl<F: StoreFlash> Store<F> {
    /// An unmounted engine over `flash`.
    pub fn new(flash: F) -> Self {
        let geo = Geo::of(flash.media(), flash.sectors());
        Store {
            flash: RefCell::new(flash),
            geo,
            m: None,
            buf: RefCell::new([0u8; SECTOR as usize]),
            buf2: [0u8; SECTOR as usize],
        }
    }

    /// The flash (tests inspect it).
    pub fn flash_mut(&mut self) -> &mut F {
        self.flash.get_mut()
    }

    /// Whether a store is mounted (read-write or degraded).
    pub fn is_mounted(&self) -> bool {
        self.m.is_some()
    }

    /// Drop every cached state (card removal, §9.2).
    pub fn unmount(&mut self) {
        self.m = None;
    }

    fn ring_blank(&mut self) -> Result<bool, StorageError> {
        // First-boot test: every ring header reads erased.  On SD, all-zero
        // counts as erased too (many cards read 0x00 after erase, R11).
        let mut h = [0u8; 32];
        for pos in 0..self.geo.ring {
            self.flash.get_mut().read(pos * SECTOR, &mut h)?;
            let ff = h.iter().all(|&b| b == 0xFF);
            let zero = self.geo.media == Media::Sd && h.iter().all(|&b| b == 0);
            if !(ff || zero) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether the journal ring is blank (for the first-boot rule, §8.3).
    pub fn is_blank(&mut self) -> Result<bool, StorageError> {
        self.ring_blank()
    }

    // ── Low-level slot access ───────────────────────────────────────────

    fn read_slot(
        &mut self,
        pos: u32,
        slot: u16,
        k: &[u8; 32],
        store_id: &[u8; 16],
        ring_seq: u32,
    ) -> Result<Slot, StorageError> {
        let mut b = [0u8; 32];
        self.flash
            .get_mut()
            .read(self.geo.slot_offset(pos, slot), &mut b)?;
        if b.iter().all(|&x| x == 0xFF) {
            return Ok(Slot::Blank);
        }
        if b.iter().all(|&x| x == 0) {
            return Ok(Slot::Void);
        }
        let mut body = [0u8; 24];
        body.copy_from_slice(&b[..24]);
        let mac = record_mac(k, store_id, ring_seq, self.geo.global(pos, slot), &body);
        if !bool::from(mac.ct_eq(&b[24..32])) {
            return Ok(Slot::Garbage);
        }
        Ok(Rec::parse(&body).map_or(Slot::Garbage, Slot::Record))
    }

    fn encode_slot(
        &self,
        rec: &Rec,
        k: &[u8; 32],
        store_id: &[u8; 16],
        ring_seq: u32,
        global: u16,
    ) -> [u8; SD_BLOCK as usize] {
        let mut out = [0xFFu8; SD_BLOCK as usize];
        let body = rec.body();
        out[..24].copy_from_slice(&body);
        out[24..32].copy_from_slice(&record_mac(k, store_id, ring_seq, global, &body));
        out
    }

    fn slot_len(&self) -> usize {
        match self.geo.media {
            Media::Nor => 32,
            Media::Sd => SD_BLOCK as usize,
        }
    }

    fn program_void(&mut self, pos: u32, slot: u16) -> Result<(), StorageError> {
        let zeros = [0u8; SD_BLOCK as usize];
        let len = self.slot_len();
        self.flash
            .get_mut()
            .program(self.geo.slot_offset(pos, slot), &zeros[..len])?;
        let mut b = [0xFFu8; 32];
        self.flash
            .get_mut()
            .read(self.geo.slot_offset(pos, slot), &mut b)?;
        if b.iter().all(|&x| x == 0) {
            Ok(())
        } else {
            Err(StorageError::WriteError)
        }
    }

    fn read_ring_header(
        &mut self,
        pos: u32,
        k: &[u8; 32],
        store_id: &[u8; 16],
    ) -> Result<Header, StorageError> {
        let mut h = [0u8; 32];
        self.flash.get_mut().read(pos * SECTOR, &mut h)?;
        if h.iter().all(|&b| b == 0xFF)
            || (self.geo.media == Media::Sd && h.iter().all(|&b| b == 0))
        {
            return Ok(Header::Blank);
        }
        let ring_seq = u32::from_le_bytes([h[20], h[21], h[22], h[23]]);
        let want = ring_header(k, store_id, ring_seq);
        if h[0..4] != *b"P2J2" || !bool::from(want.ct_eq(&h)) {
            if h[0..4] == *b"P2J2" && h[4..20] != *store_id {
                return Ok(Header::Foreign);
            }
            return Ok(Header::Invalid);
        }
        Ok(Header::Valid(ring_seq))
    }

    fn write_ring_header(
        &mut self,
        pos: u32,
        ring_seq: u32,
        k: &[u8; 32],
        store_id: &[u8; 16],
    ) -> Result<(), StorageError> {
        self.flash.get_mut().erase_sector(pos)?;
        let mut probe = [0u8; 32];
        for slot in 0..=self.geo.slots {
            let off = if slot == 0 {
                pos * SECTOR
            } else {
                self.geo.slot_offset(pos, slot - 1)
            };
            self.flash.get_mut().read(off, &mut probe)?;
            if probe.iter().any(|&b| b != 0xFF) {
                return Err(StorageError::EraseError);
            }
        }
        let mut block = [0xFFu8; SD_BLOCK as usize];
        block[..32].copy_from_slice(&ring_header(k, store_id, ring_seq));
        let len = self.slot_len();
        self.flash.get_mut().program(pos * SECTOR, &block[..len])?;
        self.flash.get_mut().sync()?;
        match self.read_ring_header(pos, k, store_id)? {
            Header::Valid(rs) if rs == ring_seq => Ok(()),
            _ => Err(StorageError::WriteError),
        }
    }

    // ── Bitmap ──────────────────────────────────────────────────────────

    fn data_range(&self) -> core::ops::Range<u32> {
        self.geo.ring
            ..self
                .geo
                .data_end
                .min(self.geo.ring + MAX_DATA_SECTORS as u32)
    }

    fn mark(m: &mut Mounted, sector: u32, used: bool) {
        let i = sector as usize;
        if i / 8 < m.bitmap.len() {
            if used {
                m.bitmap[i / 8] |= 1 << (i % 8);
            } else {
                m.bitmap[i / 8] &= !(1 << (i % 8));
            }
        }
    }

    fn is_used(m: &Mounted, sector: u32) -> bool {
        let i = sector as usize;
        i / 8 < m.bitmap.len() && m.bitmap[i / 8] & (1 << (i % 8)) != 0
    }

    fn free_sectors(&self) -> u32 {
        let Some(m) = &self.m else { return 0 };
        self.data_range().filter(|&s| !Self::is_used(m, s)).count() as u32
    }

    /// A free data sector, blank (erased first if it holds leftovers).
    /// The search starts after `hint`, spreading the wear.
    fn allocate(&mut self, hint: u32) -> Result<u32, StorageError> {
        let Some(m) = self.m.take() else {
            return Err(StorageError::NotFormatted);
        };
        let r = self.allocate_in(&m, &[], hint);
        self.m = Some(m);
        r
    }

    /// [`Self::allocate`] against `m`'s bitmap, also skipping `taken`.
    fn allocate_in(&mut self, m: &Mounted, taken: &[u32], hint: u32) -> Result<u32, StorageError> {
        let range = self.data_range();
        let span = range.end - range.start;
        if span == 0 {
            return Err(StorageError::KeystoreFull);
        }
        let start = range.start + hint % span;
        for k in 0..span {
            let s = range.start + (start - range.start + k) % span;
            if Self::is_used(m, s) || taken.contains(&s) {
                continue;
            }
            if !self.sector_blank(s)?
                && (self.flash.get_mut().erase_sector(s).is_err() || !self.sector_blank(s)?)
            {
                continue;
            }
            return Ok(s);
        }
        Err(StorageError::KeystoreFull)
    }

    fn sector_blank(&mut self, s: u32) -> Result<bool, StorageError> {
        let mut buf = self.buf.borrow_mut();
        self.flash.get_mut().read(s * SECTOR, &mut buf[..])?;
        Ok(buf.iter().all(|&b| b == 0xFF))
    }

    /// Program a whole sector from `buf`, its first `head` bytes last (on
    /// SD the first block last): until the header is there the sector is
    /// not a valid object or snapshot.
    fn program_sector_header_last(&mut self, s: u32, head: usize) -> Result<(), StorageError> {
        let split = match self.geo.media {
            Media::Nor => head,
            Media::Sd => SD_BLOCK as usize,
        };
        let buf = self.buf.borrow();
        self.flash
            .get_mut()
            .program(s * SECTOR + split as u32, &buf[split..])?;
        self.flash.get_mut().program(s * SECTOR, &buf[..split])?;
        drop(buf);
        self.flash.get_mut().sync()?;
        // Verify.
        let mut chunk = [0u8; 256];
        for i in 0..(SECTOR as usize / 256) {
            self.flash
                .get_mut()
                .read(s * SECTOR + (i * 256) as u32, &mut chunk)?;
            if chunk[..] != self.buf.borrow()[i * 256..(i + 1) * 256] {
                return Err(StorageError::WriteError);
            }
        }
        Ok(())
    }

    // ── Format ──────────────────────────────────────────────────────────

    /// Steps 2–3 of a format (§8.3): erase the ring, write ring sector 0's
    /// header and a CHECKPOINT (seq 0) of the empty snapshot, then the
    /// anchor `(format_gen, 0, slot 0)`.  The caller has put the binding in
    /// FORMATTING before and moves it to ACTIVE after; both steps are
    /// idempotent, so a cut anywhere is resumed by calling this again.
    pub fn format(
        &mut self,
        info: MountInfo,
        env: &mut dyn Env,
        auth: FormatAuth,
    ) -> Result<(), StorageError> {
        if auth.0 == FormatWhy::FirstBoot && (!self.ring_blank()? || env.anchor()?.is_some()) {
            // Not a first boot: a store (or its anchor) exists.  Never
            // format it implicitly.
            return Err(StorageError::IntegrityFailure);
        }
        self.m = None;
        for pos in 0..self.geo.ring {
            self.flash.get_mut().erase_sector(pos)?;
        }
        self.write_ring_header(0, 0, &info.k_idx, &info.store_id)?;
        let rec = Rec {
            kind: Kind::Checkpoint,
            count: 0,
            key_id: u32::from_le_bytes(snapshot_hash(&[])[..4].try_into().unwrap_or([0; 4])),
            sector: 0,
            seq: 0,
            aux: u32::from_le_bytes(snapshot_hash(&[])[4..8].try_into().unwrap_or([0; 4])),
        };
        let slot = self.encode_slot(&rec, &info.k_idx, &info.store_id, 0, 0);
        let len = self.slot_len();
        self.flash
            .get_mut()
            .program(self.geo.slot_offset(0, 0), &slot[..len])?;
        self.flash.get_mut().sync()?;
        env.put_anchor(Anchor {
            format_gen: info.format_gen as u16,
            head_seq: 0,
            head_slot: 0,
        })?;
        Ok(())
    }

    // ── Mount ───────────────────────────────────────────────────────────

    /// Mount the store read-write (§9.1 steps 3–6): ring headers, newest
    /// checkpoint and its snapshot, the contiguous tail, torn-tail repair,
    /// the anchor.
    pub fn mount(&mut self, info: MountInfo, env: &mut dyn Env) -> Result<(), Refusal> {
        self.mount_inner(info, env, false)
    }

    /// OPEN DEGRADED (§9.3): mount read-only, accepting a head behind the
    /// anchor and stopping at the first damaged record (the longest
    /// verifiable state).  Needs the SO-PIN.
    pub fn mount_degraded(
        &mut self,
        info: MountInfo,
        env: &mut dyn Env,
        _auth: DegradedAuth,
    ) -> Result<(), Refusal> {
        self.mount_inner(info, env, true)
    }

    fn mount_inner(
        &mut self,
        info: MountInfo,
        env: &mut dyn Env,
        read_only: bool,
    ) -> Result<(), Refusal> {
        self.m = None;
        let anchor = env.anchor().map_err(|_| Refusal::Io)?;
        let anchor = match anchor {
            Some(a) if a.format_gen == info.format_gen as u16 => Some(a),
            _ if read_only => None,
            _ => return Err(Refusal::NoAnchor),
        };
        let k = info.k_idx.clone();
        let sid = info.store_id;
        let n = self.geo.ring;

        // 1. Ring headers.
        let mut headers = [Header::Blank; 64];
        let mut head: Option<(u32, u32)> = None;
        let mut any_valid = false;
        for pos in 0..n {
            let h = self
                .read_ring_header(pos, &k, &sid)
                .map_err(|_| Refusal::Io)?;
            if let Header::Valid(rs) = h {
                any_valid = true;
                if rs % n != pos {
                    return Err(Refusal::Corrupt("ring_seq does not match its position"));
                }
                if head.map_or(true, |(_, best)| rs > best) {
                    head = Some((pos, rs));
                }
            }
            headers[pos as usize] = h;
        }
        if !any_valid {
            return Err(
                if headers.iter().take(n as usize).all(|h| *h == Header::Blank) {
                    Refusal::Blank
                } else {
                    Refusal::WrongStore
                },
            );
        }
        let (head_pos, head_rs) = head.ok_or(Refusal::WrongStore)?;
        let first_lap = head_rs < n;
        for pos in 0..n {
            let behind = (head_pos + n - pos) % n; // 0 = head, n-1 = next to recycle
            let h = headers[pos as usize];
            let ok = match h {
                Header::Valid(rs) => !first_lap || pos <= head_pos && rs == pos,
                // R5: blank after the head in the first lap; one blank or
                // invalid header at the next-to-recycle position (a cut
                // recycle, §6.3).
                Header::Blank => (first_lap && pos > head_pos) || behind == n - 1,
                Header::Invalid => {
                    behind == n - 1 && !first_lap || (first_lap && pos == head_pos + 1)
                }
                Header::Foreign => false,
            };
            if !ok {
                return Err(if h == Header::Foreign {
                    Refusal::WrongStore
                } else {
                    Refusal::Corrupt("ring header")
                });
            }
            if let Header::Valid(rs) = h {
                // Older laps: position p behind the head holds head_rs − behind.
                if !first_lap && rs != head_rs.wrapping_sub(behind) {
                    return Err(Refusal::Corrupt("ring_seq not contiguous"));
                }
            }
        }

        // 2. Walk the ring oldest → newest, collecting the newest
        //    checkpoint, then the contiguous chain after it.
        let order: heapless::Vec<u32, 64> = (1..=n)
            .map(|i| (head_pos + i) % n)
            .filter(|&p| matches!(headers[p as usize], Header::Valid(_)))
            .collect();
        let rs_of = |p: u32| match headers[p as usize] {
            Header::Valid(rs) => rs,
            _ => 0,
        };
        // Find the newest checkpoint.
        let mut cp: Option<(Rec, u16)> = None;
        for &pos in order.iter() {
            for slot in 0..self.geo.slots {
                if let Slot::Record(r) = self
                    .read_slot(pos, slot, &k, &sid, rs_of(pos))
                    .map_err(|_| Refusal::Io)?
                {
                    if r.kind == Kind::Checkpoint && cp.map_or(true, |(c, _)| r.seq > c.seq) {
                        cp = Some((r, self.geo.global(pos, slot)));
                    }
                }
            }
        }
        let (cp_rec, cp_global) = cp.ok_or(Refusal::Corrupt("no checkpoint"))?;

        let mut m = Mounted {
            store_id: sid,
            format_gen: info.format_gen,
            k_idx: info.k_idx,
            group_gen: info.group_gen,
            head_pos,
            head_ring_seq: head_rs,
            next_slot: 0,
            head_seq: cp_rec.seq,
            head_global: cp_global,
            checkpoint: Checkpoint {
                seq: cp_rec.seq,
                first: cp_rec.sector,
                count: cp_rec.count,
                hash: {
                    let mut h = [0u8; 8];
                    h[..4].copy_from_slice(&cp_rec.key_id.to_le_bytes());
                    h[4..].copy_from_slice(&cp_rec.aux.to_le_bytes());
                    h
                },
            },
            checkpoint_global: cp_global,
            snapshot: heapless::Vec::new(),
            fence: heapless::Vec::new(),
            snapshot_entries: 0,
            tail: heapless::Vec::new(),
            bitmap: [0; MAX_DATA_SECTORS / 8],
            commit_blocked: false,
            poisoned: false,
            read_only,
        };

        // 3. The snapshot.
        self.verify_snapshot(&mut m).map_err(|e| match e {
            StorageError::ReadError => Refusal::Io,
            _ => Refusal::Corrupt("snapshot"),
        })?;

        // 4. The tail: from the checkpoint's slot, in ring order.
        let (cp_pos, cp_slot) = self.geo.split(cp_global);
        let start_idx = order
            .iter()
            .position(|&p| p == cp_pos)
            .ok_or(Refusal::Corrupt("checkpoint sector"))?;
        let mut expect = cp_rec.seq + 1;
        let mut tail_end: Option<(u32, u16)> = None; // first slot after the last valid record
        let mut torn: Option<(u32, u16)> = None;
        'walk: for (oi, &pos) in order.iter().enumerate().skip(start_idx) {
            let first = if oi == start_idx { cp_slot + 1 } else { 0 };
            let is_head = pos == head_pos;
            for slot in first..self.geo.slots {
                match self
                    .read_slot(pos, slot, &k, &sid, rs_of(pos))
                    .map_err(|_| Refusal::Io)?
                {
                    Slot::Void => {}
                    Slot::Record(r) => {
                        if torn.is_some() || tail_end.is_some() {
                            return Err(Refusal::Corrupt("record after a blank or torn slot"));
                        }
                        if r.seq != expect {
                            if read_only {
                                break 'walk;
                            }
                            return Err(Refusal::Corrupt("journal not contiguous"));
                        }
                        expect += 1;
                        m.head_seq = r.seq;
                        m.head_global = self.geo.global(pos, slot);
                        if m.tail.push(Tail { rec: r }).is_err() {
                            return Err(Refusal::Corrupt("tail too long"));
                        }
                    }
                    Slot::Blank => {
                        if !is_head {
                            if read_only {
                                break 'walk;
                            }
                            return Err(Refusal::Corrupt("blank slot outside the head sector"));
                        }
                        if tail_end.is_none() {
                            tail_end = Some((pos, slot));
                        }
                    }
                    Slot::Garbage => {
                        // Only the slot after the tail, in the head sector,
                        // may be torn (§6.1, R4).
                        if !is_head || torn.is_some() || tail_end.is_some() {
                            if read_only {
                                break 'walk;
                            }
                            return Err(Refusal::Corrupt("damaged journal record"));
                        }
                        torn = Some((pos, slot));
                    }
                }
            }
        }

        // 5. Head against the anchor (R1).
        if let Some(a) = anchor {
            let at_anchor = m.head_seq == a.head_seq && m.head_global == a.head_slot;
            let one_more = m.head_seq == a.head_seq + 1
                && self.only_voids_between(&k, &sid, &headers, a.head_slot, m.head_global, rs_of);
            if !(at_anchor || one_more) {
                if read_only {
                    // OPEN DEGRADED: the longest verifiable state.
                } else if m.head_seq < a.head_seq {
                    return Err(Refusal::BehindAnchor(a.head_seq - m.head_seq));
                } else {
                    return Err(Refusal::BehindAnchor(0));
                }
            }
        }

        // 6. Pending epoch rotation (R7): a WIPE whose generation is above
        //    the binding's.
        for t in m.tail.iter() {
            if t.rec.kind == Kind::Wipe {
                let g = (t.rec.aux & 0xFF) as usize;
                let gen = t.rec.aux >> 8;
                if g < 3 && gen > m.group_gen[g] & 0x00FF_FFFF {
                    return Err(Refusal::PendingRotation {
                        group: g as u8,
                        gen,
                    });
                }
            }
        }

        // 7. Bitmap and the head position.
        self.build_bitmap(&mut m)
            .map_err(|_| Refusal::Corrupt("index"))?;
        let (hp, _) = self.geo.split(m.head_global);
        let _ = hp;
        // Appends continue in the head sector after the last used slot.
        let mut next = 0u16;
        for slot in 0..self.geo.slots {
            match self
                .read_slot(head_pos, slot, &k, &sid, head_rs)
                .map_err(|_| Refusal::Io)?
            {
                Slot::Blank => break,
                _ => next = slot + 1,
            }
        }
        m.next_slot = next;
        self.m = Some(m);

        if read_only {
            return Ok(());
        }
        // Torn-tail repair (§6.1, R4): re-program the tail record on NOR,
        // VOID the slot after it in the head sector, before any append.
        if let Some((pos, slot)) = torn.or(tail_end) {
            if pos == head_pos {
                if self.geo.media == Media::Nor {
                    let (tp, ts) = self
                        .geo
                        .split(self.m.as_ref().map(|m| m.head_global).unwrap_or(0));
                    if tp == head_pos {
                        if let Some(last) =
                            self.m.as_ref().and_then(|m| m.tail.last().map(|t| t.rec))
                        {
                            let enc =
                                self.encode_slot(&last, &k, &sid, head_rs, self.geo.global(tp, ts));
                            let _ = self
                                .flash
                                .get_mut()
                                .program(self.geo.slot_offset(tp, ts), &enc[..32]);
                        }
                    }
                }
                if self.program_void(pos, slot).is_err() {
                    if let Some(m) = self.m.as_mut() {
                        m.poisoned = true;
                    }
                }
                if let Some(m) = self.m.as_mut() {
                    m.next_slot = m.next_slot.max(slot + 1);
                }
            }
        }
        // Bring the anchor forward to the head.
        let (fg, hs, hg) = {
            let m = self.m.as_ref().ok_or(Refusal::Io)?;
            (m.format_gen, m.head_seq, m.head_global)
        };
        if env
            .put_anchor(Anchor {
                format_gen: fg as u16,
                head_seq: hs,
                head_slot: hg,
            })
            .is_err()
        {
            if let Some(m) = self.m.as_mut() {
                m.commit_blocked = true;
            }
        }
        Ok(())
    }

    fn only_voids_between(
        &mut self,
        k: &[u8; 32],
        sid: &[u8; 16],
        headers: &[Header; 64],
        from: u16,
        to: u16,
        rs_of: impl Fn(u32) -> u32,
    ) -> bool {
        let total = u32::from(self.geo.slots) * self.geo.ring;
        let mut g = (u32::from(from) + 1) % total;
        let to = u32::from(to);
        let mut steps = 0;
        while g != to {
            let (pos, slot) = self.geo.split(g as u16);
            if !matches!(headers[pos as usize], Header::Valid(_)) {
                return false;
            }
            match self.read_slot(pos, slot, k, sid, rs_of(pos)) {
                Ok(Slot::Void) => {}
                _ => return false,
            }
            g = (g + 1) % total;
            steps += 1;
            if steps > total {
                return false;
            }
        }
        true
    }

    fn verify_snapshot(&mut self, m: &mut Mounted) -> Result<(), StorageError> {
        let cp = m.checkpoint;
        let range = self.data_range();
        let mut macs: heapless::Vec<[u8; 16], MAX_SNAPSHOT_SECTORS> = heapless::Vec::new();
        let mut sector = cp.first;
        let mut last_key: Option<u32> = None;
        for idx in 0..cp.count as usize {
            if !range.contains(&sector) {
                return Err(StorageError::IntegrityFailure);
            }
            let buf = self.buf.get_mut();
            self.flash.get_mut().read(sector * SECTOR, &mut buf[..])?;
            let (next, entries, mac, gens) = parse_snapshot(
                buf,
                &m.k_idx,
                &m.store_id,
                cp.seq.wrapping_sub(1),
                idx as u16,
                cp.count as u16,
            )
            .ok_or(StorageError::IntegrityFailure)?;
            if idx == 0 {
                for (g, &gen) in gens.iter().enumerate() {
                    // R7: the snapshot's group generations must not be
                    // ahead of the binding's.
                    if gen > m.group_gen[g] & 0x00FF_FFFF {
                        return Err(StorageError::IntegrityFailure);
                    }
                }
            }
            let first = Entry::decode(&buf[SNAP_HEADER..SNAP_HEADER + SNAP_ENTRY]).key_id;
            for i in 0..entries {
                let e = Entry::decode(&buf[SNAP_HEADER + i * SNAP_ENTRY..]);
                if last_key.is_some_and(|l| e.key_id <= l) || !range.contains(&e.sector) {
                    return Err(StorageError::IntegrityFailure);
                }
                last_key = Some(e.key_id);
            }
            m.snapshot
                .push(sector)
                .map_err(|_| StorageError::IntegrityFailure)?;
            m.fence
                .push(if entries == 0 { u32::MAX } else { first })
                .map_err(|_| StorageError::IntegrityFailure)?;
            m.snapshot_entries += entries;
            macs.push(mac).map_err(|_| StorageError::IntegrityFailure)?;
            sector = next;
        }
        if snapshot_hash(&macs) != cp.hash {
            return Err(StorageError::IntegrityFailure);
        }
        Ok(())
    }

    fn build_bitmap(&mut self, m: &mut Mounted) -> Result<(), StorageError> {
        for s in m.snapshot.clone() {
            Self::mark(m, s, true);
        }
        // Snapshot entries, unless the tail superseded them.
        let snaps = m.snapshot.clone();
        for &s in snaps.iter() {
            let buf = self.buf.get_mut();
            self.flash.get_mut().read(s * SECTOR, &mut buf[..])?;
            let n = u16::from_le_bytes([buf[32], buf[33]]) as usize;
            for i in 0..n.min(SNAP_PER_SECTOR) {
                let e = Entry::decode(&buf[SNAP_HEADER + i * SNAP_ENTRY..]);
                if !tail_touches(&m.tail, e.key_id) {
                    Self::mark(m, e.sector, true);
                }
            }
        }
        // The tail's live objects.
        let tail = m.tail.clone();
        for t in tail.iter() {
            if t.rec.kind == Kind::Put
                && tail_current(&tail, t.rec.key_id).is_some_and(|c| c.seq == t.rec.seq)
            {
                Self::mark(m, t.rec.sector, true);
            }
        }
        Ok(())
    }

    // ── Lookup ──────────────────────────────────────────────────────────

    /// The live entry for `key_id`, if any.
    pub fn lookup(&self, key_id: u32) -> Result<Option<Entry>, StorageError> {
        let m = self.m.as_ref().ok_or(StorageError::NotFormatted)?;
        if let Some(r) = tail_current(&m.tail, key_id) {
            return Ok(match r.kind {
                Kind::Put => Some(Entry {
                    key_id,
                    sector: r.sector,
                    seq: r.seq,
                    meta: r.meta(),
                }),
                _ => None,
            });
        }
        self.snapshot_lookup(m, key_id)
    }

    fn snapshot_lookup(&self, m: &Mounted, key_id: u32) -> Result<Option<Entry>, StorageError> {
        // The sector whose first key is the largest ≤ key_id.
        let mut idx = None;
        for (i, &f) in m.fence.iter().enumerate() {
            if f != u32::MAX && f <= key_id {
                idx = Some(i);
            }
        }
        let Some(i) = idx else { return Ok(None) };
        let mut buf = self.buf.borrow_mut();
        self.flash
            .borrow_mut()
            .read(m.snapshot[i] * SECTOR, &mut buf[..])?;
        let (_, entries, _, _) = parse_snapshot(
            &buf,
            &m.k_idx,
            &m.store_id,
            m.checkpoint.seq.wrapping_sub(1),
            i as u16,
            m.checkpoint.count as u16,
        )
        .ok_or(StorageError::IntegrityFailure)?;
        let (mut lo, mut hi) = (0usize, entries);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let e = Entry::decode(&buf[SNAP_HEADER + mid * SNAP_ENTRY..]);
            if e.key_id == key_id {
                return Ok(Some(e));
            }
            if e.key_id < key_id {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(None)
    }

    /// Call `f` for every live entry: the snapshot's (in key-ID order)
    /// that the tail did not supersede, then the tail's live PUTs.  `f`
    /// runs while the store's sector buffer is borrowed: it must not call
    /// back into the store.
    pub fn for_each(&self, f: &mut dyn FnMut(Entry)) -> Result<(), StorageError> {
        let m = self.m.as_ref().ok_or(StorageError::NotFormatted)?;
        self.for_each_with_tail(m, m.tail.len(), f)
    }

    /// [`Self::for_each`] as if only the first `tail_len` tail records
    /// existed (the index before them: `wipe_group` finds what it wiped).
    fn for_each_with_tail(
        &self,
        m: &Mounted,
        tail_len: usize,
        f: &mut dyn FnMut(Entry),
    ) -> Result<(), StorageError> {
        let tail = &m.tail[..tail_len.min(m.tail.len())];
        for (i, &s) in m.snapshot.iter().enumerate() {
            let mut buf = self.buf.borrow_mut();
            self.flash.borrow_mut().read(s * SECTOR, &mut buf[..])?;
            let (_, entries, _, _) = parse_snapshot(
                &buf,
                &m.k_idx,
                &m.store_id,
                m.checkpoint.seq.wrapping_sub(1),
                i as u16,
                m.checkpoint.count as u16,
            )
            .ok_or(StorageError::IntegrityFailure)?;
            for j in 0..entries {
                let e = Entry::decode(&buf[SNAP_HEADER + j * SNAP_ENTRY..]);
                if !tail_touches(tail, e.key_id) {
                    f(e);
                }
            }
        }
        for t in tail.iter() {
            if t.rec.kind == Kind::Put
                && tail_current(tail, t.rec.key_id).is_some_and(|c| c.seq == t.rec.seq)
            {
                f(Entry {
                    key_id: t.rec.key_id,
                    sector: t.rec.sector,
                    seq: t.rec.seq,
                    meta: t.rec.meta(),
                });
            }
        }
        Ok(())
    }

    /// Read `key_id`'s object into `out` (the blob, header checked against
    /// the index: key ID, seq, metadata).  The caller opens the blob with
    /// [`object_header`] as its AAD prefix.
    pub fn fetch_into(&self, key_id: u32, out: &mut [u8]) -> Result<Fetched, StorageError> {
        let Some(e) = self.lookup(key_id)? else {
            return Ok(Fetched::Missing);
        };
        let m = self.m.as_ref().ok_or(StorageError::NotFormatted)?;
        let mut flash = self.flash.borrow_mut();
        let mut h = [0u8; OBJECT_HEADER];
        flash.read(e.sector * SECTOR, &mut h)?;
        let len = u16::from_le_bytes([h[36], h[37]]);
        if h != object_header(&m.store_id, key_id, e.seq, e.meta, len)
            || len as usize > out.len().min(MAX_OBJECT_BLOB)
        {
            // The header disagrees with the index: this key is damaged
            // (§9.3), nothing else is.
            return Err(StorageError::IntegrityFailure);
        }
        flash.read(
            e.sector * SECTOR + OBJECT_HEADER as u32,
            &mut out[..len as usize],
        )?;
        Ok(Fetched::Found {
            meta: e.meta,
            seq: e.seq,
            len: len as usize,
        })
    }

    /// The store's identity (for the caller's K_obj and AAD).
    pub fn store_id(&self) -> Option<[u8; 16]> {
        self.m.as_ref().map(|m| m.store_id)
    }

    /// The seq the next commit gets.
    pub fn next_seq(&self) -> Option<u64> {
        self.m.as_ref().map(|m| m.head_seq + 1)
    }

    /// Live objects.
    pub fn len(&self) -> usize {
        let mut n = 0;
        let _ = self.for_each(&mut |_| n += 1);
        n
    }

    /// Whether the store holds no object.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // ── Commits ─────────────────────────────────────────────────────────

    fn writable_check(&mut self, env: &mut dyn Env) -> Result<(), StorageError> {
        let m = self.m.as_mut().ok_or(StorageError::NotFormatted)?;
        if m.read_only || m.poisoned {
            return Err(StorageError::WriteError);
        }
        if m.commit_blocked {
            // Bring the anchor forward first (§8.2).
            env.put_anchor(Anchor {
                format_gen: m.format_gen as u16,
                head_seq: m.head_seq,
                head_slot: m.head_global,
            })?;
            m.commit_blocked = false;
        }
        Ok(())
    }

    /// Ring sectors that can take records: the head's free slots plus the
    /// sectors ahead of it holding nothing at or after the checkpoint.
    fn writable_slots(&self) -> u32 {
        let Some(m) = &self.m else { return 0 };
        let n = self.geo.ring;
        let (cp_pos, _) = self.geo.split(m.checkpoint_global);
        let mut free = u32::from(self.geo.slots - m.next_slot.min(self.geo.slots));
        let mut p = (m.head_pos + 1) % n;
        while p != cp_pos && p != m.head_pos {
            free += u32::from(self.geo.slots);
            p = (p + 1) % n;
        }
        free
    }

    /// Append one record (it gets the next seq).  Recycles the next ring
    /// sector when the head is full; retries a failed program in the next
    /// slot after VOIDing it (R3).  Returns the record's global slot.
    fn append(&mut self, mut rec: Rec) -> Result<u16, StorageError> {
        let mut attempts = 0;
        loop {
            let (k, sid, need_recycle) = {
                let m = self.m.as_ref().ok_or(StorageError::NotFormatted)?;
                (m.k_idx.clone(), m.store_id, m.next_slot >= self.geo.slots)
            };
            if need_recycle {
                self.recycle()?;
            }
            let m = self.m.as_mut().ok_or(StorageError::NotFormatted)?;
            rec.seq = m.head_seq + 1;
            let (pos, slot, rs) = (m.head_pos, m.next_slot, m.head_ring_seq);
            m.next_slot += 1;
            let global = self.geo.global(pos, slot);
            let enc = self.encode_slot(&rec, &k, &sid, rs, global);
            let len = self.slot_len();
            let ok = self
                .flash
                .get_mut()
                .program(self.geo.slot_offset(pos, slot), &enc[..len])
                .is_ok()
                && self.flash.get_mut().sync().is_ok()
                && self.read_slot(pos, slot, &k, &sid, rs).ok() == Some(Slot::Record(rec));
            if ok {
                let m = self.m.as_mut().ok_or(StorageError::NotFormatted)?;
                m.head_seq = rec.seq;
                m.head_global = global;
                return Ok(global);
            }
            // R3: retire the slot, retry the same seq in the next one.
            if self.program_void(pos, slot).is_err() {
                if let Some(m) = self.m.as_mut() {
                    m.poisoned = true;
                }
                return Err(StorageError::WriteError);
            }
            attempts += 1;
            if attempts >= APPEND_ATTEMPTS {
                return Err(StorageError::WriteError);
            }
        }
    }

    fn recycle(&mut self) -> Result<(), StorageError> {
        let (k, sid, next_pos, next_rs, cp_pos) = {
            let m = self.m.as_ref().ok_or(StorageError::NotFormatted)?;
            let n = self.geo.ring;
            (
                m.k_idx.clone(),
                m.store_id,
                (m.head_pos + 1) % n,
                m.head_ring_seq + 1,
                self.geo.split(m.checkpoint_global).0,
            )
        };
        // §6.2: never recycle the sector holding the newest checkpoint (or
        // anything after it).
        if next_pos == cp_pos {
            return Err(StorageError::KeystoreFull);
        }
        self.write_ring_header(next_pos, next_rs, &k, &sid)?;
        let m = self.m.as_mut().ok_or(StorageError::NotFormatted)?;
        m.head_pos = next_pos;
        m.head_ring_seq = next_rs;
        m.next_slot = 0;
        Ok(())
    }

    fn commit(&mut self, env: &mut dyn Env, rec: Rec) -> Result<u64, StorageError> {
        let global = self.append(rec)?;
        let (fg, seq) = {
            let m = self.m.as_mut().ok_or(StorageError::NotFormatted)?;
            let mut r = rec;
            r.seq = m.head_seq;
            if m.tail.push(Tail { rec: r }).is_err() {
                // Unreachable while checkpoints work (MAX_TAIL > threshold).
                m.poisoned = true;
            }
            (m.format_gen, m.head_seq)
        };
        if env
            .put_anchor(Anchor {
                format_gen: fg as u16,
                head_seq: seq,
                head_slot: global,
            })
            .is_err()
        {
            if let Some(m) = self.m.as_mut() {
                m.commit_blocked = true;
            }
            // Committed all the same: the host sees 6581 (§8.2).
            return Err(StorageError::WriteError);
        }
        Ok(seq)
    }

    /// Store a new version of `key_id`: `seal(seq, header_prefix, out)`
    /// writes the sealed blob into `out` (sealing with `object_header(…,
    /// seq, meta, len)` as AAD needs the seq first, so the engine passes it)
    /// and returns its length.  Refuses a new key ID when the store would
    /// lose its reserves (`KeystoreFull`, 6A84).
    pub fn put(
        &mut self,
        env: &mut dyn Env,
        key_id: u32,
        meta: Meta,
        seal: &mut Sealer<'_>,
    ) -> Result<(), StorageError> {
        self.writable_check(env)?;
        self.maybe_checkpoint(env)?;
        let old = self.lookup(key_id)?;
        let needed_snapshot = snapshot_sectors_for(self.live_estimate() + 1);
        let reserve = needed_snapshot + 1 + if old.is_none() { 1 } else { 0 };
        if self.free_sectors() < reserve as u32 {
            return Err(StorageError::KeystoreFull);
        }
        if self.writable_slots() < SLOT_RESERVE + 1 {
            return Err(StorageError::KeystoreFull);
        }
        let seq = self.next_seq().ok_or(StorageError::NotFormatted)?;
        let hint = (seq as u32).wrapping_mul(0x9E37_79B9);
        let sector = self.allocate(hint)?;
        let sid = self.store_id().ok_or(StorageError::NotFormatted)?;
        {
            let mut buf = self.buf.borrow_mut();
            buf.fill(0xFF);
            let len = seal(seq, &mut buf[OBJECT_HEADER..])?;
            if len > MAX_OBJECT_BLOB {
                return Err(StorageError::WriteError);
            }
            let h = object_header(&sid, key_id, seq, meta, len as u16);
            buf[..OBJECT_HEADER].copy_from_slice(&h);
        }
        self.program_sector_header_last(sector, OBJECT_HEADER)?;
        let rec = Rec {
            kind: Kind::Put,
            count: 1,
            key_id,
            sector,
            seq,
            aux: meta_aux(meta),
        };
        let committed = self.commit(env, rec);
        if let Some(m) = self.m.as_mut() {
            if committed.is_ok() || m.commit_blocked {
                Self::mark(m, sector, true);
            }
        }
        let committed_seq = committed?;
        if committed_seq != seq {
            // A retried append moved past a VOID: the object's header says
            // `seq`, the record another.  Rewrite the object under the new
            // seq is impossible after the commit, so fail closed.
            return Err(StorageError::IntegrityFailure);
        }
        if let Some(o) = old {
            let _ = self.flash.get_mut().erase_sector(o.sector);
            if let Some(m) = self.m.as_mut() {
                Self::mark(m, o.sector, false);
            }
        }
        Ok(())
    }

    /// Delete `key_id` (record first, then the sectors, §6 / F7).
    pub fn delete(&mut self, env: &mut dyn Env, key_id: u32) -> Result<(), StorageError> {
        self.writable_check(env)?;
        let Some(old) = self.lookup(key_id)? else {
            return Ok(());
        };
        self.maybe_checkpoint(env)?;
        self.commit(
            env,
            Rec {
                kind: Kind::Delete,
                count: 0,
                key_id,
                sector: 0,
                seq: 0,
                aux: 0,
            },
        )?;
        let _ = self.flash.get_mut().erase_sector(old.sector);
        if let Some(m) = self.m.as_mut() {
            Self::mark(m, old.sector, false);
        }
        Ok(())
    }

    /// Wipe every key of `group` (applet reset / SC-HSM INITIALIZE, §6):
    /// one WIPE_OWNER record carrying the new epoch generation, the anchor,
    /// then `rotate(new_gen)` (the caller writes the binding with the
    /// group's new epoch), then the group's sectors are erased.  Until
    /// `rotate` succeeds no other commit is allowed (R7).
    pub fn wipe_group(
        &mut self,
        env: &mut dyn Env,
        group: usize,
        rotate: &mut dyn FnMut(u32) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        if group >= 3 {
            return Err(StorageError::WriteError);
        }
        self.writable_check(env)?;
        self.maybe_checkpoint(env)?;
        let new_gen =
            (self.m.as_ref().ok_or(StorageError::NotFormatted)?.group_gen[group] + 1) & 0x00FF_FFFF;
        let tail_before = self.m.as_ref().map_or(0, |m| m.tail.len());
        self.commit(
            env,
            Rec {
                kind: Kind::Wipe,
                count: 0,
                key_id: 0,
                sector: 0,
                seq: 0,
                aux: group as u32 | new_gen << 8,
            },
        )?;
        if rotate(new_gen).is_err() {
            if let Some(m) = self.m.as_mut() {
                // Committed but not rotated: no further commit until the
                // next mount finishes or refuses it (R7).
                m.poisoned = true;
            }
            return Err(StorageError::WriteError);
        }
        if let Some(m) = self.m.as_mut() {
            m.group_gen[group] = new_gen;
        }
        // Erase what the group held, found in the index as it was before
        // the WIPE record (nothing was written since).  Batches of 64: an
        // erased sector is marked free and skipped by the next pass.
        let Some(mut m) = self.m.take() else {
            return Err(StorageError::NotFormatted);
        };
        loop {
            let mut batch: heapless::Vec<u32, 64> = heapless::Vec::new();
            let mut more = false;
            let walked = self.for_each_with_tail(&m, tail_before, &mut |e| {
                if group_of(e.key_id) == group
                    && Self::is_used(&m, e.sector)
                    && batch.push(e.sector).is_err()
                {
                    more = true;
                }
            });
            for &s in batch.iter() {
                let _ = self.flash.get_mut().erase_sector(s);
                Self::mark(&mut m, s, false);
            }
            if walked.is_err() || !more {
                break;
            }
        }
        self.m = Some(m);
        Ok(())
    }

    fn live_estimate(&self) -> usize {
        let Some(m) = &self.m else { return 0 };
        m.snapshot_entries + m.tail.len()
    }

    fn maybe_checkpoint(&mut self, env: &mut dyn Env) -> Result<(), StorageError> {
        let need = {
            let m = self.m.as_ref().ok_or(StorageError::NotFormatted)?;
            m.tail.len() >= self.geo.threshold
                || self.writable_slots() <= SLOT_RESERVE + u32::from(self.geo.slots)
        };
        if need {
            self.checkpoint(env)?;
        }
        Ok(())
    }

    /// Write a snapshot of every live entry, append CHECKPOINT, bring the
    /// anchor forward, then erase the previous snapshot (§7).  The new
    /// snapshot is a streaming merge of the old one (one verified sector at
    /// a time, in `buf2`) with the tail's keys (sorted, in RAM): no
    /// per-entry table, nothing large on the stack.
    pub fn checkpoint(&mut self, env: &mut dyn Env) -> Result<(), StorageError> {
        let Some(m) = self.m.take() else {
            return Err(StorageError::NotFormatted);
        };
        let r = self.checkpoint_with(&m, env);
        self.m = Some(m);
        let (sectors, count, all, hash, total) = r?;
        // The new snapshot's sectors are in use from now on (a failed
        // append releases them).
        if let Some(m) = self.m.as_mut() {
            for &s in sectors.iter() {
                Self::mark(m, s, true);
            }
        }
        // Append CHECKPOINT (seq = head + 1; the snapshot is as of head).
        let rec = Rec {
            kind: Kind::Checkpoint,
            count: count as u8,
            key_id: u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]),
            sector: sectors[0],
            seq: 0,
            aux: u32::from_le_bytes([hash[4], hash[5], hash[6], hash[7]]),
        };
        let global = match self.append(rec) {
            Ok(g) => g,
            Err(e) => {
                if let Some(m) = self.m.as_mut() {
                    for &s in sectors.iter() {
                        Self::mark(m, s, false);
                    }
                }
                return Err(e);
            }
        };
        let (old_snapshot, fg, seq) = {
            let m = self.m.as_mut().ok_or(StorageError::NotFormatted)?;
            let old = m.snapshot.clone();
            m.checkpoint = Checkpoint {
                seq: m.head_seq,
                first: sectors[0],
                count: count as u8,
                hash,
            };
            m.checkpoint_global = global;
            m.snapshot = sectors.clone();
            m.fence = all;
            m.snapshot_entries = total;
            m.tail.clear();
            (old, m.format_gen, m.head_seq)
        };
        if env
            .put_anchor(Anchor {
                format_gen: fg as u16,
                head_seq: seq,
                head_slot: global,
            })
            .is_err()
        {
            if let Some(m) = self.m.as_mut() {
                m.commit_blocked = true;
            }
            return Err(StorageError::WriteError);
        }
        for s in old_snapshot {
            if !sectors.contains(&s) {
                let _ = self.flash.get_mut().erase_sector(s);
                if let Some(m) = self.m.as_mut() {
                    Self::mark(m, s, false);
                }
            }
        }
        Ok(())
    }

    /// Write the merged snapshot to fresh sectors (marked used).  Returns
    /// the sectors, their count, the new fence table and the hash.
    #[allow(clippy::type_complexity)]
    fn checkpoint_with(
        &mut self,
        m: &Mounted,
        _env: &mut dyn Env,
    ) -> Result<
        (
            heapless::Vec<u32, MAX_SNAPSHOT_SECTORS>,
            usize,
            heapless::Vec<u32, MAX_SNAPSHOT_SECTORS>,
            [u8; 8],
            usize,
        ),
        StorageError,
    > {
        // The tail's distinct keys with a live PUT, sorted.
        let mut tail_keys: heapless::Vec<u32, MAX_TAIL> = heapless::Vec::new();
        for t in m.tail.iter() {
            if t.rec.kind == Kind::Put
                && tail_current(&m.tail, t.rec.key_id).is_some_and(|c| c.seq == t.rec.seq)
            {
                let _ = tail_keys.push(t.rec.key_id);
            }
        }
        tail_keys.sort_unstable();
        let mut w = 0;
        for r in 0..tail_keys.len() {
            if w == 0 || tail_keys[r] != tail_keys[w - 1] {
                tail_keys[w] = tail_keys[r];
                w += 1;
            }
        }
        tail_keys.truncate(w);
        // Count the merged entries first: the chain length goes in every
        // sector header.
        let mut total = tail_keys.len();
        for i in 0..m.snapshot.len() {
            let entries = self.load_old_snapshot(m, i)?;
            for j in 0..entries {
                let e = Entry::decode(&self.buf2[SNAP_HEADER + j * SNAP_ENTRY..]);
                if !tail_touches(&m.tail, e.key_id) {
                    total += 1;
                }
            }
        }
        let count = snapshot_sectors_for(total).max(1);
        if count > MAX_SNAPSHOT_SECTORS {
            return Err(StorageError::KeystoreFull);
        }
        let as_of = m.head_seq;
        // Allocate every sector first (the chain needs the next pointer);
        // mark them so the next allocation skips them.
        let mut sectors: heapless::Vec<u32, MAX_SNAPSHOT_SECTORS> = heapless::Vec::new();
        for i in 0..count {
            let s = self.allocate_in(m, &sectors, as_of as u32 + i as u32 * 7919)?;
            let _ = sectors.push(s);
        }
        // Merge.
        let mut fence: heapless::Vec<u32, MAX_SNAPSHOT_SECTORS> = heapless::Vec::new();
        let mut macs: heapless::Vec<[u8; 16], MAX_SNAPSHOT_SECTORS> = heapless::Vec::new();
        let mut out_n = 0usize;
        let mut out_idx = 0usize;
        let mut ti = 0usize;
        let mut written = 0usize;
        self.buf.get_mut().fill(0xFF);
        let mut emit = |me: &mut Self,
                        e: Entry,
                        out_n: &mut usize,
                        out_idx: &mut usize,
                        written: &mut usize|
         -> Result<(), StorageError> {
            if *out_n == 0 {
                let _ = fence.push(e.key_id);
            }
            let buf = me.buf.get_mut();
            e.encode(
                &mut buf
                    [SNAP_HEADER + *out_n * SNAP_ENTRY..SNAP_HEADER + (*out_n + 1) * SNAP_ENTRY],
            );
            *out_n += 1;
            *written += 1;
            if *out_n == SNAP_PER_SECTOR || *written == total {
                me.flush_snapshot_sector(m, &sectors, *out_idx, count, *out_n, as_of, &mut macs)?;
                *out_idx += 1;
                *out_n = 0;
                me.buf.get_mut().fill(0xFF);
            }
            Ok(())
        };
        let tail_entry = |k: u32| -> Entry {
            let r = tail_current(&m.tail, k).unwrap_or(Rec {
                kind: Kind::Put,
                count: 0,
                key_id: k,
                sector: 0,
                seq: 0,
                aux: 0,
            });
            Entry {
                key_id: k,
                sector: r.sector,
                seq: r.seq,
                meta: r.meta(),
            }
        };
        for i in 0..m.snapshot.len() {
            let entries = self.load_old_snapshot(m, i)?;
            for j in 0..entries {
                let e = Entry::decode(&self.buf2[SNAP_HEADER + j * SNAP_ENTRY..]);
                while ti < tail_keys.len() && tail_keys[ti] < e.key_id {
                    emit(
                        self,
                        tail_entry(tail_keys[ti]),
                        &mut out_n,
                        &mut out_idx,
                        &mut written,
                    )?;
                    ti += 1;
                }
                if !tail_touches(&m.tail, e.key_id) {
                    emit(self, e, &mut out_n, &mut out_idx, &mut written)?;
                }
            }
        }
        while ti < tail_keys.len() {
            emit(
                self,
                tail_entry(tail_keys[ti]),
                &mut out_n,
                &mut out_idx,
                &mut written,
            )?;
            ti += 1;
        }
        if total == 0 {
            // An empty store still has one (empty) snapshot sector.
            self.flush_snapshot_sector(m, &sectors, 0, count, 0, as_of, &mut macs)?;
            let _ = fence.push(u32::MAX);
        }
        Ok((sectors, count, fence, snapshot_hash(&macs), total))
    }

    fn load_old_snapshot(&mut self, m: &Mounted, i: usize) -> Result<usize, StorageError> {
        let s = m.snapshot[i];
        self.flash.get_mut().read(s * SECTOR, &mut self.buf2[..])?;
        let (_, entries, _, _) = parse_snapshot(
            &self.buf2,
            &m.k_idx,
            &m.store_id,
            m.checkpoint.seq.wrapping_sub(1),
            i as u16,
            m.checkpoint.count as u16,
        )
        .ok_or(StorageError::IntegrityFailure)?;
        Ok(entries)
    }

    #[allow(clippy::too_many_arguments)]
    fn flush_snapshot_sector(
        &mut self,
        m: &Mounted,
        sectors: &[u32],
        idx: usize,
        count: usize,
        n: usize,
        as_of: u64,
        macs: &mut heapless::Vec<[u8; 16], MAX_SNAPSHOT_SECTORS>,
    ) -> Result<(), StorageError> {
        let next = if idx + 1 < count { sectors[idx + 1] } else { 0 };
        let mac = finish_snapshot(
            self.buf.get_mut(),
            &m.k_idx,
            &m.store_id,
            as_of,
            idx as u16,
            count as u16,
            next,
            n,
            m.group_gen,
        );
        self.program_sector_header_last(sectors[idx], SNAP_HEADER)?;
        let _ = macs.push(mac);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Header {
    Blank,
    Invalid,
    Foreign,
    Valid(u32),
}

/// The newest tail record about `key_id` (PUT, DELETE, or a WIPE of its
/// group), if any.
fn tail_current(tail: &[Tail], key_id: u32) -> Option<Rec> {
    tail.iter().rev().map(|t| t.rec).find(|r| match r.kind {
        Kind::Put | Kind::Delete => r.key_id == key_id,
        Kind::Wipe => (r.aux & 0xFF) as usize == group_of(key_id),
        Kind::Checkpoint => false,
    })
}

fn tail_touches(tail: &[Tail], key_id: u32) -> bool {
    tail_current(tail, key_id).is_some()
}

fn snapshot_sectors_for(entries: usize) -> usize {
    entries.div_ceil(SNAP_PER_SECTOR)
}

fn snapshot_hash(macs: &[[u8; 16]]) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for m in macs {
        h.update(m);
    }
    let d = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

/// Fill in a snapshot sector's header and MAC (its `n` entries are
/// already in `buf` after the header).  Returns the MAC.
#[allow(clippy::too_many_arguments)]
fn finish_snapshot(
    buf: &mut [u8; SECTOR as usize],
    k: &[u8; 32],
    store_id: &[u8; 16],
    as_of: u64,
    index: u16,
    count: u16,
    next: u32,
    n: usize,
    gens: [u32; 3],
) -> [u8; 16] {
    buf[0..4].copy_from_slice(b"P2S2");
    buf[4..20].copy_from_slice(store_id);
    buf[20..28].copy_from_slice(&as_of.to_le_bytes());
    buf[28..30].copy_from_slice(&index.to_le_bytes());
    buf[30..32].copy_from_slice(&count.to_le_bytes());
    buf[32..34].copy_from_slice(&(n as u16).to_le_bytes());
    buf[34..38].copy_from_slice(&next.to_le_bytes());
    for (g, gen) in gens.iter().enumerate() {
        buf[38 + 3 * g..41 + 3 * g].copy_from_slice(&gen.to_le_bytes()[..3]);
    }
    buf[47] = 0;
    let mac = snapshot_mac(buf, k, n);
    buf[48..64].copy_from_slice(&mac);
    mac
}

fn snapshot_mac(buf: &[u8; SECTOR as usize], k: &[u8; 32], entries: usize) -> [u8; 16] {
    use hmac::Mac as _;
    let mut mac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(k).unwrap_or_else(|_| {
        <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(&[0; 32]).unwrap()
    });
    mac.update(&buf[..48]);
    mac.update(&buf[SNAP_HEADER..SNAP_HEADER + entries * SNAP_ENTRY]);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Parse and verify a snapshot sector: `(next, entries, mac, group gens)`.
fn parse_snapshot(
    buf: &[u8; SECTOR as usize],
    k: &[u8; 32],
    store_id: &[u8; 16],
    as_of: u64,
    index: u16,
    count: u16,
) -> Option<(u32, usize, [u8; 16], [u32; 3])> {
    if buf[0..4] != *b"P2S2" || buf[4..20] != *store_id {
        return None;
    }
    let u16_at = |i: usize| u16::from_le_bytes([buf[i], buf[i + 1]]);
    let mut seq = [0u8; 8];
    seq.copy_from_slice(&buf[20..28]);
    let entries = u16_at(32) as usize;
    if u64::from_le_bytes(seq) != as_of
        || u16_at(28) != index
        || u16_at(30) != count
        || entries > SNAP_PER_SECTOR
    {
        return None;
    }
    let mac = snapshot_mac(buf, k, entries);
    if !bool::from(mac.ct_eq(&buf[48..64])) {
        return None;
    }
    let next = u32::from_le_bytes([buf[34], buf[35], buf[36], buf[37]]);
    let mut gens = [0u32; 3];
    for (g, gen) in gens.iter_mut().enumerate() {
        let i = 38 + 3 * g;
        *gen = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], 0]);
    }
    Some((next, entries, mac, gens))
}
