//! RSA key pool — the slot region on internal flash.
//!
//! [`flash_layout::RSA_POOL_SECTORS`] sectors, one pooled key per sector
//! (slot).  A key is stored as a [`KeyObject`] blob encrypted under the
//! device storage key, exactly like a keystore object (AES-256-GCM, the
//! header as AAD); the slot header around it is plaintext.  The policy that
//! fills, rotates and issues keys is in `crate::rsa_pool`.
//!
//! # Slot format (one 4 KiB sector)
//! ```text
//! [0..4]   magic "P2RP"
//! [4]      format version (1)
//! [5]      size class (0 = RSA-2048, 1 = RSA-3072, 2 = RSA-4096)
//! [6..8]   blob length (u16 LE)
//! [8..12]  birth: pool clock in minutes (u32 LE)
//! [12..16] sequence number (u32 LE)
//! [16..20] CRC-32 of [0..16] || blob
//! [20..24] 0xFF (reserved)
//! [24..28] COMMIT word "CMIT" — programmed last
//! [28..32] TAKEN word: FF FF FF FF = available, anything else = taken
//! [32..]   the encrypted KeyObject blob
//! ```
//!
//! # Program-without-erase, power-cut safety
//! - **Write**: the slot is checked blank (erased first if not), then the
//!   header (COMMIT and TAKEN still 0xFF) and blob are programmed and read
//!   back, and the COMMIT word is programmed last.  A cut before COMMIT
//!   leaves a slot that is neither blank nor valid: it is erased before
//!   reuse and never issued.
//! - **Take**: the TAKEN word is programmed to 0 (1→0 only, no erase) and
//!   read back *before* the key is handed out.  A torn program leaves some
//!   bits cleared, which also reads as taken.  So a power cut can waste a
//!   key but can never issue one twice.
//! - **Erase**: retiring a key (rotation, take, pool off, INITIALIZE)
//!   erases its sector.  A torn erase leaves garbage, never a valid slot.
//!
//! The blob's own header binds it to its slot, size class, sequence number
//! and birth time: the KeyObject `key_id` (`pool_key_id(slot, class)`),
//! `generation` (= sequence number) and `use_count` (= birth) are in the
//! GCM AAD, and [`PoolRegion::get_key`] checks them against the slot and
//! its plaintext header.  A blob copied into another slot, or a header
//! edited to claim another size, sequence or age, does not decrypt to a
//! usable key.  A taken slot is erased right after the take (and by the
//! background if that erase fails), so there is no ciphertext left whose
//! TAKEN word could be "un-programmed" by erasing and rewriting the sector
//! from the same image.  Restoring an *older* image (with the key still
//! untaken) is the rollback class (S-15, `docs/AUDIT_2026-10.md`), out of
//! scope here as for every flash-backed state.

use pico2hsm_core::error::{CryptoError, HsmError, StorageError};
use pico2hsm_core::key::KeyType as CoreKeyType;

use super::flash_layout::{RSA_POOL_SECTORS, SECTOR};
use super::retry_counter::CounterFlash;
use crate::security::key_management::{KeyObject, MAX_BLOB_SIZE};

/// Slots in the region.
pub const POOL_SLOTS: usize = RSA_POOL_SECTORS as usize;
/// Most keys of one size the pool holds.
pub const MAX_DEPTH: u8 = 4;
const _: () = assert!(3 * MAX_DEPTH as usize <= POOL_SLOTS);

const MAGIC: [u8; 4] = *b"P2RP";
const VERSION: u8 = 1;
const COMMIT: [u8; 4] = *b"CMIT";
const AVAILABLE: [u8; 4] = [0xFF; 4];
const COMMIT_OFFSET: u32 = 24;
const TAKEN_OFFSET: u32 = 28;
/// Header bytes before the blob.
pub const HEADER: usize = 32;
/// Largest blob a slot holds.
pub const MAX_SLOT_BLOB: usize = SECTOR as usize - HEADER;
const _: () = assert!(MAX_BLOB_SIZE <= MAX_SLOT_BLOB);

/// A pooled key size.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizeClass {
    R2048 = 0,
    R3072 = 1,
    R4096 = 2,
}

impl SizeClass {
    /// Every class, smallest first.
    pub const ALL: [SizeClass; 3] = [SizeClass::R2048, SizeClass::R3072, SizeClass::R4096];

    /// Modulus bits.
    pub fn bits(self) -> u32 {
        match self {
            SizeClass::R2048 => 2048,
            SizeClass::R3072 => 3072,
            SizeClass::R4096 => 4096,
        }
    }

    /// The class of an on-flash class byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|c| *c as u8 == v)
    }

    /// The class of a key type (RSA-1024 and non-RSA: none).
    pub fn of_key_type(kt: CoreKeyType) -> Option<Self> {
        match kt {
            CoreKeyType::RsaPrivate2048 => Some(SizeClass::R2048),
            CoreKeyType::RsaPrivate3072 => Some(SizeClass::R3072),
            CoreKeyType::RsaPrivate4096 => Some(SizeClass::R4096),
            _ => None,
        }
    }

    /// The core key type.
    pub fn key_type(self) -> CoreKeyType {
        match self {
            SizeClass::R2048 => CoreKeyType::RsaPrivate2048,
            SizeClass::R3072 => CoreKeyType::RsaPrivate3072,
            SizeClass::R4096 => CoreKeyType::RsaPrivate4096,
        }
    }
}

/// The internal key id a pooled blob is encrypted under: never a keystore
/// id (applet byte 0xF0), and specific to the slot and size class.
pub fn pool_key_id(slot: u8, class: SizeClass) -> u32 {
    0x00F0_0000 | (u32::from(class as u8) << 8) | u32::from(slot)
}

/// What a slot holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    /// Header area erased (the sector is checked fully blank before use).
    Blank,
    /// A committed, untaken key.
    Valid {
        class: SizeClass,
        birth: u32,
        seq: u32,
    },
    /// Handed out (or its take was interrupted): never issued again.
    Taken,
    /// Torn write, unknown format or failed CRC: erase before reuse.
    Dirty,
}

impl SlotState {
    /// Needs an erase before the slot can be written.
    pub fn needs_erase(self) -> bool {
        matches!(self, SlotState::Taken | SlotState::Dirty)
    }
}

/// Persistence for the pool, as the applets and the background generator
/// see it.  Implemented by the keystore (the blob is encrypted with the
/// storage key) and by host-test stores.
pub trait PoolBackend {
    /// The slot table (kept in RAM; reading it costs no flash access).
    fn pool_slots(&mut self) -> Result<[SlotState; POOL_SLOTS], StorageError>;
    /// Encrypt `obj` and write it to the blank-or-dirty `slot`.  `obj`'s
    /// `key_id` / `generation` / `use_count` must be
    /// `pool_key_id(slot, class)` / `seq` / `birth`.
    fn pool_put(
        &mut self,
        slot: u8,
        class: SizeClass,
        birth: u32,
        seq: u32,
        obj: &KeyObject,
    ) -> Result<(), HsmError>;
    /// Read and decrypt a valid slot's key.
    fn pool_get(&mut self, slot: u8) -> Result<KeyObject, HsmError>;
    /// Durably mark a slot taken (before its key is handed out).
    fn pool_take(&mut self, slot: u8) -> Result<(), HsmError>;
    /// Erase a slot.
    fn pool_erase(&mut self, slot: u8) -> Result<(), HsmError>;
}

fn crc_of(header16: &[u8], blob: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(header16);
    h.update(blob);
    h.finalize()
}

/// The slot region over a [`CounterFlash`] (offsets relative to the
/// region) with its in-RAM slot table.
pub struct PoolRegion<F: CounterFlash> {
    flash: F,
    slots: [SlotState; POOL_SLOTS],
    /// The region could not be read at boot: every access fails closed.
    failed: bool,
}

impl<F: CounterFlash> PoolRegion<F> {
    /// Scan the region and build the slot table.
    pub fn open(flash: F) -> Self {
        let mut r = PoolRegion {
            flash,
            slots: [SlotState::Dirty; POOL_SLOTS],
            failed: false,
        };
        for slot in 0..POOL_SLOTS {
            match r.scan_slot(slot as u8) {
                Ok(s) => r.slots[slot] = s,
                Err(_) => r.failed = true,
            }
        }
        r
    }

    /// The underlying flash (tests inspect it).
    pub fn flash_mut(&mut self) -> &mut F {
        &mut self.flash
    }

    fn base(slot: u8) -> u32 {
        u32::from(slot) * SECTOR
    }

    fn check(&self, slot: u8) -> Result<(), StorageError> {
        if self.failed {
            return Err(StorageError::ReadError);
        }
        if slot as usize >= POOL_SLOTS {
            return Err(StorageError::WriteError);
        }
        Ok(())
    }

    fn scan_slot(&mut self, slot: u8) -> Result<SlotState, StorageError> {
        let mut h = [0u8; HEADER];
        self.flash.read(Self::base(slot), &mut h)?;
        if h.iter().all(|&b| b == 0xFF) {
            return Ok(SlotState::Blank);
        }
        if h[0..4] != MAGIC || h[4] != VERSION || h[24..28] != COMMIT {
            return Ok(SlotState::Dirty);
        }
        if h[28..32] != AVAILABLE {
            return Ok(SlotState::Taken);
        }
        let Some(class) = SizeClass::from_u8(h[5]) else {
            return Ok(SlotState::Dirty);
        };
        let len = u16::from_le_bytes([h[6], h[7]]) as usize;
        if len == 0 || len > MAX_SLOT_BLOB {
            return Ok(SlotState::Dirty);
        }
        // CRC over the blob, read in pieces (no sector buffer).
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&h[0..16]);
        let mut off = 0;
        let mut buf = [0u8; 256];
        while off < len {
            let n = (len - off).min(buf.len());
            self.flash
                .read(Self::base(slot) + HEADER as u32 + off as u32, &mut buf[..n])?;
            hasher.update(&buf[..n]);
            off += n;
        }
        if hasher.finalize().to_le_bytes() != h[16..20] {
            return Ok(SlotState::Dirty);
        }
        Ok(SlotState::Valid {
            class,
            birth: u32::from_le_bytes([h[8], h[9], h[10], h[11]]),
            seq: u32::from_le_bytes([h[12], h[13], h[14], h[15]]),
        })
    }

    /// The slot table.
    pub fn slots(&self) -> Result<[SlotState; POOL_SLOTS], StorageError> {
        if self.failed {
            return Err(StorageError::ReadError);
        }
        Ok(self.slots)
    }

    fn sector_is_blank(&mut self, slot: u8) -> Result<bool, StorageError> {
        let mut buf = [0u8; 256];
        let mut off = 0;
        while off < SECTOR {
            self.flash.read(Self::base(slot) + off, &mut buf)?;
            if buf.iter().any(|&b| b != 0xFF) {
                return Ok(false);
            }
            off += buf.len() as u32;
        }
        Ok(true)
    }

    /// Erase `slot` and check it blank.
    pub fn erase(&mut self, slot: u8) -> Result<(), StorageError> {
        self.check(slot)?;
        // Whatever happens next, the old content is no longer trusted.
        self.slots[slot as usize] = SlotState::Dirty;
        self.flash.erase_sector(u32::from(slot))?;
        if !self.sector_is_blank(slot)? {
            return Err(StorageError::EraseError);
        }
        self.slots[slot as usize] = SlotState::Blank;
        crate::watchdog::progress();
        Ok(())
    }

    /// Write `blob` (already encrypted) to `slot` and commit it.
    pub fn write(
        &mut self,
        slot: u8,
        class: SizeClass,
        birth: u32,
        seq: u32,
        blob: &[u8],
    ) -> Result<(), StorageError> {
        self.check(slot)?;
        if blob.is_empty() || blob.len() > MAX_SLOT_BLOB {
            return Err(StorageError::WriteError);
        }
        if !self.sector_is_blank(slot)? {
            self.erase(slot)?;
        }
        self.slots[slot as usize] = SlotState::Dirty;
        let mut h = [0xFFu8; HEADER];
        h[0..4].copy_from_slice(&MAGIC);
        h[4] = VERSION;
        h[5] = class as u8;
        h[6..8].copy_from_slice(&(blob.len() as u16).to_le_bytes());
        h[8..12].copy_from_slice(&birth.to_le_bytes());
        h[12..16].copy_from_slice(&seq.to_le_bytes());
        let c = crc_of(&h[0..16], blob);
        h[16..20].copy_from_slice(&c.to_le_bytes());
        let base = Self::base(slot);
        self.flash.program(base, &h)?;
        self.flash.program(base + HEADER as u32, blob)?;
        crate::watchdog::progress();
        // Read back before committing.
        let mut rb = [0u8; HEADER];
        self.flash.read(base, &mut rb)?;
        if rb != h {
            return Err(StorageError::WriteError);
        }
        let mut buf = [0u8; 256];
        let mut off = 0;
        while off < blob.len() {
            let n = (blob.len() - off).min(buf.len());
            self.flash
                .read(base + HEADER as u32 + off as u32, &mut buf[..n])?;
            if buf[..n] != blob[off..off + n] {
                return Err(StorageError::WriteError);
            }
            off += n;
        }
        self.flash.program(base + COMMIT_OFFSET, &COMMIT)?;
        if self.scan_slot(slot)? != (SlotState::Valid { class, birth, seq }) {
            return Err(StorageError::WriteError);
        }
        self.slots[slot as usize] = SlotState::Valid { class, birth, seq };
        Ok(())
    }

    /// Mark `slot` taken (program-without-erase) and check it reads taken.
    pub fn take(&mut self, slot: u8) -> Result<(), StorageError> {
        self.check(slot)?;
        if !matches!(self.slots[slot as usize], SlotState::Valid { .. }) {
            return Err(StorageError::WriteError);
        }
        // From here on the slot is never issued, whatever the flash says.
        self.slots[slot as usize] = SlotState::Taken;
        let base = Self::base(slot);
        let prog = self.flash.program(base + TAKEN_OFFSET, &[0u8; 4]);
        let mut w = [0u8; 4];
        self.flash.read(base + TAKEN_OFFSET, &mut w)?;
        if w == AVAILABLE {
            // Not marked on flash: a reboot would see the key as available.
            return Err(prog.err().unwrap_or(StorageError::WriteError));
        }
        Ok(())
    }

    /// Read a valid slot's blob into `out`; returns its length.  The header
    /// and CRC are checked again (the table could be stale only through a
    /// bug, but a take must never rely on that).
    pub fn read_blob(
        &mut self,
        slot: u8,
        out: &mut [u8],
    ) -> Result<(usize, SizeClass, u32, u32), StorageError> {
        self.check(slot)?;
        match self.scan_slot(slot)? {
            SlotState::Valid { class, seq, birth }
                if self.slots[slot as usize] != SlotState::Taken =>
            {
                let mut h = [0u8; HEADER];
                self.flash.read(Self::base(slot), &mut h)?;
                let len = u16::from_le_bytes([h[6], h[7]]) as usize;
                if len > out.len() {
                    return Err(StorageError::ReadError);
                }
                self.flash
                    .read(Self::base(slot) + HEADER as u32, &mut out[..len])?;
                Ok((len, class, seq, birth))
            }
            _ => Err(StorageError::IntegrityFailure),
        }
    }

    /// Encrypt `obj` under `smk` with `nonce` and write it.
    pub fn put_key(
        &mut self,
        smk: &[u8; 32],
        nonce: &[u8; 12],
        slot: u8,
        class: SizeClass,
        birth: u32,
        seq: u32,
        obj: &KeyObject,
    ) -> Result<(), HsmError> {
        if obj.key_id != pool_key_id(slot, class) || obj.generation != seq || obj.use_count != birth
        {
            return Err(HsmError::InvalidInput);
        }
        let mut blob = obj
            .encrypt(smk, nonce)
            .map_err(|_| HsmError::Crypto(CryptoError::EncryptFailure))?;
        let r = self.write(slot, class, birth, seq, &blob);
        // Ciphertext only, but don't leave copies around either.
        zeroize::Zeroize::zeroize(&mut blob[..]);
        r.map_err(HsmError::Storage)
    }

    /// Read and decrypt a valid slot's key under `smk`.
    pub fn get_key(&mut self, smk: &[u8; 32], slot: u8) -> Result<KeyObject, HsmError> {
        let mut buf = [0u8; MAX_BLOB_SIZE];
        let (len, class, seq, birth) = self.read_blob(slot, &mut buf).map_err(HsmError::Storage)?;
        let id = pool_key_id(slot, class);
        let obj = KeyObject::decrypt(&buf[..len], id, smk)
            .map_err(|_| HsmError::Crypto(CryptoError::DecryptFailure));
        zeroize::Zeroize::zeroize(&mut buf[..]);
        let obj = obj?;
        // The authenticated copies of the header's sequence and birth.
        if obj.generation != seq || obj.use_count != birth {
            return Err(HsmError::Storage(StorageError::IntegrityFailure));
        }
        Ok(obj)
    }
}

// ─── Host-test flash and store ───────────────────────────────────────────────

/// NOR flash simulator for the pool region (and its host tests): program
/// ANDs bits in, erase sets 0xFF; it can cut power after a number of
/// programmed bytes, leaving the interrupted program half done.
#[cfg(test)]
#[derive(Clone)]
pub struct SimFlash {
    pub data: std::vec::Vec<u8>,
    /// Bytes still programmable before the simulated power cut.
    pub program_budget: Option<usize>,
    /// Fail every erase.
    pub fail_erase: bool,
    pub erases: usize,
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
impl SimFlash {
    pub fn new() -> Self {
        SimFlash {
            data: std::vec![0xFF; POOL_SLOTS * SECTOR as usize],
            program_budget: None,
            fail_erase: false,
            erases: 0,
        }
    }

    /// Power back on: same contents, no fault armed.
    pub fn reboot(&self) -> Self {
        SimFlash {
            data: self.data.clone(),
            program_budget: None,
            fail_erase: false,
            erases: 0,
        }
    }
}

#[cfg(test)]
impl CounterFlash for SimFlash {
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        let o = offset as usize;
        let src = self
            .data
            .get(o..o + buf.len())
            .ok_or(StorageError::ReadError)?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError> {
        let o = offset as usize;
        if o + data.len() > self.data.len() {
            return Err(StorageError::WriteError);
        }
        for (i, &b) in data.iter().enumerate() {
            if let Some(budget) = self.program_budget.as_mut() {
                if *budget == 0 {
                    return Err(StorageError::WriteError);
                }
                *budget -= 1;
            }
            self.data[o + i] &= b;
        }
        Ok(())
    }

    fn erase_sector(&mut self, sector: u32) -> Result<(), StorageError> {
        if self.fail_erase {
            return Err(StorageError::EraseError);
        }
        let s = sector as usize * SECTOR as usize;
        if s + SECTOR as usize > self.data.len() {
            return Err(StorageError::EraseError);
        }
        self.data[s..s + SECTOR as usize].fill(0xFF);
        self.erases += 1;
        Ok(())
    }
}

/// A [`PoolBackend`] over a simulated region with a fixed test storage key.
#[cfg(test)]
pub struct MemPool {
    pub region: PoolRegion<SimFlash>,
    pub smk: [u8; 32],
    pub nonce: u64,
    /// Fail every `pool_take`.
    pub fail_take: bool,
}

#[cfg(test)]
impl MemPool {
    pub fn new() -> Self {
        MemPool {
            region: PoolRegion::open(SimFlash::new()),
            smk: [0x42; 32],
            nonce: 0,
            fail_take: false,
        }
    }

    /// Simulated power cycle: reopen the region from the same flash.
    pub fn reboot(&mut self) {
        let flash = self.region.flash_mut().reboot();
        self.region = PoolRegion::open(flash);
    }
}

#[cfg(test)]
impl PoolBackend for MemPool {
    fn pool_slots(&mut self) -> Result<[SlotState; POOL_SLOTS], StorageError> {
        self.region.slots()
    }
    fn pool_put(
        &mut self,
        slot: u8,
        class: SizeClass,
        birth: u32,
        seq: u32,
        obj: &KeyObject,
    ) -> Result<(), HsmError> {
        self.nonce += 1;
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.nonce.to_le_bytes());
        let smk = self.smk;
        self.region
            .put_key(&smk, &nonce, slot, class, birth, seq, obj)
    }
    fn pool_get(&mut self, slot: u8) -> Result<KeyObject, HsmError> {
        let smk = self.smk;
        self.region.get_key(&smk, slot)
    }
    fn pool_take(&mut self, slot: u8) -> Result<(), HsmError> {
        if self.fail_take {
            return Err(HsmError::Storage(StorageError::WriteError));
        }
        self.region.take(slot).map_err(HsmError::Storage)
    }
    fn pool_erase(&mut self, slot: u8) -> Result<(), HsmError> {
        self.region.erase(slot).map_err(HsmError::Storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::key_management::{AlgorithmId, KeyType as KmType};
    use pico2hsm_core::key::AppletId;

    fn obj(slot: u8, class: SizeClass, seq: u32) -> KeyObject {
        obj_born(slot, class, seq, 0)
    }

    fn obj_born(slot: u8, class: SizeClass, seq: u32, birth: u32) -> KeyObject {
        let mut o = KeyObject::new(
            KmType::Rsa,
            pool_key_id(slot, class),
            AppletId::ScHsm,
            AlgorithmId::RsaDecrypt,
        );
        o.generation = seq;
        o.use_count = birth;
        o.private_key.extend_from_slice(&[0xA5; 1200]).unwrap();
        o.public_key.extend_from_slice(&[0x5A; 258]).unwrap();
        o
    }

    #[test]
    fn write_reopen_take_erase() {
        let mut p = MemPool::new();
        assert_eq!(p.pool_slots().unwrap(), [SlotState::Blank; POOL_SLOTS]);
        p.pool_put(
            3,
            SizeClass::R2048,
            100,
            7,
            &obj_born(3, SizeClass::R2048, 7, 100),
        )
        .unwrap();
        p.reboot();
        let s = p.pool_slots().unwrap();
        assert_eq!(
            s[3],
            SlotState::Valid {
                class: SizeClass::R2048,
                birth: 100,
                seq: 7
            }
        );
        let k = p.pool_get(3).unwrap();
        assert_eq!(&k.private_key[..], &[0xA5; 1200][..]);
        p.pool_take(3).unwrap();
        assert!(p.pool_get(3).is_err());
        p.reboot();
        assert_eq!(p.pool_slots().unwrap()[3], SlotState::Taken);
        assert!(p.pool_get(3).is_err());
        p.pool_erase(3).unwrap();
        p.reboot();
        assert_eq!(p.pool_slots().unwrap()[3], SlotState::Blank);
    }

    #[test]
    fn mismatched_ids_are_refused() {
        let mut p = MemPool::new();
        // Wrong slot in the key id.
        assert!(p
            .pool_put(1, SizeClass::R2048, 0, 1, &obj(2, SizeClass::R2048, 1))
            .is_err());
        // Wrong sequence.
        assert!(p
            .pool_put(1, SizeClass::R2048, 0, 1, &obj(1, SizeClass::R2048, 2))
            .is_err());
    }

    #[test]
    fn a_blob_moved_to_another_slot_does_not_decrypt() {
        let mut p = MemPool::new();
        p.pool_put(
            0,
            SizeClass::R3072,
            5,
            9,
            &obj_born(0, SizeClass::R3072, 9, 5),
        )
        .unwrap();
        let sector = SECTOR as usize;
        let copy: std::vec::Vec<u8> = p.region.flash_mut().data[..sector].to_vec();
        p.region.flash_mut().data[sector..2 * sector].copy_from_slice(&copy);
        p.reboot();
        assert!(matches!(
            p.pool_slots().unwrap()[1],
            SlotState::Valid { .. }
        ));
        assert!(p.pool_get(1).is_err());
        assert!(p.pool_get(0).is_ok());
    }

    /// Rewrites a slot's plaintext header field at `off` (with a fixed-up
    /// CRC) — what an attacker with flash access could do in place.
    fn tamper_header(p: &mut MemPool, slot: usize, off: usize, value: &[u8]) {
        let sector = SECTOR as usize;
        let data = &mut p.region.flash_mut().data;
        let base = slot * sector;
        data[base + off..base + off + value.len()].copy_from_slice(value);
        let len = u16::from_le_bytes([data[base + 6], data[base + 7]]) as usize;
        let mut h = crc32fast::Hasher::new();
        h.update(&data[base..base + 16]);
        h.update(&data[base + 32..base + 32 + len]);
        let c = h.finalize().to_le_bytes();
        data[base + 16..base + 20].copy_from_slice(&c);
    }

    #[test]
    fn header_tampering_in_place_is_caught() {
        // Claim another size, another sequence number, a younger birth.
        for (off, value) in [
            (5usize, &[SizeClass::R4096 as u8][..]),
            (12, &8u32.to_le_bytes()[..]),
            (8, &999u32.to_le_bytes()[..]),
        ] {
            let mut p = MemPool::new();
            p.pool_put(
                2,
                SizeClass::R2048,
                10,
                7,
                &obj_born(2, SizeClass::R2048, 7, 10),
            )
            .unwrap();
            tamper_header(&mut p, 2, off, value);
            p.reboot();
            // The header parses (CRC fixed up) ...
            assert!(matches!(
                p.pool_slots().unwrap()[2],
                SlotState::Valid { .. }
            ));
            // ... but the authenticated copy disagrees: refused.
            assert!(p.pool_get(2).is_err(), "tamper at {off}");
        }
    }

    #[test]
    fn birth_must_match_on_put() {
        let mut p = MemPool::new();
        assert!(p
            .pool_put(
                1,
                SizeClass::R2048,
                5,
                1,
                &obj_born(1, SizeClass::R2048, 1, 6)
            )
            .is_err());
    }

    #[test]
    fn torn_write_is_never_valid() {
        let o = obj_born(2, SizeClass::R4096, 1, 1);
        let mut written = 0;
        // Cut power after every possible number of programmed bytes.
        for budget in (0..1600).step_by(37).chain([1650, 1700, 1800, 4000]) {
            let mut p = MemPool::new();
            p.region.flash_mut().program_budget = Some(budget);
            let r = p.pool_put(2, SizeClass::R4096, 1, 1, &o);
            p.reboot();
            let st = p.pool_slots().unwrap()[2];
            match r {
                Ok(()) => {
                    written += 1;
                    assert!(matches!(st, SlotState::Valid { .. }));
                }
                Err(_) => assert!(
                    matches!(st, SlotState::Dirty | SlotState::Blank),
                    "budget {budget}: {st:?}"
                ),
            }
        }
        assert!(written > 0);
    }

    #[test]
    fn torn_take_reads_as_taken_or_fails_closed() {
        for budget in 0..4 {
            let mut p = MemPool::new();
            p.pool_put(0, SizeClass::R2048, 0, 1, &obj(0, SizeClass::R2048, 1))
                .unwrap();
            p.region.flash_mut().program_budget = Some(budget);
            let r = p.pool_take(0);
            p.reboot();
            let st = p.pool_slots().unwrap()[0];
            // Either the take failed before any bit was cleared (the key
            // stays available and was *not* handed out), or the slot is
            // taken for good.
            match r {
                Ok(()) => assert_eq!(st, SlotState::Taken),
                Err(_) => assert!(budget == 0 && matches!(st, SlotState::Valid { .. })),
            }
        }
    }

    #[test]
    fn dirty_slot_is_erased_before_rewrite() {
        let mut p = MemPool::new();
        p.region.flash_mut().data[5] = 0x00; // stray bits in slot 0
        p.reboot();
        assert_eq!(p.pool_slots().unwrap()[0], SlotState::Dirty);
        p.pool_put(0, SizeClass::R2048, 0, 1, &obj(0, SizeClass::R2048, 1))
            .unwrap();
        assert!(matches!(
            p.pool_slots().unwrap()[0],
            SlotState::Valid { .. }
        ));
        assert!(p.pool_get(0).is_ok());
    }
}
