//! PKCS#15 key filesystem — logical key storage on top of the physical layer.
//!
//! This module provides:
//!
//! - **`Directory`** — an in-RAM cache of all key locations.  The directory
//!   is loaded from flash sector 0 of each chip at mount time and kept
//!   synchronised on every write/delete.
//!
//! - **`KeyFilesystem<Chip>`** — logical key storage layer that translates
//!   `read_key` / `write_key` / `delete_key` calls into physical sector
//!   operations on a `FlashChip` implementation.
//!
//! The `KeyFilesystem` does **not** perform any encryption or RAID
//! mirroring — those responsibilities belong to the `StorageManager` in
//! `mod.rs`.
//!
//! # Directory: two copies, A/B (sectors 0 and 1)
//! ```text
//! [0..4]    Magic  *b"P2D2"
//! [4..6]    Entry count (u16 LE)
//! [6..8]    Reserved (0)
//! [8..12]   Sequence number (u32 LE) — the higher valid copy is current
//! [12..16]  CRC32 of [4..12] and the entries
//! [16..N]   DirectoryEntry records (12 bytes each)
//! [N..4096] Padding (0xFF)
//! ```
//! A flush writes the copy that is *not* current, so losing power during
//! the erase or program leaves the previous directory intact (the torn
//! copy fails its CRC).  Each copy is erased half as often as the single
//! sector 0 was.  Sector 1 was reserved for a write-ahead log that is not
//! used at runtime.
//!
//! The legacy single-copy format (`P2KD` in sector 0, XOR checksum) is
//! still read, as sequence 0; the first flush writes copy B.
//!
//! Falling back to the older copy rolls the directory back by one flush.
//! Only someone able to corrupt the newer copy can force that, and such an
//! attacker can already replay a whole old flash image (no anti-rollback
//! counter; see S-15 in docs/AUDIT_2026-10.md).  What it can resurrect is
//! limited: deleted and superseded objects have their data sectors erased
//! before or right after the flush, and every applet loads a credential
//! record it can't read as blocked or unset, never as a factory default
//! (SC-HSM: no PIN, so VERIFY refuses; PIV/OpenPGP: blocked).
//!
//! Maximum entries per copy: (4096 - 16) / 12 = 340.

use crate::storage::{
    integrity::{
        compute_object_crc32, compute_plaintext_blake2s, read_header, verify_header_crc32,
        verify_magic, write_header, IntegrityChecker, HEADER_SIZE,
    },
    wal::{Wal, WalRecovery},
};
use heapless::Vec;
use pico2hsm_core::{
    error::StorageError,
    flash::{FlashChip, PAGE_SIZE, SECTOR_SIZE},
    key::{KeyId, KeyRecord, KeyType},
    storage::{
        ChipState, DATA_START_SECTOR, DIRECTORY_SECTOR, SECTOR_MAGIC, WAL_SECTOR_0, WAL_SECTOR_1,
    },
    storage::{DirectoryEntry, ObjectHeader},
};

// ─── Directory sector constants ───────────────────────────────────────────────

/// Magic of the legacy single-copy directory (XOR checksum, read only).
const DIR_MAGIC_LEGACY: [u8; 4] = *b"P2KD";
/// Size of the legacy header (magic + count + xor16).
const DIR_HEADER_SIZE_LEGACY: usize = 8;
/// Magic of an A/B directory copy.
const DIR_MAGIC: [u8; 4] = *b"P2D2";
/// Size of the A/B header (magic + count + reserved + seq + crc32).
const DIR_HEADER_SIZE: usize = 16;
/// Sectors holding directory copies A and B.  Sector 1 doubles as the
/// first WAL sector, which nothing uses at runtime (`wal.rs`).
pub const DIR_SLOTS: [u32; 2] = [DIRECTORY_SECTOR, WAL_SECTOR_0];
/// Size of a single `DirectoryEntry` on disk (packed layout).
const DIR_ENTRY_SIZE: usize = 12;
/// Maximum number of directory entries in one sector.
const DIR_MAX_ENTRIES: usize = (SECTOR_SIZE - DIR_HEADER_SIZE) / DIR_ENTRY_SIZE;
/// Maximum entries tracked in the in-RAM `Directory` — exactly what one
/// directory sector can hold, so RAM can never accept an entry that
/// `serialize` would then fail to persist (was 512 vs. 340 on flash).
pub const MAX_DIRECTORY_ENTRIES: usize = DIR_MAX_ENTRIES;

// ─── Directory ────────────────────────────────────────────────────────────────

/// In-RAM directory: maps `KeyId` → physical location (`DirectoryEntry`).
pub struct Directory {
    pub entries: Vec<DirectoryEntry, MAX_DIRECTORY_ENTRIES>,
    /// `true` if entries have been added/removed since last serialisation.
    pub dirty: bool,
}

impl Directory {
    /// Create an empty directory.
    pub fn new() -> Self {
        Directory {
            entries: Vec::new(),
            dirty: false,
        }
    }

    /// Find the directory entry for a key ID.
    pub fn find(&self, key_id: KeyId) -> Option<&DirectoryEntry> {
        self.entries
            .iter()
            .find(|e| e.key_id == key_id.0 && (e.flags & 0x01) == 0)
    }

    /// Find a mutable reference to the directory entry for a key ID.
    pub fn find_mut(&mut self, key_id: KeyId) -> Option<&mut DirectoryEntry> {
        self.entries
            .iter_mut()
            .find(|e| e.key_id == key_id.0 && (e.flags & 0x01) == 0)
    }

    /// Add or update a directory entry.
    ///
    /// If an entry with the same `key_id` already exists it is replaced;
    /// otherwise the new entry is appended.
    pub fn insert(&mut self, entry: DirectoryEntry) -> Result<(), StorageError> {
        // Replace existing entry if present.
        if let Some(e) = self.entries.iter_mut().find(|e| e.key_id == entry.key_id) {
            *e = entry;
            self.dirty = true;
            return Ok(());
        }
        // Append, or reuse a tombstoned slot (tombstones are not written to
        // flash, so they must not use up capacity).
        if let Err(entry) = self.entries.push(entry) {
            let slot = self
                .entries
                .iter_mut()
                .find(|e| (e.flags & 0x01) != 0)
                .ok_or(StorageError::KeystoreFull)?;
            *slot = entry;
        }
        self.dirty = true;
        Ok(())
    }

    /// Remove an entry (tombstone: set bit 0 of `flags`).
    ///
    /// Returns `true` if the entry was found and marked deleted.
    pub fn remove(&mut self, key_id: KeyId) -> bool {
        for entry in self.entries.iter_mut() {
            if entry.key_id == key_id.0 && (entry.flags & 0x01) == 0 {
                entry.flags |= 0x01; // tombstone
                self.dirty = true;
                return true;
            }
        }
        false
    }

    /// Find a free sector on `chip_index` that is not referenced by any
    /// non-tombstoned directory entry.
    ///
    /// Sectors 0–2 are reserved (directory + WAL).  Search starts at
    /// `DATA_START_SECTOR` and returns the first gap.
    pub fn find_free_sector(&self, chip_index: u8, chip_capacity_sectors: u32) -> Option<u32> {
        'outer: for s in DATA_START_SECTOR..chip_capacity_sectors {
            for e in self.entries.iter() {
                if e.chip_index == chip_index
                    && (e.flags & 0x01) == 0
                    && s >= e.sector_index
                    && s < e.sector_index + e.sector_count as u32
                {
                    continue 'outer;
                }
            }
            return Some(s);
        }
        None
    }

    /// Serialise the directory into a 4096-byte sector buffer.
    ///
    /// Only non-tombstoned entries are written.  Extra space is padded with
    /// 0xFF (erased-flash value).
    /// Serialize an empty directory (what `Directory::new().serialize()`
    /// produces) without building the ~8 KB entry table on the stack.
    pub fn serialize_empty(buf: &mut [u8; SECTOR_SIZE], seq: u32) {
        buf.fill(0xFF);
        Self::finish_header(buf, 0, seq);
    }

    /// Fill in magic, count, sequence number and CRC32 (over everything
    /// from the count to the last entry).
    fn finish_header(buf: &mut [u8; SECTOR_SIZE], count: u16, seq: u32) {
        buf[0..4].copy_from_slice(&DIR_MAGIC);
        buf[4..6].copy_from_slice(&count.to_le_bytes());
        buf[6..8].copy_from_slice(&[0, 0]);
        buf[8..12].copy_from_slice(&seq.to_le_bytes());
        let crc = Self::crc_of(buf, count as usize);
        buf[12..16].copy_from_slice(&crc.to_le_bytes());
    }

    fn crc_of(buf: &[u8; SECTOR_SIZE], count: usize) -> u32 {
        let end = DIR_HEADER_SIZE + count * DIR_ENTRY_SIZE;
        let mut h = crc32fast::Hasher::new();
        h.update(&buf[4..12]);
        h.update(&buf[DIR_HEADER_SIZE..end]);
        h.finalize()
    }

    /// The sequence number of a valid directory copy in `buf`, or `None`
    /// (blank, torn, corrupt).  A legacy `P2KD` sector counts as sequence 0.
    pub fn validate(buf: &[u8; SECTOR_SIZE]) -> Option<u32> {
        let count = u16::from_le_bytes([buf[4], buf[5]]) as usize;
        if buf[0..4] == DIR_MAGIC {
            if count > DIR_MAX_ENTRIES {
                return None;
            }
            let stored = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
            (Self::crc_of(buf, count) == stored)
                .then(|| u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]))
        } else if buf[0..4] == DIR_MAGIC_LEGACY {
            let end = DIR_HEADER_SIZE_LEGACY + count * DIR_ENTRY_SIZE;
            if end > SECTOR_SIZE {
                return None;
            }
            let xor = buf[DIR_HEADER_SIZE_LEGACY..end]
                .iter()
                .fold(0u16, |a, &b| a ^ b as u16);
            (xor == u16::from_le_bytes([buf[6], buf[7]])).then_some(0)
        } else {
            None
        }
    }

    pub fn serialize(&self, buf: &mut [u8; SECTOR_SIZE], seq: u32) -> Result<(), StorageError> {
        buf.fill(0xFF);

        // Collect live entries.
        let mut count = 0u16;
        let mut offset = DIR_HEADER_SIZE;

        for entry in self.entries.iter().filter(|e| (e.flags & 0x01) == 0) {
            if offset + DIR_ENTRY_SIZE > SECTOR_SIZE {
                return Err(StorageError::KeystoreFull);
            }
            let chunk = &mut buf[offset..offset + DIR_ENTRY_SIZE];
            chunk[0..4].copy_from_slice(&entry.key_id.to_le_bytes());
            chunk[4] = entry.chip_index;
            chunk[5..9].copy_from_slice(&entry.sector_index.to_le_bytes());
            chunk[9] = entry.sector_count;
            chunk[10] = entry.flags;
            chunk[11] = entry._pad[0];
            offset += DIR_ENTRY_SIZE;
            count += 1;
        }

        Self::finish_header(buf, count, seq);
        Ok(())
    }

    /// Deserialise a directory from a 4096-byte sector buffer.
    pub fn deserialize(buf: &[u8; SECTOR_SIZE]) -> Result<Self, StorageError> {
        let mut dir = Directory::new();
        dir.deserialize_from(buf)?;
        Ok(dir)
    }

    /// Deserialise a directory sector into `self`, replacing all existing entries.
    ///
    /// Unlike `deserialize()` (which returns a new `Directory` on the stack),
    /// this writes directly into `self` — avoiding a 6 KB stack allocation
    /// for `Vec<DirectoryEntry, 512>` that can overflow core0's stack on
    /// boards with tight SRAM headroom (SD card variants).
    pub fn deserialize_from(&mut self, buf: &[u8; SECTOR_SIZE]) -> Result<(), StorageError> {
        let header_size = if buf[0..4] == DIR_MAGIC {
            DIR_HEADER_SIZE
        } else if buf[0..4] == DIR_MAGIC_LEGACY {
            DIR_HEADER_SIZE_LEGACY
        } else {
            return Err(StorageError::NotFormatted);
        };
        if Self::validate(buf).is_none() {
            return Err(StorageError::IntegrityFailure);
        }
        let count = u16::from_le_bytes([buf[4], buf[5]]) as usize;

        self.entries.clear();
        let mut offset = header_size;

        for _ in 0..count {
            if offset + DIR_ENTRY_SIZE > SECTOR_SIZE {
                break;
            }
            let chunk = &buf[offset..offset + DIR_ENTRY_SIZE];
            let key_id = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let chip_index = chunk[4];
            let sector_index = u32::from_le_bytes([chunk[5], chunk[6], chunk[7], chunk[8]]);
            let sector_count = chunk[9];
            let flags = chunk[10];
            let pad = chunk[11];

            let entry = DirectoryEntry {
                key_id,
                chip_index,
                sector_index,
                sector_count,
                flags,
                _pad: [pad],
            };
            self.entries
                .push(entry)
                .map_err(|_| StorageError::KeystoreFull)?;
            offset += DIR_ENTRY_SIZE;
        }

        self.dirty = false;
        Ok(())
    }

    /// Return an iterator over all live key IDs.
    pub fn list_keys(&self) -> impl Iterator<Item = KeyId> + '_ {
        self.entries
            .iter()
            .filter(|e| e.key_id != 0xFFFF_FFFF && (e.flags & 0x01) == 0)
            .map(|e| KeyId(e.key_id))
    }

    /// Number of entries (including tombstones).
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

// ─── ScrubReport ─────────────────────────────────────────────────────────────

/// Result of a background integrity scrub pass.
#[derive(Debug, Clone, Copy)]
pub struct ScrubReport {
    /// Number of chips scanned.
    pub chips_checked: u8,
    /// Total number of data sectors checked.
    pub sectors_checked: u32,
    /// Number of CRC32 failures detected.
    pub errors_found: u32,
    /// Number of errors automatically corrected from the RAID mirror.
    pub errors_corrected: u32,
}

// ─── KeyFilesystem<Chip> ──────────────────────────────────────────────────────

/// Logical key filesystem on top of a set of `FlashChip` instances.
///
/// Owns up to 8 chip slots (heapless Vec).  Each chip is accessed
/// directly — the caller (StorageManager) is responsible for choosing
/// which chip to use and handling RAID mirroring above this layer.
pub struct KeyFilesystem<Chip: FlashChip> {
    pub chips: Vec<Chip, 8>,
    pub directory: Directory,
    /// Index into `DIR_SLOTS` of the current directory copy.
    dir_slot: usize,
    /// Its sequence number; the next flush writes the other slot with +1.
    dir_seq: u32,
    /// Where the next allocation search starts.  Rotating it spreads
    /// erases over all free sectors instead of wearing out the lowest
    /// ones (a PIN record rewritten on every VERIFY used to ping-pong
    /// between the same two sectors).
    alloc_cursor: u32,
}

impl<Chip: FlashChip> KeyFilesystem<Chip> {
    /// Create a new (unmounted) `KeyFilesystem`.
    pub fn new() -> Self {
        KeyFilesystem {
            chips: Vec::new(),
            directory: Directory::new(),
            dir_slot: 0,
            dir_seq: 0,
            alloc_cursor: 0,
        }
    }

    /// Add a chip to the filesystem (call before `mount()`).
    pub fn add_chip(&mut self, chip: Chip) -> Result<(), StorageError> {
        self.chips
            .push(chip)
            .map_err(|_| StorageError::KeystoreFull)?;
        Ok(())
    }

    /// Mount the filesystem: scan all chips, load the directory, run WAL
    /// recovery.
    ///
    /// The directory is loaded from the first chip that presents a valid
    /// directory sector.  WAL recovery is run on every chip that has a
    /// valid WAL sector.
    pub fn mount(&mut self) -> Result<(), StorageError> {
        // Static buffer avoids 4 KB stack allocation — critical on SD card
        // boards with tight core0 stack headroom.
        // SAFETY: mount() is single-threaded, called once at init.
        static mut SECTOR0: [u8; SECTOR_SIZE] = [0u8; SECTOR_SIZE];
        let buf = unsafe { &mut *core::ptr::addr_of_mut!(SECTOR0) };

        // The newest valid copy on any chip: (chip, slot, seq).
        let mut best: Option<(usize, usize, u32)> = None;
        for chip_index in 0..self.chips.len() {
            for (slot, &sector) in DIR_SLOTS.iter().enumerate() {
                if self.chips[chip_index].read(sector * SECTOR_SIZE as u32, buf).is_err() {
                    defmt::warn!("KeyFilesystem: chip {} directory slot {} unreadable", chip_index, slot);
                    continue;
                }
                match Directory::validate(buf) {
                    Some(seq) if best.map_or(true, |(_, _, b)| seq > b) => {
                        best = Some((chip_index, slot, seq));
                    }
                    Some(_) => {}
                    None if IntegrityChecker::is_blank(buf) => {}
                    None => defmt::warn!(
                        "KeyFilesystem: chip {} directory slot {} invalid (torn or corrupt)",
                        chip_index,
                        slot
                    ),
                }
            }
        }

        let Some((chip_index, slot, seq)) = best else {
            defmt::warn!("KeyFilesystem: no valid directory found on any chip");
            // Not an error — the first flush creates one.
            return Ok(());
        };
        self.chips[chip_index]
            .read(DIR_SLOTS[slot] * SECTOR_SIZE as u32, buf)
            .map_err(|_| StorageError::ReadError)?;
        // Deserialise directly into self.directory to avoid a stack copy.
        self.directory.deserialize_from(buf)?;
        self.dir_slot = slot;
        self.dir_seq = seq;
        // Different boots start allocating in different places.
        self.alloc_cursor = seq.wrapping_mul(0x9E37_79B9);
        defmt::info!(
            "KeyFilesystem: directory from chip {} slot {} seq {} ({} entries)",
            chip_index,
            slot,
            seq,
            self.directory.len(),
        );
        Ok(())
    }

    /// Format a chip: write an empty directory to sector 0, clear WAL sectors.
    pub fn format_chip(&mut self, chip_index: usize) -> Result<(), StorageError> {
        if chip_index >= self.chips.len() {
            return Err(StorageError::WriteError);
        }
        let chip = &mut self.chips[chip_index];

        // Erase both directory copies and the remaining WAL sector.
        for &sector in DIR_SLOTS.iter() {
            chip.erase_sector(sector * SECTOR_SIZE as u32)?;
        }
        chip.erase_sector(WAL_SECTOR_1 * SECTOR_SIZE as u32)?;

        // Write an empty directory as copy A.
        let mut buf = [0xFFu8; SECTOR_SIZE];
        Directory::serialize_empty(&mut buf, 0);
        write_sector(chip, DIR_SLOTS[0] * SECTOR_SIZE as u32, &buf)?;
        self.dir_slot = 0;
        self.dir_seq = 0;

        defmt::info!("KeyFilesystem: chip {} formatted", chip_index);
        Ok(())
    }

    // ── Directory persistence ────────────────────────────────────────────────

    /// Flush the in-RAM directory to the non-current copy (A/B) of every chip.
    pub fn flush_directory(&mut self) -> Result<(), StorageError> {
        if !self.directory.dirty {
            return Ok(());
        }
        // Write the copy that is not current; the current one stays valid
        // until the new one is complete.
        let target = 1 - self.dir_slot;
        let seq = self.dir_seq.wrapping_add(1);
        let mut buf = [0u8; SECTOR_SIZE];
        self.directory.serialize(&mut buf, seq)?;

        // A failed write is reported, and the directory stays dirty: callers
        // (DELETE, INITIALIZE) must not believe a removal is durable when
        // the old directory — still listing the key — is what's on flash.
        let mut result = Ok(());
        for chip in self.chips.iter_mut() {
            let addr = DIR_SLOTS[target] * SECTOR_SIZE as u32;
            if let Err(e) = chip.erase_sector(addr) {
                defmt::warn!(
                    "KeyFilesystem: erase directory sector failed: {:?}",
                    defmt::Debug2Format(&e)
                );
                result = Err(e);
                continue;
            }
            if let Err(e) = write_sector(chip, addr, &buf) {
                defmt::warn!(
                    "KeyFilesystem: write directory sector failed: {:?}",
                    defmt::Debug2Format(&e)
                );
                result = Err(e);
            }
        }
        if result.is_ok() {
            self.directory.dirty = false;
            self.dir_slot = target;
            self.dir_seq = seq;
        }
        result
    }

    // ── Key read ─────────────────────────────────────────────────────────────

    /// Read a key object's encrypted blob from flash.
    ///
    /// Returns the ciphertext bytes (the caller decrypts and verifies BLAKE2s).
    pub fn read_key(
        &mut self,
        key_id: KeyId,
    ) -> Result<Vec<u8, { crate::security::key_management::MAX_BLOB_SIZE }>, StorageError> {
        let entry = self.directory.find(key_id).ok_or(StorageError::ReadError)?;

        let chip_index = entry.chip_index as usize;
        let sector_index = entry.sector_index;
        let sector_count = entry.sector_count as u32;

        if chip_index >= self.chips.len() {
            return Err(StorageError::ReadError);
        }

        let mut out: Vec<u8, { crate::security::key_management::MAX_BLOB_SIZE }> = Vec::new();
        // The total plaintext length is stored in the header; read it from the
        // first sector and use it to truncate the output (sector data is padded
        // to 256-byte alignment for CRC, but the caller needs the exact blob).
        let mut total_plaintext_len: usize = 0;

        for s in 0..sector_count {
            let addr = (sector_index + s) * SECTOR_SIZE as u32;
            let mut sector_buf = [0u8; SECTOR_SIZE];
            self.chips[chip_index].read(addr, &mut sector_buf)?;

            // Verify magic and CRC32.
            if !IntegrityChecker::verify_magic(&sector_buf) {
                return Err(StorageError::IntegrityFailure);
            }
            IntegrityChecker::verify_crc32(&sector_buf)?;

            // Parse header to know ciphertext length.
            let hdr = IntegrityChecker::read_header(&sector_buf)?;
            if s == 0 {
                total_plaintext_len = hdr.plaintext_len as usize;
            }
            // Read the padded extent (CRC covers padded data) but only push
            // up to the remaining plaintext bytes to avoid including padding.
            let max_ciphertext = SECTOR_SIZE - HEADER_SIZE;
            let already_read = out.len();
            let remaining = total_plaintext_len.saturating_sub(already_read);
            let chunk_len = remaining.min(max_ciphertext);

            let ciphertext = &sector_buf[HEADER_SIZE..HEADER_SIZE + chunk_len];
            for &b in ciphertext {
                out.push(b).map_err(|_| StorageError::ReadError)?;
            }
        }
        Ok(out)
    }

    // ── Key write ────────────────────────────────────────────────────────────

    /// Write a new key object.
    ///
    /// `encrypted_blob` is already encrypted by the caller.
    /// `plaintext_hash` is the BLAKE2s-256 digest of the decrypted key
    /// material (for post-decrypt verification by the caller).
    ///
    /// The function:
    /// 1. Finds a free sector on chip 0 (or the first chip with space).
    /// 2. Builds the sector data (header + ciphertext).
    /// 3. Writes via WAL for atomicity.
    /// 4. Updates the directory.
    pub fn write_key(
        &mut self,
        key_id: KeyId,
        key_type: KeyType,
        encrypted_blob: &[u8],
        plaintext_hash: &[u8; 32],
        sector_count: u8,
    ) -> Result<(), StorageError> {
        // Find a chip and free sector.
        let (chip_index, free_sector) = self.find_free_location(sector_count as u32)?;
        self.alloc_cursor = free_sector + sector_count as u32;

        // Determine seq_no — increment if key already exists.
        let seq_no = if let Some(e) = self.directory.find(key_id) {
            // Read existing sector to get old seq_no.
            let mut old_sector = [0u8; SECTOR_SIZE];
            let old_addr = e.sector_index * SECTOR_SIZE as u32;
            let old_chip = e.chip_index as usize;
            if old_chip < self.chips.len() {
                if self.chips[old_chip].read(old_addr, &mut old_sector).is_ok() {
                    if let Ok(old_hdr) = IntegrityChecker::read_header(&old_sector) {
                        old_hdr.seq_no.wrapping_add(1)
                    } else {
                        1
                    }
                } else {
                    1
                }
            } else {
                1
            }
        } else {
            1
        };

        let plaintext_len = encrypted_blob.len() as u16;

        // Build the sector buffer(s).
        // For simplicity we write the entire blob into consecutive sectors,
        // fitting as much ciphertext as possible per sector.
        let max_ciphertext_per_sector = SECTOR_SIZE - HEADER_SIZE;

        let mut header = ObjectHeader {
            magic: SECTOR_MAGIC,
            key_id: key_id.0,
            key_type: key_type as u8,
            flags: 0,
            plaintext_len,
            sector_count,
            seq_no,
            crc32: 0, // computed below
            blake2s: *plaintext_hash,
        };

        for s in 0..sector_count as u32 {
            let blob_start = (s as usize) * max_ciphertext_per_sector;
            let blob_end =
                core::cmp::min(blob_start + max_ciphertext_per_sector, encrypted_blob.len());
            let chunk = if blob_start < encrypted_blob.len() {
                &encrypted_blob[blob_start..blob_end]
            } else {
                &[]
            };

            let mut sector_buf = [0xFFu8; SECTOR_SIZE];

            // Write header (with crc32=0) and ciphertext into the sector buffer
            // first, then compute CRC over the padded sector.  The read path
            // rounds plaintext_len up to a 256-byte boundary, so the CRC must
            // cover the same padded extent (including trailing 0xFF bytes).
            write_header(&mut sector_buf, &header);
            if !chunk.is_empty() {
                sector_buf[HEADER_SIZE..HEADER_SIZE + chunk.len()].copy_from_slice(chunk);
            }
            let padded_len = (chunk.len() + 255) & !255;
            let crc = compute_object_crc32(
                &sector_buf[..HEADER_SIZE],
                &sector_buf[HEADER_SIZE..HEADER_SIZE + padded_len],
            );
            header.crc32 = crc;
            // Re-write header with the computed CRC.
            write_header(&mut sector_buf, &header);

            // Write via WAL using chip 0 as the WAL chip (simple strategy).
            let target_sector = free_sector + s;
            let addr = target_sector * SECTOR_SIZE as u32;

            // Write through WAL if this is the primary (chip 0) write.
            // For this single-chip filesystem layer, we write directly.
            // The RAID layer (caller) manages atomicity across mirrors.
            {
                let chip = &mut self.chips[chip_index];
                chip.erase_sector(addr)?;
                write_sector(chip, addr, &sector_buf)?;
            }
        }

        // Update directory.
        let new_entry = DirectoryEntry {
            key_id: key_id.0,
            chip_index: chip_index as u8,
            sector_index: free_sector,
            sector_count,
            flags: 0,
            _pad: [0],
        };
        // The entry being replaced, if any (live entries only).
        let superseded = self
            .directory
            .find(key_id)
            .map(|e| (e.chip_index as usize, e.sector_index, e.sector_count as u32));
        self.directory.insert(new_entry)?;
        self.flush_directory()?;
        // Only once the new copy is what the directory points at: erase the
        // old one, so a replaced key's ciphertext doesn't linger in a free
        // sector.  The save itself already succeeded; a failed erase here
        // leaves only unreferenced ciphertext.
        if let Some((chip, sector, count)) = superseded {
            let _ = self.erase_data_sectors(chip, sector, count);
        }
        Ok(())
    }

    // ── Key delete ────────────────────────────────────────────────────────────

    /// Delete a key: erase its sector(s), remove from directory.
    pub fn delete_key(&mut self, key_id: KeyId) -> Result<(), StorageError> {
        // Look up entry before removing from directory.
        let (chip_index, sector_index, sector_count) = {
            let entry = self.directory.find(key_id).ok_or(StorageError::ReadError)?;
            (
                entry.chip_index as usize,
                entry.sector_index,
                entry.sector_count as u32,
            )
        };

        if chip_index >= self.chips.len() {
            return Err(StorageError::WriteError);
        }

        // Erase the data sectors.  A failed erase is an error: the key's
        // ciphertext may still be on flash, and the caller must not report
        // it deleted.
        self.erase_data_sectors(chip_index, sector_index, sector_count)?;

        // Remove from directory.
        self.directory.remove(key_id);
        self.flush_directory()
    }

    fn erase_data_sectors(
        &mut self,
        chip_index: usize,
        sector_index: u32,
        sector_count: u32,
    ) -> Result<(), StorageError> {
        let chip = self.chips.get_mut(chip_index).ok_or(StorageError::WriteError)?;
        for s in 0..sector_count {
            let addr = (sector_index + s) * SECTOR_SIZE as u32;
            if let Err(e) = chip.erase_sector(addr) {
                defmt::warn!(
                    "KeyFilesystem: erase sector {} failed: {:?}",
                    sector_index + s,
                    defmt::Debug2Format(&e)
                );
                return Err(e);
            }
        }
        Ok(())
    }

    /// Delete every key whose id matches `pred`, writing the directory once.
    ///
    /// Walks the whole directory (no 64-entry cap: keys past it used to
    /// survive INITIALIZE).  Data sectors are erased before the directory
    /// drops the entry; a key whose erase fails stays listed and the call
    /// fails, but the rest are still removed.
    pub fn delete_where(&mut self, pred: &dyn Fn(KeyId) -> bool) -> Result<(), StorageError> {
        let mut result = Ok(());
        for i in 0..self.directory.entries.len() {
            let e = &self.directory.entries[i];
            if e.key_id == 0xFFFF_FFFF || (e.flags & 0x01) != 0 || !pred(KeyId(e.key_id)) {
                continue;
            }
            let (kid, chip, sector, count) = (
                KeyId(e.key_id),
                e.chip_index as usize,
                e.sector_index,
                e.sector_count as u32,
            );
            match self.erase_data_sectors(chip, sector, count) {
                Ok(()) => {
                    self.directory.remove(kid);
                }
                Err(err) => result = Err(err),
            }
        }
        let flushed = self.flush_directory();
        result.and(flushed)
    }

    // ── Key list ─────────────────────────────────────────────────────────────

    /// List all keys with their metadata.
    ///
    /// Returns a `Vec` of `KeyRecord` objects.  The `label` and
    /// `access_counter` fields are left at their defaults since they are
    /// not stored by the filesystem layer.
    pub fn list_keys(&self) -> Vec<KeyRecord, 64> {
        let mut out = Vec::new();
        for key_id in self.directory.list_keys() {
            if let Some(entry) = self.directory.find(key_id) {
                let key_type = key_type_from_u8(entry.flags >> 4); // top nibble = type tag
                let record = KeyRecord {
                    key_id,
                    key_type: key_type.unwrap_or(KeyType::Aes256),
                    label: heapless::String::new(),
                    flags: entry.flags as u16,
                    access_counter: 0,
                };
                let _ = out.push(record);
            }
        }
        out
    }

    // ── Integrity scrub ───────────────────────────────────────────────────────

    /// Verify CRC32 integrity of all key objects on all chips.
    pub fn scrub_all(&mut self) -> Result<ScrubReport, StorageError> {
        let mut report = ScrubReport {
            chips_checked: 0,
            sectors_checked: 0,
            errors_found: 0,
            errors_corrected: 0,
        };

        for chip_idx in 0..self.chips.len() {
            report.chips_checked += 1;
            let capacity = self.chips[chip_idx].capacity();
            let total_sectors = (capacity / SECTOR_SIZE as u64) as u32;

            for sector in DATA_START_SECTOR..total_sectors {
                let addr = sector * SECTOR_SIZE as u32;
                let mut buf = [0u8; SECTOR_SIZE];
                if self.chips[chip_idx].read(addr, &mut buf).is_err() {
                    report.errors_found += 1;
                    continue;
                }
                if IntegrityChecker::is_blank(&buf) {
                    continue;
                }
                report.sectors_checked += 1;
                if IntegrityChecker::verify_magic(&buf)
                    && IntegrityChecker::verify_crc32(&buf).is_err()
                {
                    defmt::warn!("scrub: CRC32 failure chip {} sector {}", chip_idx, sector);
                    report.errors_found += 1;
                }
            }
        }
        Ok(report)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Find a chip with at least `needed_sectors` free consecutive sectors
    /// starting at or after `DATA_START_SECTOR`.
    ///
    /// Returns `(chip_index, first_free_sector)`.
    fn find_free_location(&self, needed_sectors: u32) -> Result<(usize, u32), StorageError> {
        for (chip_idx, chip) in self.chips.iter().enumerate() {
            if chip.is_degraded() {
                continue;
            }
            let cap_sectors = (chip.capacity() / SECTOR_SIZE as u64) as u32;
            if cap_sectors <= DATA_START_SECTOR {
                continue;
            }
            // Find `needed_sectors` consecutive free sectors, searching from
            // the rotating cursor to the end, then from the start.
            let span = cap_sectors - DATA_START_SECTOR;
            let from = DATA_START_SECTOR + self.alloc_cursor % span;
            if let Some(start) = self
                .find_consecutive_free(chip_idx as u8, from, cap_sectors, needed_sectors)
                .or_else(|| {
                    self.find_consecutive_free(
                        chip_idx as u8,
                        DATA_START_SECTOR,
                        cap_sectors,
                        needed_sectors,
                    )
                })
            {
                return Ok((chip_idx, start));
            }
        }
        Err(StorageError::KeystoreFull)
    }

    /// Find `count` consecutive free sectors on `chip_index`.
    fn find_consecutive_free(
        &self,
        chip_index: u8,
        from: u32,
        chip_capacity_sectors: u32,
        count: u32,
    ) -> Option<u32> {
        let mut run_start = from;
        let mut run_len = 0u32;

        'sector: for s in from..chip_capacity_sectors {
            // Check if this sector is used by any directory entry.
            for entry in self.directory.entries.iter() {
                if entry.chip_index == chip_index
                    && (entry.flags & 0x01) == 0
                    && s >= entry.sector_index
                    && s < entry.sector_index + entry.sector_count as u32
                {
                    // Sector is occupied — reset run.
                    run_start = s + 1;
                    run_len = 0;
                    continue 'sector;
                }
            }
            run_len += 1;
            if run_len >= count {
                return Some(run_start);
            }
        }
        None
    }
}

// ─── Free functions ───────────────────────────────────────────────────────────

/// Write a full 4096-byte sector to a chip using 16 × 256-byte page writes.
pub fn write_sector<C: FlashChip>(
    chip: &mut C,
    addr: u32,
    data: &[u8; SECTOR_SIZE],
) -> Result<(), StorageError> {
    for p in 0..16usize {
        let page_addr = addr + (p * PAGE_SIZE) as u32;
        chip.write_page(page_addr, &data[p * PAGE_SIZE..(p + 1) * PAGE_SIZE])?;
    }
    Ok(())
}

/// Convert a `u8` key-type tag to a `KeyType`.
fn key_type_from_u8(tag: u8) -> Option<KeyType> {
    match tag {
        0 => Some(KeyType::RsaPrivate2048),
        1 => Some(KeyType::RsaPrivate4096),
        2 => Some(KeyType::EcPrivateP256),
        3 => Some(KeyType::EcPrivateP384),
        4 => Some(KeyType::EcPrivateP521),
        5 => Some(KeyType::EcPrivateK256),
        6 => Some(KeyType::EcPrivateBrainpoolP256),
        7 => Some(KeyType::EcPrivateBrainpoolP384),
        8 => Some(KeyType::EcPrivateBrainpoolP512),
        9 => Some(KeyType::Aes128),
        10 => Some(KeyType::Aes192),
        11 => Some(KeyType::Aes256),
        12 => Some(KeyType::Bip32Master),
        13 => Some(KeyType::Ed25519),
        14 => Some(KeyType::X25519),
        15 => Some(KeyType::RsaPrivate3072),
        _ => None,
    }
}
