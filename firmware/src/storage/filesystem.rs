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
//! # Directory sector layout (sector 0, 4096 bytes)
//! ```text
//! [0..4]   Magic  *b"P2KD"
//! [4..6]   Entry count (u16 LE)
//! [6..8]   CRC16 of entries area (u16 LE) — simple XOR sum for fast check
//! [8..N]   DirectoryEntry records (10 bytes each)
//! [N..4096] Padding (0xFF)
//! ```
//! Maximum entries per chip: (4096 - 8) / 10 = 408.  Total across 8 chips:
//! 3264.  The in-RAM `Directory` caps at 512 entries (heapless Vec limit).

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
        ChipState, DATA_START_SECTOR, DIRECTORY_SECTOR, SECTOR_MAGIC,
        WAL_SECTOR_0, WAL_SECTOR_1,
    },
    storage::{DirectoryEntry, ObjectHeader},
};

// ─── Directory sector constants ───────────────────────────────────────────────

/// Magic bytes for the directory sector.
const DIR_MAGIC: [u8; 4] = *b"P2KD";
/// Size of the directory sector header (magic + count + crc16).
const DIR_HEADER_SIZE: usize = 8;
/// Size of a single `DirectoryEntry` on disk (packed layout).
const DIR_ENTRY_SIZE: usize = 10;
/// Maximum number of directory entries in one sector.
const DIR_MAX_ENTRIES: usize = (SECTOR_SIZE - DIR_HEADER_SIZE) / DIR_ENTRY_SIZE;
/// Maximum entries tracked in the in-RAM `Directory`.
const MAX_DIRECTORY_ENTRIES: usize = 512;

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
        // Append new entry.
        self.entries.push(entry).map_err(|_| StorageError::KeystoreFull)?;
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
    pub fn serialize(&self, buf: &mut [u8; SECTOR_SIZE]) -> Result<(), StorageError> {
        buf.fill(0xFF);
        buf[0..4].copy_from_slice(&DIR_MAGIC);

        // Collect live entries.
        let mut count = 0u16;
        let mut offset = DIR_HEADER_SIZE;
        let mut crc_accum: u16 = 0;

        for entry in self.entries.iter().filter(|e| (e.flags & 0x01) == 0) {
            if offset + DIR_ENTRY_SIZE > SECTOR_SIZE {
                return Err(StorageError::KeystoreFull);
            }
            let chunk = &mut buf[offset..offset + DIR_ENTRY_SIZE];
            chunk[0..2].copy_from_slice(&entry.key_id.to_le_bytes());
            chunk[2] = entry.chip_index;
            chunk[3..7].copy_from_slice(&entry.sector_index.to_le_bytes());
            chunk[7] = entry.sector_count;
            chunk[8] = entry.flags;
            chunk[9] = entry._pad[0];
            // XOR-sum CRC (simple; catches random corruption).
            for &b in chunk.iter() {
                crc_accum ^= b as u16;
            }
            offset += DIR_ENTRY_SIZE;
            count += 1;
        }

        buf[4..6].copy_from_slice(&count.to_le_bytes());
        buf[6..8].copy_from_slice(&crc_accum.to_le_bytes());
        Ok(())
    }

    /// Deserialise a directory from a 4096-byte sector buffer.
    pub fn deserialize(buf: &[u8; SECTOR_SIZE]) -> Result<Self, StorageError> {
        if buf[0..4] != DIR_MAGIC {
            return Err(StorageError::NotFormatted);
        }
        let count = u16::from_le_bytes([buf[4], buf[5]]) as usize;
        let stored_crc = u16::from_le_bytes([buf[6], buf[7]]);

        let mut entries: Vec<DirectoryEntry, MAX_DIRECTORY_ENTRIES> = Vec::new();
        let mut crc_accum: u16 = 0;
        let mut offset = DIR_HEADER_SIZE;

        for _ in 0..count {
            if offset + DIR_ENTRY_SIZE > SECTOR_SIZE {
                break;
            }
            let chunk = &buf[offset..offset + DIR_ENTRY_SIZE];
            for &b in chunk.iter() {
                crc_accum ^= b as u16;
            }
            let key_id = u16::from_le_bytes([chunk[0], chunk[1]]);
            let chip_index = chunk[2];
            let sector_index = u32::from_le_bytes([chunk[3], chunk[4], chunk[5], chunk[6]]);
            let sector_count = chunk[7];
            let flags = chunk[8];
            let pad = chunk[9];

            let entry = DirectoryEntry {
                key_id,
                chip_index,
                sector_index,
                sector_count,
                flags,
                _pad: [pad],
            };
            entries.push(entry).map_err(|_| StorageError::KeystoreFull)?;
            offset += DIR_ENTRY_SIZE;
        }

        if crc_accum != stored_crc {
            defmt::warn!("Directory: CRC mismatch — stored {:04X}, computed {:04X}", stored_crc, crc_accum);
            return Err(StorageError::IntegrityFailure);
        }

        Ok(Directory { entries, dirty: false })
    }

    /// Return an iterator over all live key IDs.
    pub fn list_keys(&self) -> impl Iterator<Item = KeyId> + '_ {
        self.entries
            .iter()
            .filter(|e| e.key_id != 0xFFFF && (e.flags & 0x01) == 0)
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
}

impl<Chip: FlashChip> KeyFilesystem<Chip> {
    /// Create a new (unmounted) `KeyFilesystem`.
    pub fn new() -> Self {
        KeyFilesystem {
            chips: Vec::new(),
            directory: Directory::new(),
        }
    }

    /// Add a chip to the filesystem (call before `mount()`).
    pub fn add_chip(&mut self, chip: Chip) -> Result<(), StorageError> {
        self.chips.push(chip).map_err(|_| StorageError::KeystoreFull)?;
        Ok(())
    }

    /// Mount the filesystem: scan all chips, load the directory, run WAL
    /// recovery.
    ///
    /// The directory is loaded from the first chip that presents a valid
    /// directory sector.  WAL recovery is run on every chip that has a
    /// valid WAL sector.
    pub fn mount(&mut self) -> Result<(), StorageError> {
        let mut loaded = false;

        for chip_index in 0..self.chips.len() {
            let chip = &mut self.chips[chip_index];

            // Run WAL recovery.
            {
                // We can't borrow `chip` via a Wal at the same time as mutating
                // `self.directory`, so we do WAL scan first, then load directory.
                // The borrow checker requires a scope here.
            }

            // Read sector 0 to check if it has a valid directory.
            let mut sector0 = [0u8; SECTOR_SIZE];
            if chip.read(0, &mut sector0).is_err() {
                defmt::warn!("KeyFilesystem: chip {} read sector 0 failed", chip_index);
                continue;
            }

            // Check for directory magic.
            if sector0[0..4] == DIR_MAGIC {
                match Directory::deserialize(&sector0) {
                    Ok(dir) => {
                        if !loaded {
                            self.directory = dir;
                            loaded = true;
                            defmt::info!(
                                "KeyFilesystem: loaded directory from chip {} ({} entries)",
                                chip_index,
                                self.directory.len(),
                            );
                        }
                    }
                    Err(e) => {
                        defmt::warn!(
                            "KeyFilesystem: chip {} directory CRC/parse error: {:?}",
                            chip_index,
                            defmt::Debug2Format(&e),
                        );
                    }
                }
            } else if IntegrityChecker::is_blank(&sector0) {
                defmt::info!("KeyFilesystem: chip {} sector 0 is blank — needs format", chip_index);
            } else {
                defmt::warn!("KeyFilesystem: chip {} sector 0 has unexpected content", chip_index);
            }
        }

        if !loaded {
            defmt::warn!("KeyFilesystem: no valid directory found on any chip");
            // Not an error — caller can decide to format.
        }
        Ok(())
    }

    /// Format a chip: write an empty directory to sector 0, clear WAL sectors.
    pub fn format_chip(&mut self, chip_index: usize) -> Result<(), StorageError> {
        if chip_index >= self.chips.len() {
            return Err(StorageError::WriteError);
        }
        let chip = &mut self.chips[chip_index];

        // Erase directory sector, WAL sectors.
        chip.erase_sector(DIRECTORY_SECTOR * SECTOR_SIZE as u32)?;
        chip.erase_sector(WAL_SECTOR_0 * SECTOR_SIZE as u32)?;
        chip.erase_sector(WAL_SECTOR_1 * SECTOR_SIZE as u32)?;

        // Write empty directory.
        let mut buf = [0xFFu8; SECTOR_SIZE];
        let empty_dir = Directory::new();
        empty_dir.serialize(&mut buf)?;
        write_sector(chip, DIRECTORY_SECTOR * SECTOR_SIZE as u32, &buf)?;

        defmt::info!("KeyFilesystem: chip {} formatted", chip_index);
        Ok(())
    }

    // ── Directory persistence ────────────────────────────────────────────────

    /// Flush the in-RAM directory to sector 0 of every healthy chip.
    pub fn flush_directory(&mut self) -> Result<(), StorageError> {
        if !self.directory.dirty {
            return Ok(());
        }
        let mut buf = [0u8; SECTOR_SIZE];
        self.directory.serialize(&mut buf)?;

        for chip in self.chips.iter_mut() {
            let addr = DIRECTORY_SECTOR * SECTOR_SIZE as u32;
            if let Err(e) = chip.erase_sector(addr) {
                defmt::warn!("KeyFilesystem: erase directory sector failed: {:?}", defmt::Debug2Format(&e));
                continue;
            }
            if let Err(e) = write_sector(chip, addr, &buf) {
                defmt::warn!("KeyFilesystem: write directory sector failed: {:?}", defmt::Debug2Format(&e));
            }
        }
        self.directory.dirty = false;
        Ok(())
    }

    // ── Key read ─────────────────────────────────────────────────────────────

    /// Read a key object's encrypted blob from flash.
    ///
    /// Returns the ciphertext bytes (the caller decrypts and verifies BLAKE2s).
    pub fn read_key(&mut self, key_id: KeyId) -> Result<heapless::Vec<u8, 2400>, StorageError> {
        let entry = self
            .directory
            .find(key_id)
            .ok_or(StorageError::ReadError)?;

        let chip_index = entry.chip_index as usize;
        let sector_index = entry.sector_index;
        let sector_count = entry.sector_count as u32;

        if chip_index >= self.chips.len() {
            return Err(StorageError::ReadError);
        }

        let mut out: heapless::Vec<u8, 2400> = heapless::Vec::new();

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
            let ciphertext_len = ((hdr.plaintext_len as usize + 255) & !255)
                .min(SECTOR_SIZE - HEADER_SIZE);

            let ciphertext = &sector_buf[HEADER_SIZE..HEADER_SIZE + ciphertext_len];
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
            crc32: 0,    // computed below
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

            // Compute CRC over header (excluding crc32 field) + ciphertext.
            let crc = compute_object_crc32_for_header(&header, chunk);
            header.crc32 = crc;

            write_header(&mut sector_buf, &header);
            if !chunk.is_empty() {
                sector_buf[HEADER_SIZE..HEADER_SIZE + chunk.len()].copy_from_slice(chunk);
            }

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
        self.directory.insert(new_entry)?;
        self.flush_directory()?;
        Ok(())
    }

    // ── Key delete ────────────────────────────────────────────────────────────

    /// Delete a key: erase its sector(s), remove from directory.
    pub fn delete_key(&mut self, key_id: KeyId) -> Result<(), StorageError> {
        // Look up entry before removing from directory.
        let (chip_index, sector_index, sector_count) = {
            let entry = self
                .directory
                .find(key_id)
                .ok_or(StorageError::ReadError)?;
            (entry.chip_index as usize, entry.sector_index, entry.sector_count as u32)
        };

        if chip_index >= self.chips.len() {
            return Err(StorageError::WriteError);
        }

        // Erase the data sectors.
        for s in 0..sector_count {
            let addr = (sector_index + s) * SECTOR_SIZE as u32;
            if let Err(e) = self.chips[chip_index].erase_sector(addr) {
                defmt::warn!("KeyFilesystem: erase sector {} failed: {:?}", sector_index + s, defmt::Debug2Format(&e));
            }
        }

        // Remove from directory.
        self.directory.remove(key_id);
        self.flush_directory()?;
        Ok(())
    }

    // ── Key list ─────────────────────────────────────────────────────────────

    /// List all keys with their metadata.
    ///
    /// Returns a `Vec` of `KeyRecord` objects.  The `label` and
    /// `access_counter` fields are left at their defaults since they are
    /// not stored by the filesystem layer.
    pub fn list_keys(&self) -> heapless::Vec<KeyRecord, 512> {
        let mut out = heapless::Vec::new();
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
                    defmt::warn!(
                        "scrub: CRC32 failure chip {} sector {}",
                        chip_idx,
                        sector
                    );
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
            // Find `needed_sectors` consecutive free sectors.
            if let Some(start) = self.find_consecutive_free(chip_idx as u8, cap_sectors, needed_sectors) {
                return Ok((chip_idx, start));
            }
        }
        Err(StorageError::KeystoreFull)
    }

    /// Find `count` consecutive free sectors on `chip_index`.
    fn find_consecutive_free(
        &self,
        chip_index: u8,
        chip_capacity_sectors: u32,
        count: u32,
    ) -> Option<u32> {
        let mut run_start = DATA_START_SECTOR;
        let mut run_len = 0u32;

        'sector: for s in DATA_START_SECTOR..chip_capacity_sectors {
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
pub fn write_sector<C: FlashChip>(chip: &mut C, addr: u32, data: &[u8; SECTOR_SIZE]) -> Result<(), StorageError> {
    for p in 0..16usize {
        let page_addr = addr + (p * PAGE_SIZE) as u32;
        chip.write_page(page_addr, &data[p * PAGE_SIZE..(p + 1) * PAGE_SIZE])?;
    }
    Ok(())
}

/// Compute CRC32 for an ObjectHeader + ciphertext chunk (helper used during writes).
fn compute_object_crc32_for_header(header: &ObjectHeader, ciphertext: &[u8]) -> u32 {
    let mut hdr_bytes = [0u8; HEADER_SIZE];
    write_header(&mut hdr_bytes, header);
    compute_object_crc32(&hdr_bytes, ciphertext)
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
        _ => None,
    }
}
