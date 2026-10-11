//! Storage manager — coordinates RAID, WAL, filesystem, and integrity layers.
//!
//! The storage stack (bottom to top):
//! ```text
//! FlashChip trait  (flash_chip.rs / sdcard.rs)
//!    ↑
//! RAID-1 mirror layer  (raid.rs)
//!    ↑
//! Write-ahead log  (wal.rs)
//!    ↑
//! Integrity verification  (integrity.rs)
//!    ↑
//! Storage encryption  (AES-256-GCM, key from security::otp)
//!    ↑
//! PKCS#15 filesystem abstraction  (filesystem.rs)
//!    ↑
//! StorageManager (this module)
//! ```
//!
//! # Thread safety
//! The `StorageManager` is owned by the storage task and accessed via
//! Embassy channel messages.  No concurrent access is permitted.
//!
//! # No-alloc type erasure design
//! Since we are `no_std` without a heap allocator, `Box<dyn FlashChip>` is
//! not available.  Instead we use a concrete `AnyChip` enum that wraps all
//! possible chip types.  The `StorageManager` is parametrised by the four
//! chip types that can appear in each slot:
//!
//! ```text
//! chip slots 0–3: SPI0 bus chips  (type parameter `S0`)
//! chip slots 4–7: SPI1 bus chips  (type parameter `S1`)
//! chip slots 0,1: optionally SDCard chips  (type parameter `SD`)
//! ```
//!
//! For boards with a single chip type on all slots, instantiate with the
//! same type for all type parameters.  For mixed boards (e.g. SDCard + SPI
//! flash) use the `AnyChip` enum or a board-specific concrete type.

pub mod keystore;
pub use keystore::HybridKeyStore;
pub use keystore::KeyStore;

pub use keystore::NullKeyStore;

// The following sub-modules use embassy-rp / embassy-time / defmt and can
// only compile for ARM bare-metal targets.
#[cfg(target_arch = "arm")]
pub mod board_chips;
#[cfg(target_arch = "arm")]
pub mod filesystem;
#[cfg(target_arch = "arm")]
pub mod flash_chip;
#[cfg(target_arch = "arm")]
pub mod integrity;
#[cfg(target_arch = "arm")]
pub mod raid;
#[cfg(target_arch = "arm")]
pub mod sdcard;
#[cfg(target_arch = "arm")]
pub mod sdcard_spi;
#[cfg(target_arch = "arm")]
pub use sdcard::{
    check_sd_signature, compute_device_fingerprint, write_sd_signature, SdCardCheckResult,
};
#[cfg(target_arch = "arm")]
pub mod wal;

#[cfg(target_arch = "arm")]
pub use board_chips::BoardChip;
#[cfg(target_arch = "arm")]
pub use board_chips::BoardKeyStore;
#[cfg(target_arch = "arm")]
pub use keystore::FlashKeyStore;

#[cfg(target_arch = "arm")]
use filesystem::{Directory, KeyFilesystem, ScrubReport};
#[cfg(target_arch = "arm")]
use pico2hsm_core::{
    error::{HsmError, StorageError},
    flash::{FlashChip, SECTOR_SIZE},
    key::{KeyId, KeyMaterial, KeyRecord, KeyType},
    storage::{ChipState, MirrorPair, MirrorState, DATA_START_SECTOR, WAL_SECTOR_0, WAL_SECTOR_1},
};

// ─── AnyChip — erased chip type for static dispatch ──────────────────────────

/// Static-dispatch chip wrapper that avoids `dyn FlashChip` without a heap.
///
/// In a real board port, `S0` is the SPI0 flash type, `S1` is the SPI1
/// flash type, and `SD` is the SDCard type.  The `Empty` variant covers
/// absent chip slots.
///
/// Implement new variants here as additional hardware is supported.
#[cfg(target_arch = "arm")]
pub enum AnyChip<S0, S1, SD>
where
    S0: FlashChip,
    S1: FlashChip,
    SD: FlashChip,
{
    /// SPI0 bus flash chip.
    Spi0(S0),
    /// SPI1 bus flash chip.
    Spi1(S1),
    /// SDCard chip.
    SdCard(SD),
    /// Chip slot is empty (not present).
    Empty,
}

#[cfg(target_arch = "arm")]
impl<S0, S1, SD> FlashChip for AnyChip<S0, S1, SD>
where
    S0: FlashChip,
    S1: FlashChip,
    SD: FlashChip,
{
    fn capacity(&self) -> u64 {
        match self {
            AnyChip::Spi0(c) => c.capacity(),
            AnyChip::Spi1(c) => c.capacity(),
            AnyChip::SdCard(c) => c.capacity(),
            AnyChip::Empty => 0,
        }
    }

    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        match self {
            AnyChip::Spi0(c) => c.read(addr, buf),
            AnyChip::Spi1(c) => c.read(addr, buf),
            AnyChip::SdCard(c) => c.read(addr, buf),
            AnyChip::Empty => Err(StorageError::ReadError),
        }
    }

    fn write_page(&mut self, addr: u32, data: &[u8]) -> Result<(), StorageError> {
        match self {
            AnyChip::Spi0(c) => c.write_page(addr, data),
            AnyChip::Spi1(c) => c.write_page(addr, data),
            AnyChip::SdCard(c) => c.write_page(addr, data),
            AnyChip::Empty => Err(StorageError::WriteError),
        }
    }

    fn erase_sector(&mut self, addr: u32) -> Result<(), StorageError> {
        match self {
            AnyChip::Spi0(c) => c.erase_sector(addr),
            AnyChip::Spi1(c) => c.erase_sector(addr),
            AnyChip::SdCard(c) => c.erase_sector(addr),
            AnyChip::Empty => Err(StorageError::EraseError),
        }
    }

    fn jedec_id(&mut self) -> Option<[u8; 3]> {
        match self {
            AnyChip::Spi0(c) => c.jedec_id(),
            AnyChip::Spi1(c) => c.jedec_id(),
            AnyChip::SdCard(c) => c.jedec_id(),
            AnyChip::Empty => None,
        }
    }

    fn is_degraded(&self) -> bool {
        match self {
            AnyChip::Spi0(c) => c.is_degraded(),
            AnyChip::Spi1(c) => c.is_degraded(),
            AnyChip::SdCard(c) => c.is_degraded(),
            AnyChip::Empty => true,
        }
    }

    fn mark_bad_sector(&mut self, sector: u32) -> Result<(), StorageError> {
        match self {
            AnyChip::Spi0(c) => c.mark_bad_sector(sector),
            AnyChip::Spi1(c) => c.mark_bad_sector(sector),
            AnyChip::SdCard(c) => c.mark_bad_sector(sector),
            AnyChip::Empty => Err(StorageError::WriteError),
        }
    }
}

// ─── StorageStatus ────────────────────────────────────────────────────────────

/// Health and utilisation snapshot for the host tool status query.
#[cfg(target_arch = "arm")]
#[derive(Debug, Clone)]
pub struct StorageStatus {
    /// Per-chip health state (slots 0–7, `NotPresent` for unused slots).
    pub chip_states: [ChipState; 8],
    /// Total number of live key objects.
    pub total_keys: u32,
    /// Total data sectors currently allocated to key objects.
    pub total_sectors_used: u32,
    /// Total data sectors available across all healthy chips.
    pub total_sectors_available: u32,
}

// ─── StorageManager<Chip> ────────────────────────────────────────────────────

/// Top-level storage manager.
///
/// Owns the `KeyFilesystem` (which owns the physical chip instances) and
/// maintains the RAID pair state and per-chip health information.
///
/// Type parameter `Chip` is the concrete `FlashChip` type used for all
/// slots.  For boards with heterogeneous chips, use `AnyChip<S0, S1, SD>`.
#[cfg(target_arch = "arm")]
pub struct StorageManager<Chip: FlashChip> {
    /// Logical key filesystem (owns chip instances and in-RAM directory).
    filesystem: KeyFilesystem<Chip>,
    /// Per-chip health state (indices 0–7).
    chip_states: [ChipState; 8],
    /// Mirror pair definitions (up to 4 pairs, indices 0–3).
    mirror_pairs: [MirrorPair; 4],
}

#[cfg(target_arch = "arm")]
impl<Chip: FlashChip> StorageManager<Chip> {
    /// Create a new `StorageManager` from a pre-built `KeyFilesystem`.
    ///
    /// The filesystem should already have chips added via
    /// `KeyFilesystem::add_chip()`.  Call `init()` to scan chips, load
    /// the directory, and run WAL recovery.
    pub fn new(filesystem: KeyFilesystem<Chip>) -> Self {
        StorageManager {
            filesystem,
            chip_states: [ChipState::NotPresent; 8],
            mirror_pairs: [
                MirrorPair {
                    primary: 0,
                    mirror: 4,
                    state: MirrorState::Degraded { failed_member: 4 },
                },
                MirrorPair {
                    primary: 1,
                    mirror: 5,
                    state: MirrorState::Degraded { failed_member: 5 },
                },
                MirrorPair {
                    primary: 2,
                    mirror: 6,
                    state: MirrorState::Degraded { failed_member: 6 },
                },
                MirrorPair {
                    primary: 3,
                    mirror: 7,
                    state: MirrorState::Degraded { failed_member: 7 },
                },
            ],
        }
    }

    /// Initialise: scan chips, load directory, run WAL recovery on all chips.
    pub fn init(&mut self) -> Result<(), StorageError> {
        // Probe each chip slot.
        for (idx, chip) in self.filesystem.chips.iter_mut().enumerate() {
            if chip.is_degraded() {
                self.chip_states[idx] = ChipState::Degraded;
                continue;
            }
            if chip.jedec_id().is_none() && chip.capacity() == 0 {
                self.chip_states[idx] = ChipState::NotPresent;
                continue;
            }
            // Try reading sector 0 to detect blank vs formatted.
            // Use a static buffer to avoid putting 4 KB on the stack —
            // critical on SD card boards where BSS leaves < 50 KB for core0.
            // SAFETY: init() is called once, single-threaded, before dispatch.
            static mut SECTOR0: [u8; SECTOR_SIZE] = [0u8; SECTOR_SIZE];
            let sector0 = unsafe { &mut *core::ptr::addr_of_mut!(SECTOR0) };
            // Blank only if both directory copies are: copy A is legitimately
            // erased after a power cut mid-flush while copy B is current.
            let mut state = ChipState::Blank;
            for &sector in filesystem::DIR_SLOTS.iter() {
                match chip.read(sector * SECTOR_SIZE as u32, sector0) {
                    Ok(()) if integrity::is_blank(sector0) => {}
                    Ok(()) => state = ChipState::Healthy,
                    Err(_) => {
                        state = ChipState::Dead;
                        break;
                    }
                }
            }
            self.chip_states[idx] = state;
        }

        // Update mirror pair states from chip states.
        for pair in self.mirror_pairs.iter_mut() {
            let primary_state = self.chip_states[pair.primary as usize];
            let mirror_state = self.chip_states[pair.mirror as usize];
            pair.state = match (primary_state, mirror_state) {
                (ChipState::Healthy, ChipState::Healthy) => MirrorState::InSync,
                (ChipState::Healthy, _) => MirrorState::Degraded {
                    failed_member: pair.mirror,
                },
                (_, ChipState::Healthy) => MirrorState::Degraded {
                    failed_member: pair.primary,
                },
                _ => MirrorState::Degraded {
                    failed_member: pair.mirror,
                },
            };
        }

        // Mount the filesystem (load directory from first valid chip).
        self.filesystem.mount()?;
        Ok(())
    }

    // ── Key API ───────────────────────────────────────────────────────────────

    /// Read a key object's encrypted blob.
    ///
    /// Returns the ciphertext — the caller is responsible for decryption
    /// and BLAKE2s verification.
    pub fn read_key(
        &mut self,
        key_id: KeyId,
    ) -> Result<heapless::Vec<u8, { crate::security::key_management::MAX_BLOB_SIZE }>, StorageError>
    {
        self.filesystem.read_key(key_id)
    }

    /// Write (create or update) a key object.
    ///
    /// `encrypted_blob` must already be encrypted.
    /// `plaintext_hash` is the BLAKE2s-256 digest of the raw key material.
    pub fn write_key(
        &mut self,
        key_id: KeyId,
        key_type: KeyType,
        encrypted_blob: &[u8],
        plaintext_hash: &[u8; 32],
    ) -> Result<(), StorageError> {
        // RSA-4096 requires 2 sectors; everything else fits in 1.
        let sector_count = if matches!(key_type, KeyType::RsaPrivate4096) {
            2
        } else {
            1
        };
        self.filesystem.write_key(
            key_id,
            key_type,
            encrypted_blob,
            plaintext_hash,
            sector_count,
        )
    }

    /// Delete a key.
    pub fn delete_key(&mut self, key_id: KeyId) -> Result<(), StorageError> {
        self.filesystem.delete_key(key_id)
    }

    /// Delete every key matching `pred`; see [`KeyFilesystem::delete_where`].
    pub fn delete_where(&mut self, pred: &dyn Fn(KeyId) -> bool) -> Result<(), StorageError> {
        self.filesystem.delete_where(pred)
    }

    /// Check whether a key ID exists in the directory.
    pub fn key_exists(&self, key_id: KeyId) -> bool {
        self.filesystem.directory.find(key_id).is_some()
    }

    /// List all key IDs (capped at 64 entries).
    pub fn list_keys(&self) -> heapless::Vec<KeyId, 64> {
        let mut out = heapless::Vec::new();
        for kid in self.filesystem.directory.list_keys() {
            if out.push(kid).is_err() {
                break; // Vec full
            }
        }
        out
    }

    /// Invoke `f` for each key ID without allocating a Vec.
    pub fn for_each_key(&self, f: &mut dyn FnMut(KeyId)) {
        for kid in self.filesystem.directory.list_keys() {
            f(kid);
        }
    }

    /// Get the health state of a specific chip.
    pub fn chip_state(&self, chip_index: u8) -> ChipState {
        if (chip_index as usize) < self.chip_states.len() {
            self.chip_states[chip_index as usize]
        } else {
            ChipState::NotPresent
        }
    }

    /// Get storage health status for the host tool query.
    pub fn storage_status(&self) -> StorageStatus {
        let total_keys = self.filesystem.directory.list_keys().count() as u32;

        // Count used sectors (one entry = sector_count sectors used).
        let total_sectors_used: u32 = self
            .filesystem
            .directory
            .entries
            .iter()
            .filter(|e| (e.flags & 0x01) == 0 && e.key_id != 0xFFFF_FFFF)
            .map(|e| e.sector_count as u32)
            .sum();

        // Sum available sectors across healthy chips.
        let total_sectors_available: u32 = self
            .filesystem
            .chips
            .iter()
            .enumerate()
            .filter(|(idx, chip)| {
                matches!(self.chip_states[*idx], ChipState::Healthy) && !chip.is_degraded()
            })
            .map(|(_, chip)| {
                let cap = chip.capacity();
                if cap >= SECTOR_SIZE as u64 {
                    (cap / SECTOR_SIZE as u64) as u32
                } else {
                    0
                }
            })
            .sum();

        StorageStatus {
            chip_states: self.chip_states,
            total_keys,
            total_sectors_used,
            total_sectors_available,
        }
    }

    /// Background scrub: verify all CRC32 checksums across all chips.
    pub fn scrub(&mut self) -> ScrubReport {
        self.filesystem.scrub_all().unwrap_or(ScrubReport {
            chips_checked: 0,
            sectors_checked: 0,
            errors_found: 0,
            errors_corrected: 0,
        })
    }

    /// Trigger RAID resync for a degraded chip (call from background task).
    ///
    /// The actual resync logic is in `raid::RaidManager::resync()`.  At the
    /// `StorageManager` level, resync is initiated by the caller after
    /// detecting a `ChipState::Blank` on a previously-dead chip.
    pub async fn resync_chip(&mut self, chip_index: u8) -> Result<(), HsmError> {
        // Locate the mirror pair for this chip.
        let pair_idx = self
            .mirror_pairs
            .iter()
            .position(|p| p.primary == chip_index || p.mirror == chip_index)
            .ok_or(HsmError::NotFound)?;

        // Determine which chip is healthy (the source for resync).
        let pair = &self.mirror_pairs[pair_idx];
        let healthy_idx = if pair.primary == chip_index {
            pair.mirror as usize
        } else {
            pair.primary as usize
        };
        let recovering_idx = chip_index as usize;

        if recovering_idx >= self.filesystem.chips.len()
            || healthy_idx >= self.filesystem.chips.len()
        {
            return Err(HsmError::NotSupported);
        }

        defmt::info!(
            "StorageManager: starting resync chip {} from chip {}",
            recovering_idx,
            healthy_idx,
        );

        // Mark recovering chip as resyncing.
        self.chip_states[recovering_idx] = ChipState::Resyncing { progress_sector: 0 };
        self.mirror_pairs[pair_idx].state = MirrorState::Resyncing { progress_sector: 0 };

        // Copy all sectors from healthy to recovering chip.
        let capacity = self.filesystem.chips[healthy_idx].capacity();
        let total_sectors = (capacity / SECTOR_SIZE as u64) as u32;

        let mut buf = [0u8; SECTOR_SIZE];
        for sector in pico2hsm_core::storage::DATA_START_SECTOR..total_sectors {
            let addr = sector * SECTOR_SIZE as u32;

            // Read from healthy chip.
            // We can't borrow two chip slots simultaneously, so we read then write.
            self.filesystem.chips[healthy_idx]
                .read(addr, &mut buf)
                .map_err(|_| HsmError::Storage(StorageError::ReadError))?;

            // Erase + write to recovering chip.
            self.filesystem.chips[recovering_idx]
                .erase_sector(addr)
                .map_err(|_| HsmError::Storage(StorageError::EraseError))?;

            // Write in 256-byte pages.
            for p in 0..16usize {
                let page_addr = addr + (p * 256) as u32;
                self.filesystem.chips[recovering_idx]
                    .write_page(page_addr, &buf[p * 256..(p + 1) * 256])
                    .map_err(|_| HsmError::Storage(StorageError::WriteError))?;
            }

            self.chip_states[recovering_idx] = ChipState::Resyncing {
                progress_sector: sector,
            };
            self.mirror_pairs[pair_idx].state = MirrorState::Resyncing {
                progress_sector: sector,
            };

            // Yield to allow other embassy tasks to run.
            embassy_time::Timer::after_micros(0).await;
        }

        // Resync complete.
        self.chip_states[recovering_idx] = ChipState::Healthy;
        self.mirror_pairs[pair_idx].state = MirrorState::InSync;
        defmt::info!("StorageManager: resync chip {} complete", recovering_idx);
        Ok(())
    }

    // ── Legacy API compat (matches original mod.rs stubs) ──────────────────

    /// Read and decrypt a key object (legacy API — decryption handled by caller).
    pub fn read_key_legacy(&mut self, key_id: KeyId) -> Result<KeyMaterial, HsmError> {
        // This layer returns the encrypted blob; the key management layer
        // above us handles decryption.  We return NotFound here because
        // the StorageManager only deals in encrypted blobs.
        let _ = self.filesystem.read_key(key_id)?;
        Err(HsmError::NotSupported)
    }

    /// Write a key object (legacy API — encryption handled by caller).
    pub fn write_key_legacy(
        &mut self,
        _key: &KeyMaterial,
        _record: &KeyRecord,
    ) -> Result<(), HsmError> {
        Err(HsmError::NotSupported)
    }

    /// Delete a key object (legacy API).
    pub fn delete_key_legacy(&mut self, key_id: KeyId) -> Result<(), HsmError> {
        self.filesystem
            .delete_key(key_id)
            .map_err(HsmError::Storage)
    }

    /// List all key records (legacy API, capped at 64 entries).
    pub fn list_key_records(&self) -> heapless::Vec<KeyRecord, 64> {
        self.filesystem.list_keys()
    }

    /// Wipe ALL keys from persistent storage. Called only by INITIALIZE.
    ///
    /// Only erases sectors that are referenced by live directory entries
    /// (i.e. sectors that actually contain key data).  Erasing every sector
    /// unconditionally takes O(capacity / 4 KB) flash erase cycles — on
    /// internal QMI flash that is ~1 s/sector × 512 sectors ≈ 8 minutes.
    /// Instead we limit erasure to the N sectors in use (typically 0–20).
    ///
    /// WAL sectors and the directory sector are always erased and reformatted.
    /// Best-effort: individual erase failures are logged but do not abort.
    pub fn wipe_all(&mut self) -> Result<(), StorageError> {
        // Erase the sectors of every live entry (directory and chips are
        // disjoint fields, so no copy of the 512-entry table is needed).
        // A failed erase is an error: INITIALIZE relies on the old keys
        // really being gone.
        let fs = &mut self.filesystem;
        for entry in fs.directory.entries.iter() {
            if entry.key_id == 0xFFFF_FFFF || (entry.flags & 0x01) != 0 {
                continue; // empty slot or tombstoned
            }
            let Some(chip) = fs.chips.get_mut(entry.chip_index as usize) else {
                continue;
            };
            for s in 0..u32::from(entry.sector_count) {
                let addr = (entry.sector_index + s) * SECTOR_SIZE as u32;
                chip.erase_sector(addr)?;
            }
        }

        // Erase WAL sectors and reformat directory on every healthy chip.
        let chip_count = self.filesystem.chips.len();
        for chip_idx in 0..chip_count {
            {
                let chip = &mut self.filesystem.chips[chip_idx];
                if chip.is_degraded() || chip.capacity() == 0 {
                    continue;
                }
            }
            // format_chip erases the directory and WAL sectors itself.
            self.filesystem.format_chip(chip_idx)?;
        }

        // Reset the in-RAM directory in place (Directory::new() would build
        // the ~8 KB table on the stack in debug builds).
        self.filesystem.directory.entries.clear();
        self.filesystem.directory.dirty = false;
        Ok(())
    }

    /// Trigger a background RAID resync for a degraded mirror pair.
    pub async fn start_resync(&mut self, pair_index: u8) -> Result<(), HsmError> {
        if (pair_index as usize) >= self.mirror_pairs.len() {
            return Err(HsmError::NotFound);
        }
        let pair_state = self.mirror_pairs[pair_index as usize].state;
        // Find the degraded member.
        let degraded_chip = match pair_state {
            MirrorState::Degraded { failed_member } => failed_member,
            MirrorState::Resyncing { .. } => {
                // Already in progress.
                return Ok(());
            }
            MirrorState::InSync => return Ok(()),
        };
        self.resync_chip(degraded_chip).await
    }
}
