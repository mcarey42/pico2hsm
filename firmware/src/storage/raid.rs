//! RAID-1 mirror logic — bilateral symmetry, resync, bad chip replacement.
//!
//! The pico2hsm keystore is stored across up to 8 SPI flash chips arranged
//! as RAID-1 mirror pairs:
//!
//! ```text
//! SPI0/CS0 ←→ SPI1/CS0   (mirror pair 0, chip indices 0 ↔ 4)
//! SPI0/CS1 ←→ SPI1/CS1   (mirror pair 1, chip indices 1 ↔ 5)
//! SPI0/CS2 ←→ SPI1/CS2   (mirror pair 2, chip indices 2 ↔ 6)
//! SPI0/CS3 ←→ SPI1/CS3   (mirror pair 3, chip indices 3 ↔ 7)
//! ```
//!
//! All writes go to both members of a pair atomically (via WAL).  Reads
//! prefer the primary (SPI0 side); the mirror is used if the primary read
//! fails or fails CRC32 integrity verification.
//!
//! # Resync procedure
//! When a chip transitions from `Dead`/`NotPresent` to `Blank` (new chip
//! detected), or when CRC32 failures are detected on one side, a resync is
//! triggered:
//! 1. Iterate all data sectors on the healthy member.
//! 2. Read each sector, verify CRC32.
//! 3. Write to the recovering member.
//! 4. Update `progress_sector` in `MirrorState::Resyncing`.
//! 5. On completion, transition both chips to `Healthy`, pair to `InSync`.
//!
//! Resync is interruptible — `progress_sector` allows resumption after a
//! power cycle.
//!
//! # Bad chip replacement
//! 1. Chip is marked `Dead`.
//! 2. All reads fall back to the mirror.
//! 3. Operator physically replaces the chip.
//! 4. New blank chip is detected on next probe (`jedec_id` succeeds but sector 0 all-0xFF).
//! 5. `check_for_replacement()` initiates resync.

use crate::storage::{
    integrity::{is_blank, verify_header_crc32, verify_magic, HEADER_SIZE},
    wal::{Wal, WalRecovery},
};
use pico2hsm_core::{
    error::StorageError,
    flash::{FlashChip, SECTOR_SIZE},
    storage::{ChipState, MirrorPair, MirrorState, DATA_START_SECTOR},
};

// ─── RaidManager<P, M> ────────────────────────────────────────────────────────

/// RAID-1 manager for one mirror pair.
///
/// `P` is the primary chip type (SPI0 side), `M` is the mirror chip type
/// (SPI1 side).  Both must implement `FlashChip`.
///
/// For boards with mixed chip types (e.g., SDCard + SpiFlash) the caller
/// wraps each chip in the `AnyChip` enum defined in `mod.rs`.
pub struct RaidManager<P: FlashChip, M: FlashChip> {
    pub primary: P,
    pub mirror: M,
    pub primary_idx: u8,
    pub mirror_idx: u8,
    pub primary_state: ChipState,
    pub mirror_state: ChipState,
    pub pair_state: MirrorState,
}

impl<P: FlashChip, M: FlashChip> RaidManager<P, M> {
    /// Create a new `RaidManager`.
    ///
    /// `primary_idx` and `mirror_idx` are the logical chip indices (0–7)
    /// used for diagnostics and `BadBlock` error fields.
    pub fn new(primary: P, mirror: M, primary_idx: u8, mirror_idx: u8) -> Self {
        RaidManager {
            primary,
            mirror,
            primary_idx,
            mirror_idx,
            primary_state: ChipState::NotPresent,
            mirror_state: ChipState::NotPresent,
            pair_state: MirrorState::Degraded {
                failed_member: mirror_idx,
            },
        }
    }

    /// Probe both chips, set initial `ChipState` values, and detect the
    /// initial `MirrorState`.
    ///
    /// - Chips that respond to `jedec_id()` and are not degraded start as
    ///   `Healthy`.
    /// - Chips with an all-0xFF sector 0 are `Blank`.
    /// - Chips that do not respond are `NotPresent`.
    ///
    /// Returns `Err` if neither chip is present.
    pub fn probe(&mut self) -> Result<(), StorageError> {
        // Probe primary.
        self.primary_state = if self.primary.is_degraded() {
            ChipState::Degraded
        } else if self.primary.jedec_id().is_some() || self.primary_is_sdcard() {
            // Check sector 0 for blank detection.
            let mut sector0 = [0u8; SECTOR_SIZE];
            if self.primary.read(0, &mut sector0).is_ok() && is_blank(&sector0) {
                ChipState::Blank
            } else {
                ChipState::Healthy
            }
        } else {
            ChipState::NotPresent
        };

        // Probe mirror.
        self.mirror_state = if self.mirror.is_degraded() {
            ChipState::Degraded
        } else if self.mirror.jedec_id().is_some() || self.mirror_is_sdcard() {
            let mut sector0 = [0u8; SECTOR_SIZE];
            if self.mirror.read(0, &mut sector0).is_ok() && is_blank(&sector0) {
                ChipState::Blank
            } else {
                ChipState::Healthy
            }
        } else {
            ChipState::NotPresent
        };

        // Determine pair state.
        self.pair_state = match (self.primary_state, self.mirror_state) {
            (ChipState::Healthy, ChipState::Healthy) => MirrorState::InSync,
            (ChipState::Healthy, _) => MirrorState::Degraded {
                failed_member: self.mirror_idx,
            },
            (_, ChipState::Healthy) => MirrorState::Degraded {
                failed_member: self.primary_idx,
            },
            _ => MirrorState::Degraded {
                failed_member: self.mirror_idx,
            },
        };

        // If neither is present, return an error.
        if matches!(self.primary_state, ChipState::NotPresent | ChipState::Dead)
            && matches!(self.mirror_state, ChipState::NotPresent | ChipState::Dead)
        {
            return Err(StorageError::NotFormatted);
        }
        Ok(())
    }

    // SDCards return None from jedec_id() but are still valid chips;
    // we detect them by checking is_degraded() == false and capacity > 0.
    fn primary_is_sdcard(&self) -> bool {
        !self.primary.is_degraded() && self.primary.capacity() > 0
    }
    fn mirror_is_sdcard(&self) -> bool {
        !self.mirror.is_degraded() && self.mirror.capacity() > 0
    }

    // ── Read ─────────────────────────────────────────────────────────────────

    /// Read one 4 KiB sector from the mirror pair.
    ///
    /// Reads from the primary chip first.  On read error or CRC32 integrity
    /// failure, falls back to the mirror.  Records the failure in chip state.
    pub fn read(&mut self, sector: u32, buf: &mut [u8; SECTOR_SIZE]) -> Result<(), StorageError> {
        // Try primary.
        let primary_ok = match self.primary_state {
            ChipState::Dead | ChipState::NotPresent => false,
            _ => {
                let addr = sector * SECTOR_SIZE as u32;
                match self.primary.read(addr, buf) {
                    Ok(()) => {
                        // Quick CRC check if the sector looks written.
                        if verify_magic(buf) {
                            verify_header_crc32(&buf[..HEADER_SIZE], &self.ciphertext_slice(buf))
                                .is_ok()
                        } else {
                            true // blank or non-key sector; accept as-is
                        }
                    }
                    Err(e) => {
                        defmt::warn!(
                            "RAID: primary chip {} read error sector {}: {:?}",
                            self.primary_idx,
                            sector,
                            defmt::Debug2Format(&e),
                        );
                        false
                    }
                }
            }
        };

        if primary_ok {
            return Ok(());
        }

        // Mark primary degraded if it failed.
        if !matches!(self.primary_state, ChipState::Dead | ChipState::NotPresent) {
            defmt::warn!(
                "RAID: primary chip {} degraded after read failure on sector {}",
                self.primary_idx,
                sector,
            );
            self.primary_state = ChipState::Degraded;
            self.pair_state = MirrorState::Degraded {
                failed_member: self.primary_idx,
            };
        }

        // Fall back to mirror.
        match self.mirror_state {
            ChipState::Dead | ChipState::NotPresent => {
                defmt::error!(
                    "RAID: both chips unavailable for sector {} (pair {}/{})",
                    sector,
                    self.primary_idx,
                    self.mirror_idx,
                );
                Err(StorageError::ReadError)
            }
            _ => {
                let addr = sector * SECTOR_SIZE as u32;
                self.mirror.read(addr, buf).map_err(|e| {
                    defmt::error!(
                        "RAID: mirror chip {} also failed on sector {}: {:?}",
                        self.mirror_idx,
                        sector,
                        defmt::Debug2Format(&e),
                    );
                    self.mirror_state = ChipState::Dead;
                    e
                })
            }
        }
    }

    /// Build a slice covering the ciphertext portion of a sector buffer.
    ///
    /// Ciphertext immediately follows the header; length is derived from
    /// `plaintext_len` rounded up to 256-byte page boundary.
    fn ciphertext_slice<'b>(&self, buf: &'b [u8; SECTOR_SIZE]) -> &'b [u8] {
        if buf.len() < HEADER_SIZE + 2 {
            return &buf[HEADER_SIZE..];
        }
        let plaintext_len = u16::from_le_bytes([buf[8], buf[9]]) as usize;
        let ciphertext_len = (plaintext_len + 255) & !255;
        let end = core::cmp::min(HEADER_SIZE + ciphertext_len, SECTOR_SIZE);
        &buf[HEADER_SIZE..end]
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /// Write one 4 KiB sector to both members of the mirror pair.
    ///
    /// Uses the WAL for atomicity.  Write order: mirror first, then primary.
    /// This ensures that if primary fails after mirror succeeds, the mirror
    /// becomes the authoritative copy and can rebuild the primary.
    ///
    /// `wal` must be a `Wal` instance bound to either chip — the WAL entry
    /// covers the sector content and target address regardless of chip.
    pub fn write<W: FlashChip>(
        &mut self,
        sector: u32,
        data: &[u8; SECTOR_SIZE],
        wal: &mut Wal<W>,
    ) -> Result<(), StorageError> {
        let addr = sector * SECTOR_SIZE as u32;

        // Step 1: Write WAL entry.
        wal.begin_write(sector, data)?;
        wal.commit()?;

        // Step 2: Write to mirror first.
        let mirror_ok = match self.mirror_state {
            ChipState::Dead | ChipState::NotPresent => false,
            _ => self.write_sector_to_chip_mirror(addr, data).is_ok(),
        };

        if !mirror_ok {
            defmt::warn!(
                "RAID: mirror chip {} write failed sector {} — continuing with primary only",
                self.mirror_idx,
                sector,
            );
            self.mirror_state = ChipState::Degraded;
            self.pair_state = MirrorState::Degraded {
                failed_member: self.mirror_idx,
            };
        }

        // Step 3: Write to primary.
        let primary_ok = match self.primary_state {
            ChipState::Dead | ChipState::NotPresent => false,
            _ => self.write_sector_to_chip_primary(addr, data).is_ok(),
        };

        if !primary_ok {
            if mirror_ok {
                defmt::warn!(
                    "RAID: primary chip {} write failed sector {} — mirror is now authoritative",
                    self.primary_idx,
                    sector,
                );
                self.primary_state = ChipState::Degraded;
                self.pair_state = MirrorState::Degraded {
                    failed_member: self.primary_idx,
                };
            } else {
                // Both failed.
                defmt::error!(
                    "RAID: both chips failed writing sector {} — keystore may be corrupt",
                    sector,
                );
                wal.complete()?;
                return Err(StorageError::WriteError);
            }
        }

        // Step 4: Clear WAL.
        wal.complete()?;
        Ok(())
    }

    /// Write a full 4096-byte sector to the primary chip in 256-byte pages.
    fn write_sector_to_chip_primary(
        &mut self,
        addr: u32,
        data: &[u8; SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        self.primary.erase_sector(addr)?;
        for p in 0..16usize {
            let page_addr = addr + (p * 256) as u32;
            self.primary
                .write_page(page_addr, &data[p * 256..(p + 1) * 256])?;
        }
        Ok(())
    }

    /// Write a full 4096-byte sector to the mirror chip in 256-byte pages.
    fn write_sector_to_chip_mirror(
        &mut self,
        addr: u32,
        data: &[u8; SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        self.mirror.erase_sector(addr)?;
        for p in 0..16usize {
            let page_addr = addr + (p * 256) as u32;
            self.mirror
                .write_page(page_addr, &data[p * 256..(p + 1) * 256])?;
        }
        Ok(())
    }

    // ── Erase ─────────────────────────────────────────────────────────────────

    /// Erase a sector on both chips.
    pub fn erase(&mut self, sector: u32) -> Result<(), StorageError> {
        let addr = sector * SECTOR_SIZE as u32;
        let mut err = Ok(());

        if !matches!(self.primary_state, ChipState::Dead | ChipState::NotPresent) {
            if let Err(e) = self.primary.erase_sector(addr) {
                defmt::warn!(
                    "RAID: primary chip {} erase sector {} failed: {:?}",
                    self.primary_idx,
                    sector,
                    defmt::Debug2Format(&e),
                );
                err = Err(e);
            }
        }
        if !matches!(self.mirror_state, ChipState::Dead | ChipState::NotPresent) {
            if let Err(e) = self.mirror.erase_sector(addr) {
                defmt::warn!(
                    "RAID: mirror chip {} erase sector {} failed: {:?}",
                    self.mirror_idx,
                    sector,
                    defmt::Debug2Format(&e),
                );
                err = Err(e);
            }
        }
        err
    }

    // ── Resync ────────────────────────────────────────────────────────────────

    /// Perform a full resync: copy all sectors from the healthy chip to the
    /// recovering chip.
    ///
    /// Determines the healthy and recovering chips from `pair_state`.
    /// Updates `pair_state` to `Resyncing { progress_sector }` after each
    /// sector, then to `InSync` on completion.
    ///
    /// This is an async function so the caller can yield between sectors;
    /// the resync is interruptible.
    pub async fn resync(&mut self) -> Result<(), StorageError> {
        // Determine source and target.
        let (src_is_primary, start_sector) = match self.pair_state {
            MirrorState::Degraded { failed_member } => {
                let src_is_primary = failed_member == self.mirror_idx;
                (src_is_primary, DATA_START_SECTOR)
            }
            MirrorState::Resyncing { progress_sector } => {
                // Determine which chip was the source.
                let src_is_primary = matches!(self.mirror_state, ChipState::Degraded);
                (src_is_primary, progress_sector)
            }
            MirrorState::InSync => return Ok(()),
        };

        let capacity = if src_is_primary {
            self.primary.capacity()
        } else {
            self.mirror.capacity()
        };
        let total_sectors = (capacity / SECTOR_SIZE as u64) as u32;

        let mut sector_buf = [0u8; SECTOR_SIZE];
        let mut sector = start_sector;

        while sector < total_sectors {
            let addr = sector * SECTOR_SIZE as u32;

            // Read from source.
            if src_is_primary {
                self.primary.read(addr, &mut sector_buf)?;
            } else {
                self.mirror.read(addr, &mut sector_buf)?;
            }

            // Verify CRC if the sector has a P2HM header.
            if verify_magic(&sector_buf) {
                let ciphertext_end = {
                    let plen = u16::from_le_bytes([sector_buf[8], sector_buf[9]]) as usize;
                    let clen = (plen + 255) & !255;
                    core::cmp::min(HEADER_SIZE + clen, SECTOR_SIZE)
                };
                verify_header_crc32(
                    &sector_buf[..HEADER_SIZE],
                    &sector_buf[HEADER_SIZE..ciphertext_end],
                )
                .map_err(|_| {
                    defmt::warn!(
                        "RAID resync: CRC failure on source sector {} — skipping",
                        sector
                    );
                    StorageError::IntegrityFailure
                })?;
            }

            // Write to target (erase + pages).
            if src_is_primary {
                self.mirror.erase_sector(addr)?;
                for p in 0..16usize {
                    let pa = addr + (p * 256) as u32;
                    self.mirror
                        .write_page(pa, &sector_buf[p * 256..(p + 1) * 256])?;
                }
                self.mirror_state = ChipState::Resyncing {
                    progress_sector: sector,
                };
            } else {
                self.primary.erase_sector(addr)?;
                for p in 0..16usize {
                    let pa = addr + (p * 256) as u32;
                    self.primary
                        .write_page(pa, &sector_buf[p * 256..(p + 1) * 256])?;
                }
                self.primary_state = ChipState::Resyncing {
                    progress_sector: sector,
                };
            }

            self.pair_state = MirrorState::Resyncing {
                progress_sector: sector,
            };

            sector += 1;

            // Yield to allow other tasks to run.
            embassy_time::Timer::after_micros(0).await;
        }

        // Resync complete.
        self.primary_state = ChipState::Healthy;
        self.mirror_state = ChipState::Healthy;
        self.pair_state = MirrorState::InSync;
        defmt::info!(
            "RAID: resync complete for pair {}/{}",
            self.primary_idx,
            self.mirror_idx,
        );
        Ok(())
    }

    // ── Chip replacement detection ────────────────────────────────────────────

    /// Detect and handle a new blank chip (after physical replacement).
    ///
    /// Probes both chips and returns `true` if a blank chip was found and a
    /// resync has been initiated (state set to `Resyncing`).  The caller
    /// should then invoke `resync()` in a background task.
    pub fn check_for_replacement(&mut self) -> bool {
        // Check primary.
        if matches!(self.primary_state, ChipState::Dead | ChipState::Degraded) {
            let mut sector0 = [0u8; SECTOR_SIZE];
            if self.primary.read(0, &mut sector0).is_ok() && is_blank(&sector0) {
                defmt::info!(
                    "RAID: blank chip detected at primary slot {} — initiating resync",
                    self.primary_idx,
                );
                self.primary_state = ChipState::Blank;
                self.pair_state = MirrorState::Resyncing {
                    progress_sector: DATA_START_SECTOR,
                };
                return true;
            }
        }

        // Check mirror.
        if matches!(self.mirror_state, ChipState::Dead | ChipState::Degraded) {
            let mut sector0 = [0u8; SECTOR_SIZE];
            if self.mirror.read(0, &mut sector0).is_ok() && is_blank(&sector0) {
                defmt::info!(
                    "RAID: blank chip detected at mirror slot {} — initiating resync",
                    self.mirror_idx,
                );
                self.mirror_state = ChipState::Blank;
                self.pair_state = MirrorState::Resyncing {
                    progress_sector: DATA_START_SECTOR,
                };
                return true;
            }
        }
        false
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Return the `MirrorPair` definition for this manager.
    pub fn mirror_pair(&self) -> MirrorPair {
        MirrorPair {
            primary: self.primary_idx,
            mirror: self.mirror_idx,
            state: self.pair_state,
        }
    }

    /// Return the health state of the primary chip.
    pub fn primary_chip_state(&self) -> ChipState {
        self.primary_state
    }

    /// Return the health state of the mirror chip.
    pub fn mirror_chip_state(&self) -> ChipState {
        self.mirror_state
    }
}
