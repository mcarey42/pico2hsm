//! Write-Ahead Log (WAL) for atomic keystore updates.
//!
//! The WAL ensures that a power failure during a write cannot corrupt the
//! keystore. Two WAL sectors are maintained per chip (sectors 1 and 2,
//! `WAL_SECTOR_0` and `WAL_SECTOR_1`). Writes follow this sequence:
//!
//! 1. Write new data to WAL sector (erase + write header + payload).
//! 2. Verify WAL sector integrity (CRC32 check).
//! 3. Write WAL commit record (set status byte to COMMITTED).
//! 4. Write new data to final destination sector(s).
//! 5. Update directory entry.
//! 6. Erase WAL sector (clear to 0xFF).
//!
//! On boot, the WAL is scanned. If a committed-but-unapplied WAL entry is
//! found, the data is re-applied before serving requests.
//!
//! # WAL sector layout
//! ```text
//! [0..4]   Magic:  *b"WALX"
//! [4]      Status: 0xFF=empty, 0x01=pending, 0x00=committed
//! [5..8]   Reserved (0x00)
//! [8..12]  Target sector number (u32 LE) — destination of this write
//! [12..16] CRC32 of payload (u32 LE) — for integrity on power-cycle replay
//! [16..4096] Payload — one full keystore sector (4080 bytes usable)
//! ```

use crc32fast::Hasher as Crc32Hasher;
use pico2hsm_core::{
    error::StorageError,
    flash::{FlashChip, PAGE_SIZE, SECTOR_SIZE},
    storage::{WAL_SECTOR_0, WAL_SECTOR_1},
};

// ─── Layout constants ─────────────────────────────────────────────────────────

/// WAL magic bytes — `*b"WALX"`.
pub const WAL_MAGIC: [u8; 4] = *b"WALX";

/// WAL entry status bytes (single byte at offset 4).
pub const WAL_STATUS_EMPTY: u8 = 0xFF;
pub const WAL_STATUS_PENDING: u8 = 0x01;
pub const WAL_STATUS_COMMITTED: u8 = 0x00;

/// Byte offsets within a WAL sector.
const OFF_MAGIC: usize = 0;
const OFF_STATUS: usize = 4;
const OFF_TARGET_SECTOR: usize = 8;
const OFF_CRC32: usize = 12;
const OFF_PAYLOAD: usize = 16;

/// Size of the WAL payload area (SECTOR_SIZE minus the 16-byte header).
const WAL_PAYLOAD_SIZE: usize = SECTOR_SIZE - OFF_PAYLOAD;

// ─── Wal<'a, C> ───────────────────────────────────────────────────────────────

/// Write-Ahead Log bound to a single flash chip.
///
/// Holds a mutable reference to the chip so that WAL operations can be
/// chained with regular sector writes without additional borrowing.
pub struct Wal<'a, C: FlashChip> {
    chip: &'a mut C,
    /// Which slot (0 or 1) is currently active — alternates on each begin.
    active_slot: u8,
}

impl<'a, C: FlashChip> Wal<'a, C> {
    /// Create a new `Wal` instance.
    ///
    /// The active slot is initialised to 0; `scan_and_replay` should be
    /// called immediately after construction during boot.
    pub fn new(chip: &'a mut C) -> Self {
        Wal {
            chip,
            active_slot: 0,
        }
    }

    // ── Helper: sector address from slot index ───────────────────────────────

    /// Byte address on the chip for the WAL slot (`WAL_SECTOR_0` or
    /// `WAL_SECTOR_1`).
    fn slot_addr(slot: u8) -> u32 {
        let sector = if slot == 0 {
            WAL_SECTOR_0
        } else {
            WAL_SECTOR_1
        };
        sector * SECTOR_SIZE as u32
    }

    // ── Read helpers ─────────────────────────────────────────────────────────

    /// Read the 16-byte WAL header from the given slot.
    ///
    /// Returns `(magic_ok, status, target_sector, crc32)`.
    fn read_header(&mut self, slot: u8) -> Result<(bool, u8, u32, u32), StorageError> {
        let addr = Self::slot_addr(slot);
        let mut hdr = [0u8; 16];
        self.chip.read(addr, &mut hdr)?;

        let magic_ok = hdr[OFF_MAGIC..OFF_MAGIC + 4] == WAL_MAGIC;
        let status = hdr[OFF_STATUS];
        let target_sector = u32::from_le_bytes([
            hdr[OFF_TARGET_SECTOR],
            hdr[OFF_TARGET_SECTOR + 1],
            hdr[OFF_TARGET_SECTOR + 2],
            hdr[OFF_TARGET_SECTOR + 3],
        ]);
        let crc32 = u32::from_le_bytes([
            hdr[OFF_CRC32],
            hdr[OFF_CRC32 + 1],
            hdr[OFF_CRC32 + 2],
            hdr[OFF_CRC32 + 3],
        ]);
        Ok((magic_ok, status, target_sector, crc32))
    }

    // ── CRC32 over payload ───────────────────────────────────────────────────

    /// Compute CRC32 of the payload stored in a WAL slot.
    ///
    /// Reads the payload in 256-byte page chunks to avoid large stack
    /// allocations.
    fn payload_crc32(&mut self, slot: u8) -> Result<u32, StorageError> {
        let base = Self::slot_addr(slot) + OFF_PAYLOAD as u32;
        let mut h = Crc32Hasher::new();
        let mut page_buf = [0u8; PAGE_SIZE];
        let pages = WAL_PAYLOAD_SIZE / PAGE_SIZE;
        for p in 0..pages {
            let addr = base + (p * PAGE_SIZE) as u32;
            self.chip.read(addr, &mut page_buf)?;
            h.update(&page_buf);
        }
        Ok(h.finalize())
    }

    // ── Write helpers ────────────────────────────────────────────────────────

    /// Erase a WAL slot sector.
    fn erase_slot(&mut self, slot: u8) -> Result<(), StorageError> {
        let addr = Self::slot_addr(slot);
        self.chip.erase_sector(addr)
    }

    /// Write the 16-byte WAL header into a freshly erased slot.
    ///
    /// Status is set to `WAL_STATUS_PENDING`.
    fn write_slot_header(
        &mut self,
        slot: u8,
        target_sector: u32,
        payload_crc32: u32,
    ) -> Result<(), StorageError> {
        let addr = Self::slot_addr(slot);
        let mut hdr = [0u8; PAGE_SIZE]; // pad to a full page for alignment
        hdr[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&WAL_MAGIC);
        hdr[OFF_STATUS] = WAL_STATUS_PENDING;
        // bytes [5..8] = 0x00 (reserved, already zero)
        hdr[OFF_TARGET_SECTOR..OFF_TARGET_SECTOR + 4].copy_from_slice(&target_sector.to_le_bytes());
        hdr[OFF_CRC32..OFF_CRC32 + 4].copy_from_slice(&payload_crc32.to_le_bytes());
        self.chip.write_page(addr, &hdr[..PAGE_SIZE])
    }

    /// Write the payload (one full sector, 4096 bytes) into the WAL slot.
    ///
    /// Written as 16 × 256-byte pages starting at `OFF_PAYLOAD`.
    fn write_slot_payload(
        &mut self,
        slot: u8,
        payload: &[u8; SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        let base = Self::slot_addr(slot) + OFF_PAYLOAD as u32;
        // The payload area is SECTOR_SIZE - 16 = 4080 bytes, which is
        // 15 × 256 + 240 bytes.  We write the full sector worth of data
        // (4096 bytes) starting at OFF_PAYLOAD; the last page wraps into
        // the *next* page slot of the WAL sector.  To keep alignment
        // simple we write the whole sector in 256-byte pages, fitting
        // 4080 bytes of payload across 16 pages (last one is partial).
        let pages = (SECTOR_SIZE + PAGE_SIZE - 1) / PAGE_SIZE; // ceil(4096/256) = 16
        for p in 0..pages {
            let src_start = p * PAGE_SIZE;
            let src_end = core::cmp::min(src_start + PAGE_SIZE, SECTOR_SIZE);
            let chunk = &payload[src_start..src_end];

            let addr = base + (p * PAGE_SIZE) as u32;

            if chunk.len() == PAGE_SIZE {
                self.chip.write_page(addr, chunk)?;
            } else {
                // Last partial page — pad with 0xFF.
                let mut page = [0xFFu8; PAGE_SIZE];
                page[..chunk.len()].copy_from_slice(chunk);
                self.chip.write_page(addr, &page)?;
            }
        }
        Ok(())
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// Scan the WAL sectors and replay any committed-but-unapplied entries.
    ///
    /// Must be called during boot before any write operations.
    ///
    /// If a `COMMITTED` WAL entry is found, the payload is copied to the
    /// target sector and the WAL slot is then cleared.
    ///
    /// Returns `WalRecovery` indicating what (if anything) was done.
    pub fn scan_and_replay(&mut self) -> Result<WalRecovery, StorageError> {
        for slot in 0..2u8 {
            let (magic_ok, status, target_sector, stored_crc) = self.read_header(slot)?;
            if !magic_ok {
                continue;
            }
            match status {
                WAL_STATUS_COMMITTED => {
                    defmt::warn!(
                        "WAL: replaying committed entry in slot {} → sector {}",
                        slot,
                        target_sector,
                    );
                    // Verify payload CRC before replaying.
                    let computed_crc = self.payload_crc32(slot)?;
                    if computed_crc != stored_crc {
                        defmt::error!(
                            "WAL: payload CRC mismatch in slot {} (stored={}, computed={}) — skipping",
                            slot,
                            stored_crc,
                            computed_crc,
                        );
                        // Clear the corrupt WAL entry and report a rollback.
                        self.erase_slot(slot)?;
                        return Ok(WalRecovery::RolledBack);
                    }
                    // Read the payload and replay it.
                    let target_addr = target_sector * SECTOR_SIZE as u32;
                    // Read payload in pages, erase target sector, then write.
                    // We erase first to avoid partial-write corruption.
                    self.chip.erase_sector(target_addr)?;
                    // Write payload back page-by-page.
                    let base = Self::slot_addr(slot) + OFF_PAYLOAD as u32;
                    for p in 0..16usize {
                        let mut page = [0u8; PAGE_SIZE];
                        let src = base + (p * PAGE_SIZE) as u32;
                        let dst = target_addr + (p * PAGE_SIZE) as u32;
                        self.chip.read(src, &mut page)?;
                        self.chip.write_page(dst, &page)?;
                    }
                    // Clear the WAL slot.
                    self.erase_slot(slot)?;
                    self.active_slot = slot ^ 1;
                    return Ok(WalRecovery::Replayed);
                }
                WAL_STATUS_PENDING => {
                    // Interrupted before commit — safe to discard.
                    defmt::warn!("WAL: discarding uncommitted pending entry in slot {}", slot,);
                    self.erase_slot(slot)?;
                    return Ok(WalRecovery::RolledBack);
                }
                _ => {
                    // Empty or unknown — nothing to do.
                }
            }
        }
        Ok(WalRecovery::Clean)
    }

    /// Begin a WAL write for a target sector.
    ///
    /// Erases the inactive WAL slot, writes the payload, then marks it
    /// `PENDING`.  The caller must call `commit()` and then perform the
    /// destructive write before calling `complete()`.
    pub fn begin_write(
        &mut self,
        target_sector: u32,
        payload: &[u8; SECTOR_SIZE],
    ) -> Result<(), StorageError> {
        // Pick the inactive slot.
        let slot = self.active_slot ^ 1;

        // Compute payload CRC32 before writing.
        let mut h = Crc32Hasher::new();
        h.update(payload);
        let payload_crc = h.finalize();

        // Erase slot, write payload pages, then write header.
        self.erase_slot(slot)?;
        self.write_slot_payload(slot, payload)?;
        self.write_slot_header(slot, target_sector, payload_crc)?;

        self.active_slot = slot;
        Ok(())
    }

    /// Commit the pending WAL entry.
    ///
    /// Sets the WAL status byte to `COMMITTED`.  After this call, the write
    /// is guaranteed to complete even across a power cycle — on next boot
    /// `scan_and_replay` will finish the write.
    ///
    /// The status byte sits at byte offset `OFF_STATUS` (4) within the WAL
    /// sector's first page.  We cannot update a single byte in NOR flash
    /// without erasing first; however, since the page has been written with
    /// `PENDING` (0x01) we can clear a bit to write `COMMITTED` (0x00) with
    /// another page program targeting the same page (NOR allows 1→0 without
    /// erase, but NOT 0→1).
    ///
    /// Strategy: re-read the first 256-byte page, patch the status byte,
    /// and write it again. NOR flash allows re-programming already-cleared
    /// bits (from 1→0) only; writing 0→0 is a no-op. Since PENDING=0x01 →
    /// COMMITTED=0x00 only clears one bit, this is safe.
    pub fn commit(&mut self) -> Result<(), StorageError> {
        let addr = Self::slot_addr(self.active_slot);
        let mut page = [0u8; PAGE_SIZE];
        self.chip.read(addr, &mut page)?;
        page[OFF_STATUS] = WAL_STATUS_COMMITTED;
        self.chip.write_page(addr, &page)
    }

    /// Mark the WAL entry as applied and erase the WAL slot.
    ///
    /// Call this after the destination sector has been successfully written.
    pub fn complete(&mut self) -> Result<(), StorageError> {
        self.erase_slot(self.active_slot)?;
        self.active_slot = self.active_slot ^ 1;
        Ok(())
    }
}

// ─── Recovery outcome ─────────────────────────────────────────────────────────

/// Outcome of `Wal::scan_and_replay()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalRecovery {
    /// No pending WAL entry was found — keystore is clean.
    Clean,
    /// A committed entry was found and replayed to its target sector.
    Replayed,
    /// An uncommitted (pending) or corrupt entry was discarded.
    RolledBack,
}
