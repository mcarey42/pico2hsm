//! SDCard `FlashChip` implementation using `embedded-sdmmc`.
//!
//! Wraps an SDCard accessed via `embedded-sdmmc` as a `FlashChip` instance,
//! allowing the RAID manager to treat an SDCard identically to a SPI flash
//! chip.
//!
//! # Addressing
//! SDCards use 512-byte sectors internally.  This wrapper maps the 4096-byte
//! `FlashChip` sector interface to 8 consecutive 512-byte SDCard sectors.
//! `write_page` (256 bytes) performs a read-modify-write on the containing
//! 512-byte SDCard sector.
//!
//! # Erase
//! SDCards have an internal FTL that handles wear levelling and bad block
//! management.  "Erasing" a 4096-byte logical sector is implemented as
//! writing 0xFF to all 8 corresponding 512-byte sectors.
//!
//! # API notes (`embedded-sdmmc` 0.9)
//! - `SdCard::new(spi_device, delay)` — `spi_device` must implement
//!   `embedded_hal::spi::SpiDevice<u8>`; a bare `SpiBus` does not work here.
//!   For RP2350, wrap the bus in `embassy_embedded_hal::shared_bus::blocking::spi::SpiDevice`.
//! - `BlockDevice::read` / `write` take `&self` (interior mutability via `RefCell`).
//! - `SdCard::num_bytes()` returns the total byte capacity.

use embedded_sdmmc::{Block, BlockDevice, BlockIdx, SdCard};
use pico2hsm_core::{error::StorageError, flash::FlashChip};

/// Number of consecutive write failures before the SDCard is marked degraded.
const BAD_WRITE_THRESHOLD: u32 = 8;

/// SD card physical sector size (512 bytes).
const SD_SECTOR_BYTES: u32 = 512;

/// Number of SD card sectors per one logical 4096-byte `FlashChip` sector.
const SD_SECTORS_PER_LOGICAL: u32 = 4096 / SD_SECTOR_BYTES; // 8

// ─── SdCardFlash<SPI, DELAY> ─────────────────────────────────────────────────

/// SDCard wrapped as a `FlashChip`.
///
/// `SPI` must implement `embedded_hal::spi::SpiDevice<u8>`.
/// `DELAY` must implement `embedded_hal::delay::DelayNs`.
pub struct SdCardFlash<SPI, DELAY>
where
    SPI: embedded_hal::spi::SpiDevice<u8>,
    DELAY: embedded_hal::delay::DelayNs,
{
    /// The underlying `embedded-sdmmc` SD card driver.
    card: SdCard<SPI, DELAY>,
    /// Total capacity in bytes.
    capacity_bytes: u64,
    /// `true` if write errors have exceeded `BAD_WRITE_THRESHOLD`.
    degraded: bool,
    /// Running count of consecutive write errors for degradation detection.
    write_errors: u32,
}

impl<SPI, DELAY> SdCardFlash<SPI, DELAY>
where
    SPI: embedded_hal::spi::SpiDevice<u8>,
    DELAY: embedded_hal::delay::DelayNs,
{
    /// Create a new `SdCardFlash` and initialise the SDCard.
    ///
    /// Reads the card's CSD register to determine capacity.
    /// Returns `Err(StorageError::NotFormatted)` if the card does not respond.
    pub fn new(spi: SPI, delay: DELAY) -> Result<Self, StorageError> {
        let card = SdCard::new(spi, delay);

        let capacity_bytes = card
            .num_bytes()
            .map_err(|_| StorageError::NotFormatted)?;

        defmt::info!(
            "SdCardFlash: {} bytes ({} MiB)",
            capacity_bytes,
            capacity_bytes / (1024 * 1024),
        );

        Ok(SdCardFlash {
            card,
            capacity_bytes,
            degraded: false,
            write_errors: 0,
        })
    }
}

impl<SPI, DELAY> FlashChip for SdCardFlash<SPI, DELAY>
where
    SPI: embedded_hal::spi::SpiDevice<u8>,
    DELAY: embedded_hal::delay::DelayNs,
{
    fn capacity(&self) -> u64 {
        self.capacity_bytes
    }

    /// Read `buf.len()` bytes starting at byte address `addr`.
    ///
    /// Reads one 512-byte SD sector at a time, handling any byte offset
    /// within the first sector.  For our use-case `addr` is always a
    /// multiple of 4096 and `buf.len()` is always 4096.
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        let first_sd_sector = addr / SD_SECTOR_BYTES;
        let byte_offset = (addr % SD_SECTOR_BYTES) as usize;
        let total = buf.len();
        let mut written = 0usize;
        let mut sd_sector_idx = first_sd_sector;

        while written < total {
            let mut block = [Block::new()];
            self.card
                .read(&mut block, BlockIdx(sd_sector_idx))
                .map_err(|_| StorageError::ReadError)?;

            let src_start = if written == 0 { byte_offset } else { 0 };
            let available = Block::LEN - src_start;
            let to_copy = core::cmp::min(available, total - written);
            buf[written..written + to_copy]
                .copy_from_slice(&block[0].contents[src_start..src_start + to_copy]);

            written += to_copy;
            sd_sector_idx += 1;
        }
        Ok(())
    }

    /// Write up to 256 bytes (`PAGE_SIZE`) at a page-aligned address.
    ///
    /// Performs a read-modify-write on the containing 512-byte SD sector:
    /// 1. Read the 512-byte sector that contains `addr`.
    /// 2. Overwrite the 256-byte window with `data`.
    /// 3. Write the modified 512-byte sector back.
    fn write_page(&mut self, addr: u32, data: &[u8]) -> Result<(), StorageError> {
        let sd_sector_idx = addr / SD_SECTOR_BYTES;
        let byte_offset = (addr % SD_SECTOR_BYTES) as usize;

        // Step 1: read existing 512-byte sector.
        let mut block = [Block::new()];
        self.card
            .read(&mut block, BlockIdx(sd_sector_idx))
            .map_err(|_| StorageError::ReadError)?;

        // Step 2: patch the window.
        let len = data.len().min(Block::LEN - byte_offset);
        block[0].contents[byte_offset..byte_offset + len].copy_from_slice(&data[..len]);

        // Step 3: write back.
        self.card
            .write(&block, BlockIdx(sd_sector_idx))
            .map_err(|_| {
                self.write_errors += 1;
                if self.write_errors >= BAD_WRITE_THRESHOLD {
                    defmt::error!(
                        "SdCardFlash: {} consecutive write errors — marking degraded",
                        self.write_errors,
                    );
                    self.degraded = true;
                }
                StorageError::WriteError
            })?;

        self.write_errors = 0;
        Ok(())
    }

    /// Erase a 4096-byte logical sector by overwriting 8 × 512-byte SD
    /// sectors with 0xFF.
    ///
    /// SDCards handle physical erase internally via FTL.  We write 0xFF to
    /// match the FlashChip erased-sector contract (blank = all-ones).
    fn erase_sector(&mut self, addr: u32) -> Result<(), StorageError> {
        let first_sd_sector = addr / SD_SECTOR_BYTES;
        let mut blank_block = Block::new();
        blank_block.contents.fill(0xFF);
        let blocks = [blank_block];

        for i in 0..SD_SECTORS_PER_LOGICAL {
            self.card
                .write(&blocks, BlockIdx(first_sd_sector + i))
                .map_err(|_| StorageError::EraseError)?;
        }
        Ok(())
    }

    /// SDCards don't expose a JEDEC ID; returns `None`.
    fn jedec_id(&mut self) -> Option<[u8; 3]> {
        None
    }

    fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// Increment the write-error counter; mark degraded if threshold exceeded.
    ///
    /// SDCards have internal FTL bad-block management; we just track a simple
    /// error count and eventually mark the whole card degraded.
    fn mark_bad_sector(&mut self, _sector: u32) -> Result<(), StorageError> {
        self.write_errors += 1;
        if self.write_errors >= BAD_WRITE_THRESHOLD {
            self.degraded = true;
        }
        Ok(())
    }
}

// ─── Non-generic legacy stub (kept for source compatibility) ──────────────────

/// Non-generic SDCard stub.
///
/// This is the original stub kept for source compatibility. All operations
/// return errors. New code should use `SdCardFlash<SPI, DELAY>`.
pub struct SdCardFlashLegacy {
    capacity: u64,
    degraded: bool,
}

impl SdCardFlashLegacy {
    #[allow(dead_code)]
    pub fn new_stub(capacity: u64) -> Self {
        SdCardFlashLegacy { capacity, degraded: false }
    }
}

impl FlashChip for SdCardFlashLegacy {
    fn capacity(&self) -> u64 {
        self.capacity
    }
    fn read(&mut self, _addr: u32, _buf: &mut [u8]) -> Result<(), StorageError> {
        Err(StorageError::ReadError)
    }
    fn write_page(&mut self, _addr: u32, _data: &[u8]) -> Result<(), StorageError> {
        Err(StorageError::WriteError)
    }
    fn erase_sector(&mut self, _addr: u32) -> Result<(), StorageError> {
        Err(StorageError::EraseError)
    }
    fn jedec_id(&mut self) -> Option<[u8; 3]> {
        None
    }
    fn is_degraded(&self) -> bool {
        self.degraded
    }
    fn mark_bad_sector(&mut self, _sector: u32) -> Result<(), StorageError> {
        self.degraded = true;
        Ok(())
    }
}
