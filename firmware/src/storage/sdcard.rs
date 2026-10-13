//! The SD card as the Storage V2 keystore medium (`embedded-sdmmc`).
//!
//! # Addressing
//! The store sees 4096-byte sectors of 8 × 512-byte card blocks, starting
//! `SD_BYTE_OFFSET` into the card.  Writes are whole blocks, written as
//! they are: no read-modify-write (STORAGE_V2 §6.4).
//!
//! # Erase
//! The card's FTL does wear levelling and bad-block management.  "Erasing"
//! a 4096-byte sector writes 0xFF to its 8 blocks.
//!
//! # API notes (`embedded-sdmmc` 0.9)
//! - `SdCard::new(spi_device, delay)` — `spi_device` must implement
//!   `embedded_hal::spi::SpiDevice<u8>`; a bare `SpiBus` does not work here.
//!   For RP2350, wrap the bus in `embassy_embedded_hal::shared_bus::blocking::spi::SpiDevice`.
//! - `BlockDevice::read` / `write` take `&self` (interior mutability via `RefCell`).
//! - `SdCard::num_bytes()` returns the total byte capacity.

use embedded_sdmmc::{Block, BlockDevice, BlockIdx, SdCard};
use pico2hsm_core::error::StorageError;

/// Number of consecutive write failures before the SDCard is marked degraded.
const BAD_WRITE_THRESHOLD: u32 = 8;

/// SD card physical sector size (512 bytes).
const SD_SECTOR_BYTES: u32 = 512;

/// Card blocks per 4096-byte store sector.
const SD_SECTORS_PER_LOGICAL: u32 = 4096 / SD_SECTOR_BYTES; // 8

// ─── SdCardFlash<SPI, DELAY> ─────────────────────────────────────────────────

/// Number of SD sectors (512 bytes each) reserved at the start of the card for
/// the 1.x pairing signature (no longer written or read).  The store's
/// sector 0 maps to card block `SD_RESERVED_SECTORS`.
const SD_RESERVED_SECTORS: u32 = 8; // 8 × 512 = 4 096 bytes = one 4 KiB logical sector
/// Byte offset added to every store address before issuing SD card I/O.
const SD_BYTE_OFFSET: u32 = SD_RESERVED_SECTORS * SD_SECTOR_BYTES;

/// Keystore region on the card (16 MiB = 4096 sectors of 4 KiB).
const SD_KEYSTORE_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// The SD card keystore region.
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
    /// Usable capacity in bytes (total minus reserved region).
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

        let total_bytes = card.num_bytes().map_err(|_| StorageError::NotFormatted)?;

        // Subtract the reserved region (signature block) from usable capacity,
        // and use only the first SD_KEYSTORE_MAX_BYTES: addresses are u32, so
        // anything past 4 GiB (minus the offset) would wrap onto other keys,
        // the directory or the signature block.  340 directory entries need
        // only a few MB.
        let capacity_bytes = total_bytes
            .saturating_sub(SD_BYTE_OFFSET as u64)
            .min(SD_KEYSTORE_MAX_BYTES);

        defmt::info!(
            "SdCardFlash: total={} B usable={} B ({} MiB), reserved {} sectors for signature",
            total_bytes,
            capacity_bytes,
            capacity_bytes / (1024 * 1024),
            SD_RESERVED_SECTORS,
        );

        Ok(SdCardFlash {
            card,
            capacity_bytes,
            degraded: false,
            write_errors: 0,
        })
    }

    /// Wrap an already-initialized `SdCard` as a `SdCardFlash`.
    ///
    /// `capacity_bytes` is the usable capacity (total minus reserved region).
    /// The caller must have already called `card.num_bytes()` to trigger init.
    pub fn from_initialized(card: SdCard<SPI, DELAY>, capacity_bytes: u64) -> Self {
        SdCardFlash {
            card,
            // Same cap as `new`: u32 addresses must not wrap on big cards.
            capacity_bytes: capacity_bytes.min(SD_KEYSTORE_MAX_BYTES),
            degraded: false,
            write_errors: 0,
        }
    }

    /// Borrow the underlying `SdCard` for direct block-level operations.
    pub fn card(&self) -> &SdCard<SPI, DELAY> {
        &self.card
    }
}

impl<SPI, DELAY> SdCardFlash<SPI, DELAY>
where
    SPI: embedded_hal::spi::SpiDevice<u8>,
    DELAY: embedded_hal::delay::DelayNs,
{
    /// Read `buf.len()` bytes starting at byte address `addr`.
    ///
    /// Reads one 512-byte SD sector at a time, handling any byte offset
    /// within the first sector.  For our use-case `addr` is always a
    /// multiple of 4096 and `buf.len()` is always 4096.
    ///
    /// `SD_BYTE_OFFSET` is added so that the filesystem never touches the
    /// reserved signature region at the start of the card.
    pub fn read_at(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        let physical_addr = addr + SD_BYTE_OFFSET;
        let first_sd_sector = physical_addr / SD_SECTOR_BYTES;
        let byte_offset = (physical_addr % SD_SECTOR_BYTES) as usize;
        let total = buf.len();

        // Read one SD sector at a time into a static buffer to avoid
        // putting 4 KB (8 × Block) on the stack — critical on boards where
        // BSS leaves < 50 KB for the core0 stack.
        let mut written = 0usize;
        let mut sd_sector_idx = first_sd_sector;
        while written < total {
            // SAFETY: SdCardFlash I/O is single-threaded (no concurrent callers).
            static mut SD_BLOCK: [Block; 1] = [Block {
                contents: [0u8; 512],
            }];
            let block = unsafe { &mut *core::ptr::addr_of_mut!(SD_BLOCK) };
            if self.card.read(block, BlockIdx(sd_sector_idx)).is_err() {
                crate::display_snapshot::note_sd_io(false);
                return Err(StorageError::ReadError);
            }

            let src_start = if written == 0 { byte_offset } else { 0 };
            let available = Block::LEN - src_start;
            let to_copy = core::cmp::min(available, total - written);
            buf[written..written + to_copy]
                .copy_from_slice(&block[0].contents[src_start..src_start + to_copy]);

            written += to_copy;
            sd_sector_idx += 1;
        }
        crate::display_snapshot::note_sd_io(true);
        Ok(())
    }

    /// Erase a 4096-byte logical sector by overwriting 8 × 512-byte SD
    /// sectors with 0xFF.
    ///
    /// SDCards handle physical erase internally via FTL.  We write 0xFF to
    /// match the FlashChip erased-sector contract (blank = all-ones).
    pub fn erase_at(&mut self, addr: u32) -> Result<(), StorageError> {
        let first_sd_sector = (addr + SD_BYTE_OFFSET) / SD_SECTOR_BYTES;
        let mut blank_block = Block::new();
        blank_block.contents.fill(0xFF);
        let blocks = [blank_block];

        for i in 0..SD_SECTORS_PER_LOGICAL {
            // A slow card can take up to 250 ms per block write.
            crate::watchdog::progress();
            if self
                .card
                .write(&blocks, BlockIdx(first_sd_sector + i))
                .is_err()
            {
                crate::display_snapshot::note_sd_io(false);
                return Err(StorageError::EraseError);
            }
        }
        crate::display_snapshot::note_sd_io(true);
        Ok(())
    }
}

// ─── Storage V2: the card as a `StoreFlash` ──────────────────────────────────

impl<SPI, DELAY> super::store_v2::StoreFlash for SdCardFlash<SPI, DELAY>
where
    SPI: embedded_hal::spi::SpiDevice<u8>,
    DELAY: embedded_hal::delay::DelayNs,
{
    fn media(&self) -> super::store_v2::Media {
        super::store_v2::Media::Sd
    }

    fn sectors(&self) -> u32 {
        (self.capacity_bytes / u64::from(super::store_v2::SECTOR)) as u32
    }

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        self.read_at(offset, buf)
    }

    /// Whole 512-byte blocks, written as they are: no read-modify-write
    /// (STORAGE_V2 §6.4).  `write` returns once the card has accepted the
    /// block and left busy.
    fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError> {
        if offset % SD_SECTOR_BYTES != 0 || data.len() % SD_SECTOR_BYTES as usize != 0 {
            return Err(StorageError::WriteError);
        }
        let first = (offset + SD_BYTE_OFFSET) / SD_SECTOR_BYTES;
        for (i, chunk) in data.chunks(SD_SECTOR_BYTES as usize).enumerate() {
            crate::watchdog::progress();
            let mut block = Block::new();
            block.contents.copy_from_slice(chunk);
            if self
                .card
                .write(core::slice::from_ref(&block), BlockIdx(first + i as u32))
                .is_err()
            {
                crate::display_snapshot::note_sd_io(false);
                return Err(StorageError::WriteError);
            }
        }
        crate::display_snapshot::note_sd_io(true);
        Ok(())
    }

    fn erase_sector(&mut self, sector: u32) -> Result<(), StorageError> {
        self.erase_at(sector * super::store_v2::SECTOR)
    }
}

impl<SPI, DELAY> SdCardFlash<SPI, DELAY>
where
    SPI: embedded_hal::spi::SpiDevice<u8>,
    DELAY: embedded_hal::delay::DelayNs,
{
    /// Create an `SdCardFlash` from an already-initialized `SdCard`.
    ///
    /// The caller is responsible for having already called `card.num_bytes()`
    /// to initialize the card and obtain `capacity_bytes`.
    /// `total_bytes` is the raw SD card capacity from `num_bytes()`.
    /// The usable capacity exposed to the filesystem is reduced by the
    /// reserved signature region.
    pub fn from_card(card: SdCard<SPI, DELAY>, total_bytes: u64) -> Self {
        let capacity_bytes = total_bytes
            .saturating_sub(SD_BYTE_OFFSET as u64)
            .min(SD_KEYSTORE_MAX_BYTES);
        defmt::info!(
            "SdCardFlash::from_card: total={} B usable={} B ({} MiB)",
            total_bytes,
            capacity_bytes,
            capacity_bytes / (1024 * 1024),
        );
        SdCardFlash {
            card,
            capacity_bytes,
            degraded: false,
            write_errors: 0,
        }
    }
}
