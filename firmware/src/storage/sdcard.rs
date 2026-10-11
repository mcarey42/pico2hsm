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

/// Number of SD sectors (512 bytes each) reserved at the start of the card for
/// the P2HSDCARD signature block. The KeyFilesystem's sector 0 maps to SD
/// physical sector `SD_RESERVED_SECTORS`, never touching sector 0 (signature).
const SD_RESERVED_SECTORS: u32 = 8; // 8 × 512 = 4 096 bytes = one 4 KiB logical sector
/// Byte offset added to every FlashChip address before issuing SD card I/O.
const SD_BYTE_OFFSET: u32 = SD_RESERVED_SECTORS * SD_SECTOR_BYTES;

/// Keystore region on the card (16 MiB = 4096 sectors of 4 KiB).
const SD_KEYSTORE_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// SDCard wrapped as a `FlashChip`.
///
/// `SPI` must implement `embedded_hal::spi::SpiDevice<u8>`.
/// `DELAY` must implement `embedded_hal::delay::DelayNs`.
///
/// The first `SD_RESERVED_SECTORS` physical sectors are reserved for the
/// P2HSDCARD pairing signature and are never touched by the FlashChip API.
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
    ///
    /// `SD_BYTE_OFFSET` is added so that the filesystem never touches the
    /// reserved signature region at the start of the card.
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), StorageError> {
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
            self.card
                .read(block, BlockIdx(sd_sector_idx))
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
        let physical_addr = addr + SD_BYTE_OFFSET;
        let sd_sector_idx = physical_addr / SD_SECTOR_BYTES;
        let byte_offset = (physical_addr % SD_SECTOR_BYTES) as usize;

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
                    #[cfg(target_arch = "arm")]
                    crate::cdc_error!(
                        "SD write err {} consec, sector {} — degraded",
                        self.write_errors,
                        sd_sector_idx
                    );
                    self.degraded = true;
                } else {
                    #[cfg(target_arch = "arm")]
                    crate::cdc_warn!(
                        "SD write err on sector {} ({}/{})",
                        sd_sector_idx,
                        self.write_errors,
                        BAD_WRITE_THRESHOLD
                    );
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
        let first_sd_sector = (addr + SD_BYTE_OFFSET) / SD_SECTOR_BYTES;
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

// ─── SD card signature block (block 0 pairing) ─────────────────────────────────

/// Check/adoption result returned by `check_sd_signature`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdCardCheckResult {
    /// Raw block 0 has our magic + fingerprint matches this device. Proceed with RAID-1.
    Matched,
    /// Raw block 0 is blank (all 0x00 or 0xFF) or has no P2HSDCARD magic. Auto-adopt.
    Blank,
    /// Raw block 0 has valid magic but fingerprint is from a different device. Boot degraded.
    Foreign,
    /// Magic present but CRC invalid. Treat as Blank (overwrite safe).
    Corrupt,
}

/// Signature stored in raw SD card block 0 (512 bytes, first 64 bytes used).
#[allow(dead_code)]
pub struct SdCardSignature {
    pub device_fingerprint: [u8; 32],
    pub pairing_timestamp: u64,
}

const SD_SIG_MAGIC: [u8; 9] = *b"P2HSDCARD";
const SD_SIG_VERSION: u8 = 0x01;

/// Compute device fingerprint: SHA-256 of the 8-byte flash chip unique ID.
/// This is stable, hardware-unique, and works before OTP provisioning.
pub fn compute_device_fingerprint(flash_uid: &[u8; 8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(flash_uid);
    h.finalize().into()
}

/// Read raw block 0 from the SD card and classify the signature.
/// `card` must be initialized (num_bytes() already called).
pub fn check_sd_signature<SPI, DELAY>(
    card: &SdCard<SPI, DELAY>,
    our_fingerprint: &[u8; 32],
) -> SdCardCheckResult
where
    SPI: embedded_hal::spi::SpiDevice<u8>,
    DELAY: embedded_hal::delay::DelayNs,
{
    let mut block = [Block::new()];
    if card.read(&mut block, BlockIdx(0)).is_err() {
        return SdCardCheckResult::Blank;
    }
    let data = &block[0].contents;

    // Check if block is blank (all 0x00 or all 0xFF).
    let all_zero = data.iter().all(|&b| b == 0x00);
    let all_ff = data.iter().all(|&b| b == 0xFF);
    if all_zero || all_ff {
        return SdCardCheckResult::Blank;
    }

    // Check magic.
    if data[0..9] != SD_SIG_MAGIC {
        return SdCardCheckResult::Blank;
    }

    // Check version.
    if data[9] != SD_SIG_VERSION {
        return SdCardCheckResult::Blank;
    }

    // Verify CRC32 over bytes [0..54].
    let stored_crc = u32::from_le_bytes([data[54], data[55], data[56], data[57]]);
    let computed_crc = crc32fast::hash(&data[0..54]);
    if stored_crc != computed_crc {
        return SdCardCheckResult::Corrupt;
    }

    // Compare fingerprint.
    if data[10..42] == our_fingerprint[..] {
        SdCardCheckResult::Matched
    } else {
        SdCardCheckResult::Foreign
    }
}

/// Write our pairing signature to raw block 0.
pub fn write_sd_signature<SPI, DELAY>(
    card: &SdCard<SPI, DELAY>,
    fingerprint: &[u8; 32],
) -> Result<(), ()>
where
    SPI: embedded_hal::spi::SpiDevice<u8>,
    DELAY: embedded_hal::delay::DelayNs,
{
    let mut block = Block::new();
    // Fill padding with 0xFF.
    block.contents.fill(0xFF);

    // [0..9] magic
    block.contents[0..9].copy_from_slice(&SD_SIG_MAGIC);
    // [9] version
    block.contents[9] = SD_SIG_VERSION;
    // [10..42] device fingerprint
    block.contents[10..42].copy_from_slice(fingerprint);
    // [42..50] pairing timestamp (u64 LE) — use 0 for now (no RTC)
    block.contents[42..50].copy_from_slice(&0u64.to_le_bytes());
    // [50..54] reserved
    block.contents[50..54].fill(0x00);
    // [54..58] CRC32 over [0..54]
    let crc = crc32fast::hash(&block.contents[0..54]);
    block.contents[54..58].copy_from_slice(&crc.to_le_bytes());

    let blocks = [block];
    card.write(&blocks, BlockIdx(0)).map_err(|_| ())
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
        SdCardFlashLegacy {
            capacity,
            degraded: false,
        }
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
