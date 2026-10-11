//! `FlashChip` trait — abstraction over any SPI flash chip or `SDCard`.
//!
//! Implementations handle 3-byte vs 4-byte address mode internally.
//! All addresses are byte-aligned. Sector size is always 4096 bytes.
//! Page size is always 256 bytes for write granularity.
//!
//! The firmware storage stack calls only these methods; concrete
//! implementations live in `firmware/src/storage/flash_chip.rs`
//! (for QMI/SPI flash) and `firmware/src/storage/sdcard.rs`.

use crate::error::StorageError;

/// Size of one erasable sector in bytes (4 KiB).
pub const SECTOR_SIZE: usize = 4096;

/// Size of one programmable page in bytes (256 B).
pub const PAGE_SIZE: usize = 256;

/// Maximum number of simultaneously attached flash chips.
/// 4 chips per SPI bus × 2 buses (SPI0 + SPI1).
pub const MAX_CHIPS: usize = 8;

/// Abstraction over any SPI flash chip or `SDCard` used as keystore storage.
///
/// All addresses are byte-aligned. Sector size is always 4096 bytes.
/// Implementations handle 3-byte vs 4-byte addressing internally.
pub trait FlashChip {
    /// Total capacity in bytes.
    fn capacity(&self) -> u64;

    /// Read `buf.len()` bytes starting at byte address `addr`.
    ///
    /// `addr` does not need to be aligned for reads.
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), StorageError>;

    /// Write a page (up to 256 bytes).
    ///
    /// `addr` MUST be page-aligned (256-byte boundary).
    /// `data.len()` MUST be <= `PAGE_SIZE`.
    fn write_page(&mut self, addr: u32, data: &[u8]) -> Result<(), StorageError>;

    /// Erase one 4096-byte sector.
    ///
    /// `addr` MUST be sector-aligned (4096-byte boundary).
    fn erase_sector(&mut self, addr: u32) -> Result<(), StorageError>;

    /// Returns the JEDEC manufacturer+device ID (3 bytes), or `None` if the
    /// chip is not responding on the SPI bus.
    fn jedec_id(&mut self) -> Option<[u8; 3]>;

    /// Returns `true` if the chip has been marked degraded (exceeded erase
    /// cycle estimates or returned persistent errors).
    fn is_degraded(&self) -> bool;

    /// Record a permanently failed sector in the bad-block table stored in
    /// the chip's directory sector metadata area.
    fn mark_bad_sector(&mut self, sector: u32) -> Result<(), StorageError>;
}
