//! Internal (QMI) flash drivers.
//!
//! # `QmiFlash` — the keystore region of the RP2350's own flash
//! Uses `embassy_rp::flash::Flash` in blocking mode.  Offsets are relative
//! to the keystore start; the firmware below it can never be erased.  All
//! erase/write calls go through the RP2350 bootrom routines
//! (`flash_range_erase` / `flash_range_program`), which manage the XIP
//! cache from a SRAM trampoline (core0 only).
//!
//! # `QmiRegionFlash` — the counter log, binding ring and RSA pool regions
//! Fixed regions outside the firmware and the keystore (`flash_layout`).

use heapless::Vec;
use pico2hsm_core::{error::StorageError, flash::FlashChip};

// ─── QmiFlash ─────────────────────────────────────────────────────────────────

/// Byte offset from flash start where the keystore partition begins.
/// Below it: firmware, the binding ring, the counter log and the RSA pool.
/// Never touch below this.  See `flash_layout`.
pub const QMI_KEYSTORE_OFFSET: u32 = super::flash_layout::QMI_KEYSTORE_OFFSET;

/// Flash size the QMI driver is instantiated with (4 MB; the 16 MB boards
/// use only the same lower 4 MB).
pub const QMI_FLASH_SIZE: usize = super::flash_layout::QMI_FLASH_SIZE as usize;

/// The RP2350 built-in QMI flash chip, restricted to the keystore partition.
///
/// All `addr` arguments in the `FlashChip` trait methods are **relative to
/// the keystore start** (0 = first byte of keystore, not start of chip).
/// `QMI_KEYSTORE_OFFSET` is added internally before every hardware call,
/// ensuring firmware flash (below 2 MB) can never be accidentally erased.
///
/// Erase/write operations are routed through the RP2350 bootrom routines
/// (`flash_range_erase` / `flash_range_program`) via a SRAM trampoline
/// managed by `embassy_rp::flash`.  This is safe to call from running
/// firmware — the bootrom handles XIP cache invalidation automatically.
pub struct QmiFlash {
    flash: embassy_rp::flash::Flash<
        'static,
        embassy_rp::peripherals::FLASH,
        embassy_rp::flash::Blocking,
        QMI_FLASH_SIZE,
    >,
    capacity: u64,
    degraded: bool,
    bad_sectors: Vec<u32, 256>,
}

impl QmiFlash {
    /// Create a new `QmiFlash` wrapping an embassy-rp blocking flash driver.
    ///
    /// `flash` must be created with `Flash::new_blocking(p.FLASH)` and the
    /// `FLASH_SIZE` const generic must equal `QMI_FLASH_SIZE` (4 MB).
    pub fn new(
        flash: embassy_rp::flash::Flash<
            'static,
            embassy_rp::peripherals::FLASH,
            embassy_rp::flash::Blocking,
            QMI_FLASH_SIZE,
        >,
    ) -> Self {
        QmiFlash {
            flash,
            capacity: (QMI_FLASH_SIZE as u64) - (QMI_KEYSTORE_OFFSET as u64),
            degraded: false,
            bad_sectors: Vec::new(),
        }
    }
}

impl FlashChip for QmiFlash {
    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        if addr as u64 + buf.len() as u64 > self.capacity {
            return Err(StorageError::ReadError);
        }
        self.flash
            .blocking_read(QMI_KEYSTORE_OFFSET + addr, buf)
            .map_err(|_| StorageError::ReadError)
    }

    fn write_page(&mut self, addr: u32, data: &[u8]) -> Result<(), StorageError> {
        // Feeds the hardware watchdog on core0 / bumps core1's heartbeat.
        crate::watchdog::progress();
        if addr as u64 + data.len() as u64 > self.capacity {
            return Err(StorageError::WriteError);
        }
        if self.degraded || self.bad_sectors.contains(&(addr / 4096)) {
            return Err(StorageError::WriteError);
        }
        self.flash
            .blocking_write(QMI_KEYSTORE_OFFSET + addr, data)
            .map_err(|_| StorageError::WriteError)?;

        // Write-back verification.
        let mut verify_buf = [0u8; 256];
        let verify_slice = &mut verify_buf[..data.len()];
        self.flash
            .blocking_read(QMI_KEYSTORE_OFFSET + addr, verify_slice)
            .map_err(|_| StorageError::ReadError)?;

        if verify_slice != data {
            let sector = addr / 4096;
            defmt::error!(
                "QmiFlash: write-verify failed at addr 0x{:08X} (sector {})",
                addr,
                sector,
            );
            // Never retire a directory copy (sectors below DATA_START): one
            // failed verify would then fail every save until reboot.  The
            // error is reported and the next flush simply tries again.
            if sector >= pico2hsm_core::storage::DATA_START_SECTOR {
                let _ = self.mark_bad_sector(sector);
            }
            return Err(StorageError::BadBlock { chip: 0, sector });
        }
        Ok(())
    }

    fn erase_sector(&mut self, addr: u32) -> Result<(), StorageError> {
        // Runs from flash after the previous erase returned (XIP is back),
        // so nothing here needs to be in RAM.
        // Feeds the hardware watchdog on core0 / bumps core1's heartbeat.
        crate::watchdog::progress();
        if addr as u64 + 4096 > self.capacity {
            return Err(StorageError::EraseError);
        }
        if self.degraded || self.bad_sectors.contains(&(addr / 4096)) {
            return Err(StorageError::EraseError);
        }
        if addr % 4096 != 0 {
            return Err(StorageError::EraseError);
        }
        let from = QMI_KEYSTORE_OFFSET + addr;
        let to = from + 4096;
        self.flash
            .blocking_erase(from, to)
            .map_err(|_| StorageError::EraseError)
    }

    fn jedec_id(&mut self) -> Option<[u8; 3]> {
        // Internal flash has no JEDEC ID accessible via SPI from firmware.
        None
    }

    fn is_degraded(&self) -> bool {
        self.degraded
    }

    fn mark_bad_sector(&mut self, sector: u32) -> Result<(), StorageError> {
        // Ignore push errors (table full); degrade if too many bad sectors.
        let _ = self.bad_sectors.push(sector);
        if self.bad_sectors.len() > 32 {
            self.degraded = true;
        }
        Ok(())
    }
}

// ─── QmiRegionFlash — the counter log and RSA pool regions ──────────────────

/// A fixed region of internal flash outside the firmware image and the
/// keystore: the retry-counter log ([`QmiCounterFlash`]) or the RSA key
/// pool ([`QmiPoolFlash`]), at `flash_layout` offsets on every board.
///
/// Offsets are relative to the region; anything outside it is refused, so
/// the region can never reach the firmware image or the keystore.  Writes
/// and erases go through the bootrom (`embassy_rp::flash`), which only
/// works on core0 — on core1 they fail with an error, never a panic.
pub struct QmiRegionFlash<const OFFSET: u32, const SIZE: u32> {
    flash: embassy_rp::flash::Flash<
        'static,
        embassy_rp::peripherals::FLASH,
        embassy_rp::flash::Blocking,
        QMI_FLASH_SIZE,
    >,
}

/// The retry-counter log region (`flash_layout::RETRY_COUNTER_OFFSET`).
pub type QmiCounterFlash = QmiRegionFlash<
    { super::flash_layout::RETRY_COUNTER_OFFSET },
    { super::flash_layout::RETRY_COUNTER_SIZE },
>;

/// The version-1 counter log region (`flash_layout::LEGACY_COUNTER_OFFSET`),
/// read once to migrate it, then erased.
pub type QmiLegacyCounterFlash = QmiRegionFlash<
    { super::flash_layout::LEGACY_COUNTER_OFFSET },
    { super::flash_layout::LEGACY_COUNTER_SIZE },
>;

/// The Storage V2 binding block ring (`flash_layout::BINDING_OFFSET`).
pub type QmiBindingFlash =
    QmiRegionFlash<{ super::flash_layout::BINDING_OFFSET }, { super::flash_layout::BINDING_SIZE }>;

/// The RSA key pool region (`flash_layout::RSA_POOL_OFFSET`).
pub type QmiPoolFlash = QmiRegionFlash<
    { super::flash_layout::RSA_POOL_OFFSET },
    { super::flash_layout::RSA_POOL_SIZE },
>;

impl<const OFFSET: u32, const SIZE: u32> QmiRegionFlash<OFFSET, SIZE> {
    /// Wrap a blocking flash driver.  On QMI boards the keystore's
    /// `QmiFlash` owns `p.FLASH`, so this one is built from a stolen
    /// handle: the driver is stateless and all of them are used only from
    /// core0, one operation at a time (`handle_flash_op` / boot).
    pub fn new(
        flash: embassy_rp::flash::Flash<
            'static,
            embassy_rp::peripherals::FLASH,
            embassy_rp::flash::Blocking,
            QMI_FLASH_SIZE,
        >,
    ) -> Self {
        QmiRegionFlash { flash }
    }

    fn absolute(offset: u32, len: usize) -> Result<u32, StorageError> {
        let end = offset
            .checked_add(len as u32)
            .ok_or(StorageError::WriteError)?;
        if end > SIZE {
            return Err(StorageError::WriteError);
        }
        Ok(OFFSET + offset)
    }
}

impl<const OFFSET: u32, const SIZE: u32> super::retry_counter::CounterFlash
    for QmiRegionFlash<OFFSET, SIZE>
{
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        let at = Self::absolute(offset, buf.len()).map_err(|_| StorageError::ReadError)?;
        self.flash
            .blocking_read(at, buf)
            .map_err(|_| StorageError::ReadError)
    }

    fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError> {
        let at = Self::absolute(offset, data.len())?;
        // embassy pads partial pages with 0xFF, which programs nothing.
        self.flash
            .blocking_write(at, data)
            .map_err(|_| StorageError::WriteError)
    }

    fn erase_sector(&mut self, sector: u32) -> Result<(), StorageError> {
        let size = super::flash_layout::SECTOR;
        let from =
            Self::absolute(sector * size, size as usize).map_err(|_| StorageError::EraseError)?;
        self.flash
            .blocking_erase(from, from + size)
            .map_err(|_| StorageError::EraseError)
    }
}

// ─── Storage V2: the QMI keystore region as a `StoreFlash` ───────────────────

impl super::store_v2::StoreFlash for QmiFlash {
    fn media(&self) -> super::store_v2::Media {
        super::store_v2::Media::Nor
    }

    fn sectors(&self) -> u32 {
        (self.capacity / u64::from(super::store_v2::SECTOR)) as u32
    }

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        FlashChip::read(self, offset, buf)
    }

    /// NOR program through the bootrom (core0 only), any length; the
    /// engine verifies what it needs to.
    fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError> {
        crate::watchdog::progress();
        if offset as u64 + data.len() as u64 > self.capacity {
            return Err(StorageError::WriteError);
        }
        self.flash
            .blocking_write(QMI_KEYSTORE_OFFSET + offset, data)
            .map_err(|_| StorageError::WriteError)
    }

    fn erase_sector(&mut self, sector: u32) -> Result<(), StorageError> {
        FlashChip::erase_sector(self, sector * super::store_v2::SECTOR)
    }
}
