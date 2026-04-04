//! SPI flash chip implementations of `FlashChip`.
//!
//! Provides three concrete `FlashChip` implementations:
//!
//! # `SpiFlash<SPI, CS>` — General SPI flash over SPI0 or SPI1
//! Supports W25Qxx Winbond flash chips with JEDEC ID auto-detection.
//! 3-byte addressing for chips up to 128 Mbit; 4-byte addressing for
//! 256 Mbit and larger (EN4B command sent on `init()`).
//!
//! # `QmiFlash` — RP2350 built-in QMI flash (pico2_4m keystore partition)
//! Uses `embassy_rp::flash::Flash` in blocking mode to access the upper half
//! of the 4 MB on-board flash.  The lower 2 MB (firmware XIP region) is
//! protected by a compile-time partition guard (`QMI_KEYSTORE_OFFSET`).
//! All erase/write calls go through the RP2350 bootrom routines
//! (`flash_range_erase` / `flash_range_program`) which automatically manage
//! XIP cache invalidation from a SRAM trampoline — safe to call from running
//! firmware without a custom bootloader stub.
//!
//! # Supported ICs (JEDEC ID → capacity)
//! | JEDEC ID | Part      | Capacity | Addressing |
//! |----------|-----------|----------|------------|
//! | 0xEF4015 | W25Q16    |  2 MB    | 3-byte     |
//! | 0xEF4016 | W25Q32    |  4 MB    | 3-byte     |
//! | 0xEF4017 | W25Q64    |  8 MB    | 3-byte     |
//! | 0xEF4018 | W25Q128   | 16 MB    | 3-byte     |
//! | 0xEF4019 | W25Q256   | 32 MB    | 4-byte (EN4B on init) |
//! | 0xEF4020 | W25Q512   | 64 MB    | 4-byte mandatory      |
//! | 0xEF4022 | W25Q02    |256 MB    | 4-byte mandatory      |
//!
//! Unknown JEDEC IDs return `StorageError::ReadError` from `init()` and
//! set the chip as not-present (degraded).
//!
//! # Write-back verification
//! After every `write_page()` the written data is read back and compared
//! byte-by-byte.  On mismatch the sector is added to the bad-block table
//! and `StorageError::BadBlock` is returned so the RAID layer can remap.

use heapless::Vec;
use pico2hsm_core::{error::StorageError, flash::FlashChip};

// ─── SPI command bytes ────────────────────────────────────────────────────────

const CMD_READ_3B: u8 = 0x03;
const CMD_READ_4B: u8 = 0x13;
const CMD_PAGE_PROG_3B: u8 = 0x02;
const CMD_PAGE_PROG_4B: u8 = 0x12;
const CMD_SECTOR_ERASE_3B: u8 = 0x20;
const CMD_SECTOR_ERASE_4B: u8 = 0x21;
const CMD_READ_STATUS: u8 = 0x05;
const CMD_WRITE_ENABLE: u8 = 0x06;
const CMD_JEDEC_ID: u8 = 0x9F;
const CMD_EN4B: u8 = 0xB7; // Enter 4-byte address mode
#[allow(dead_code)]
const CMD_EX4B: u8 = 0xE9; // Exit 4-byte address mode
#[allow(dead_code)]
const CMD_CHIP_ERASE: u8 = 0xC7;
const STATUS_BUSY: u8 = 0x01;
#[allow(dead_code)]
const STATUS_WEL: u8 = 0x02;

/// Maximum busy-poll iterations before declaring a timeout (~5 s at ~1 µs/iter).
const BUSY_POLL_MAX: u32 = 5_000_000;

/// Maximum number of bad sectors tracked per chip.
const MAX_BAD_SECTORS: usize = 256;

// ─── SpiFlash<SPI, CS> ────────────────────────────────────────────────────────

/// External SPI flash chip on SPI0 or SPI1.
///
/// Generic over the SPI bus type `SPI` and a GPIO chip-select type `CS`.
/// Both must implement their respective embedded-hal 1.x traits.
pub struct SpiFlash<SPI, CS> {
    spi: SPI,
    cs: CS,
    /// Total chip capacity in bytes (set by `init()` after JEDEC probe).
    capacity_bytes: u32,
    /// `true` if this chip requires 4-byte addresses (>128 Mbit).
    use_4byte_addr: bool,
    /// Sectors known to be permanently bad.
    bad_block_table: Vec<u32, MAX_BAD_SECTORS>,
    /// `true` if the chip has been marked degraded.
    degraded: bool,
}

impl<SPI, CS> SpiFlash<SPI, CS>
where
    SPI: embedded_hal::spi::SpiBus,
    CS: embedded_hal::digital::OutputPin,
{
    /// Create a new `SpiFlash` instance.
    ///
    /// `capacity_bytes` and `use_4byte_addr` are set to zero/false until
    /// `init()` is called; the chip is not usable until `init()` succeeds.
    pub fn new(spi: SPI, cs: CS) -> Self {
        SpiFlash {
            spi,
            cs,
            capacity_bytes: 0,
            use_4byte_addr: false,
            bad_block_table: Vec::new(),
            degraded: false,
        }
    }

    /// Read JEDEC ID and configure capacity + addressing mode.
    ///
    /// Must be called before any read/write/erase operation.
    pub fn init(&mut self) -> Result<(), StorageError> {
        let id = self.read_jedec_id_raw()?;
        let jedec24 = ((id[0] as u32) << 16) | ((id[1] as u32) << 8) | (id[2] as u32);

        let (capacity, needs_4b) = match jedec24 {
            0xEF4015 => (2 * 1024 * 1024, false),   // W25Q16  — 2 MB
            0xEF4016 => (4 * 1024 * 1024, false),   // W25Q32  — 4 MB
            0xEF4017 => (8 * 1024 * 1024, false),   // W25Q64  — 8 MB
            0xEF4018 => (16 * 1024 * 1024, false),  // W25Q128 — 16 MB
            0xEF4019 => (32 * 1024 * 1024, true),   // W25Q256 — 32 MB
            0xEF4020 => (64 * 1024 * 1024, true),   // W25Q512 — 64 MB
            0xEF4022 => (256 * 1024 * 1024, true),  // W25Q02  — 256 MB
            _ => {
                defmt::error!(
                    "SpiFlash: unknown JEDEC ID 0x{:06X} — chip not present or unsupported",
                    jedec24,
                );
                self.degraded = true;
                return Err(StorageError::ReadError);
            }
        };

        self.capacity_bytes = capacity;
        self.use_4byte_addr = needs_4b;

        defmt::info!(
            "SpiFlash: JEDEC 0x{:06X} → {} MB, 4-byte addr: {}",
            jedec24,
            capacity / (1024 * 1024),
            needs_4b,
        );

        // Enter 4-byte address mode if required.
        if needs_4b {
            self.send_command_only(CMD_EN4B)?;
            defmt::info!("SpiFlash: entered 4-byte address mode");
        }

        Ok(())
    }

    // ── CS helpers ──────────────────────────────────────────────────────────

    fn cs_low(&mut self) -> Result<(), StorageError> {
        self.cs.set_low().map_err(|_| StorageError::WriteError)
    }

    fn cs_high(&mut self) -> Result<(), StorageError> {
        self.cs.set_high().map_err(|_| StorageError::WriteError)
    }

    // ── Low-level SPI helpers ───────────────────────────────────────────────

    fn spi_write(&mut self, data: &[u8]) -> Result<(), StorageError> {
        self.spi.write(data).map_err(|_| StorageError::WriteError)
    }

    fn spi_read(&mut self, buf: &mut [u8]) -> Result<(), StorageError> {
        self.spi.read(buf).map_err(|_| StorageError::ReadError)
    }

    fn spi_transfer(&mut self, read: &mut [u8], write: &[u8]) -> Result<(), StorageError> {
        self.spi.transfer(read, write).map_err(|_| StorageError::ReadError)
    }

    // ── Address encoding ────────────────────────────────────────────────────

    /// Encode `addr` as 3 or 4 address bytes depending on `use_4byte_addr`.
    fn encode_addr(&self, addr: u32, buf: &mut [u8; 4]) -> usize {
        if self.use_4byte_addr {
            buf[0] = (addr >> 24) as u8;
            buf[1] = (addr >> 16) as u8;
            buf[2] = (addr >> 8) as u8;
            buf[3] = addr as u8;
            4
        } else {
            buf[0] = (addr >> 16) as u8;
            buf[1] = (addr >> 8) as u8;
            buf[2] = addr as u8;
            buf[3] = 0; // unused
            3
        }
    }

    // ── Status register polling ─────────────────────────────────────────────

    fn read_status(&mut self) -> Result<u8, StorageError> {
        self.cs_low()?;
        self.spi_write(&[CMD_READ_STATUS])?;
        let mut status = [0u8; 1];
        self.spi_read(&mut status)?;
        self.cs_high()?;
        Ok(status[0])
    }

    /// Poll until BUSY bit clears.  Returns error on timeout (~5 s).
    fn wait_ready(&mut self) -> Result<(), StorageError> {
        for _ in 0..BUSY_POLL_MAX {
            let status = self.read_status()?;
            if status & STATUS_BUSY == 0 {
                return Ok(());
            }
            // Small busy-wait — cortex-m nop (≈6 ns @ 150 MHz ≈ 1 µs with overhead).
            cortex_m::asm::nop();
        }
        defmt::error!("SpiFlash: BUSY timeout — chip may be dead");
        self.degraded = true;
        Err(StorageError::WriteError)
    }

    // ── Single-byte command (no address, no data) ───────────────────────────

    fn send_command_only(&mut self, cmd: u8) -> Result<(), StorageError> {
        self.cs_low()?;
        self.spi_write(&[cmd])?;
        self.cs_high()?;
        Ok(())
    }

    // ── Write Enable ────────────────────────────────────────────────────────

    fn write_enable(&mut self) -> Result<(), StorageError> {
        self.send_command_only(CMD_WRITE_ENABLE)
    }

    // ── JEDEC ID (internal) ─────────────────────────────────────────────────

    fn read_jedec_id_raw(&mut self) -> Result<[u8; 3], StorageError> {
        self.cs_low()?;
        self.spi_write(&[CMD_JEDEC_ID])?;
        let mut id = [0u8; 3];
        self.spi_read(&mut id)?;
        self.cs_high()?;
        if id == [0x00, 0x00, 0x00] || id == [0xFF, 0xFF, 0xFF] {
            return Err(StorageError::ReadError);
        }
        Ok(id)
    }

    // ── Internal read (shared by FlashChip::read) ───────────────────────────

    fn read_internal(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        let cmd = if self.use_4byte_addr {
            CMD_READ_4B
        } else {
            CMD_READ_3B
        };
        let mut addr_buf = [0u8; 4];
        let addr_len = self.encode_addr(addr, &mut addr_buf);

        self.cs_low()?;
        // Send command + address.
        let mut header = [0u8; 5];
        header[0] = cmd;
        header[1..1 + addr_len].copy_from_slice(&addr_buf[..addr_len]);
        self.spi_write(&header[..1 + addr_len])?;
        // Read data.
        self.spi_read(buf)?;
        self.cs_high()?;
        Ok(())
    }

    // ── Write-back verification helper ──────────────────────────────────────

    /// Read back `len` bytes at `addr` and compare with `expected`.
    ///
    /// On mismatch: marks the containing sector bad and returns
    /// `StorageError::BadBlock`.
    fn verify_write(&mut self, addr: u32, expected: &[u8]) -> Result<(), StorageError> {
        // Stack-limited readback buffer (max 256 B = PAGE_SIZE).
        let mut readback = [0u8; 256];
        let len = expected.len().min(256);
        self.read_internal(addr, &mut readback[..len])?;

        if readback[..len] != expected[..len] {
            let sector = addr / 4096;
            defmt::error!(
                "SpiFlash: write-verify failed at addr 0x{:08X} (sector {})",
                addr,
                sector,
            );
            let _ = self.bad_block_table.push(sector);
            return Err(StorageError::BadBlock { chip: 0, sector });
        }
        Ok(())
    }
}

impl<SPI, CS> FlashChip for SpiFlash<SPI, CS>
where
    SPI: embedded_hal::spi::SpiBus,
    CS: embedded_hal::digital::OutputPin,
{
    fn capacity(&self) -> u64 {
        self.capacity_bytes as u64
    }

    /// Read `buf.len()` bytes starting at byte address `addr`.
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), StorageError> {
        self.read_internal(addr, buf)
    }

    /// Write a page (up to 256 bytes) at a page-aligned address.
    ///
    /// Steps:
    /// 1. Write Enable.
    /// 2. Page Program command + 3- or 4-byte address + data.
    /// 3. Wait for BUSY to clear.
    /// 4. Verify by reading back and comparing.
    fn write_page(&mut self, addr: u32, data: &[u8]) -> Result<(), StorageError> {
        self.write_enable()?;

        let cmd = if self.use_4byte_addr {
            CMD_PAGE_PROG_4B
        } else {
            CMD_PAGE_PROG_3B
        };
        let mut addr_buf = [0u8; 4];
        let addr_len = self.encode_addr(addr, &mut addr_buf);

        self.cs_low()?;
        let mut header = [0u8; 5];
        header[0] = cmd;
        header[1..1 + addr_len].copy_from_slice(&addr_buf[..addr_len]);
        self.spi_write(&header[..1 + addr_len])?;
        self.spi_write(data)?;
        self.cs_high()?;

        self.wait_ready()?;

        // Write-back verification.
        self.verify_write(addr, data)
    }

    /// Erase one 4096-byte sector at a sector-aligned address.
    ///
    /// Steps:
    /// 1. Write Enable.
    /// 2. Sector Erase command + address.
    /// 3. Wait for BUSY to clear (sector erase ≤ 400 ms on W25Qxx).
    fn erase_sector(&mut self, addr: u32) -> Result<(), StorageError> {
        self.write_enable()?;

        let cmd = if self.use_4byte_addr {
            CMD_SECTOR_ERASE_4B
        } else {
            CMD_SECTOR_ERASE_3B
        };
        let mut addr_buf = [0u8; 4];
        let addr_len = self.encode_addr(addr, &mut addr_buf);

        self.cs_low()?;
        let mut header = [0u8; 5];
        header[0] = cmd;
        header[1..1 + addr_len].copy_from_slice(&addr_buf[..addr_len]);
        self.spi_write(&header[..1 + addr_len])?;
        self.cs_high()?;

        self.wait_ready()
    }

    /// Read the JEDEC manufacturer + device ID (3 bytes).
    ///
    /// Returns `None` if the chip is not responding (all-zero or all-ones).
    fn jedec_id(&mut self) -> Option<[u8; 3]> {
        self.read_jedec_id_raw().ok()
    }

    fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// Record a permanently failed sector in the in-memory bad-block table.
    ///
    /// The bad-block table is persisted on power cycle only if the storage
    /// manager writes it to the chip's directory sector — this is handled
    /// at a higher layer.  This call only updates the in-memory table.
    fn mark_bad_sector(&mut self, sector: u32) -> Result<(), StorageError> {
        if self.bad_block_table.iter().any(|&s| s == sector) {
            return Ok(()); // Already tracked.
        }
        self.bad_block_table
            .push(sector)
            .map_err(|_| StorageError::WriteError)?;
        defmt::warn!("SpiFlash: sector {} marked bad (total bad: {})", sector, self.bad_block_table.len());
        Ok(())
    }
}

// ─── QmiFlash — RP2350 built-in flash (pico2_4m) ─────────────────────────────

/// Byte offset from flash start where the keystore partition begins.
/// The first 2 MB is firmware (XIP-executable). Never touch below this.
pub const QMI_KEYSTORE_OFFSET: u32 = 0x0020_0000;

/// Total physical flash size for the pico2_4m board.
pub const QMI_FLASH_SIZE: usize = 0x0040_0000; // 4 MB

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
    bad_sectors: heapless::Vec<u32, 256>,
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
            bad_sectors: heapless::Vec::new(),
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
            let _ = self.mark_bad_sector(sector);
            return Err(StorageError::BadBlock { chip: 0, sector });
        }
        Ok(())
    }

    fn erase_sector(&mut self, addr: u32) -> Result<(), StorageError> {
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

// ─── Legacy SpiFlash stub (kept for source compat) ───────────────────────────

/// Type-erased wrapper kept for source compatibility with any code that
/// instantiates the old `SpiFlash { capacity, degraded }` struct directly.
///
/// New code should use `SpiFlash<SPI, CS>` generically.
pub struct SpiFlashLegacy {
    capacity: u64,
    degraded: bool,
}

impl SpiFlashLegacy {
    #[allow(dead_code)]
    pub fn new(_capacity: u64) -> Self {
        SpiFlashLegacy { capacity: _capacity, degraded: false }
    }
}

impl FlashChip for SpiFlashLegacy {
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
        Err(StorageError::WriteError)
    }
}
