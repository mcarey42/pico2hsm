//! Board-specific `BoardChip` type aliases for `StaticCell` monomorphization.
//!
//! Exactly one `BoardChip` alias is active at compile time, selected by
//! the active board feature flag.
//!
//! # pico2_4m
//! Uses `QmiFlash` — the RP2350 internal QMI flash (upper 2 MB partition).
//! No external SPI flash is required; the on-board 4 MB chip is shared between
//! firmware XIP (lower 2 MB) and keystore (upper 2 MB).
//!
//! # rp2350_one_* / rp2350_geek_*
//! Uses `AnyChip<Spi0Flash, Spi1Flash, QmiFlash>` where Spi0Flash is the
//! primary flash on SPI0 and Spi1Flash is the RAID-1 mirror on SPI1.
//! `QmiFlash` is the unused SD-slot placeholder for the type parameter.
//!
//! NOTE: The AnyChip variants for SPI boards require that the SpiFlash instances
//! are built from the respective SPI buses before the board struct is constructed.
//! See `main.rs` `run_one_board` / `run_geek_board` for the wiring.

#[cfg(target_arch = "arm")]
use embassy_rp::gpio::Output;

#[cfg(target_arch = "arm")]
use crate::storage::{
    AnyChip,
    flash_chip::{QmiFlash, SpiFlash},
};

#[cfg(all(target_arch = "arm", any(feature = "waveshare_rp2350_lcd_sdcard", feature = "waveshare_rp2350_lcd_sdcard_hybrid")))]
use crate::storage::sdcard::SdCardFlash;

// ── pico2_4m ─────────────────────────────────────────────────────────────────

/// Internal QMI flash — no external chips on the stock Pico 2.
#[cfg(all(target_arch = "arm", feature = "pico2_4m"))]
pub type BoardChip = QmiFlash;

// ── rp2350_one_* ─────────────────────────────────────────────────────────────

/// RAID-1 pair: SPI0 primary (W25Qxx) + SPI1 mirror (W25Qxx).
/// The third type parameter (`QmiFlash`) is the unused SD-slot placeholder.
#[cfg(all(target_arch = "arm", any(feature = "rp2350_one_4m", feature = "rp2350_one_16m")))]
pub type BoardChip = AnyChip<
    SpiFlash<
        embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Blocking>,
        Output<'static>,
    >,
    SpiFlash<
        embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>,
        Output<'static>,
    >,
    QmiFlash,
>;

// ── rp2350_geek_* ─────────────────────────────────────────────────────────────

/// RAID-1 pair: SPI0 primary + SPI1 mirror.
/// SPI pin assignments are identical to RP2350-One.
#[cfg(all(target_arch = "arm", any(
    feature = "rp2350_geek_16m",
    feature = "rp2350_geek_sdcard",
    feature = "rp2350_geek_sdcard_dual",
)))]
pub type BoardChip = AnyChip<
    SpiFlash<
        embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Blocking>,
        Output<'static>,
    >,
    SpiFlash<
        embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>,
        Output<'static>,
    >,
    QmiFlash,
>;

// ── waveshare_rp2350_lcd_16m ──────────────────────────────────────────────────

/// The RP2350-LCD-1.47-B has a 16 MB W25Q128JVSIQ on QSPI.  The SPI0 bus
/// drives the LCD (write-only, no keystore flash chips wired) and SPI1 drives
/// the SD card.  Until QmiFlash is wired via p.FLASH (see run_waveshare_lcd_board
/// TODO), use QmiFlash directly as the BoardChip type so the type system
/// stays consistent with pico2_4m while keeping storage in degraded mode.
///
/// TODO (board-storage wiring): switch to QmiFlash and initialise it from
/// p.FLASH once the storage wiring is completed.
#[cfg(all(target_arch = "arm", any(feature = "waveshare_rp2350_lcd_16m", feature = "waveshare_rp2350_lcd_sdcard_dual")))]
pub type BoardChip = QmiFlash;

// ── waveshare_rp2350_lcd_sdcard ──────────────────────────────────────────────

/// Single SD card on SPI1 (SCK=GPIO10, MOSI=GPIO11, MISO=GPIO12, CS=GPIO15).
/// SPI1 is consumed entirely by the SD card; the LCD uses SPI0.
#[cfg(all(target_arch = "arm", feature = "waveshare_rp2350_lcd_sdcard"))]
pub type BoardChip = SdCardFlash<
    embassy_embedded_hal::shared_bus::blocking::spi::SpiDevice<
        'static,
        embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
        embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>,
        Output<'static>,
    >,
    embassy_time::Delay,
>;

// ── waveshare_rp2350_lcd_sdcard_hybrid ──────────────────────────────────────

/// Hybrid RAID-1: QMI flash (primary) + single SD card on SPI1 (secondary).
/// The SD card is on SPI1 (SCK=GPIO10, MOSI=GPIO11, MISO=GPIO12, CS=GPIO15).
/// The primary `BoardChip` for the hybrid variant is QMI flash.
#[cfg(all(target_arch = "arm", feature = "waveshare_rp2350_lcd_sdcard_hybrid"))]
pub type BoardChip = QmiFlash;

/// SD card chip type for the hybrid variant — SPI1 bus wrapped as a shared-bus
/// `SpiDevice` via `embassy_embedded_hal`.
#[cfg(all(target_arch = "arm", feature = "waveshare_rp2350_lcd_sdcard_hybrid"))]
pub type HybridSdChip = SdCardFlash<
    embassy_embedded_hal::shared_bus::blocking::spi::SpiDevice<
        'static,
        embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
        embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>,
        Output<'static>,
    >,
    embassy_time::Delay,
>;

// ── BoardKeyStore type alias ──────────────────────────────────────────────────

/// `BoardKeyStore` for non-hybrid variants: a single `FlashKeyStore` over `BoardChip`.
#[cfg(all(target_arch = "arm", not(feature = "waveshare_rp2350_lcd_sdcard_hybrid")))]
pub type BoardKeyStore = crate::storage::FlashKeyStore<BoardChip>;

/// `BoardKeyStore` for the hybrid variant: RAID-1 over QMI flash and SD card.
#[cfg(all(target_arch = "arm", feature = "waveshare_rp2350_lcd_sdcard_hybrid"))]
pub type BoardKeyStore = crate::storage::HybridKeyStore<
    crate::storage::FlashKeyStore<QmiFlash>,
    crate::storage::FlashKeyStore<HybridSdChip>,
>;
