//! The keystore medium per board, for `StaticCell` monomorphization.
//!
//! Every board without an SD card keeps its keystore in the upper part of
//! the internal QMI flash (`QmiFlash`); the SD-card boards on the card
//! (`SdCardFlash`).  No board has external SPI flash (STORAGE_V2 §2).

#[cfg(all(
    target_arch = "arm",
    any(
        feature = "waveshare_rp2350_lcd_sdcard",
        feature = "rp2350_geek_sdcard"
    )
))]
use embassy_rp::gpio::Output;

#[cfg(target_arch = "arm")]
use crate::storage::flash_chip::QmiFlash;

#[cfg(all(
    target_arch = "arm",
    any(
        feature = "waveshare_rp2350_lcd_sdcard",
        feature = "rp2350_geek_sdcard",
    )
))]
use crate::storage::sdcard::SdCardFlash;

// ── pico2_4m ─────────────────────────────────────────────────────────────────

/// Internal QMI flash — no external chips on the stock Pico 2.
#[cfg(all(target_arch = "arm", feature = "pico2_4m"))]
pub type BoardChip = QmiFlash;

// ── rp2350_one_* ─────────────────────────────────────────────────────────────

/// Internal QMI flash (the RAID-1 SPI chips of the 1.x design were never
/// fitted).
#[cfg(all(target_arch = "arm", feature = "rp2350_one_4m"))]
pub type BoardChip = QmiFlash;

// ── rp2350_geek_16m ──────────────────────────────────────────────────────────

/// QMI flash — upper 2 MB of the 16 MB on-board QSPI chip.
/// No external SPI flash chips on this board; SPI0 is unused.
#[cfg(all(target_arch = "arm", feature = "rp2350_geek_16m"))]
pub type BoardChip = QmiFlash;

// ── rp2350_geek_sdcard ──────────────────────────────────────────────────────

/// SD card on SPI0 (SCK=GPIO18, MOSI=GPIO19, MISO=GPIO20, CS=GPIO23).
#[cfg(all(target_arch = "arm", feature = "rp2350_geek_sdcard"))]
pub type BoardChip = SdCardFlash<
    embassy_embedded_hal::shared_bus::blocking::spi::SpiDevice<
        'static,
        embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
        embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Blocking>,
        Output<'static>,
    >,
    embassy_time::Delay,
>;

// ── waveshare_rp2350_lcd_16m ──────────────────────────────────────────────────

/// The RP2350-LCD-1.47-B has a 16 MB W25Q128JVSIQ on QSPI.  The SPI0 bus
/// drives the LCD (write-only, no keystore flash chips wired) and SPI1 drives
/// the SD card.  QmiFlash is initialised from p.FLASH in run_waveshare_lcd_board
/// (upper 2 MB keystore partition, same layout as pico2_4m).
#[cfg(all(target_arch = "arm", feature = "waveshare_rp2350_lcd_16m"))]
pub type BoardChip = QmiFlash;

// ── waveshare_rp2350_lcd_sdcard ──────────────────────────────────────────────

/// Single SD card on SPI1 (SCK=GPIO10, MOSI=GPIO11, MISO=GPIO12, CS=GPIO15).
/// SPI1 is consumed entirely by the SD card; the LCD uses SPI0.
/// Uses `SimpleSpiDevice` (no mutex/critical section) since the SD card is the
/// sole SPI1 consumer on this board.
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

// ── BoardKeyStore type alias ──────────────────────────────────────────────────

/// The keystore medium of the Storage V2 store: internal QMI flash on every
/// board without an SD card (the RP2350-One included: its RAID `BoardChip`
/// was never populated), the card on the SD boards.
#[cfg(all(
    target_arch = "arm",
    not(any(
        feature = "rp2350_geek_sdcard",
        feature = "waveshare_rp2350_lcd_sdcard"
    ))
))]
pub type BoardStoreChip = QmiFlash;
#[cfg(all(
    target_arch = "arm",
    any(
        feature = "rp2350_geek_sdcard",
        feature = "waveshare_rp2350_lcd_sdcard"
    )
))]
pub type BoardStoreChip = BoardChip;

/// `BoardKeyStore`: the Storage V2 key store over `BoardStoreChip`, with
/// the binding ring and the counter log on internal flash.
#[cfg(target_arch = "arm")]
pub type BoardKeyStore = crate::storage::keystore_v2::FlashKeyStoreV2<
    BoardStoreChip,
    crate::storage::flash_chip::RoutedBindingFlash,
    crate::storage::BoardCounterLog,
>;
