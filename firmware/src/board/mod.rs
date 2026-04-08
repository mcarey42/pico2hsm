//! Board-specific hardware initialisation and LED control.
//!
//! This module provides a `Board` trait and per-board implementations
//! selected at compile time via feature flags.
//!
//! # Board variants
//! - `rp2350_one`          — Waveshare RP2350-One (4MB and 16MB): WS2812B LED on GPIO16
//! - `rp2350_geek`         — Waveshare RP2350-Geek (16MB, SDCard): SPI LCD + SDCard pins
//! - `pico2`               — Stock Raspberry Pi Pico 2 (RP2350A, 4MB): GPIO25 LED
//! - `waveshare_rp2350_lcd`— Waveshare RP2350-LCD-1.47-B (16MB, SD card, LCD, RGB LED)
//!
//! # Feature flags
//! - `rp2350_one_4m`             → RP2350-One with 4 MB flash
//! - `rp2350_one_16m`            → RP2350-One with 16 MB flash
//! - `rp2350_geek_16m`           → RP2350-Geek with 16 MB flash, no SDCard
//! - `rp2350_geek_sdcard`        → RP2350-Geek with SDCard slot
//! - `pico2_4m`                  → Stock Pico 2 with 4 MB flash, GPIO25 LED
//! - `waveshare_rp2350_lcd_16m`  → Waveshare RP2350-LCD-1.47-B with 16 MB external flash
//! - `waveshare_rp2350_lcd_sdcard` → Waveshare RP2350-LCD-1.47-B with SD card storage

pub mod pico2;
pub mod rp2350_geek;
pub mod rp2350_one;
pub mod waveshare_rp2350_lcd;

/// LED status codes understood by all board variants.
///
/// Each variant maps to a specific colour and blink pattern on the
/// physical LED (WS2812B on RP2350-One; ST7789 status bar on RP2350-Geek).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedStatus {
    /// LED off — device not initialised or powered down.
    Off,
    /// Solid green / slow 1 Hz pulse — HSM idle, ready for USB commands.
    Ready,
    /// Fast 10 Hz blink — a command is being processed.
    Busy,
    /// Red / fast triple blink — an unrecoverable error occurred.
    Error,
    /// Yellow / double blink — storage RAID is degraded (one chip missing).
    Degraded,
    /// Cyan pulse — RAID resync in progress.
    Resyncing,
    /// Blue pulse — waiting for PIN entry from host.
    WaitingForPin,
}

/// Colour type kept for backward-compat with existing call-sites in stubs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedColor {
    Off,
    Red,
    Green,
    Blue,
    White,
}

/// Convert a `LedColor` (legacy) to a `LedStatus`.
impl From<LedColor> for LedStatus {
    fn from(c: LedColor) -> Self {
        match c {
            LedColor::Off => LedStatus::Off,
            LedColor::Green => LedStatus::Ready,
            LedColor::Blue => LedStatus::WaitingForPin,
            LedColor::Red => LedStatus::Error,
            LedColor::White => LedStatus::Busy,
        }
    }
}

/// Trait implemented by every board LED driver.
///
/// The implementation may be sync (WS2812B PIO) or block until the
/// LED update is complete; callers are expected to be inside an async
/// task context.
pub trait LedController {
    /// Update the LED to reflect the given system status.
    fn set_status(&mut self, status: LedStatus);
}

/// Core board trait — every supported board variant must implement this.
///
/// All associated types must satisfy their respective embedded-hal 1.x
/// traits so that upper layers (storage, crypto) can use them generically.
pub trait Board {
    /// The board's LED / status indicator driver.
    type Led: LedController;

    /// SPI bus 0 — used for keystore flash chips (up to 4 × CS).
    ///
    /// Must implement `embedded_hal::spi::SpiBus` (blocking, 8-bit).
    type Spi0: embedded_hal::spi::SpiBus;

    /// SPI bus 1 — used for RAID-1 mirror flash chips (up to 4 × CS).
    ///
    /// Must implement `embedded_hal::spi::SpiBus` (blocking, 8-bit).
    type Spi1: embedded_hal::spi::SpiBus;

    /// Borrow the LED controller mutably.
    fn led(&mut self) -> &mut Self::Led;

    /// Borrow SPI bus 0 mutably.
    fn spi0(&mut self) -> &mut Self::Spi0;

    /// Borrow SPI bus 1 mutably.
    fn spi1(&mut self) -> &mut Self::Spi1;

    /// GPIO pin numbers used as software chip-selects on SPI0.
    ///
    /// Returns a slice of up to 4 pin numbers (BCM/RP2350 GPIO numbering).
    /// The storage layer drives these as `Output` pins around each SPI transfer.
    fn spi0_cs_pins(&self) -> &[u8];

    /// GPIO pin numbers used as software chip-selects on SPI1.
    fn spi1_cs_pins(&self) -> &[u8];
}
