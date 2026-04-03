//! Waveshare RP2350-Geek board support.
//!
//! Board variants covered by this module:
//! - RP2350-Geek 16MB               (`rp2350_geek_16m` feature)
//! - RP2350-Geek with SDCard        (`rp2350_geek_sdcard` feature)
//! - RP2350-Geek with dual SDCard   (`rp2350_geek_sdcard_dual` feature)
//!
//! # Hardware specifics
//! - Status display: 1.14" SPI ST7789 LCD on SPI0 (320×240 px)
//!   ST7789 is a write-only display: data flows MOSI only, MISO unused.
//! - SPI0 pins same as RP2350-One: SCK=GPIO18, MOSI=GPIO19, MISO=GPIO20
//!   CS[0..3] = GPIO17, GPIO21, GPIO22, GPIO26
//! - SPI1 pins same as RP2350-One: SCK=GPIO10, MOSI=GPIO11, MISO=GPIO12
//!   CS[0..3] = GPIO9, GPIO13, GPIO14, GPIO15
//! - SDCard slot CS: GPIO5 (first card)
//! - Second SDCard CS: GPIO4 (dual-SDCard variant only, `rp2350_geek_sdcard_dual`)
//!
//! # ST7789 LCD
//! The ST7789 initialisation sequence is a sequence of SPI commands with
//! a dedicated Data/Command (D/C) pin.  Full implementation is left as a
//! TODO — the `init_lcd()` stub below logs a defmt message so the rest of
//! the firmware can compile and boot.
//!
//! TODO (display agent): implement ST7789 init sequence and status screen
//! rendering.  The `embedded-graphics` crate is the suggested drawing API.
//!
//! # SPI frequency
//! Both buses are configured at 40 MHz.

// Always import shared types — St7789StatusDisplay implements LedController unconditionally.
use super::{LedController, LedStatus};
// Board is only needed inside the feature-gated impl block.
#[cfg(any(
    feature = "rp2350_geek_16m",
    feature = "rp2350_geek_sdcard",
    feature = "rp2350_geek_sdcard_dual",
))]
use super::Board;

// ─── GPIO pin assignments ─────────────────────────────────────────────────────

/// SPI0 SCK pin (shared with LCD SCK and keystore flash).
pub const SPI0_SCK: u8 = 18;
/// SPI0 MOSI pin.
pub const SPI0_MOSI: u8 = 19;
/// SPI0 MISO pin.
pub const SPI0_MISO: u8 = 20;
/// SPI0 software CS pins — same as RP2350-One.
pub const SPI0_CS: [u8; 4] = [17, 21, 22, 26];

/// SPI1 SCK pin.
pub const SPI1_SCK: u8 = 10;
/// SPI1 MOSI pin.
pub const SPI1_MOSI: u8 = 11;
/// SPI1 MISO pin.
pub const SPI1_MISO: u8 = 12;
/// SPI1 software CS pins — same as RP2350-One.
pub const SPI1_CS: [u8; 4] = [9, 13, 14, 15];

/// SD-Card slot 0 chip-select pin.
pub const SDCARD0_CS: u8 = 5;

/// SD-Card slot 1 chip-select pin (dual-SDCard variant only).
#[cfg(feature = "rp2350_geek_sdcard_dual")]
pub const SDCARD1_CS: u8 = 4;

/// SPI bus frequency (40 MHz).
pub const SPI_FREQ_HZ: u32 = 40_000_000;

// ─── LED / display driver ─────────────────────────────────────────────────────

/// Minimal ST7789 status display driver.
///
/// The RP2350-Geek does not have a discrete LED; status is shown on
/// the built-in 1.14" LCD.  This stub logs to defmt until the full
/// display driver is implemented.
///
/// TODO (display agent):
/// - Store the SPI + D/C + RST pin handles.
/// - Implement `st7789_init_sequence()` — hardware reset + init commands.
/// - Implement `draw_status_screen()` using `embedded-graphics`.
pub struct St7789StatusDisplay {
    current_status: LedStatus,
}

impl St7789StatusDisplay {
    fn new() -> Self {
        defmt::info!("ST7789 LCD: driver stub — full implementation pending");
        Self {
            current_status: LedStatus::Off,
        }
    }
}

impl LedController for St7789StatusDisplay {
    fn set_status(&mut self, status: LedStatus) {
        if self.current_status != status {
            self.current_status = status;
            // TODO: render actual status screen on ST7789.
            defmt::info!("LCD status: {:?}", defmt::Debug2Format(&status));
        }
    }
}

// ─── SPI bus type aliases ─────────────────────────────────────────────────────

/// Blocking SPI0 type for the RP2350-Geek.
/// `'static` lifetime: peripherals come from `embassy_rp::init()` which
/// returns `Peri<'static, ...>` tokens.
pub type Rp2350GeekSpi0 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Blocking>;
pub type Rp2350GeekSpi1 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>;

// ─── Board struct ─────────────────────────────────────────────────────────────

/// Concrete board representation for the Waveshare RP2350-Geek.
pub struct Rp2350GeekBoard {
    display: St7789StatusDisplay,
    pub spi0: Rp2350GeekSpi0,
    pub spi1: Rp2350GeekSpi1,
}

impl Rp2350GeekBoard {
    /// Create a board from pre-constructed SPI buses.
    pub fn new(spi0: Rp2350GeekSpi0, spi1: Rp2350GeekSpi1) -> Self {
        defmt::info!("RP2350-Geek: board created (SPI0 + SPI1 @ {} Hz)", SPI_FREQ_HZ);
        Self { display: St7789StatusDisplay::new(), spi0, spi1 }
    }
}

#[cfg(any(
    feature = "rp2350_geek_16m",
    feature = "rp2350_geek_sdcard",
    feature = "rp2350_geek_sdcard_dual",
))]
impl Board for Rp2350GeekBoard {
    type Led = St7789StatusDisplay;
    type Spi0 = Rp2350GeekSpi0;
    type Spi1 = Rp2350GeekSpi1;

    fn led(&mut self) -> &mut Self::Led {
        &mut self.display
    }

    fn spi0(&mut self) -> &mut Self::Spi0 {
        &mut self.spi0
    }

    fn spi1(&mut self) -> &mut Self::Spi1 {
        &mut self.spi1
    }

    fn spi0_cs_pins(&self) -> &[u8] {
        &SPI0_CS
    }

    fn spi1_cs_pins(&self) -> &[u8] {
        &SPI1_CS
    }
}

// ─── Summary of HSM state for the LCD status display ─────────────────────────

/// Summary of HSM state rendered on the LCD status screen.
#[derive(Debug, Clone, Copy)]
pub struct DisplayState {
    /// Number of stored key objects.
    pub key_count: u8,
    /// Whether a PIN session is active.
    pub authenticated: bool,
    /// RAID health indicator (`true` = both mirrors healthy).
    pub storage_ok: bool,
}

// ─── Legacy free functions (kept for source compat with old stubs) ─────────────

/// Initialise the ST7789 LCD controller over SPI.
///
/// Sends the hardware reset and init command sequence, then sets the display
/// to show the HSM idle state screen.
///
/// TODO (display agent): implement the full ST7789 init sequence.
pub async fn init_lcd() {
    defmt::warn!("init_lcd(): ST7789 initialisation not yet implemented");
}

/// Update the LCD status display.
///
/// Shows current HSM state (idle/active/error), key count, and RAID health.
///
/// TODO (display agent): render this using embedded-graphics on the ST7789.
pub async fn update_status_display(_state: DisplayState) {
    defmt::trace!("update_status_display(): rendering not yet implemented");
}
