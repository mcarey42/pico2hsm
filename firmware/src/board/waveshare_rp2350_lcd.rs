//! Waveshare RP2350-LCD-1.47-B board support.
//!
//! Board variant covered by this module:
//! - RP2350-LCD-1.47-B 16MB  (`waveshare_rp2350_lcd_16m` feature)
//!
//! # Hardware specifics
//! - MCU: RP2350A
//! - External flash: Winbond W25Q128JVSIQ 16MB on QSPI
//! - Display: 1.47" ST7789V3 172×320 LCD on SPI0 (write-only, no MISO needed)
//! - MicroSD slot on SPI1
//! - RGB LED: single WS2812B on GPIO22
//!
//! # Pin assignments
//! Confirmed from the official Waveshare example code distributed in
//! `RP2350-LCD-1.47.zip` (waveshare.net, 2025):
//!   - LCD: `C/01-LCD/lib/Config/DEV_Config.h` and
//!           `Arduino/RP2350-LCD-1.47/DEV_Config.h`
//!   - SD card: `MicroPython/02-SD/boot.py` (machine.SPI id=1 on GPIO10/11/12/15)
//!   - Schematic: `RP2350-LCD-1.47-A.pdf` (waveshare.net)
//!
//! ## LCD (ST7789V3, SPI0)
//! | Signal    | GPIO | Note                      |
//! |-----------|------|---------------------------|
//! | DC        |  16  | Data/Command select        |
//! | CS        |  17  | Chip select                |
//! | SCK       |  18  | SPI0 clock                 |
//! | MOSI/DIN  |  19  | SPI0 MOSI                  |
//! | RST       |  20  | Hardware reset (active-low)|
//! | BL        |  21  | Backlight PWM              |
//!
//! ## SD card (microSD slot, SPI1)
//! | Signal | GPIO | Note                            |
//! |--------|------|---------------------------------|
//! | SCK    |  10  | SPI1 clock                      |
//! | MOSI   |  11  | SPI1 MOSI                       |
//! | MISO   |  12  | SPI1 MISO                       |
//! | CS     |  15  | Chip select                     |
//!
//! ## RGB LED
//! | Signal  | GPIO | Note               |
//! |---------|------|--------------------|
//! | WS2812B |  22  | Single-pixel chain |
//!
//! # ST7789V3 LCD
//! The ST7789V3 initialisation sequence is a sequence of SPI commands.
//! Full implementation is left as a TODO — the `init_lcd()` stub below logs
//! a defmt message so the rest of the firmware can compile and boot.
//!
//! TODO (display agent): implement ST7789V3 init sequence and status screen
//! rendering.  `embedded-graphics` is the suggested drawing API.
//!
//! # SD card
//! `embedded-sdmmc` is already a dependency.  The `init_sdcard()` stub below
//! logs the pin assignments.  Wire it up once a `VolumeManager` is needed.
//!
//! TODO (sdcard agent): wire `embedded_sdmmc::SdCard` onto `board.spi1` and
//! expose a `VolumeManager` for FAT32 key backup / restore.
//!
//! # SPI frequency
//! Both buses are configured at 40 MHz.

// Always import shared types — St7789V3StatusDisplay implements LedController unconditionally.
use super::{LedController, LedStatus};
// Board trait is only needed inside the feature-gated impl block.
#[cfg(feature = "waveshare_rp2350_lcd_16m")]
use super::Board;

// ─── GPIO pin assignments — LCD (SPI0) ────────────────────────────────────────

/// LCD Data/Command select pin.
pub const LCD_DC_PIN: u8 = 16;
/// LCD SPI chip-select pin.
pub const LCD_CS_PIN: u8 = 17;
/// LCD SPI clock (SPI0 SCK).
pub const LCD_SCK_PIN: u8 = 18;
/// LCD SPI data out (SPI0 MOSI/TX).
pub const LCD_MOSI_PIN: u8 = 19;
/// LCD hardware reset pin (active-low).
pub const LCD_RST_PIN: u8 = 20;
/// LCD backlight control pin (active-high / PWM).
pub const LCD_BL_PIN: u8 = 21;

// ─── GPIO pin assignments — SD card (SPI1) ───────────────────────────────────

/// SD card SPI clock (SPI1 SCK).
pub const SDCARD_SCK_PIN: u8 = 10;
/// SD card SPI MOSI (SPI1 TX).
pub const SDCARD_MOSI_PIN: u8 = 11;
/// SD card SPI MISO (SPI1 RX).
pub const SDCARD_MISO_PIN: u8 = 12;
/// SD card chip-select pin.
pub const SDCARD_CS_PIN: u8 = 15;

// ─── GPIO pin assignments — RGB LED ──────────────────────────────────────────

/// WS2812B RGB LED data pin.
pub const RGB_LED_PIN: u8 = 22;

// ─── Board-trait-facing SPI pin constants ────────────────────────────────────

/// SPI0 pins drive the LCD (write-only display).
pub const SPI0_SCK: u8 = LCD_SCK_PIN;
pub const SPI0_MOSI: u8 = LCD_MOSI_PIN;
/// SPI0 MISO: GPIO4 is in the hardware netlist (Arduino DEV_Config.h `LCD_MISO_PIN = 4`)
/// but the ST7789V3 is a write-only display and never drives the pin.  The
/// SPI peripheral needs a valid MISO pin configured even for TX-only use.
pub const SPI0_MISO: u8 = 4;
/// SPI0 chip-select list — only the LCD CS.
pub const SPI0_CS: [u8; 1] = [LCD_CS_PIN];

/// SPI1 pins drive the SD card.
pub const SPI1_SCK: u8 = SDCARD_SCK_PIN;
pub const SPI1_MOSI: u8 = SDCARD_MOSI_PIN;
pub const SPI1_MISO: u8 = SDCARD_MISO_PIN;
/// SPI1 chip-select list — only the SD card CS.
pub const SPI1_CS: [u8; 1] = [SDCARD_CS_PIN];

/// SPI bus frequency (40 MHz — matches Waveshare C example at 30 MHz for LCD,
/// raised to 40 MHz to match other boards in this project).
pub const SPI_FREQ_HZ: u32 = 40_000_000;

// ─── LED / display driver ─────────────────────────────────────────────────────

/// Minimal ST7789V3 status display driver.
///
/// The RP2350-LCD-1.47-B has a 1.47" LCD and a WS2812B RGB LED.  Both are
/// stub-implemented here; defmt logging is used until the full drivers are
/// written.
///
/// TODO (display agent):
/// - Store the SPI0 + DC + RST + BL pin handles.
/// - Store PIO handle for the WS2812B on GPIO22.
/// - Implement `st7789_init_sequence()` — hardware reset + init commands.
/// - Implement `draw_status_screen()` using `embedded-graphics`.
/// - Implement `ws2812_set(r, g, b)` — single-pixel WS2812B update via PIO.
pub struct St7789V3StatusDisplay {
    current_status: LedStatus,
}

impl St7789V3StatusDisplay {
    fn new() -> Self {
        defmt::info!(
            "RP2350-LCD-1.47-B: ST7789V3 + WS2812B driver stub — full implementation pending"
        );
        Self { current_status: LedStatus::Off }
    }
}

impl LedController for St7789V3StatusDisplay {
    fn set_status(&mut self, status: LedStatus) {
        if self.current_status != status {
            self.current_status = status;
            // TODO (display agent): update WS2812B colour + render LCD status screen.
            defmt::info!("LCD status: {:?}", defmt::Debug2Format(&status));
        }
    }
}

// ─── SPI bus type aliases ─────────────────────────────────────────────────────

/// Blocking SPI0 type for the Waveshare RP2350-LCD-1.47-B (LCD bus).
/// `'static` lifetime: peripherals come from `embassy_rp::init()`.
pub type WaveshareRp2350LcdSpi0 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Blocking>;

/// Blocking SPI1 type for the Waveshare RP2350-LCD-1.47-B (SD card bus).
pub type WaveshareRp2350LcdSpi1 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>;

// ─── Board struct ─────────────────────────────────────────────────────────────

/// Concrete board representation for the Waveshare RP2350-LCD-1.47-B.
pub struct WaveshareRp2350LcdBoard {
    display: St7789V3StatusDisplay,
    pub spi0: WaveshareRp2350LcdSpi0,
    pub spi1: WaveshareRp2350LcdSpi1,
}

impl WaveshareRp2350LcdBoard {
    /// Create a board from pre-constructed SPI buses.
    pub fn new(spi0: WaveshareRp2350LcdSpi0, spi1: WaveshareRp2350LcdSpi1) -> Self {
        defmt::info!(
            "RP2350-LCD-1.47-B: board created (SPI0 LCD @ {} Hz, SPI1 SD @ {} Hz)",
            SPI_FREQ_HZ,
            SPI_FREQ_HZ,
        );
        Self {
            display: St7789V3StatusDisplay::new(),
            spi0,
            spi1,
        }
    }
}

#[cfg(feature = "waveshare_rp2350_lcd_16m")]
impl Board for WaveshareRp2350LcdBoard {
    type Led = St7789V3StatusDisplay;
    type Spi0 = WaveshareRp2350LcdSpi0;
    type Spi1 = WaveshareRp2350LcdSpi1;

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
    /// Storage health indicator (`true` = flash available).
    pub storage_ok: bool,
}

// ─── Stub free functions ──────────────────────────────────────────────────────

/// Initialise the ST7789V3 LCD controller over SPI0.
///
/// Sends the hardware reset and init command sequence, then sets the display
/// to show the HSM idle state screen.
///
/// TODO (display agent): implement the full ST7789V3 init sequence.
pub async fn init_lcd() {
    defmt::warn!("init_lcd(): ST7789V3 initialisation not yet implemented");
}

/// Update the LCD status display with the current HSM state.
///
/// TODO (display agent): render using embedded-graphics on the ST7789V3.
pub async fn update_status_display(_state: DisplayState) {
    defmt::trace!("update_status_display(): rendering not yet implemented");
}

/// Initialise the microSD card over SPI1.
///
/// Pin assignments (from official Waveshare MicroPython 02-SD example):
///   SCK=GPIO{SDCARD_SCK_PIN}, MOSI=GPIO{SDCARD_MOSI_PIN},
///   MISO=GPIO{SDCARD_MISO_PIN}, CS=GPIO{SDCARD_CS_PIN}.
///
/// TODO (sdcard agent): wire `embedded_sdmmc::SdCard` onto `board.spi1` and
/// expose a `VolumeManager` for FAT32 key backup / restore.
pub async fn init_sdcard() {
    defmt::warn!(
        "init_sdcard(): SD card initialisation not yet implemented \
         (SPI1 SCK=GPIO{} MOSI=GPIO{} MISO=GPIO{} CS=GPIO{})",
        SDCARD_SCK_PIN,
        SDCARD_MOSI_PIN,
        SDCARD_MISO_PIN,
        SDCARD_CS_PIN,
    );
}
