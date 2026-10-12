//! Waveshare RP2350-Geek board support.
//!
//! Board variants covered by this module:
//! - RP2350-Geek 16MB               (`rp2350_geek_16m` feature)
//! - RP2350-Geek with SDCard        (`rp2350_geek_sdcard` feature)
//!
//! # Hardware specifics
//! - MCU: RP2350A @ 150 MHz
//! - External flash: 16 MB on QSPI
//! - Status display: 1.14" SPI ST7789 LCD on SPI1 (135×240 px, landscape 240×135)
//!   ST7789 is a write-only display: data flows MOSI only, MISO unused.
//!   Display uses COLMOD=0x33 (12-bit RGB444) with colour inversion (INVON).
//! - SPI1 LCD pins: SCK=GPIO10, MOSI=GPIO11
//!   DC=GPIO8, CS=GPIO9, RST=GPIO12, BL=GPIO25
//! - SPI0 pins: SCK=GPIO18, MOSI=GPIO19, MISO=GPIO20 (SD card)
//! - SDCard slot CS: GPIO23
//!
//! # ST7789 LCD pin assignments
//! Confirmed from:
//! - MicroPython nano-gui setup (scripsi/rp2350-geek-mpy / color_setup.py)
//! - mipidsi Rust example (melastmohican/rp2350-geek-rust-examples / examples/mipidsi.rs)
//!
//! | Signal | GPIO | Note                          |
//! |--------|------|-------------------------------|
//! | DC     |   8  | Data/Command select            |
//! | CS     |   9  | Chip select (active-low)       |
//! | SCK    |  10  | SPI1 clock                     |
//! | MOSI   |  11  | SPI1 data out                  |
//! | RST    |  12  | Hardware reset (active-low)    |
//! | BL     |  25  | Backlight enable (active-high) |
//!
//! # ST7789 init sequence (async, `embassy_time` delays)
//! RST pulse → SWRESET (150 ms) → SLPOUT (255 ms) → COLMOD 0x33 (RGB444) →
//! MADCTL 0x70 → clear 320×240 GRAM → INVON → NORON → DISPON → backlight.
//!
//! MADCTL 0x70 = MX (0x40) | MV (0x20) | ML (0x10): landscape with row/column
//! exchange and column mirror.  Bit 3 (RGB/BGR order) is **clear**, so this
//! is RGB order — earlier comments calling 0x70 "BGR" were wrong.
//!
//! ## Window offsets (unverified, design spec B13)
//! The visible window is CASET 52..291 × RASET 40..174.  Those are the
//! *portrait* offsets of the 135×240 panel (52 = (240−135)/2, 40 = (320−240)/2);
//! with MV=1 the landscape offsets would be expected at CASET 40..279 ×
//! RASET 53..187, so the image may sit about 12 px off.  They are left
//! unchanged until checked on a Geek: debug builds draw a 1 px border at the
//! panel edge on the boot splash, and all four edges must be visible.
//!
//! # SPI frequency
//! SPI1 (LCD) requests 40 MHz, which the RP2350 divider makes 37.5 MHz
//! (150 MHz / 4; the old 30 MHz request gave 25 MHz).  Never request more:
//! the next step, 75 MHz, is out of spec for the ST7789.

// Always import shared types — St7789StatusDisplay implements LedController unconditionally.
use super::{LedController, LedStatus};
// Board is only needed inside the feature-gated impl block.
#[cfg(any(feature = "rp2350_geek_16m", feature = "rp2350_geek_sdcard",))]
use super::Board;

// ─── GPIO pin assignments ─────────────────────────────────────────────────────

/// LCD Data/Command select pin.
pub const LCD_DC_PIN: u8 = 8;
/// LCD SPI chip-select pin (active-low).
pub const LCD_CS_PIN: u8 = 9;
/// LCD SPI clock (SPI1 SCK).
pub const LCD_SCK_PIN: u8 = 10;
/// LCD SPI data out (SPI1 MOSI).
pub const LCD_MOSI_PIN: u8 = 11;
/// LCD hardware reset pin (active-low).
pub const LCD_RST_PIN: u8 = 12;
/// LCD backlight enable pin (active-high).
pub const LCD_BL_PIN: u8 = 25;

/// SPI0 SCK pin (SD card interface).
pub const SPI0_SCK: u8 = 18;
/// SPI0 MOSI pin (SD card interface).
pub const SPI0_MOSI: u8 = 19;
/// SPI0 MISO pin (SD card interface).
pub const SPI0_MISO: u8 = 20;

/// SPI1 SCK pin (shared with LCD SCK).
pub const SPI1_SCK: u8 = LCD_SCK_PIN;
/// SPI1 MOSI pin (shared with LCD MOSI).
pub const SPI1_MOSI: u8 = LCD_MOSI_PIN;

/// SD card chip-select pin (active-low, directly driven via GPIO).
/// On the RP2350-Geek schematic this is SD_CS / SDIO_D3 = GPIO23.
pub const SDCARD0_CS: u8 = 23;

/// SPI0 frequency for SD card data transfers (after identification at
/// 400 kHz).
pub const SD_SPI_FREQ_HZ: u32 = 25_000_000;
/// SPI1 / LCD frequency requested: 37.5 MHz actual (see the module docs).
pub const LCD_SPI_FREQ_HZ: u32 = 40_000_000;

// ─── ST7789 register constants ────────────────────────────────────────────────

const ST7789_SWRESET: u8 = 0x01;
const ST7789_SLPIN: u8 = 0x10;
const ST7789_SLPOUT: u8 = 0x11;
const ST7789_NORON: u8 = 0x13;
const ST7789_INVON: u8 = 0x21;
const ST7789_DISPOFF: u8 = 0x28;
const ST7789_DISPON: u8 = 0x29;
const ST7789_CASET: u8 = 0x2A;
const ST7789_RASET: u8 = 0x2B;
const ST7789_RAMWR: u8 = 0x2C;
const ST7789_MADCTL: u8 = 0x36;
const ST7789_COLMOD: u8 = 0x3A;

/// MADCTL: MX | MV | ML, RGB order (see the module docs).
const MADCTL_LANDSCAPE: u8 = 0x70;

/// Visible panel size (landscape).
pub const LCD_WIDTH: u16 = 240;
/// See [`LCD_WIDTH`].
pub const LCD_HEIGHT: u16 = 135;
/// Column offset of the visible window (unverified, see the module docs).
const LCD_COL_OFFSET: u16 = 52;
/// Row offset of the visible window (unverified, see the module docs).
const LCD_ROW_OFFSET: u16 = 40;

// ─── LCD driver ───────────────────────────────────────────────────────────────

/// ST7789 driver for the RP2350-Geek's 240×135 LCD; the display task's
/// [`crate::display::Panel`].
///
/// # GPIO ownership
/// Owns SPI1 and the four LCD control GPIOs (DC=GPIO8, CS=GPIO9, RST=GPIO12,
/// BL=GPIO25), obtained with `AnyPin::steal()` in `new()`.  This is sound
/// because `run_geek_board()` uses those pins for nothing else and the steal
/// happens once.
#[cfg(target_arch = "arm")]
pub struct St7789StatusDisplay {
    /// SPI1 bus — the LCD (TX-only, CS is a separate GPIO).
    spi: Rp2350GeekSpi1,
    dc: embassy_rp::gpio::Output<'static>,
    cs: embassy_rp::gpio::Output<'static>,
    rst: embassy_rp::gpio::Output<'static>,
    bl: embassy_rp::gpio::Output<'static>,
    current_status: LedStatus,
}

/// Stub version for non-ARM (unit-test) builds.
#[cfg(not(target_arch = "arm"))]
pub struct St7789StatusDisplay {
    current_status: LedStatus,
}

#[cfg(target_arch = "arm")]
impl St7789StatusDisplay {
    /// Take SPI1 and steal the four LCD pins.  No bus traffic: call
    /// [`Self::init`] next.
    fn new(spi: Rp2350GeekSpi1) -> Self {
        use embassy_rp::gpio::{AnyPin, Level, Output};
        // Safety: these four GPIOs are exclusively wired to the ST7789 LCD on
        // the RP2350-Geek and are not claimed anywhere else in the firmware.
        let dc = Output::new(unsafe { AnyPin::steal(LCD_DC_PIN) }, Level::Low);
        let cs = Output::new(unsafe { AnyPin::steal(LCD_CS_PIN) }, Level::High);
        let rst = Output::new(unsafe { AnyPin::steal(LCD_RST_PIN) }, Level::High);
        let bl = Output::new(unsafe { AnyPin::steal(LCD_BL_PIN) }, Level::Low);
        Self {
            spi,
            dc,
            cs,
            rst,
            bl,
            current_status: LedStatus::Off,
        }
    }

    fn cmd(&mut self, cmd: u8, data: &[u8]) {
        self.cs.set_low();
        self.dc.set_low();
        let _ = self.spi.blocking_write(&[cmd]);
        if !data.is_empty() {
            self.dc.set_high();
            let _ = self.spi.blocking_write(data);
        }
        self.cs.set_high();
    }

    fn window(&mut self, x0: u16, y0: u16, x1: u16, y1: u16) {
        let [a, b] = x0.to_be_bytes();
        let [c, d] = x1.to_be_bytes();
        self.cmd(ST7789_CASET, &[a, b, c, d]);
        let [a, b] = y0.to_be_bytes();
        let [c, d] = y1.to_be_bytes();
        self.cmd(ST7789_RASET, &[a, b, c, d]);
    }

    /// Stream `total` bytes of `chunk` (repeated) after RAMWR, by DMA.
    async fn stream(&mut self, chunk: &[u8], total: usize) {
        self.cs.set_low();
        self.dc.set_low();
        let _ = self.spi.blocking_write(&[ST7789_RAMWR]);
        self.dc.set_high();
        let mut left = total;
        while left > 0 {
            let n = left.min(chunk.len());
            let _ = self.spi.write(&chunk[..n]).await;
            left -= n;
        }
        self.cs.set_high();
    }

    /// Reset and initialise the controller (async: about 0.6 s of delays
    /// that no longer block the executor or the watchdog feeder).  The
    /// panel ends up black with the backlight on.  `scratch` (the band
    /// buffer) feeds the GRAM clear.
    pub async fn init(&mut self, scratch: &mut [u8]) {
        use embassy_time::Timer;
        self.rst.set_low();
        Timer::after_millis(10).await;
        self.rst.set_high();
        Timer::after_millis(150).await;
        self.cmd(ST7789_SWRESET, &[]);
        Timer::after_millis(150).await;
        self.cmd(ST7789_SLPOUT, &[]);
        Timer::after_millis(255).await;
        self.cmd(ST7789_COLMOD, &[0x33]);
        self.cmd(ST7789_MADCTL, &[MADCTL_LANDSCAPE]);
        // Clear all 320 × 240 of GRAM: the area outside the visible window
        // maps to the panel border and shows garbage until cleared.
        scratch.fill(0);
        self.window(0, 0, 319, 239);
        self.stream(scratch, 320 * 240 * 3 / 2).await;
        self.cmd(ST7789_INVON, &[]);
        self.cmd(ST7789_NORON, &[]);
        self.cmd(ST7789_DISPON, &[]);
        Timer::after_millis(10).await;
        self.bl.set_high();
    }
}

#[cfg(target_arch = "arm")]
impl crate::display::Panel for St7789StatusDisplay {
    async fn write_rows(&mut self, y0: u16, rows: u16, data: &[u8]) {
        let top = LCD_ROW_OFFSET + y0;
        self.window(
            LCD_COL_OFFSET,
            top,
            LCD_COL_OFFSET + LCD_WIDTH - 1,
            top + rows - 1,
        );
        self.stream(data, data.len()).await;
    }

    async fn sleep(&mut self) {
        self.bl.set_low();
        self.cmd(ST7789_DISPOFF, &[]);
        self.cmd(ST7789_SLPIN, &[]);
        embassy_time::Timer::after_millis(5).await;
    }

    async fn wake(&mut self) {
        self.cmd(ST7789_SLPOUT, &[]);
        embassy_time::Timer::after_millis(120).await;
        self.cmd(ST7789_DISPON, &[]);
        self.bl.set_high();
    }
}

/// The display is drawn by the display task; `set_status` only records
/// (it used to fill the whole screen with a solid colour).
impl LedController for St7789StatusDisplay {
    fn set_status(&mut self, status: LedStatus) {
        self.current_status = status;
    }
}

#[cfg(not(target_arch = "arm"))]
impl St7789StatusDisplay {
    fn new_stub() -> Self {
        Self {
            current_status: LedStatus::Off,
        }
    }
}

// ─── SPI bus type aliases ─────────────────────────────────────────────────────

/// Blocking SPI0 type for the RP2350-Geek (SD card bus in sdcard variant, unused in 16m).
pub type Rp2350GeekSpi0 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Blocking>;

/// Async SPI1 type for the RP2350-Geek (LCD bus): band transfers use DMA
/// and yield to the executor; small command writes use `blocking_write()`.
pub type Rp2350GeekSpi1 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Async>;

// ─── Board struct ─────────────────────────────────────────────────────────────

/// Concrete board representation for the Waveshare RP2350-Geek.
pub struct Rp2350GeekBoard {
    display: St7789StatusDisplay,
}

#[cfg(target_arch = "arm")]
impl Rp2350GeekBoard {
    /// Create the board with only the LCD on SPI1 (no bus traffic yet).
    pub fn new(spi1: Rp2350GeekSpi1) -> Self {
        let display = St7789StatusDisplay::new(spi1);
        Self { display }
    }

    /// Hand the LCD to the display task.
    pub fn into_display(self) -> St7789StatusDisplay {
        self.display
    }
}

#[cfg(not(target_arch = "arm"))]
impl Rp2350GeekBoard {
    #[allow(dead_code)]
    fn _new_stub() -> Self {
        Self {
            display: St7789StatusDisplay::new_stub(),
        }
    }
}

#[cfg(any(feature = "rp2350_geek_16m", feature = "rp2350_geek_sdcard",))]
impl Board for Rp2350GeekBoard {
    type Led = St7789StatusDisplay;
    type Spi0 = Rp2350GeekSpi0;
    type Spi1 = Rp2350GeekSpi1;

    fn led(&mut self) -> &mut Self::Led {
        &mut self.display
    }

    fn spi0(&mut self) -> &mut Self::Spi0 {
        unimplemented!("SPI0 not in board struct — consumed by SD card or unused")
    }

    fn spi1(&mut self) -> &mut Self::Spi1 {
        #[cfg(target_arch = "arm")]
        return &mut self.display.spi;
        #[cfg(not(target_arch = "arm"))]
        unimplemented!("spi1 not available on non-ARM test build")
    }

    fn spi0_cs_pins(&self) -> &[u8] {
        &[]
    }
    fn spi1_cs_pins(&self) -> &[u8] {
        &[]
    }
}
