//! Waveshare RP2350-LCD-1.47-B board support.
//!
//! Board variants covered by this module:
//! - RP2350-LCD-1.47-B 16MB  (`waveshare_rp2350_lcd_16m` feature)
//! - RP2350-LCD-1.47-B with the SD card keystore (`waveshare_rp2350_lcd_sdcard`)
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
//! | BL        |  21  | Backlight                  |
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
//!
//! ## Init sequence (from Waveshare C reference: `LCD_1in47.c`)
//! ```text
//! RST pulse, SWRESET (150 ms), SLPOUT (255 ms)
//! COLMOD   (3Ah)  0x03 = 12-bit RGB444
//! MADCTL   (36h)  0xA0 (MY+MV, landscape 180°-corrected)
//! INVON    (21h)  inversion on  (required for correct colours on V3 panel)
//! NORON    (13h)  normal display mode on
//!                 [clear full 320×240 controller GRAM to black]
//! DISPON   (29h)  display on, then backlight on
//! ```
//! All delays are `embassy_time` awaits: the executor and the watchdog
//! feeder keep running during init.
//!
//! ## Row address offset (landscape)
//! The ST7789V3 controller has 240 GRAM columns.  With MV=1 (landscape), RASET
//! addresses physical GRAM columns — only 172 of the 240 are connected to the
//! panel (columns 34–205).  Logical row `y` is RASET `34 + y`.
//!
//! ## Pixel data
//! RGB444, two pixels in three bytes.  The screen is sent as full-width
//! 16-row bands from a 7 680-byte band buffer (no framebuffer); see
//! `crate::display`.
//!
//! # WS2812B LED
//!
//! The single WS2812B on GPIO22 uses the embassy-rp PIO WS2812 driver with
//! its `Grb` colour order: the driver itself puts green first on the wire,
//! so the `RGB8` handed to it is plain `{ r, g, b }`.  (Earlier firmware
//! swapped R and G before the driver swapped them again, so READY showed
//! red.)  The LED is written only when its colour changes.
//!
//! # SPI frequency
//! Both buses are configured at 40 MHz requested (37.5 MHz actual,
//! clk_peri 150 MHz / 4).

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
/// LCD backlight control pin (active-high).
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
/// SPI1 frequency for SD card data transfers (after identification at
/// 400 kHz).
pub const SDCARD_SPI_FREQ_HZ: u32 = 25_000_000;

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

/// SPI bus frequency requested: 40 MHz, which the RP2350 divider turns into
/// 37.5 MHz (150 MHz / 4).  Never request more (75 MHz is out of spec for
/// the ST7789V3).
pub const SPI_FREQ_HZ: u32 = 40_000_000;

// ─── LCD display dimensions ───────────────────────────────────────────────────

/// LCD width in pixels (landscape, 320).
pub const LCD_WIDTH: u16 = 320;
/// LCD height in pixels (landscape, 172).
pub const LCD_HEIGHT: u16 = 172;

/// ST7789V3 controller GRAM height (240 — becomes the landscape row axis with MV=1).
pub const CTRL_HEIGHT: u16 = 240;

/// Row offset in landscape: the 172-px panel starts at physical GRAM column 34.
pub const LCD_ROW_OFFSET: u16 = 34;

/// MADCTL byte for corrected landscape orientation (MY + MV = 0xA0).
///
/// | Bit | Name | Value | Meaning                                 |
/// |-----|------|-------|-----------------------------------------|
/// |  7  | MY   |  1    | Flips transposed row direction          |
/// |  6  | MX   |  0    | Column address order: normal            |
/// |  5  | MV   |  1    | Row/column exchange → landscape         |
/// |  4  | ML   |  0    | Vertical refresh: top-to-bottom         |
/// |  3  | RGB  |  0    | RGB colour order                        |
/// |  2  | MH   |  0    | Horizontal refresh: left-to-right       |
pub const MADCTL_LANDSCAPE: u8 = 0xA0;

// ─── ST7789V3 command registers ───────────────────────────────────────────────

/// Software reset — forces all registers to default values.
pub const CMD_SWRESET: u8 = 0x01;
/// Sleep in.
pub const CMD_SLPIN: u8 = 0x10;
/// Sleep out — exits sleep mode, enables the display oscillator.
pub const CMD_SLPOUT: u8 = 0x11;
/// Normal display mode on.
pub const CMD_NORON: u8 = 0x13;
/// Display inversion on — required for correct colour rendering on ST7789V3.
pub const CMD_INVON: u8 = 0x21;
/// Display off.
pub const CMD_DISPOFF: u8 = 0x28;
/// Display on.
pub const CMD_DISPON: u8 = 0x29;
/// Column address set — 4-byte parameter: [XS_H, XS_L, XE_H, XE_L].
pub const CMD_CASET: u8 = 0x2A;
/// Row address set — 4-byte parameter: [YS_H, YS_L, YE_H, YE_L].
pub const CMD_RASET: u8 = 0x2B;
/// Memory write — starts pixel data stream after CASET/RASET.
pub const CMD_RAMWR: u8 = 0x2C;
/// Memory data access control — controls scan direction and colour order.
pub const CMD_MADCTL: u8 = 0x36;
/// Interface pixel format — 0x03 = 12-bit/pixel (RGB444).
pub const CMD_COLMOD: u8 = 0x3A;

/// WS2812 brightness per lit channel (normal / screen asleep).  Dim, to
/// stay within the USB 100 mA budget and not dazzle.
pub const LED_LEVEL: u8 = 8;
/// See [`LED_LEVEL`].
pub const LED_LEVEL_DIM: u8 = 2;

// ─── Status holder (Board trait) ──────────────────────────────────────────────

/// Board-trait LED stand-in.  The real display and LED are driven by the
/// display task through [`WavesharePanel`]; `set_status` only records.
pub struct St7789V3StatusDisplay {
    current_status: LedStatus,
}

impl Default for St7789V3StatusDisplay {
    fn default() -> Self {
        Self::new()
    }
}

impl St7789V3StatusDisplay {
    pub fn new() -> Self {
        Self {
            current_status: LedStatus::Off,
        }
    }
}

impl LedController for St7789V3StatusDisplay {
    fn set_status(&mut self, status: LedStatus) {
        self.current_status = status;
    }
}

// ─── SPI bus type aliases ─────────────────────────────────────────────────────

/// SPI0 bus for the LCD — Async mode so band transfers use DMA and yield to
/// the executor.  Small command writes use `blocking_write()`.
pub type WaveshareRp2350LcdSpi0 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Async>;

/// Blocking SPI1 type for the Waveshare RP2350-LCD-1.47-B (SD card bus).
pub type WaveshareRp2350LcdSpi1 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>;

// ─── Board struct ─────────────────────────────────────────────────────────────

/// Concrete board representation for the Waveshare RP2350-LCD-1.47-B.
///
/// When the `waveshare_rp2350_lcd_sdcard` feature is active, SPI1 is consumed
/// by the SD card keystore and is NOT part of the board struct.
pub struct WaveshareRp2350LcdBoard {
    display: St7789V3StatusDisplay,
    pub spi0: WaveshareRp2350LcdSpi0,
    #[cfg(not(feature = "waveshare_rp2350_lcd_sdcard"))]
    pub spi1: WaveshareRp2350LcdSpi1,
}

impl WaveshareRp2350LcdBoard {
    /// Create a board from pre-constructed SPI buses.
    #[cfg(not(feature = "waveshare_rp2350_lcd_sdcard"))]
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

    /// Create an LCD-only board — SPI1 is consumed by the SD card keystore.
    #[cfg(feature = "waveshare_rp2350_lcd_sdcard")]
    pub fn new_lcd_only(spi0: WaveshareRp2350LcdSpi0) -> Self {
        defmt::info!(
            "RP2350-LCD-1.47-B: board created (SPI0 LCD @ {} Hz, SPI1 → SD keystore)",
            SPI_FREQ_HZ,
        );
        Self {
            display: St7789V3StatusDisplay::new(),
            spi0,
        }
    }

    /// Hand the LCD bus to the display panel (the board keeps nothing else
    /// the firmware uses).
    pub fn into_spi0(self) -> WaveshareRp2350LcdSpi0 {
        self.spi0
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

// ─── WS2812B ─────────────────────────────────────────────────────────────────

/// Writes one pixel to the WS2812B chain.
pub trait Ws2812Writer {
    /// Show `[r, g, b]`.
    async fn write_rgb(&mut self, rgb: [u8; 3]);
}

/// Stub `Ws2812Writer` (no LED).
pub struct NullWs2812;

impl Ws2812Writer for NullWs2812 {
    async fn write_rgb(&mut self, _rgb: [u8; 3]) {}
}

/// Embassy-rp PIO WS2812 adapter for a single-pixel chain (N=1).
#[cfg(target_arch = "arm")]
pub struct PioWs2812Writer<'d, P, const S: usize>
where
    P: embassy_rp::pio::Instance,
{
    inner: embassy_rp::pio_programs::ws2812::PioWs2812<
        'd,
        P,
        S,
        1,
        embassy_rp::pio_programs::ws2812::Grb,
    >,
}

#[cfg(target_arch = "arm")]
impl<'d, P, const S: usize> PioWs2812Writer<'d, P, S>
where
    P: embassy_rp::pio::Instance,
{
    /// Wrap a `PioWs2812` single-pixel driver.
    pub fn new(
        inner: embassy_rp::pio_programs::ws2812::PioWs2812<
            'd,
            P,
            S,
            1,
            embassy_rp::pio_programs::ws2812::Grb,
        >,
    ) -> Self {
        Self { inner }
    }
}

#[cfg(target_arch = "arm")]
impl<'d, P, const S: usize> Ws2812Writer for PioWs2812Writer<'d, P, S>
where
    P: embassy_rp::pio::Instance,
{
    async fn write_rgb(&mut self, rgb: [u8; 3]) {
        // `PioWs2812::write()` takes `&[smart_leds::RGB8; N]`, a
        // `#[repr(C)] struct { r, g, b: u8 }` — layout-identical to
        // `[u8; 3]` (smart_leds is only a transitive dependency).  The
        // driver's `Grb` order puts green first on the wire itself, so the
        // channels go in unswapped.
        // SAFETY: RGB8 is `#[repr(C)]` with three `u8` fields r, g, b.
        #[allow(clippy::missing_transmute_annotations)] // target type is the inferred RGB8
        let pixels: [_; 1] = [unsafe { core::mem::transmute::<[u8; 3], _>(rgb) }];
        self.inner.write(&pixels).await;
    }
}

// ─── ST7789V3 panel (display task) ───────────────────────────────────────────

#[cfg(target_arch = "arm")]
use embassy_rp::gpio::Output;

/// The LCD and the LED as one [`crate::display::Panel`], owned by the
/// display task.
#[cfg(target_arch = "arm")]
pub struct WavesharePanel<W: Ws2812Writer> {
    spi: WaveshareRp2350LcdSpi0,
    dc: Output<'static>,
    cs: Output<'static>,
    rst: Output<'static>,
    bl: Output<'static>,
    led: W,
}

#[cfg(target_arch = "arm")]
impl<W: Ws2812Writer> WavesharePanel<W> {
    /// Take the LCD bus, its control pins and the LED.
    pub fn new(
        spi: WaveshareRp2350LcdSpi0,
        dc: Output<'static>,
        cs: Output<'static>,
        rst: Output<'static>,
        bl: Output<'static>,
        led: W,
    ) -> Self {
        WavesharePanel {
            spi,
            dc,
            cs,
            rst,
            bl,
            led,
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
        self.cmd(CMD_CASET, &[a, b, c, d]);
        let [a, b] = y0.to_be_bytes();
        let [c, d] = y1.to_be_bytes();
        self.cmd(CMD_RASET, &[a, b, c, d]);
    }

    /// Stream `total` bytes of `chunk` (repeated) after RAMWR.
    async fn stream(&mut self, chunk: &[u8], total: usize) {
        self.cs.set_low();
        self.dc.set_low();
        let _ = self.spi.blocking_write(&[CMD_RAMWR]);
        self.dc.set_high();
        let mut left = total;
        while left > 0 {
            let n = left.min(chunk.len());
            let _ = self.spi.write(&chunk[..n]).await;
            left -= n;
        }
        self.cs.set_high();
    }

    /// Reset and initialise the controller; the panel ends up black with
    /// the backlight on.  `scratch` (the zeroed band buffer) feeds the GRAM
    /// clear.
    pub async fn init(&mut self, scratch: &mut [u8]) {
        use embassy_time::Timer;
        self.cs.set_high();
        self.bl.set_low();
        self.rst.set_high();
        Timer::after_millis(10).await;
        self.rst.set_low();
        Timer::after_millis(10).await;
        self.rst.set_high();
        Timer::after_millis(120).await;
        self.cmd(CMD_SWRESET, &[]);
        Timer::after_millis(150).await;
        self.cmd(CMD_SLPOUT, &[]);
        Timer::after_millis(255).await;
        self.cmd(CMD_COLMOD, &[0x03]);
        self.cmd(CMD_MADCTL, &[MADCTL_LANDSCAPE]);
        self.cmd(CMD_INVON, &[]);
        self.cmd(CMD_NORON, &[]);
        // Clear all 320 × 240 of GRAM (the off-panel columns too, so no
        // border artefacts), from the band buffer.
        scratch.fill(0);
        self.window(0, 0, LCD_WIDTH - 1, CTRL_HEIGHT - 1);
        self.stream(
            scratch,
            usize::from(LCD_WIDTH) * usize::from(CTRL_HEIGHT) * 3 / 2,
        )
        .await;
        self.cmd(CMD_DISPON, &[]);
        Timer::after_millis(20).await;
        self.bl.set_high();
    }
}

#[cfg(target_arch = "arm")]
impl<W: Ws2812Writer> crate::display::Panel for WavesharePanel<W> {
    async fn write_rows(&mut self, y0: u16, rows: u16, data: &[u8]) {
        let top = LCD_ROW_OFFSET + y0;
        self.window(0, top, LCD_WIDTH - 1, top + rows - 1);
        self.stream(data, data.len()).await;
    }

    async fn sleep(&mut self) {
        self.bl.set_low();
        self.cmd(CMD_DISPOFF, &[]);
        self.cmd(CMD_SLPIN, &[]);
        embassy_time::Timer::after_millis(5).await;
    }

    async fn wake(&mut self) {
        self.cmd(CMD_SLPOUT, &[]);
        embassy_time::Timer::after_millis(120).await;
        self.cmd(CMD_DISPON, &[]);
    }

    async fn backlight_on(&mut self) {
        self.bl.set_high();
    }

    async fn set_led(&mut self, tone: crate::display::view::LedTone, dim: bool) {
        let level = if dim { LED_LEVEL_DIM } else { LED_LEVEL };
        self.led.write_rgb(tone.rgb(level)).await;
    }
}
