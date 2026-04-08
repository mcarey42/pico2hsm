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
//!
//! ## Init sequence (from Waveshare C reference: `LCD_1in47.c`)
//! The sequence below is derived from `LCD_1in47_Init()` in the Waveshare
//! RP2350-LCD-1.47 C example, with corrections for column offset and
//! 180-degree rotation.
//!
//! ```text
//! SWRESET  (01h)  software reset — 150 ms delay
//! SLPOUT   (11h)  sleep out     — 255 ms delay
//! COLMOD   (3Ah)  colour format — 0x05 = 16-bit RGB565
//! MADCTL   (36h)  memory access — 0xA0 (MY+MV, landscape 180°-corrected)
//! INVON    (21h)  inversion on  (required for correct colours on V3 panel)
//! NORON    (13h)  normal display mode on
//!                 [clear full 320×240 controller GRAM to black]
//! CASET    (2Ah)  column address: 0x0000 … 0x013F (0–319, 320 px wide)
//! RASET    (2Bh)  row address:    0x0022 … 0x00CD (34–205, 172 px tall)
//! DISPON   (29h)  display on    — 255 ms delay
//! BL high          backlight on (GPIO21 high)
//! ```
//!
//! ## Row address offset (landscape)
//! The ST7789V3 controller has 240 GRAM columns.  With MV=1 (landscape), RASET
//! addresses physical GRAM columns — only 172 of the 240 are connected to the
//! panel (columns 34–205).  RASET must use 34–205; addressing outside that
//! range writes to pixels not connected to the panel, causing border artefacts.
//!
//! ## 180-degree landscape correction
//! The previous landscape attempt (MADCTL=0x60, MX+MV) showed content rotated
//! 180°.  MADCTL=0xA0 (MY+MV) is 180° opposite and produces the correct image.
//!
//! ## Colour encoding
//! RGB565: 5 bits red (bits 15–11), 6 bits green (bits 10–5), 5 bits blue (bits 4–0).
//! The display expects big-endian byte order (MSB first) over SPI.
//!
//! ## Flood-fill pixel write
//! After `CASET`/`RASET` the host enters write mode with `RAMWR (2Ch)`.
//! Each pixel is two bytes (big-endian u16). A full fill is 172 × 320 = 55 040 pixels
//! = 110 080 bytes.  Sent in 128-byte chunks to avoid large stack allocations.
//!
//! # WS2812B LED
//!
//! The single WS2812B on GPIO22 uses the embassy-rp PIO WS2812 driver.
//! The LED expects GRB byte order (Green first, then Red, then Blue).
//!
//! The driver uses PIO0 state machine 0 and DMA channel 0.  The PIO program
//! runs at 800 kHz (10 cycles per bit at 8 MHz PIO clock).
//!
//! ## Colour mapping
//! | `LedStatus`   | LCD colour (RGB565) | WS2812B GRB   | Description       |
//! |---------------|---------------------|---------------|-------------------|
//! | Off           | 0x0000 black        | (0,  0,  0)   | Black / off       |
//! | Ready         | 0x07E0 green        | (8,  0,  0)   | Dim green         |
//! | Busy          | 0x001F blue         | (0,  0,  8)   | Dim blue          |
//! | Error         | 0xF800 red          | (0,  8,  0)   | Dim red           |
//! | Degraded      | 0xFFE0 yellow       | (8,  8,  0)   | Dim yellow        |
//! | Resyncing     | 0x07FF cyan         | (8,  0,  8)   | Dim cyan          |
//! | WaitingForPin | 0x031F bright blue  | (0,  0, 24)   | Brighter blue     |
//!
//! # SD card
//! `embedded-sdmmc` is already a dependency.  Wire `embedded_sdmmc::SdCard`
//! onto `board.spi1` once a `VolumeManager` is needed.
//!
//! # SPI frequency
//! Both buses are configured at 40 MHz.
//!
//! # Async rendering wiring
//! `LedController::set_status()` is synchronous — it stores the desired
//! status.  Actual LCD rendering and WS2812B updates are driven by the async
//! free functions `init_lcd()` and `update_status_display()`, which accept
//! explicit GPIO + SPI handles.  The intended call site is `run_waveshare_lcd_board()`
//! in `main.rs`.  See `update_status_display()` for the full async rendering path.

// Always import shared types — St7789V3StatusDisplay implements LedController unconditionally.
use super::{LedController, LedStatus};
// Board trait is only needed inside the feature-gated impl block.
#[cfg(any(feature = "waveshare_rp2350_lcd_16m", feature = "waveshare_rp2350_lcd_sdcard"))]
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

// ─── LCD display dimensions ───────────────────────────────────────────────────

/// LCD width in pixels (landscape, 320).
pub const LCD_WIDTH: u16 = 320;
/// LCD height in pixels (landscape, 172).
pub const LCD_HEIGHT: u16 = 172;

/// Total pixel count: 320 × 172 = 55 040.
pub const LCD_PIXEL_COUNT: u32 = LCD_WIDTH as u32 * LCD_HEIGHT as u32;

/// ST7789V3 controller GRAM height (240 — becomes the landscape row axis with MV=1).
///
/// In landscape mode (MV=1) RASET addresses physical GRAM columns.  The
/// controller has 240 GRAM columns; the panel occupies columns 34–205 (172 px).
/// All 240 must be cleared during init to prevent border artefacts.
pub const CTRL_HEIGHT: u16 = 240;

/// Row offset in landscape: the 172-px panel starts at physical GRAM column 34.
///
/// With MV=1, RASET addresses physical GRAM columns.  The panel occupies
/// GRAM columns 34–205; RASET must use these values to address the visible area.
pub const LCD_ROW_OFFSET: u16 = 34;

/// First active display row in controller GRAM (landscape): 34.
pub const LCD_ROW_START: u16 = LCD_ROW_OFFSET;
/// Last active display row in controller GRAM (landscape): 34 + 172 − 1 = 205.
pub const LCD_ROW_END: u16 = LCD_ROW_OFFSET + LCD_HEIGHT - 1;

/// MADCTL byte for corrected landscape orientation (MY + MV = 0xA0).
///
/// MV=1 exchanges rows↔columns (landscape transpose).
/// MY=1 flips the transposed row direction.
/// 0xA0 is 180° opposite to 0x60 (MX+MV), correcting the inverted image
/// that appeared with 0x60.
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
/// Sleep out — exits sleep mode, enables the display oscillator.
pub const CMD_SLPOUT: u8 = 0x11;
/// Normal display mode on.
pub const CMD_NORON: u8 = 0x13;
/// Display inversion on — required for correct colour rendering on ST7789V3.
pub const CMD_INVON: u8 = 0x21;
/// Column address set — 4-byte parameter: [XS_H, XS_L, XE_H, XE_L].
pub const CMD_CASET: u8 = 0x2A;
/// Row address set — 4-byte parameter: [YS_H, YS_L, YE_H, YE_L].
pub const CMD_RASET: u8 = 0x2B;
/// Memory write — starts pixel data stream after CASET/RASET.
pub const CMD_RAMWR: u8 = 0x2C;
/// Display on.
pub const CMD_DISPON: u8 = 0x29;
/// Memory data access control — controls scan direction and colour order.
pub const CMD_MADCTL: u8 = 0x36;
/// Interface pixel format — 0x05 = 16-bit/pixel (RGB565).
pub const CMD_COLMOD: u8 = 0x3A;

// ─── RGB565 status colours ────────────────────────────────────────────────────

/// Black (display off).
pub const COLOR_BLACK: u16 = 0x0000;
/// Solid green (Ready).
pub const COLOR_GREEN: u16 = 0x07E0;
/// Solid blue (Busy).
pub const COLOR_BLUE: u16 = 0x001F;
/// Solid red (Error).
pub const COLOR_RED: u16 = 0xF800;
/// Solid yellow (Degraded).
pub const COLOR_YELLOW: u16 = 0xFFE0;
/// Solid cyan (Resyncing).
pub const COLOR_CYAN: u16 = 0x07FF;
/// Bright blue (WaitingForPin) — deep blue with a hint of green.
pub const COLOR_BRIGHT_BLUE: u16 = 0x031F;

// ─── WS2812B GRB colour constants ────────────────────────────────────────────

/// WS2812B GRB colour tuple: (green, red, blue).
///
/// The WS2812B expects Green byte first, then Red, then Blue.
/// Brightness is kept dim (≤ 24/255) to avoid blinding the user and to
/// minimise current draw from the USB 100 mA allocation.
#[derive(Clone, Copy, Debug)]
pub struct Grb(pub u8, pub u8, pub u8); // (G, R, B)

impl Grb {
    pub const OFF: Self = Self(0, 0, 0);
    pub const READY: Self = Self(8, 0, 0);      // dim green
    pub const BUSY: Self = Self(0, 0, 8);       // dim blue
    pub const ERROR: Self = Self(0, 8, 0);      // dim red
    pub const DEGRADED: Self = Self(8, 8, 0);   // dim yellow  (G+R)
    pub const RESYNCING: Self = Self(8, 0, 8);  // dim cyan    (G+B)
    pub const WAITING: Self = Self(0, 0, 24);   // brighter blue
}

/// Map a `LedStatus` to an RGB565 LCD fill colour and a WS2812B GRB tuple.
pub fn status_to_colors(status: LedStatus) -> (u16, Grb) {
    match status {
        LedStatus::Off => (COLOR_BLACK, Grb::OFF),
        LedStatus::Ready => (COLOR_GREEN, Grb::READY),
        LedStatus::Busy => (COLOR_BLUE, Grb::BUSY),
        LedStatus::Error => (COLOR_RED, Grb::ERROR),
        LedStatus::Degraded => (COLOR_YELLOW, Grb::DEGRADED),
        LedStatus::Resyncing => (COLOR_CYAN, Grb::RESYNCING),
        LedStatus::WaitingForPin => (COLOR_BRIGHT_BLUE, Grb::WAITING),
    }
}

// ─── LED / display driver ─────────────────────────────────────────────────────

/// ST7789V3 + WS2812B status display driver for the RP2350-LCD-1.47-B.
///
/// # Architecture
///
/// `LedController::set_status()` is a synchronous method — it records the
/// desired status and returns immediately.  Actual LCD rendering and WS2812B
/// pixel writes are async operations and must be driven from the async side:
///
/// - Call `init_lcd()` once at startup to perform hardware reset + init sequence.
/// - Call `update_status_display(state)` after each `set_status()` call to
///   push the new colour to the LCD and WS2812B.
///
/// The companion free functions `init_lcd()` and `update_status_display()` in
/// this module accept explicit SPI + GPIO pin handles so that `set_status()`
/// can remain synchronous (as required by the `LedController` trait).
///
/// # WS2812B wiring note
///
/// The WS2812B on GPIO22 is driven by the `embassy_rp::pio_programs::ws2812`
/// PIO-backed driver via DMA.  The PIO state machine (PIO0, SM0) and DMA channel
/// must be wired up in `run_waveshare_lcd_board()` in `main.rs`.  The
/// `update_status_display()` free function accepts a `PioWs2812` handle and
/// calls `write(&[RGB8 { r, g, b }])` asynchronously.
///
/// # ST7789V3 SPI protocol
///
/// All transactions follow the 4-wire SPI protocol: DC low = command byte,
/// DC high = data bytes.  CS is asserted (low) for the duration of each
/// command + data sequence, then deasserted.  The ST7789V3 accepts SPI mode 0
/// (CPOL=0, CPHA=0).
pub struct St7789V3StatusDisplay {
    /// Last status set by `set_status()` — informational only; rendering is
    /// driven by the `DisplayState` passed to `update_status_display()`.
    current_status: LedStatus,
}

impl St7789V3StatusDisplay {
    pub fn new() -> Self {
        Self { current_status: LedStatus::Off }
    }
}

impl LedController for St7789V3StatusDisplay {
    fn set_status(&mut self, status: LedStatus) {
        self.current_status = status;
    }
}

// ─── Software framebuffer (ARM only) ─────────────────────────────────────────

/// Full 320×172 landscape framebuffer.
///
/// With CORE1_STACK reduced from 256 KB to 128 KB (actual peak ~65 KB), there
/// is now sufficient BSS headroom for the full-resolution buffer.
/// `flush_display()` maps this to CASET 0–319 × RASET 34–205.
const FB_W: usize = 320;
const FB_H: usize = 172;

/// 320×172 RGB565 framebuffer — 2 bytes per pixel, row-major, big-endian.
/// Owned exclusively by `flush_display()` and the `DrawTarget` impl.
///
/// # Safety
/// `FRAMEBUF` is only ever accessed from core0 display code.  No other task
/// or core touches this buffer, so there is no concurrent mutation.
#[cfg(target_arch = "arm")]
static mut FRAMEBUF: [u8; FB_W * FB_H * 2] = [0u8; FB_W * FB_H * 2];

#[cfg(target_arch = "arm")]
use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{OriginDimensions, Size},
    pixelcolor::{Rgb565, raw::{RawData, RawU16}},
    primitives::Rectangle,
    Pixel,
};

#[cfg(target_arch = "arm")]
impl OriginDimensions for St7789V3StatusDisplay {
    fn size(&self) -> Size {
        Size::new(FB_W as u32, FB_H as u32)
    }
}

#[cfg(target_arch = "arm")]
impl DrawTarget for St7789V3StatusDisplay {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        // SAFETY: FRAMEBUF is only accessed from core0 display code; no concurrent access.
        let fb = unsafe { &mut *(&raw mut FRAMEBUF) };
        for Pixel(coord, color) in pixels {
            if coord.x < 0
                || coord.y < 0
                || coord.x >= FB_W as i32
                || coord.y >= FB_H as i32
            {
                continue;
            }
            let raw: u16 = RawU16::from(color).into_inner();
            let idx = (coord.y as usize * FB_W + coord.x as usize) * 2;
            fb[idx]     = (raw >> 8) as u8;
            fb[idx + 1] = (raw & 0xFF) as u8;
        }
        Ok(())
    }

    fn fill_contiguous<I>(&mut self, area: &Rectangle, colors: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Self::Color>,
    {
        use embedded_graphics::geometry::Point;
        let disp = Rectangle::new(Point::zero(), Size::new(FB_W as u32, FB_H as u32));
        let area = area.intersection(&disp);
        if area.size.width == 0 || area.size.height == 0 {
            return Ok(());
        }
        let fb = unsafe { &mut *(&raw mut FRAMEBUF) };
        let x0 = area.top_left.x as usize;
        let y0 = area.top_left.y as usize;
        let w  = area.size.width as usize;
        let mut col = 0usize;
        let mut row = 0usize;
        for color in colors {
            if row >= area.size.height as usize { break; }
            let raw: u16 = RawU16::from(color).into_inner();
            let idx = ((y0 + row) * FB_W + (x0 + col)) * 2;
            fb[idx]     = (raw >> 8) as u8;
            fb[idx + 1] = (raw & 0xFF) as u8;
            col += 1;
            if col >= w { col = 0; row += 1; }
        }
        Ok(())
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Self::Color) -> Result<(), Self::Error> {
        use embedded_graphics::geometry::Point;
        let disp = Rectangle::new(Point::zero(), Size::new(FB_W as u32, FB_H as u32));
        let area = area.intersection(&disp);
        if area.size.width == 0 || area.size.height == 0 {
            return Ok(());
        }
        let raw: u16 = RawU16::from(color).into_inner();
        let hi = (raw >> 8) as u8;
        let lo = (raw & 0xFF) as u8;
        let fb = unsafe { &mut *(&raw mut FRAMEBUF) };
        let x0 = area.top_left.x as usize;
        let y0 = area.top_left.y as usize;
        let w  = area.size.width as usize;
        let h  = area.size.height as usize;
        for row in y0..(y0 + h) {
            let base = (row * FB_W + x0) * 2;
            for col in 0..w {
                fb[base + col * 2]     = hi;
                fb[base + col * 2 + 1] = lo;
            }
        }
        Ok(())
    }
}

// ─── SPI bus type aliases ─────────────────────────────────────────────────────

/// Blocking SPI0 type for the Waveshare RP2350-LCD-1.47-B (LCD bus).
/// `'static` lifetime: peripherals come from `embassy_rp::init()`.
/// SPI0 bus for the LCD — Async mode so `flush_display` / `fill_screen` use
/// DMA and yield to the embassy executor during the 110 KB framebuffer transfer,
/// preventing USB starvation.  Small command writes use `spi.blocking_write()`.
pub type WaveshareRp2350LcdSpi0 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Async>;

/// Blocking SPI1 type for the Waveshare RP2350-LCD-1.47-B (SD card bus).
pub type WaveshareRp2350LcdSpi1 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>;

// ─── Board struct ─────────────────────────────────────────────────────────────

/// Concrete board representation for the Waveshare RP2350-LCD-1.47-B.
///
/// When the `waveshare_rp2350_lcd_sdcard` feature is active, SPI1 is consumed
/// by the SD card keystore and is NOT part of the board struct.  The `spi1`
/// field is only present for the `waveshare_rp2350_lcd_16m` and
/// `waveshare_rp2350_lcd_sdcard_dual` variants.
pub struct WaveshareRp2350LcdBoard {
    display: St7789V3StatusDisplay,
    pub spi0: WaveshareRp2350LcdSpi0,
    #[cfg(not(feature = "waveshare_rp2350_lcd_sdcard"))]
    pub spi1: WaveshareRp2350LcdSpi1,
}

impl WaveshareRp2350LcdBoard {
    /// Create a board from pre-constructed SPI buses.
    ///
    /// GPIO control pins for the LCD (DC=GPIO16, RST=GPIO20, BL=GPIO21) and
    /// the WS2812B (GPIO22) are claimed and driven from the async functions
    /// `init_lcd()` and `update_status_display()` in this module.  Call those
    /// functions from `run_waveshare_lcd_board()` in `main.rs` after creating
    /// the board.
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
    ///
    /// Used when `waveshare_rp2350_lcd_sdcard` is active: the SD card owns
    /// SPI1 exclusively, so the board struct only holds SPI0 (LCD bus).
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

    /// Split-borrow: return mutable references to the display state and SPI0
    /// bus simultaneously.  Needed because `update_status_display()` requires
    /// both, and Rust does not allow two `&mut self` method calls at once.
    pub fn led_and_spi0_mut(
        &mut self,
    ) -> (&mut St7789V3StatusDisplay, &mut WaveshareRp2350LcdSpi0) {
        (&mut self.display, &mut self.spi0)
    }
}

#[cfg(any(feature = "waveshare_rp2350_lcd_16m", feature = "waveshare_rp2350_lcd_sdcard"))]
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

// ─── ST7789V3 hardware driver — ARM-only async free functions ────────────────
//
// These functions are gated on `#[cfg(target_arch = "arm")]` because they use
// embassy-rp GPIO + SPI types that are not available on x86_64 test builds.
//
// Callers in main.rs must hold the GPIO Output handles for DC, CS, RST, BL and
// pass them in by &mut reference.  This avoids storing `'static` GPIO handles
// inside `St7789V3StatusDisplay` (which would require changing the `new(spi0,
// spi1)` call site in main.rs).

#[cfg(target_arch = "arm")]
use embassy_rp::gpio::Output;

/// Send one command byte to the ST7789V3.
///
/// Asserts CS, pulls DC low (command mode), writes the byte, then deasserts CS.
#[cfg(target_arch = "arm")]
#[inline]
fn lcd_write_cmd(
    spi: &mut WaveshareRp2350LcdSpi0,
    dc: &mut Output<'static>,
    cs: &mut Output<'static>,
    cmd: u8,
) {
    cs.set_low();
    dc.set_low();
    let _ = spi.blocking_write(&[cmd]);
    cs.set_high();
}

/// Send one command byte followed immediately by data bytes.
///
/// CS is held asserted across the whole transaction.
#[cfg(target_arch = "arm")]
#[inline]
fn lcd_cmd_data(
    spi: &mut WaveshareRp2350LcdSpi0,
    dc: &mut Output<'static>,
    cs: &mut Output<'static>,
    cmd: u8,
    data: &[u8],
) {
    cs.set_low();
    dc.set_low();
    let _ = spi.blocking_write(&[cmd]);
    if !data.is_empty() {
        dc.set_high();
        let _ = spi.blocking_write(data);
    }
    cs.set_high();
}

/// Set the active drawing window on the ST7789V3.
///
/// Issues `CASET` (column) and `RASET` (row) commands to define the rectangle
/// that the next `RAMWR` data stream will fill.
///
/// Coordinates are inclusive: (x0, y0) top-left, (x1, y1) bottom-right.
#[cfg(target_arch = "arm")]
fn lcd_set_window(
    spi: &mut WaveshareRp2350LcdSpi0,
    dc: &mut Output<'static>,
    cs: &mut Output<'static>,
    x0: u16,
    y0: u16,
    x1: u16,
    y1: u16,
) {
    lcd_cmd_data(spi, dc, cs, CMD_CASET, &[
        (x0 >> 8) as u8, (x0 & 0xFF) as u8,
        (x1 >> 8) as u8, (x1 & 0xFF) as u8,
    ]);
    lcd_cmd_data(spi, dc, cs, CMD_RASET, &[
        (y0 >> 8) as u8, (y0 & 0xFF) as u8,
        (y1 >> 8) as u8, (y1 & 0xFF) as u8,
    ]);
}

/// Flood-fill the entire LCD with a single RGB565 colour.
///
/// Sets the drawing window to the full 172×320 display, then streams
/// `LCD_PIXEL_COUNT` × 2 bytes of pixel data in 128-byte chunks to avoid
/// large stack allocations.
///
/// # Parameters
/// - `spi`   — SPI0 bus handle (blocking, 40 MHz, mode 0).
/// - `dc`    — GPIO16 Data/Command select output.
/// - `cs`    — GPIO17 chip-select output.
/// - `color` — RGB565 colour value (big-endian u16: high byte first).
#[cfg(target_arch = "arm")]
pub async fn fill_screen(
    spi: &mut WaveshareRp2350LcdSpi0,
    dc: &mut Output<'static>,
    cs: &mut Output<'static>,
    color: u16,
) {
    // Set window to the full landscape display area (CASET 0–319, RASET 34–205).
    lcd_set_window(spi, dc, cs, 0, LCD_ROW_START, LCD_WIDTH - 1, LCD_ROW_END);

    // Enter pixel data write mode.
    cs.set_low();
    dc.set_low();
    let _ = spi.blocking_write(&[CMD_RAMWR]);
    dc.set_high();

    // Stream pixel data in 64-pixel (128-byte) chunks via async DMA.
    // Each chunk yields to the executor, keeping USB serviced.
    let hi = (color >> 8) as u8;
    let lo = (color & 0xFF) as u8;

    let mut chunk = [0u8; 128];
    for i in 0..64 {
        chunk[i * 2] = hi;
        chunk[i * 2 + 1] = lo;
    }

    let total_pixels = LCD_PIXEL_COUNT;
    let full_chunks = total_pixels / 64;
    let remainder = (total_pixels % 64) as usize;

    for _ in 0..full_chunks {
        let _ = spi.write(&chunk).await;
    }
    if remainder > 0 {
        let _ = spi.write(&chunk[..remainder * 2]).await;
    }

    cs.set_high();
}

/// Initialise the ST7789V3 LCD controller over SPI0.
///
/// Performs the hardware reset sequence and sends the init command stream
/// from the Waveshare C reference (`LCD_1in47_Init()`).  After this function
/// returns the display is on and showing whatever colour is in GRAM (initially
/// undefined — call `fill_screen()` immediately after).
///
/// # Parameters
/// - `spi`  — SPI0 bus handle, already configured at 40 MHz, mode 0.
/// - `dc`   — GPIO16 Data/Command select output (`Output<'static>`).
/// - `cs`   — GPIO17 chip-select output.
/// - `rst`  — GPIO20 hardware reset output (active-low, hold low for ≥ 10 ms).
/// - `bl`   — GPIO21 backlight enable output (set high after init).
///
/// # Delays
/// Uses `embassy_time::Timer` for the mandatory inter-command delays.
#[cfg(target_arch = "arm")]
pub async fn init_lcd(
    spi: &mut WaveshareRp2350LcdSpi0,
    dc: &mut Output<'static>,
    cs: &mut Output<'static>,
    rst: &mut Output<'static>,
    bl: &mut Output<'static>,
) {
    use embassy_time::Timer;

    // Ensure CS and BL are in known states before touching the display.
    cs.set_high();
    bl.set_low();

    // Hardware reset: drive RST low for 10 ms, then high, wait 120 ms.
    rst.set_high();
    Timer::after_millis(10).await;
    rst.set_low();
    Timer::after_millis(10).await;
    rst.set_high();
    Timer::after_millis(120).await;

    // Software reset — resets all registers to defaults.
    lcd_write_cmd(spi, dc, cs, CMD_SWRESET);
    Timer::after_millis(150).await;

    // Sleep out — exits sleep mode, enables oscillator.
    lcd_write_cmd(spi, dc, cs, CMD_SLPOUT);
    Timer::after_millis(255).await;

    // Colour format: 16-bit/pixel RGB565 (0x05).
    lcd_cmd_data(spi, dc, cs, CMD_COLMOD, &[0x05]);

    // Memory access control: landscape (MY=1, MV=1 = 0xA0).
    // 180° opposite of the broken 0x60 (MX+MV), correcting the inverted image.
    lcd_cmd_data(spi, dc, cs, CMD_MADCTL, &[MADCTL_LANDSCAPE]);

    // Display inversion on — required for correct colour polarity on ST7789V3.
    lcd_write_cmd(spi, dc, cs, CMD_INVON);

    // Normal display mode on.
    lcd_write_cmd(spi, dc, cs, CMD_NORON);

    // Clear the full controller GRAM to black to eliminate border artefacts.
    // In landscape (MV=1): CASET = physical GRAM rows 0–319, RASET = physical
    // GRAM columns 0–239.  Total: 320 × 240 = 76 800 pixels.
    {
        lcd_cmd_data(spi, dc, cs, CMD_CASET, &[0x00, 0x00, 0x01, 0x3F]); // 0–319
        lcd_cmd_data(spi, dc, cs, CMD_RASET, &[0x00, 0x00, 0x00, 0xEF]); // 0–239
        cs.set_low();
        dc.set_low();
        let _ = spi.blocking_write(&[CMD_RAMWR]);
        dc.set_high();
        let chunk = [0u8; 128];
        let total_pixels = LCD_WIDTH as u32 * CTRL_HEIGHT as u32; // 76 800
        let full_chunks = total_pixels / 64;
        let remainder = (total_pixels % 64) as usize;
        for _ in 0..full_chunks { let _ = spi.write(&chunk).await; }
        if remainder > 0 { let _ = spi.write(&chunk[..remainder * 2]).await; }
        cs.set_high();
    }

    // Set panel window: CASET 0–319 (landscape width), RASET 34–205
    // (physical GRAM columns 34–205 = 172 px landscape height).
    lcd_cmd_data(spi, dc, cs, CMD_CASET, &[0x00, 0x00, 0x01, 0x3F]); // 0–319
    lcd_cmd_data(spi, dc, cs, CMD_RASET, &[0x00, 0x22, 0x00, 0xCD]); // 34–205

    // Display on.
    lcd_write_cmd(spi, dc, cs, CMD_DISPON);
    Timer::after_millis(255).await;

    // Backlight on.
    bl.set_high();
}

/// Send the FRAMEBUF contents to the ST7789V3 LCD in one SPI burst.
///
/// Sets CASET to 0–319 (landscape width) and RASET to 34–205 (panel row
/// window), then writes the full 320×172 FRAMEBUF.
#[cfg(target_arch = "arm")]
/// Send the FRAMEBUF to the LCD via DMA.  The async DMA write yields to the
/// embassy executor while the 110 KB transfer is in flight, so `usb_fut` keeps
/// running and USB does not stall.
pub async fn flush_display(
    spi: &mut WaveshareRp2350LcdSpi0,
    dc: &mut Output<'static>,
    cs: &mut Output<'static>,
) {
    // Set window to the full landscape panel: CASET 0–319, RASET 34–205.
    lcd_set_window(spi, dc, cs, 0, LCD_ROW_START, LCD_WIDTH - 1, LCD_ROW_END);

    // Begin RAM write.
    cs.set_low();
    dc.set_low();
    let _ = spi.blocking_write(&[CMD_RAMWR]);
    dc.set_high();

    // SAFETY: FRAMEBUF is only accessed from core0; no concurrent mutation.
    // DMA write: yields to executor during the ~22 ms transfer.
    let _ = spi.write(unsafe { &*(&raw const FRAMEBUF) }).await;

    cs.set_high();
}

/// Update the LCD status display and WS2812B LED with the current HSM state.
///
/// Renders the full info UI onto FRAMEBUF via `display::render()`, then
/// pushes it to the ST7789V3 with `flush_display()`.  Also updates the
/// WS2812B LED colour to match `state.status`.
///
/// # Parameters
/// - `display` — mutable reference to the board's `St7789V3StatusDisplay`.
/// - `spi`     — SPI0 bus handle.
/// - `dc`      — GPIO16 Data/Command select.
/// - `cs`      — GPIO17 chip-select.
/// - `ws2812`  — PIO-backed WS2812B driver (PIO0, SM0, DMA0, GPIO22).
/// - `state`   — current HSM display state (status, key count, uptime, …).
///
/// # Note on defmt
/// This function MUST NOT be called from Core1 — see the core1 defmt deadlock
/// note in `CLAUDE.md`.  It is intended for use on Core0 only.
#[cfg(target_arch = "arm")]
pub async fn update_status_display(
    display: &mut St7789V3StatusDisplay,
    spi: &mut WaveshareRp2350LcdSpi0,
    dc: &mut Output<'static>,
    cs: &mut Output<'static>,
    ws2812: &mut impl Ws2812Writer,
    state: &crate::display::DisplayState,
) {
    use crate::display::{render, ScreenLayout};

    // Render info UI into the 320×172 FRAMEBUF using the landscape layout.
    let layout = ScreenLayout::waveshare_320x172();
    render(display, state, &layout);

    // Push FRAMEBUF to the LCD via DMA (async — yields to executor during transfer).
    flush_display(spi, dc, cs).await;

    // Update WS2812B LED colour to match status.
    let (_, grb) = status_to_colors(state.status);
    ws2812.write_pixel(grb).await;
}

/// Trait abstracting the WS2812B write operation.
///
/// This allows `update_status_display()` to accept the embassy-rp
/// `PioWs2812` driver without naming its full generic type in the free
/// function signature.
///
/// Implement this trait on the concrete `PioWs2812` type via a small wrapper
/// in `main.rs`, or use the provided `PioWs2812Writer` adapter.
pub trait Ws2812Writer {
    /// Write a single pixel GRB colour to the WS2812B chain and wait for the
    /// 55 µs reset signal.
    async fn write_pixel(&mut self, grb: Grb);
}

/// Stub `Ws2812Writer` for use in unit tests and stub boards.
pub struct NullWs2812;

/// Embassy-rp PIO WS2812 adapter for a single-pixel chain (N=1).
///
/// Wraps `PioWs2812<'d, P, S, 1, Grb>` and converts the internal `Grb`
/// colour tuple to `smart_leds::RGB8` before calling `write()`.
///
/// # Usage (in `main.rs`)
/// ```rust,ignore
/// use pico2hsm_firmware::board::waveshare_rp2350_lcd::PioWs2812Writer;
///
/// let mut led_driver = PioWs2812Writer::new(ws2812);
/// update_status_display(..., &mut led_driver).await;
/// ```
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
    async fn write_pixel(&mut self, grb: Grb) {
        // `PioWs2812::write()` takes `&[smart_leds::RGB8; N]`.
        // `smart_leds::RGB8` is `#[repr(C)] struct { r: u8, g: u8, b: u8 }` —
        // layout-identical to `[u8; 3]`.  We use `core::mem::transmute` to
        // convert a `[u8; 3]` into the expected element type so this crate does
        // not need `smart_leds` as a direct dependency (it is already resolved
        // as a transitive dep of embassy-rp in Cargo.lock).
        //
        // The `Grb` ORDER type parameter on `PioWs2812` means the driver will
        // repack the RGB8 { r, g, b } values into G-R-B order before writing to
        // the PIO FIFO.  We therefore provide { r, g, b } in standard order here.
        let rgb_bytes: [u8; 3] = [grb.1, grb.0, grb.2]; // [r=grb.1, g=grb.0, b=grb.2]
        // SAFETY: `smart_leds::RGB8` is `#[repr(C)]` with fields `r, g, b: u8`
        // in that order, making it layout-identical to `[u8; 3]`.
        let pixels: [_; 1] = [unsafe { core::mem::transmute::<[u8; 3], _>(rgb_bytes) }];
        self.inner.write(&pixels).await;
    }
}

/// `NullWs2812` implements `Ws2812Writer` on all targets.
///
/// On ARM it is available as a stub during bringup before PIO is wired up.
/// On non-ARM (x86_64 unit tests) it is the only available implementation.
impl Ws2812Writer for NullWs2812 {
    async fn write_pixel(&mut self, _grb: Grb) {}
}

/// Initialise the microSD card over SPI1.
///
/// Pin assignments (from official Waveshare MicroPython 02-SD example):
///   SCK=GPIO{SDCARD_SCK_PIN}, MOSI=GPIO{SDCARD_MOSI_PIN},
///   MISO=GPIO{SDCARD_MISO_PIN}, CS=GPIO{SDCARD_CS_PIN}.
///
/// Wire `embedded_sdmmc::SdCard` onto `board.spi1` and expose a
/// `VolumeManager` for FAT32 key backup / restore.
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
