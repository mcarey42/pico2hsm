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
//! The sequence below is the definitive byte-accurate init derived from
//! `LCD_1in47_Init()` in the Waveshare RP2350-LCD-1.47 C example.
//!
//! ```text
//! SWRESET  (01h)  software reset — 150 ms delay
//! SLPOUT   (11h)  sleep out     — 255 ms delay
//! COLMOD   (3Ah)  colour format — 0x05 = 16-bit RGB565
//! MADCTL   (36h)  memory access — 0x00 normal orientation
//! INVON    (21h)  inversion on  (required for correct colours on V3 panel)
//! NORON    (13h)  normal display mode on
//! CASET    (2Ah)  column address: 0x0000 … 0x00AB (0–171, 172 px wide)
//! RASET    (2Bh)  row address:    0x0000 … 0x013F (0–319, 320 px tall)
//! DISPON   (29h)  display on    — 255 ms delay
//! BL high          backlight on (GPIO21 high)
//! ```
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

// ─── LCD display dimensions ───────────────────────────────────────────────────

/// LCD width in pixels (172).
pub const LCD_WIDTH: u16 = 172;
/// LCD height in pixels (320).
pub const LCD_HEIGHT: u16 = 320;

/// Total pixel count: 172 × 320 = 55 040.
pub const LCD_PIXEL_COUNT: u32 = LCD_WIDTH as u32 * LCD_HEIGHT as u32;

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
    /// Last status set by `set_status()` — used to suppress redundant updates.
    current_status: LedStatus,
    /// Desired LCD fill colour (RGB565) for the next async render cycle.
    pub pending_rgb565: u16,
    /// Desired WS2812B colour (GRB) for the next async render cycle.
    pub pending_grb: Grb,
}

impl St7789V3StatusDisplay {
    fn new() -> Self {
        Self {
            current_status: LedStatus::Off,
            pending_rgb565: COLOR_BLACK,
            pending_grb: Grb::OFF,
        }
    }
}

impl LedController for St7789V3StatusDisplay {
    /// Record the desired status.
    ///
    /// Updates `pending_rgb565` and `pending_grb` so that the next call to
    /// `update_status_display()` will push the correct colour to hardware.
    ///
    /// LCD rendering and WS2812B writes are async — they happen in
    /// `update_status_display()`, not here.
    fn set_status(&mut self, status: LedStatus) {
        if self.current_status != status {
            self.current_status = status;
            let (rgb565, grb) = status_to_colors(status);
            self.pending_rgb565 = rgb565;
            self.pending_grb = grb;
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
    ///
    /// GPIO control pins for the LCD (DC=GPIO16, RST=GPIO20, BL=GPIO21) and
    /// the WS2812B (GPIO22) are claimed and driven from the async functions
    /// `init_lcd()` and `update_status_display()` in this module.  Call those
    /// functions from `run_waveshare_lcd_board()` in `main.rs` after creating
    /// the board.
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
    use embedded_hal::spi::SpiBus;
    cs.set_low();
    dc.set_low();
    let _ = spi.write(&[cmd]);
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
    use embedded_hal::spi::SpiBus;
    cs.set_low();
    dc.set_low();
    let _ = spi.write(&[cmd]);
    if !data.is_empty() {
        dc.set_high();
        let _ = spi.write(data);
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
pub fn fill_screen(
    spi: &mut WaveshareRp2350LcdSpi0,
    dc: &mut Output<'static>,
    cs: &mut Output<'static>,
    color: u16,
) {
    use embedded_hal::spi::SpiBus;

    // Set window to full display area.
    lcd_set_window(spi, dc, cs, 0, 0, LCD_WIDTH - 1, LCD_HEIGHT - 1);

    // Enter pixel data write mode.
    cs.set_low();
    dc.set_low();
    let _ = spi.write(&[CMD_RAMWR]);
    dc.set_high();

    // Stream pixel data in 64-pixel (128-byte) chunks to keep stack usage low.
    // Each pixel is two bytes, big-endian.
    let hi = (color >> 8) as u8;
    let lo = (color & 0xFF) as u8;

    // Build a 128-byte chunk (64 pixels) on the stack.
    let mut chunk = [0u8; 128];
    for i in 0..64 {
        chunk[i * 2] = hi;
        chunk[i * 2 + 1] = lo;
    }

    let total_pixels = LCD_PIXEL_COUNT;
    let full_chunks = total_pixels / 64;
    let remainder = (total_pixels % 64) as usize;

    for _ in 0..full_chunks {
        let _ = spi.write(&chunk);
    }
    if remainder > 0 {
        let _ = spi.write(&chunk[..remainder * 2]);
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

    // Memory access control: normal scan direction, no mirror.
    // 0x00 = top-to-bottom, left-to-right, RGB (not BGR).
    lcd_cmd_data(spi, dc, cs, CMD_MADCTL, &[0x00]);

    // Display inversion on — required for correct colour polarity on ST7789V3.
    lcd_write_cmd(spi, dc, cs, CMD_INVON);

    // Normal display mode on.
    lcd_write_cmd(spi, dc, cs, CMD_NORON);

    // Column address: 0x0000 – 0x00AB (0–171, 172 pixels wide).
    lcd_cmd_data(spi, dc, cs, CMD_CASET, &[0x00, 0x00, 0x00, 0xAB]);

    // Row address: 0x0000 – 0x013F (0–319, 320 pixels tall).
    lcd_cmd_data(spi, dc, cs, CMD_RASET, &[0x00, 0x00, 0x01, 0x3F]);

    // Display on.
    lcd_write_cmd(spi, dc, cs, CMD_DISPON);
    Timer::after_millis(255).await;

    // Backlight on.
    bl.set_high();
}

/// Update the LCD status display and WS2812B LED with the current HSM state.
///
/// Reads `pending_rgb565` and `pending_grb` from the `display` struct (set by
/// `set_status()`) and:
/// 1. Calls `fill_screen()` to flood the entire 172×320 LCD with the status colour.
/// 2. Writes the GRB colour to the WS2812B LED via PIO DMA.
///
/// # Parameters
/// - `display` — mutable reference to the board's `St7789V3StatusDisplay`.
/// - `spi`     — SPI0 bus handle.
/// - `dc`      — GPIO16 Data/Command select.
/// - `cs`      — GPIO17 chip-select.
/// - `ws2812`  — PIO-backed WS2812B driver (PIO0, SM0, DMA0, GPIO22).
///
/// # Wiring this up in `main.rs`
/// ```rust,ignore
/// use embassy_rp::gpio::{Level, Output};
/// use embassy_rp::pio::Pio;
/// use embassy_rp::pio_programs::ws2812::{PioWs2812, PioWs2812Program};
/// use smart_leds::RGB8;
///
/// // LCD control pins
/// let mut dc  = Output::new(p.PIN_16, Level::Low);
/// let mut cs  = Output::new(p.PIN_17, Level::High);
/// let mut rst = Output::new(p.PIN_20, Level::High);
/// let mut bl  = Output::new(p.PIN_21, Level::Low);
///
/// // WS2812B on GPIO22 via PIO0 SM0
/// let Pio { mut common, sm0, .. } = Pio::new(p.PIO0, Irqs);
/// let ws2812_program = PioWs2812Program::new(&mut common);
/// let mut ws2812: PioWs2812<'_, PIO0, 0, 1, _> =
///     PioWs2812::new(&mut common, sm0, p.DMA_CH0, Irqs, p.PIN_22, &ws2812_program);
///
/// // Init LCD and fill with initial status
/// init_lcd(&mut board.spi0, &mut dc, &mut cs, &mut rst, &mut bl).await;
/// update_status_display(board.led(), &mut board.spi0, &mut dc, &mut cs, &mut ws2812).await;
/// ```
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
) {
    let rgb565 = display.pending_rgb565;
    let grb = display.pending_grb;

    // Flood-fill the LCD with the status colour (synchronous SPI writes).
    fill_screen(spi, dc, cs, rgb565);

    // Update the WS2812B LED colour.
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
