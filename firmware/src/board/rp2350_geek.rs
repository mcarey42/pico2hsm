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
//!   Visible area is 240×135 with column offset 52 and row offset 40.
//! - SPI1 LCD pins: SCK=GPIO10, MOSI=GPIO11
//!   DC=GPIO8, CS=GPIO9, RST=GPIO12, BL=GPIO25
//! - SPI0 pins: SCK=GPIO18, MOSI=GPIO19, MISO=GPIO20
//!   CS[0..3] = GPIO17, GPIO21, GPIO22, GPIO26 (keystore flash chips)
//! - SPI1 also: CS[1..3] = GPIO13, GPIO14, GPIO15 (mirror flash, beyond LCD CS=GPIO9)
//! - SDCard slot CS: GPIO5
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
//! # ST7789 init sequence
//! SWRESET → delay 150 ms → SLPOUT → delay 255 ms → COLMOD(0x33 = RGB444) →
//! MADCTL(0x70 = landscape, BGR) → CASET(52..291) → RASET(40..174) →
//! INVON → NORON → DISPON.
//!
//! # SPI frequency
//! SPI0 (flash) is configured at 40 MHz.
//! SPI1 (LCD) is configured at 30 MHz (conservative for ST7789; can reach 62.5 MHz).

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
/// SDIO_D1 (GPIO21) and SDIO_D2 (GPIO22) are unused in SPI mode.
pub const SDCARD0_CS: u8 = 23;

/// SPI0 frequency for SD card — must start ≤ 400 kHz for initialisation,
/// then may increase to 25 MHz after CMD0 response.  embedded-sdmmc handles
/// the speed switch internally; this is the post-init transfer speed.
pub const SD_SPI_FREQ_HZ: u32 = 25_000_000;
/// SPI1 / LCD frequency — ST7789 at 30 MHz (conservative; rated up to 62.5 MHz).
pub const LCD_SPI_FREQ_HZ: u32 = 30_000_000;

// ─── ST7789 register constants ────────────────────────────────────────────────

const ST7789_SWRESET: u8 = 0x01;
const ST7789_SLPOUT: u8 = 0x11;
const ST7789_NORON: u8 = 0x13;
const ST7789_INVON: u8 = 0x21;
const ST7789_DISPON: u8 = 0x29;
const ST7789_CASET: u8 = 0x2A;
const ST7789_RASET: u8 = 0x2B;
const ST7789_RAMWR: u8 = 0x2C;
const ST7789_MADCTL: u8 = 0x36;
const ST7789_COLMOD: u8 = 0x3A;

/// Display physical dimensions (landscape orientation after MADCTL rotation).
/// The ST7789 in the RP2350-Geek is a 240×135 panel mounted landscape.
/// CASET range: 52..(52+240-1) = 52..291
/// RASET range: 40..(40+135-1) = 40..174
pub const LCD_WIDTH: u16 = 240;
pub const LCD_HEIGHT: u16 = 135;
const LCD_COL_OFFSET: u16 = 52;
const LCD_ROW_OFFSET: u16 = 40;

/// Cortex-M33 at 150 MHz: ~150_000 cycles per millisecond.
/// Using a generous constant to ensure minimum timing even if clock is lower.
const CYCLES_PER_MS: u32 = 150_000;

// ─── Software framebuffer ─────────────────────────────────────────────────────

/// 240×135 RGB444 framebuffer — 3 bytes per 2 pixels (packed), row-major.
///
/// Two pixels are packed into 3 bytes (ST7789 "Interface II" RGB444):
///   Byte 0: [R1₃R1₂R1₁R1₀ | G1₃G1₂G1₁G1₀]
///   Byte 1: [B1₃B1₂B1₁B1₀ | R2₃R2₂R2₁R2₀]
///   Byte 2: [G2₃G2₂G2₁G2₀ | B2₃B2₂B2₁B2₀]
///
/// 240×135 = 32 400 pixels → 48 600 bytes (saves ~16 KB vs RGB565's 64 800).
/// Both dimensions are even, so rows always end on a pixel-pair boundary.
///
/// Owned exclusively by `St7789StatusDisplay::flush()` and the `DrawTarget` impl.
///
/// # Safety
/// `FRAMEBUF` is only ever accessed from core0 display code (the `DrawTarget`
/// impl and `flush()`).  No other task or core touches this buffer, so there is
/// no concurrent mutation.
#[cfg(target_arch = "arm")]
static mut FRAMEBUF: [u8; (LCD_WIDTH as usize) * (LCD_HEIGHT as usize) * 3 / 2] =
    [0u8; (LCD_WIDTH as usize) * (LCD_HEIGHT as usize) * 3 / 2];

// ─── LED / display driver ─────────────────────────────────────────────────────

/// ST7789 status display driver for the Waveshare RP2350-Geek.
///
/// Drives the 1.14" 240×135 ST7789 LCD over SPI1.  On each `set_status()`
/// call the entire screen is filled with a solid RGB444 colour that encodes
/// the current HSM state.
///
/// # GPIO ownership
/// The driver takes ownership of SPI1 and the four LCD control GPIOs
/// (DC=GPIO8, CS=GPIO9, RST=GPIO12, BL=GPIO25).  The GPIO pins are
/// obtained via `embassy_rp::gpio::AnyPin::steal()` inside `new()` so that
/// the `Rp2350GeekBoard::new(spi0, spi1)` call signature does not need to
/// change (main.rs passes the SPI peripherals but not the discrete GPIOs).
///
/// # Safety of AnyPin::steal
/// `AnyPin::steal()` is `unsafe` because it creates an aliased handle.
/// It is safe here because:
/// 1. `run_geek_board()` does not use GPIO8, GPIO9, GPIO12, or GPIO25 for
///    any other purpose — they are only wired to the LCD.
/// 2. The steal happens exactly once at board construction time, inside the
///    single-owner `St7789StatusDisplay::new()` call.
/// 3. No other code in this crate takes those pins after the steal.
#[cfg(target_arch = "arm")]
pub struct St7789StatusDisplay {
    /// SPI1 bus — shared with LCD (TX-only, CS is a separate GPIO).
    spi: Rp2350GeekSpi1,
    /// D/C (Data/Command) pin — HIGH = data, LOW = command.
    dc: embassy_rp::gpio::Output<'static>,
    /// Chip-select pin (active-low).
    cs: embassy_rp::gpio::Output<'static>,
    /// Hardware reset pin (active-low).
    rst: embassy_rp::gpio::Output<'static>,
    /// Backlight enable pin (active-high).
    bl: embassy_rp::gpio::Output<'static>,
    /// Last rendered status — skip re-renders of the same state.
    current_status: LedStatus,
}

/// Stub version for non-ARM (unit-test) builds.  No GPIO or SPI types needed.
#[cfg(not(target_arch = "arm"))]
pub struct St7789StatusDisplay {
    current_status: LedStatus,
}

// ─── ARM-only LCD implementation ─────────────────────────────────────────────

#[cfg(target_arch = "arm")]
impl St7789StatusDisplay {
    /// Construct the display driver and run the ST7789 init sequence.
    ///
    /// Takes ownership of the SPI1 bus.  The four LCD GPIO pins (DC, CS, RST,
    /// BL) are stolen from the PAC — see the safety note on the struct.
    fn new(spi: Rp2350GeekSpi1) -> Self {
        use embassy_rp::gpio::{AnyPin, Level, Output};

        // Safety: these four GPIOs are exclusively wired to the ST7789 LCD on
        // the RP2350-Geek and are not claimed anywhere else in the firmware.
        let dc = Output::new(unsafe { AnyPin::steal(LCD_DC_PIN) }, Level::Low);
        let cs = Output::new(unsafe { AnyPin::steal(LCD_CS_PIN) }, Level::High); // deasserted
        let rst = Output::new(unsafe { AnyPin::steal(LCD_RST_PIN) }, Level::High); // not in reset
        let bl = Output::new(unsafe { AnyPin::steal(LCD_BL_PIN) }, Level::Low); // backlight off

        let mut display = Self {
            spi,
            dc,
            cs,
            rst,
            bl,
            current_status: LedStatus::Off,
        };

        display.st7789_init();
        display
    }

    /// Turn the display backlight on (wake from screensaver).
    pub fn backlight_on(&mut self) {
        self.bl.set_high();
    }

    /// Turn the display backlight off (screensaver).
    pub fn backlight_off(&mut self) {
        self.bl.set_low();
    }

    /// Send the entire framebuffer to the ST7789 display via DMA.
    ///
    /// Call this once after `render()` completes to push the composed frame
    /// to the display in a single SPI burst.  The display only transitions
    /// from the old frame to the new frame during this call — no intermediate
    /// blank-screen state is ever visible.
    ///
    /// The 48 KB framebuffer write uses `spi.write().await` (DMA-backed) so
    /// the Embassy executor is not blocked during the ~13 ms transfer.  Small
    /// command/window writes use `blocking_write()` which is fine on an Async
    /// SPI bus and requires no async context.
    pub async fn flush(&mut self) {
        // Re-assert the visible window before RAMWR.
        let col_start = LCD_COL_OFFSET;
        let col_end = LCD_COL_OFFSET + LCD_WIDTH - 1;
        let row_start = LCD_ROW_OFFSET;
        let row_end = LCD_ROW_OFFSET + LCD_HEIGHT - 1;
        self.write_command_data(
            ST7789_CASET,
            &[
                (col_start >> 8) as u8,
                (col_start & 0xFF) as u8,
                (col_end >> 8) as u8,
                (col_end & 0xFF) as u8,
            ],
        );
        self.write_command_data(
            ST7789_RASET,
            &[
                (row_start >> 8) as u8,
                (row_start & 0xFF) as u8,
                (row_end >> 8) as u8,
                (row_end & 0xFF) as u8,
            ],
        );

        self.dc.set_low();
        self.cs_assert();
        let _ = self.spi.blocking_write(&[ST7789_RAMWR]);
        self.dc.set_high();

        // SAFETY: FRAMEBUF is only accessed from core0; no concurrent mutation.
        // DMA write: yields to executor during the ~13 ms transfer.
        let _ = self
            .spi
            .write(unsafe { &*core::ptr::addr_of!(FRAMEBUF) })
            .await;

        self.cs_deassert();
    }

    // ── Low-level SPI helpers ────────────────────────────────────────────────

    /// Busy-wait for approximately `ms` milliseconds.
    ///
    /// Uses `cortex_m::asm::delay` (cycle-counted).  Accurate enough for the
    /// 5 ms and 150 ms delays the ST7789 init requires; does not require an
    /// async context.
    #[inline]
    fn delay_ms(&self, ms: u32) {
        cortex_m::asm::delay(ms * CYCLES_PER_MS);
    }

    /// Assert CS (pull low) before a transaction.
    #[inline]
    fn cs_assert(&mut self) {
        self.cs.set_low();
    }

    /// Deassert CS (pull high) after a transaction.
    #[inline]
    fn cs_deassert(&mut self) {
        self.cs.set_high();
    }

    /// Send a single command byte (DC low).
    fn write_command(&mut self, cmd: u8) {
        self.dc.set_low();
        self.cs_assert();
        let _ = self.spi.blocking_write(&[cmd]);
        self.cs_deassert();
    }

    /// Send a command followed immediately by data bytes in one CS assertion.
    fn write_command_data(&mut self, cmd: u8, data: &[u8]) {
        // Send command byte (DC low)
        self.dc.set_low();
        self.cs_assert();
        let _ = self.spi.blocking_write(&[cmd]);
        // Switch to data phase (DC high) without toggling CS
        self.dc.set_high();
        let _ = self.spi.blocking_write(data);
        self.cs_deassert();
    }

    // ── ST7789 initialisation ────────────────────────────────────────────────

    /// Clear the entire ST7789 controller RAM (320 × 240 pixels) to black.
    ///
    /// The ST7789 has a 320 × 240 internal framebuffer.  After MADCTL = 0x70,
    /// our visible window is CASET(52..291) × RASET(40..174) — only 240 × 135
    /// of those pixels.  The remaining controller pixels (left columns 0..51,
    /// bottom rows 175..239) map to physical border areas of the panel and show
    /// as garbage until explicitly cleared.  This must be called once during
    /// init, after MADCTL is set.
    fn clear_full_controller_ram(&mut self) {
        // With MADCTL = 0x70 the full addressable range is
        //   CASET  0 .. 319   (320 columns in the rotated landscape frame)
        //   RASET  0 .. 239   (240 rows   in the rotated landscape frame)
        self.write_command_data(ST7789_CASET, &[0x00, 0x00, 0x01, 0x3F]); // 0..319
        self.write_command_data(ST7789_RASET, &[0x00, 0x00, 0x00, 0xEF]); // 0..239

        self.dc.set_low();
        self.cs_assert();
        let _ = self.spi.blocking_write(&[ST7789_RAMWR]);
        self.dc.set_high();

        // 320 × 240 = 76 800 pixels → 115 200 bytes in RGB444 (3 bytes per 2 pixels).
        // Write in 320-pixel (480-byte) row chunks — all zeros = black.
        let row_buf = [0u8; 480]; // 320 pixels × 3/2 bytes = 480 bytes
        for _ in 0..240u16 {
            let _ = self.spi.blocking_write(&row_buf);
        }

        self.cs_deassert();
    }

    /// Run the full ST7789 hardware-reset + init sequence.
    ///
    /// Sequence:
    /// 1. Hardware reset pulse (RST low 10 ms, high 150 ms)
    /// 2. SWRESET + 150 ms
    /// 3. SLPOUT + 255 ms
    /// 4. COLMOD = 0x33 (12-bit RGB444)
    /// 5. MADCTL = 0x70 (landscape, MX+MV, BGR colour order for ST7789)
    /// 6. Full controller RAM clear (320 × 240 black pixels — eliminates border garbage)
    /// 7. CASET = 52..291  (column window for 240 px wide display)
    /// 8. RASET = 40..174  (row window for 135 px tall display)
    /// 9. INVON (colour inversion — required for correct colours on ST7789)
    /// 10. NORON (normal display mode)
    /// 11. DISPON (display on) + backlight enable
    fn st7789_init(&mut self) {
        defmt::info!("ST7789: hardware reset...");

        // Hardware reset: pulse RST low
        self.rst.set_low();
        self.delay_ms(10);
        self.rst.set_high();
        self.delay_ms(150);

        defmt::info!("ST7789: SWRESET...");
        self.write_command(ST7789_SWRESET);
        self.delay_ms(150);

        defmt::info!("ST7789: SLPOUT...");
        self.write_command(ST7789_SLPOUT);
        self.delay_ms(255);

        // 12-bit RGB444 colour format — saves ~25% framebuffer SRAM vs RGB565
        defmt::info!("ST7789: COLMOD 0x33 (RGB444)...");
        self.write_command_data(ST7789_COLMOD, &[0x33]);
        self.delay_ms(10);

        // Memory Access Control:
        //   MX=1 (column mirror) | MV=1 (row/col exchange = 90° rotation) | BGR=1
        //   = 0b0111_0000 = 0x70
        // This puts the display in landscape orientation (240 wide × 135 tall).
        defmt::info!("ST7789: MADCTL 0x70 (landscape)...");
        self.write_command_data(ST7789_MADCTL, &[0x70]);

        // Clear full controller RAM (320 × 240) to remove border garbage pixels.
        defmt::info!("ST7789: clearing full controller RAM (320x240)...");
        self.clear_full_controller_ram();

        // Column address set: 52 to 291 (52 + 240 - 1)
        let col_start = LCD_COL_OFFSET;
        let col_end = LCD_COL_OFFSET + LCD_WIDTH - 1;
        defmt::info!("ST7789: CASET {}..{}...", col_start, col_end);
        self.write_command_data(
            ST7789_CASET,
            &[
                (col_start >> 8) as u8,
                (col_start & 0xFF) as u8,
                (col_end >> 8) as u8,
                (col_end & 0xFF) as u8,
            ],
        );

        // Row address set: 40 to 174 (40 + 135 - 1)
        let row_start = LCD_ROW_OFFSET;
        let row_end = LCD_ROW_OFFSET + LCD_HEIGHT - 1;
        defmt::info!("ST7789: RASET {}..{}...", row_start, row_end);
        self.write_command_data(
            ST7789_RASET,
            &[
                (row_start >> 8) as u8,
                (row_start & 0xFF) as u8,
                (row_end >> 8) as u8,
                (row_end & 0xFF) as u8,
            ],
        );

        // Inversion on — ST7789 requires INVON for correct (non-inverted) colours
        defmt::info!("ST7789: INVON...");
        self.write_command(ST7789_INVON);
        self.delay_ms(10);

        // Normal display mode on
        defmt::info!("ST7789: NORON...");
        self.write_command(ST7789_NORON);
        self.delay_ms(10);

        // Display on
        defmt::info!("ST7789: DISPON...");
        self.write_command(ST7789_DISPON);
        self.delay_ms(10);

        // Backlight on
        self.bl.set_high();
        defmt::info!("ST7789: init complete — backlight on");

        // Clear to black
        self.fill_screen(0x0000);
    }

    // ── Screen fill ──────────────────────────────────────────────────────────

    /// Fill the entire display with a solid RGB565 colour (converted to RGB444).
    ///
    /// Sends 240 × 135 = 32 400 pixels in 48 600 bytes (3 bytes per 2 pixels).
    /// To avoid a large stack allocation, pixels are written in 240-pixel
    /// (360-byte) row chunks that fit comfortably in the call stack.
    fn fill_screen(&mut self, color: u16) {
        // Re-assert the column and row windows before RAMWR in case they were
        // disturbed by a previous partial write.
        let col_start = LCD_COL_OFFSET;
        let col_end = LCD_COL_OFFSET + LCD_WIDTH - 1;
        let row_start = LCD_ROW_OFFSET;
        let row_end = LCD_ROW_OFFSET + LCD_HEIGHT - 1;

        self.write_command_data(
            ST7789_CASET,
            &[
                (col_start >> 8) as u8,
                (col_start & 0xFF) as u8,
                (col_end >> 8) as u8,
                (col_end & 0xFF) as u8,
            ],
        );
        self.write_command_data(
            ST7789_RASET,
            &[
                (row_start >> 8) as u8,
                (row_start & 0xFF) as u8,
                (row_end >> 8) as u8,
                (row_end & 0xFF) as u8,
            ],
        );

        // Begin RAM write
        self.dc.set_low();
        self.cs_assert();
        let _ = self.spi.blocking_write(&[ST7789_RAMWR]);
        self.dc.set_high();

        // Convert RGB565 to RGB444: extract top 4 bits of each channel.
        let r = ((color >> 12) & 0x0F) as u8;
        let g = ((color >> 7) & 0x0F) as u8;
        let b = ((color >> 1) & 0x0F) as u8;

        // Pack two identical pixels into 3 bytes (RGB444 Interface II):
        //   Byte 0: R1G1, Byte 1: B1R2, Byte 2: G2B2
        let byte0 = (r << 4) | g;
        let byte1 = (b << 4) | r;
        let byte2 = (g << 4) | b;

        // Write rows one at a time — 360 bytes per row (240 pixels × 3/2 bytes).
        let mut row_buf = [0u8; (LCD_WIDTH as usize) * 3 / 2]; // 360 bytes
        for i in 0..(LCD_WIDTH as usize / 2) {
            row_buf[i * 3] = byte0;
            row_buf[i * 3 + 1] = byte1;
            row_buf[i * 3 + 2] = byte2;
        }
        for _ in 0..LCD_HEIGHT {
            let _ = self.spi.blocking_write(&row_buf);
        }

        self.cs_deassert();
    }

    /// Map a `LedStatus` to an RGB565 colour for the status screen.
    fn status_color(status: LedStatus) -> u16 {
        match status {
            LedStatus::Off => 0x0000,           // black
            LedStatus::Ready => 0x07E0,         // green
            LedStatus::Busy => 0x001F,          // blue
            LedStatus::Error => 0xF800,         // red
            LedStatus::Degraded => 0xFFE0,      // yellow
            LedStatus::Resyncing => 0x07FF,     // cyan
            LedStatus::WaitingForPin => 0x031F, // bright blue (slightly lighter)
        }
    }
}

// ─── LedController implementation (ARM) ──────────────────────────────────────

#[cfg(target_arch = "arm")]
impl LedController for St7789StatusDisplay {
    fn set_status(&mut self, status: LedStatus) {
        if self.current_status != status {
            self.current_status = status;
            let color = Self::status_color(status);
            self.fill_screen(color);
        }
    }
}

// ─── embedded-graphics DrawTarget implementation (ARM) ────────────────────────

#[cfg(target_arch = "arm")]
use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{OriginDimensions, Size},
    pixelcolor::{
        raw::{RawData, RawU16},
        Rgb565,
    },
    primitives::Rectangle,
    Pixel,
};

// ─── RGB444 packing helpers ─────────────────────────────────────────────────

/// Extract 4-bit R, G, B components from an RGB565 raw u16.
///
/// Takes the top 4 bits of each channel:
///   R4 = bits 15–12 of the raw value (top 4 of 5-bit R)
///   G4 = bits 10–7  (top 4 of 6-bit G)
///   B4 = bits 4–1   (top 4 of 5-bit B)
#[cfg(target_arch = "arm")]
#[inline(always)]
fn rgb565_to_rgb444(color: Rgb565) -> (u8, u8, u8) {
    let raw: u16 = RawU16::from(color).into_inner();
    let r = ((raw >> 12) & 0x0F) as u8;
    let g = ((raw >> 7) & 0x0F) as u8;
    let b = ((raw >> 1) & 0x0F) as u8;
    (r, g, b)
}

/// Pack one pixel's RGB444 components into the framebuffer at `linear_idx`.
///
/// Two pixels share 3 bytes (ST7789 Interface II):
///   Even pixel (i%2==0): byte[base]   = R1G1, byte[base+1] upper nibble = B1
///   Odd pixel  (i%2==1): byte[base+1] lower nibble = R2, byte[base+2] = G2B2
#[cfg(target_arch = "arm")]
#[inline(always)]
fn pack_pixel_444(fb: &mut [u8], linear_idx: usize, r: u8, g: u8, b: u8) {
    let base = linear_idx / 2 * 3;
    if linear_idx % 2 == 0 {
        fb[base] = (r << 4) | g;
        fb[base + 1] = (fb[base + 1] & 0x0F) | (b << 4);
    } else {
        fb[base + 1] = (fb[base + 1] & 0xF0) | r;
        fb[base + 2] = (g << 4) | b;
    }
}

#[cfg(target_arch = "arm")]
impl OriginDimensions for St7789StatusDisplay {
    fn size(&self) -> Size {
        Size::new(LCD_WIDTH as u32, LCD_HEIGHT as u32)
    }
}

#[cfg(target_arch = "arm")]
impl DrawTarget for St7789StatusDisplay {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        // SAFETY: FRAMEBUF is only accessed from core0 display code; no concurrent access.
        let fb = unsafe { &mut *core::ptr::addr_of_mut!(FRAMEBUF) };
        for Pixel(coord, color) in pixels {
            if coord.x < 0
                || coord.y < 0
                || coord.x >= LCD_WIDTH as i32
                || coord.y >= LCD_HEIGHT as i32
            {
                continue;
            }
            let (r, g, b) = rgb565_to_rgb444(color);
            let linear = coord.y as usize * LCD_WIDTH as usize + coord.x as usize;
            pack_pixel_444(fb, linear, r, g, b);
        }
        Ok(())
    }

    fn fill_contiguous<I>(&mut self, area: &Rectangle, colors: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Self::Color>,
    {
        use embedded_graphics::geometry::Point;
        let disp = Rectangle::new(
            Point::zero(),
            Size::new(LCD_WIDTH as u32, LCD_HEIGHT as u32),
        );
        let area = area.intersection(&disp);
        if area.size.width == 0 || area.size.height == 0 {
            return Ok(());
        }

        // SAFETY: FRAMEBUF is only accessed from core0 display code; no concurrent access.
        let fb = unsafe { &mut *core::ptr::addr_of_mut!(FRAMEBUF) };
        let x0 = area.top_left.x as usize;
        let y0 = area.top_left.y as usize;
        let w = area.size.width as usize;

        let mut col = 0usize;
        let mut row = 0usize;
        for color in colors {
            if row >= area.size.height as usize {
                break;
            }
            let (r, g, b) = rgb565_to_rgb444(color);
            let linear = (y0 + row) * LCD_WIDTH as usize + (x0 + col);
            pack_pixel_444(fb, linear, r, g, b);
            col += 1;
            if col >= w {
                col = 0;
                row += 1;
            }
        }
        Ok(())
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Self::Color) -> Result<(), Self::Error> {
        use embedded_graphics::geometry::Point;
        let disp = Rectangle::new(
            Point::zero(),
            Size::new(LCD_WIDTH as u32, LCD_HEIGHT as u32),
        );
        let area = area.intersection(&disp);
        if area.size.width == 0 || area.size.height == 0 {
            return Ok(());
        }

        let (r, g, b) = rgb565_to_rgb444(color);

        // SAFETY: FRAMEBUF is only accessed from core0 display code; no concurrent access.
        let fb = unsafe { &mut *core::ptr::addr_of_mut!(FRAMEBUF) };
        let x0 = area.top_left.x as usize;
        let y0 = area.top_left.y as usize;
        let w = area.size.width as usize;
        let h = area.size.height as usize;
        for row in y0..(y0 + h) {
            for col in 0..w {
                let linear = row * LCD_WIDTH as usize + (x0 + col);
                pack_pixel_444(fb, linear, r, g, b);
            }
        }
        Ok(())
    }
}

// ─── Non-ARM stub ─────────────────────────────────────────────────────────────

#[cfg(not(target_arch = "arm"))]
impl St7789StatusDisplay {
    fn new_stub() -> Self {
        Self {
            current_status: LedStatus::Off,
        }
    }
}

#[cfg(not(target_arch = "arm"))]
impl LedController for St7789StatusDisplay {
    fn set_status(&mut self, status: LedStatus) {
        if self.current_status != status {
            self.current_status = status;
        }
    }
}

// ─── SPI bus type aliases ─────────────────────────────────────────────────────

/// Blocking SPI0 type for the RP2350-Geek (SD card bus in sdcard variant, unused in 16m).
/// `'static` lifetime: peripherals come from `embassy_rp::init()` which
/// returns `Peri<'static, ...>` tokens.
pub type Rp2350GeekSpi0 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Blocking>;

/// Async SPI1 type for the RP2350-Geek (LCD bus).
/// Async mode enables DMA-backed `flush()` that yields to the Embassy executor
/// during the ~13 ms 48 KB framebuffer transfer, preventing USB starvation.
/// Small command writes (1–5 bytes) still use `blocking_write()` which works
/// on an Async SPI bus without requiring an async context.
pub type Rp2350GeekSpi1 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Async>;

// ─── Board struct ─────────────────────────────────────────────────────────────

/// Concrete board representation for the Waveshare RP2350-Geek.
pub struct Rp2350GeekBoard {
    display: St7789StatusDisplay,
    // SPI1 is owned by St7789StatusDisplay (the LCD lives on SPI1).
    // The Board::spi1() accessor borrows it back from the display struct.
}

#[cfg(target_arch = "arm")]
impl Rp2350GeekBoard {
    /// Create the board with only the LCD on SPI1.
    ///
    /// For `rp2350_geek_sdcard`, SPI0 is consumed by the SD card keystore
    /// and is not part of the board struct.  For `rp2350_geek_16m`, SPI0
    /// is unused (no external flash chips on this board).
    ///
    /// The four LCD GPIO pins (DC=GPIO8, CS=GPIO9, RST=GPIO12, BL=GPIO25)
    /// are acquired inside this call via `AnyPin::steal()` — see the safety
    /// note on [`St7789StatusDisplay`].
    pub fn new(spi1: Rp2350GeekSpi1) -> Self {
        let display = St7789StatusDisplay::new(spi1);
        Self { display }
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
