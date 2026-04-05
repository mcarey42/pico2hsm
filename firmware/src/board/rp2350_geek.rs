//! Waveshare RP2350-Geek board support.
//!
//! Board variants covered by this module:
//! - RP2350-Geek 16MB               (`rp2350_geek_16m` feature)
//! - RP2350-Geek with SDCard        (`rp2350_geek_sdcard` feature)
//! - RP2350-Geek with dual SDCard   (`rp2350_geek_sdcard_dual` feature)
//!
//! # Hardware specifics
//! - MCU: RP2350A @ 150 MHz
//! - External flash: 16 MB on QSPI
//! - Status display: 1.14" SPI ST7789 LCD on SPI1 (135×240 px, landscape 240×135)
//!   ST7789 is a write-only display: data flows MOSI only, MISO unused.
//!   Display uses COLMOD=0x55 (16-bit RGB565) with colour inversion (INVON).
//!   Visible area is 240×135 with column offset 52 and row offset 40.
//! - SPI1 LCD pins: SCK=GPIO10, MOSI=GPIO11
//!   DC=GPIO8, CS=GPIO9, RST=GPIO12, BL=GPIO25
//! - SPI0 pins: SCK=GPIO18, MOSI=GPIO19, MISO=GPIO20
//!   CS[0..3] = GPIO17, GPIO21, GPIO22, GPIO26 (keystore flash chips)
//! - SPI1 also: CS[1..3] = GPIO13, GPIO14, GPIO15 (mirror flash, beyond LCD CS=GPIO9)
//! - SDCard slot CS: GPIO5 (first card)
//! - Second SDCard CS: GPIO4 (dual-SDCard variant only, `rp2350_geek_sdcard_dual`)
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
//! SWRESET → delay 150 ms → SLPOUT → delay 255 ms → COLMOD(0x55 = RGB565) →
//! MADCTL(0x70 = landscape, BGR) → CASET(52..291) → RASET(40..174) →
//! INVON → NORON → DISPON.
//!
//! # SPI frequency
//! SPI0 (flash) is configured at 40 MHz.
//! SPI1 (LCD) is configured at 30 MHz (conservative for ST7789; can reach 62.5 MHz).

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

/// SPI0 SCK pin (shared with keystore flash).
pub const SPI0_SCK: u8 = 18;
/// SPI0 MOSI pin.
pub const SPI0_MOSI: u8 = 19;
/// SPI0 MISO pin.
pub const SPI0_MISO: u8 = 20;
/// SPI0 software CS pins — keystore flash chips.
pub const SPI0_CS: [u8; 4] = [17, 21, 22, 26];

/// SPI1 SCK pin (shared with LCD SCK).
pub const SPI1_SCK: u8 = LCD_SCK_PIN;
/// SPI1 MOSI pin (shared with LCD MOSI).
pub const SPI1_MOSI: u8 = LCD_MOSI_PIN;
/// SPI1 MISO pin (unused for LCD; available for SD or mirror flash if needed).
pub const SPI1_MISO: u8 = 24;
/// SPI1 software CS pins — LCD CS is GPIO9; extra CS slots for mirror flash.
pub const SPI1_CS: [u8; 4] = [9, 13, 14, 15];

/// SD-Card slot 0 chip-select pin.
pub const SDCARD0_CS: u8 = 5;

/// SD-Card slot 1 chip-select pin (dual-SDCard variant only).
#[cfg(feature = "rp2350_geek_sdcard_dual")]
pub const SDCARD1_CS: u8 = 4;

/// SPI0 frequency — flash chips at 40 MHz.
pub const SPI_FREQ_HZ: u32 = 40_000_000;
/// SPI1 / LCD frequency — ST7789 at 30 MHz (conservative; rated up to 62.5 MHz).
pub const LCD_SPI_FREQ_HZ: u32 = 30_000_000;

// ─── ST7789 register constants ────────────────────────────────────────────────

const ST7789_SWRESET: u8 = 0x01;
const ST7789_SLPOUT: u8  = 0x11;
const ST7789_NORON: u8   = 0x13;
const ST7789_INVON: u8   = 0x21;
const ST7789_DISPON: u8  = 0x29;
const ST7789_CASET: u8   = 0x2A;
const ST7789_RASET: u8   = 0x2B;
const ST7789_RAMWR: u8   = 0x2C;
const ST7789_MADCTL: u8  = 0x36;
const ST7789_COLMOD: u8  = 0x3A;

/// Display physical dimensions (landscape orientation after MADCTL rotation).
/// The ST7789 in the RP2350-Geek is a 240×135 panel mounted landscape.
/// CASET range: 52..(52+240-1) = 52..291
/// RASET range: 40..(40+135-1) = 40..174
const LCD_WIDTH: u16  = 240;
const LCD_HEIGHT: u16 = 135;
const LCD_COL_OFFSET: u16 = 52;
const LCD_ROW_OFFSET: u16 = 40;

/// Cortex-M33 at 150 MHz: ~150_000 cycles per millisecond.
/// Using a generous constant to ensure minimum timing even if clock is lower.
const CYCLES_PER_MS: u32 = 150_000;

// ─── LED / display driver ─────────────────────────────────────────────────────

/// ST7789 status display driver for the Waveshare RP2350-Geek.
///
/// Drives the 1.14" 240×135 ST7789 LCD over SPI1.  On each `set_status()`
/// call the entire screen is filled with a solid RGB565 colour that encodes
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
        let dc  = Output::new(unsafe { AnyPin::steal(LCD_DC_PIN) },  Level::Low);
        let cs  = Output::new(unsafe { AnyPin::steal(LCD_CS_PIN) },  Level::High); // deasserted
        let rst = Output::new(unsafe { AnyPin::steal(LCD_RST_PIN) }, Level::High); // not in reset
        let bl  = Output::new(unsafe { AnyPin::steal(LCD_BL_PIN) },  Level::Low);  // backlight off

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

    /// Run the full ST7789 hardware-reset + init sequence.
    ///
    /// Sequence:
    /// 1. Hardware reset pulse (RST low 10 ms, high 150 ms)
    /// 2. SWRESET + 150 ms
    /// 3. SLPOUT + 255 ms
    /// 4. COLMOD = 0x55 (16-bit RGB565)
    /// 5. MADCTL = 0x70 (landscape, MX+MV, BGR colour order for ST7789)
    /// 6. CASET = 52..291  (column window for 240 px wide display)
    /// 7. RASET = 40..174  (row window for 135 px tall display)
    /// 8. INVON (colour inversion — required for correct colours on ST7789)
    /// 9. NORON (normal display mode)
    /// 10. DISPON (display on) + backlight enable
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

        // 16-bit RGB565 colour format
        defmt::info!("ST7789: COLMOD 0x55 (RGB565)...");
        self.write_command_data(ST7789_COLMOD, &[0x55]);
        self.delay_ms(10);

        // Memory Access Control:
        //   MX=1 (column mirror) | MV=1 (row/col exchange = 90° rotation) | BGR=1
        //   = 0b0111_0000 = 0x70
        // This puts the display in landscape orientation (240 wide × 135 tall).
        defmt::info!("ST7789: MADCTL 0x70 (landscape)...");
        self.write_command_data(ST7789_MADCTL, &[0x70]);

        // Column address set: 52 to 291 (52 + 240 - 1)
        let col_start = LCD_COL_OFFSET;
        let col_end   = LCD_COL_OFFSET + LCD_WIDTH - 1;
        defmt::info!("ST7789: CASET {}..{}...", col_start, col_end);
        self.write_command_data(ST7789_CASET, &[
            (col_start >> 8) as u8,
            (col_start & 0xFF) as u8,
            (col_end   >> 8) as u8,
            (col_end   & 0xFF) as u8,
        ]);

        // Row address set: 40 to 174 (40 + 135 - 1)
        let row_start = LCD_ROW_OFFSET;
        let row_end   = LCD_ROW_OFFSET + LCD_HEIGHT - 1;
        defmt::info!("ST7789: RASET {}..{}...", row_start, row_end);
        self.write_command_data(ST7789_RASET, &[
            (row_start >> 8) as u8,
            (row_start & 0xFF) as u8,
            (row_end   >> 8) as u8,
            (row_end   & 0xFF) as u8,
        ]);

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

    /// Fill the entire display with a solid RGB565 colour.
    ///
    /// Sends 240 × 135 = 32 400 pixels in 64 800 bytes (two bytes per pixel).
    /// To avoid a 64 KB stack allocation, pixels are written in 240-pixel
    /// (480-byte) row chunks that fit comfortably in the call stack.
    fn fill_screen(&mut self, color: u16) {
        // Re-assert the column and row windows before RAMWR in case they were
        // disturbed by a previous partial write.
        let col_start = LCD_COL_OFFSET;
        let col_end   = LCD_COL_OFFSET + LCD_WIDTH - 1;
        let row_start = LCD_ROW_OFFSET;
        let row_end   = LCD_ROW_OFFSET + LCD_HEIGHT - 1;

        self.write_command_data(ST7789_CASET, &[
            (col_start >> 8) as u8,
            (col_start & 0xFF) as u8,
            (col_end   >> 8) as u8,
            (col_end   & 0xFF) as u8,
        ]);
        self.write_command_data(ST7789_RASET, &[
            (row_start >> 8) as u8,
            (row_start & 0xFF) as u8,
            (row_end   >> 8) as u8,
            (row_end   & 0xFF) as u8,
        ]);

        // Begin RAM write
        self.dc.set_low();
        self.cs_assert();
        let _ = self.spi.blocking_write(&[ST7789_RAMWR]);
        self.dc.set_high();

        // Write rows one at a time — 480 bytes per row (240 pixels × 2 bytes).
        // This keeps stack usage at ~480 bytes rather than ~65 KB.
        let hi = (color >> 8) as u8;
        let lo = (color & 0xFF) as u8;
        let mut row_buf = [0u8; (LCD_WIDTH as usize) * 2];
        for i in 0..(LCD_WIDTH as usize) {
            row_buf[i * 2]     = hi;
            row_buf[i * 2 + 1] = lo;
        }
        for _ in 0..LCD_HEIGHT {
            let _ = self.spi.blocking_write(&row_buf);
        }

        self.cs_deassert();
    }

    /// Map a `LedStatus` to an RGB565 colour for the status screen.
    fn status_color(status: LedStatus) -> u16 {
        match status {
            LedStatus::Off          => 0x0000, // black
            LedStatus::Ready        => 0x07E0, // green
            LedStatus::Busy         => 0x001F, // blue
            LedStatus::Error        => 0xF800, // red
            LedStatus::Degraded     => 0xFFE0, // yellow
            LedStatus::Resyncing    => 0x07FF, // cyan
            LedStatus::WaitingForPin=> 0x031F, // bright blue (slightly lighter)
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
            defmt::info!(
                "LCD status: {:?} → color=0x{:04X}",
                defmt::Debug2Format(&status),
                color
            );
            self.fill_screen(color);
        }
    }
}

// ─── Non-ARM stub ─────────────────────────────────────────────────────────────

#[cfg(not(target_arch = "arm"))]
impl St7789StatusDisplay {
    fn new_stub() -> Self {
        Self { current_status: LedStatus::Off }
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

/// Blocking SPI0 type for the RP2350-Geek (flash bus).
/// `'static` lifetime: peripherals come from `embassy_rp::init()` which
/// returns `Peri<'static, ...>` tokens.
pub type Rp2350GeekSpi0 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Blocking>;

/// Blocking SPI1 type for the RP2350-Geek (LCD bus).
pub type Rp2350GeekSpi1 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>;

// ─── Board struct ─────────────────────────────────────────────────────────────

/// Concrete board representation for the Waveshare RP2350-Geek.
pub struct Rp2350GeekBoard {
    display: St7789StatusDisplay,
    pub spi0: Rp2350GeekSpi0,
    // SPI1 is owned by St7789StatusDisplay (the LCD lives on SPI1).
    // The Board::spi1() accessor borrows it back from the display struct.
}

#[cfg(target_arch = "arm")]
impl Rp2350GeekBoard {
    /// Create a board from pre-constructed SPI buses.
    ///
    /// SPI0 is the keystore flash bus.
    /// SPI1 is taken by the LCD driver — the `Board::spi1()` accessor
    /// returns a mutable reference to it via the display struct.
    ///
    /// The four LCD GPIO pins (DC=GPIO8, CS=GPIO9, RST=GPIO12, BL=GPIO25)
    /// are acquired inside this call via `AnyPin::steal()` — see the safety
    /// note on [`St7789StatusDisplay`].
    pub fn new(spi0: Rp2350GeekSpi0, spi1: Rp2350GeekSpi1) -> Self {
        defmt::info!(
            "RP2350-Geek: board init (SPI0 flash @ {} Hz, SPI1 LCD @ {} Hz)",
            SPI_FREQ_HZ,
            LCD_SPI_FREQ_HZ,
        );
        let display = St7789StatusDisplay::new(spi1);
        defmt::info!("RP2350-Geek: ST7789 LCD ready");
        Self { display, spi0 }
    }
}

#[cfg(not(target_arch = "arm"))]
impl Rp2350GeekBoard {
    // Stub constructor used only when compiling for the test host (x86_64).
    // On the host there are no real SPI peripherals; unit tests instantiate
    // the board by other means.  This constructor is never called in practice
    // (the feature-gated Board impl is also absent on non-ARM) but it keeps
    // the type resolvable during `cargo test`.
    #[allow(dead_code)]
    fn _new_stub() -> Self {
        Self { display: St7789StatusDisplay::new_stub(), spi0: unimplemented!() }
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

    /// Return a mutable reference to the SPI1 bus, which is owned by the
    /// LCD display driver.  Callers that need to use SPI1 directly (e.g.,
    /// a mirror-flash storage layer) must coordinate with the LCD driver
    /// to avoid concurrent access — the LCD deasserts CS after each frame,
    /// so SPI1 is safe to borrow between renders.
    fn spi1(&mut self) -> &mut Self::Spi1 {
        #[cfg(target_arch = "arm")]
        return &mut self.display.spi;
        #[cfg(not(target_arch = "arm"))]
        unimplemented!("spi1 not available on non-ARM test build")
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
/// On the RP2350-Geek, the LCD is initialised inside `Rp2350GeekBoard::new()`;
/// this free function is retained for source compatibility with any code that
/// calls `rp2350_geek::init_lcd()` directly.
pub async fn init_lcd() {
    defmt::info!("init_lcd(): ST7789 init is handled by Rp2350GeekBoard::new()");
}

/// Update the LCD status display.
///
/// Full colour-coded status screens are rendered by `LedController::set_status()`.
/// This free function is retained for source compatibility.
pub async fn update_status_display(_state: DisplayState) {
    defmt::trace!("update_status_display(): use Board::led().set_status() instead");
}
