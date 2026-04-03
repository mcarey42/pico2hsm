//! Waveshare RP2350-One board support.
//!
//! Board variants covered by this module:
//! - RP2350-One 4MB  (`rp2350_one_4m` feature)
//! - RP2350-One 16MB (`rp2350_one_16m` feature)
//!
//! # Hardware specifics
//! - Status LED: single WS2812B RGB LED on GPIO 16
//!   Driven via PIO state machine 0, state machine 0 using the
//!   embassy-rp `pio_programs::ws2812` helper.
//! - SPI0: GPIO 18 (SCK), 19 (MOSI), 20 (MISO) — keystore flash chips
//!   Software CS lines: GPIO 17, 21, 22, 26
//! - SPI1: GPIO 10 (SCK), 11 (MOSI), 12 (MISO) — RAID-1 mirror flash
//!   Software CS lines: GPIO 9, 13, 14, 15
//! - No SDCard slot on this board variant.
//!
//! # LED colour mapping
//! | `LedStatus`    | Colour (GRB) |
//! |----------------|--------------|
//! | Off            | (0,0,0)      |
//! | Ready          | (0,32,0)     |  dim green
//! | Busy           | (0,0,32)     |  dim blue
//! | Error          | (32,0,0)     |  dim red
//! | Degraded       | (16,16,0)    |  yellow
//! | Resyncing      | (0,16,16)    |  cyan
//! | WaitingForPin  | (0,0,64)     |  brighter blue
//!
//! # SPI frequency
//! Both buses are configured at 40 MHz for fast flash access.

// Always import shared types — Ws2812Led implements LedController unconditionally.
use super::{LedController, LedStatus};
// Board is only needed inside the feature-gated impl block.
#[cfg(any(feature = "rp2350_one_4m", feature = "rp2350_one_16m"))]
use super::Board;

// ─── GPIO pin assignments ─────────────────────────────────────────────────────

/// SPI0 SCK pin.
pub const SPI0_SCK: u8 = 18;
/// SPI0 MOSI pin.
pub const SPI0_MOSI: u8 = 19;
/// SPI0 MISO pin.
pub const SPI0_MISO: u8 = 20;
/// SPI0 software CS pins (up to 4 flash chips on bus 0).
pub const SPI0_CS: [u8; 4] = [17, 21, 22, 26];

/// SPI1 SCK pin.
pub const SPI1_SCK: u8 = 10;
/// SPI1 MOSI pin.
pub const SPI1_MOSI: u8 = 11;
/// SPI1 MISO pin.
pub const SPI1_MISO: u8 = 12;
/// SPI1 software CS pins (up to 4 flash chips on bus 1).
pub const SPI1_CS: [u8; 4] = [9, 13, 14, 15];

/// WS2812B data pin.
pub const WS2812_PIN: u8 = 16;

/// SPI bus frequency (40 MHz).
pub const SPI_FREQ_HZ: u32 = 40_000_000;

// ─── LED driver ──────────────────────────────────────────────────────────────

/// GRB colour tuple for a WS2812B pixel.
#[derive(Clone, Copy)]
struct Grb(u8, u8, u8); // (G, R, B)

impl Grb {
    const OFF: Self = Self(0, 0, 0);
    const READY: Self = Self(32, 0, 0);       // green
    const BUSY: Self = Self(0, 0, 32);        // blue
    const ERROR: Self = Self(0, 32, 0);       // red
    const DEGRADED: Self = Self(16, 16, 0);   // yellow  (G+R)
    const RESYNCING: Self = Self(16, 0, 16);  // cyan    (G+B)
    const WAITING: Self = Self(0, 0, 64);     // bright blue
}

/// WS2812B LED controller backed by a simple state variable.
///
/// # Implementation note
/// On hardware this would hold the PIO + DMA handle and call
/// `PioWs2812::write()` on each status update.  Until the PIO
/// peripheral is wired up in `Rp2350OneBoard::init()`, this struct
/// records the desired colour so that the rest of the firmware compiles
/// and the LED task can iterate without panicking.
///
/// TODO (board-bringup): Wire up PIO0 / DMA0 in `init()` and replace
/// the `_current` field with a real `PioWs2812<PIO0, 0, 1>` handle.
pub struct Ws2812Led {
    /// Last colour written — for logging / debugging.
    _current: Grb,
}

impl Ws2812Led {
    /// Construct a new (uninitialised) LED controller.
    fn new() -> Self {
        Self { _current: Grb::OFF }
    }

    fn set_color(&mut self, color: Grb) {
        self._current = color;
        // TODO: call self.ws2812.write(&[RGB8 { r: color.1, g: color.0, b: color.2 }]).await
        // once the PIO handle is stored here.
        defmt::debug!(
            "LED → G={} R={} B={}",
            color.0,
            color.1,
            color.2,
        );
    }
}

impl LedController for Ws2812Led {
    fn set_status(&mut self, status: LedStatus) {
        let color = match status {
            LedStatus::Off => Grb::OFF,
            LedStatus::Ready => Grb::READY,
            LedStatus::Busy => Grb::BUSY,
            LedStatus::Error => Grb::ERROR,
            LedStatus::Degraded => Grb::DEGRADED,
            LedStatus::Resyncing => Grb::RESYNCING,
            LedStatus::WaitingForPin => Grb::WAITING,
        };
        self.set_color(color);
    }
}

// ─── SPI bus type alias ───────────────────────────────────────────────────────

/// Blocking SPI bus type used for RP2350-One flash access.
///
/// SPI0 and SPI1 are both configured as `Blocking` mode drivers.
/// The `'static` lifetime reflects that `embassy_rp::Peripherals` fields
/// are `Peri<'static, ...>` when obtained from `embassy_rp::init()`.
/// Software chip-select is managed by the `SpiFlash` storage layer.
pub type Rp2350OneSpi0 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Blocking>;
pub type Rp2350OneSpi1 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>;

// ─── Board struct ─────────────────────────────────────────────────────────────

/// Concrete board representation for the Waveshare RP2350-One.
pub struct Rp2350OneBoard {
    led: Ws2812Led,
    pub spi0: Rp2350OneSpi0,
    pub spi1: Rp2350OneSpi1,
}

impl Rp2350OneBoard {
    /// Create a board from pre-constructed SPI buses.
    ///
    /// The caller is responsible for constructing the SPI buses with the
    /// correct pin assignments and frequency before calling this function.
    /// The LED controller starts in the `Off` state.
    pub fn new(spi0: Rp2350OneSpi0, spi1: Rp2350OneSpi1) -> Self {
        defmt::info!("RP2350-One: board created (SPI0 + SPI1 @ {} Hz)", SPI_FREQ_HZ);
        Self { led: Ws2812Led::new(), spi0, spi1 }
    }
}

#[cfg(any(feature = "rp2350_one_4m", feature = "rp2350_one_16m"))]
impl Board for Rp2350OneBoard {
    type Led = Ws2812Led;
    type Spi0 = Rp2350OneSpi0;
    type Spi1 = Rp2350OneSpi1;

    fn led(&mut self) -> &mut Self::Led {
        &mut self.led
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

// ─── Legacy free function (kept for source compat with old stubs) ─────────────

/// Set the WS2812B LED colour on GPIO 16.
///
/// This is a legacy compatibility shim kept to avoid breaking any code
/// that calls `rp2350_one::set_led(color)` directly.
/// Prefer using the `Board::led()` accessor instead.
pub async fn set_led(_color: super::LedColor) {
    // Colour is logged inside Ws2812Led::set_color via defmt.
    // Full PIO implementation is tracked in the TODO inside Ws2812Led.
}
