//! Raspberry Pi Pico 2 board support (stock RP2350A, no external flash).
//!
//! Board variants:
//! - Pico 2 4MB (`pico2_4m` feature)
//!
//! # Hardware specifics
//! - Status LED: onboard GPIO 25 (simple GPIO, not WS2812B)
//! - SPI0: GPIO 18 (SCK), 19 (MOSI), 20 (MISO) — header pins, no flash attached
//!   Software CS lines: GPIO 17, 21, 22, 26
//! - SPI1: GPIO 10 (SCK), 11 (MOSI), 12 (MISO) — header pins, no flash attached
//!   Software CS lines: GPIO 9, 13, 14, 15
//!
//! # Notes
//! The stock Pico 2 has no external SPI flash chips. The SPI buses are
//! initialised on their standard header pins for bringup and testing, but
//! storage operations will fail gracefully (no devices on the bus).

#[cfg(feature = "pico2_4m")]
use super::Board;
use super::{LedController, LedStatus};

use embassy_rp::gpio::{Level, Output};

// ─── GPIO pin assignments ─────────────────────────────────────────────────────

/// Onboard LED pin (GPIO 25).
pub const LED_PIN: u8 = 25;

/// SPI0 SCK pin.
pub const SPI0_SCK: u8 = 18;
/// SPI0 MOSI pin.
pub const SPI0_MOSI: u8 = 19;
/// SPI0 MISO pin.
pub const SPI0_MISO: u8 = 20;
/// SPI0 software CS pins.
pub const SPI0_CS: [u8; 4] = [17, 21, 22, 26];

/// SPI1 SCK pin.
pub const SPI1_SCK: u8 = 10;
/// SPI1 MOSI pin.
pub const SPI1_MOSI: u8 = 11;
/// SPI1 MISO pin.
pub const SPI1_MISO: u8 = 12;
/// SPI1 software CS pins.
pub const SPI1_CS: [u8; 4] = [9, 13, 14, 15];

/// Conservative SPI frequency for bringup (no confirmed flash chips attached).
pub const SPI_FREQ_HZ: u32 = 10_000_000;

// ─── LED driver ──────────────────────────────────────────────────────────────

/// GPIO 25 onboard LED controller.
///
/// The Pico 2 has a single on/off LED. Any non-Off status lights it up.
/// The LED blinks to indicate different states via the on/off mapping:
/// - Off        → low
/// - Everything → high (on)
pub struct GpioLed {
    pin: Output<'static>,
}

impl GpioLed {
    pub fn new(pin: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_25>) -> Self {
        Self {
            pin: Output::new(pin, Level::Low),
        }
    }
}

impl LedController for GpioLed {
    fn set_status(&mut self, status: LedStatus) {
        match status {
            LedStatus::Off => {
                self.pin.set_low();
                defmt::debug!("Pico2 LED → off");
            }
            _ => {
                self.pin.set_high();
                defmt::debug!("Pico2 LED → on");
            }
        }
    }
}

// ─── SPI bus type aliases ─────────────────────────────────────────────────────

pub type Pico2Spi0 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Blocking>;
pub type Pico2Spi1 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>;

// ─── Board struct ─────────────────────────────────────────────────────────────

/// Concrete board representation for the stock Raspberry Pi Pico 2.
pub struct Pico2Board {
    led: GpioLed,
    pub spi0: Pico2Spi0,
    pub spi1: Pico2Spi1,
}

impl Pico2Board {
    /// Create a board from pre-constructed peripherals.
    pub fn new(
        led_pin: embassy_rp::Peri<'static, embassy_rp::peripherals::PIN_25>,
        spi0: Pico2Spi0,
        spi1: Pico2Spi1,
    ) -> Self {
        defmt::info!("Pico 2: board created (SPI0 + SPI1 @ {} Hz)", SPI_FREQ_HZ);
        Self {
            led: GpioLed::new(led_pin),
            spi0,
            spi1,
        }
    }
}

#[cfg(feature = "pico2_4m")]
impl Board for Pico2Board {
    type Led = GpioLed;
    type Spi0 = Pico2Spi0;
    type Spi1 = Pico2Spi1;

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
