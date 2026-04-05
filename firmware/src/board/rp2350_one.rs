//! Waveshare RP2350-One board support.
//!
//! Board variants covered by this module:
//! - RP2350-One 4MB  (`rp2350_one_4m` feature)
//! - RP2350-One 16MB (`rp2350_one_16m` feature)
//!
//! # Hardware specifics
//! - Status LED: single WS2812B RGB LED on GPIO 16
//!   Driven via PIO0 state machine 0.  The WS2812 bit-bang PIO program is
//!   assembled inline (mirroring `embassy_rp::pio_programs::ws2812`) and
//!   loaded at board init.  LED writes are synchronous (spin-wait on TX FIFO
//!   + cycle-count reset delay) so that `LedController::set_status()` remains
//!   a plain `&mut self` method with no async overhead.
//! - SPI0: GPIO 18 (SCK), 19 (MOSI), 20 (MISO) — keystore flash chips
//!   Software CS lines: GPIO 17, 21, 22, 26
//! - SPI1: GPIO 10 (SCK), 11 (MOSI), 12 (MISO) — RAID-1 mirror flash
//!   Software CS lines: GPIO 9, 13, 14, 15
//! - No SDCard slot on this board variant.
//!
//! # LED colour mapping
//! | `LedStatus`    | Colour (R, G, B) |
//! |----------------|------------------|
//! | Off            | (0, 0, 0)        |
//! | Ready          | (0, 32, 0)       | dim green
//! | Busy           | (0, 0, 32)       | dim blue
//! | Error          | (32, 0, 0)       | dim red
//! | Degraded       | (16, 16, 0)      | yellow
//! | Resyncing      | (0, 16, 16)      | cyan
//! | WaitingForPin  | (0, 0, 64)       | brighter blue
//!
//! # WS2812B PIO resource usage
//! - **PIO0** — stolen at board init via `peripherals::PIO0::steal()`.
//!   No other peripheral in this firmware build uses PIO0.
//! - **PIO0 SM0** — runs the WS2812 bit-bang program continuously.
//! - **GPIO 16** — configured as PIO0 side-set output; driven by SM0.
//! - **DMA** — NOT used.  The single-pixel write fits in the 4-word TX FIFO;
//!   `StateMachineTx::push()` is used for a fully synchronous write.
//!
//! # SPI frequency
//! Both buses are configured at 40 MHz for fast flash access.
//!
//! # External SD card wiring (no built-in slot)
//! The RP2350-One has no SD card slot.  An external SPI SD card module can be
//! wired to any free GPIOs.  Recommended assignment (GPIOs not used by SPI0/1
//! or the WS2812B LED):
//!
//! | SD card signal | RP2350-One GPIO | Note                     |
//! |----------------|-----------------|--------------------------|
//! | CLK / SCK      | GPIO 6          | SPI0-capable (not SPI0)  |
//! | CMD / MOSI     | GPIO 7          |                          |
//! | DAT0 / MISO    | GPIO 4          |                          |
//! | CS / DAT3      | GPIO 5          | `SDCARD_CS` constant     |
//! | 3V3            | 3V3 (pin 36)    |                          |
//! | GND            | GND             |                          |
//!
//! See [`SDCARD_CS`], [`SDCARD_SCK`], [`SDCARD_MOSI`], [`SDCARD_MISO`].

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

/// WS2812B data pin — GPIO 16.
pub const WS2812_PIN: u8 = 16;

/// Recommended external SD card chip-select pin (free GPIO, not used by SPI0/SPI1).
pub const SDCARD_CS: u8 = 5;
/// Recommended external SD card SPI clock pin.
pub const SDCARD_SCK: u8 = 6;
/// Recommended external SD card MOSI pin.
pub const SDCARD_MOSI: u8 = 7;
/// Recommended external SD card MISO pin.
pub const SDCARD_MISO: u8 = 4;

/// SPI bus frequency (40 MHz).
pub const SPI_FREQ_HZ: u32 = 40_000_000;

// ─── LED driver ──────────────────────────────────────────────────────────────

/// WS2812B bit timing constants.
///
/// The PIO program uses T1=2, T2=5, T3=3 cycles per bit-phase, giving
/// 10 cycles/bit total at 800 kHz, i.e. the PIO clock runs at 8 MHz.
///
/// At 150 MHz system clock: divider ≈ 18.75 → PIO clock = 8.0 MHz.
///
/// | Symbol | PIO cycles | Duration    |
/// |--------|-----------|-------------|
/// | T0H    | 2          | 250 ns      |
/// | T0L    | 8          | 1 000 ns    |
/// | T1H    | 7          | 875 ns      |
/// | T1L    | 3          | 375 ns      |
///
/// These values satisfy the WS2812B specification (T0H 220–380 ns,
/// T0L 580–1 000 ns, T1H 580–1 000 ns, T1L 220–420 ns).
///
/// Reset period: ≥ 50 µs.  The driver waits 100 µs via `cortex_m::asm::delay`
/// (15 000 cycles at 150 MHz) after each pixel write.
///
/// # Wire colour order
/// WS2812B uses **GRB** on the wire.  The PIO TX FIFO expects:
/// `(G << 24) | (R << 16) | (B << 8)` in each 32-bit word.
pub mod timing {
    /// WS2812B wire frequency in Hz.
    pub const FREQ_HZ: u32 = 800_000;
    /// PIO cycles per bit (T1 + T2 + T3 = 2 + 5 + 3).
    pub const CYCLES_PER_BIT: u32 = 10;
    /// Reset period in microseconds (minimum 50 µs; 100 µs for margin).
    pub const RESET_US: u32 = 100;
    /// CPU cycles for reset at 150 MHz.  `cortex_m::asm::delay` counts
    /// CPU cycles (each iteration ≥ 3 cycles on Cortex-M33).
    /// Actual delay = RESET_CYCLES / cpu_freq; the WS2812B tolerates any
    /// reset ≥ 50 µs so being too long is harmless.
    pub const RESET_CYCLES: u32 = 150 * RESET_US; // 15 000
}

/// RGB colour stored in component order; packed into GRB on the wire.
#[derive(Clone, Copy)]
struct RgbColor { r: u8, g: u8, b: u8 }

impl RgbColor {
    const fn new(r: u8, g: u8, b: u8) -> Self { Self { r, g, b } }
    const OFF:      Self = Self::new(0, 0, 0);
    const READY:    Self = Self::new(0, 32, 0);    // dim green
    const BUSY:     Self = Self::new(0, 0, 32);    // dim blue
    const ERROR:    Self = Self::new(32, 0, 0);    // dim red
    const DEGRADED: Self = Self::new(16, 16, 0);   // yellow (R + G)
    const RESYNCING:Self = Self::new(0, 16, 16);   // cyan   (G + B)
    const WAITING:  Self = Self::new(0, 0, 64);    // bright blue
}

// ─── ARM-specific PIO handle ──────────────────────────────────────────────────

/// PIO0 state machine 0 handle, held at `'static` lifetime after stealing PIO0.
///
/// Only present on ARM targets.  On x86_64 (unit-test builds) `Ws2812Led`
/// falls back to a defmt-only stub.
#[cfg(target_arch = "arm")]
struct Ws2812Pio {
    sm: embassy_rp::pio::StateMachine<'static, embassy_rp::peripherals::PIO0, 0>,
}

/// `StaticCell` holding the PIO0 `Common` (instruction-memory book-keeper).
///
/// `Common` is moved here so that it lives for `'static`, satisfying the
/// lifetime bounds on `LoadedProgram<'static, PIO0>`.  The cell is
/// initialised exactly once in `Ws2812Led::new()`.
#[cfg(target_arch = "arm")]
static PIO0_COMMON_CELL: static_cell::StaticCell<
    embassy_rp::pio::Common<'static, embassy_rp::peripherals::PIO0>
> = static_cell::StaticCell::new();

/// `StaticCell` holding the `LoadedProgram` for the WS2812 PIO program.
///
/// The program bytes are written to PIO0 instruction memory during init.
/// The `LoadedProgram` struct must stay alive to keep the instruction-memory
/// tracking in `Common` consistent (even though the hardware retains the
/// opcodes regardless).
#[cfg(target_arch = "arm")]
static WS2812_LOADED_PROGRAM_CELL: static_cell::StaticCell<
    embassy_rp::pio::LoadedProgram<'static, embassy_rp::peripherals::PIO0>
> = static_cell::StaticCell::new();

/// WS2812B LED controller for the Waveshare RP2350-One.
///
/// # ARM implementation
/// Owns `PIO0 SM0` (`StateMachine<'static, PIO0, 0>`).  PIO0 and GPIO 16 are
/// **stolen** during [`Ws2812Led::new`] — callers must ensure that no other
/// code claims these resources after this point (see safety note there).
///
/// [`set_color`] writes one pixel synchronously:
/// 1. Packs (r, g, b) into a u32 in GRB order at bits [31:8].
/// 2. Spin-waits for TX FIFO not-full.
/// 3. Pushes the word — PIO SM0 shifts it out at 800 kHz.
/// 4. Waits `timing::RESET_CYCLES` CPU cycles for the WS2812B reset period.
///
/// # x86_64 / test build
/// On non-ARM targets the struct is a pure defmt-log stub.
pub struct Ws2812Led {
    /// Last colour written — used to suppress no-op writes.
    current: RgbColor,
    /// PIO state machine handle (ARM only).
    #[cfg(target_arch = "arm")]
    pio: Ws2812Pio,
}

impl Ws2812Led {
    /// Initialise the WS2812B LED driver.
    ///
    /// On ARM: steals `PIO0` and `PIN_16`, assembles and loads the WS2812
    /// PIO program into PIO0 instruction memory, configures SM0, and enables
    /// the state machine.
    ///
    /// # Safety (ARM targets)
    /// Calls `embassy_rp::peripherals::{PIO0, PIN_16}::steal()`.
    /// Safe provided that `p.PIO0` and `p.PIN_16` from `embassy_rp::init()`
    /// have NOT been consumed by any other code.  In the `run_one_board` path
    /// in `main.rs` only SPI0, SPI1, USB, CORE1, and TRNG tokens are taken;
    /// PIO0 and PIN_16 are deliberately left unclaimed.
    pub fn new() -> Self {
        #[cfg(target_arch = "arm")]
        {
            Self::init_arm()
        }

        #[cfg(not(target_arch = "arm"))]
        Self { current: RgbColor::OFF }
    }

    /// ARM-only initialisation (kept in a separate method to avoid deep nesting).
    #[cfg(target_arch = "arm")]
    fn init_arm() -> Self {
        use embassy_rp::pio::{
            Config, FifoJoin, Pio, ShiftConfig, ShiftDirection,
        };
        use embassy_rp::clocks::clk_sys_freq;

        // ── Steal PIO0 and PIN_16 ─────────────────────────────────────────────
        //
        // SAFETY: Only called once; PIO0 / PIN_16 are not taken by main.rs.
        let pio0_peri = unsafe { embassy_rp::peripherals::PIO0::steal() };
        let pin16     = unsafe { embassy_rp::peripherals::PIN_16::steal() };

        // ── Satisfy the Binding trait bound required by Pio::new() ───────────
        //
        // `bind_interrupts!` in main.rs cannot be modified.  We provide a
        // zero-size type that manually implements the compile-time `Binding`
        // marker for PIO0_IRQ_0 → PIO0 InterruptHandler.
        //
        // The PIO0_IRQ_0 interrupt is enabled in NVIC by `Pio::new()`, but
        // no `irqs.inte()` bits are ever set (we use synchronous `push()` not
        // async `wait_push()`), so the interrupt never fires and the absence
        // of a linked ISR vector is harmless (cortex-m-rt DefaultHandler is
        // used as the fallback).
        #[derive(Copy, Clone)]
        struct PioIrqBinding;
        // SAFETY: We are the exclusive owner of PIO0; no other code holds a
        // Pio<PIO0> or calls enable() on PIO0_IRQ_0 concurrently.
        unsafe impl embassy_rp::interrupt::typelevel::Binding<
            embassy_rp::interrupt::typelevel::PIO0_IRQ_0,
            embassy_rp::pio::InterruptHandler<embassy_rp::peripherals::PIO0>,
        > for PioIrqBinding {}

        // ── Construct the Pio peripheral (splits PIO0 into Common + SMs) ─────
        let Pio { mut common, sm0, .. } = Pio::new(pio0_peri, PioIrqBinding);

        // ── Assemble the WS2812 PIO program ───────────────────────────────────
        //
        // Program adapted from embassy-rp/src/pio_programs/ws2812.rs.
        // T1=2 (start), T2=5 (data), T3=3 (stop) cycles per bit phase.
        // Side-set drives the output pin high/low per phase.
        //
        // `pio` is re-exported by embassy-rp as `embassy_rp::pio::program`
        // (see `pub use pio as program;` in embassy-rp/src/pio/mod.rs).
        let program = {
            use embassy_rp::pio::program::{
                Assembler, JmpCondition, OutDestination, SetDestination, SideSet,
            };
            const T1: u8 = 2;
            const T2: u8 = 5;
            const T3: u8 = 3;

            let side_set = SideSet::new(false, 1, false);
            let mut a: Assembler<32> = Assembler::new_with_side_set(side_set);

            let mut wrap_target = a.label();
            let mut wrap_source = a.label();
            let mut do_zero     = a.label();

            a.set_with_side_set(SetDestination::PINDIRS, 1, 0);
            a.bind(&mut wrap_target);
            // Stop bit: de-assert side-set, shift next bit out
            a.out_with_delay_and_side_set(OutDestination::X, 1, T3 - 1, 0);
            // Start bit: assert side-set; branch on X==0 → zero pulse
            a.jmp_with_delay_and_side_set(JmpCondition::XIsZero, &mut do_zero, T1 - 1, 1);
            // Data=1: side stays high through T2-1 then loops
            a.jmp_with_delay_and_side_set(JmpCondition::Always, &mut wrap_target, T2 - 1, 1);
            a.bind(&mut do_zero);
            // Data=0: side goes low through T2-1
            a.nop_with_delay_and_side_set(T2 - 1, 0);
            a.bind(&mut wrap_source);

            a.assemble_with_wrap(wrap_source, wrap_target)
        };

        // Load the assembled program into PIO0 instruction memory.
        let loaded = common.load_program(&program);

        // ── Configure SM0 ─────────────────────────────────────────────────────
        let mut cfg = Config::default();

        // GPIO 16 as the side-set output pin.
        let out_pin = common.make_pio_pin(pin16);
        cfg.set_out_pins(&[&out_pin]);
        cfg.set_set_pins(&[&out_pin]);
        cfg.use_program(&loaded, &[&out_pin]);

        // Clock divider: target 8 MHz PIO clock (= 800 kHz × 10 cycles/bit).
        //
        // We avoid a direct `fixed` crate dependency (it's only a transitive
        // dep via embassy-rp) by computing the divider using integer arithmetic
        // and writing the PIO SM CLKDIV register through the PAC directly after
        // sm.set_config() leaves it at the default of 1.
        //
        // Formula: divider = clk_sys_freq / (FREQ_HZ × CYCLES_PER_BIT)
        //   int_part = divider (integer)
        //   frac_part = (remainder * 256) / divisor   (8-bit fraction)
        //
        // At 150 MHz: divisor = 8_000_000, int = 18, rem = 6_000_000
        //             frac = (6_000_000 * 256) / 8_000_000 = 192 → divider ≈ 18.75
        //
        // The clock_divider field in Config uses the `fixed` crate which is only
        // a transitive dep; we leave it at default (1.0) and override via PAC.
        // The override is applied immediately after sm.set_config() below.
        let pio_divisor = timing::FREQ_HZ * timing::CYCLES_PER_BIT; // 8_000_000
        let sys_freq    = clk_sys_freq();
        let clkdiv_int  = sys_freq / pio_divisor;
        let clkdiv_frac = ((sys_freq % pio_divisor) as u64 * 256 / pio_divisor as u64) as u8;

        // TX FIFO only; 24-bit auto-shift left.
        cfg.fifo_join = FifoJoin::TxOnly;
        cfg.shift_out = ShiftConfig {
            auto_fill:  true,
            threshold:  24,
            direction:  ShiftDirection::Left,
        };

        let mut sm0 = sm0;
        sm0.set_config(&cfg);

        // Override the clock divider computed above.
        // The PAC CLKDIV register layout: bits[31:16] = INT, bits[15:8] = FRAC.
        // `set_config` leaves CLKDIV at 1.0; we now write the real value.
        // SAFETY: We own SM0 exclusively; no concurrent access to this register.
        unsafe {
            embassy_rp::pac::PIO0.sm(0).clkdiv().write(|w| {
                w.set_int(clkdiv_int as u16);
                w.set_frac(clkdiv_frac);
            });
        }

        sm0.set_enable(true);

        // ── Keep Common and LoadedProgram alive in StaticCells ────────────────
        //
        // `common` must not be dropped: its Drop impl calls `on_pio_drop` which
        // decrements the PIO user count.  Store it in a StaticCell so its
        // destructor never runs.
        //
        // `loaded` must not be dropped either: its InstanceMemory tracks which
        // PIO instruction slots are occupied.  This matters if any other code
        // ever calls `Common::load_program` again (it won't in our firmware,
        // but keeping it alive is the correct pattern).
        let _ = PIO0_COMMON_CELL.init(common);
        let _ = WS2812_LOADED_PROGRAM_CELL.init(loaded);

        defmt::info!(
            "RP2350-One: WS2812B ready — PIO0/SM0 on GPIO{} @ 800 kHz (sync)",
            WS2812_PIN,
        );

        Self {
            current: RgbColor::OFF,
            pio: Ws2812Pio { sm: sm0 },
        }
    }

    /// Write a single colour to the WS2812B LED.
    ///
    /// Packs `color` into a GRB u32, spin-waits for TX FIFO not-full,
    /// pushes the word, then delays for the WS2812B reset period.
    fn set_color(&mut self, color: RgbColor) {
        self.current = color;

        #[cfg(target_arch = "arm")]
        {
            // GRB wire order: G[31:24] R[23:16] B[15:8] (zeros at [7:0]).
            // PIO shift_out auto_fill with threshold=24 and direction=Left
            // sends bit 31 first, consuming exactly 24 bits per word.
            let grb: u32 = (u32::from(color.g) << 24)
                         | (u32::from(color.r) << 16)
                         | (u32::from(color.b) << 8);

            // Spin-wait for TX FIFO not-full.
            // With threshold=24 and a 4-entry TX FIFO (TxOnly doubles to 8),
            // and only one pixel per call, this is essentially always
            // immediate — the SM empties the previous word in ~30 µs.
            while self.pio.sm.tx().full() {
                cortex_m::asm::nop();
            }

            // Push the packed GRB word into the TX FIFO.
            // The PIO SM shifts it out at 800 kHz over 30 µs.
            self.pio.sm.tx().push(grb);

            // Wait for the WS2812B reset period (≥ 50 µs low on data line).
            // cortex_m::asm::delay(n) busy-waits for n CPU cycles.
            // At 150 MHz: RESET_CYCLES = 15 000 → 100 µs.
            cortex_m::asm::delay(timing::RESET_CYCLES);
        }

        #[cfg(not(target_arch = "arm"))]
        defmt::debug!(
            "LED (stub) → R={} G={} B={}",
            color.r, color.g, color.b,
        );
    }
}

impl LedController for Ws2812Led {
    fn set_status(&mut self, status: LedStatus) {
        let color = match status {
            LedStatus::Off          => RgbColor::OFF,
            LedStatus::Ready        => RgbColor::READY,
            LedStatus::Busy         => RgbColor::BUSY,
            LedStatus::Error        => RgbColor::ERROR,
            LedStatus::Degraded     => RgbColor::DEGRADED,
            LedStatus::Resyncing    => RgbColor::RESYNCING,
            LedStatus::WaitingForPin => RgbColor::WAITING,
        };
        self.set_color(color);
    }
}

// ─── SPI bus type aliases ─────────────────────────────────────────────────────

/// Blocking SPI bus type used for RP2350-One flash access (keystore).
///
/// The `'static` lifetime reflects that `embassy_rp::Peripherals` fields
/// are `Peri<'static, ...>` when obtained from `embassy_rp::init()`.
/// Software chip-select is managed by the `SpiFlash` storage layer.
pub type Rp2350OneSpi0 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Blocking>;

/// Blocking SPI bus type used for RP2350-One flash access (RAID mirror).
pub type Rp2350OneSpi1 =
    embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>;

// ─── Board struct ─────────────────────────────────────────────────────────────

/// Concrete board representation for the Waveshare RP2350-One.
pub struct Rp2350OneBoard {
    led:  Ws2812Led,
    pub spi0: Rp2350OneSpi0,
    pub spi1: Rp2350OneSpi1,
}

impl Rp2350OneBoard {
    /// Create the RP2350-One board from pre-constructed SPI buses.
    ///
    /// Internally calls [`Ws2812Led::new`] which steals `PIO0` and `GPIO 16`.
    /// The caller must ensure that `p.PIO0` and `p.PIN_16` from
    /// `embassy_rp::init()` have **not** been taken before calling this.
    ///
    /// # Peripheral ownership after this call
    ///
    /// | Resource | Claimed by                           |
    /// |----------|--------------------------------------|
    /// | SPI0     | `spi0` parameter (already consumed)  |
    /// | SPI1     | `spi1` parameter (already consumed)  |
    /// | PIO0     | `Ws2812Led::new()` — stolen here     |
    /// | GPIO 16  | `Ws2812Led::new()` — stolen here     |
    pub fn new(spi0: Rp2350OneSpi0, spi1: Rp2350OneSpi1) -> Self {
        defmt::info!("RP2350-One: board created (SPI0 + SPI1 @ {} Hz)", SPI_FREQ_HZ);
        Self { led: Ws2812Led::new(), spi0, spi1 }
    }
}

#[cfg(any(feature = "rp2350_one_4m", feature = "rp2350_one_16m"))]
impl Board for Rp2350OneBoard {
    type Led  = Ws2812Led;
    type Spi0 = Rp2350OneSpi0;
    type Spi1 = Rp2350OneSpi1;

    fn led(&mut self)  -> &mut Self::Led  { &mut self.led  }
    fn spi0(&mut self) -> &mut Self::Spi0 { &mut self.spi0 }
    fn spi1(&mut self) -> &mut Self::Spi1 { &mut self.spi1 }

    fn spi0_cs_pins(&self) -> &[u8] { &SPI0_CS }
    fn spi1_cs_pins(&self) -> &[u8] { &SPI1_CS }
}

// ─── Legacy free function (kept for source compatibility) ─────────────────────

/// Set the WS2812B LED colour on GPIO 16.
///
/// **Legacy shim** — kept so that any code still calling
/// `rp2350_one::set_led(color)` compiles.  Prefer
/// `Board::led().set_status()` going forward.
pub async fn set_led(_color: super::LedColor) {
    // No-op: real implementation lives in Ws2812Led::set_color(),
    // invoked via Board::led().set_status().
}
