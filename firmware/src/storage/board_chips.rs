//! Board-specific `BoardChip` type aliases for `StaticCell` monomorphization.
//!
//! Exactly one `BoardChip` alias is active at compile time, selected by
//! the active board feature flag.
//!
//! # pico2_4m
//! Uses `QmiFlash` — the RP2350 internal QMI flash (upper 2 MB partition).
//! No external SPI flash is required; the on-board 4 MB chip is shared between
//! firmware XIP (lower 2 MB) and keystore (upper 2 MB).
//!
//! # rp2350_one_* / rp2350_geek_*
//! Uses `AnyChip<Spi0Flash, Spi1Flash, QmiFlash>` where Spi0Flash is the
//! primary flash on SPI0 and Spi1Flash is the RAID-1 mirror on SPI1.
//! `QmiFlash` is the unused SD-slot placeholder for the type parameter.
//!
//! NOTE: The AnyChip variants for SPI boards require that the SpiFlash instances
//! are built from the respective SPI buses before the board struct is constructed.
//! See `main.rs` `run_one_board` / `run_geek_board` for the wiring.

#[cfg(target_arch = "arm")]
use embassy_rp::gpio::Output;

#[cfg(target_arch = "arm")]
use crate::storage::{
    AnyChip,
    flash_chip::{QmiFlash, SpiFlash},
};

// ── pico2_4m ─────────────────────────────────────────────────────────────────

/// Internal QMI flash — no external chips on the stock Pico 2.
#[cfg(all(target_arch = "arm", feature = "pico2_4m"))]
pub type BoardChip = QmiFlash;

// ── rp2350_one_* ─────────────────────────────────────────────────────────────

/// RAID-1 pair: SPI0 primary (W25Qxx) + SPI1 mirror (W25Qxx).
/// The third type parameter (`QmiFlash`) is the unused SD-slot placeholder.
#[cfg(all(target_arch = "arm", any(feature = "rp2350_one_4m", feature = "rp2350_one_16m")))]
pub type BoardChip = AnyChip<
    SpiFlash<
        embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Blocking>,
        Output<'static>,
    >,
    SpiFlash<
        embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>,
        Output<'static>,
    >,
    QmiFlash,
>;

// ── rp2350_geek_* ─────────────────────────────────────────────────────────────

/// RAID-1 pair: SPI0 primary + SPI1 mirror.
/// SPI pin assignments are identical to RP2350-One.
#[cfg(all(target_arch = "arm", any(
    feature = "rp2350_geek_16m",
    feature = "rp2350_geek_sdcard",
    feature = "rp2350_geek_sdcard_dual",
)))]
pub type BoardChip = AnyChip<
    SpiFlash<
        embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI0, embassy_rp::spi::Blocking>,
        Output<'static>,
    >,
    SpiFlash<
        embassy_rp::spi::Spi<'static, embassy_rp::peripherals::SPI1, embassy_rp::spi::Blocking>,
        Output<'static>,
    >,
    QmiFlash,
>;
