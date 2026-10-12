//! Status display for the LCD boards (RP2350-Geek 240×135, Waveshare
//! RP2350-LCD-1.47 320×172).
//!
//! Data flow (see `docs/DISPLAY_ARCHITECTURE.md`):
//!
//! ```text
//! core1 dispatcher ──publish──▶ display_snapshot::SNAP ─┐
//! core0 CCID loop ──atomics + DISPLAY_KICK──────────────┤
//!                                                       ▼
//!            display task (core0): model::Controller::step → view::Screen
//!                                                       ▼
//!            driver::ScreenDriver: dirty bands → render → band → Panel (SPI DMA)
//! ```
//!
//! Everything except the task loop and the board panels compiles on the
//! host: the render code is tested there, including golden-hash snapshots
//! of every screen at both resolutions (`tests.rs`).
//!
//! Security rule (design spec §4.1): on-screen text is firmware-static.
//! Nothing here renders host-supplied bytes; numbers come from firmware
//! state only.

pub mod band;
pub mod color;
pub mod driver;
pub mod fmt;
pub mod layout;
pub mod model;
pub mod render;
#[cfg(target_arch = "arm")]
pub mod task;
pub mod view;

#[cfg(test)]
mod tests;

pub use driver::{Panel, ScreenDriver};
pub use layout::{Layout, GEEK_240X135, WAVESHARE_320X172};
pub use view::Screen;

/// Debug builds show per-applet key counts, operation detail and the panel
/// border check (design spec §4.6).
pub const DETAIL: bool = cfg!(any(debug_assertions, feature = "debug"));
