//! pico2hsm firmware library root.
//!
//! This lib target exists so that unit tests can run on the host (without
//! hardware) by importing individual modules. The `main.rs` binary target
//! imports this crate as a library.
//!
//! All modules are `no_std`. Platform-specific Embassy / RP2350 imports
//! are gated to `#[cfg(target_arch = "arm")]` so that the pure logic
//! modules (crypto, security, apdu, protocol) can be tested on x86_64.
#![no_std]
#![allow(unused)]

pub mod allocator;
pub mod apdu;
pub mod crypto;
pub mod protocol;
pub mod security;

// These modules depend on embassy-rp / embassy-usb / embassy-time which
// only compile for ARM bare-metal targets. They are excluded from host tests.
#[cfg(target_arch = "arm")]
pub mod board;
#[cfg(target_arch = "arm")]
pub mod image_def;
// The storage module's keystore.rs (KeyStore trait + NullKeyStore) is
// required by protocol/sc_hsm/mod.rs on all targets. ARM-specific sub-modules
// (board_chips, flash_chip, filesystem, StorageManager) are gated inside
// storage/mod.rs via #[cfg(target_arch = "arm")].
pub mod storage;
#[cfg(target_arch = "arm")]
pub mod transport;
#[cfg(target_arch = "arm")]
pub mod display;
