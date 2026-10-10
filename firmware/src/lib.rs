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
pub mod serial_debug;

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
#[cfg(target_arch = "arm")]
pub mod display;
pub mod storage;
#[cfg(target_arch = "arm")]
pub mod transport;

// No-op stubs for crate::cdc_log!/cdc_warn!/cdc_error! on non-ARM (host test) builds.
// On ARM, the real implementations live in transport::cdc_serial and are exported via
// #[macro_export] from that module. On x86_64 the transport module is not compiled,
// so we define the stubs here directly at the crate root.
/// Core1 dispatch progress breadcrumb for cross-core debugging.
/// Written by core1 at each dispatch stage; read by core0 during time-extension
/// logging to diagnose hangs without defmt (which deadlocks on core1).
pub static CORE1_PROGRESS: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// Watchdog heartbeat counter incremented by Core1 during long-running crypto
/// operations (via `FwRng::fill_bytes` — called thousands of times during RSA
/// prime generation and before each ECDSA sign).  Core0 monitors this in the
/// time-extension loop: if the heartbeat has not changed for several consecutive
/// 1.5 s intervals, Core1 is assumed stuck and the APDU is aborted with an
/// error response.
///
/// `Relaxed` ordering is sufficient: RP2350 is cache-coherent across cores and
/// we only need eventual visibility, not ordering with other memory operations.
pub static WATCHDOG_HEARTBEAT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Consecutive time-extension intervals (1.5 s each) without a heartbeat change
/// before Core0 declares Core1 stuck and aborts the APDU.  20 intervals = 30 s.
/// The watchdog is a true deadlock detector — legitimate long operations (DKEK
/// derivation, ECDSA scalar multiply) bump the heartbeat via `FwRng::fill_bytes`.
/// RSA keygen suppresses the watchdog via [`WATCHDOG_SUPPRESS`] because modular
/// exponentiation runs for minutes without RNG calls.
pub const WATCHDOG_STALL_LIMIT: u32 = 20;

/// When `true`, Core0 skips stall detection and never aborts — it just sends
/// time-extensions.  Core1 sets this before RSA keygen and clears it after.
/// `Relaxed` ordering is fine (same rationale as `WATCHDOG_HEARTBEAT`).
pub static WATCHDOG_SUPPRESS: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Holds [`WATCHDOG_SUPPRESS`] set for its lifetime and clears it on drop,
/// so every return path (including `?` and early returns) re-arms the
/// stall detector.
pub struct WatchdogSuppressGuard(());

impl WatchdogSuppressGuard {
    /// Disarm the core1 stall detector until the guard is dropped.
    pub fn new() -> Self {
        WATCHDOG_SUPPRESS.store(true, core::sync::atomic::Ordering::Relaxed);
        WatchdogSuppressGuard(())
    }
}

impl Drop for WatchdogSuppressGuard {
    fn drop(&mut self) {
        WATCHDOG_SUPPRESS.store(false, core::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(not(target_arch = "arm"))]
#[macro_export]
macro_rules! cdc_log {
    ($($arg:tt)*) => {{}};
}
#[cfg(not(target_arch = "arm"))]
#[macro_export]
macro_rules! cdc_warn {
    ($($arg:tt)*) => {{}};
}
#[cfg(not(target_arch = "arm"))]
#[macro_export]
macro_rules! cdc_error {
    ($($arg:tt)*) => {{}};
}
