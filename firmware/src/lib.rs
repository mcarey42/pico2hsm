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
// Style lints that do not fit this no_std firmware: constructors are
// explicit `new()`s (several build large structs in place), and the display
// and storage APIs mirror their hardware.
#![allow(
    clippy::new_without_default,
    clippy::len_without_is_empty,
    clippy::too_many_arguments,
    clippy::result_large_err,
    async_fn_in_trait,
    clippy::doc_lazy_continuation,
    clippy::doc_overindented_list_items
)]

pub mod allocator;
pub mod apdu;
pub mod crypto;
pub mod protocol;
pub mod security;
pub mod serial_debug;
pub mod watchdog;

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
/// time-extension loop and in the hardware-watchdog feeder: if neither the
/// heartbeat nor the request/reply counters move for 30 s while a request is
/// outstanding, Core1 is assumed stuck and the chip is reset (see
/// [`watchdog`]).  Storage sector operations bump it too
/// ([`watchdog::progress`]).
///
/// `Relaxed` ordering is sufficient: RP2350 is cache-coherent across cores and
/// we only need eventual visibility, not ordering with other memory operations.
pub static WATCHDOG_HEARTBEAT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Time-extension intervals (1.5 s each) without a heartbeat change before
/// Core0 declares Core1 stuck, answers 6F00 and resets the chip through the
/// hardware watchdog.  20 intervals = 30 s ([`watchdog::CORE1_STALL_MS`]).
/// The watchdog is a true deadlock detector — legitimate long operations (DKEK
/// derivation, ECDSA scalar multiply) bump the heartbeat via `FwRng::fill_bytes`.
/// RSA keygen suppresses the watchdog via [`WatchdogSuppressGuard`] because modular
/// exponentiation runs for minutes without RNG calls.
pub const WATCHDOG_STALL_LIMIT: u32 = 20;

/// Uptime (seconds) until which Core0 skips stall detection and just sends
/// time extensions; 0 = not suppressed.  Core1 sets it for RSA keygen (see
/// [`WatchdogSuppressGuard`]).  A deadline rather than a flag: if core1
/// faults mid-keygen the guard is never dropped, and a flag would keep the
/// host waiting forever.  `Relaxed` ordering is fine (same rationale as
/// `WATCHDOG_HEARTBEAT`).
pub static WATCHDOG_SUPPRESS_UNTIL: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Longest a suppression lasts: generous for RSA-4096 keygen, which the
/// test suite allows an hour.
pub const WATCHDOG_SUPPRESS_MAX_SECS: u32 = 3600;

fn uptime_secs() -> u32 {
    #[cfg(target_arch = "arm")]
    {
        embassy_time::Instant::now().as_secs() as u32
    }
    #[cfg(not(target_arch = "arm"))]
    {
        0
    }
}

/// Whether stall detection is currently suppressed.
pub fn watchdog_suppressed() -> bool {
    let until = WATCHDOG_SUPPRESS_UNTIL.load(core::sync::atomic::Ordering::Relaxed);
    until != 0 && uptime_secs() < until
}

/// Host session counter.  Bumped when the host session ends — USB bus
/// reset / deconfiguration (core0's USB handler) or a CCID card power cycle
/// (IccPowerOn/Off).  Core1 clears all authentication state before the
/// first APDU of a new session; core0 drops any response computed for an
/// older one instead of sending it into the new session.
pub static SESSION_EPOCH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The session the APDU currently in `APDU_CHANNEL` belongs to.  Core0
/// stores it before each send; core1 refuses an APDU whose session has
/// already ended, so a command from the old host can't run in (and
/// authenticate) the new one.
pub static APDU_EPOCH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Start a new host session (see [`SESSION_EPOCH`]).
pub fn bump_session_epoch() {
    SESSION_EPOCH.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
}

/// Suppresses stall detection (for at most [`WATCHDOG_SUPPRESS_MAX_SECS`])
/// for its lifetime and re-arms it on drop, so every return path
/// (including `?` and early returns) re-arms the stall detector.
pub struct WatchdogSuppressGuard(());

impl WatchdogSuppressGuard {
    /// Disarm the core1 stall detector until the guard is dropped.
    pub fn new() -> Self {
        let until = uptime_secs()
            .saturating_add(WATCHDOG_SUPPRESS_MAX_SECS)
            .max(1);
        WATCHDOG_SUPPRESS_UNTIL.store(until, core::sync::atomic::Ordering::Relaxed);
        WatchdogSuppressGuard(())
    }
}

impl Drop for WatchdogSuppressGuard {
    fn drop(&mut self) {
        WATCHDOG_SUPPRESS_UNTIL.store(0, core::sync::atomic::Ordering::Relaxed);
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
