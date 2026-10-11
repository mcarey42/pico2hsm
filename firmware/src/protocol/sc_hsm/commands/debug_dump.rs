//! Debug memory dump APDU handler.
//! Only compiled when `#[cfg(feature = "debug")]` — gated at module declaration in mod.rs.
//!
//! # Security warning
//! Including this command in a production build would constitute a
//! critical security vulnerability. The `debug` feature MUST NOT be
//! enabled for devices deployed in production.
//!
//! # Command data
//! - P1=0x00: Dump RAM region (address in data[0..4], length in data[4..6])
//! - P1=0x01: Dump flash region (address in data[0..4], length in data[4..6])
//! - P1=0x02: Dump OTP region (page in data[0], row in data[1])
//!
//! Watchdog test hooks (hardware test plan for the RP2350 watchdog):
//! - P1=0x10: wedge core1 — spin forever inside the APDU without a heartbeat.
//!   Expected: time extensions for 30 s, SW 6F00, then a forced watchdog
//!   reset logged as "core1 stuck during an APDU".
//! - P1=0x11: wedge core0 — after this reply is sent, core0 spins without
//!   yielding.  Expected: watchdog timeout ~8 s later, logged as "core0
//!   stopped feeding".
//! - P1=0x12: reset the chip now through the watchdog trigger (from core1).

use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_WRONG_DATA};

/// INS byte for DEBUG MEMORY DUMP.
pub const INS_DEBUG_DUMP: u8 = 0xFE;

/// P1: wedge core1 (watchdog test).
pub const P1_WEDGE_CORE1: u8 = 0x10;
/// P1: wedge core0 after replying (watchdog test).
pub const P1_WEDGE_CORE0: u8 = 0x11;
/// P1: immediate watchdog reset (watchdog test).
pub const P1_WATCHDOG_RESET: u8 = 0x12;

/// Handle a DEBUG MEMORY DUMP APDU command.
pub fn handle(cmd: &ApduCommand<'_>) -> ApduResponse {
    match cmd.p1 {
        P1_WEDGE_CORE1 => loop {
            core::hint::spin_loop();
        },
        P1_WEDGE_CORE0 => {
            crate::watchdog::DEBUG_WEDGE_CORE0.store(true, core::sync::atomic::Ordering::SeqCst);
            return ApduResponse::ok(&[]);
        }
        #[cfg(target_arch = "arm")]
        P1_WATCHDOG_RESET => crate::watchdog::reset_now(crate::watchdog::ResetCause::DebugTest),
        _ => {}
    }
    // TODO: implement — read memory region and return raw bytes.
    // NOTE: This is a debug-only stub. Production builds never compile this.
    ApduResponse::err(SW_WRONG_DATA)
}
