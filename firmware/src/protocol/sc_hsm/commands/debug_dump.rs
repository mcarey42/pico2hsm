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
//!
//! Benchmark (`rsa` builds):
//! - P1=0x20: P2 = modulus size in 32-bit words (64 = 2048-bit, 128 =
//!   4096-bit).  Runs 256 Montgomery squarings plus 256 multiplications
//!   modulo a fixed odd number and returns the elapsed microseconds (4
//!   bytes, big-endian): the inner loop of RSA key generation.

use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_WRONG_DATA};

/// INS byte for DEBUG MEMORY DUMP.
pub const INS_DEBUG_DUMP: u8 = 0xFE;

/// P1: wedge core1 (watchdog test).
pub const P1_WEDGE_CORE1: u8 = 0x10;
/// P1: wedge core0 after replying (watchdog test).
pub const P1_WEDGE_CORE0: u8 = 0x11;
/// P1: immediate watchdog reset (watchdog test).
pub const P1_WATCHDOG_RESET: u8 = 0x12;
/// P1: Montgomery multiplication benchmark.
pub const P1_BENCH_MONT: u8 = 0x20;

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
        #[cfg(all(target_arch = "arm", feature = "rsa"))]
        P1_BENCH_MONT => return bench_mont(cmd.p2 as usize),
        _ => {}
    }
    // TODO: implement — read memory region and return raw bytes.
    // NOTE: This is a debug-only stub. Production builds never compile this.
    ApduResponse::err(SW_WRONG_DATA)
}

/// See `P1_BENCH_MONT`.
#[cfg(all(target_arch = "arm", feature = "rsa"))]
fn bench_mont(words: usize) -> ApduResponse {
    use crate::crypto::bignum as bn;
    if !(2..=bn::MAX_WORDS).contains(&words) {
        return ApduResponse::err(SW_WRONG_DATA);
    }
    let mut m = [0u32; bn::MAX_WORDS];
    let mut x = [0u32; bn::MAX_WORDS];
    let mut y = [0u32; bn::MAX_WORDS];
    // Fixed, full-size operands: m odd with its top bit set, x and y < m.
    for i in 0..words {
        m[i] = 0x9E37_79B9u32.wrapping_mul(i as u32 + 1) | 1;
        x[i] = 0x7F4A_7C15u32.wrapping_mul(i as u32 + 3);
        y[i] = 0x2545_F491u32.wrapping_mul(i as u32 + 5);
    }
    m[words - 1] |= 0x8000_0000;
    x[words - 1] &= 0x7FFF_FFFF;
    y[words - 1] &= 0x7FFF_FFFF;
    let minv = bn::neg_inv32(m[0]);
    let (m, x, y) = (&m[..words], &mut x[..words], &y[..words]);
    let start = embassy_time::Instant::now();
    for _ in 0..256 {
        bn::mont_sqr_assign(x, m, minv);
        bn::mont_mul_assign(x, y, m, minv);
    }
    let us = start.elapsed().as_micros() as u32;
    // Keep the result live.
    core::hint::black_box(&x);
    ApduResponse::ok(&us.to_be_bytes())
}
