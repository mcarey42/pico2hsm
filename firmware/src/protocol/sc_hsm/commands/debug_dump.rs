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
//! Storage V2 recovery test hook (hardware test plan, STORAGE_V2 §9.3):
//! - P1=0x13: move the keystore anchor P2 records (1–255) ahead of the
//!   journal, as if that many acknowledged writes were lost.  The store
//!   keeps working until the next boot, which refuses it as behind its
//!   anchor by P2.
//!
//! Benchmark (`rsa` builds):
//! - P1=0x20: P2 = modulus size in 32-bit words (64 = 2048-bit, 128 =
//!   4096-bit).  Runs 256 Montgomery squarings plus 256 multiplications
//!   modulo a fixed odd number and returns the elapsed microseconds (4
//!   bytes, big-endian): the inner loop of RSA key generation.
//! - P1=0x21: self-test of the M33 two-row multiply-accumulate (UMAAL
//!   assembly) against its portable Rust twin, on pseudo-random inputs of
//!   every length 0..=130 with random carries; 9000 if every word matches,
//!   else 6F00 and the first failing length.

use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_WRONG_DATA};

/// INS byte for DEBUG MEMORY DUMP.
pub const INS_DEBUG_DUMP: u8 = 0xFE;

/// P1: wedge core1 (watchdog test).
pub const P1_WEDGE_CORE1: u8 = 0x10;
/// P1: wedge core0 after replying (watchdog test).
pub const P1_WEDGE_CORE0: u8 = 0x11;
/// P1: immediate watchdog reset (watchdog test).
pub const P1_WATCHDOG_RESET: u8 = 0x12;
/// P1: move the keystore anchor ahead (recovery test).
pub const P1_ANCHOR_AHEAD: u8 = 0x13;
/// P1: reboot into BOOTSEL (boards without a probe or a reachable button).
pub const P1_REBOOT_BOOTSEL: u8 = 0x14;
/// P1: image version and the bootrom's boot info (which slot booted).
pub const P1_IMAGE_INFO: u8 = 0x15;
/// P1: the loaded partition table, raw (`get_partition_table_info`).
pub const P1_PT_INFO: u8 = 0x16;
/// P1: Montgomery multiplication benchmark.
pub const P1_BENCH_MONT: u8 = 0x20;
/// P1: self-test the UMAAL kernel against the portable one.
pub const P1_SELFTEST_MAC2: u8 = 0x21;

/// Handle a DEBUG MEMORY DUMP APDU command.
pub fn handle(cmd: &ApduCommand<'_>, store: &mut dyn crate::storage::KeyStore) -> ApduResponse {
    match cmd.p1 {
        P1_ANCHOR_AHEAD => return anchor_ahead(store, cmd.p2),
        P1_WEDGE_CORE1 => loop {
            core::hint::spin_loop();
        },
        P1_WEDGE_CORE0 => {
            crate::watchdog::DEBUG_WEDGE_CORE0.store(true, core::sync::atomic::Ordering::SeqCst);
            return ApduResponse::ok(&[]);
        }
        #[cfg(target_arch = "arm")]
        P1_WATCHDOG_RESET => crate::watchdog::reset_now(crate::watchdog::ResetCause::DebugTest),
        #[cfg(target_arch = "arm")]
        P1_IMAGE_INFO => return image_info(),
        P1_PT_INFO => return pt_info(),
        #[cfg(target_arch = "arm")]
        P1_REBOOT_BOOTSEL => {
            // Both USB interfaces (PICOBOOT for picotool, the UF2 drive).
            embassy_rp::rom_data::reset_to_usb_boot(0, 0);
            loop {
                cortex_m::asm::wfi();
            }
        }
        #[cfg(all(target_arch = "arm", feature = "rsa"))]
        P1_BENCH_MONT => return bench_mont(cmd.p2 as usize),
        #[cfg(all(target_arch = "arm", feature = "rsa"))]
        P1_SELFTEST_MAC2 => return selftest_mac2(),
        _ => {}
    }
    // TODO: implement — read memory region and return raw bytes.
    // NOTE: This is a debug-only stub. Production builds never compile this.
    ApduResponse::err(SW_WRONG_DATA)
}

/// See `P1_IMAGE_INFO`: `major u16 | minor u16` (big-endian), then the
/// `get_sys_info(BOOT_INFO)` words as the ROM returns them (little-endian;
/// the first is the mask of flags it filled).
fn image_info() -> ApduResponse {
    let mut out = heapless::Vec::<u8, 32>::new();
    #[cfg(target_arch = "arm")]
    {
        let _ = out.extend_from_slice(&crate::image_def::IMAGE_MAJOR.to_be_bytes());
        let _ = out.extend_from_slice(&crate::image_def::IMAGE_MINOR.to_be_bytes());
        /// `SYS_INFO_BOOT_INFO` (datasheet §5.5.11.1).
        const BOOT_INFO: u32 = 0x0040;
        let mut words = [0u32; 5];
        // SAFETY: the buffer is `words.len()` words long.
        let n = unsafe {
            embassy_rp::rom_data::get_sys_info(words.as_mut_ptr(), words.len(), BOOT_INFO)
        };
        for w in words.iter().take(n.clamp(0, 5) as usize) {
            let _ = out.extend_from_slice(&w.to_le_bytes());
        }
    }
    ApduResponse::ok(&out)
}

/// See `P1_PT_INFO`: the words `get_partition_table_info(PT_INFO |
/// PARTITION_LOCATION_AND_FLAGS)` returns, little-endian (the first is the
/// mask of flags it filled).
fn pt_info() -> ApduResponse {
    let mut out = heapless::Vec::<u8, 160>::new();
    #[cfg(target_arch = "arm")]
    {
        /// `PT_INFO_PT_INFO | PT_INFO_PARTITION_LOCATION_AND_FLAGS`.
        const FLAGS: u32 = 0x0001 | 0x0010;
        let mut words = [0u32; 40];
        // SAFETY: the buffer is `words.len()` words long.
        let n = unsafe {
            embassy_rp::rom_data::get_partition_table_info(words.as_mut_ptr(), words.len(), FLAGS)
        };
        for w in words.iter().take(n.clamp(0, 40) as usize) {
            let _ = out.extend_from_slice(&w.to_le_bytes());
        }
    }
    ApduResponse::ok(&out)
}

/// See `P1_ANCHOR_AHEAD`.
fn anchor_ahead(store: &mut dyn crate::storage::KeyStore, n: u8) -> ApduResponse {
    use crate::storage::retry_counter::Anchor;
    use pico2hsm_core::apdu::SW_MEMORY_FAILURE;
    if n == 0 {
        return ApduResponse::err(SW_WRONG_DATA);
    }
    let Some(log) = store.retry_counters() else {
        return ApduResponse::err(SW_MEMORY_FAILURE);
    };
    let Ok(Some(a)) = log.anchor() else {
        return ApduResponse::err(SW_MEMORY_FAILURE);
    };
    let ahead = Anchor {
        head_seq: a.head_seq + u64::from(n),
        ..a
    };
    match log.put_anchor(ahead) {
        Ok(()) => ApduResponse::ok(&[]),
        Err(_) => ApduResponse::err(SW_MEMORY_FAILURE),
    }
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

/// See `P1_SELFTEST_MAC2`.
#[cfg(all(target_arch = "arm", feature = "rsa"))]
fn selftest_mac2() -> ApduResponse {
    use crate::crypto::bignum::{mac2_m33, mac2_portable};
    let mut x = 0x2545_F491u32;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    };
    let mut a = [0u32; 130];
    let mut t1 = [0u32; 130];
    let mut t2 = [0u32; 130];
    for round in 0..4u32 {
        for n in 0..=130usize {
            for i in 0..n {
                // Round 0: all ones (every carry at its limit).
                a[i] = if round == 0 { u32::MAX } else { next() };
                t1[i] = if round == 0 { u32::MAX } else { next() };
                t2[i] = t1[i];
            }
            let (b0, b1, c0, c1, p) = if round == 0 {
                (u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX)
            } else {
                (next(), next(), next(), next(), next())
            };
            let r1 = mac2_m33(&mut t1[..n], &a[..n], b0, b1, (c0, c1), p);
            let r2 = mac2_portable(&mut t2[..n], &a[..n], b0, b1, (c0, c1), p);
            if r1 != r2 || t1[..n] != t2[..n] {
                return ApduResponse {
                    data: heapless::Vec::from_slice(&[round as u8, n as u8]).unwrap_or_default(),
                    sw: 0x6F00,
                };
            }
        }
    }
    ApduResponse::ok(&[])
}
