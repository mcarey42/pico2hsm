//! Cortex-M33 instruction counts for the sliced RSA key generator
//! (`firmware/src/crypto/{bignum,rsa_keygen}.rs`), compiled the way the
//! firmware compiles it (thumbv8m.main-none-eabihf, `opt-level = "z"`, LTO,
//! the `UMAAL` inner loop), run on QEMU's Cortex-M33 board:
//!
//! ```sh
//! cd tools/m33bench
//! cargo build --release --target thumbv8m.main-none-eabihf
//! qemu-system-arm -machine mps2-an505 -cpu cortex-m33 -nographic \
//!     -monitor none -serial none -semihosting-config enable=on,target=native \
//!     -icount shift=0 -kernel target/thumbv8m.main-none-eabihf/release/m33bench
//! # the `rsa` crate's keygen instead (as the firmware's dev profile builds it):
//! cargo build --release --target thumbv8m.main-none-eabihf --features rsacmp
//! ```
//!
//! With `-icount shift=0` every instruction takes 1 ns of virtual time, so
//! the CMSDK timer measures instructions (calibrated below).  QEMU does not
//! model cycles: multiply instruction counts by a CPI (~1.5–2.4 on the
//! RP2350 from flash) and divide by 150 MHz for a time.  The keys are the
//! same as the host build's for the same seed (the CRC column; see the
//! `reference_crcs` host test in `rsa_keygen.rs`).
#![no_std]
#![no_main]
// The firmware modules are included whole; the harness uses part of them.
#![allow(dead_code)]

use cortex_m_rt::entry;
use cortex_m_semihosting::{debug, hprintln};
use rand_core::RngCore;

mod security {
    pub mod zeroize {
        pub fn wipe_words(b: &mut [u32]) {
            zeroize::Zeroize::zeroize(b)
        }
    }
}

#[path = "../../../firmware/src/crypto/bignum.rs"]
mod bignum;
#[path = "../../../firmware/src/crypto/rsa_keygen.rs"]
mod rsa_keygen;

use bignum as bn;
use rsa_keygen::{Budget, KeyGen, Poll};

/// CMSDK APB TIMER0 (secure alias), counting down at the APB clock.
const TIMER0: usize = 0x5000_0000;

fn timer_init() {
    // SAFETY: the timer's registers on mps2-an505.
    unsafe {
        core::ptr::write_volatile((TIMER0 + 0x8) as *mut u32, u32::MAX); // RELOAD
        core::ptr::write_volatile((TIMER0 + 0x4) as *mut u32, u32::MAX); // VALUE
        core::ptr::write_volatile(TIMER0 as *mut u32, 1); // CTRL.EN
    }
}

/// Timer ticks since `timer_init` (wraps after 2^32 ticks; use deltas).
fn now() -> u32 {
    // SAFETY: as above.
    u32::MAX - unsafe { core::ptr::read_volatile((TIMER0 + 0x4) as *const u32) }
}

fn since(t0: u32) -> u64 {
    u64::from(now().wrapping_sub(t0))
}

/// SplitMix64, the same test DRBG as the host tests.
struct TestRng(u64);
impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Exactly one unit per step (to find the longest unit).
struct OneUnit(bool);
impl Budget for OneUnit {
    fn should_yield(&mut self) -> bool {
        core::mem::replace(&mut self.0, true)
    }
}

static mut KG: KeyGen = KeyGen::new();

#[cfg(feature = "rsacmp")]
extern crate alloc;
#[cfg(feature = "rsacmp")]
#[global_allocator]
static HEAP: embedded_alloc::LlffHeap = embedded_alloc::LlffHeap::empty();
#[cfg(feature = "rsacmp")]
impl rand_core::CryptoRng for TestRng {}

#[cfg(feature = "rsacmp")]
fn rsa_crate_keygen(ipkt: u64) {
    static mut MEM: [u8; 65536] = [0; 65536];
    // SAFETY: the heap memory is handed to the allocator once.
    unsafe { HEAP.init(core::ptr::addr_of_mut!(MEM) as usize, 65536) }
    for &(bits, seed) in &[
        (2048usize, 5000u64),
        (2048, 5001),
        (3072, 5010),
        (4096, 5020),
    ] {
        let mut rng = TestRng(seed);
        let t0 = now();
        let k = rsa::RsaPrivateKey::new(&mut rng, bits);
        let dt = since(t0);
        hprintln!(
            "rsa crate RSA-{} seed {}: {} Minsn ok={}",
            bits,
            seed,
            dt * ipkt / 1000 / 1_000_000,
            k.is_ok()
        );
    }
}

#[entry]
fn main() -> ! {
    timer_init();

    // Calibrate: 2 instructions per iteration.
    let iters: u32 = 2_000_000;
    let t0 = now();
    // SAFETY: a register-only countdown loop.
    unsafe {
        core::arch::asm!("1:", "subs {0}, #1", "bne 1b", inout(reg) iters => _);
    }
    let cal = since(t0).max(1);
    let ipkt = (2 * u64::from(iters)) * 1000 / cal; // instructions per 1000 ticks
    hprintln!("calibration: {} insn per 1000 ticks", ipkt);
    let insns = |t: u64| t * ipkt / 1000;

    #[cfg(feature = "rsacmp")]
    {
        rsa_crate_keygen(ipkt);
        debug::exit(debug::EXIT_SUCCESS);
    }

    // Montgomery multiply / square per operand size.
    for &n in &[32usize, 48, 64, 128] {
        let (mut m, mut a, mut b, mut o) = ([0u32; 128], [0u32; 128], [0u32; 128], [0u32; 128]);
        let mut r = TestRng(n as u64);
        for i in 0..n {
            m[i] = r.next_u32();
            a[i] = r.next_u32() >> 1;
            b[i] = r.next_u32() >> 1;
        }
        m[0] |= 1;
        m[n - 1] |= 0x8000_0000;
        let minv = bn::neg_inv32(m[0]);
        let reps = 100u64;
        let t0 = now();
        for _ in 0..reps {
            bn::mont_mul(&mut o[..n], &a[..n], &b[..n], &m[..n], minv);
        }
        let tm = since(t0);
        let t0 = now();
        for _ in 0..reps {
            bn::mont_sqr_assign(&mut a[..n], &m[..n], minv);
        }
        let ts = since(t0);
        hprintln!(
            "{} words: mont_mul {} insns, mont_sqr_assign {} insns",
            n,
            insns(tm) / reps,
            insns(ts) / reps
        );
    }

    // Whole keys, one unit per step: total and the longest unit.
    for &(nlen, seed) in &[
        (2048u32, 42u64),
        (2048, 47),
        (3072, 8),
        (4096, 9),
        (4096, 11),
    ] {
        // SAFETY: the only reference to KG.
        let kg = unsafe { &mut *core::ptr::addr_of_mut!(KG) };
        kg.start(nlen);
        let mut rng = TestRng(seed);
        let mut worst = 0u64;
        let t_start = now();
        loop {
            let t0 = now();
            let p = kg.step(&mut rng, &mut OneUnit(false));
            worst = worst.max(since(t0));
            match p {
                Poll::Pending => {}
                Poll::Ready => break,
                _ => {
                    hprintln!("keygen failed");
                    break;
                }
            }
        }
        let total = since(t_start);
        let mut der: heapless::Vec<u8, 2400> = heapless::Vec::new();
        let _ = kg.write_der(&mut der);
        let st = kg.stats;
        hprintln!(
            "RSA-{} seed {}: {} Minsn, longest unit {} insns, modmul {} modsqr {} units {} crc {:08x}",
            nlen,
            seed,
            insns(total) / 1_000_000,
            insns(worst),
            st.modmul,
            st.modsqr,
            st.units,
            crc32fast::hash(&der)
        );
        kg.reset();
    }
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    hprintln!("panic: {}", info);
    debug::exit(debug::EXIT_FAILURE);
    loop {}
}
