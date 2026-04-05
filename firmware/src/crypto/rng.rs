//! True Random Number Generator — TRNG + ADC entropy mixing.
//!
//! The RP2350 has a dedicated TRNG hardware block (12.12 in the datasheet).
//! This module wraps it and optionally mixes in ADC noise-floor entropy for
//! defence-in-depth.
//!
//! # Architecture
//! 1. RP2350 TRNG block produces 192-bit EHR frames at ~2 ms/frame.
//! 2. ADC channels (floating or internal-temperature pin) contribute thermal
//!    noise: the low 3 bits of each 12-bit ADC reading are most noisy and
//!    are accumulated into a 256-sample pool.
//! 3. The 256-sample pool is hashed with SHA-256 and XOR'd into an
//!    internal entropy pool (`adc_pool`).
//! 4. The TRNG is used as the primary source; `adc_pool` is mixed in as
//!    additional defensive entropy but is never the sole source.
//!
//! # Usage (blocking)
//! ```rust,ignore
//! let mut buf = [0u8; 32];
//! rng::fill_random(&mut buf).unwrap();
//! ```
//!
//! # Struct-based API
//! The `Rng` struct wraps the embassy-rp TRNG driver and the ADC entropy pool.
//! It exposes `fill_bytes` (blocking) and `mix_adc_entropy` for the background
//! entropy task.
//!
//! # embassy-rp API notes
//! The RP2350 TRNG is exposed as `embassy_rp::trng::Trng<'d, TRNG>` and
//! requires an interrupt binding (`TRNG_IRQ`).  Because binding interrupts
//! requires a concrete `bind_interrupts!` call at the crate root (which only
//! appears in `main.rs`), the `Rng` struct stores the TRNG via a type-erased
//! approach: callers pass a mutable reference to the concrete `Trng` type
//! for blocking fills, while `fill_random` (the legacy free function) falls
//! back to direct PAC register access so it can be used without an owned
//! peripheral handle.
//!
//! TODO (crypto agent): once the interrupt binding is established in main.rs,
//! replace the PAC fallback with a reference to the shared `Rng` instance
//! passed through an Embassy channel or a global mutex.

use chacha20::{ChaCha20, Key, Nonce};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use core::cell::UnsafeCell;
use pico2hsm_core::error::CryptoError;
use sha2::{Digest, Sha256};

// ─── ADC entropy constants ────────────────────────────────────────────────────

/// Number of ADC readings to accumulate before hashing into the pool.
const ADC_POOL_SAMPLES: usize = 256;

/// Number of low-noise bits taken from each 12-bit ADC sample.
const ADC_NOISY_BITS: u16 = 0x07; // low 3 bits

// ─── Global CSPRNG state ─────────────────────────────────────────────────────
//
// A ChaCha20 stream cipher instance used as a software CSPRNG.  Seeded (and
// periodically re-seeded) from the hardware TRNG by `reseed()`.
//
// # Safety invariant
// This module is only compiled for `target_arch = "arm"` (see crypto/mod.rs).
// `fill_random` and `reseed` are *only* called from Core1's single dispatcher
// task.  Core0 never calls either function.  Therefore there is no concurrent
// access across tasks or cores and the `UnsafeCell` is sound.
struct CsprngCell(UnsafeCell<Option<ChaCha20>>);

// SAFETY: single-core access as documented above.
unsafe impl Sync for CsprngCell {}

static CSPRNG: CsprngCell = CsprngCell(UnsafeCell::new(None));

// ─── Rng struct ───────────────────────────────────────────────────────────────

/// Hardware TRNG + ADC entropy pool.
///
/// # Struct-level API
/// Use the `Rng` struct when you have ownership of the TRNG peripheral.
/// For the free-function fallback that works before peripheral init,
/// see [`fill_random`].
pub struct Rng {
    /// SHA-256 derived entropy pool fed by ADC noise samples.
    /// 32 bytes; XOR'd into TRNG output for defence in depth.
    adc_pool: [u8; 32],
    /// How many ADC samples have been accumulated since the last pool hash.
    adc_sample_count: usize,
    /// Running XOR accumulator for ADC low bits.
    adc_accumulator: [u8; ADC_POOL_SAMPLES],
}

impl Rng {
    /// Construct a new `Rng` with an all-zero ADC entropy pool.
    ///
    /// The TRNG peripheral (`embassy_rp::trng::Trng`) is not stored here
    /// because it requires a concrete lifetime tied to the peripheral
    /// singleton; callers pass it in when calling `fill_bytes`.
    /// See module-level doc for rationale.
    pub fn new() -> Self {
        Self {
            adc_pool: [0u8; 32],
            adc_sample_count: 0,
            adc_accumulator: [0u8; ADC_POOL_SAMPLES],
        }
    }

    /// Fill `buf` with random bytes from the RP2350 hardware TRNG.
    ///
    /// The TRNG output is XOR'd with `self.adc_pool` (after wrapping)
    /// to mix in ADC entropy.
    ///
    /// `trng` must be an already-initialised `embassy_rp::trng::Trng`.
    pub fn fill_bytes<T>(&mut self, trng: &mut embassy_rp::trng::Trng<'_, T>, buf: &mut [u8])
    where
        T: embassy_rp::trng::Instance,
    {
        // Use the blocking fill — no async context needed for crypto ops.
        trng.blocking_fill_bytes(buf);

        // Mix in ADC pool entropy (defensive, not the sole source).
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte ^= self.adc_pool[i % 32];
        }
    }

    /// Incorporate one raw ADC reading into the entropy pool.
    ///
    /// Takes the low 3 bits of `raw_adc` (most thermally noisy on a
    /// floating input) and stores it in the accumulator.  After
    /// `ADC_POOL_SAMPLES` readings, hashes the accumulator with SHA-256
    /// and XOR's the result into `self.adc_pool`.
    ///
    /// This should be called from a background task at 10–100 Hz.
    pub fn mix_adc_entropy(&mut self, raw_adc: u16) {
        let noisy_byte = (raw_adc & ADC_NOISY_BITS) as u8;
        self.adc_accumulator[self.adc_sample_count] = noisy_byte;
        self.adc_sample_count += 1;

        if self.adc_sample_count >= ADC_POOL_SAMPLES {
            // Hash the accumulated samples.
            let mut hasher = Sha256::new();
            hasher.update(&self.adc_accumulator);
            hasher.update(&self.adc_pool); // chain previous pool
            let digest = hasher.finalize();

            // XOR digest into the pool.
            for (pool_byte, digest_byte) in self.adc_pool.iter_mut().zip(digest.iter()) {
                *pool_byte ^= digest_byte;
            }

            // Reset accumulator.
            self.adc_sample_count = 0;
            self.adc_accumulator = [0u8; ADC_POOL_SAMPLES];

            defmt::debug!("RNG: ADC entropy pool refreshed");
        }
    }
}

// ─── PAC-based fallback for pre-peripheral-init use ──────────────────────────

/// Read one 32-bit word directly from the TRNG EHR registers via PAC.
///
/// This bypasses the embassy-rp driver and directly accesses the TRNG
/// peripheral registers.  It is used by [`fill_random`] when no owned
/// `Trng` peripheral handle is available (e.g. during early boot).
///
/// The sequence:
/// 1. Enable the ROSC (RND_SOURCE_ENABLE).
/// 2. Poll TRNG_BUSY until idle.
/// 3. Check EHR_VALID; retry on autocorrelation error.
/// 4. Read EHR_DATA[5] (reading this register clears all EHR registers).
/// 5. Disable the ROSC.
///
/// # Safety
/// Direct PAC access is safe as long as no other code concurrently owns
/// the TRNG peripheral.  This function is only called from `fill_random`
/// which is documented as a pre-init fallback.
fn pac_trng_read_word() -> Result<u32, CryptoError> {
    use embassy_rp::pac;

    let trng = pac::TRNG;

    // Enable ROSC.
    trng.rnd_source_enable().write(|w| w.set_rnd_src_en(true));

    // Poll until not busy (with a timeout counter to avoid infinite loops
    // if the TRNG hardware is absent or malfunctioning).
    let mut retries: u32 = 100_000;
    loop {
        if retries == 0 {
            trng.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
            return Err(CryptoError::RngFailure);
        }
        retries -= 1;

        if trng.trng_busy().read().trng_busy() {
            // Still generating — spin.
            continue;
        }

        if !trng.trng_valid().read().ehr_valid() {
            // Check for autocorrelation error — reset and retry.
            if trng.rng_isr().read().autocorr_err() {
                trng.trng_sw_reset().write(|w| w.set_trng_sw_reset(true));
                // A dummy read is required after reset (per RP2350 datasheet 12.12.5).
                let _ = trng.trng_sw_reset().read();
                // Re-enable.
                trng.rnd_source_enable().write(|w| w.set_rnd_src_en(true));
            }
            continue;
        }

        // EHR is valid: reading ehr_data5 clears all EHR registers.
        let word = trng.ehr_data5().read();
        trng.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
        trng.rst_bits_counter().write(|w| w.set_rst_bits_counter(true));
        return Ok(word);
    }
}

/// Fill `buf` from the hardware TRNG via `pac_trng_read_word`.
///
/// Shared by [`fill_random`]'s fallback path and [`reseed`]'s seed collection.
fn pac_fill_bytes(buf: &mut [u8]) -> Result<(), CryptoError> {
    let mut i = 0;
    while i < buf.len() {
        let word = pac_trng_read_word()?;
        let bytes = word.to_le_bytes();
        let to_copy = (buf.len() - i).min(4);
        buf[i..i + to_copy].copy_from_slice(&bytes[..to_copy]);
        i += to_copy;
    }
    Ok(())
}

// ─── Free-function API (legacy / pre-init fallback) ───────────────────────────

/// Fill `buf` with cryptographically secure random bytes.
///
/// This is the primary RNG interface used by all cryptographic operations.
///
/// # Implementation
/// Uses the RP2350 TRNG via direct PAC register access so it can be called
/// before the embassy-rp TRNG driver is fully initialised.  For bulk use
/// after init, prefer `Rng::fill_bytes` with the owned peripheral handle.
///
/// Returns `Err(CryptoError::RngFailure)` if the TRNG hardware times out
/// (should not happen on functional silicon).
pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    // SAFETY: only called from Core1 dispatcher task; no concurrent access.
    let csprng_opt = unsafe { &mut *CSPRNG.0.get() };
    if let Some(csprng) = csprng_opt {
        // Use the software CSPRNG (ChaCha20 keystream over zeroed buffer).
        // This is faster than repeated PAC TRNG polls and provides
        // forward secrecy after each reseed().
        buf.fill(0);
        csprng.apply_keystream(buf);
    } else {
        // CSPRNG not yet seeded — fall back to direct TRNG reads.
        pac_fill_bytes(buf)?;
    }
    Ok(())
}

/// Generate `n` random bytes and return them in a heapless Vec.
pub fn get_random_bytes(n: usize) -> Result<heapless::Vec<u8, 256>, CryptoError> {
    if n > 256 {
        return Err(CryptoError::BufferTooSmall);
    }
    let mut buf = heapless::Vec::new();
    // SAFETY: we just checked n <= 256 == capacity
    buf.resize_default(n).map_err(|_| CryptoError::BufferTooSmall)?;
    fill_random(&mut buf)?;
    Ok(buf)
}

/// Trigger an immediate CSPRNG reseed from the hardware TRNG.
///
/// Reads a fresh 32-byte key and 12-byte nonce from the hardware TRNG via
/// direct PAC register access (bypassing the CSPRNG so the seed is always
/// fresh hardware entropy) and installs a new `ChaCha20` instance in the
/// global CSPRNG state.  Subsequent calls to `fill_random` will draw from
/// the newly-keyed ChaCha20 keystream until the next reseed.
///
/// Provides forward secrecy: compromise of the CSPRNG state after a reseed
/// does not reveal outputs generated before it.
///
/// # When to call
/// Call once during early boot (after peripherals are up) and then
/// periodically — e.g. every N operations or after significant time elapses.
pub fn reseed() -> Result<(), CryptoError> {
    // Read key and nonce directly from TRNG (not via CSPRNG — we need
    // fresh hardware entropy for the seed, not CSPRNG-derived bytes).
    let mut key_bytes = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    pac_fill_bytes(&mut key_bytes)?;
    pac_fill_bytes(&mut nonce_bytes)?;

    let new_csprng = ChaCha20::new(Key::from_slice(&key_bytes), Nonce::from_slice(&nonce_bytes));

    // Install new CSPRNG state.
    // SAFETY: only called from Core1 dispatcher task; no concurrent access.
    let csprng_opt = unsafe { &mut *CSPRNG.0.get() };
    *csprng_opt = Some(new_csprng);

    // Zeroize seed material.
    zeroize_slice(&mut key_bytes);
    zeroize_slice(&mut nonce_bytes);

    Ok(())
}

/// Zeroize a byte slice in a way the compiler cannot optimise away.
#[inline(never)]
fn zeroize_slice(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // Volatile write prevents the compiler from eliding the zeroing.
        unsafe { core::ptr::write_volatile(b as *mut u8, 0) };
    }
}
