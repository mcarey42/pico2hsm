//! Anti-glitch and fault injection countermeasures.
//!
//! Voltage-glitch attacks and electromagnetic fault injection (EMFI) can
//! cause a processor to skip instructions or corrupt register values. These
//! countermeasures increase the cost of such attacks by:
//!
//! 1. Arming the RP2350 hardware voltage-glitch detector (GLITCH_DETECTOR peripheral)
//! 2. Providing software double-check patterns for critical comparisons
//! 3. Detecting stack corruption via a canary word
//!
//! # RP2350 hardware glitch detector
//! The RP2350 has a dedicated GLITCH_DETECTOR peripheral (at 0x4015_8000)
//! separate from POWMAN. When armed, any detector trigger causes an immediate
//! reset of the switched core power domain. The peripheral has:
//! - `arm` register: write `Arm::YES` (0x0000) to arm; `Arm::NO` (0x5BAD) to not arm
//! - `sensitivity` register: 4 detector pairs (det0-det3 + det0_inv-det3_inv);
//!   `_inv` fields must be bitwise complement of their matching detector field
//! - `lock` register: write any nonzero value to prevent further changes
//!
//! The `arm_glitch_detector()` function configures all 4 detectors to maximum
//! sensitivity and locks the configuration.
//!
//! # Software double-check pattern
//! For security-critical boolean decisions (e.g., PIN verification result,
//! crypto key comparison), the caller should evaluate the condition twice
//! and pass both results to `double_check()`. A compiler fence between the
//! two evaluations makes it harder for a single fault to affect both:
//!
//! ```ignore
//! let result1 = verify_pin(pin);
//! let result2 = verify_pin(pin); // re-evaluate
//! if double_check(result1, result2) != DoubleCheckResult::Ok {
//!     halt_or_error();
//! }
//! ```
//!
//! # References
//! - RP2350 datasheet §12.5 "Glitch Detector"
//! - rp-pac GLITCH_DETECTOR peripheral (0x4015_8000)
//! - "Fault Attacks on Secure Embedded Software", Riscure (2020)

use core::sync::atomic::{compiler_fence, AtomicU32, Ordering};

// ─── Double-check result ──────────────────────────────────────────────────────

/// Result of a double-check verification.
///
/// `Ok` means both evaluations of a condition agreed.
/// `Mismatch` means the two evaluations disagreed, which may indicate
/// a fault injection attack or a software bug.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(target_arch = "arm", derive(defmt::Format))]
pub enum DoubleCheckResult {
    /// Both evaluations agreed — no fault detected.
    Ok,
    /// The two evaluations disagreed — possible fault injection.
    Mismatch,
}

/// Perform a double-check of a boolean condition.
///
/// Evaluates the condition TWICE (by the caller) with a `SeqCst` compiler
/// fence between them to prevent the compiler from merging the two reads.
/// Returns `Mismatch` if the two evaluations disagree.
///
/// # Usage pattern
/// ```ignore
/// let first  = expensive_check();
/// let second = expensive_check(); // caller must evaluate twice
/// match double_check(first, second) {
///     DoubleCheckResult::Ok      => { /* proceed */ }
///     DoubleCheckResult::Mismatch => { /* abort / alarm */ }
/// }
/// ```
///
/// The `#[inline(never)]` attribute prevents inlining so that the fence
/// is not optimised away across the call boundary.
#[inline(never)]
pub fn double_check(condition: bool, verify: bool) -> DoubleCheckResult {
    // Full compiler fence — prevents the compiler from reordering or
    // merging accesses across this point.
    compiler_fence(Ordering::SeqCst);
    if condition == verify {
        DoubleCheckResult::Ok
    } else {
        DoubleCheckResult::Mismatch
    }
}

// ─── Stack canary ─────────────────────────────────────────────────────────────

/// Magic value used as the stack canary.
///
/// Chosen to be unlikely to appear naturally in stack data.
/// Any value works as long as it is constant and checked consistently.
const CANARY_VALUE: u32 = 0xDEAD_BEEF;

/// Stack canary word, initialised at boot to `CANARY_VALUE`.
///
/// Stored as an `AtomicU32` so that `check_stack_canary()` can read it
/// without requiring exclusive access, and to prevent the compiler from
/// optimising away the check.
static STACK_CANARY: AtomicU32 = AtomicU32::new(CANARY_VALUE);

/// Check that the stack canary is intact.
///
/// Returns `true` if the canary word equals `CANARY_VALUE`, meaning no
/// detected stack smashing has overwritten it.
///
/// Returns `false` if the canary has been corrupted, which may indicate:
/// - Stack buffer overflow / smashing attack
/// - Fault injection that corrupted BSS/data
///
/// Callers should treat a `false` return as a critical security event
/// and halt or reset immediately.
pub fn check_stack_canary() -> bool {
    // SeqCst load ensures the read is not reordered past other operations.
    STACK_CANARY.load(Ordering::SeqCst) == CANARY_VALUE
}

/// Refresh the stack canary to the known-good value.
///
/// Call at startup (or after a known-safe stack unwind) to (re)arm the canary.
/// After calling this, `check_stack_canary()` will return `true` until the
/// canary memory is corrupted.
pub fn reset_stack_canary() {
    STACK_CANARY.store(CANARY_VALUE, Ordering::SeqCst);
}

// ─── Hardware glitch detector ─────────────────────────────────────────────────

/// Arm the RP2350 hardware voltage-glitch detector.
///
/// Uses the dedicated GLITCH_DETECTOR peripheral (at 0x4015_8000, separate
/// from POWMAN). Configures all 4 detector pairs to maximum sensitivity (3),
/// arms the detector, and locks the configuration to prevent tampering.
///
/// When armed, any individual detector trigger causes an immediate reset of
/// the switched core power domain. The reset reason is recorded in
/// POWMAN_CHIP_RESET.
///
/// # Sensitivity register layout
/// Each detector pair consists of a 2-bit `detN` field and a 2-bit `detN_inv`
/// field. The `_inv` field MUST be the bitwise complement of the `detN` field
/// (hardware design requirement); if they don't match, the hardware falls
/// back to the OTP default sensitivity instead.
///
/// Maximum sensitivity = 3 (0b11), so `detN_inv` = bitwise NOT of 3 within
/// 2 bits = 0 (0b00).
///
/// # Lock register
/// Writing any nonzero value to the `lock` register permanently prevents
/// further writes to ARM, DISARM, SENSITIVITY, and LOCK until the next
/// power-on reset.
///
/// # Safety
/// Uses `unsafe` to access MMIO registers via the rp-pac PAC. This is safe
/// because:
/// 1. The GLITCH_DETECTOR peripheral address (0x4015_8000) is a well-known
///    RP2350 hardware register block.
/// 2. These writes configure security-critical hardware exactly once at boot.
/// 3. The lock register prevents any further modification.
/// 4. No other code accesses these registers (single-owner at boot time).
#[cfg(target_arch = "arm")]
pub fn arm_glitch_detector() {
    use embassy_rp::pac::GLITCH_DETECTOR;

    // SAFETY: Single-owner MMIO access at boot time to well-known RP2350
    // GLITCH_DETECTOR registers. No other code accesses these registers.
    // The lock at the end prevents any further modification.
    unsafe {
        // Step 1: Set all 4 detectors to maximum sensitivity (3).
        // The _inv fields must be the 2-bit bitwise complement of the
        // sensitivity value: NOT(3) & 0x03 = 0.
        GLITCH_DETECTOR.sensitivity().write(|w| {
            w.set_det0(3); // max sensitivity
            w.set_det1(3);
            w.set_det2(3);
            w.set_det3(3);
            w.set_det0_inv(0); // bitwise complement of 3 within 2 bits
            w.set_det1_inv(0);
            w.set_det2_inv(0);
            w.set_det3_inv(0);
            // Override OTP defaults — use register values instead.
            w.set_default(embassy_rp::pac::glitch_detector::vals::Default::NO);
        });

        // Step 2: Arm the glitch detector.
        // Arm::YES = 0x0000 (any value other than 0x5BAD arms the detector).
        GLITCH_DETECTOR.arm().write(|w| {
            w.set_arm(embassy_rp::pac::glitch_detector::vals::Arm::YES);
        });

        // Step 3: Lock the configuration to prevent tampering.
        // Any nonzero value disables further writes to ARM, DISARM,
        // SENSITIVITY, and LOCK registers until next power-on reset.
        GLITCH_DETECTOR.lock().write(|w| {
            w.set_lock(1);
        });
    }
}

/// Check whether the glitch detector is currently armed.
///
/// Reads the ARM register and returns `true` if the value is not
/// `Arm::NO` (0x5BAD), meaning the detector is armed.
#[cfg(target_arch = "arm")]
pub fn is_glitch_detector_armed() -> bool {
    use embassy_rp::pac::GLITCH_DETECTOR;
    unsafe {
        let val = GLITCH_DETECTOR.arm().read().arm();
        val != embassy_rp::pac::glitch_detector::vals::Arm::NO
    }
}
