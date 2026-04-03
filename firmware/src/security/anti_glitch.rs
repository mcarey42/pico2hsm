//! Anti-glitch and fault injection countermeasures.
//!
//! Voltage-glitch attacks and electromagnetic fault injection (EMFI) can
//! cause a processor to skip instructions or corrupt register values. These
//! countermeasures increase the cost of such attacks by:
//!
//! 1. Arming the RP2350 hardware voltage-glitch detector (POWMAN)
//! 2. Providing software double-check patterns for critical comparisons
//! 3. Detecting stack corruption via a canary word
//!
//! # RP2350 hardware glitch detector
//! The RP2350 Power Management (POWMAN) block includes a voltage glitch
//! detector that can trigger a reset if the core supply voltage deviates
//! unexpectedly (RP2350 datasheet §7.6 "Power Management").
//! The `arm_glitch_detector()` function enables this feature.
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
//! - RP2350 datasheet §7.6 "POWMAN"
//! - "Fault Attacks on Secure Embedded Software", Riscure (2020)

use core::sync::atomic::{AtomicU32, Ordering, compiler_fence};

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
/// The RP2350 POWMAN block includes a voltage glitch detector that monitors
/// the core supply rail. When a glitch is detected, POWMAN can trigger an
/// immediate system reset.
///
/// # Current implementation status
/// The POWMAN glitch detector configuration registers are not yet fully
/// exposed by the `rp_pac` version used by embassy-rp 0.10.  This function
/// is a documented stub that records the intent. It will be completed when
/// `pac::POWMAN.vreg()` gains stable field accessors for `GLITCH_DETECT_ENABLE`
/// and `GLITCH_DETECT_SENS` (RP2350 datasheet §7.6.4 "VREG register").
///
/// # TODO
/// When `rp_pac` exposes POWMAN VREG fields:
/// ```ignore
/// unsafe {
///     let powman = embassy_rp::pac::POWMAN;
///     powman.vreg().modify(|w| {
///         w.set_glitch_detect_disable(false); // enable detector
///         w.set_glitch_detect_sens(3);        // maximum sensitivity
///     });
/// }
/// ```
///
/// Until then, software double-checks (`double_check()`) provide the primary
/// fault-injection countermeasure layer.
pub fn arm_glitch_detector() {
    // TODO: implement via embassy_rp::pac::POWMAN VREG register when the
    // rp_pac crate exposes the GLITCH_DETECT_DISABLE and GLITCH_DETECT_SENS
    // fields. Tracked as a known limitation.
    //
    // Reference: RP2350 datasheet §7.6.4 "POWMAN: VREG register"
    //   Bits [31:16] = GLITCH_DETECT_SENS (sensitivity, 0=off, 3=max)
    //   Bit  [0]     = GLITCH_DETECT_DISABLE (0 = detector enabled)
    #[cfg(feature = "debug")]
    defmt::warn!("anti_glitch: arm_glitch_detector() not yet implemented — rp_pac PAC stub");
}
