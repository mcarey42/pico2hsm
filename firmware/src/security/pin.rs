//! PIN management — verification, change, PUK unblock, lockout, session key.
//!
//! # PIN storage format
//! ```text
//! [0..32]  PBKDF2-HMAC-SHA256(pin, salt=device_id||b"pin", iters=10000) — PIN hash
//! [32..48] 16-byte random salt (refreshed on every PIN change)
//! [48]     retry counter (decremented on wrong PIN, reset on correct)
//! [49]     max retries (set at init, default = 3)
//! [50..52] reserved (0xFF)
//! ```
//!
//! # Timing attack resistance
//! - All PIN comparisons use `subtle::ConstantTimeEq`.
//! - PBKDF2 is always computed before the comparison, even when the counter
//!   is zero, to prevent timing oracles on the retry state.
//! - The retry counter is decremented BEFORE the hash comparison so that
//!   an attacker cannot exploit a timing window between check and decrement.
//!
//! # PUK (PIN Unblocking Key)
//! The PUK is a separate credential (SO-PIN or factory PUK) stored with its
//! own retry counter.  PUK unblock allows resetting the PIN when it is locked.
//! PUK operations use the same PBKDF2 scheme with a different salt suffix.
//!
//! # Session key
//! On successful PIN verification, a 32-byte session key is derived:
//! `HKDF-SHA256(ikm=SMK, salt=pin_hash, info=b"pico2hsm-session-key-v1")`
//! This session key is used by the SC-HSM Secure Messaging layer.  It is
//! cleared on `reset_session()` or when the card is logically removed.

#![allow(dead_code)]

use core::convert::TryInto;

use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use pico2hsm_core::error::AuthError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum number of PIN verification attempts before lockout.
pub const MAX_PIN_RETRIES: u8 = 3;

/// Default maximum number of PUK verification attempts before lockout.
pub const MAX_PUK_RETRIES: u8 = 10;

/// Minimum allowed PIN length in bytes.
pub const MIN_PIN_LENGTH: usize = 6;

/// Maximum allowed PIN length in bytes.
pub const MAX_PIN_LENGTH: usize = 16;

/// PBKDF2 iteration count.  Calibrated for ~50 ms on RP2350 at 150 MHz.
pub const PIN_PBKDF2_ITERATIONS: u32 = 10_000;

/// Suffix appended to `device_id` to form the PIN PBKDF2 salt.
const PIN_SALT_SUFFIX: &[u8] = b"pin";

/// Suffix appended to `device_id` to form the PUK PBKDF2 salt.
const PUK_SALT_SUFFIX: &[u8] = b"puk";

/// HKDF info string for session key derivation.
const SESSION_KEY_INFO: &[u8] = b"pico2hsm-session-key-v1";

// ---------------------------------------------------------------------------
// PinVerifyResult
// ---------------------------------------------------------------------------

/// Result of a PIN verification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinVerifyResult {
    /// PIN is correct; session is now authenticated.
    Success,
    /// PIN is incorrect; `retries_remaining` decremented.
    WrongPin { retries_remaining: u8 },
    /// Retry counter has reached zero; PIN is permanently locked.
    Blocked,
}

// ---------------------------------------------------------------------------
// PinError
// ---------------------------------------------------------------------------

/// Errors specific to PIN operations beyond the standard `AuthError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinError {
    /// PIN length is outside [MIN_PIN_LENGTH, MAX_PIN_LENGTH].
    InvalidLength,
    /// The old (current) PIN was incorrect during a change operation.
    WrongCurrentPin,
    /// PIN is locked; must be unblocked by PUK before use.
    Locked,
    /// PUK is locked; cannot unblock PIN.
    PukLocked,
    /// Old PIN is correct but the new PIN fails the length policy.
    NewPinInvalidLength,
    /// Internal buffer overflow.
    BufferOverflow,
}

// ---------------------------------------------------------------------------
// PinState
// ---------------------------------------------------------------------------

/// Full PIN + PUK state held in RAM (persisted to storage by the caller).
///
/// Sensitive fields (`session_key`) are wrapped in `Zeroizing` so they are
/// cleared from memory when `PinState` is dropped.
pub struct PinState {
    // --- PIN ---
    /// Stored PBKDF2 hash of the current PIN (32 bytes).
    pub pin_hash: [u8; 32],
    /// 16-byte random salt used for the PIN hash.
    pub pin_salt: [u8; 16],
    /// Number of remaining PIN verification attempts before lockout.
    pub pin_retries_remaining: u8,
    /// Maximum PIN retries (configured at init; written to storage).
    pub pin_max_retries: u8,
    /// True when pin_retries_remaining == 0.
    pub pin_blocked: bool,

    // --- PUK ---
    /// Stored PBKDF2 hash of the PUK.
    pub puk_hash: [u8; 32],
    /// 16-byte random salt used for the PUK hash.
    pub puk_salt: [u8; 16],
    /// Number of remaining PUK attempts before lockout.
    pub puk_retries_remaining: u8,
    /// True when puk_retries_remaining == 0.
    pub puk_blocked: bool,

    // --- Session ---
    /// True after a successful PIN `verify`.
    pub session_authenticated: bool,
    /// Session key derived on successful PIN verify.  `None` when not authenticated.
    pub session_key: Option<Zeroizing<[u8; 32]>>,
}

impl Zeroize for PinState {
    fn zeroize(&mut self) {
        self.pin_hash.zeroize();
        self.pin_salt.zeroize();
        self.puk_hash.zeroize();
        self.puk_salt.zeroize();
        if let Some(ref mut sk) = self.session_key {
            sk.zeroize();
        }
        self.session_key = None;
        self.session_authenticated = false;
    }
}

impl Drop for PinState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PinState {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a `PinState` with a freshly-computed PIN and PUK hash.
    ///
    /// `pin_salt` and `puk_salt` must be provided by the caller (typically 16
    /// random bytes each generated by the RNG during INITIALIZE).
    pub fn new(
        pin:       &[u8],
        puk:       &[u8],
        device_id: &[u8],
        pin_salt:  [u8; 16],
        puk_salt:  [u8; 16],
        pin_max_retries: u8,
        puk_max_retries: u8,
    ) -> Result<Self, PinError> {
        validate_pin_length(pin)?;

        let pin_hash = Self::hash_pin(pin, device_id, &pin_salt);
        let puk_hash = Self::hash_puk(puk, device_id, &puk_salt);

        Ok(PinState {
            pin_hash,
            pin_salt,
            pin_retries_remaining: pin_max_retries,
            pin_max_retries,
            pin_blocked: false,
            puk_hash,
            puk_salt,
            puk_retries_remaining: puk_max_retries,
            puk_blocked: false,
            session_authenticated: false,
            session_key: None,
        })
    }

    // -----------------------------------------------------------------------
    // PIN hash
    // -----------------------------------------------------------------------

    /// Compute the PBKDF2-HMAC-SHA256 hash for a PIN.
    ///
    /// `salt = device_id || PIN_SALT_SUFFIX || pin_salt_bytes`
    ///
    /// Always runs the full PBKDF2 even if the counter is zero, to prevent
    /// timing side-channels on the retry state.
    pub fn hash_pin(pin: &[u8], device_id: &[u8], pin_salt: &[u8; 16]) -> [u8; 32] {
        hash_credential(pin, device_id, PIN_SALT_SUFFIX, pin_salt)
    }

    /// Compute the PBKDF2-HMAC-SHA256 hash for a PUK.
    pub fn hash_puk(puk: &[u8], device_id: &[u8], puk_salt: &[u8; 16]) -> [u8; 32] {
        hash_credential(puk, device_id, PUK_SALT_SUFFIX, puk_salt)
    }

    // -----------------------------------------------------------------------
    // Session key
    // -----------------------------------------------------------------------

    /// Derive a 32-byte session key.
    ///
    /// `HKDF-SHA256(ikm=smk, salt=pin_hash, info=SESSION_KEY_INFO)`
    fn derive_session_key(smk: &[u8; 32], pin_hash: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(Some(pin_hash), smk);
        let mut sk = Zeroizing::new([0u8; 32]);
        hkdf.expand(SESSION_KEY_INFO, sk.as_mut())
            .expect("HKDF expand cannot fail for 32 bytes");
        sk
    }

    // -----------------------------------------------------------------------
    // PIN verify
    // -----------------------------------------------------------------------

    /// Verify a presented PIN against the stored hash.
    ///
    /// Retry counter is decremented BEFORE the hash comparison (fail-safe).
    /// If correct, the session is activated and a session key derived from
    /// `smk` is stored.
    pub fn verify_pin(
        &mut self,
        pin:       &[u8],
        device_id: &[u8],
        smk:       Option<&[u8; 32]>,
    ) -> Result<PinVerifyResult, PinError> {
        // Always compute the hash to resist timing attacks.
        let presented_hash = Self::hash_pin(pin, device_id, &self.pin_salt);

        // Blocked — return immediately, but only after computing the hash.
        if self.pin_blocked || self.pin_retries_remaining == 0 {
            self.pin_blocked = true;
            return Ok(PinVerifyResult::Blocked);
        }

        // Pre-decrement the retry counter (written to storage by caller).
        self.pin_retries_remaining = self.pin_retries_remaining.saturating_sub(1);

        // Constant-time comparison.
        let matches = bool::from(presented_hash.ct_eq(&self.pin_hash));

        if matches {
            // Correct PIN — restore counter and activate session.
            self.pin_retries_remaining = self.pin_max_retries;
            self.session_authenticated = true;

            if let Some(smk) = smk {
                self.session_key = Some(Self::derive_session_key(smk, &self.pin_hash));
            }

            Ok(PinVerifyResult::Success)
        } else {
            if self.pin_retries_remaining == 0 {
                self.pin_blocked = true;
                Ok(PinVerifyResult::Blocked)
            } else {
                Ok(PinVerifyResult::WrongPin {
                    retries_remaining: self.pin_retries_remaining,
                })
            }
        }
    }

    // -----------------------------------------------------------------------
    // PIN change
    // -----------------------------------------------------------------------

    /// Change the PIN after verifying the old PIN.
    ///
    /// On success, generates a new hash using `new_pin_salt` and resets the
    /// retry counter.  The session remains active.
    pub fn change_pin(
        &mut self,
        old_pin:      &[u8],
        new_pin:      &[u8],
        device_id:    &[u8],
        new_pin_salt: [u8; 16],
    ) -> Result<(), PinError> {
        // Validate new PIN before checking old PIN (fail fast on policy).
        validate_pin_length(new_pin)?;

        // Hash old PIN (always, for timing resistance).
        let old_hash = Self::hash_pin(old_pin, device_id, &self.pin_salt);

        if self.pin_blocked || self.pin_retries_remaining == 0 {
            return Err(PinError::Locked);
        }

        if !bool::from(old_hash.ct_eq(&self.pin_hash)) {
            self.pin_retries_remaining = self.pin_retries_remaining.saturating_sub(1);
            if self.pin_retries_remaining == 0 {
                self.pin_blocked = true;
            }
            return Err(PinError::WrongCurrentPin);
        }

        // Old PIN correct — update hash, salt, and reset counter.
        self.pin_salt = new_pin_salt;
        self.pin_hash = Self::hash_pin(new_pin, device_id, &new_pin_salt);
        self.pin_retries_remaining = self.pin_max_retries;
        self.pin_blocked = false;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // PUK unblock
    // -----------------------------------------------------------------------

    /// Unblock a locked PIN using the PUK, then set a new PIN.
    ///
    /// PUK retry counter is decremented before verification.
    pub fn unblock_pin(
        &mut self,
        puk:          &[u8],
        new_pin:      &[u8],
        device_id:    &[u8],
        new_pin_salt: [u8; 16],
    ) -> Result<(), PinError> {
        validate_pin_length(new_pin)?;

        // Hash PUK (always, for timing resistance).
        let puk_hash = Self::hash_puk(puk, device_id, &self.puk_salt);

        if self.puk_blocked || self.puk_retries_remaining == 0 {
            return Err(PinError::PukLocked);
        }

        // Pre-decrement PUK counter.
        self.puk_retries_remaining = self.puk_retries_remaining.saturating_sub(1);

        if !bool::from(puk_hash.ct_eq(&self.puk_hash)) {
            if self.puk_retries_remaining == 0 {
                self.puk_blocked = true;
            }
            return Err(PinError::WrongCurrentPin);
        }

        // PUK correct — reset PUK counter, update PIN.
        self.puk_retries_remaining = MAX_PUK_RETRIES;
        self.puk_blocked = false;

        self.pin_salt = new_pin_salt;
        self.pin_hash = Self::hash_pin(new_pin, device_id, &new_pin_salt);
        self.pin_retries_remaining = self.pin_max_retries;
        self.pin_blocked = false;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Lockout
    // -----------------------------------------------------------------------

    /// Immediately lock the PIN (e.g. on security violation).
    pub fn lock_out(&mut self) {
        self.pin_retries_remaining = 0;
        self.pin_blocked = true;
        self.reset_session();
    }

    // -----------------------------------------------------------------------
    // Session management
    // -----------------------------------------------------------------------

    /// Clear the current session (deauthenticate).
    pub fn reset_session(&mut self) {
        self.session_authenticated = false;
        if let Some(ref mut sk) = self.session_key {
            sk.zeroize();
        }
        self.session_key = None;
    }
}

// ---------------------------------------------------------------------------
// Legacy PinManager (kept for backward compat with existing mod.rs stub)
// ---------------------------------------------------------------------------

/// Minimal PIN manager shim (backward-compatible with the prior stub API).
///
/// New code should use [`PinState`] directly.  This wrapper exists so that
/// existing callers of `PinManager::verify()` continue to compile without
/// modification.
pub struct PinManager {
    retry_count: u8,
    max_retries: u8,
    locked: bool,
}

impl PinManager {
    /// Create a new `PinManager` with the given retry limit.
    pub fn new(max_retries: u8) -> Self {
        PinManager {
            retry_count: max_retries,
            max_retries,
            locked: false,
        }
    }

    /// Verify a presented PIN.
    ///
    /// This stub always returns `Err(AuthError::WrongPin)` until wired to
    /// real storage.  Use [`PinState::verify_pin`] for the full implementation.
    pub fn verify(&mut self, _presented_pin: &[u8]) -> Result<(), AuthError> {
        if self.locked || self.retry_count == 0 {
            return Err(AuthError::PinLocked);
        }
        // Placeholder — real verification goes through PinState.
        Err(AuthError::WrongPin)
    }

    /// Change the PIN (stub — delegates to `PinState` in practice).
    pub fn change(&mut self, _old_pin: &[u8], _new_pin: &[u8]) -> Result<(), AuthError> {
        Err(AuthError::NotAuthenticated)
    }

    /// Reset the retry counter (called by RESET RETRY COUNTER command).
    pub fn reset_retry(&mut self) {
        self.retry_count = self.max_retries;
        self.locked = false;
    }

    /// Returns the number of remaining PIN attempts.
    pub fn retries_remaining(&self) -> u8 {
        self.retry_count
    }

    /// Returns `true` if the PIN is locked.
    pub fn is_locked(&self) -> bool {
        self.locked || self.retry_count == 0
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute `PBKDF2-HMAC-SHA256(password=credential, salt=device_id||suffix||extra_salt, ...)`.
fn hash_credential(
    credential: &[u8],
    device_id:  &[u8],
    suffix:     &[u8],
    extra_salt: &[u8; 16],
) -> [u8; 32] {
    // salt = device_id || suffix || extra_salt (stack allocated, max 256 bytes)
    let mut salt_buf = [0u8; 256];
    let d_len = device_id.len().min(200);
    let s_len = suffix.len().min(32);
    let e_len = 16;
    let total = d_len + s_len + e_len;
    debug_assert!(total <= salt_buf.len());

    salt_buf[..d_len].copy_from_slice(&device_id[..d_len]);
    salt_buf[d_len..d_len + s_len].copy_from_slice(&suffix[..s_len]);
    salt_buf[d_len + s_len..d_len + s_len + e_len].copy_from_slice(extra_salt);

    let salt = &salt_buf[..total];

    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(credential, salt, PIN_PBKDF2_ITERATIONS, &mut out);

    // Zeroize intermediate salt buffer.
    salt_buf.zeroize();

    out
}

/// Validate PIN length against policy.
fn validate_pin_length(pin: &[u8]) -> Result<(), PinError> {
    if pin.len() < MIN_PIN_LENGTH || pin.len() > MAX_PIN_LENGTH {
        Err(PinError::InvalidLength)
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE_ID: &[u8] = b"pico2hsm-test-dev";
    const TEST_PIN: &[u8] = b"123456";
    const TEST_PUK: &[u8] = b"12345678";
    const PIN_SALT: [u8; 16] = [0xAAu8; 16];
    const PUK_SALT: [u8; 16] = [0xBBu8; 16];

    fn make_pin_state() -> PinState {
        PinState::new(
            TEST_PIN,
            TEST_PUK,
            DEVICE_ID,
            PIN_SALT,
            PUK_SALT,
            MAX_PIN_RETRIES,
            MAX_PUK_RETRIES,
        ).unwrap()
    }

    #[test]
    fn test_hash_pin_deterministic() {
        let h1 = PinState::hash_pin(TEST_PIN, DEVICE_ID, &PIN_SALT);
        let h2 = PinState::hash_pin(TEST_PIN, DEVICE_ID, &PIN_SALT);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_pin_different_salt_differs() {
        let h1 = PinState::hash_pin(TEST_PIN, DEVICE_ID, &[0xAA; 16]);
        let h2 = PinState::hash_pin(TEST_PIN, DEVICE_ID, &[0xBB; 16]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_verify_correct_pin_succeeds() {
        let mut state = make_pin_state();
        let result = state.verify_pin(TEST_PIN, DEVICE_ID, None).unwrap();
        assert_eq!(result, PinVerifyResult::Success);
        assert!(state.session_authenticated);
        assert_eq!(state.pin_retries_remaining, MAX_PIN_RETRIES);
    }

    #[test]
    fn test_verify_wrong_pin_decrements_counter() {
        let mut state = make_pin_state();
        let result = state.verify_pin(b"wrong1", DEVICE_ID, None).unwrap();
        assert!(matches!(result, PinVerifyResult::WrongPin { retries_remaining: 2 }));
        assert!(!state.session_authenticated);
    }

    #[test]
    fn test_verify_lockout_after_max_retries() {
        let mut state = make_pin_state();
        // Exhaust all retries.
        for _ in 0..MAX_PIN_RETRIES {
            let _ = state.verify_pin(b"wrong1", DEVICE_ID, None);
        }
        let result = state.verify_pin(b"wrong1", DEVICE_ID, None).unwrap();
        assert_eq!(result, PinVerifyResult::Blocked);
        assert!(state.pin_blocked);
    }

    #[test]
    fn test_change_pin_correct_old_pin() {
        let mut state = make_pin_state();
        let new_salt = [0xCCu8; 16];
        state.change_pin(TEST_PIN, b"newpin123", DEVICE_ID, new_salt).unwrap();

        // Old PIN should no longer work.
        let r = state.verify_pin(TEST_PIN, DEVICE_ID, None).unwrap();
        assert!(matches!(r, PinVerifyResult::WrongPin { .. }));

        // New PIN should work.
        let r2 = state.verify_pin(b"newpin123", DEVICE_ID, None).unwrap();
        assert_eq!(r2, PinVerifyResult::Success);
    }

    #[test]
    fn test_change_pin_wrong_old_pin_fails() {
        let mut state = make_pin_state();
        let result = state.change_pin(b"wrong1", b"newpin123", DEVICE_ID, [0u8; 16]);
        assert_eq!(result, Err(PinError::WrongCurrentPin));
    }

    #[test]
    fn test_unblock_with_correct_puk() {
        let mut state = make_pin_state();
        state.lock_out();
        assert!(state.pin_blocked);

        let new_salt = [0xDDu8; 16];
        state.unblock_pin(TEST_PUK, b"newpin1", DEVICE_ID, new_salt).unwrap();
        assert!(!state.pin_blocked);

        let r = state.verify_pin(b"newpin1", DEVICE_ID, None).unwrap();
        assert_eq!(r, PinVerifyResult::Success);
    }

    #[test]
    fn test_unblock_wrong_puk_decrements_puk_counter() {
        let mut state = make_pin_state();
        state.lock_out();

        let result = state.unblock_pin(b"wrongpuk", b"newpin1", DEVICE_ID, [0u8; 16]);
        assert_eq!(result, Err(PinError::WrongCurrentPin));
        assert_eq!(state.puk_retries_remaining, MAX_PUK_RETRIES - 1);
    }

    #[test]
    fn test_session_reset_clears_key() {
        let smk = [0xABu8; 32];
        let mut state = make_pin_state();
        state.verify_pin(TEST_PIN, DEVICE_ID, Some(&smk)).unwrap();
        assert!(state.session_key.is_some());

        state.reset_session();
        assert!(!state.session_authenticated);
        assert!(state.session_key.is_none());
    }

    #[test]
    fn test_pin_length_validation() {
        assert!(validate_pin_length(b"12345").is_err()); // too short (5)
        assert!(validate_pin_length(b"123456").is_ok()); // minimum (6)
        assert!(validate_pin_length(b"1234567890123456").is_ok()); // maximum (16)
        assert!(validate_pin_length(b"12345678901234567").is_err()); // too long (17)
    }

    #[test]
    fn test_lockout_immediately_blocks() {
        let mut state = make_pin_state();
        state.lock_out();
        let r = state.verify_pin(TEST_PIN, DEVICE_ID, None).unwrap();
        assert_eq!(r, PinVerifyResult::Blocked);
    }
}
