//! PIN management tests.
//!
//! Tests `PinState` and `PinManager` from `security::pin`. All tests run on
//! x86_64. No embassy-rp / embassy-executor imports.

use pico2hsm_firmware::security::pin::{
    PinError, PinState, PinVerifyResult, MAX_PIN_LENGTH, MAX_PIN_RETRIES, MAX_PUK_RETRIES,
    MIN_PIN_LENGTH,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEVICE_ID: &[u8] = b"pico2hsm-test-dev-01";
const TEST_PIN: &[u8] = b"123456";
const TEST_PUK: &[u8] = b"12345678";
const PIN_SALT: [u8; 16] = [0xAAu8; 16];
const PUK_SALT: [u8; 16] = [0xBBu8; 16];

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn make_state() -> PinState {
    PinState::new(
        TEST_PIN,
        TEST_PUK,
        DEVICE_ID,
        PIN_SALT,
        PUK_SALT,
        MAX_PIN_RETRIES,
        MAX_PUK_RETRIES,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// Tests — PIN hash
// ---------------------------------------------------------------------------

#[test]
fn test_pin_hash_deterministic() {
    let h1 = PinState::hash_pin(TEST_PIN, DEVICE_ID, &PIN_SALT);
    let h2 = PinState::hash_pin(TEST_PIN, DEVICE_ID, &PIN_SALT);
    assert_eq!(
        h1, h2,
        "PIN hash must be deterministic for identical inputs"
    );
}

#[test]
fn test_pin_hash_different_pins_differ() {
    let h1 = PinState::hash_pin(b"111111", DEVICE_ID, &PIN_SALT);
    let h2 = PinState::hash_pin(b"222222", DEVICE_ID, &PIN_SALT);
    assert_ne!(h1, h2, "Different PINs must produce different hashes");
}

#[test]
fn test_pin_hash_different_salts_differ() {
    let h1 = PinState::hash_pin(TEST_PIN, DEVICE_ID, &[0xAAu8; 16]);
    let h2 = PinState::hash_pin(TEST_PIN, DEVICE_ID, &[0xBBu8; 16]);
    assert_ne!(h1, h2, "Different salts must produce different hashes");
}

#[test]
fn test_pin_hash_different_device_ids_differ() {
    let h1 = PinState::hash_pin(TEST_PIN, b"device-A", &PIN_SALT);
    let h2 = PinState::hash_pin(TEST_PIN, b"device-B", &PIN_SALT);
    assert_ne!(h1, h2, "Different device IDs must produce different hashes");
}

#[test]
fn test_pin_hash_is_32_bytes() {
    let h = PinState::hash_pin(TEST_PIN, DEVICE_ID, &PIN_SALT);
    assert_eq!(h.len(), 32, "PIN hash must be 32 bytes");
}

// ---------------------------------------------------------------------------
// Tests — PIN verify
// ---------------------------------------------------------------------------

#[test]
fn test_pin_verify_correct() {
    let mut state = make_state();
    let result = state.verify_pin(TEST_PIN, DEVICE_ID, None).unwrap();

    assert_eq!(
        result,
        PinVerifyResult::Success,
        "Correct PIN must return Success"
    );
    assert!(
        state.session_authenticated,
        "Session must be authenticated after success"
    );
    assert_eq!(
        state.pin_retries_remaining, MAX_PIN_RETRIES,
        "Retry count must be restored after correct PIN"
    );
}

#[test]
fn test_pin_verify_wrong() {
    let mut state = make_state();
    let result = state.verify_pin(b"wrong1", DEVICE_ID, None).unwrap();

    assert!(
        matches!(
            result,
            PinVerifyResult::WrongPin {
                retries_remaining: 2
            }
        ),
        "First wrong PIN must return WrongPin with 2 retries remaining"
    );
    assert!(
        !state.session_authenticated,
        "Session must not be authenticated after wrong PIN"
    );
    assert_eq!(state.pin_retries_remaining, 2);
}

#[test]
fn test_pin_verify_wrong_second_attempt() {
    let mut state = make_state();
    let _ = state.verify_pin(b"wrong1", DEVICE_ID, None);
    let result = state.verify_pin(b"wrong2", DEVICE_ID, None).unwrap();

    assert!(
        matches!(
            result,
            PinVerifyResult::WrongPin {
                retries_remaining: 1
            }
        ),
        "Second wrong PIN must return WrongPin with 1 retry remaining"
    );
}

#[test]
fn test_pin_lockout_at_zero_retries() {
    let mut state = make_state();

    // Exhaust all retries
    for _ in 0..MAX_PIN_RETRIES {
        let _ = state.verify_pin(b"wrong1", DEVICE_ID, None);
    }

    // Next attempt: blocked
    let result = state.verify_pin(b"wrong1", DEVICE_ID, None).unwrap();
    assert_eq!(
        result,
        PinVerifyResult::Blocked,
        "PIN after lockout must return Blocked"
    );
    assert!(state.pin_blocked, "pin_blocked flag must be set");
    assert_eq!(state.pin_retries_remaining, 0);
}

#[test]
fn test_pin_correct_after_wrong_restores_counter() {
    let mut state = make_state();

    // One wrong attempt
    let _ = state.verify_pin(b"wrong1", DEVICE_ID, None);
    assert_eq!(state.pin_retries_remaining, 2);

    // Correct PIN — counter must be restored
    let result = state.verify_pin(TEST_PIN, DEVICE_ID, None).unwrap();
    assert_eq!(result, PinVerifyResult::Success);
    assert_eq!(
        state.pin_retries_remaining, MAX_PIN_RETRIES,
        "Retry counter must reset after successful verify"
    );
}

#[test]
fn test_pin_blocked_returns_blocked_even_for_correct_pin() {
    let mut state = make_state();

    // Lock the PIN out
    for _ in 0..MAX_PIN_RETRIES {
        let _ = state.verify_pin(b"wrong1", DEVICE_ID, None);
    }

    // Even the correct PIN returns Blocked
    let result = state.verify_pin(TEST_PIN, DEVICE_ID, None).unwrap();
    assert_eq!(
        result,
        PinVerifyResult::Blocked,
        "Correct PIN after lockout must still return Blocked"
    );
}

// ---------------------------------------------------------------------------
// Tests — Session key derivation
// ---------------------------------------------------------------------------

#[test]
fn test_verify_with_smk_derives_session_key() {
    let smk = [0xDEu8; 32];
    let mut state = make_state();

    state.verify_pin(TEST_PIN, DEVICE_ID, Some(&smk)).unwrap();

    assert!(
        state.session_key.is_some(),
        "Session key must be derived on success"
    );
    assert_eq!(
        state.session_key.as_ref().unwrap().len(),
        32,
        "Session key must be 32 bytes"
    );
}

#[test]
fn test_verify_session_key_is_deterministic() {
    let smk = [0xEFu8; 32];

    let mut state1 = make_state();
    state1.verify_pin(TEST_PIN, DEVICE_ID, Some(&smk)).unwrap();
    let sk1: [u8; 32] = **state1.session_key.as_ref().unwrap();

    let mut state2 = make_state();
    state2.verify_pin(TEST_PIN, DEVICE_ID, Some(&smk)).unwrap();
    let sk2: [u8; 32] = **state2.session_key.as_ref().unwrap();

    assert_eq!(
        sk1, sk2,
        "Session key must be deterministic for same SMK + PIN"
    );
}

#[test]
fn test_verify_different_smk_different_session_key() {
    let smk1 = [0x01u8; 32];
    let smk2 = [0x02u8; 32];

    let mut state1 = make_state();
    state1.verify_pin(TEST_PIN, DEVICE_ID, Some(&smk1)).unwrap();
    let sk1: [u8; 32] = **state1.session_key.as_ref().unwrap();

    let mut state2 = make_state();
    state2.verify_pin(TEST_PIN, DEVICE_ID, Some(&smk2)).unwrap();
    let sk2: [u8; 32] = **state2.session_key.as_ref().unwrap();

    assert_ne!(
        sk1, sk2,
        "Different SMKs must produce different session keys"
    );
}

#[test]
fn test_reset_session_clears_session_key() {
    let smk = [0xABu8; 32];
    let mut state = make_state();

    state.verify_pin(TEST_PIN, DEVICE_ID, Some(&smk)).unwrap();
    assert!(state.session_key.is_some());
    assert!(state.session_authenticated);

    state.reset_session();

    assert!(
        !state.session_authenticated,
        "session_authenticated must be false after reset"
    );
    assert!(
        state.session_key.is_none(),
        "session_key must be None after reset"
    );
}

// ---------------------------------------------------------------------------
// Tests — PIN change
// ---------------------------------------------------------------------------

#[test]
fn test_pin_change_correct_old_pin() {
    let mut state = make_state();
    let new_salt = [0xCCu8; 16];
    let new_pin = b"newpin1!";

    state
        .change_pin(TEST_PIN, new_pin, DEVICE_ID, new_salt)
        .unwrap();

    // Old PIN must no longer work
    let r_old = state.verify_pin(TEST_PIN, DEVICE_ID, None).unwrap();
    assert!(
        matches!(r_old, PinVerifyResult::WrongPin { .. }),
        "Old PIN must not work after change"
    );

    // New PIN must work
    let r_new = state.verify_pin(new_pin, DEVICE_ID, None).unwrap();
    assert_eq!(
        r_new,
        PinVerifyResult::Success,
        "New PIN must work after change"
    );
}

#[test]
fn test_pin_change_wrong_old_pin_fails() {
    let mut state = make_state();
    let result = state.change_pin(b"wrong1", b"newpin1!", DEVICE_ID, [0u8; 16]);

    assert_eq!(
        result,
        Err(PinError::WrongCurrentPin),
        "Wrong old PIN must return WrongCurrentPin"
    );
}

#[test]
fn test_pin_change_new_pin_too_short_fails() {
    let mut state = make_state();
    let result = state.change_pin(TEST_PIN, b"short", DEVICE_ID, [0u8; 16]);

    assert_eq!(
        result,
        Err(PinError::InvalidLength),
        "New PIN too short must return InvalidLength"
    );
}

#[test]
fn test_pin_change_new_pin_too_long_fails() {
    let mut state = make_state();
    let long_pin = [b'x'; MAX_PIN_LENGTH + 1];
    let result = state.change_pin(TEST_PIN, &long_pin, DEVICE_ID, [0u8; 16]);

    assert_eq!(
        result,
        Err(PinError::InvalidLength),
        "New PIN too long must return InvalidLength"
    );
}

#[test]
fn test_pin_change_resets_retry_counter() {
    let mut state = make_state();

    // Burn one retry
    let _ = state.verify_pin(b"wrong1", DEVICE_ID, None);
    assert_eq!(state.pin_retries_remaining, 2);

    // Change PIN — should reset counter
    state
        .change_pin(TEST_PIN, b"newpin99", DEVICE_ID, [0xDDu8; 16])
        .unwrap();
    assert_eq!(
        state.pin_retries_remaining, MAX_PIN_RETRIES,
        "Retry counter must reset after PIN change"
    );
}

#[test]
fn test_pin_change_locked_pin_fails() {
    let mut state = make_state();
    for _ in 0..MAX_PIN_RETRIES {
        let _ = state.verify_pin(b"wrong1", DEVICE_ID, None);
    }

    let result = state.change_pin(TEST_PIN, b"newpin99", DEVICE_ID, [0u8; 16]);
    assert_eq!(
        result,
        Err(PinError::Locked),
        "PIN change on locked PIN must return Locked"
    );
}

// ---------------------------------------------------------------------------
// Tests — PUK unblock
// ---------------------------------------------------------------------------

#[test]
fn test_puk_unblock_correct_puk() {
    let mut state = make_state();
    state.lock_out();
    assert!(state.pin_blocked);

    let new_salt = [0xEEu8; 16];
    state
        .unblock_pin(TEST_PUK, b"newpin11", DEVICE_ID, new_salt)
        .unwrap();

    assert!(
        !state.pin_blocked,
        "PIN must be unblocked after PUK unblock"
    );
    let r = state.verify_pin(b"newpin11", DEVICE_ID, None).unwrap();
    assert_eq!(
        r,
        PinVerifyResult::Success,
        "New PIN must work after PUK unblock"
    );
}

#[test]
fn test_puk_unblock_wrong_puk_fails() {
    let mut state = make_state();
    state.lock_out();

    let result = state.unblock_pin(b"wrongpuk", b"newpin11", DEVICE_ID, [0u8; 16]);
    assert_eq!(
        result,
        Err(PinError::WrongCurrentPin),
        "Wrong PUK must return WrongCurrentPin"
    );
}

#[test]
fn test_puk_unblock_decrements_puk_counter() {
    let mut state = make_state();
    state.lock_out();

    let _ = state.unblock_pin(b"wrongpuk", b"newpin11", DEVICE_ID, [0u8; 16]);
    assert_eq!(
        state.puk_retries_remaining,
        MAX_PUK_RETRIES - 1,
        "PUK counter must decrement on wrong PUK"
    );
}

#[test]
fn test_puk_correct_resets_puk_counter() {
    let mut state = make_state();
    state.lock_out();

    // Burn one PUK retry
    let _ = state.unblock_pin(b"wrongpuk", b"newpin11", DEVICE_ID, [0u8; 16]);
    assert_eq!(state.puk_retries_remaining, MAX_PUK_RETRIES - 1);

    // Correct PUK — should restore PUK counter
    state
        .unblock_pin(TEST_PUK, b"newpin11", DEVICE_ID, [0xFFu8; 16])
        .unwrap();
    assert_eq!(
        state.puk_retries_remaining, MAX_PUK_RETRIES,
        "PUK counter must reset after successful unblock"
    );
}

// ---------------------------------------------------------------------------
// Tests — Lockout
// ---------------------------------------------------------------------------

#[test]
fn test_lockout_immediately_blocks() {
    let mut state = make_state();
    state.lock_out();

    let result = state.verify_pin(TEST_PIN, DEVICE_ID, None).unwrap();
    assert_eq!(
        result,
        PinVerifyResult::Blocked,
        "lock_out must immediately block the PIN"
    );
}

#[test]
fn test_lockout_clears_session() {
    let smk = [0xABu8; 32];
    let mut state = make_state();

    state.verify_pin(TEST_PIN, DEVICE_ID, Some(&smk)).unwrap();
    assert!(state.session_authenticated);

    state.lock_out();

    assert!(
        !state.session_authenticated,
        "lock_out must clear the session"
    );
    assert!(
        state.session_key.is_none(),
        "lock_out must clear session key"
    );
}

// ---------------------------------------------------------------------------
// Tests — PIN length validation (via PinState::new)
// ---------------------------------------------------------------------------

#[test]
fn test_pin_length_minimum_accepted() {
    let min_pin = vec![b'1'; MIN_PIN_LENGTH];
    let result = PinState::new(
        &min_pin,
        TEST_PUK,
        DEVICE_ID,
        PIN_SALT,
        PUK_SALT,
        MAX_PIN_RETRIES,
        MAX_PUK_RETRIES,
    );
    assert!(
        result.is_ok(),
        "PIN of minimum length ({}) must be accepted",
        MIN_PIN_LENGTH
    );
}

#[test]
fn test_pin_length_too_short_rejected() {
    let short_pin = vec![b'1'; MIN_PIN_LENGTH - 1];
    let result = PinState::new(
        &short_pin,
        TEST_PUK,
        DEVICE_ID,
        PIN_SALT,
        PUK_SALT,
        MAX_PIN_RETRIES,
        MAX_PUK_RETRIES,
    );
    assert!(
        matches!(result, Err(PinError::InvalidLength)),
        "PIN shorter than {} bytes must be rejected",
        MIN_PIN_LENGTH
    );
}

#[test]
fn test_pin_length_maximum_accepted() {
    let max_pin = vec![b'A'; MAX_PIN_LENGTH];
    let result = PinState::new(
        &max_pin,
        TEST_PUK,
        DEVICE_ID,
        PIN_SALT,
        PUK_SALT,
        MAX_PIN_RETRIES,
        MAX_PUK_RETRIES,
    );
    assert!(
        result.is_ok(),
        "PIN of maximum length ({}) must be accepted",
        MAX_PIN_LENGTH
    );
}

#[test]
fn test_pin_length_too_long_rejected() {
    let long_pin = vec![b'Z'; MAX_PIN_LENGTH + 1];
    let result = PinState::new(
        &long_pin,
        TEST_PUK,
        DEVICE_ID,
        PIN_SALT,
        PUK_SALT,
        MAX_PIN_RETRIES,
        MAX_PUK_RETRIES,
    );
    assert!(
        matches!(result, Err(PinError::InvalidLength)),
        "PIN longer than {} bytes must be rejected",
        MAX_PIN_LENGTH
    );
}

// ---------------------------------------------------------------------------
// Tests — PinManager (legacy shim)
// ---------------------------------------------------------------------------

use pico2hsm_firmware::security::pin::PinManager;

#[test]
fn test_pin_manager_always_returns_wrong_pin() {
    let mut mgr = PinManager::new(3);
    let result = mgr.verify(b"anypinvalue");
    // PinManager is a stub that always returns WrongPin until wired to storage
    assert!(
        result.is_err(),
        "PinManager stub must return Err for any PIN"
    );
}

#[test]
fn test_pin_manager_locked_returns_locked() {
    // Create manager with 0 retries (already locked)
    let mut mgr = PinManager::new(0);
    use pico2hsm_core::error::AuthError;
    let result = mgr.verify(b"anypin");
    assert_eq!(
        result,
        Err(AuthError::PinLocked),
        "PinManager with 0 retries must return PinLocked"
    );
}

#[test]
fn test_pin_manager_retries_remaining() {
    let mgr = PinManager::new(5);
    assert_eq!(mgr.retries_remaining(), 5);
}

#[test]
fn test_pin_manager_is_locked_when_zero() {
    let mgr = PinManager::new(0);
    assert!(
        mgr.is_locked(),
        "PinManager with 0 retries must report locked"
    );
}

#[test]
fn test_pin_manager_reset_retry() {
    let mut mgr = PinManager::new(3);
    // Decrement manually (no public method, so just check reset works)
    mgr.reset_retry();
    assert!(
        !mgr.is_locked(),
        "After reset_retry, manager must not be locked"
    );
    assert_eq!(mgr.retries_remaining(), 3);
}
