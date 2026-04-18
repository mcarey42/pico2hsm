//! DKEK (Device Key Encryption Key) tests.
//!
//! Tests the DkekManager state machine (share collection, XOR accumulation),
//! the share blob encrypt/decrypt helpers, and the simplified Noise-like
//! DKEK exchange protocol.
//! No embassy-rp / embassy-executor imports — all tests run on x86_64.

use pico2hsm_firmware::security::dkek::{
    encrypt_share_blob, DkekError, DkekImportResult, DkekManager, SHARE_BLOB_SIZE,
};

// ---------------------------------------------------------------------------
// Deterministic RNG (same as in crypto_tests.rs)
// ---------------------------------------------------------------------------

struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn seeded(seed: u64) -> Self {
        DeterministicRng { state: seed | 1 }
    }
}

impl rand_core::RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&v[..n]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for DeterministicRng {}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEVICE_ID: [u8; 16] = [0x01; 16];

/// A fixed 32-byte share value for deterministic tests.
const SHARE_VALUE_A: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01,
];

const SHARE_VALUE_B: [u8; 32] = [
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
    0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0, 0x09, 0x18, 0x27, 0x36, 0x45, 0x54, 0x63, 0x72,
];

const TEST_PASSWORD_A: &[u8] = b"password-for-share-A";
const TEST_PASSWORD_B: &[u8] = b"password-for-share-B";

/// Fixed IV for deterministic share blob encryption in tests.
const TEST_IV: [u8; 16] = [0xAA; 16];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encrypt a share into the 64-byte blob format and return it.
fn make_blob(share: &[u8; 32], password: &[u8]) -> [u8; SHARE_BLOB_SIZE] {
    encrypt_share_blob(share, password, &TEST_IV).unwrap()
}

// ---------------------------------------------------------------------------
// Tests — DkekManager state machine
// ---------------------------------------------------------------------------

#[test]
fn test_dkek_not_initialized_state() {
    let mgr = DkekManager::new(DEVICE_ID);
    assert!(!mgr.is_ready(), "Fresh DkekManager must not be ready");
    assert_eq!(mgr.shares_received(), 0);
    assert_eq!(mgr.shares_total(), 0);
    assert!(
        mgr.get_dkek().is_none(),
        "get_dkek must return None when not initialized"
    );
}

#[test]
fn test_dkek_init_zero_shares_stays_not_initialized() {
    let mut mgr = DkekManager::new(DEVICE_ID);
    mgr.init_shares(0);

    assert!(!mgr.is_ready(), "n=0 must leave manager NotInitialized");
    assert!(mgr.get_dkek().is_none());
}

#[test]
fn test_dkek_single_share_completes() {
    let mut mgr = DkekManager::new(DEVICE_ID);
    mgr.init_shares(1);

    let blob = make_blob(&SHARE_VALUE_A, TEST_PASSWORD_A);
    let result = mgr.import_share(&blob, TEST_PASSWORD_A).unwrap();

    assert_eq!(
        result,
        DkekImportResult::Complete,
        "n=1: single share must complete the DKEK"
    );
    assert!(mgr.is_ready(), "Manager must be Ready after n=1 share");
    assert_eq!(mgr.shares_received(), 1);
    assert_eq!(mgr.shares_total(), 1);
}

#[test]
fn test_dkek_single_share_value_is_the_share() {
    // When n=1, DKEK = XOR(share) = share itself
    let mut mgr = DkekManager::new(DEVICE_ID);
    mgr.init_shares(1);

    let blob = make_blob(&SHARE_VALUE_A, TEST_PASSWORD_A);
    mgr.import_share(&blob, TEST_PASSWORD_A).unwrap();

    let dkek = mgr.get_dkek().unwrap();
    assert_eq!(
        dkek, &SHARE_VALUE_A,
        "n=1: DKEK must equal the single share value"
    );
}

#[test]
fn test_dkek_two_shares_xor_accumulation() {
    // When n=2, DKEK = share_A XOR share_B
    let mut mgr = DkekManager::new(DEVICE_ID);
    mgr.init_shares(2);

    let blob_a = make_blob(&SHARE_VALUE_A, TEST_PASSWORD_A);
    let blob_b = make_blob(&SHARE_VALUE_B, TEST_PASSWORD_B);

    let r1 = mgr.import_share(&blob_a, TEST_PASSWORD_A).unwrap();
    assert_eq!(
        r1,
        DkekImportResult::MoreSharesNeeded {
            received: 1,
            total: 2
        },
        "After first of two shares, manager must report MoreSharesNeeded"
    );
    assert!(
        !mgr.is_ready(),
        "Manager must not be ready after only one of two shares"
    );

    let r2 = mgr.import_share(&blob_b, TEST_PASSWORD_B).unwrap();
    assert_eq!(
        r2,
        DkekImportResult::Complete,
        "After second share, manager must complete"
    );
    assert!(mgr.is_ready());

    let expected_dkek: [u8; 32] = core::array::from_fn(|i| SHARE_VALUE_A[i] ^ SHARE_VALUE_B[i]);
    let dkek = mgr.get_dkek().unwrap();
    assert_eq!(dkek, &expected_dkek, "n=2: DKEK must be XOR of both shares");
}

#[test]
fn test_dkek_two_shares_received_count() {
    let mut mgr = DkekManager::new(DEVICE_ID);
    mgr.init_shares(2);

    let blob_a = make_blob(&SHARE_VALUE_A, TEST_PASSWORD_A);
    let blob_b = make_blob(&SHARE_VALUE_B, TEST_PASSWORD_B);

    assert_eq!(mgr.shares_received(), 0);
    mgr.import_share(&blob_a, TEST_PASSWORD_A).unwrap();
    assert_eq!(mgr.shares_received(), 1);
    mgr.import_share(&blob_b, TEST_PASSWORD_B).unwrap();
    assert_eq!(mgr.shares_received(), 2);
}

#[test]
fn test_dkek_import_in_wrong_state_fails() {
    // Manager not initialized — import_share should return WrongState
    let mut mgr = DkekManager::new(DEVICE_ID);

    let blob = make_blob(&SHARE_VALUE_A, TEST_PASSWORD_A);
    let result = mgr.import_share(&blob, TEST_PASSWORD_A);

    assert_eq!(
        result,
        Err(DkekError::WrongState),
        "import_share before init_shares must return WrongState"
    );
}

#[test]
fn test_dkek_import_after_complete_fails() {
    let mut mgr = DkekManager::new(DEVICE_ID);
    mgr.init_shares(1);

    let blob = make_blob(&SHARE_VALUE_A, TEST_PASSWORD_A);
    mgr.import_share(&blob, TEST_PASSWORD_A).unwrap(); // completes

    // Try to import another share — should fail with WrongState (Ready, not Collecting)
    let blob2 = make_blob(&SHARE_VALUE_B, TEST_PASSWORD_B);
    let result = mgr.import_share(&blob2, TEST_PASSWORD_B);

    assert_eq!(
        result,
        Err(DkekError::WrongState),
        "import_share after completion must return WrongState"
    );
}

#[test]
fn test_dkek_clear_resets_to_not_initialized() {
    let mut mgr = DkekManager::new(DEVICE_ID);
    mgr.init_shares(1);

    let blob = make_blob(&SHARE_VALUE_A, TEST_PASSWORD_A);
    mgr.import_share(&blob, TEST_PASSWORD_A).unwrap();
    assert!(mgr.is_ready());

    mgr.clear();

    assert!(!mgr.is_ready(), "After clear(), manager must not be ready");
    assert!(
        mgr.get_dkek().is_none(),
        "After clear(), get_dkek must return None"
    );
    assert_eq!(mgr.shares_total(), 0);
}

#[test]
fn test_dkek_reinit_resets_accumulated_shares() {
    let mut mgr = DkekManager::new(DEVICE_ID);
    mgr.init_shares(2);

    let blob_a = make_blob(&SHARE_VALUE_A, TEST_PASSWORD_A);
    mgr.import_share(&blob_a, TEST_PASSWORD_A).unwrap();
    assert_eq!(mgr.shares_received(), 1);

    // Re-init with n=1 — should clear the partial accumulation
    mgr.init_shares(1);
    assert_eq!(
        mgr.shares_received(),
        0,
        "Re-init must reset received count"
    );

    // Fresh single share should complete
    let blob2 = make_blob(&SHARE_VALUE_B, TEST_PASSWORD_B);
    let result = mgr.import_share(&blob2, TEST_PASSWORD_B).unwrap();
    assert_eq!(result, DkekImportResult::Complete);

    // DKEK must be SHARE_VALUE_B (not XOR with A)
    assert_eq!(mgr.get_dkek().unwrap(), &SHARE_VALUE_B);
}

// ---------------------------------------------------------------------------
// Tests — Wrong password on share import
// ---------------------------------------------------------------------------

#[test]
fn test_dkek_wrong_password_fails() {
    let mut mgr = DkekManager::new(DEVICE_ID);
    mgr.init_shares(1);

    let blob = make_blob(&SHARE_VALUE_A, TEST_PASSWORD_A);
    let result = mgr.import_share(&blob, b"wrong-password");

    // Wrong password → decryption succeeds but SHA-256 integrity check fails
    assert!(
        matches!(
            result,
            Err(DkekError::ShareDecryptFailure) | Err(DkekError::ShareIntegrityFailure)
        ),
        "Wrong password must return decrypt or integrity failure, got {:?}",
        result
    );
}

#[test]
fn test_dkek_share_tamper_detected() {
    let mut mgr = DkekManager::new(DEVICE_ID);
    mgr.init_shares(1);

    let mut blob = make_blob(&SHARE_VALUE_A, TEST_PASSWORD_A);
    // Flip a byte in the ciphertext portion (bytes 16..64)
    blob[20] ^= 0xFF;

    let result = mgr.import_share(&blob, TEST_PASSWORD_A);

    assert!(
        matches!(
            result,
            Err(DkekError::ShareDecryptFailure) | Err(DkekError::ShareIntegrityFailure)
        ),
        "Tampered share blob must return an error"
    );
}

#[test]
fn test_dkek_invalid_blob_length_fails() {
    let mut mgr = DkekManager::new(DEVICE_ID);
    mgr.init_shares(1);

    // Blob is too short
    let short_blob = [0u8; 32];
    let result = mgr.import_share(&short_blob, TEST_PASSWORD_A);

    assert_eq!(
        result,
        Err(DkekError::InvalidShareBlob),
        "Too-short share blob must return InvalidShareBlob"
    );
}

// ---------------------------------------------------------------------------
// Tests — share blob encrypt/decrypt
// ---------------------------------------------------------------------------

#[test]
fn test_share_blob_size() {
    let blob = encrypt_share_blob(&SHARE_VALUE_A, TEST_PASSWORD_A, &TEST_IV).unwrap();
    assert_eq!(
        blob.len(),
        SHARE_BLOB_SIZE,
        "Share blob must be exactly SHARE_BLOB_SIZE bytes"
    );
    assert_eq!(
        SHARE_BLOB_SIZE, 80,
        "SHARE_BLOB_SIZE must be 80 (IV=16 + ciphertext=64)"
    );
}

#[test]
fn test_share_blob_iv_at_start() {
    let blob = encrypt_share_blob(&SHARE_VALUE_A, TEST_PASSWORD_A, &TEST_IV).unwrap();
    assert_eq!(
        &blob[..16],
        &TEST_IV,
        "First 16 bytes of share blob must be the IV"
    );
}

#[test]
fn test_share_blob_different_passwords_different_blobs() {
    let blob_a = encrypt_share_blob(&SHARE_VALUE_A, b"pass1", &TEST_IV).unwrap();
    let blob_b = encrypt_share_blob(&SHARE_VALUE_A, b"pass2", &TEST_IV).unwrap();

    // IV part is the same (same TEST_IV), ciphertext must differ
    assert_ne!(
        &blob_a[16..],
        &blob_b[16..],
        "Different passwords must produce different ciphertexts"
    );
}

#[test]
fn test_share_blob_different_shares_different_blobs() {
    let blob_a = encrypt_share_blob(&SHARE_VALUE_A, TEST_PASSWORD_A, &TEST_IV).unwrap();
    let blob_b = encrypt_share_blob(&SHARE_VALUE_B, TEST_PASSWORD_A, &TEST_IV).unwrap();

    assert_ne!(
        &blob_a[16..],
        &blob_b[16..],
        "Different share values must produce different ciphertexts"
    );
}

#[test]
fn test_share_blob_roundtrip_via_import() {
    let mut mgr = DkekManager::new(DEVICE_ID);
    mgr.init_shares(1);

    let blob = encrypt_share_blob(&SHARE_VALUE_A, TEST_PASSWORD_A, &TEST_IV).unwrap();
    mgr.import_share(&blob, TEST_PASSWORD_A).unwrap();

    assert_eq!(mgr.get_dkek().unwrap(), &SHARE_VALUE_A);
}

// ---------------------------------------------------------------------------
// Tests — DKEK exchange (simplified Noise-like P-256 ECDH)
// ---------------------------------------------------------------------------

#[test]
fn test_noise_exchange_roundtrip() {
    use pico2hsm_core::key::KeyType as CryptoKeyType;
    use pico2hsm_firmware::crypto::asymmetric::generate_ec_keypair;

    let mut rng = DeterministicRng::seeded(0xDEAD_CAFE);

    // Set up a DKEK on the sender side
    let mut sender = DkekManager::new(DEVICE_ID);
    sender.init_shares(1);
    let blob = make_blob(&SHARE_VALUE_A, TEST_PASSWORD_A);
    sender.import_share(&blob, TEST_PASSWORD_A).unwrap();
    assert!(sender.is_ready());

    // Generate ephemeral P-256 keypairs for both sides
    let alice_pair = generate_ec_keypair(CryptoKeyType::EcPrivateP256, &mut rng).unwrap();
    let bob_pair = generate_ec_keypair(CryptoKeyType::EcPrivateP256, &mut rng).unwrap();

    let alice_priv: [u8; 32] = alice_pair.private_key.as_slice().try_into().unwrap();
    let bob_priv: [u8; 32] = bob_pair.private_key.as_slice().try_into().unwrap();

    let alice_pub: [u8; 65] = alice_pair.public_key.as_slice().try_into().unwrap();
    let bob_pub: [u8; 65] = bob_pair.public_key.as_slice().try_into().unwrap();

    // Sender (Alice) encrypts the DKEK for Bob using Bob's ephemeral public key
    let encrypted_dkek = sender
        .noise_send_dkek_data(&bob_pub, &alice_priv, &mut rng)
        .unwrap();

    // Receiver (Bob) decrypts the DKEK using Alice's public key and his private key
    let mut receiver = DkekManager::new(DEVICE_ID);
    receiver
        .noise_recv_dkek_data(
            &alice_pub,
            &bob_priv,
            &encrypted_dkek,
            &DEVICE_ID, // initiator_device_id used as AAD
        )
        .unwrap();

    assert!(
        receiver.is_ready(),
        "Receiver must be ready after noise exchange"
    );
    assert_eq!(
        receiver.get_dkek().unwrap(),
        sender.get_dkek().unwrap(),
        "Receiver must hold the same DKEK as sender after exchange"
    );
}

#[test]
fn test_noise_recv_wrong_key_fails() {
    use pico2hsm_core::key::KeyType as CryptoKeyType;
    use pico2hsm_firmware::crypto::asymmetric::generate_ec_keypair;

    let mut rng = DeterministicRng::seeded(0x9999_CAFE);

    let mut sender = DkekManager::new(DEVICE_ID);
    sender.init_shares(1);
    sender
        .import_share(&make_blob(&SHARE_VALUE_A, TEST_PASSWORD_A), TEST_PASSWORD_A)
        .unwrap();

    let alice_pair = generate_ec_keypair(CryptoKeyType::EcPrivateP256, &mut rng).unwrap();
    let bob_pair = generate_ec_keypair(CryptoKeyType::EcPrivateP256, &mut rng).unwrap();
    let mallory_pair = generate_ec_keypair(CryptoKeyType::EcPrivateP256, &mut rng).unwrap();

    let alice_priv: [u8; 32] = alice_pair.private_key.as_slice().try_into().unwrap();
    let bob_pub: [u8; 65] = bob_pair.public_key.as_slice().try_into().unwrap();

    let alice_pub: [u8; 65] = alice_pair.public_key.as_slice().try_into().unwrap();
    let mallory_priv: [u8; 32] = mallory_pair.private_key.as_slice().try_into().unwrap();

    // Sender encrypts for Bob
    let encrypted_dkek = sender
        .noise_send_dkek_data(&bob_pub, &alice_priv, &mut rng)
        .unwrap();

    // Mallory tries to decrypt — wrong private key → AES-GCM tag failure
    let mut receiver = DkekManager::new(DEVICE_ID);
    let result =
        receiver.noise_recv_dkek_data(&alice_pub, &mallory_priv, &encrypted_dkek, &DEVICE_ID);

    assert!(
        matches!(result, Err(DkekError::DecryptFailure)),
        "noise_recv with wrong private key must fail with DecryptFailure"
    );
}

#[test]
fn test_noise_send_without_dkek_fails() {
    let mut rng = DeterministicRng::seeded(0x1234);
    use pico2hsm_core::key::KeyType as CryptoKeyType;
    use pico2hsm_firmware::crypto::asymmetric::generate_ec_keypair;

    let sender = DkekManager::new(DEVICE_ID); // Not initialized
    let bob_pair = generate_ec_keypair(CryptoKeyType::EcPrivateP256, &mut rng).unwrap();
    let fake_priv = [0x01u8; 32];
    let bob_pub: [u8; 65] = bob_pair.public_key.as_slice().try_into().unwrap();

    let result = sender.noise_send_dkek_data(&bob_pub, &fake_priv, &mut rng);
    assert_eq!(
        result,
        Err(DkekError::WrongState),
        "noise_send without DKEK must return WrongState"
    );
}

// ---------------------------------------------------------------------------
// Tests — Static key derivation
// ---------------------------------------------------------------------------

#[test]
fn test_derive_static_private_key_deterministic() {
    let otp_key = [0x42u8; 32];
    let sk1 = DkekManager::derive_static_private_key(&otp_key);
    let sk2 = DkekManager::derive_static_private_key(&otp_key);
    assert_eq!(*sk1, *sk2, "Static key derivation must be deterministic");
}

#[test]
fn test_derive_static_private_key_different_otp_differs() {
    let otp1 = [0x01u8; 32];
    let otp2 = [0x02u8; 32];
    let sk1 = DkekManager::derive_static_private_key(&otp1);
    let sk2 = DkekManager::derive_static_private_key(&otp2);
    assert_ne!(
        *sk1, *sk2,
        "Different OTP keys must produce different static keys"
    );
}

#[test]
fn test_derive_static_private_key_is_32_bytes() {
    let otp_key = [0xFFu8; 32];
    let sk = DkekManager::derive_static_private_key(&otp_key);
    assert_eq!(sk.len(), 32, "Static key must be 32 bytes");
}

// ---------------------------------------------------------------------------
// Tests — share generation
// ---------------------------------------------------------------------------

#[test]
fn test_generate_share_returns_32_bytes() {
    let mgr = DkekManager::new(DEVICE_ID);
    let mut rng = DeterministicRng::seeded(0xABCD);
    let share = mgr.generate_share(&mut rng);
    assert_eq!(share.len(), 32, "Generated share must be 32 bytes");
}

#[test]
fn test_generate_share_two_calls_differ() {
    let mgr = DkekManager::new(DEVICE_ID);
    let mut rng = DeterministicRng::seeded(0xBEEF);
    let share1 = *mgr.generate_share(&mut rng);
    let share2 = *mgr.generate_share(&mut rng);
    assert_ne!(
        share1, share2,
        "Two consecutive share generations must differ"
    );
}

// Use core:: for no_std compat
use core::convert::TryInto;
