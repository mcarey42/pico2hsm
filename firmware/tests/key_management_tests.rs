//! Key management round-trip tests.
//!
//! Tests the KeyObject encrypt/decrypt cycle (SMK-keyed AES-GCM storage blobs)
//! and DKEK wrap/unwrap (HSM-to-HSM export format).
//! No embassy-rp / embassy-executor imports — runs on x86_64.

use pico2hsm_firmware::security::key_management::{
    AlgorithmId, KeyError, KeyObject, KeyType, derive_key_encryption_key,
};

// ---------------------------------------------------------------------------
// Constants for all tests
// ---------------------------------------------------------------------------

/// Deterministic fake Storage Master Key (NOT a real key — test use only).
const TEST_SMK: [u8; 32] = [0xAA; 32];

/// Deterministic fake device identifier.
const TEST_DEVICE_ID: [u8; 16] = [0x42; 16];

/// Fixed 12-byte nonce used for deterministic encrypt/decrypt tests.
const TEST_NONCE: [u8; 12] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal EC key object with a 32-byte fake private key.
fn ec_key(id: u8) -> KeyObject {
    let mut obj = KeyObject::new(KeyType::Ec, id, AlgorithmId::EcdsaP256);
    // Fake 32-byte P-256 scalar
    obj.private_key.extend_from_slice(&[0x42u8; 32]).unwrap();
    // Fake 65-byte uncompressed public key
    obj.public_key.extend_from_slice(&[0x04u8; 65]).unwrap();
    obj
}

/// Build a minimal AES-256 key object with a 32-byte fake key.
fn aes_key(id: u8) -> KeyObject {
    let mut obj = KeyObject::new(KeyType::Aes, id, AlgorithmId::AesGcm);
    obj.private_key.extend_from_slice(&[0x55u8; 32]).unwrap();
    // AES keys have no public component
    obj
}

// ---------------------------------------------------------------------------
// KEK derivation
// ---------------------------------------------------------------------------

#[test]
fn test_kek_derivation_deterministic() {
    let kek1 = derive_key_encryption_key(&TEST_SMK, 0x01).unwrap();
    let kek2 = derive_key_encryption_key(&TEST_SMK, 0x01).unwrap();
    assert_eq!(*kek1, *kek2, "KEK derivation must be deterministic for the same key_id");
}

#[test]
fn test_kek_derivation_unique_per_id() {
    let kek1 = derive_key_encryption_key(&TEST_SMK, 0x01).unwrap();
    let kek2 = derive_key_encryption_key(&TEST_SMK, 0x02).unwrap();
    assert_ne!(*kek1, *kek2, "Different key_ids must yield different KEKs");
}

#[test]
fn test_kek_derivation_unique_per_smk() {
    let smk2 = [0xBBu8; 32];
    let kek1 = derive_key_encryption_key(&TEST_SMK, 0x01).unwrap();
    let kek2 = derive_key_encryption_key(&smk2, 0x01).unwrap();
    assert_ne!(*kek1, *kek2, "Different SMKs must yield different KEKs");
}

#[test]
fn test_kek_derivation_all_key_ids_unique() {
    // Spot-check: first 16 key IDs should all differ from each other.
    let keks: Vec<_> = (1u8..=16)
        .map(|id| derive_key_encryption_key(&TEST_SMK, id).unwrap())
        .collect();

    for i in 0..keks.len() {
        for j in (i + 1)..keks.len() {
            assert_ne!(
                *keks[i],
                *keks[j],
                "KEK for id={} and id={} must differ",
                i + 1,
                j + 1
            );
        }
    }
}

// ---------------------------------------------------------------------------
// KeyObject — SMK encrypt / decrypt roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_key_object_encrypt_decrypt_roundtrip_ec() {
    let obj = ec_key(0x01);
    let blob = obj.encrypt(&TEST_SMK, &TEST_NONCE).unwrap();
    let recovered = KeyObject::decrypt(&blob, 0x01, &TEST_SMK).unwrap();

    assert_eq!(recovered.key_type, KeyType::Ec);
    assert_eq!(recovered.key_id, 0x01);
    assert_eq!(recovered.algorithm, AlgorithmId::EcdsaP256);
    assert_eq!(recovered.private_key.as_slice(), &[0x42u8; 32]);
    assert_eq!(recovered.public_key.as_slice(), &[0x04u8; 65]);
    assert_eq!(recovered.use_count, 0);
    assert_eq!(recovered.key_domain, 0);
}

#[test]
fn test_key_object_encrypt_decrypt_roundtrip_aes() {
    let obj = aes_key(0x05);
    let blob = obj.encrypt(&TEST_SMK, &TEST_NONCE).unwrap();
    let recovered = KeyObject::decrypt(&blob, 0x05, &TEST_SMK).unwrap();

    assert_eq!(recovered.key_type, KeyType::Aes);
    assert_eq!(recovered.key_id, 0x05);
    assert_eq!(recovered.algorithm, AlgorithmId::AesGcm);
    assert_eq!(recovered.private_key.as_slice(), &[0x55u8; 32]);
    assert!(recovered.public_key.is_empty(), "AES keys have no public component");
}

#[test]
fn test_key_object_encrypt_produces_deterministic_output() {
    let obj1 = ec_key(0x01);
    let obj2 = ec_key(0x01);
    let blob1 = obj1.encrypt(&TEST_SMK, &TEST_NONCE).unwrap();
    let blob2 = obj2.encrypt(&TEST_SMK, &TEST_NONCE).unwrap();

    assert_eq!(
        blob1.as_slice(),
        blob2.as_slice(),
        "Encrypt with same inputs must produce identical blobs (deterministic nonce)"
    );
}

#[test]
fn test_key_object_wrong_smk_fails() {
    let obj = ec_key(0x02);
    let blob = obj.encrypt(&TEST_SMK, &TEST_NONCE).unwrap();

    let wrong_smk = [0xFFu8; 32];
    let result = KeyObject::decrypt(&blob, 0x02, &wrong_smk);

    assert!(
        matches!(result, Err(KeyError::DecryptFailure)),
        "Decrypt with wrong SMK must return DecryptFailure"
    );
}

#[test]
fn test_key_object_wrong_key_id_fails() {
    let obj = ec_key(0x03);
    let blob = obj.encrypt(&TEST_SMK, &TEST_NONCE).unwrap();

    // Try to decrypt claiming it's key_id = 0x07 (different from 0x03)
    let result = KeyObject::decrypt(&blob, 0x07, &TEST_SMK);

    assert!(
        matches!(result, Err(KeyError::DecryptFailure | KeyError::InvalidFormat)),
        "Decrypt with wrong key_id must fail"
    );
}

#[test]
fn test_key_object_tamper_detection_ciphertext() {
    let obj = ec_key(0x04);
    let mut blob = obj.encrypt(&TEST_SMK, &TEST_NONCE).unwrap();

    // Flip a byte in the ciphertext portion (between header [0..13] and tag [len-28..len-12])
    // Safe index: offset 20 is inside the encrypted key material.
    blob[20] ^= 0xFF;

    let result = KeyObject::decrypt(&blob, 0x04, &TEST_SMK);
    assert!(
        matches!(result, Err(KeyError::DecryptFailure)),
        "Tampered ciphertext must cause DecryptFailure"
    );
}

#[test]
fn test_key_object_tamper_detection_tag() {
    let obj = ec_key(0x05);
    let mut blob = obj.encrypt(&TEST_SMK, &TEST_NONCE).unwrap();

    // Tag is at blob[len-28..len-12] (before the 12-byte nonce at the end).
    let tag_start = blob.len() - 28;
    blob[tag_start] ^= 0x01;

    let result = KeyObject::decrypt(&blob, 0x05, &TEST_SMK);
    assert!(
        matches!(result, Err(KeyError::DecryptFailure)),
        "Tampered GCM tag must cause DecryptFailure"
    );
}

#[test]
fn test_key_object_tamper_detection_header_magic() {
    let obj = ec_key(0x06);
    let mut blob = obj.encrypt(&TEST_SMK, &TEST_NONCE).unwrap();

    // Header is the first 13 bytes; magic is first 4 bytes.
    blob[0] = b'X'; // Break "P2KY" magic

    let result = KeyObject::decrypt(&blob, 0x06, &TEST_SMK);
    // BadMagic is checked before decryption, so we get BadMagic not DecryptFailure
    assert!(
        matches!(result, Err(KeyError::BadMagic | KeyError::DecryptFailure)),
        "Tampered header magic must fail with BadMagic or DecryptFailure"
    );
}

#[test]
fn test_key_object_too_short_blob_fails() {
    // Minimum blob: header(13) + tag(16) + nonce(12) = 41 bytes
    let short_blob = [0u8; 40];
    let result = KeyObject::decrypt(&short_blob, 0x01, &TEST_SMK);
    assert!(
        matches!(result, Err(KeyError::InvalidFormat)),
        "Too-short blob must return InvalidFormat"
    );
}

#[test]
fn test_key_object_with_use_count_preserved() {
    let mut obj = ec_key(0x08);
    obj.use_count = 1234;

    let blob = obj.encrypt(&TEST_SMK, &TEST_NONCE).unwrap();
    let recovered = KeyObject::decrypt(&blob, 0x08, &TEST_SMK).unwrap();

    assert_eq!(recovered.use_count, 1234, "use_count must be preserved through encrypt/decrypt");
}

// ---------------------------------------------------------------------------
// DKEK wrap / unwrap roundtrip
// ---------------------------------------------------------------------------

const TEST_DKEK: [u8; 32] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                               0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
                               0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00];

#[test]
fn test_dkek_wrap_unwrap_roundtrip_ec() {
    let obj = ec_key(0x10);
    let blob = obj
        .wrap_dkek(&TEST_DKEK, &TEST_DEVICE_ID, &TEST_NONCE)
        .unwrap();

    let recovered = KeyObject::unwrap_dkek(
        &blob,
        &TEST_DKEK,
        &TEST_DEVICE_ID,
        0x20, // new key_id on importing HSM
        AlgorithmId::EcdsaP256,
    ).unwrap();

    // Private key material must match
    assert_eq!(
        recovered.private_key.as_slice(),
        &[0x42u8; 32],
        "DKEK unwrap must recover original private key"
    );
    assert_eq!(recovered.key_type, KeyType::Ec);
    assert_eq!(recovered.algorithm, AlgorithmId::EcdsaP256);
}

#[test]
fn test_dkek_wrap_unwrap_roundtrip_aes() {
    let obj = aes_key(0x11);
    let blob = obj
        .wrap_dkek(&TEST_DKEK, &TEST_DEVICE_ID, &TEST_NONCE)
        .unwrap();

    let recovered = KeyObject::unwrap_dkek(
        &blob,
        &TEST_DKEK,
        &TEST_DEVICE_ID,
        0x21,
        AlgorithmId::AesGcm,
    ).unwrap();

    assert_eq!(
        recovered.private_key.as_slice(),
        &[0x55u8; 32],
        "DKEK AES wrap/unwrap must recover original key"
    );
}

#[test]
fn test_dkek_wrap_wrong_dkek_fails() {
    let obj = ec_key(0x12);
    let blob = obj.wrap_dkek(&TEST_DKEK, &TEST_DEVICE_ID, &TEST_NONCE).unwrap();

    let wrong_dkek = [0xFFu8; 32];
    let result = KeyObject::unwrap_dkek(
        &blob,
        &wrong_dkek,
        &TEST_DEVICE_ID,
        0x12,
        AlgorithmId::EcdsaP256,
    );

    assert!(
        matches!(result, Err(KeyError::DecryptFailure)),
        "Wrong DKEK must cause DecryptFailure"
    );
}

#[test]
fn test_dkek_wrap_wrong_device_id_fails() {
    let obj = ec_key(0x13);
    let blob = obj.wrap_dkek(&TEST_DKEK, &TEST_DEVICE_ID, &TEST_NONCE).unwrap();

    let wrong_device_id = [0x99u8; 16];
    let result = KeyObject::unwrap_dkek(
        &blob,
        &TEST_DKEK,
        &wrong_device_id,
        0x13,
        AlgorithmId::EcdsaP256,
    );

    assert!(
        matches!(result, Err(KeyError::DecryptFailure)),
        "Wrong device_id (wrong AAD) must cause DecryptFailure"
    );
}

#[test]
fn test_dkek_blob_tamper_fails() {
    let obj = ec_key(0x14);
    let mut blob = obj.wrap_dkek(&TEST_DKEK, &TEST_DEVICE_ID, &TEST_NONCE).unwrap();

    // Flip a byte in the ciphertext (between nonce [0..12] and tag [len-16..])
    blob[15] ^= 0x55;

    let result = KeyObject::unwrap_dkek(
        &blob,
        &TEST_DKEK,
        &TEST_DEVICE_ID,
        0x14,
        AlgorithmId::EcdsaP256,
    );

    assert!(
        matches!(result, Err(KeyError::DecryptFailure)),
        "Tampered DKEK blob must cause DecryptFailure"
    );
}

#[test]
fn test_dkek_wrap_blob_format() {
    // blob = nonce(12) || ciphertext || tag(16)
    // For a 32-byte private key with no padding (already block-aligned: 1+2+32=35 → pad 5 → 40),
    // ciphertext is 40 bytes, so total = 12 + 40 + 16 = 68 bytes.
    let obj = ec_key(0x15);
    let blob = obj.wrap_dkek(&TEST_DKEK, &TEST_DEVICE_ID, &TEST_NONCE).unwrap();

    assert!(
        blob.len() >= 12 + 16,
        "DKEK blob must contain at least nonce(12) + tag(16)"
    );
    // Nonce at start must match the provided test nonce
    assert_eq!(
        &blob[..12],
        &TEST_NONCE,
        "First 12 bytes of DKEK blob must be the nonce"
    );
}

// ---------------------------------------------------------------------------
// KeyType / AlgorithmId — from_u8 coverage
// ---------------------------------------------------------------------------

#[test]
fn test_key_type_roundtrip() {
    let types = [
        (0x01u8, KeyType::Rsa),
        (0x02u8, KeyType::Ec),
        (0x03u8, KeyType::Aes),
        (0x04u8, KeyType::Generic),
    ];
    for (byte, expected) in types {
        let parsed = KeyType::from_u8(byte).expect("valid byte should parse");
        assert_eq!(parsed, expected);
        assert_eq!(parsed as u8, byte, "round-trip KeyType byte must match");
    }
}

#[test]
fn test_key_type_unknown_returns_none() {
    assert!(KeyType::from_u8(0x00).is_none());
    assert!(KeyType::from_u8(0xFF).is_none());
    assert!(KeyType::from_u8(0x05).is_none());
}

#[test]
fn test_algorithm_id_roundtrip() {
    let ids = [
        (0x13u8, AlgorithmId::EcdsaP256),
        (0x15u8, AlgorithmId::EcdsaP384),
        (0x17u8, AlgorithmId::EcdsaP521),
        (0x19u8, AlgorithmId::EcdsaK256),
        (0x63u8, AlgorithmId::AesGcm),
        (0x61u8, AlgorithmId::AesCbc),
    ];
    for (byte, expected) in ids {
        let parsed = AlgorithmId::from_u8(byte).expect("valid algorithm byte should parse");
        assert_eq!(parsed, expected);
        assert_eq!(parsed as u8, byte, "round-trip AlgorithmId byte must match");
    }
}

#[test]
fn test_algorithm_id_unknown_returns_none() {
    assert!(AlgorithmId::from_u8(0x00).is_none());
    assert!(AlgorithmId::from_u8(0xFF).is_none());
    assert!(AlgorithmId::from_u8(0x99).is_none());
}
