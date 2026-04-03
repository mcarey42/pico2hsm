//! Integration tests for key type definitions (pico2hsm-core).

use pico2hsm_core::key::{KeyId, KeyType, MAX_KEY_BYTES};

#[test]
fn test_key_id_equality() {
    let a = KeyId(0x0001);
    let b = KeyId(0x0001);
    let c = KeyId(0x0002);
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn test_key_type_raw_len_ec() {
    assert_eq!(KeyType::EcPrivateP256.raw_key_len(), 32);
    assert_eq!(KeyType::EcPrivateP384.raw_key_len(), 48);
    assert_eq!(KeyType::EcPrivateP521.raw_key_len(), 66);
    assert_eq!(KeyType::EcPrivateK256.raw_key_len(), 32);
}

#[test]
fn test_key_type_raw_len_aes() {
    assert_eq!(KeyType::Aes128.raw_key_len(), 16);
    assert_eq!(KeyType::Aes192.raw_key_len(), 24);
    assert_eq!(KeyType::Aes256.raw_key_len(), 32);
}

#[test]
fn test_max_key_bytes_sufficient_for_ec() {
    // EC keys are always smaller than MAX_KEY_BYTES
    assert!(KeyType::EcPrivateP521.raw_key_len() <= MAX_KEY_BYTES);
}

#[test]
fn test_bip32_master_key_len() {
    // BIP32 master = 32-byte seed + 32-byte chain code
    assert_eq!(KeyType::Bip32Master.raw_key_len(), 64);
    assert!(64 <= MAX_KEY_BYTES);
}
