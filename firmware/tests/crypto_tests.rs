//! Cryptographic primitive tests.
//!
//! Uses real NIST / RFC test vectors wherever available.
//! No embassy-rp, embassy-executor, or embassy-time is imported.
//! All tests run on x86_64 via `cargo test --test crypto_tests`.

use pico2hsm_firmware::crypto::symmetric::{
    aes_gcm_decrypt_raw, aes_gcm_encrypt_raw,
    aes_cbc_decrypt, aes_cbc_encrypt,
};
use pico2hsm_firmware::crypto::kdf::{
    hkdf_sha256, pbkdf2_hmac_sha256, slip10_master_key, Slip10Curve,
};
use pico2hsm_firmware::crypto::asymmetric::{
    ecdsa_sign, ecdsa_verify, ecdh_agree, generate_ec_keypair,
};
use pico2hsm_core::key::{KeyId, KeyMaterial, KeyType};
use pico2hsm_core::error::CryptoError;

// ---------------------------------------------------------------------------
// RNG: deterministic LCG for tests (implements RngCore + CryptoRng marker)
// ---------------------------------------------------------------------------

/// A Lehmer / Park-Miller LCG seeded from a fixed value.
/// DO NOT use in production — for testing only.
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
        // Splitmix64 step — good statistical quality for test purposes
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

/// Mark as CryptoRng — safe because tests don't use this for real key material.
impl rand_core::CryptoRng for DeterministicRng {}

// ---------------------------------------------------------------------------
// Helper: build a KeyMaterial with a 32-byte raw key
// ---------------------------------------------------------------------------

fn make_key256(raw: &[u8; 32]) -> KeyMaterial {
    let mut km = KeyMaterial {
        key_type: KeyType::Aes256,
        key_id:   KeyId(0x0001),
        raw:      heapless::Vec::new(),
    };
    km.raw.extend_from_slice(raw).unwrap();
    km
}

fn make_key128(raw: &[u8; 16]) -> KeyMaterial {
    let mut km = KeyMaterial {
        key_type: KeyType::Aes128,
        key_id:   KeyId(0x0001),
        raw:      heapless::Vec::new(),
    };
    km.raw.extend_from_slice(raw).unwrap();
    km
}

// ---------------------------------------------------------------------------
// AES-256-GCM  (raw-key interface)
// ---------------------------------------------------------------------------

/// NIST SP 800-38D Test Case 4 (128-bit key variant converted to 256-bit
/// using the standard's 256-bit vector GCM-AES-256 Test Case 1).
///
/// Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
/// Test vector: AES-GCM 256-bit key, zero-length plaintext (tag-only).
#[test]
fn test_aes_gcm_256_empty_plaintext_nist() {
    // Key: NIST GCM-AES-256 Test Case 1
    // K   = 0000..0000 (32 bytes of 0x00)
    // IV  = 000000000000000000000000
    // PT  = (empty)
    // AAD = (empty)
    // CT  = (empty)
    // Tag = 530f8afbc74536b9a963b4f1c4cb738b
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let expected_tag =
        hex::decode("530f8afbc74536b9a963b4f1c4cb738b").unwrap();

    let result = aes_gcm_encrypt_raw(&key, &nonce, &[], &[]).unwrap();
    // result = ciphertext(0) || tag(16)
    assert_eq!(result.len(), 16, "Empty PT should produce only the 16-byte tag");
    assert_eq!(
        result.as_slice(),
        expected_tag.as_slice(),
        "NIST GCM-256 test case 1: tag mismatch"
    );
}

/// NIST GCM-AES-256 Test Case 2: non-empty plaintext.
/// K   = 0000..0000 (32 bytes)
/// IV  = 000000000000000000000000
/// PT  = 00000000000000000000000000000000  (16 zero bytes)
/// AAD = (empty)
/// CT  = cea7403d4d606b6e074ec5d3baf39d18
/// Tag = d0d1c8a799996bf0265b98b5d48ab919
#[test]
fn test_aes_gcm_256_nist_case2() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let pt = [0u8; 16];

    let expected_ct =
        hex::decode("cea7403d4d606b6e074ec5d3baf39d18").unwrap();
    let expected_tag =
        hex::decode("d0d1c8a799996bf0265b98b5d48ab919").unwrap();

    let result = aes_gcm_encrypt_raw(&key, &nonce, &pt, &[]).unwrap();
    assert_eq!(result.len(), 32, "16 bytes PT + 16 bytes tag = 32 bytes");
    assert_eq!(
        &result[..16],
        expected_ct.as_slice(),
        "NIST GCM-256 test case 2: ciphertext mismatch"
    );
    assert_eq!(
        &result[16..],
        expected_tag.as_slice(),
        "NIST GCM-256 test case 2: tag mismatch"
    );
}

#[test]
fn test_aes_gcm_decrypt_nist_case2() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];

    // First encrypt to get ciphertext+tag
    let pt_orig = [0u8; 16];
    let ct_tag = aes_gcm_encrypt_raw(&key, &nonce, &pt_orig, &[]).unwrap();

    // Decrypt
    let plaintext = aes_gcm_decrypt_raw(&key, &nonce, ct_tag.as_slice(), &[]).unwrap();
    assert_eq!(
        plaintext.as_slice(),
        &pt_orig,
        "GCM decrypt must recover original plaintext"
    );
}

#[test]
fn test_aes_gcm_bad_tag_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let pt = b"hello secret message";

    let mut ct_tag = aes_gcm_encrypt_raw(&key, &nonce, pt, &[]).unwrap();

    // Flip a tag byte (last 16 bytes)
    let last = ct_tag.len() - 1;
    ct_tag[last] ^= 0xFF;

    let result = aes_gcm_decrypt_raw(&key, &nonce, ct_tag.as_slice(), &[]);
    assert!(
        matches!(result, Err(CryptoError::DecryptFailure)),
        "Tampered tag must fail with DecryptFailure"
    );
}

#[test]
fn test_aes_gcm_wrong_aad_fails() {
    let key = [0xABu8; 32];
    let nonce = [0x00u8; 12];
    let pt = b"protect me";
    let aad = b"valid-aad";
    let wrong_aad = b"invalid-aad";

    let ct_tag = aes_gcm_encrypt_raw(&key, &nonce, pt, aad).unwrap();
    let result = aes_gcm_decrypt_raw(&key, &nonce, ct_tag.as_slice(), wrong_aad);

    assert!(
        matches!(result, Err(CryptoError::DecryptFailure)),
        "Wrong AAD must fail with DecryptFailure"
    );
}

#[test]
fn test_aes_gcm_roundtrip_with_aad() {
    let key = [0xCCu8; 32];
    let nonce = [0xDDu8; 12];
    let pt = b"this is plaintext data";
    let aad = b"authenticated-but-not-encrypted";

    let ct_tag = aes_gcm_encrypt_raw(&key, &nonce, pt, aad).unwrap();
    let recovered = aes_gcm_decrypt_raw(&key, &nonce, ct_tag.as_slice(), aad).unwrap();

    assert_eq!(
        recovered.as_slice(),
        pt.as_slice(),
        "GCM roundtrip must recover original plaintext"
    );
}

// ---------------------------------------------------------------------------
// AES-CBC (KeyMaterial interface)
// ---------------------------------------------------------------------------

/// NIST AESAVS CBC Known-Answer Test vector.
/// Key  = 2b7e151628aed2a6abf7158809cf4f3c  (AES-128)
/// IV   = 000102030405060708090a0b0c0d0e0f
/// PT   = 6bc1bee22e409f96e93d7e117393172a
/// CT   = 7649abac8119b246cee98e9b12e9197d
///
/// Source: NIST SP 800-38A, Section F.2.1
#[test]
fn test_aes_128_cbc_encrypt_nist_sp800_38a() {
    let key_raw: [u8; 16] =
        hex::decode("2b7e151628aed2a6abf7158809cf4f3c")
            .unwrap()
            .try_into()
            .unwrap();
    let iv: [u8; 16] =
        hex::decode("000102030405060708090a0b0c0d0e0f")
            .unwrap()
            .try_into()
            .unwrap();
    let pt = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let expected_ct = hex::decode("7649abac8119b246cee98e9b12e9197d").unwrap();

    let km = make_key128(&key_raw);
    let mut out: heapless::Vec<u8, 4096> = heapless::Vec::new();
    aes_cbc_encrypt(&km, &iv, &pt, &mut out).unwrap();

    // Our implementation uses PKCS#7 padding, so result is 32 bytes (16 data + 16 padding).
    // First 16 bytes should match the NIST vector.
    assert!(out.len() >= 16, "Ciphertext must be at least 16 bytes");
    assert_eq!(
        &out[..16],
        expected_ct.as_slice(),
        "AES-128-CBC encrypt: first block mismatch vs NIST SP 800-38A F.2.1"
    );
}

#[test]
fn test_aes_256_cbc_encrypt_decrypt_roundtrip() {
    let key_raw = [0xFEu8; 32];
    let iv = [0x11u8; 16];
    let pt = b"test vector data!"; // 17 bytes — crosses a block boundary

    let km = make_key256(&key_raw);
    let mut ct_out: heapless::Vec<u8, 4096> = heapless::Vec::new();
    aes_cbc_encrypt(&km, &iv, pt, &mut ct_out).unwrap();

    let mut pt_out: heapless::Vec<u8, 4096> = heapless::Vec::new();
    aes_cbc_decrypt(&km, &iv, &ct_out, &mut pt_out).unwrap();

    assert_eq!(
        pt_out.as_slice(),
        pt.as_slice(),
        "AES-256-CBC roundtrip must recover original plaintext"
    );
}

#[test]
fn test_aes_cbc_wrong_key_fails_to_decrypt_correctly() {
    let key_raw = [0xAAu8; 32];
    let wrong_key = [0xBBu8; 32];
    let iv = [0x00u8; 16];
    let pt = b"secret message!1";

    let km = make_key256(&key_raw);
    let mut ct: heapless::Vec<u8, 4096> = heapless::Vec::new();
    aes_cbc_encrypt(&km, &iv, pt, &mut ct).unwrap();

    let km_wrong = make_key256(&wrong_key);
    let mut pt_bad: heapless::Vec<u8, 4096> = heapless::Vec::new();
    // Decryption may succeed or fail depending on PKCS#7 padding; either way
    // the plaintext should not match.
    let _ = aes_cbc_decrypt(&km_wrong, &iv, &ct, &mut pt_bad);
    // If decryption succeeded, plaintext must differ from original
    if !pt_bad.is_empty() {
        assert_ne!(
            pt_bad.as_slice(),
            pt.as_slice(),
            "Wrong key must not decrypt to the original plaintext"
        );
    }
    // If decryption returned Err (bad padding), that is also acceptable.
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 — RFC 5869 Test Case 1
// ---------------------------------------------------------------------------

/// RFC 5869 Test Case 1.
/// Hash = SHA-256
/// IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
/// Salt = 000102030405060708090a0b0c (13 bytes)
/// Info = f0f1f2f3f4f5f6f7f8f9 (10 bytes)
/// L    = 42 bytes
/// OKM  = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
#[test]
fn test_hkdf_sha256_rfc5869_case1() {
    let ikm  = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let expected_okm = hex::decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    ).unwrap();

    let mut out = [0u8; 42];
    hkdf_sha256(&salt, &ikm, &info, &mut out).unwrap();

    assert_eq!(
        &out,
        expected_okm.as_slice(),
        "HKDF-SHA256 RFC 5869 test case 1 mismatch"
    );
}

/// RFC 5869 Test Case 2 (longer IKM, longer OKM).
/// IKM  = 000102030405060708090a0b0c0d0e0f ... (80 bytes)
/// Salt = 606162...af (80 bytes)
/// Info = b0b1b2...bf (80 bytes)
/// L    = 82 bytes
/// OKM  = b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87
#[test]
fn test_hkdf_sha256_rfc5869_case2() {
    let ikm: Vec<u8>  = (0x00u8..=0x4f).collect();
    let salt: Vec<u8> = (0x60u8..=0xaf).collect();
    let info: Vec<u8> = (0xb0u8..=0xff).collect();
    let expected_okm = hex::decode(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    ).unwrap();

    let mut out = [0u8; 82];
    hkdf_sha256(&salt, &ikm, &info, &mut out).unwrap();

    assert_eq!(
        &out,
        expected_okm.as_slice(),
        "HKDF-SHA256 RFC 5869 test case 2 mismatch"
    );
}

/// RFC 5869 Test Case 3: empty salt and info.
/// IKM  = 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
/// Salt = (not provided → treated as zero-filled 32 bytes per RFC)
/// Info = (empty)
/// L    = 42 bytes
/// OKM  = 8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8
#[test]
fn test_hkdf_sha256_rfc5869_case3_no_salt() {
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let expected_okm = hex::decode(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    ).unwrap();

    let mut out = [0u8; 42];
    // Empty salt → HKDF uses zero-filled salt of hash-length per RFC 5869 §2.2
    hkdf_sha256(&[], &ikm, &[], &mut out).unwrap();

    assert_eq!(
        &out,
        expected_okm.as_slice(),
        "HKDF-SHA256 RFC 5869 test case 3 (no salt) mismatch"
    );
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA256 — RFC 6070 test vectors
// ---------------------------------------------------------------------------

/// RFC 6070, Test vector 1.
/// Password = "password", Salt = "salt", c = 1, dkLen = 20
/// DK = 120fb6cffccd202212d02a7a92c4a4b33e9c9f0c (hex, first 20 bytes)
///
/// Note: RFC 6070 uses PBKDF2-SHA1, but the implementation here uses SHA-256.
/// We use the SHA-256 equivalent vectors from RFC 7914 / test suite instead.
#[test]
fn test_pbkdf2_sha256_basic() {
    // PBKDF2-HMAC-SHA256("password", "salt", 1, 32)
    // Expected: 120fb6cffccd202212d02a7a92c4a4b3...
    // Source: https://www.ietf.org/rfc/rfc7914.txt / NIST test vectors
    // c=1: single iteration
    let password = b"password";
    let salt     = b"salt";
    let c = 1u32;
    let expected = hex::decode(
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
    ).unwrap();

    let mut out = [0u8; 32];
    pbkdf2_hmac_sha256(password, salt, c, &mut out).unwrap();

    assert_eq!(
        &out,
        expected.as_slice(),
        "PBKDF2-HMAC-SHA256 c=1 mismatch"
    );
}

/// PBKDF2-HMAC-SHA256 determinism: same inputs → same output.
#[test]
fn test_pbkdf2_sha256_deterministic() {
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    pbkdf2_hmac_sha256(b"pass", b"saltsalt", 100, &mut out1).unwrap();
    pbkdf2_hmac_sha256(b"pass", b"saltsalt", 100, &mut out2).unwrap();

    assert_eq!(out1, out2, "PBKDF2 must be deterministic");
}

/// PBKDF2-HMAC-SHA256 different passwords → different keys.
#[test]
fn test_pbkdf2_sha256_different_passwords() {
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    pbkdf2_hmac_sha256(b"password1", b"salt", 1000, &mut out1).unwrap();
    pbkdf2_hmac_sha256(b"password2", b"salt", 1000, &mut out2).unwrap();

    assert_ne!(out1, out2, "Different passwords must produce different derived keys");
}

/// PBKDF2-HMAC-SHA256 different salts → different keys.
#[test]
fn test_pbkdf2_sha256_different_salts() {
    let mut out1 = [0u8; 32];
    let mut out2 = [0u8; 32];
    pbkdf2_hmac_sha256(b"password", b"salt1", 1000, &mut out1).unwrap();
    pbkdf2_hmac_sha256(b"password", b"salt2", 1000, &mut out2).unwrap();

    assert_ne!(out1, out2, "Different salts must produce different derived keys");
}

// ---------------------------------------------------------------------------
// ECC ECDSA P-256 — sign + verify roundtrip
// ---------------------------------------------------------------------------

/// ECDSA P-256: generate keypair, sign, verify.
#[test]
fn test_ecdsa_p256_sign_verify_roundtrip() {
    let mut rng = DeterministicRng::seeded(0xDEAD_BEEF_CAFE_BABEu64);
    let pair = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();

    // Use a 32-byte pre-hash (as if SHA-256 was applied to a message)
    let hash = [0xABu8; 32];

    let sig = ecdsa_sign(
        KeyType::EcPrivateP256,
        &pair.private_key,
        &hash,
        &mut rng,
    ).unwrap();

    let valid = ecdsa_verify(
        KeyType::EcPrivateP256,
        &pair.public_key,
        &hash,
        &sig,
    ).unwrap();

    assert!(valid, "ECDSA P-256 signature must verify against own public key");
}

/// ECDSA P-256: verify fails for a different hash.
#[test]
fn test_ecdsa_p256_wrong_hash_fails() {
    let mut rng = DeterministicRng::seeded(0x1234_5678u64);
    let pair = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();

    let hash         = [0x01u8; 32];
    let different_hash = [0x02u8; 32];

    let sig = ecdsa_sign(
        KeyType::EcPrivateP256,
        &pair.private_key,
        &hash,
        &mut rng,
    ).unwrap();

    let valid = ecdsa_verify(
        KeyType::EcPrivateP256,
        &pair.public_key,
        &different_hash,
        &sig,
    ).unwrap();

    assert!(!valid, "ECDSA verify must fail for a different hash");
}

/// ECDSA P-256: verify fails for a different public key.
#[test]
fn test_ecdsa_p256_wrong_pubkey_fails() {
    let mut rng = DeterministicRng::seeded(0xABCD_1234u64);
    let pair1 = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();
    let pair2 = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();

    let hash = [0x55u8; 32];
    let sig = ecdsa_sign(
        KeyType::EcPrivateP256,
        &pair1.private_key,
        &hash,
        &mut rng,
    ).unwrap();

    // Verify with pair2's public key — should fail
    let valid = ecdsa_verify(
        KeyType::EcPrivateP256,
        &pair2.public_key,
        &hash,
        &sig,
    ).unwrap();

    assert!(!valid, "Signature must not verify with a different public key");
}

/// ECDSA P-384: generate keypair, sign, verify.
#[test]
fn test_ecdsa_p384_sign_verify_roundtrip() {
    let mut rng = DeterministicRng::seeded(0xFEED_FACE_CAFE_BABEu64);
    let pair = generate_ec_keypair(KeyType::EcPrivateP384, &mut rng).unwrap();

    // Use 48-byte pre-hash (matching P-384 field size)
    let hash = [0x77u8; 48];

    let sig = ecdsa_sign(
        KeyType::EcPrivateP384,
        &pair.private_key,
        &hash,
        &mut rng,
    ).unwrap();

    let valid = ecdsa_verify(
        KeyType::EcPrivateP384,
        &pair.public_key,
        &hash,
        &sig,
    ).unwrap();

    assert!(valid, "ECDSA P-384 signature must verify");
}

/// ECDSA K-256 (secp256k1): generate, sign, verify.
#[test]
fn test_ecdsa_k256_sign_verify_roundtrip() {
    let mut rng = DeterministicRng::seeded(0x0102_0304u64);
    let pair = generate_ec_keypair(KeyType::EcPrivateK256, &mut rng).unwrap();

    let hash = [0x3Cu8; 32];
    let sig = ecdsa_sign(
        KeyType::EcPrivateK256,
        &pair.private_key,
        &hash,
        &mut rng,
    ).unwrap();

    let valid = ecdsa_verify(
        KeyType::EcPrivateK256,
        &pair.public_key,
        &hash,
        &sig,
    ).unwrap();

    assert!(valid, "ECDSA K-256 signature must verify");
}

// ---------------------------------------------------------------------------
// ECC ECDH P-256 — shared secret
// ---------------------------------------------------------------------------

/// ECDH P-256: two parties derive the same shared secret.
#[test]
fn test_ecdh_p256_shared_secret_symmetric() {
    let mut rng = DeterministicRng::seeded(0xEC_D_CAFE_BABEu64);
    let alice = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();
    let bob   = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();

    // Alice computes shared secret using her private key and Bob's public key
    let ss_alice = ecdh_agree(
        KeyType::EcPrivateP256,
        &alice.private_key,
        &bob.public_key,
    ).unwrap();

    // Bob computes shared secret using his private key and Alice's public key
    let ss_bob = ecdh_agree(
        KeyType::EcPrivateP256,
        &bob.private_key,
        &alice.public_key,
    ).unwrap();

    assert_eq!(
        ss_alice.as_slice(),
        ss_bob.as_slice(),
        "ECDH P-256: Alice and Bob must derive the same shared secret"
    );
}

/// ECDH P-256: different parties produce different shared secrets.
#[test]
fn test_ecdh_p256_different_parties_different_secrets() {
    let mut rng = DeterministicRng::seeded(0xABCDu64);
    let alice = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();
    let bob   = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();
    let carol = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();

    let ss_alice_bob = ecdh_agree(
        KeyType::EcPrivateP256,
        &alice.private_key,
        &bob.public_key,
    ).unwrap();

    let ss_alice_carol = ecdh_agree(
        KeyType::EcPrivateP256,
        &alice.private_key,
        &carol.public_key,
    ).unwrap();

    assert_ne!(
        ss_alice_bob.as_slice(),
        ss_alice_carol.as_slice(),
        "ECDH shared secrets with different peers must differ"
    );
}

/// ECDH P-384: cross-curve check.
#[test]
fn test_ecdh_p384_shared_secret_symmetric() {
    let mut rng = DeterministicRng::seeded(0x3848u64);
    let alice = generate_ec_keypair(KeyType::EcPrivateP384, &mut rng).unwrap();
    let bob   = generate_ec_keypair(KeyType::EcPrivateP384, &mut rng).unwrap();

    let ss_alice = ecdh_agree(KeyType::EcPrivateP384, &alice.private_key, &bob.public_key).unwrap();
    let ss_bob   = ecdh_agree(KeyType::EcPrivateP384, &bob.private_key, &alice.public_key).unwrap();

    assert_eq!(
        ss_alice.as_slice(),
        ss_bob.as_slice(),
        "ECDH P-384 shared secrets must match"
    );
}

// ---------------------------------------------------------------------------
// SLIP-0010 — master key derivation
// ---------------------------------------------------------------------------

/// SLIP-0010 Test Vector 1 (secp256k1).
///
/// Source: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-secp256k1
/// Seed   = 000102030405060708090a0b0c0d0e0f
/// Chain  = 873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
/// Key    = e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
#[test]
fn test_slip10_secp256k1_vector1_master() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let expected_key = hex::decode(
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
    ).unwrap();
    let expected_chain = hex::decode(
        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
    ).unwrap();

    let (key, chain) = slip10_master_key(&seed, Slip10Curve::Secp256k1).unwrap();

    assert_eq!(
        key.as_slice(),
        expected_key.as_slice(),
        "SLIP-10 secp256k1 vector 1: master key mismatch"
    );
    assert_eq!(
        chain.as_slice(),
        expected_chain.as_slice(),
        "SLIP-10 secp256k1 vector 1: chain code mismatch"
    );
}

/// SLIP-0010 Test Vector 1 — NIST P-256 master key.
///
/// Source: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-nist-p-256
/// Seed   = 000102030405060708090a0b0c0d0e0f
/// Key    = 612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2
/// Chain  = 98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185d55
#[test]
fn test_slip10_nist256p1_vector1_master() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let expected_key = hex::decode(
        "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2",
    ).unwrap();
    let expected_chain = hex::decode(
        "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea",
    ).unwrap();

    let (key, chain) = slip10_master_key(&seed, Slip10Curve::Nist256p1).unwrap();

    assert_eq!(
        key.as_slice(),
        expected_key.as_slice(),
        "SLIP-10 Nist256p1 vector 1: master key mismatch"
    );
    assert_eq!(
        chain.as_slice(),
        expected_chain.as_slice(),
        "SLIP-10 Nist256p1 vector 1: chain code mismatch"
    );
}

/// SLIP-0010 Test Vector 2 (secp256k1).
///
/// Source: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-2-for-secp256k1
/// Seed   = fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
/// Key    = 4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e
/// Chain  = 60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689
#[test]
fn test_slip10_secp256k1_vector2_master() {
    let seed = hex::decode(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    ).unwrap();

    let expected_key = hex::decode(
        "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
    ).unwrap();
    let expected_chain = hex::decode(
        "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
    ).unwrap();

    let (key, chain) = slip10_master_key(&seed, Slip10Curve::Secp256k1).unwrap();

    assert_eq!(
        key.as_slice(),
        expected_key.as_slice(),
        "SLIP-10 secp256k1 vector 2: master key mismatch"
    );
    assert_eq!(
        chain.as_slice(),
        expected_chain.as_slice(),
        "SLIP-10 secp256k1 vector 2: chain code mismatch"
    );
}

/// SLIP-0010: Ed25519 master key generation.
///
/// Source: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-1-for-ed25519
/// Seed  = 000102030405060708090a0b0c0d0e0f
/// Key   = 2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7
/// Chain = 90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb
#[test]
fn test_slip10_ed25519_vector1_master() {
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let expected_key = hex::decode(
        "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
    ).unwrap();
    let expected_chain = hex::decode(
        "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
    ).unwrap();

    let (key, chain) = slip10_master_key(&seed, Slip10Curve::Ed25519).unwrap();

    assert_eq!(
        key.as_slice(),
        expected_key.as_slice(),
        "SLIP-10 Ed25519 vector 1: master key mismatch"
    );
    assert_eq!(
        chain.as_slice(),
        expected_chain.as_slice(),
        "SLIP-10 Ed25519 vector 1: chain code mismatch"
    );
}

/// SLIP-0010: invalid seed (too short) returns Err.
#[test]
fn test_slip10_seed_too_short_fails() {
    let short_seed = [0u8; 15]; // minimum is 16 bytes
    let result = slip10_master_key(&short_seed, Slip10Curve::Secp256k1);
    assert!(
        result.is_err(),
        "SLIP-10 with 15-byte seed must fail"
    );
}

/// SLIP-0010: invalid seed (too long) returns Err.
#[test]
fn test_slip10_seed_too_long_fails() {
    let long_seed = [0u8; 65]; // maximum is 64 bytes
    let result = slip10_master_key(&long_seed, Slip10Curve::Secp256k1);
    assert!(
        result.is_err(),
        "SLIP-10 with 65-byte seed must fail"
    );
}

// ---------------------------------------------------------------------------
// Key generation — basic sanity
// ---------------------------------------------------------------------------

#[test]
fn test_generate_p256_keypair_sizes() {
    let mut rng = DeterministicRng::seeded(0x1111u64);
    let pair = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();

    assert_eq!(pair.private_key.len(), 32, "P-256 private key must be 32 bytes");
    assert_eq!(pair.public_key.len(), 65, "P-256 uncompressed public key must be 65 bytes");
    assert_eq!(pair.public_key[0], 0x04, "Uncompressed point must start with 0x04");
}

#[test]
fn test_generate_p384_keypair_sizes() {
    let mut rng = DeterministicRng::seeded(0x2222u64);
    let pair = generate_ec_keypair(KeyType::EcPrivateP384, &mut rng).unwrap();

    assert_eq!(pair.private_key.len(), 48, "P-384 private key must be 48 bytes");
    assert_eq!(pair.public_key.len(), 97, "P-384 uncompressed public key must be 97 bytes");
    assert_eq!(pair.public_key[0], 0x04, "Uncompressed point must start with 0x04");
}

#[test]
fn test_generate_k256_keypair_sizes() {
    let mut rng = DeterministicRng::seeded(0x3333u64);
    let pair = generate_ec_keypair(KeyType::EcPrivateK256, &mut rng).unwrap();

    assert_eq!(pair.private_key.len(), 32, "K-256 private key must be 32 bytes");
    assert_eq!(pair.public_key.len(), 65, "K-256 uncompressed public key must be 65 bytes");
}

#[test]
fn test_generate_brainpool_not_supported() {
    let mut rng = DeterministicRng::seeded(0x4444u64);
    let result = generate_ec_keypair(KeyType::EcPrivateBrainpoolP256, &mut rng);
    assert!(
        matches!(result, Err(CryptoError::UnsupportedAlgorithm)),
        "Brainpool key generation must return UnsupportedAlgorithm (not yet implemented)"
    );
}

