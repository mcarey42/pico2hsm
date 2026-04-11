//! Asymmetric cryptography — ECDSA, ECDH, RSA.
//!
//! Provides key generation, signing, verification, and key agreement for
//! all asymmetric algorithms supported by pico2hsm:
//!
//! # Supported operations
//! | Algorithm          | Sign | Verify | ECDH/Decrypt | KeyGen |
//! |--------------------|------|--------|--------------|--------|
//! | ECDSA P-256        | yes  | yes    | ECDH         | yes    |
//! | ECDSA P-384        | yes  | yes    | ECDH         | yes    |
//! | ECDSA P-521        | yes  | yes    | ECDH         | yes    |
//! | ECDSA K-256        | yes  | yes    | ECDH         | yes    |
//! | Brainpool P-256r1  | stub | stub   | stub         | stub   |
//! | Brainpool P-384r1  | stub | stub   | stub         | stub   |
//! | Brainpool P-512r1  | stub | stub   | stub         | stub   |
//! | RSA-2048           | yes  | —      | decrypt      | yes    |
//! | RSA-4096           | yes  | —      | decrypt      | yes    |
//!
//! # Brainpool curve status
//! The `bp-curves` / `bign-curve` crates that implement brainpool curves with
//! the `ecdsa` + `elliptic-curve` trait ecosystem exist but are **not
//! available as published crates on crates.io** with no_std support at the
//! versions compatible with ecdsa-0.16 / elliptic-curve-0.13.  The `bp256r1`,
//! `bp384r1`, and `bp512r1` crates on crates.io do not yet implement the
//! `CurveArithmetic` trait required for ECDSA signing/verification.
//! TODO: Revisit when <https://github.com/RustCrypto/elliptic-curves> lands
//! brainpool arithmetic support (tracking issue #1114).
//!
//! # RSA implementation
//! RSA is enabled by the `rsa` feature flag.  It requires a global heap
//! allocator because the `rsa` crate uses `Vec<u32>` internally for
//! big-integer arithmetic.  The firmware uses `embedded-alloc` (48 KB static
//! heap) on ARM; on x86_64 (host tests) the std allocator is used.
//!
//! Build with: `--features rsa` (already included in `build-all-debug.sh`).

#![allow(unused_imports)]

// RSA operations require heap allocation (via embedded-alloc on ARM, std on host).
#[cfg(feature = "rsa")]
extern crate alloc;

use heapless::Vec;
use rand_core::RngCore;
use zeroize::Zeroize;

use pico2hsm_core::{
    error::CryptoError,
    key::{KeyId, KeyMaterial, KeyType, MAX_KEY_BYTES},
};

// ---- Re-used curve crate imports ----------------------------------------

use elliptic_curve::{
    ecdh::diffie_hellman,
    sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint},
    PublicKey, SecretKey,
};
use ecdsa::{
    // PrehashSigner / PrehashVerifier live in the `signature` crate which
    // ecdsa re-exports as `ecdsa::signature`.
    signature::hazmat::{PrehashSigner, PrehashVerifier},
    der::Signature as DerSignature,
};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Hash algorithm selector used by RSA sign/decrypt functions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

/// ECC key pair (both public and private components).
///
/// `private_key` is the big-endian scalar encoding (field element).
/// `public_key` is the uncompressed SEC1 point: `0x04 || X || Y`.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct EcKeyPair {
    pub key_type: KeyType,
    /// Raw private key bytes (big-endian scalar), up to 66 bytes for P-521.
    pub private_key: Vec<u8, 66>,
    /// Uncompressed public key `0x04 || X || Y`, up to 133 bytes for P-521.
    pub public_key: Vec<u8, 133>,
}

/// RSA key pair returned by [`generate_rsa_keypair`].
#[cfg(feature = "rsa")]
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct RsaKeyPair {
    /// `RsaPrivate2048`, `RsaPrivate3072`, or `RsaPrivate4096`.
    pub key_type: KeyType,
    /// DER-encoded PKCS#1 `RSAPrivateKey` (≤1200 bytes for 2048-bit, ≤2350 bytes for 4096-bit).
    pub private_key_der: Vec<u8, 2400>,
    /// DER-encoded PKCS#1 `RSAPublicKey` (≤300 bytes for 2048-bit, ≤560 bytes for 4096-bit).
    pub public_key_der: Vec<u8, 560>,
    /// Raw modulus bytes, big-endian (256 bytes for RSA-2048, 512 bytes for RSA-4096).
    pub modulus: Vec<u8, 512>,
    /// Raw public exponent bytes, big-endian (3 bytes for e=65537).
    pub exponent: Vec<u8, 4>,
}

/// ECDSA signature output (DER-encoded).
///
/// Maximum size: P-521 DER signature ≤ 139 bytes (2 + 2*(2+1+66)).
pub type EcdsaSignature = Vec<u8, 139>;

// ---------------------------------------------------------------------------
// Internal macro: dispatch over supported curve types
// ---------------------------------------------------------------------------

/// Generate an EC key pair for `$Curve` using the `elliptic-curve` / `ecdsa` crates.
///
/// Requires that the curve type implements `CurveArithmetic` (for key-gen and
/// ECDH) and that `AffinePoint` implements `ToEncodedPoint`.
macro_rules! ec_keygen_for_curve {
    ($Curve:ty, $key_type:expr, $rng:expr, $priv_len:expr, $pub_len:expr) => {{
        use elliptic_curve::CurveArithmetic;

        // Generate random secret key
        let secret = SecretKey::<$Curve>::random($rng);
        let priv_bytes = secret.to_bytes();

        let public_key: PublicKey<$Curve> = secret.public_key();
        let encoded_pub = public_key.to_encoded_point(/*compress=*/ false);
        let pub_bytes = encoded_pub.as_bytes();

        let mut pair = EcKeyPair {
            key_type: $key_type,
            private_key: Vec::new(),
            public_key: Vec::new(),
        };
        pair.private_key
            .extend_from_slice(priv_bytes.as_slice())
            .map_err(|_| CryptoError::BufferTooSmall)?;
        pair.public_key
            .extend_from_slice(pub_bytes)
            .map_err(|_| CryptoError::BufferTooSmall)?;

        Ok(pair)
    }};
}

// ---------------------------------------------------------------------------
// Key Generation
// ---------------------------------------------------------------------------

/// Generate an ECC key pair for the given `key_type`.
///
/// `rng` must be a cryptographically secure RNG provided by the caller (the
/// firmware hands in the hardware TRNG; tests can use a software RNG).
///
/// Returns an [`EcKeyPair`] containing:
/// - `private_key`: big-endian scalar (field element), length matches the curve.
/// - `public_key`: uncompressed SEC1 point `0x04 || X || Y`.
pub fn generate_ec_keypair(
    key_type: KeyType,
    rng: &mut (impl RngCore + rand_core::CryptoRng),
) -> Result<EcKeyPair, CryptoError> {
    match key_type {
        KeyType::EcPrivateP256 => {
            ec_keygen_for_curve!(p256::NistP256, key_type, rng, 32, 65)
        }
        KeyType::EcPrivateP384 => {
            ec_keygen_for_curve!(p384::NistP384, key_type, rng, 48, 97)
        }
        KeyType::EcPrivateP521 => {
            ec_keygen_for_curve!(p521::NistP521, key_type, rng, 66, 133)
        }
        KeyType::EcPrivateK256 => {
            ec_keygen_for_curve!(k256::Secp256k1, key_type, rng, 32, 65)
        }
        KeyType::EcPrivateBrainpoolP256
        | KeyType::EcPrivateBrainpoolP384
        | KeyType::EcPrivateBrainpoolP512 => {
            // TODO: Implement once bp-curves crate supports CurveArithmetic
            // in a no_std context compatible with elliptic-curve 0.13.
            // See module-level doc comment for tracking details.
            Err(CryptoError::UnsupportedAlgorithm)
        }
        #[cfg(feature = "applet-openpgp-curve25519")]
        KeyType::Ed25519 => {
            use ed25519_dalek::SigningKey;
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let signing_key = SigningKey::from_bytes(&seed);
            let verifying_key = signing_key.verifying_key();
            let private_bytes = signing_key.to_bytes();
            let public_bytes = verifying_key.to_bytes(); // 32 bytes (compressed)

            let mut pair = EcKeyPair {
                key_type,
                private_key: Vec::new(),
                public_key: Vec::new(),
            };
            pair.private_key
                .extend_from_slice(&private_bytes)
                .map_err(|_| CryptoError::BufferTooSmall)?;
            pair.public_key
                .extend_from_slice(&public_bytes)
                .map_err(|_| CryptoError::BufferTooSmall)?;
            Ok(pair)
        }
        #[cfg(feature = "applet-openpgp-curve25519")]
        KeyType::X25519 => {
            use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let secret = StaticSecret::from(seed);
            let public = X25519PublicKey::from(&secret);
            let private_bytes = secret.to_bytes();
            let public_bytes = public.to_bytes(); // 32 bytes

            let mut pair = EcKeyPair {
                key_type,
                private_key: Vec::new(),
                public_key: Vec::new(),
            };
            pair.private_key
                .extend_from_slice(&private_bytes)
                .map_err(|_| CryptoError::BufferTooSmall)?;
            pair.public_key
                .extend_from_slice(&public_bytes)
                .map_err(|_| CryptoError::BufferTooSmall)?;
            Ok(pair)
        }
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// Sign a message with an Ed25519 private key (OpenPGP EdDSA path).
///
/// `private_key` must be a 32-byte Ed25519 seed.
/// `message` is the pre-hashed digest (OpenPGP sends the hash to the card).
///
/// Returns a 64-byte raw signature (`r || s`, each 32 bytes).
#[cfg(feature = "applet-openpgp-curve25519")]
pub fn ed25519_sign(
    private_key: &[u8],
    message: &[u8],
) -> Result<heapless::Vec<u8, 64>, CryptoError> {
    use ed25519_dalek::{Signature, Signer, SigningKey};

    if private_key.len() != 32 {
        return Err(CryptoError::WrongKeyLength);
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(private_key);
    let signing_key = SigningKey::from_bytes(&key_bytes);

    // Ed25519 signs the raw message (not a prehash for EdDSA).
    // OpenPGP sends the digest for EdDSA sign (RFC 4880bis).
    let sig: Signature = signing_key.sign(message);
    let sig_bytes = sig.to_bytes(); // 64 bytes (R || S = 32 || 32)

    let mut out: heapless::Vec<u8, 64> = heapless::Vec::new();
    out.extend_from_slice(&sig_bytes)
        .map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

/// Perform X25519 Diffie-Hellman key agreement.
///
/// `private_key` must be a 32-byte X25519 static secret.
/// `peer_public_key` must be a 32-byte X25519 public key.
///
/// Returns the 32-byte shared secret.
#[cfg(feature = "applet-openpgp-curve25519")]
pub fn x25519_ecdh(
    private_key: &[u8],
    peer_public_key: &[u8],
) -> Result<[u8; 32], CryptoError> {
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    if private_key.len() != 32 || peer_public_key.len() != 32 {
        return Err(CryptoError::WrongKeyLength);
    }

    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(private_key);
    let secret = StaticSecret::from(priv_bytes);

    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(peer_public_key);
    let peer_pub = X25519PublicKey::from(pub_bytes);

    let shared = secret.diffie_hellman(&peer_pub);
    Ok(*shared.as_bytes())
}

/// Generate an RSA key pair.
///
/// Returns an [`RsaKeyPair`] containing:
/// - `private_key_der`: PKCS#1 DER-encoded `RSAPrivateKey` structure.
/// - `public_key_der`: PKCS#1 DER-encoded `RSAPublicKey` structure.
///
/// Key sizes: 2048 bits (`RsaPrivate2048`), 3072 bits (`RsaPrivate3072`),
/// or 4096 bits (`RsaPrivate4096`).
///
/// # Performance
/// RSA key generation is computationally intensive.  On a Cortex-M33 at
/// 150 MHz (debug build, no optimisation) RSA-2048 keygen takes approximately
/// 10–60 s depending on prime-finding luck.  The CCID time-extension
/// mechanism fires every 1.5 s to keep pcscd alive during this window.
#[cfg(feature = "rsa")]
pub fn generate_rsa_keypair(
    key_type: KeyType,
    rng: &mut (impl RngCore + rand_core::CryptoRng),
) -> Result<RsaKeyPair, CryptoError> {
    use ::rsa::RsaPrivateKey;
    use ::rsa::pkcs1::EncodeRsaPrivateKey;
    use ::rsa::traits::PublicKeyParts;

    let bits: usize = match key_type {
        KeyType::RsaPrivate2048 => 2048,
        KeyType::RsaPrivate3072 => 3072,
        KeyType::RsaPrivate4096 => 4096,
        _ => return Err(CryptoError::UnsupportedAlgorithm),
    };

    let priv_key = RsaPrivateKey::new(rng, bits)
        .map_err(|_| CryptoError::RngFailure)?;

    // Encode private key as PKCS#1 DER
    let priv_der_doc = priv_key.to_pkcs1_der()
        .map_err(|_| CryptoError::RngFailure)?;
    let priv_der_bytes = priv_der_doc.as_bytes();

    // Extract raw modulus and exponent for building CVC responses
    let pub_key = priv_key.to_public_key();
    let modulus_bytes = pub_key.n().to_bytes_be();  // alloc::vec::Vec<u8>
    let exponent_bytes = pub_key.e().to_bytes_be(); // alloc::vec::Vec<u8>

    let mut pair = RsaKeyPair {
        key_type,
        private_key_der: Vec::new(),
        public_key_der: Vec::new(),
        modulus: Vec::new(),
        exponent: Vec::new(),
    };

    pair.private_key_der
        .extend_from_slice(priv_der_bytes)
        .map_err(|_| CryptoError::BufferTooSmall)?;

    // Store modulus (big-endian, no DER integer prefix)
    pair.modulus
        .extend_from_slice(&modulus_bytes)
        .map_err(|_| CryptoError::BufferTooSmall)?;

    // Store exponent (big-endian, 3 bytes for e=65537)
    pair.exponent
        .extend_from_slice(&exponent_bytes)
        .map_err(|_| CryptoError::BufferTooSmall)?;

    // Build minimal PKCS#1 public key DER for storage
    // (modulus + exponent wrapped in SEQUENCE { INTEGER n INTEGER e })
    // We reuse the modulus/exponent bytes already computed above.
    // PKCS#1 RSAPublicKey: SEQUENCE { INTEGER modulus INTEGER publicExponent }
    // For RSA-2048: total ~270 bytes.
    build_pkcs1_pub_der(&modulus_bytes, &exponent_bytes, &mut pair.public_key_der)?;

    Ok(pair)
}

/// Build a minimal PKCS#1 `RSAPublicKey` DER structure into `out`.
///
/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
///
/// Both integers are encoded as DER INTEGERs with a leading 0x00 byte when
/// the MSB is set (to distinguish from negative numbers in BER/DER).
#[cfg(feature = "rsa")]
fn build_pkcs1_pub_der<const N: usize>(
    modulus: &[u8],
    exponent: &[u8],
    out: &mut Vec<u8, N>,
) -> Result<(), CryptoError> {
    // DER-encode an unsigned big-endian integer (prepend 0x00 if high bit set)
    let needs_pad_n = modulus.first().map(|&b| b & 0x80 != 0).unwrap_or(false);
    let needs_pad_e = exponent.first().map(|&b| b & 0x80 != 0).unwrap_or(false);
    let int_n_content_len = modulus.len() + if needs_pad_n { 1 } else { 0 };
    let int_e_content_len = exponent.len() + if needs_pad_e { 1 } else { 0 };

    let int_n_total = 1 + der_int_len_size(int_n_content_len) + int_n_content_len;
    let int_e_total = 1 + der_int_len_size(int_e_content_len) + int_e_content_len;
    let seq_content_len = int_n_total + int_e_total;
    let seq_total = 1 + der_int_len_size(seq_content_len) + seq_content_len;

    if seq_total > out.capacity() {
        return Err(CryptoError::BufferTooSmall);
    }

    // SEQUENCE
    let _ = out.push(0x30);
    push_der_len_rsa(out, seq_content_len);

    // INTEGER modulus
    let _ = out.push(0x02);
    push_der_len_rsa(out, int_n_content_len);
    if needs_pad_n { let _ = out.push(0x00); }
    let _ = out.extend_from_slice(modulus);

    // INTEGER exponent
    let _ = out.push(0x02);
    push_der_len_rsa(out, int_e_content_len);
    if needs_pad_e { let _ = out.push(0x00); }
    let _ = out.extend_from_slice(exponent);

    Ok(())
}

#[cfg(feature = "rsa")]
fn der_int_len_size(len: usize) -> usize {
    if len < 0x80 { 1 } else if len <= 0xFF { 2 } else { 3 }
}

#[cfg(feature = "rsa")]
fn push_der_len_rsa<const N: usize>(buf: &mut Vec<u8, N>, len: usize) {
    if len < 0x80 {
        let _ = buf.push(len as u8);
    } else if len <= 0xFF {
        let _ = buf.push(0x81);
        let _ = buf.push(len as u8);
    } else {
        let _ = buf.push(0x82);
        let _ = buf.push((len >> 8) as u8);
        let _ = buf.push(len as u8);
    }
}

// ---------------------------------------------------------------------------
// ECDSA — Sign
// ---------------------------------------------------------------------------

/// Sign a pre-hashed message with an EC private key.
///
/// `private_key_raw` is the big-endian scalar bytes for the curve identified
/// by `key_type`.  `hash_data` is the **already-hashed** input — the caller
/// must use the appropriate hash for the key type (e.g. SHA-256 for P-256).
///
/// Returns a DER-encoded ECDSA signature.
///
/// Signing is deterministic per RFC 6979 for all curves except P-521.
/// P-521 uses randomized k (hardware TRNG) because no standard hash function
/// matches P-521's 66-byte field size — RFC 6979 type bounds cannot be satisfied.
/// Randomized ECDSA with a CSPRNG is cryptographically equivalent in security.
///
/// Short hashes (e.g. MD5, SHA-1, RIPEMD-160) are left-padded with zeros to the
/// curve's full field size before signing. `ecdsa::hazmat::bits2field` requires
/// input length >= FieldBytesSize/2; pre-padding ensures that constraint is met for
/// all hashes and all curves.
pub fn ecdsa_sign(
    key_type: KeyType,
    private_key_raw: &[u8],
    hash_data: &[u8],
    rng: &mut (impl rand_core::CryptoRng + RngCore),
) -> Result<EcdsaSignature, CryptoError> {
    // Left-pad hash to full field size so bits2field never rejects it.
    // bits2field rejects inputs shorter than FieldBytesSize/2; padding to the full
    // field size ensures short hashes (MD5=16 B, SHA-1=20 B, SHA-256=32 B on P-521)
    // are accepted. Excess bytes are truncated by bits2field, so over-length hashes
    // (e.g. SHA-512 for P-256) are also handled correctly.
    let field_size: usize = match key_type {
        KeyType::EcPrivateP256 | KeyType::EcPrivateK256 => 32,
        KeyType::EcPrivateP384 => 48,
        KeyType::EcPrivateP521 => 66,
        _ => 0,
    };
    let mut pad_buf = [0u8; 66];
    let hash: &[u8] = if field_size > 0 && hash_data.len() < field_size {
        let offset = field_size - hash_data.len();
        pad_buf[offset..field_size].copy_from_slice(hash_data);
        &pad_buf[..field_size]
    } else {
        hash_data
    };

    match key_type {
        KeyType::EcPrivateP256 => {
            ecdsa_sign_curve::<p256::NistP256>(private_key_raw, hash)
        }
        KeyType::EcPrivateP384 => {
            ecdsa_sign_curve::<p384::NistP384>(private_key_raw, hash)
        }
        KeyType::EcPrivateP521 => {
            // P-521 does not implement DigestPrimitive (no hash matches 66-byte field size).
            // Use randomized k from hardware TRNG — equivalent security to RFC 6979.
            ecdsa_sign_p521(private_key_raw, hash, rng)
        }
        KeyType::EcPrivateK256 => {
            ecdsa_sign_curve::<k256::Secp256k1>(private_key_raw, hash)
        }
        KeyType::EcPrivateBrainpoolP256
        | KeyType::EcPrivateBrainpoolP384
        | KeyType::EcPrivateBrainpoolP512 => {
            // TODO: Implement when bp-curves arithmetic is available.
            Err(CryptoError::UnsupportedAlgorithm)
        }
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// Generic ECDSA signing over any supported curve `C`.
fn ecdsa_sign_curve<C>(
    private_key_raw: &[u8],
    hash_data: &[u8],
) -> Result<EcdsaSignature, CryptoError>
where
    C: elliptic_curve::PrimeCurve + elliptic_curve::CurveArithmetic + ecdsa::hazmat::DigestPrimitive,
    C::Scalar: elliptic_curve::ops::Invert<
            Output = elliptic_curve::subtle::CtOption<C::Scalar>,
        > + ecdsa::hazmat::SignPrimitive<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    ecdsa::SignatureSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
    ecdsa::der::MaxSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
    <elliptic_curve::FieldBytesSize<C> as core::ops::Add>::Output:
        core::ops::Add<ecdsa::der::MaxOverhead>
        + elliptic_curve::generic_array::ArrayLength<u8>,
{
    use ecdsa::SigningKey;

    let secret = SecretKey::<C>::from_slice(private_key_raw)
        .map_err(|_| CryptoError::WrongKeyLength)?;
    let signing_key = SigningKey::<C>::from(&secret);

    // sign_prehash signs the raw hash bytes deterministically (RFC 6979).
    let der_sig: DerSignature<C> = signing_key
        .sign_prehash(hash_data)
        .map_err(|_| CryptoError::SignFailure)?;

    let sig_bytes = der_sig.as_bytes();
    let mut out: EcdsaSignature = Vec::new();
    out.extend_from_slice(sig_bytes)
        .map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

/// P-521 ECDSA sign — dedicated impl because NistP521 has no DigestPrimitive.
/// Uses randomized k from CryptoRng (hardware TRNG on RP2350).
/// No standard hash has OutputSize == 66 bytes (P-521 field size), so RFC 6979's
/// type-level guarantee cannot be used. Randomized k with a CSPRNG is equally secure.
fn ecdsa_sign_p521(
    private_key_raw: &[u8],
    hash_data: &[u8],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Result<EcdsaSignature, CryptoError> {
    use ecdsa::hazmat::{bits2field, SignPrimitive};
    use elliptic_curve::NonZeroScalar;

    let secret = SecretKey::<p521::NistP521>::from_slice(private_key_raw)
        .map_err(|_| CryptoError::WrongKeyLength)?;
    // SignPrimitive<NistP521> is implemented on p521::Scalar, not NonZeroScalar.
    // Deref with explicit type annotation to avoid Rust resolving to the NonZeroScalar copy.
    let nz = secret.to_nonzero_scalar();
    let scalar: p521::Scalar = *nz;
    let z = bits2field::<p521::NistP521>(hash_data)
        .map_err(|_| CryptoError::SignFailure)?;
    // Generate a random k from the hardware TRNG, convert to Scalar for Invert bound.
    let k_nz = NonZeroScalar::<p521::NistP521>::random(rng);
    let k: p521::Scalar = *k_nz;
    let (sig, _recid) = scalar
        .try_sign_prehashed(k, &z)
        .map_err(|_| CryptoError::SignFailure)?;
    let der_sig = sig.to_der();
    let sig_bytes = der_sig.as_bytes();
    let mut out: EcdsaSignature = Vec::new();
    out.extend_from_slice(sig_bytes)
        .map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

/// P-521 ECDSA verify — dedicated impl because NistP521 has no DigestPrimitive.
fn ecdsa_verify_p521(
    public_key_raw: &[u8],
    hash_data: &[u8],
    signature_der: &[u8],
) -> Result<bool, CryptoError> {
    use ecdsa::hazmat::{bits2field, VerifyPrimitive};
    use ecdsa::Signature as EcdsaSig;

    let public_key = PublicKey::<p521::NistP521>::from_sec1_bytes(public_key_raw)
        .map_err(|_| CryptoError::VerifyFailure)?;
    let sig = EcdsaSig::<p521::NistP521>::from_der(signature_der)
        .map_err(|_| CryptoError::VerifyFailure)?;
    let z = bits2field::<p521::NistP521>(hash_data)
        .map_err(|_| CryptoError::VerifyFailure)?;
    match public_key.as_affine().verify_prehashed(&z, &sig) {  // z by reference
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ---------------------------------------------------------------------------
// ECDSA — Verify
// ---------------------------------------------------------------------------

/// Verify a DER-encoded ECDSA signature against a pre-hashed message.
///
/// `public_key_raw` must be the uncompressed SEC1 encoding: `0x04 || X || Y`.
/// Returns `Ok(true)` on success, `Ok(false)` on invalid signature (the
/// distinction is intentional — callers can choose how to surface it).
///
/// Short hashes are left-padded to the curve's full field size, matching the
/// behaviour of `ecdsa_sign`.
pub fn ecdsa_verify(
    key_type: KeyType,
    public_key_raw: &[u8],
    hash_data: &[u8],
    signature_der: &[u8],
) -> Result<bool, CryptoError> {
    let field_size: usize = match key_type {
        KeyType::EcPrivateP256 | KeyType::EcPrivateK256 => 32,
        KeyType::EcPrivateP384 => 48,
        KeyType::EcPrivateP521 => 66,
        _ => 0,
    };
    let mut pad_buf = [0u8; 66];
    let hash: &[u8] = if field_size > 0 && hash_data.len() < field_size {
        let offset = field_size - hash_data.len();
        pad_buf[offset..field_size].copy_from_slice(hash_data);
        &pad_buf[..field_size]
    } else {
        hash_data
    };

    match key_type {
        KeyType::EcPrivateP256 => {
            ecdsa_verify_curve::<p256::NistP256>(public_key_raw, hash, signature_der)
        }
        KeyType::EcPrivateP384 => {
            ecdsa_verify_curve::<p384::NistP384>(public_key_raw, hash, signature_der)
        }
        KeyType::EcPrivateP521 => {
            ecdsa_verify_p521(public_key_raw, hash, signature_der)
        }
        KeyType::EcPrivateK256 => {
            ecdsa_verify_curve::<k256::Secp256k1>(public_key_raw, hash, signature_der)
        }
        KeyType::EcPrivateBrainpoolP256
        | KeyType::EcPrivateBrainpoolP384
        | KeyType::EcPrivateBrainpoolP512 => {
            // TODO: Implement when bp-curves arithmetic is available.
            Err(CryptoError::UnsupportedAlgorithm)
        }
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// Generic ECDSA verify over any supported curve `C`.
fn ecdsa_verify_curve<C>(
    public_key_raw: &[u8],
    hash_data: &[u8],
    signature_der: &[u8],
) -> Result<bool, CryptoError>
where
    C: elliptic_curve::PrimeCurve + elliptic_curve::CurveArithmetic + ecdsa::hazmat::DigestPrimitive,
    elliptic_curve::AffinePoint<C>: ecdsa::hazmat::VerifyPrimitive<C>
        + elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
    ecdsa::SignatureSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
    ecdsa::der::MaxSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
    <elliptic_curve::FieldBytesSize<C> as core::ops::Add>::Output:
        core::ops::Add<ecdsa::der::MaxOverhead>
        + elliptic_curve::generic_array::ArrayLength<u8>,
{
    use ecdsa::VerifyingKey;

    let public_key = PublicKey::<C>::from_sec1_bytes(public_key_raw)
        .map_err(|_| CryptoError::VerifyFailure)?;
    let verifying_key = VerifyingKey::<C>::from(&public_key);

    let der_sig = DerSignature::<C>::try_from(signature_der)
        .map_err(|_| CryptoError::VerifyFailure)?;

    match verifying_key.verify_prehash(hash_data, &der_sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ---------------------------------------------------------------------------
// ECDH
// ---------------------------------------------------------------------------

/// Perform ECDH key agreement using a stored private key.
///
/// `private_key_raw` is the big-endian scalar for the curve.
/// `peer_public_key_raw` is the peer's uncompressed SEC1 point `0x04 || X || Y`.
///
/// Returns the shared secret: the raw x-coordinate of the result point
/// (big-endian, zero-padded to the field size).
pub fn ecdh_agree(
    key_type: KeyType,
    private_key_raw: &[u8],
    peer_public_key_raw: &[u8],
) -> Result<Vec<u8, 66>, CryptoError> {
    match key_type {
        KeyType::EcPrivateP256 => {
            ecdh_agree_curve::<p256::NistP256>(private_key_raw, peer_public_key_raw)
        }
        KeyType::EcPrivateP384 => {
            ecdh_agree_curve::<p384::NistP384>(private_key_raw, peer_public_key_raw)
        }
        KeyType::EcPrivateP521 => {
            ecdh_agree_curve::<p521::NistP521>(private_key_raw, peer_public_key_raw)
        }
        KeyType::EcPrivateK256 => {
            ecdh_agree_curve::<k256::Secp256k1>(private_key_raw, peer_public_key_raw)
        }
        KeyType::EcPrivateBrainpoolP256
        | KeyType::EcPrivateBrainpoolP384
        | KeyType::EcPrivateBrainpoolP512 => {
            // TODO: Implement when bp-curves arithmetic is available.
            Err(CryptoError::UnsupportedAlgorithm)
        }
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// Generic ECDH key agreement over any supported curve `C`.
///
/// # Bounds
/// - `C: CurveArithmetic` — provides scalar multiplication and affine<->projective conversion.
///   This bound also implies `AffinePoint<C>: AffineCoordinates` (x-coordinate extraction).
/// - `AffinePoint<C>: FromEncodedPoint + ToEncodedPoint` — for SEC1 deserialization of the
///   peer public key.
/// - `FieldBytesSize<C>: ModulusSize` — for uncompressed-point encoding.
fn ecdh_agree_curve<C>(
    private_key_raw: &[u8],
    peer_public_key_raw: &[u8],
) -> Result<Vec<u8, 66>, CryptoError>
where
    C: elliptic_curve::CurveArithmetic,
    elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C>
        + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let secret = SecretKey::<C>::from_slice(private_key_raw)
        .map_err(|_| CryptoError::WrongKeyLength)?;
    let peer_pk = PublicKey::<C>::from_sec1_bytes(peer_public_key_raw)
        .map_err(|_| CryptoError::EcdhFailure)?;

    let shared = diffie_hellman(
        secret.to_nonzero_scalar(),
        peer_pk.as_affine(),
    );

    let raw = shared.raw_secret_bytes();
    let mut out: Vec<u8, 66> = Vec::new();
    out.extend_from_slice(raw.as_slice())
        .map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Legacy wrappers — keep old function signatures for existing callers
// ---------------------------------------------------------------------------

/// Generate an asymmetric key pair (legacy API).
///
/// Returns `(private_key_material, public_key_uncompressed)`.  The
/// public key is the raw uncompressed SEC1 encoding (`0x04 || X || Y`).
pub fn generate_keypair(
    key_type: KeyType,
    key_id: KeyId,
    rng: &mut (impl RngCore + rand_core::CryptoRng),
) -> Result<(KeyMaterial, heapless::Vec<u8, 512>), CryptoError> {
    match key_type {
        KeyType::EcPrivateP256
        | KeyType::EcPrivateP384
        | KeyType::EcPrivateP521
        | KeyType::EcPrivateK256 => {
            let pair = generate_ec_keypair(key_type, rng)?;
            let material = ec_private_to_key_material(key_type, key_id, &pair.private_key)?;
            let mut pub_out: heapless::Vec<u8, 512> = heapless::Vec::new();
            pub_out
                .extend_from_slice(&pair.public_key)
                .map_err(|_| CryptoError::BufferTooSmall)?;
            Ok((material, pub_out))
        }
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// Compute an ECDSA signature (legacy API, operates on `KeyMaterial`).
///
/// `digest` is the pre-computed hash.  A deterministic (RFC 6979) signature
/// is produced.
pub fn sign_ecdsa(
    key: &KeyMaterial,
    digest: &[u8],
    rng: &mut (impl rand_core::CryptoRng + RngCore),
) -> Result<EcdsaSignature, CryptoError> {
    ecdsa_sign(key.key_type, &key.raw, digest, rng)
}

/// Perform ECDH key agreement (legacy API, operates on `KeyMaterial`).
///
/// `peer_pubkey` is the peer's uncompressed SEC1 point (`0x04 || X || Y`).
pub fn ecdh(
    private_key: &KeyMaterial,
    peer_pubkey: &[u8],
) -> Result<heapless::Vec<u8, 66>, CryptoError> {
    ecdh_agree(private_key.key_type, &private_key.raw, peer_pubkey)
}

// ---------------------------------------------------------------------------
// RSA stubs (feature-gated)
// ---------------------------------------------------------------------------

/// Compute an RSA-PKCS#1-v1.5 signature over a pre-hashed message.
///
/// `private_key_der` must be a PKCS#1 DER-encoded `RSAPrivateKey`.
/// `hash_data` is the **already-hashed** digest; its length must match the
/// output size of `hash_algo` (20, 28, 32, 48, or 64 bytes).
///
/// Returns the raw RSA signature: modulus-length bytes (256 for RSA-2048).
#[cfg(feature = "rsa")]
pub fn rsa_sign_pkcs1v15(
    _key_type: KeyType,
    private_key_der: &[u8],
    hash_data: &[u8],
    hash_algo: HashAlgorithm,
    _rng: &mut impl RngCore,
) -> Result<heapless::Vec<u8, 512>, CryptoError> {
    use ::rsa::RsaPrivateKey;
    use ::rsa::pkcs1::DecodeRsaPrivateKey;
    use ::rsa::pkcs1v15::SigningKey;
    use ::rsa::signature::hazmat::PrehashSigner;
    use sha1::Sha1;
    use sha2::{Sha256, Sha384, Sha512};

    let priv_key = RsaPrivateKey::from_pkcs1_der(private_key_der)
        .map_err(|_| CryptoError::WrongKeyLength)?;

    // Each arm produces the raw signature bytes (heap-allocated by rsa crate).
    let sig_bytes: alloc::vec::Vec<u8> = match hash_algo {
        HashAlgorithm::Sha1 => {
            let key: SigningKey<Sha1> = SigningKey::new(priv_key);
            let sig = key.sign_prehash(hash_data).map_err(|_| CryptoError::SignFailure)?;
            use ::rsa::signature::SignatureEncoding;
            sig.to_bytes().to_vec()
        }
        HashAlgorithm::Sha224 => {
            use sha2::Sha224;
            let key: SigningKey<Sha224> = SigningKey::new(priv_key);
            let sig = key.sign_prehash(hash_data).map_err(|_| CryptoError::SignFailure)?;
            use ::rsa::signature::SignatureEncoding;
            sig.to_bytes().to_vec()
        }
        HashAlgorithm::Sha256 => {
            let key: SigningKey<Sha256> = SigningKey::new(priv_key);
            let sig = key.sign_prehash(hash_data).map_err(|_| CryptoError::SignFailure)?;
            use ::rsa::signature::SignatureEncoding;
            sig.to_bytes().to_vec()
        }
        HashAlgorithm::Sha384 => {
            let key: SigningKey<Sha384> = SigningKey::new(priv_key);
            let sig = key.sign_prehash(hash_data).map_err(|_| CryptoError::SignFailure)?;
            use ::rsa::signature::SignatureEncoding;
            sig.to_bytes().to_vec()
        }
        HashAlgorithm::Sha512 => {
            let key: SigningKey<sha2::Sha512> = SigningKey::new(priv_key);
            let sig = key.sign_prehash(hash_data).map_err(|_| CryptoError::SignFailure)?;
            use ::rsa::signature::SignatureEncoding;
            sig.to_bytes().to_vec()
        }
    };

    let mut out: heapless::Vec<u8, 512> = heapless::Vec::new();
    out.extend_from_slice(&sig_bytes).map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

/// Compute an RSA-PSS signature over a pre-hashed message using SHA-256.
///
/// PSS is inherently randomised; `rng` must be a CSPRNG.
/// The salt length is set to the hash output length (32 bytes for SHA-256),
/// which is the recommended default per RFC 8017 §9.1.
///
/// Returns the raw RSA signature bytes (256 bytes for RSA-2048).
#[cfg(feature = "rsa")]
pub fn rsa_sign_pss(
    _key_type: KeyType,
    private_key_der: &[u8],
    hash_data: &[u8],
    _hash_algo: HashAlgorithm,
    _salt_len: usize,
    rng: &mut (impl RngCore + rand_core::CryptoRng),
) -> Result<heapless::Vec<u8, 512>, CryptoError> {
    use ::rsa::RsaPrivateKey;
    use ::rsa::pkcs1::DecodeRsaPrivateKey;
    use ::rsa::pss::BlindedSigningKey;
    use ::rsa::signature::hazmat::RandomizedPrehashSigner;
    use sha2::Sha256;

    let priv_key = RsaPrivateKey::from_pkcs1_der(private_key_der)
        .map_err(|_| CryptoError::WrongKeyLength)?;

    // BlindedSigningKey uses randomized blinding against timing attacks.
    let key: BlindedSigningKey<Sha256> = BlindedSigningKey::new(priv_key);
    let sig = key
        .sign_prehash_with_rng(rng, hash_data)
        .map_err(|_| CryptoError::SignFailure)?;

    use ::rsa::signature::SignatureEncoding;
    let sig_bytes = sig.to_bytes();

    let mut out: heapless::Vec<u8, 512> = heapless::Vec::new();
    out.extend_from_slice(sig_bytes.as_ref()).map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

/// Perform RSA-PKCS#1-v1.5 decryption (block type 2).
///
/// `private_key_der` is the PKCS#1 DER-encoded `RSAPrivateKey`.
/// `ciphertext` is the RSA-encrypted data (modulus-length bytes).
///
/// Returns the plaintext on success.
#[cfg(feature = "rsa")]
pub fn rsa_decrypt_pkcs1v15(
    _key_type: KeyType,
    private_key_der: &[u8],
    ciphertext: &[u8],
) -> Result<heapless::Vec<u8, 512>, CryptoError> {
    use ::rsa::RsaPrivateKey;
    use ::rsa::pkcs1::DecodeRsaPrivateKey;
    use ::rsa::Pkcs1v15Encrypt;

    let priv_key = RsaPrivateKey::from_pkcs1_der(private_key_der)
        .map_err(|_| CryptoError::WrongKeyLength)?;

    let plaintext = priv_key
        .decrypt(Pkcs1v15Encrypt, ciphertext)
        .map_err(|_| CryptoError::DecryptFailure)?;

    let mut out: heapless::Vec<u8, 512> = heapless::Vec::new();
    out.extend_from_slice(&plaintext).map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

/// Perform RSA-OAEP decryption using SHA-256 as the hash and MGF hash.
///
/// `private_key_der` is the PKCS#1 DER-encoded `RSAPrivateKey`.
/// `ciphertext` is the RSA-OAEP-encrypted data (modulus-length bytes).
///
/// Returns the plaintext on success.
#[cfg(feature = "rsa")]
pub fn rsa_decrypt_oaep(
    _key_type: KeyType,
    private_key_der: &[u8],
    ciphertext: &[u8],
    _hash_algo: HashAlgorithm,
    _rng: &mut impl RngCore,
) -> Result<heapless::Vec<u8, 512>, CryptoError> {
    use ::rsa::RsaPrivateKey;
    use ::rsa::pkcs1::DecodeRsaPrivateKey;
    use ::rsa::Oaep;
    use sha2::Sha256;

    let priv_key = RsaPrivateKey::from_pkcs1_der(private_key_der)
        .map_err(|_| CryptoError::WrongKeyLength)?;

    let scheme = Oaep::new::<Sha256>();
    let plaintext = priv_key
        .decrypt(scheme, ciphertext)
        .map_err(|_| CryptoError::DecryptFailure)?;

    let mut out: heapless::Vec<u8, 512> = heapless::Vec::new();
    out.extend_from_slice(&plaintext).map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

/// Perform a raw RSA private key operation: result = input^d mod n.
///
/// No padding is applied or removed. The caller is responsible for any
/// padding scheme (e.g. PKCS#1 v1.5 for ALGO_RSA_RAW, or OAEP/PKCS1v1.5
/// stripping after ALGO_RSA_DECRYPT).
///
/// Returns the result as big-endian bytes, zero-padded to the modulus length.
/// For RSA-2048 this is always 256 bytes.
#[cfg(feature = "rsa")]
pub fn rsa_private_raw(
    private_key_der: &[u8],
    data: &[u8],
) -> Result<heapless::Vec<u8, 512>, CryptoError> {
    use ::rsa::RsaPrivateKey;
    use ::rsa::pkcs1::DecodeRsaPrivateKey;
    use ::rsa::traits::PublicKeyParts;

    let priv_key = RsaPrivateKey::from_pkcs1_der(private_key_der)
        .map_err(|_| CryptoError::WrongKeyLength)?;

    let n = priv_key.n();
    let key_len = (n.bits() + 7) / 8; // modulus length in bytes

    // Convert input bytes to BigUint (rsa 0.9 re-exports BigUint)
    let c = ::rsa::BigUint::from_bytes_be(data);

    // Raw RSA private key operation: m = c^d mod n (with CRT, no blinding)
    // SAFETY: hazmat — caller is responsible for ensuring correct use.
    // We pass None for the blinding RNG; a local phantom type satisfies the generic bound.
    struct NoRng;
    impl ::rsa::rand_core::RngCore for NoRng {
        fn next_u32(&mut self) -> u32 { 0 }
        fn next_u64(&mut self) -> u64 { 0 }
        fn fill_bytes(&mut self, _: &mut [u8]) {}
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), ::rsa::rand_core::Error> { Ok(()) }
    }
    impl ::rsa::rand_core::CryptoRng for NoRng {}
    let m = ::rsa::hazmat::rsa_decrypt(
        None::<&mut NoRng>,
        &priv_key,
        &c,
    )
    .map_err(|_| CryptoError::DecryptFailure)?;

    // Convert result to big-endian, zero-padded to key_len bytes
    let m_bytes = m.to_bytes_be();
    let mut out: heapless::Vec<u8, 512> = heapless::Vec::new();
    for _ in 0..key_len.saturating_sub(m_bytes.len()) {
        let _ = out.push(0x00);
    }
    out.extend_from_slice(&m_bytes).map_err(|_| CryptoError::BufferTooSmall)?;
    Ok(out)
}

/// Legacy RSA PKCS#1v1.5 sign (SHA-256) — operates on `KeyMaterial`.
#[cfg(feature = "rsa")]
pub fn rsa_sign(
    key: &KeyMaterial,
    hash_data: &[u8],
) -> Result<heapless::Vec<u8, 512>, CryptoError> {
    struct DummyRng;
    impl RngCore for DummyRng {
        fn next_u32(&mut self) -> u32 { 0 }
        fn next_u64(&mut self) -> u64 { 0 }
        fn fill_bytes(&mut self, _dest: &mut [u8]) {}
        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> { Ok(()) }
    }
    rsa_sign_pkcs1v15(key.key_type, &key.raw, hash_data, HashAlgorithm::Sha256, &mut DummyRng)
}

/// Legacy RSA PKCS#1v1.5 decrypt — operates on `KeyMaterial`.
#[cfg(feature = "rsa")]
pub fn rsa_decrypt(
    key: &KeyMaterial,
    ciphertext: &[u8],
) -> Result<heapless::Vec<u8, 512>, CryptoError> {
    rsa_decrypt_pkcs1v15(key.key_type, &key.raw, ciphertext)
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Wrap a raw private key scalar into a [`KeyMaterial`] for keystore storage.
///
/// The returned `KeyMaterial` will zeroize `private_key_raw`'s copy on drop.
pub fn ec_private_to_key_material(
    key_type: KeyType,
    key_id: KeyId,
    private_key_raw: &[u8],
) -> Result<KeyMaterial, CryptoError> {
    let expected_len = key_type.raw_key_len();
    if private_key_raw.len() != expected_len {
        return Err(CryptoError::WrongKeyLength);
    }

    let mut raw: heapless::Vec<u8, MAX_KEY_BYTES> = heapless::Vec::new();
    raw.extend_from_slice(private_key_raw)
        .map_err(|_| CryptoError::BufferTooSmall)?;

    Ok(KeyMaterial { key_type, key_id, raw })
}

// ---------------------------------------------------------------------------
// Unit tests (run with `cargo test -p pico2hsm-firmware`)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal deterministic RNG for tests — wraps a counter so it never
    // blocks.  NOT cryptographically secure; for testing only.
    struct CounterRng(u64);
    impl RngCore for CounterRng {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_add(1);
            // Mix bits so sequential outputs differ meaningfully.
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u32
        }
        fn next_u64(&mut self) -> u64 {
            let lo = self.next_u32() as u64;
            let hi = self.next_u32() as u64;
            (hi << 32) | lo
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
    // Mark as CryptoRng so the elliptic-curve crates will accept it.
    impl rand_core::CryptoRng for CounterRng {}

    #[test]
    fn p256_keygen_sign_verify_roundtrip() {
        let mut rng = CounterRng(0xdeadbeef);
        let pair = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();
        assert_eq!(pair.private_key.len(), 32);
        assert_eq!(pair.public_key.len(), 65);
        assert_eq!(pair.public_key[0], 0x04);

        let hash = [0x42u8; 32];
        let sig = ecdsa_sign(
            KeyType::EcPrivateP256,
            &pair.private_key,
            &hash,
            &mut rng,
        )
        .unwrap();

        let ok = ecdsa_verify(
            KeyType::EcPrivateP256,
            &pair.public_key,
            &hash,
            &sig,
        )
        .unwrap();
        assert!(ok, "P-256 signature verification failed");
    }

    #[test]
    fn p384_keygen_sign_verify_roundtrip() {
        let mut rng = CounterRng(0xcafebabe);
        let pair = generate_ec_keypair(KeyType::EcPrivateP384, &mut rng).unwrap();
        assert_eq!(pair.private_key.len(), 48);
        assert_eq!(pair.public_key.len(), 97);

        let hash = [0x55u8; 48];
        let sig = ecdsa_sign(
            KeyType::EcPrivateP384,
            &pair.private_key,
            &hash,
            &mut rng,
        )
        .unwrap();
        let ok = ecdsa_verify(
            KeyType::EcPrivateP384,
            &pair.public_key,
            &hash,
            &sig,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn p521_keygen_sign_verify_roundtrip() {
        let mut rng = CounterRng(0x1234);
        let pair = generate_ec_keypair(KeyType::EcPrivateP521, &mut rng).unwrap();
        assert_eq!(pair.private_key.len(), 66);
        assert_eq!(pair.public_key.len(), 133);

        let hash = [0x77u8; 64];
        let sig = ecdsa_sign(
            KeyType::EcPrivateP521,
            &pair.private_key,
            &hash,
            &mut rng,
        )
        .unwrap();
        let ok = ecdsa_verify(
            KeyType::EcPrivateP521,
            &pair.public_key,
            &hash,
            &sig,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn k256_keygen_sign_verify_roundtrip() {
        let mut rng = CounterRng(0xaabb);
        let pair = generate_ec_keypair(KeyType::EcPrivateK256, &mut rng).unwrap();
        assert_eq!(pair.private_key.len(), 32);
        assert_eq!(pair.public_key.len(), 65);

        let hash = [0x11u8; 32];
        let sig = ecdsa_sign(
            KeyType::EcPrivateK256,
            &pair.private_key,
            &hash,
            &mut rng,
        )
        .unwrap();
        let ok = ecdsa_verify(
            KeyType::EcPrivateK256,
            &pair.public_key,
            &hash,
            &sig,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn p256_ecdh_roundtrip() {
        let mut rng = CounterRng(0x9999);
        let alice = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();
        let bob = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();

        let alice_shared = ecdh_agree(
            KeyType::EcPrivateP256,
            &alice.private_key,
            &bob.public_key,
        )
        .unwrap();
        let bob_shared = ecdh_agree(
            KeyType::EcPrivateP256,
            &bob.private_key,
            &alice.public_key,
        )
        .unwrap();

        assert_eq!(alice_shared.as_slice(), bob_shared.as_slice());
        assert_eq!(alice_shared.len(), 32);
    }

    #[test]
    fn p384_ecdh_roundtrip() {
        let mut rng = CounterRng(0x8888);
        let alice = generate_ec_keypair(KeyType::EcPrivateP384, &mut rng).unwrap();
        let bob = generate_ec_keypair(KeyType::EcPrivateP384, &mut rng).unwrap();

        let alice_shared = ecdh_agree(
            KeyType::EcPrivateP384,
            &alice.private_key,
            &bob.public_key,
        )
        .unwrap();
        let bob_shared = ecdh_agree(
            KeyType::EcPrivateP384,
            &bob.private_key,
            &alice.public_key,
        )
        .unwrap();

        assert_eq!(alice_shared.as_slice(), bob_shared.as_slice());
        assert_eq!(alice_shared.len(), 48);
    }

    #[test]
    fn k256_ecdh_roundtrip() {
        let mut rng = CounterRng(0x7777);
        let alice = generate_ec_keypair(KeyType::EcPrivateK256, &mut rng).unwrap();
        let bob = generate_ec_keypair(KeyType::EcPrivateK256, &mut rng).unwrap();

        let alice_shared = ecdh_agree(
            KeyType::EcPrivateK256,
            &alice.private_key,
            &bob.public_key,
        )
        .unwrap();
        let bob_shared = ecdh_agree(
            KeyType::EcPrivateK256,
            &bob.private_key,
            &alice.public_key,
        )
        .unwrap();

        assert_eq!(alice_shared.as_slice(), bob_shared.as_slice());
    }

    #[test]
    fn invalid_signature_rejected() {
        let mut rng = CounterRng(0xfeed);
        let pair = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();
        let hash = [0x01u8; 32];
        let mut sig = ecdsa_sign(
            KeyType::EcPrivateP256,
            &pair.private_key,
            &hash,
            &mut rng,
        )
        .unwrap();

        // Corrupt the last byte of the DER signature.
        let last = sig.len() - 1;
        sig[last] ^= 0xff;

        let ok = ecdsa_verify(
            KeyType::EcPrivateP256,
            &pair.public_key,
            &hash,
            &sig,
        )
        .unwrap_or(false);
        assert!(!ok, "corrupted signature should not verify");
    }

    #[test]
    fn wrong_hash_rejected() {
        let mut rng = CounterRng(0xbeef);
        let pair = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();
        let hash = [0x01u8; 32];
        let wrong_hash = [0x02u8; 32];

        let sig = ecdsa_sign(
            KeyType::EcPrivateP256,
            &pair.private_key,
            &hash,
            &mut rng,
        )
        .unwrap();

        let ok = ecdsa_verify(
            KeyType::EcPrivateP256,
            &pair.public_key,
            &wrong_hash,
            &sig,
        )
        .unwrap_or(false);
        assert!(!ok, "signature over different hash should not verify");
    }

    #[test]
    fn ec_private_to_key_material_roundtrip() {
        let mut rng = CounterRng(0xc0ffee);
        let pair = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng).unwrap();
        let key_id = KeyId(0x0001);

        let material = ec_private_to_key_material(
            KeyType::EcPrivateP256,
            key_id,
            &pair.private_key,
        )
        .unwrap();

        assert_eq!(material.key_type, KeyType::EcPrivateP256);
        assert_eq!(material.key_id, key_id);
        assert_eq!(material.raw.as_slice(), pair.private_key.as_slice());
    }

    #[test]
    fn brainpool_returns_unsupported() {
        let mut rng = CounterRng(0);
        assert!(matches!(
            generate_ec_keypair(KeyType::EcPrivateBrainpoolP256, &mut rng),
            Err(CryptoError::UnsupportedAlgorithm)
        ));
    }
}
