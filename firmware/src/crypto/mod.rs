//! Cryptographic operations module.
//!
//! All cryptographic operations performed by the HSM firmware go through
//! this module. It provides a clean interface over the underlying RustCrypto
//! crates, with no_std compatibility and zeroize-on-drop guarantees.
//!
//! # Sub-modules
//! - `asymmetric` — ECDSA, ECDH, RSA sign/verify/encrypt/decrypt
//! - `symmetric`  — AES-CBC/CTR/GCM/CMAC, ChaCha20-Poly1305
//! - `kdf`        — HKDF, PBKDF2, X9.63 KDF, BIP32/SLIP-0010
//! - `rng`        — TRNG + ADC entropy mixing, seeded CSPRNG
//!
//! # Design principles
//! - All key material inputs and outputs are via `KeyMaterial` (which
//!   zeroizes on drop)
//! - All intermediate buffers use stack-allocated `heapless::Vec`
//! - Timing side-channels are mitigated using the `subtle` crate for
//!   all equality comparisons involving secrets

pub mod asymmetric;
/// Runtime-width big integers for the sliced RSA key generator.
#[cfg(feature = "rsa")]
pub mod bignum;
pub mod ec_params;
pub mod kdf;
/// Sliceable FIPS 186-5 RSA key generation (A.1.3 / B.3).
#[cfg(feature = "rsa")]
pub mod rsa_keygen;
pub mod symmetric;

// RNG module uses embassy_rp TRNG and ADC peripherals — ARM only.
#[cfg(target_arch = "arm")]
pub mod rng;
