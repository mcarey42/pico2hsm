//! Key object types for the pico2hsm keystore.
//!
//! `KeyMaterial` is the in-memory representation of a decrypted key. It
//! implements `zeroize::ZeroizeOnDrop` so that secret material is cleared
//! from memory as soon as it goes out of scope.
//!
//! `KeyRecord` is the metadata header stored alongside the encrypted key on
//! flash (no secret material — the ciphertext lives in subsequent sectors).

use heapless::{String, Vec};
use zeroize::Zeroize;

/// A key object identifier — 2 bytes matching SC-HSM file ID convention.
///
/// Key IDs 0x0001–0x00FE are reserved for asymmetric private keys.
/// Key IDs 0x0100–0x01FE are reserved for symmetric keys.
/// Key ID 0x0000 and 0xFFFF are reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub u16);

/// Key algorithm and type tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// RSA private key, 2048-bit modulus.
    RsaPrivate2048,
    /// RSA private key, 4096-bit modulus.
    RsaPrivate4096,
    /// ECDSA/ECDH private key on NIST P-256 (prime256v1).
    EcPrivateP256,
    /// ECDSA/ECDH private key on NIST P-384.
    EcPrivateP384,
    /// ECDSA/ECDH private key on NIST P-521.
    EcPrivateP521,
    /// ECDSA/ECDH private key on secp256k1 (Bitcoin curve).
    EcPrivateK256,
    /// ECDSA/ECDH private key on Brainpool P-256r1.
    EcPrivateBrainpoolP256,
    /// ECDSA/ECDH private key on Brainpool P-384r1.
    EcPrivateBrainpoolP384,
    /// ECDSA/ECDH private key on Brainpool P-512r1.
    EcPrivateBrainpoolP512,
    /// AES symmetric key, 128-bit.
    Aes128,
    /// AES symmetric key, 192-bit.
    Aes192,
    /// AES symmetric key, 256-bit.
    Aes256,
    /// BIP32/SLIP-0010 master key (32-byte seed + 32-byte chain code).
    Bip32Master,
}

impl KeyType {
    /// Returns the expected raw key material size in bytes for this key type.
    pub fn raw_key_len(&self) -> usize {
        match self {
            KeyType::RsaPrivate2048 => 1192, // PKCS#1 DER, ~1192 bytes
            KeyType::RsaPrivate4096 => 2350, // PKCS#1 DER, ~2350 bytes (capped at MAX_KEY_BYTES)
            KeyType::EcPrivateP256 => 32,
            KeyType::EcPrivateP384 => 48,
            KeyType::EcPrivateP521 => 66,
            KeyType::EcPrivateK256 => 32,
            KeyType::EcPrivateBrainpoolP256 => 32,
            KeyType::EcPrivateBrainpoolP384 => 48,
            KeyType::EcPrivateBrainpoolP512 => 64,
            KeyType::Aes128 => 16,
            KeyType::Aes192 => 24,
            KeyType::Aes256 => 32,
            KeyType::Bip32Master => 64, // 32-byte seed + 32-byte chain code
        }
    }
}

/// Maximum raw key material size in bytes.
///
/// Sized to hold an RSA-4096 PKCS#1 DER private key (~2350 bytes).
/// This determines the stack size of `KeyMaterial`.
pub const MAX_KEY_BYTES: usize = 2048;

// ---------------------------------------------------------------------------
// KeyMaterial — in-memory decrypted key, must be zeroized on drop
// ---------------------------------------------------------------------------

/// A decrypted key object held in RAM.
///
/// **Security contract**: This type implements `ZeroizeOnDrop`. The `raw`
/// field is zeroed as soon as the value is dropped. Callers MUST NOT copy
/// `raw` into unzeroized buffers.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct KeyMaterial {
    /// Algorithm tag.
    pub key_type: KeyType,
    /// Identifier matching the on-flash `KeyRecord`.
    pub key_id: KeyId,
    /// Raw key bytes (private key scalar or symmetric key).
    pub raw: Vec<u8, MAX_KEY_BYTES>,
}

// Manually implement Debug to avoid leaking key bytes.
impl core::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("key_type", &self.key_type)
            .field("key_id", &self.key_id)
            .field("raw", &"<redacted>")
            .finish()
    }
}

// KeyType and KeyId don't contain secret material; standard Zeroize impl is fine.
impl Zeroize for KeyType {
    fn zeroize(&mut self) {
        // Replace with a non-sensitive sentinel value.
        *self = KeyType::Aes128;
    }
}

impl Zeroize for KeyId {
    fn zeroize(&mut self) {
        self.0 = 0;
    }
}

// ---------------------------------------------------------------------------
// KeyRecord — metadata header stored on flash (no secret material)
// ---------------------------------------------------------------------------

/// Metadata record for a stored key object.
///
/// This is the header stored in the keystore directory sector. It contains
/// no secret material — only identifiers, labels, and counters.
#[derive(Debug, Clone)]
pub struct KeyRecord {
    /// Key object identifier.
    pub key_id: KeyId,
    /// Algorithm tag.
    pub key_type: KeyType,
    /// Human-readable UTF-8 label (up to 64 bytes).
    pub label: String<64>,
    /// Access flags bitfield (SC-HSM EF.Key object flags).
    pub flags: u16,
    /// Monotonically increasing usage counter (sign/decrypt operations).
    pub access_counter: u32,
}
