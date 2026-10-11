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

/// A key object identifier — 4 bytes with a structured encoding scheme.
///
/// Encoding (bits 31–0):
/// - bits 31–24: `partition_id` (u8) — 0 = default partition
/// - bits 23–16: `applet_id`    (u8) — 0=SC-HSM, 1=PIV, 2=OpenPGP, 0x10=domain
/// - bits 15–8:  reserved          — always 0
/// - bits  7–0:  `proto_ref`    (u8) — protocol-level key reference
///
/// SC-HSM partition-0 keys: `KeyId(proto_ref as u32)` — e.g. key 0x01 → `KeyId(0x00000001)`.
/// Key ID 0x00000000 and `0xFFFF_FFFF` are reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub u32);

/// Applet identifier — identifies which applet owns a key slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AppletId {
    ScHsm = 0x00,
    Piv = 0x01,
    OpenPgp = 0x02,
    /// Domain records (cluster plan V3): object sidecars, member
    /// certificates, the pinned peer.  Never a user key.
    Domain = 0x10,
}

impl Zeroize for AppletId {
    fn zeroize(&mut self) {
        *self = AppletId::ScHsm;
    }
}

/// Per-applet PIN slot identifier.
///
/// Each slot maps to a distinct flash region so that each applet stores its
/// PIN credential independently.  Slot indices are stable — do not reorder.
///
/// `ScHsmUser` and `ScHsmSo` are currently backed by in-RAM state in
/// `ScHsmState`.  `PivPin`, `OpenPgpPw1`, and `OpenPgpPw3` are placeholders
/// pending their respective applet implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PinSlot {
    ScHsmUser = 0,
    ScHsmSo = 1,
    PivPin = 2,
    OpenPgpPw1 = 3,
    OpenPgpPw3 = 4,
}

impl PinSlot {
    /// Return the `AppletId` that owns this PIN slot.
    pub fn owner(self) -> AppletId {
        match self {
            PinSlot::ScHsmUser | PinSlot::ScHsmSo => AppletId::ScHsm,
            PinSlot::PivPin => AppletId::Piv,
            PinSlot::OpenPgpPw1 | PinSlot::OpenPgpPw3 => AppletId::OpenPgp,
        }
    }

    /// Returns `true` if this slot has real flash backing today.
    pub fn is_implemented(self) -> bool {
        true
    }
}

impl KeyId {
    /// SC-HSM key on the given partition (partition=0 for default).
    pub fn sc_hsm(partition: u8, key_ref: u8) -> Self {
        KeyId((u32::from(partition) << 24) | u32::from(key_ref))
    }
    /// PIV key reference (always partition 0 — PIV has no partition concept).
    pub fn piv(key_ref: u8) -> Self {
        KeyId((AppletId::Piv as u32) << 16 | u32::from(key_ref))
    }
    /// `OpenPGP` key slot index (0=SIG, 1=DEC, 2=AUTH).
    pub fn openpgp(slot: u8) -> Self {
        KeyId((AppletId::OpenPgp as u32) << 16 | u32::from(slot))
    }
    /// SC-HSM EF file entry on the given partition.
    ///
    /// Encodes the full 16-bit file ID in bits 15–0, so every FID maps to a
    /// distinct `KeyId`.  A non-zero `file_id_hi` (bits 15–8) is what marks an
    /// EF; FIDs with `file_id_hi == 0` would collide with SC-HSM key slots
    /// (`sc_hsm(partition, file_id_lo)`) and must be refused — see
    /// [`KeyId::sc_hsm_ef_checked`].
    ///
    /// (Before 2026-10 only the low nibble of `file_id_lo` was kept, so e.g.
    /// CE01 and CE11 aliased, and FID 00Ex overwrote key slot 0xEx.)
    pub fn sc_hsm_ef(partition: u8, file_id_hi: u8, file_id_lo: u8) -> Self {
        KeyId((u32::from(partition) << 24) | (u32::from(file_id_hi) << 8) | u32::from(file_id_lo))
    }

    /// [`KeyId::sc_hsm_ef`] for FIDs that may be created or written: `None`
    /// when `file_id_hi == 0`, which would address a key slot.
    pub fn sc_hsm_ef_checked(partition: u8, file_id_hi: u8, file_id_lo: u8) -> Option<Self> {
        (file_id_hi != 0).then(|| Self::sc_hsm_ef(partition, file_id_hi, file_id_lo))
    }
    /// Extract the protocol key reference (low byte).
    pub fn proto_ref(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
    /// Extract the applet byte (bits 23–16).
    pub fn applet_byte(self) -> u8 {
        ((self.0 >> 16) & 0xFF) as u8
    }
    /// Extract the partition byte (bits 31–24).
    pub fn partition(self) -> u8 {
        ((self.0 >> 24) & 0xFF) as u8
    }
}

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
    /// Ed25519 private key (32-byte seed).
    Ed25519,
    /// X25519 private key (32 bytes).
    X25519,
    /// RSA private key, 3072-bit modulus.
    ///
    /// Placed at the end of the enum (discriminant 15) to preserve flash
    /// serialization compatibility — existing stored keys use discriminants 0–14.
    RsaPrivate3072,
    /// Elementary File (EF) entry stored in flash.
    ///
    /// Used by the operational buffer architecture to represent EF file entries
    /// (e.g. EF.C.DevAut) alongside crypto keys in the unified `key_index`.
    /// Discriminant 16.
    EfFile,
}

impl KeyType {
    /// Returns the expected raw key material size in bytes for this key type.
    #[allow(clippy::match_same_arms)] // one row per key type reads as a table
    pub fn raw_key_len(&self) -> usize {
        match self {
            KeyType::RsaPrivate2048 => 1192, // PKCS#1 DER, ~1192 bytes
            KeyType::EfFile => 0,            // Variable-length; not a fixed-size key
            KeyType::RsaPrivate3072 => 1770, // PKCS#1 DER, ~1770 bytes
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
            KeyType::Ed25519 => 32,
            KeyType::X25519 => 32,
        }
    }
}

/// Maximum raw key material size in bytes.
///
/// Sized to hold an RSA-4096 PKCS#1 DER private key (~2350 bytes).
/// This determines the stack size of `KeyMaterial`.
pub const MAX_KEY_BYTES: usize = 2400;

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

#[cfg(test)]
mod ef_id_tests {
    use super::*;

    #[test]
    fn distinct_fids_never_alias() {
        assert_ne!(
            KeyId::sc_hsm_ef(0, 0xCE, 0x01),
            KeyId::sc_hsm_ef(0, 0xCE, 0x11)
        );
        assert_ne!(
            KeyId::sc_hsm_ef(0, 0x2F, 0x02),
            KeyId::sc_hsm_ef(0, 0x2F, 0xE2)
        );
    }

    #[test]
    fn ef_ids_never_hit_key_slots() {
        for hi in 1..=0xFFu8 {
            for lo in 0..=0xFFu8 {
                let ef = KeyId::sc_hsm_ef_checked(0, hi, lo).unwrap();
                assert!((ef.0 >> 8) & 0xFF != 0, "EF marker bits 15-8");
                assert_ne!(ef, KeyId::sc_hsm(0, lo));
            }
        }
        // High byte 0 would address key slot `lo`: refused.
        assert_eq!(KeyId::sc_hsm_ef_checked(0, 0x00, 0xE5), None);
    }
}
