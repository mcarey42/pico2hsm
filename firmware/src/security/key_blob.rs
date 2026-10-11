//! CardContact SmartCard-HSM key-backup blob: the key and policy fields.
//!
//! [`crate::security::dkek`] builds and checks the blob envelope (KCV,
//! AES-256-CBC under K_enc, AES-CMAC under K_mac).  This module holds what
//! goes inside it:
//!
//! - the key type code and default-algorithm OID of the header;
//! - the policy fields of the header (allowed algorithms, access
//!   conditions) — encoded and decoded only in [`write_policy_fields`] and
//!   [`read_policy_fields`];
//! - the key material of the encrypted part, for EC (P-256, P-384, P-521,
//!   secp256k1), RSA (CRT on export; CRT and plain on import) and AES.
//!
//! The layout, with sources, is in `docs/SC_HSM_APDU_REFERENCE.md`
//! ("Key backup blob (WRAP / UNWRAP)").  In short, after the 8-byte random
//! prefix the encrypted part holds `key size (2) || material`, where
//! `LV(x)` = 2-byte big-endian length then `x`:
//!
//! | type | material                                                        |
//! |------|-----------------------------------------------------------------|
//! | 5    | RSA: `LV(d) LV(n) LV(e)` (import only)                          |
//! | 6    | RSA-CRT: `LV(dP) LV(dQ) LV(p) LV(qInv) LV(q) LV(n) LV(e)`       |
//! | 12   | EC: `LV(a) LV(b) LV(p) LV(order) LV(G) LV(d) LV(Q)`             |
//! | 15   | AES: the key; the size field is in BYTES                        |
//!
//! Everything else the firmware stores (Ed25519, X25519, brainpool, BIP32
//! masters, data objects) has no CardContact encoding:
//! [`BlobError::Unsupported`].

use heapless::Vec;
use zeroize::Zeroizing;

use pico2hsm_core::key::KeyType as CoreKeyType;

use crate::crypto::ec_params::{ec_domain_params, EcDomainParams};
use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};
use crate::security::key_policy::{KeyPolicy, MAX_ALGORITHMS};

/// Key type code: RSA, private exponent and modulus.
pub const KEY_TYPE_RSA: u8 = 5;
/// Key type code: RSA in CRT form.
pub const KEY_TYPE_RSA_CRT: u8 = 6;
/// Key type code: elliptic curve.
pub const KEY_TYPE_EC: u8 = 12;
/// Key type code: AES.
pub const KEY_TYPE_AES: u8 = 15;

/// Default algorithm of an RSA key: id-TA-RSA-v1-5-SHA-256 (0.4.0.127.0.7.2.2.2.1.2).
pub const OID_RSA_V15_SHA256: &[u8] = &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x02];
/// Default algorithm of an EC key: id-TA-ECDSA-SHA-256 (0.4.0.127.0.7.2.2.2.2.3).
pub const OID_ECDSA_SHA256: &[u8] = &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03];
/// Default algorithm of an AES key: aes (2.16.840.1.101.3.4.1).
pub const OID_AES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01];

/// Longest OID accepted in the header (default algorithm, key OID).
pub const MAX_OID: usize = 32;
/// Longest access-condition field accepted.
pub const MAX_ACCESS: usize = 16;

/// The key-flag bits that travel in the access-condition field
/// (ALLOW_SIGN, ALLOW_DECRYPT, ALLOW_DERIVE, NO_EXPORT).
const KEY_FLAG_BITS: u8 = 0x0F;

/// Why a key could not be encoded or decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobError {
    /// Inconsistent or malformed content.
    Malformed,
    /// A key the CardContact format, or this firmware, cannot express.
    Unsupported,
}

// ---------------------------------------------------------------------------
// Policy fields
// ---------------------------------------------------------------------------

/// Append the header's policy fields: `LV(allowed algorithms) LV(access
/// conditions)`.
///
/// - Allowed algorithms = the key's algorithm list (tag 91); empty = the
///   default set for the key type, as on a SmartCard-HSM.
/// - Access conditions: CardContact does not use the field (empty on a
///   SmartCard-HSM).  pico2hsm puts its key flags (`0xD4` at generation:
///   ALLOW_SIGN / ALLOW_DECRYPT / ALLOW_DERIVE) there as one byte when any
///   is set, so another pico2hsm restores them.
///
/// The use counter (tag 90) has no field; WRAP refuses keys that have one.
/// The key domain (tag 92) has none either: UNWRAP puts the key into the
/// domain whose DKEK opened it, the only one there is.
pub fn write_policy_fields<const N: usize>(
    policy: &KeyPolicy,
    key_flags: u8,
    out: &mut Vec<u8, N>,
) -> Result<(), BlobError> {
    put_lv(out, &policy.algorithms)?;
    let flags = key_flags & KEY_FLAG_BITS;
    if flags == 0 {
        put_lv(out, &[])
    } else {
        put_lv(out, &[flags])
    }
}

/// Read the header's policy fields back: `(policy, key_flags)`.
///
/// An access-condition field that is not pico2hsm's one byte (a real
/// SmartCard-HSM leaves it empty) gives no key flags.
pub fn read_policy_fields(algorithms: &[u8], access: &[u8]) -> Result<(KeyPolicy, u8), BlobError> {
    let mut policy = KeyPolicy::default();
    if algorithms.len() > MAX_ALGORITHMS {
        return Err(BlobError::Malformed);
    }
    policy
        .algorithms
        .extend_from_slice(algorithms)
        .map_err(|_| BlobError::Malformed)?;
    let key_flags = match access {
        [f] => f & KEY_FLAG_BITS,
        _ => 0,
    };
    Ok((policy, key_flags))
}

// ---------------------------------------------------------------------------
// Curves
// ---------------------------------------------------------------------------

/// The curves with a CardContact encoding that the firmware implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
    P521,
    K256,
}

impl Curve {
    const ALL: [Curve; 4] = [Curve::P256, Curve::P384, Curve::P521, Curve::K256];

    /// The curve of a stored key.
    pub fn of_algorithm(a: AlgorithmId) -> Option<Curve> {
        match a {
            AlgorithmId::EcdsaP256 | AlgorithmId::EcdhP256 => Some(Curve::P256),
            AlgorithmId::EcdsaP384 | AlgorithmId::EcdhP384 => Some(Curve::P384),
            AlgorithmId::EcdsaP521 | AlgorithmId::EcdhP521 => Some(Curve::P521),
            AlgorithmId::EcdsaK256 => Some(Curve::K256),
            _ => None,
        }
    }

    /// The algorithm a key on this curve is stored with (as GENERATE KEY
    /// PAIR does).
    pub fn algorithm(self) -> AlgorithmId {
        match self {
            Curve::P256 => AlgorithmId::EcdsaP256,
            Curve::P384 => AlgorithmId::EcdsaP384,
            Curve::P521 => AlgorithmId::EcdsaP521,
            Curve::K256 => AlgorithmId::EcdsaK256,
        }
    }

    /// Core key type for the key index.
    pub fn core_type(self) -> CoreKeyType {
        match self {
            Curve::P256 => CoreKeyType::EcPrivateP256,
            Curve::P384 => CoreKeyType::EcPrivateP384,
            Curve::P521 => CoreKeyType::EcPrivateP521,
            Curve::K256 => CoreKeyType::EcPrivateK256,
        }
    }

    fn params(self) -> EcDomainParams {
        // Every `Curve` has a table entry.
        ec_domain_params(self.algorithm() as u8).expect("curve table")
    }

    /// Bytes of a private scalar (= bytes of the order).
    pub fn scalar_len(self) -> usize {
        match self {
            Curve::P256 | Curve::K256 => 32,
            Curve::P384 => 48,
            Curve::P521 => 66,
        }
    }

    /// The key size field: bits of the field prime.
    fn bits(self) -> u16 {
        match self {
            Curve::P256 | Curve::K256 => 256,
            Curve::P384 => 384,
            Curve::P521 => 521,
        }
    }

    fn point_len(self) -> usize {
        1 + 2 * self.params().prime.len()
    }

    /// The curve whose prime is `p` (leading zero bytes ignored).
    fn from_prime(p: &[u8]) -> Option<Curve> {
        Curve::ALL
            .into_iter()
            .find(|c| strip(c.params().prime) == strip(p))
    }

    /// `d·G`, uncompressed.  `d` is a full-length scalar; 0 and values
    /// not below the order are refused.
    fn public(self, d: &[u8]) -> Result<Vec<u8, 133>, BlobError> {
        macro_rules! public_of {
            ($C:ty) => {{
                use elliptic_curve::sec1::ToEncodedPoint;
                let sk = elliptic_curve::SecretKey::<$C>::from_slice(d)
                    .map_err(|_| BlobError::Malformed)?;
                let mut out = Vec::new();
                out.extend_from_slice(sk.public_key().to_encoded_point(false).as_bytes())
                    .map_err(|_| BlobError::Malformed)?;
                Ok(out)
            }};
        }
        if d.len() != self.scalar_len() {
            return Err(BlobError::Malformed);
        }
        match self {
            Curve::P256 => public_of!(p256::NistP256),
            Curve::P384 => public_of!(p384::NistP384),
            Curve::P521 => public_of!(p521::NistP521),
            Curve::K256 => public_of!(k256::Secp256k1),
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding (WRAP)
// ---------------------------------------------------------------------------

/// Type code and default-algorithm OID for the header of `obj`'s blob.
pub fn classify(obj: &KeyObject) -> Result<(u8, &'static [u8]), BlobError> {
    match obj.key_type {
        KmType::Ec => match Curve::of_algorithm(obj.algorithm) {
            Some(_) => Ok((KEY_TYPE_EC, OID_ECDSA_SHA256)),
            None => Err(BlobError::Unsupported),
        },
        KmType::Rsa => Ok((KEY_TYPE_RSA_CRT, OID_RSA_V15_SHA256)),
        KmType::Aes if matches!(obj.private_key.len(), 16 | 24 | 32) => Ok((KEY_TYPE_AES, OID_AES)),
        _ => Err(BlobError::Unsupported),
    }
}

/// Append `key size (2) || material` of `obj` (the type from [`classify`]).
pub fn encode_key<const N: usize>(obj: &KeyObject, out: &mut Vec<u8, N>) -> Result<(), BlobError> {
    match obj.key_type {
        KmType::Ec => {
            let curve = Curve::of_algorithm(obj.algorithm).ok_or(BlobError::Unsupported)?;
            let d = &obj.private_key[..];
            if d.len() != curve.scalar_len() {
                return Err(BlobError::Malformed);
            }
            let pub_stored = &obj.public_key[..];
            let q = if pub_stored.len() == curve.point_len() && pub_stored[0] == 0x04 {
                let mut v: Vec<u8, 133> = Vec::new();
                v.extend_from_slice(pub_stored)
                    .map_err(|_| BlobError::Malformed)?;
                v
            } else {
                curve.public(d)?
            };
            let dp = curve.params();
            put(out, &curve.bits().to_be_bytes())?;
            for f in [dp.coeff_a, dp.coeff_b, dp.prime, dp.order, dp.base_g, d, &q] {
                put_lv(out, f)?;
            }
            Ok(())
        }
        KmType::Rsa => {
            let [n, e, _d, p, q, dp, dq, qinv] = pkcs1_fields(&obj.private_key)?;
            put(out, &bit_len(n).to_be_bytes())?;
            for f in [dp, dq, p, qinv, q, n, e] {
                put_lv(out, f)?;
            }
            Ok(())
        }
        KmType::Aes => {
            let k = &obj.private_key[..];
            if !matches!(k.len(), 16 | 24 | 32) {
                return Err(BlobError::Unsupported);
            }
            put(out, &(k.len() as u16).to_be_bytes())?;
            put(out, k)
        }
        _ => Err(BlobError::Unsupported),
    }
}

// ---------------------------------------------------------------------------
// Decoding (UNWRAP)
// ---------------------------------------------------------------------------

/// What an unwrapped key is, for the key index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    /// `KeyMeta.algo`, as GENERATE KEY PAIR / GENERATE KEY set it.
    pub meta_algo: u8,
    /// `KeyMeta.key_type`.
    pub core_type: CoreKeyType,
}

/// Decode `key size (2) || material` of a type-`key_type` blob into `obj`
/// (`key_type`, `algorithm`, `private_key`, `public_key`).  Trailing bytes
/// (the padding) are ignored: the blob is authenticated.
pub fn decode_key(key_type: u8, body: &[u8], obj: &mut KeyObject) -> Result<Decoded, BlobError> {
    let mut r = Reader { buf: body, pos: 0 };
    let size = u16::from_be_bytes(r.take(2)?.try_into().unwrap_or([0; 2]));
    match key_type {
        KEY_TYPE_EC => decode_ec(&mut r, obj),
        KEY_TYPE_RSA | KEY_TYPE_RSA_CRT => decode_rsa(key_type, &mut r, obj),
        KEY_TYPE_AES => {
            let len = size as usize;
            let (core_type, ok) = match len {
                16 => (CoreKeyType::Aes128, true),
                24 => (CoreKeyType::Aes192, true),
                32 => (CoreKeyType::Aes256, true),
                _ => (CoreKeyType::Aes256, false),
            };
            if !ok {
                return Err(BlobError::Unsupported);
            }
            set_private(obj, r.take(len)?)?;
            obj.key_type = KmType::Aes;
            obj.algorithm = AlgorithmId::AesGcm; // as GENERATE KEY stores AES
            Ok(Decoded {
                meta_algo: AlgorithmId::AesGcm as u8,
                core_type,
            })
        }
        _ => Err(BlobError::Unsupported),
    }
}

fn decode_ec(r: &mut Reader<'_>, obj: &mut KeyObject) -> Result<Decoded, BlobError> {
    let _a = r.lv()?;
    let _b = r.lv()?;
    let p = r.lv()?;
    let order = r.lv()?;
    let _g = r.lv()?;
    let d = r.lv()?;
    let q = r.lv()?;
    // The prime names the curve (as pico-hsm's ec_get_curve_from_prime);
    // the order must agree.  Brainpool, Curve25519 and anything else: no.
    let curve = Curve::from_prime(p).ok_or(BlobError::Unsupported)?;
    if strip(order) != strip(curve.params().order) {
        return Err(BlobError::Malformed);
    }
    let d = strip(d);
    let n = curve.scalar_len();
    if d.len() > n {
        return Err(BlobError::Malformed);
    }
    let mut scalar = Zeroizing::new([0u8; 66]);
    scalar[n - d.len()..n].copy_from_slice(d);
    let public = curve.public(&scalar[..n])?;
    // The blob's Q, when present, must be d·G.
    if !q.is_empty() && q != &public[..] {
        return Err(BlobError::Malformed);
    }
    set_private(obj, &scalar[..n])?;
    obj.public_key.clear();
    obj.public_key
        .extend_from_slice(&public)
        .map_err(|_| BlobError::Malformed)?;
    obj.key_type = KmType::Ec;
    obj.algorithm = curve.algorithm();
    Ok(Decoded {
        meta_algo: curve.algorithm() as u8,
        core_type: curve.core_type(),
    })
}

#[cfg(feature = "rsa")]
fn decode_rsa(key_type: u8, r: &mut Reader<'_>, obj: &mut KeyObject) -> Result<Decoded, BlobError> {
    extern crate alloc;
    use ::rsa::pkcs1::EncodeRsaPrivateKey;
    use ::rsa::traits::PublicKeyParts;
    use ::rsa::{BigUint, RsaPrivateKey};

    let big = |b: &[u8]| BigUint::from_bytes_be(b);
    let (key, n_blob) = if key_type == KEY_TYPE_RSA_CRT {
        let _dp = r.lv()?;
        let _dq = r.lv()?;
        let p = r.lv()?;
        let _qinv = r.lv()?;
        let q = r.lv()?;
        let n = r.lv()?;
        let e = r.lv()?;
        check_rsa_sizes(n, e)?;
        let key =
            RsaPrivateKey::from_p_q(big(p), big(q), big(e)).map_err(|_| BlobError::Malformed)?;
        (key, n)
    } else {
        let d = r.lv()?;
        let n = r.lv()?;
        let e = r.lv()?;
        check_rsa_sizes(n, e)?;
        let key = RsaPrivateKey::from_components(big(n), big(e), big(d), alloc::vec::Vec::new())
            .map_err(|_| BlobError::Malformed)?;
        (key, n)
    };
    key.validate().map_err(|_| BlobError::Malformed)?;
    let n = key.n().to_bytes_be();
    if n[..] != *strip(n_blob) {
        return Err(BlobError::Malformed);
    }
    let e = key.e().to_bytes_be();
    let der = key.to_pkcs1_der().map_err(|_| BlobError::Malformed)?;
    set_private(obj, der.as_bytes())?;
    // As GENERATE KEY PAIR stores it: [2-byte modulus length] || n || e.
    obj.public_key.clear();
    put(&mut obj.public_key, &(n.len() as u16).to_be_bytes())?;
    put(&mut obj.public_key, &n)?;
    put(&mut obj.public_key, &e)?;
    obj.key_type = KmType::Rsa;
    obj.algorithm = AlgorithmId::RsaDecrypt;
    let bits = bit_len(&n);
    let (meta_algo, core_type) = if bits <= 2048 {
        (0x05, CoreKeyType::RsaPrivate2048)
    } else if bits <= 3072 {
        (0x06, CoreKeyType::RsaPrivate3072)
    } else {
        (0x07, CoreKeyType::RsaPrivate4096)
    };
    Ok(Decoded {
        meta_algo,
        core_type,
    })
}

#[cfg(feature = "rsa")]
fn check_rsa_sizes(n: &[u8], e: &[u8]) -> Result<(), BlobError> {
    // 1024..=4096-bit moduli, as the RSA code handles; e up to 32 bits.
    if !(1024..=4096).contains(&bit_len(n)) || strip(e).len() > 4 {
        return Err(BlobError::Unsupported);
    }
    Ok(())
}

#[cfg(not(feature = "rsa"))]
fn decode_rsa(_: u8, _: &mut Reader<'_>, _: &mut KeyObject) -> Result<Decoded, BlobError> {
    Err(BlobError::Unsupported)
}

/// Map the content of a pico2hsm version-2/3 blob (`key material`,
/// `algo`, as the previous firmware stored them) onto `obj` — the
/// acceptance rules of the previous UNWRAP, unchanged.  Deprecated with
/// the format; removed in the next release.
pub fn decode_legacy(material: &[u8], algo: u8, obj: &mut KeyObject) -> Result<Decoded, BlobError> {
    let len_ok = match algo {
        0x13 | 0x23 | 0x19 | 0x53 | 0x20 | 0x21 => material.len() == 32,
        0x15 | 0x25 | 0x54 => material.len() == 48,
        0x55 => material.len() == 64,
        0x17 | 0x27 => material.len() == 66,
        0x60..=0x63 => matches!(material.len(), 16 | 24 | 32),
        0x31..=0x34 | 0x41 => (64..=2400).contains(&material.len()),
        _ => false,
    };
    let algorithm = AlgorithmId::from_u8(algo).ok_or(BlobError::Unsupported)?;
    if !len_ok {
        return Err(BlobError::Malformed);
    }
    let (key_type, core_type) = match algo {
        0x13 | 0x23 => (KmType::Ec, CoreKeyType::EcPrivateP256),
        0x15 | 0x25 => (KmType::Ec, CoreKeyType::EcPrivateP384),
        0x17 | 0x27 => (KmType::Ec, CoreKeyType::EcPrivateP521),
        0x19 => (KmType::Ec, CoreKeyType::EcPrivateK256),
        0x53 => (KmType::Ec, CoreKeyType::EcPrivateBrainpoolP256),
        0x54 => (KmType::Ec, CoreKeyType::EcPrivateBrainpoolP384),
        0x55 => (KmType::Ec, CoreKeyType::EcPrivateBrainpoolP512),
        0x20 => (KmType::Ec, CoreKeyType::Ed25519),
        0x21 => (KmType::Ec, CoreKeyType::X25519),
        0x31..=0x34 | 0x41 => (KmType::Rsa, CoreKeyType::RsaPrivate2048),
        _ => (KmType::Aes, CoreKeyType::Aes256),
    };
    set_private(obj, material)?;
    obj.public_key.clear();
    if let Some(curve) = Curve::of_algorithm(algorithm) {
        // Fill in the public key the old format did not carry.
        let q = curve.public(material)?;
        put(&mut obj.public_key, &q)?;
    }
    obj.key_type = key_type;
    obj.algorithm = algorithm;
    Ok(Decoded {
        meta_algo: algo,
        core_type,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], BlobError> {
        let end = self.pos.checked_add(n).ok_or(BlobError::Malformed)?;
        let s = self.buf.get(self.pos..end).ok_or(BlobError::Malformed)?;
        self.pos = end;
        Ok(s)
    }

    fn lv(&mut self) -> Result<&'a [u8], BlobError> {
        let l = self.take(2)?;
        self.take(u16::from_be_bytes([l[0], l[1]]) as usize)
    }
}

/// Split a header `LV(..)` off the front of `buf`: `(value, rest)`.
pub fn split_lv(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut r = Reader { buf, pos: 0 };
    let v = r.lv().ok()?;
    Some((v, &buf[r.pos..]))
}

fn put<const N: usize>(out: &mut Vec<u8, N>, b: &[u8]) -> Result<(), BlobError> {
    out.extend_from_slice(b).map_err(|_| BlobError::Malformed)
}

/// Append `LV(b)`.
pub fn put_lv<const N: usize>(out: &mut Vec<u8, N>, b: &[u8]) -> Result<(), BlobError> {
    let len = u16::try_from(b.len()).map_err(|_| BlobError::Malformed)?;
    put(out, &len.to_be_bytes())?;
    put(out, b)
}

fn set_private(obj: &mut KeyObject, b: &[u8]) -> Result<(), BlobError> {
    use zeroize::Zeroize;
    obj.private_key.as_mut_slice().zeroize();
    obj.private_key.clear();
    put(&mut obj.private_key, b)
}

/// Drop leading zero bytes (big-endian integers of any encoding length).
fn strip(b: &[u8]) -> &[u8] {
    let z = b.iter().take_while(|&&x| x == 0).count();
    &b[z..]
}

fn bit_len(b: &[u8]) -> u16 {
    let b = strip(b);
    match b.first() {
        None => 0,
        Some(&top) => (b.len() * 8 - top.leading_zeros() as usize) as u16,
    }
}

/// The integers of a PKCS#1 `RSAPrivateKey` (version 0, two primes):
/// `[n, e, d, p, q, dP, dQ, qInv]`, leading zero bytes removed.
fn pkcs1_fields(der: &[u8]) -> Result<[&[u8]; 8], BlobError> {
    fn header(b: &[u8], tag: u8) -> Result<(&[u8], &[u8]), BlobError> {
        let (&t, rest) = b.split_first().ok_or(BlobError::Malformed)?;
        let (&l0, rest) = rest.split_first().ok_or(BlobError::Malformed)?;
        if t != tag {
            return Err(BlobError::Malformed);
        }
        let (len, rest) = match l0 {
            0..=0x7F => (l0 as usize, rest),
            0x81 => (
                *rest.first().ok_or(BlobError::Malformed)? as usize,
                &rest[1..],
            ),
            0x82 => {
                let l = rest.get(..2).ok_or(BlobError::Malformed)?;
                (((l[0] as usize) << 8) | l[1] as usize, &rest[2..])
            }
            _ => return Err(BlobError::Malformed),
        };
        if rest.len() < len {
            return Err(BlobError::Malformed);
        }
        Ok(rest.split_at(len))
    }
    let (mut body, _) = header(der, 0x30)?;
    let (version, rest) = header(body, 0x02)?;
    if version != [0] {
        return Err(BlobError::Unsupported); // multi-prime
    }
    body = rest;
    let mut out: [&[u8]; 8] = [&[]; 8];
    for f in out.iter_mut() {
        let (v, rest) = header(body, 0x02)?;
        *f = strip(v);
        body = rest;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico2hsm_core::key::AppletId;

    fn ec_obj(algo: AlgorithmId, d: &[u8]) -> KeyObject {
        let mut o = KeyObject::new(KmType::Ec, 1, AppletId::ScHsm, algo);
        o.private_key.extend_from_slice(d).unwrap();
        o
    }

    #[test]
    fn ec_round_trip_every_curve() {
        for (algo, len) in [
            (AlgorithmId::EcdsaP256, 32),
            (AlgorithmId::EcdhP384, 48),
            (AlgorithmId::EcdsaP521, 66),
            (AlgorithmId::EcdsaK256, 32),
        ] {
            let mut d = [0u8; 66];
            d[len - 1] = 7;
            let obj = ec_obj(algo, &d[..len]);
            let mut body: Vec<u8, 1024> = Vec::new();
            encode_key(&obj, &mut body).unwrap();
            let mut back = KeyObject::new(KmType::Generic, 1, AppletId::ScHsm, algo);
            let dec = decode_key(KEY_TYPE_EC, &body, &mut back).unwrap();
            assert_eq!(&back.private_key[..], &d[..len]);
            assert_eq!(back.public_key[0], 0x04);
            assert_eq!(
                dec.meta_algo,
                Curve::of_algorithm(algo).unwrap().algorithm() as u8
            );
        }
    }

    #[test]
    fn unsupported_keys_are_refused() {
        for algo in [
            AlgorithmId::Ed25519,
            AlgorithmId::X25519,
            AlgorithmId::EcdsaBrainpool256,
        ] {
            let obj = ec_obj(algo, &[1u8; 32]);
            assert_eq!(classify(&obj), Err(BlobError::Unsupported));
        }
        let obj = KeyObject::new(KmType::Generic, 1, AppletId::ScHsm, AlgorithmId::AesGcm);
        assert_eq!(classify(&obj), Err(BlobError::Unsupported));
    }

    #[test]
    fn ec_scalar_out_of_range_refused() {
        // d = 0 and d = order are not keys.
        for d in [[0u8; 32], {
            let mut o = [0u8; 32];
            o.copy_from_slice(crate::crypto::ec_params::P256_ORDER);
            o
        }] {
            assert_eq!(Curve::P256.public(&d), Err(BlobError::Malformed));
        }
    }

    #[test]
    fn policy_fields_round_trip() {
        let mut p = KeyPolicy::default();
        p.algorithms.extend_from_slice(&[0x73, 0x92]).unwrap();
        let mut out: Vec<u8, 64> = Vec::new();
        write_policy_fields(&p, 0x03, &mut out).unwrap();
        assert_eq!(&out[..], &[0, 2, 0x73, 0x92, 0, 1, 0x03]);
        let (algs, rest) = split_lv(&out).unwrap();
        let (ac, rest) = split_lv(rest).unwrap();
        assert!(rest.is_empty());
        assert_eq!(read_policy_fields(algs, ac).unwrap(), (p, 0x03));
        // No list, no flags: two empty fields, as a SmartCard-HSM writes.
        let mut out: Vec<u8, 64> = Vec::new();
        write_policy_fields(&KeyPolicy::default(), 0, &mut out).unwrap();
        assert_eq!(&out[..], &[0, 0, 0, 0]);
        // Foreign access conditions carry no flags; too long a list is refused.
        assert_eq!(read_policy_fields(&[], &[1, 2]).unwrap().1, 0);
        assert!(read_policy_fields(&[0x70; MAX_ALGORITHMS + 1], &[]).is_err());
    }
}
