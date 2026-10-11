//! The domain signing key (cluster plan V3 §4.1).
//!
//! Every member derives the same P-256 key from the DKEK, so any member can
//! sign for the domain and anyone holding `Q_domain` can verify:
//!
//! ```text
//! okm       = HKDF-SHA256(ikm = DKEK, salt = "pico2hsm-domain-v1",
//!                         info = "sign", L = 48)
//! d_domain  = OS2IP(okm) mod n          (n = P-256 group order; 0 refused)
//! Q_domain  = d_domain · G              (65-byte uncompressed SEC1)
//! domain_id = SHA-256(Q_domain)[0..16]
//! ```
//!
//! Reducing 48 bytes (384 bits) mod the 256-bit order is the
//! `hash_to_field` reduction of RFC 9380 §5.2 (L = 48 for P-256, k = 128)
//! with HKDF-Expand as the expander: the bias is below 2^-128 and no retry
//! loop is needed, so every member gets the same key.  `d = 0` has
//! probability 2^-256 and is refused rather than remapped.
//!
//! The private scalar lives only in RAM (`Zeroizing`), is re-derived after
//! each boot and whenever the DKEK is completed, and is never exported.
//! The independent Python reference is `tools/python/pico2hsm/domain.py`;
//! `firmware/tests/domain_vectors.rs` checks this code against its vectors.

use elliptic_curve::ops::Reduce;
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{FieldBytes, NonZeroScalar, Scalar, U256};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// HKDF salt of the domain key derivation.
pub const DOMAIN_SALT: &[u8] = b"pico2hsm-domain-v1";
/// HKDF info of the domain signing key.
pub const DOMAIN_INFO_SIGN: &[u8] = b"sign";
/// Bytes of HKDF output reduced to the scalar (RFC 9380 `L` for P-256).
pub const OKM_LEN: usize = 48;
/// Length of a `domain_id`.
pub const DOMAIN_ID_LEN: usize = 16;

/// `SHA-256(Q)[0..16]`.
pub fn domain_id(q: &[u8; 65]) -> [u8; DOMAIN_ID_LEN] {
    let h = Sha256::digest(q);
    let mut id = [0u8; DOMAIN_ID_LEN];
    id.copy_from_slice(&h[..DOMAIN_ID_LEN]);
    id
}

/// `OS2IP(okm) mod n` for a 48-byte `okm`: `hi · 2^256 + lo` with `hi` the
/// first 16 bytes and `lo` the last 32.
fn reduce_okm(okm: &[u8; OKM_LEN]) -> Scalar {
    let mut hi = FieldBytes::default();
    hi[16..].copy_from_slice(&okm[..16]);
    let mut lo = FieldBytes::default();
    lo.copy_from_slice(&okm[16..]);
    // 2^256 mod n = (2^256 - 1 mod n) + 1.
    let two_256 = <Scalar as Reduce<U256>>::reduce(U256::MAX) + Scalar::ONE;
    let hi = <Scalar as Reduce<U256>>::reduce_bytes(&hi);
    let lo = <Scalar as Reduce<U256>>::reduce_bytes(&lo);
    hi * two_256 + lo
}

/// The derived domain key pair.  The private scalar is wiped on drop.
pub struct DomainKey {
    d: Zeroizing<[u8; 32]>,
    /// `Q_domain`, uncompressed SEC1 (`04 || x || y`).
    pub q: [u8; 65],
    /// `SHA-256(Q_domain)[0..16]`.
    pub id: [u8; DOMAIN_ID_LEN],
}

impl DomainKey {
    /// Derive the domain key from the DKEK (see the module docs).
    pub fn derive(dkek: &[u8; 32]) -> Result<Self, ()> {
        let mut okm = Zeroizing::new([0u8; OKM_LEN]);
        Hkdf::<Sha256>::new(Some(DOMAIN_SALT), dkek)
            .expand(DOMAIN_INFO_SIGN, okm.as_mut())
            .map_err(|_| ())?;
        let scalar = reduce_okm(&okm);
        let nz = Option::<NonZeroScalar>::from(NonZeroScalar::new(scalar)).ok_or(())?;
        let mut d = Zeroizing::new([0u8; 32]);
        d.copy_from_slice(&nz.to_bytes());
        let public = p256::PublicKey::from_secret_scalar(&nz);
        let encoded = public.to_encoded_point(false);
        let mut q = [0u8; 65];
        q.copy_from_slice(encoded.as_bytes());
        Ok(DomainKey {
            d,
            q,
            id: domain_id(&q),
        })
    }

    /// ECDSA-P256 (RFC 6979 deterministic) over a SHA-256 digest; `r || s`.
    pub fn sign_prehash(&self, digest: &[u8; 32]) -> Result<[u8; 64], ()> {
        use ecdsa::signature::hazmat::PrehashSigner;
        let sk = p256::ecdsa::SigningKey::from_slice(self.d.as_ref()).map_err(|_| ())?;
        let sig: p256::ecdsa::Signature = sk.sign_prehash(digest).map_err(|_| ())?;
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.to_bytes());
        Ok(out)
    }
}

/// Verify an `r || s` ECDSA-P256 signature over a SHA-256 digest.
pub fn verify_prehash(q: &[u8; 65], digest: &[u8; 32], sig: &[u8; 64]) -> bool {
    use ecdsa::signature::hazmat::PrehashVerifier;
    let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(q) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(sig) else {
        return false;
    };
    vk.verify_prehash(digest, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_dkek_bound() {
        let a = DomainKey::derive(&[0x11; 32]).unwrap();
        let b = DomainKey::derive(&[0x11; 32]).unwrap();
        let c = DomainKey::derive(&[0x12; 32]).unwrap();
        assert_eq!(a.q, b.q);
        assert_eq!(a.id, b.id);
        assert_ne!(a.id, c.id);
        assert_eq!(a.id, domain_id(&a.q));
        assert_eq!(a.q[0], 0x04);
    }

    #[test]
    fn reduction_matches_big_integer_arithmetic() {
        // okm = 2^256 (hi = 1, lo = 0)  ->  2^256 mod n.
        let mut okm = [0u8; OKM_LEN];
        okm[15] = 1;
        let r = reduce_okm(&okm);
        // 2^256 mod n for P-256 (n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551).
        let expect =
            hex_literal("00000000FFFFFFFF00000000000000004319055258E8617B0C46353D039CDAAF");
        assert_eq!(r.to_bytes().as_slice(), &expect[..]);
    }

    fn hex_literal(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn signatures_verify_under_q() {
        let k = DomainKey::derive(&[0x42; 32]).unwrap();
        let digest = [0x5A; 32];
        let sig = k.sign_prehash(&digest).unwrap();
        assert_eq!(sig, k.sign_prehash(&digest).unwrap(), "RFC 6979");
        assert!(verify_prehash(&k.q, &digest, &sig));
        let mut bad = sig;
        bad[10] ^= 1;
        assert!(!verify_prehash(&k.q, &digest, &bad));
    }
}
