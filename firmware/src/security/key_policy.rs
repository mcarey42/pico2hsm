//! Per-key usage policy (audit S-10).
//!
//! # SmartCard-HSM (CardContact)
//! GENERATE ASYMMETRIC KEY PAIR, GENERATE SYMMETRIC KEY and UNWRAP KEY
//! create a key with optional attributes appended to the command data:
//!
//! | Tag  | Length | Meaning                                                 |
//! |------|--------|---------------------------------------------------------|
//! | `90` | 4      | key use counter: uses left, big-endian; 0 = unusable    |
//! | `91` | 1..n   | algorithm list: the algorithm IDs (the P2 of SIGN /     |
//! |      |        | DECIPHER / CIPHER, `92` for WRAP) the key may be used   |
//! |      |        | with                                                    |
//! | `92` | 1      | key domain                                              |
//!
//! A key created without `91` may be used with every algorithm valid for
//! its type; without `90` it has no use limit.  Both are what a key
//! generated before this module existed gets.  The card reports them in the
//! proprietary part (`A5`) of the FCP returned by SELECT of the key file
//! `CC <key ref>`: `90 04 <uses left | FFFFFFFF>`, `91 <list>`, `92 01 <dom>`.
//!
//! # PIV (Yubico extension)
//! `AA` (PIN policy) and `AB` (touch policy) in the GENERATE `AC` template.
//!
//! # Storage
//! The policy travels inside the encrypted part of the stored key object
//! (see `key_management`, magic `P2KP`) and inside DKEK-wrapped keys (wrap
//! format version 3, see `dkek`), as the same `A5` TLV:
//! `A5 L { [90 04 n] [91 k a..] [92 01 d] [AA 01 p] [AB 01 t] }`.

use pico2hsm_core::apdu::{SW_CONDITIONS_NOT_SATISFIED, SW_MEMORY_FAILURE, SW_WRONG_DATA};

use crate::security::key_management::KeyObject;
use crate::storage::KeyStore;

// ---------------------------------------------------------------------------
// SmartCard-HSM algorithm identifiers (CardContact; OpenSC card-sc-hsm.h)
// ---------------------------------------------------------------------------

/// RSA signature, input already padded.
pub const ALGO_RSA_RAW: u8 = 0x20;
/// RSA raw decryption.
pub const ALGO_RSA_DECRYPT: u8 = 0x21;
/// RSA decryption, PKCS#1 v1.5 padding removed by the card.
pub const ALGO_RSA_DECRYPT_PKCS1: u8 = 0x22;
/// RSA decryption, OAEP padding removed by the card.
pub const ALGO_RSA_DECRYPT_OEP: u8 = 0x23;
/// RSA PKCS#1 v1.5 signature, DigestInfo input.
pub const ALGO_RSA_PKCS1: u8 = 0x30;
/// RSA PKCS#1 v1.5 signature with SHA-1 hashed by the card.
pub const ALGO_RSA_PKCS1_SHA1: u8 = 0x31;
/// ... SHA-224.
pub const ALGO_RSA_PKCS1_SHA224: u8 = 0x32;
/// ... SHA-256.
pub const ALGO_RSA_PKCS1_SHA256: u8 = 0x33;
/// ... SHA-384.
pub const ALGO_RSA_PKCS1_SHA384: u8 = 0x34;
/// ... SHA-512.
pub const ALGO_RSA_PKCS1_SHA512: u8 = 0x35;
/// RSA-PSS signature, hash input.
pub const ALGO_RSA_PSS: u8 = 0x40;
/// ECDSA, hash input.
pub const ALGO_EC_RAW: u8 = 0x70;
/// ECDSA with SHA-1 hashed by the card.
pub const ALGO_EC_SHA1: u8 = 0x71;
/// ... SHA-224.
pub const ALGO_EC_SHA224: u8 = 0x72;
/// ... SHA-256.
pub const ALGO_EC_SHA256: u8 = 0x73;
/// ... SHA-384.
pub const ALGO_EC_SHA384: u8 = 0x74;
/// ... SHA-512.
pub const ALGO_EC_SHA512: u8 = 0x75;
/// ECDH key agreement (DECIPHER).
pub const ALGO_EC_DH: u8 = 0x80;
/// WRAP KEY (export under the DKEK).
pub const ALGO_WRAP: u8 = 0x92;
/// UNWRAP KEY.
pub const ALGO_UNWRAP: u8 = 0x93;
/// DERIVE EC KEY.
pub const ALGO_EC_DERIVE: u8 = 0x98;
/// AES-CBC encrypt.
pub const ALGO_AES_CBC_ENCRYPT: u8 = 0x10;
/// AES-CBC decrypt.
pub const ALGO_AES_CBC_DECRYPT: u8 = 0x11;
/// AES-CMAC.
pub const ALGO_AES_CMAC: u8 = 0x18;
/// AES key derivation.
pub const ALGO_AES_DERIVE: u8 = 0x99;

// ---------------------------------------------------------------------------
// Tags and limits
// ---------------------------------------------------------------------------

/// Key use counter.
pub const TAG_USE_COUNTER: u8 = 0x90;
/// Algorithm list.
pub const TAG_ALGORITHMS: u8 = 0x91;
/// Key domain.
pub const TAG_DOMAIN: u8 = 0x92;
/// PIV PIN policy (Yubico).
pub const TAG_PIN_POLICY: u8 = 0xAA;
/// PIV touch policy (Yubico).
pub const TAG_TOUCH_POLICY: u8 = 0xAB;
/// Container of the stored policy (as in the FCP's proprietary part).
pub const TAG_POLICY: u8 = 0xA5;

/// Most algorithm IDs one key may list (CardContact defines fewer).
pub const MAX_ALGORITHMS: usize = 32;

/// Largest encoded policy: `A5 L` + 90(6) + 91(2+32) + 92(3) + AA(3) + AB(3).
pub const MAX_POLICY_EXT: usize = 2 + 6 + 2 + MAX_ALGORITHMS + 3 + 3 + 3;

/// What the card reports in tag 90 for a key without a use counter.
pub const NO_USE_COUNTER: u32 = 0xFFFF_FFFF;

/// The key's use counter has run out (SmartCard-HSM: "file full").
pub const SW_KEY_EXHAUSTED: u16 = 0x6A84;
/// The key domain does not exist (only domain 0 does).
pub const SW_REFERENCE_NOT_FOUND: u16 = 0x6A88;

/// PIV PIN policies (Yubico values).
pub mod pin_policy {
    /// The slot's SP 800-73-4 default.
    pub const DEFAULT: u8 = 0x00;
    /// No PIN needed.
    pub const NEVER: u8 = 0x01;
    /// PIN once per session.
    pub const ONCE: u8 = 0x02;
    /// PIN right before every use.
    pub const ALWAYS: u8 = 0x03;
}

/// PIV touch policies (Yubico values).  Without a button only "default"
/// and "never" can be honoured.
pub mod touch_policy {
    /// The slot default (never, on this device).
    pub const DEFAULT: u8 = 0x00;
    /// No touch.
    pub const NEVER: u8 = 0x01;
}

// ---------------------------------------------------------------------------
// KeyPolicy
// ---------------------------------------------------------------------------

/// Usage policy of one stored key.  `Default` is "no restriction".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyPolicy {
    /// Uses left (tag 90); `None` = no limit.
    pub use_counter: Option<u32>,
    /// Allowed algorithm IDs (tag 91); empty = every algorithm valid for
    /// the key type.
    pub algorithms: heapless::Vec<u8, MAX_ALGORITHMS>,
    /// Key domain (tag 92), if one was given.
    pub domain: Option<u8>,
    /// PIV PIN policy (`pin_policy::*`).
    pub pin_policy: u8,
    /// PIV touch policy (`touch_policy::*`).
    pub touch_policy: u8,
}

impl KeyPolicy {
    /// No restriction of any kind: what a legacy key gets.
    pub fn is_unrestricted(&self) -> bool {
        *self == Self::default()
    }

    /// Whether algorithm `algo` is allowed (tag 91; no list = any).
    pub fn allows(&self, algo: u8) -> bool {
        self.algorithms.is_empty() || self.algorithms.contains(&algo)
    }

    /// Parse the CardContact key attributes (tags 90/91/92) among the
    /// top-level TLVs of a key-creation command.  Other tags are left to
    /// the caller.  Malformed TLV structure or attribute values: 6A80; a
    /// key domain that does not exist: 6A88.
    pub fn from_creation_tlvs(data: &[u8]) -> Result<Self, u16> {
        let mut p = KeyPolicy::default();
        let mut seen = [false; 3];
        for_each_tlv(data, |tag, value| {
            let idx = match tag {
                0x90 => 0,
                0x91 => 1,
                0x92 => 2,
                _ => return Ok(()),
            };
            if core::mem::replace(&mut seen[idx], true) {
                return Err(SW_WRONG_DATA);
            }
            p.set_attribute(tag as u8, value)?;
            if let Some(d) = p.domain {
                if d != 0 {
                    // One DKEK, one key domain (0).
                    return Err(SW_REFERENCE_NOT_FOUND);
                }
            }
            Ok(())
        })?;
        Ok(p)
    }

    /// Set one attribute from its TLV value.
    fn set_attribute(&mut self, tag: u8, value: &[u8]) -> Result<(), u16> {
        match tag {
            TAG_USE_COUNTER => {
                let v: [u8; 4] = value.try_into().map_err(|_| SW_WRONG_DATA)?;
                self.use_counter = Some(u32::from_be_bytes(v));
            }
            TAG_ALGORITHMS => {
                // An empty list is no list (as the reference firmware does).
                self.algorithms.clear();
                self.algorithms
                    .extend_from_slice(value)
                    .map_err(|_| SW_WRONG_DATA)?;
            }
            TAG_DOMAIN => match value {
                [d] => self.domain = Some(*d),
                _ => return Err(SW_WRONG_DATA),
            },
            TAG_PIN_POLICY => match value {
                [p @ pin_policy::DEFAULT..=pin_policy::ALWAYS] => self.pin_policy = *p,
                _ => return Err(SW_WRONG_DATA),
            },
            TAG_TOUCH_POLICY => match value {
                [t @ (touch_policy::DEFAULT | touch_policy::NEVER)] => self.touch_policy = *t,
                _ => return Err(SW_WRONG_DATA),
            },
            _ => return Err(SW_WRONG_DATA),
        }
        Ok(())
    }

    /// Append the stored form `A5 L {...}`; nothing for an unrestricted key.
    pub fn encode<const N: usize>(&self, out: &mut heapless::Vec<u8, N>) -> Result<(), ()> {
        if self.is_unrestricted() {
            return Ok(());
        }
        let mut body: heapless::Vec<u8, MAX_POLICY_EXT> = heapless::Vec::new();
        if let Some(n) = self.use_counter {
            put(&mut body, &[TAG_USE_COUNTER, 4])?;
            put(&mut body, &n.to_be_bytes())?;
        }
        self.encode_list_and_domain(&mut body)?;
        if self.pin_policy != 0 {
            put(&mut body, &[TAG_PIN_POLICY, 1, self.pin_policy])?;
        }
        if self.touch_policy != 0 {
            put(&mut body, &[TAG_TOUCH_POLICY, 1, self.touch_policy])?;
        }
        put(out, &[TAG_POLICY, body.len() as u8])?;
        put(out, &body)
    }

    fn encode_list_and_domain<const N: usize>(
        &self,
        out: &mut heapless::Vec<u8, N>,
    ) -> Result<(), ()> {
        if !self.algorithms.is_empty() {
            put(out, &[TAG_ALGORITHMS, self.algorithms.len() as u8])?;
            put(out, &self.algorithms)?;
        }
        if let Some(d) = self.domain {
            put(out, &[TAG_DOMAIN, 1, d])?;
        }
        Ok(())
    }

    /// Parse the stored form written by [`KeyPolicy::encode`].  Anything
    /// else (unknown or repeated tags, bad lengths) is an error: the bytes
    /// are authenticated, so this only fails on a format mismatch, and a
    /// policy that can't be read must not turn into "no restriction".
    pub fn decode(stored: &[u8]) -> Result<Self, ()> {
        let mut p = KeyPolicy::default();
        if stored.is_empty() {
            return Ok(p);
        }
        let [TAG_POLICY, len, body @ ..] = stored else {
            return Err(());
        };
        if *len as usize != body.len() {
            return Err(());
        }
        let mut seen = 0u8;
        for_each_tlv(body, |tag, value| {
            let bit = match tag {
                0x90 => 1,
                0x91 => 2,
                0x92 => 4,
                0xAA => 8,
                0xAB => 16,
                _ => return Err(SW_WRONG_DATA),
            };
            if seen & bit != 0 || (tag == 0x91 && value.is_empty()) {
                return Err(SW_WRONG_DATA);
            }
            seen |= bit;
            p.set_attribute(tag as u8, value)
        })
        .map_err(|_| ())?;
        if p.is_unrestricted() {
            // `encode` never writes an empty container.
            return Err(());
        }
        Ok(p)
    }

    /// The proprietary part of the key file's FCP, as a SmartCard-HSM
    /// reports it: `A5 L { 90 04 <uses left|FFFFFFFF> [91 ..] [92 01 ..] }`.
    pub fn encode_fcp<const N: usize>(&self, out: &mut heapless::Vec<u8, N>) -> Result<(), ()> {
        let mut body: heapless::Vec<u8, MAX_POLICY_EXT> = heapless::Vec::new();
        put(&mut body, &[TAG_USE_COUNTER, 4])?;
        put(
            &mut body,
            &self.use_counter.unwrap_or(NO_USE_COUNTER).to_be_bytes(),
        )?;
        self.encode_list_and_domain(&mut body)?;
        put(out, &[TAG_POLICY, body.len() as u8])?;
        put(out, &body)
    }
}

/// Append `bytes`, failing (instead of truncating) when they don't fit.
fn put<const N: usize>(out: &mut heapless::Vec<u8, N>, bytes: &[u8]) -> Result<(), ()> {
    out.extend_from_slice(bytes).map_err(|_| ())
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

/// Check `obj`'s policy for one use with algorithm `algo` and, for a key
/// with a use counter, spend the use on flash before the caller computes
/// anything.
///
/// `algo` is the SmartCard-HSM algorithm ID of the operation, or `None`
/// for a pico2hsm operation the CardContact list has no ID for: those are
/// allowed only on keys without an algorithm list.
///
/// Call it once per operation, after every check that can refuse the
/// request without using the key (so a malformed APDU never costs a use),
/// and immediately before the private-key operation.  The decremented
/// counter is written first, like a retry counter
/// (`with_persisted_attempt`): cutting power once the result is known
/// cannot give the use back, and a result never leaves the device without
/// its use on flash.  If the write fails the use is refused (6581) and
/// `obj` keeps its old count.
///
/// Errors: 6A84 counter exhausted, 6985 algorithm not allowed, 6581 storage.
pub fn authorize_use(
    store: &mut dyn KeyStore,
    obj: &mut KeyObject,
    algo: Option<u8>,
) -> Result<(), u16> {
    if obj.policy.use_counter == Some(0) {
        return Err(SW_KEY_EXHAUSTED);
    }
    let allowed = match algo {
        Some(a) => obj.policy.allows(a),
        None => obj.policy.algorithms.is_empty(),
    };
    if !allowed {
        return Err(SW_CONDITIONS_NOT_SATISFIED);
    }
    if let Some(n) = obj.policy.use_counter {
        obj.policy.use_counter = Some(n - 1);
        if store.save_key(obj).is_err() {
            obj.policy.use_counter = Some(n);
            return Err(SW_MEMORY_FAILURE);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// BER-TLV walker
// ---------------------------------------------------------------------------

/// Call `f(tag, value)` for every top-level BER-TLV in `data`.
///
/// Tags of one or two bytes (two-byte tags as `0x5F29`); lengths in short
/// form or `81 xx` / `82 xx xx`.  A structure that does not parse to the
/// end is an error (6A80): a key attribute after a field the walker could
/// not skip must never be silently dropped.
pub fn for_each_tlv(
    data: &[u8],
    mut f: impl FnMut(u16, &[u8]) -> Result<(), u16>,
) -> Result<(), u16> {
    let mut i = 0usize;
    while i < data.len() {
        let mut tag = u16::from(data[i]);
        i += 1;
        if tag & 0x1F == 0x1F {
            let b = *data.get(i).ok_or(SW_WRONG_DATA)?;
            if b & 0x80 != 0 {
                return Err(SW_WRONG_DATA); // three-byte tags: not used here
            }
            tag = (tag << 8) | u16::from(b);
            i += 1;
        }
        let first = *data.get(i).ok_or(SW_WRONG_DATA)?;
        i += 1;
        let len = match first {
            0x00..=0x7F => usize::from(first),
            0x81 => {
                let l = *data.get(i).ok_or(SW_WRONG_DATA)?;
                i += 1;
                usize::from(l)
            }
            0x82 => {
                let hi = *data.get(i).ok_or(SW_WRONG_DATA)?;
                let lo = *data.get(i + 1).ok_or(SW_WRONG_DATA)?;
                i += 2;
                usize::from(u16::from_be_bytes([hi, lo]))
            }
            _ => return Err(SW_WRONG_DATA),
        };
        let end = i.checked_add(len).ok_or(SW_WRONG_DATA)?;
        let value = data.get(i..end).ok_or(SW_WRONG_DATA)?;
        f(tag, value)?;
        i = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(counter: Option<u32>, algos: &[u8]) -> KeyPolicy {
        let mut p = KeyPolicy {
            use_counter: counter,
            ..KeyPolicy::default()
        };
        p.algorithms.extend_from_slice(algos).unwrap();
        p
    }

    #[test]
    fn absent_list_allows_everything() {
        let p = KeyPolicy::default();
        assert!(p.is_unrestricted());
        for a in 0..=255u8 {
            assert!(p.allows(a));
        }
    }

    #[test]
    fn list_allows_only_listed_ids() {
        let p = policy(None, &[ALGO_EC_SHA256, ALGO_WRAP]);
        assert!(p.allows(ALGO_EC_SHA256));
        assert!(p.allows(ALGO_WRAP));
        assert!(!p.allows(ALGO_EC_RAW));
        assert!(!p.allows(ALGO_EC_DH));
    }

    #[test]
    fn creation_tlvs_after_a_long_7f49_are_found() {
        // OpenSC GAKP for P-521: the 7F49 block needs a 2-byte length.
        let mut d: heapless::Vec<u8, 600> = heapless::Vec::new();
        d.extend_from_slice(&[0x5F, 0x29, 0x01, 0x00]).unwrap();
        d.extend_from_slice(&[0x7F, 0x49, 0x82, 0x01, 0x10])
            .unwrap();
        d.extend_from_slice(&[0xAB; 0x110]).unwrap();
        d.extend_from_slice(&[0x5F, 0x20, 0x02, b'X', b'Y'])
            .unwrap();
        d.extend_from_slice(&[0x90, 0x04, 0, 0, 0, 7]).unwrap();
        d.extend_from_slice(&[0x91, 0x02, 0x73, 0x92]).unwrap();
        d.extend_from_slice(&[0x92, 0x01, 0x00]).unwrap();
        let p = KeyPolicy::from_creation_tlvs(&d).unwrap();
        assert_eq!(p.use_counter, Some(7));
        assert_eq!(&p.algorithms[..], &[0x73, 0x92]);
        assert_eq!(p.domain, Some(0));
    }

    #[test]
    fn creation_tlv_errors() {
        // Truncated structure: refused, never "no policy".
        assert_eq!(
            KeyPolicy::from_creation_tlvs(&[0x90, 0x04, 0, 0]),
            Err(SW_WRONG_DATA)
        );
        // Counter must be 4 bytes.
        assert_eq!(
            KeyPolicy::from_creation_tlvs(&[0x90, 0x02, 0, 1]),
            Err(SW_WRONG_DATA)
        );
        // Repeated attribute.
        assert_eq!(
            KeyPolicy::from_creation_tlvs(&[0x91, 0x01, 0x73, 0x91, 0x01, 0x70]),
            Err(SW_WRONG_DATA)
        );
        // Unknown key domain.
        assert_eq!(
            KeyPolicy::from_creation_tlvs(&[0x92, 0x01, 0x01]),
            Err(SW_REFERENCE_NOT_FOUND)
        );
        // Too long a list.
        let mut d = [0x73u8; 2 + MAX_ALGORITHMS + 1];
        d[0] = 0x91;
        d[1] = (MAX_ALGORITHMS + 1) as u8;
        assert_eq!(KeyPolicy::from_creation_tlvs(&d), Err(SW_WRONG_DATA));
        // No attributes: no restriction.
        assert!(KeyPolicy::from_creation_tlvs(&[0x5F, 0x29, 0x01, 0x00])
            .unwrap()
            .is_unrestricted());
    }

    #[test]
    fn stored_form_round_trips() {
        let mut p = policy(Some(2), &[0x73]);
        p.domain = Some(0);
        p.pin_policy = pin_policy::ALWAYS;
        p.touch_policy = touch_policy::NEVER;
        let mut v: heapless::Vec<u8, 80> = heapless::Vec::new();
        p.encode(&mut v).unwrap();
        assert_eq!(KeyPolicy::decode(&v), Ok(p));
        // The largest policy fits the reserved space.
        let mut big = policy(Some(u32::MAX - 1), &[0x11; MAX_ALGORITHMS]);
        big.domain = Some(0);
        big.pin_policy = 3;
        big.touch_policy = 1;
        let mut v: heapless::Vec<u8, MAX_POLICY_EXT> = heapless::Vec::new();
        big.encode(&mut v).unwrap();
        assert_eq!(KeyPolicy::decode(&v), Ok(big));
    }

    #[test]
    fn unrestricted_encodes_to_nothing() {
        let mut v: heapless::Vec<u8, 8> = heapless::Vec::new();
        KeyPolicy::default().encode(&mut v).unwrap();
        assert!(v.is_empty());
        assert_eq!(KeyPolicy::decode(&[]), Ok(KeyPolicy::default()));
    }

    #[test]
    fn malformed_stored_policy_is_an_error() {
        for bad in [
            &[0xA5, 0x00][..],                           // empty container
            &[0xA5, 0x03, 0x90, 0x01, 0x00],             // bad counter
            &[0xA5, 0x03, 0xC0, 0x01, 0x00],             // unknown tag
            &[0xA5, 0x05, 0x92, 0x01, 0x00],             // length mismatch
            &[0xA6, 0x03, 0x92, 0x01, 0x00],             // wrong container
            &[0xA5, 0x03, 0xAB, 0x01, 0x02],             // touch "always"
            &[0xA5, 0x06, 0x92, 0x01, 0x00, 0x92, 1, 0], // repeated tag
        ] {
            assert!(KeyPolicy::decode(bad).is_err(), "{bad:02X?}");
        }
    }

    #[test]
    fn fcp_reports_no_counter_as_ffffffff() {
        let mut v: heapless::Vec<u8, 80> = heapless::Vec::new();
        KeyPolicy::default().encode_fcp(&mut v).unwrap();
        assert_eq!(&v[..], &[0xA5, 0x06, 0x90, 0x04, 0xFF, 0xFF, 0xFF, 0xFF]);
        let mut p = policy(Some(5), &[0x99, 0x92]);
        p.domain = Some(0);
        let mut v: heapless::Vec<u8, 80> = heapless::Vec::new();
        p.encode_fcp(&mut v).unwrap();
        assert_eq!(
            &v[..],
            &[0xA5, 0x0D, 0x90, 0x04, 0, 0, 0, 5, 0x91, 0x02, 0x99, 0x92, 0x92, 0x01, 0x00]
        );
    }

    #[test]
    fn tlv_walker_lengths() {
        let mut seen: heapless::Vec<(u16, usize), 4> = heapless::Vec::new();
        let data = [
            0x5F, 0x29, 0x81, 0x01, 0xAA, 0x90, 0x00, 0x7F, 0x49, 0x82, 0x00, 0x00,
        ];
        for_each_tlv(&data, |t, v| {
            seen.push((t, v.len())).unwrap();
            Ok(())
        })
        .unwrap();
        assert_eq!(&seen[..], &[(0x5F29, 1), (0x90, 0), (0x7F49, 0)]);
        assert!(for_each_tlv(&[0x90, 0x83, 0, 0, 1], |_, _| Ok(())).is_err());
        assert!(for_each_tlv(&[0x5F], |_, _| Ok(())).is_err());
    }
}
