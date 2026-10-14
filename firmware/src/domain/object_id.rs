//! Global object IDs (cluster plan V3 §6.2) and their sidecars (§6.5).
//!
//! # Asymmetric keys: the OpenSC intrinsic ID (20 bytes)
//! The ID of an RSA or EC key is the CKA_ID that OpenSC's pkcs15init
//! computes for it when the caller supplies none (`pkcs15.profile`:
//! `pkcs15-id-style = mozilla`, `sc_pkcs15init_select_intrinsic_id`):
//!
//! - EC:  `SHA-1(x)` — the X coordinate of the public point, "according to
//!   PKCS#15 v1.1";
//! - RSA: `SHA-1(n)` — the modulus, big-endian without leading zeros.
//!
//! (The plan's draft said SHA-256 truncated to 20 bytes; OpenSC 0.25 uses
//! SHA-1, and the ID is only a name — integrity comes from signatures.)
//! It is computed from the public key every time and never stored: every
//! member derives the same ID for the same key, wherever its slot is, and
//! existing keys need no migration.  The PRKD the firmware synthesises for
//! a key without an OpenSC-written one carries this ID as its CKA_ID, so it
//! no longer depends on the slot either.
//!
//! # Symmetric keys, keys without an intrinsic ID, and EFs: random 16 bytes
//! Assigned when the object is created (GENERATE KEY, UNWRAP of an AES
//! key, the first write of a standalone EF) and kept in the object's
//! sidecar.  Objects from before this firmware get theirs lazily, the
//! first time an ID is needed by an authenticated command
//! (`GET_KEY_MANIFEST` today).  Only standalone EFs get one — CD/DCOD
//! descriptors, CA certificates and data objects (prefixes C8, C9, CA, CD,
//! CF).  A key's PRKD (C4) and EE certificate (CE) travel with the key
//! (record kind 1) and have no ID of their own.
//!
//! # Sidecar (`SIDECAR_LEN` = 144 bytes, keystore object `records::sidecar`)
//! ```text
//! [0]        format version   1
//! [1]        kind             1 = key, 2 = file
//! [2]        id length        16 or 20
//! [3]        flags            0 (reserved)
//! [4..24]    object_id        zero-padded to 20
//! [24..32]   version          u64 BE Lamport (0 = never versioned; P3)
//! [32..48]   origin           member ID of the minting member (P3)
//! [48..80]   record hash      SHA-256 of the signed record (P3)
//! [80..144]  sig_member       the origin's record signature (P3)
//! ```
//! P1 writes only the first 24 bytes' worth of meaning; the rest is zero
//! and reserved for the sync records of P3, so the format need not change.

use pico2hsm_core::error::{HsmError, StorageError};
use pico2hsm_core::key::KeyId;
use rand_core::RngCore;

use super::records;
use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};
use crate::storage::KeyStore;

/// Length of an intrinsic (public-key) ID.
pub const INTRINSIC_ID_LEN: u8 = 20;
/// Length of a random ID.
pub const RANDOM_ID_LEN: u8 = 16;
/// Sidecar format version.
pub const SIDECAR_VERSION: u8 = 1;
/// Stored sidecar size.
pub const SIDECAR_LEN: usize = 144;
/// Sidecar kind: a key (with its PRKD and certificate).
pub const KIND_KEY: u8 = 1;
/// Sidecar kind: a standalone file.
pub const KIND_FILE: u8 = 2;

/// A global object ID: 20 bytes (intrinsic) or 16 (random), zero-padded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectId {
    pub len: u8,
    pub bytes: [u8; 20],
}

impl ObjectId {
    /// The significant bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len.min(20))]
    }

    /// A fresh random 16-byte ID.
    pub fn random() -> Self {
        let mut bytes = [0u8; 20];
        crate::protocol::sc_hsm::FwRng.fill_bytes(&mut bytes[..usize::from(RANDOM_ID_LEN)]);
        ObjectId {
            len: RANDOM_ID_LEN,
            bytes,
        }
    }
}

pub(crate) fn strip_zeros(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|&&x| x == 0).count();
    &b[n..]
}

/// The modulus inside a PKCS#1 `RSAPrivateKey` DER (`SEQUENCE { INTEGER
/// version, INTEGER n, ... }`), for RSA keys stored without a public part.
pub(crate) fn pkcs1_modulus(der: &[u8]) -> Option<&[u8]> {
    // Read one DER TLV header at `at`: (tag, content start, content len).
    fn tlv(b: &[u8], at: usize) -> Option<(u8, usize, usize)> {
        let tag = *b.get(at)?;
        let first = *b.get(at + 1)?;
        let (len, hdr) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let n = usize::from(first & 0x7F);
            if n == 0 || n > 2 {
                return None;
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | usize::from(*b.get(at + 2 + i)?);
            }
            (len, 2 + n)
        };
        let start = at + hdr;
        (start.checked_add(len)? <= b.len()).then_some((tag, start, len))
    }
    let (t, seq, _) = tlv(der, 0)?;
    if t != 0x30 {
        return None;
    }
    let (t, vs, vl) = tlv(der, seq)?;
    if t != 0x02 {
        return None;
    }
    let (t, ns, nl) = tlv(der, vs + vl)?;
    (t == 0x02).then(|| &der[ns..ns + nl])
}

/// The OpenSC intrinsic ID of an asymmetric key (see the module docs), or
/// `None` for keys that have none (AES, Ed25519/X25519, a missing public
/// part).
pub fn intrinsic(obj: &KeyObject) -> Option<ObjectId> {
    let digest: [u8; 20] = match obj.key_type {
        KmType::Ec => {
            let p = obj.public_key.as_slice();
            if p.len() < 3 || p[0] != 0x04 || p.len() % 2 == 0 {
                return None;
            }
            let x = &p[1..1 + (p.len() - 1) / 2];
            crate::crypto::symmetric::sha1(x)
        }
        KmType::Rsa => {
            let p = obj.public_key.as_slice();
            let n = if p.len() > 2 {
                let n_len = usize::from(u16::from_be_bytes([p[0], p[1]]));
                p.get(2..2 + n_len)?
            } else {
                pkcs1_modulus(&obj.private_key)?
            };
            let n = strip_zeros(n);
            if n.is_empty() {
                return None;
            }
            crate::crypto::symmetric::sha1(n)
        }
        _ => return None,
    };
    Some(ObjectId {
        len: INTRINSIC_ID_LEN,
        bytes: digest,
    })
}

/// Whether the EF `fid` is a standalone file that gets its own ID.
pub fn is_standalone_ef(fid: u16) -> bool {
    matches!((fid >> 8) as u8, 0xC8 | 0xC9 | 0xCA | 0xCD | 0xCF)
}

/// A decoded sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sidecar {
    pub kind: u8,
    pub id: ObjectId,
    /// Lamport version of the last record (P3); 0 = unversioned.
    pub version: u64,
    pub origin: [u8; 16],
    pub record_hash: [u8; 32],
    pub sig_member: [u8; 64],
}

impl Sidecar {
    /// A fresh, unversioned sidecar.
    pub fn new(kind: u8, id: ObjectId) -> Self {
        Sidecar {
            kind,
            id,
            version: 0,
            origin: [0; 16],
            record_hash: [0; 32],
            sig_member: [0; 64],
        }
    }

    pub fn encode(&self) -> [u8; SIDECAR_LEN] {
        let mut b = [0u8; SIDECAR_LEN];
        b[0] = SIDECAR_VERSION;
        b[1] = self.kind;
        b[2] = self.id.len;
        b[4..24].copy_from_slice(&self.id.bytes);
        b[24..32].copy_from_slice(&self.version.to_be_bytes());
        b[32..48].copy_from_slice(&self.origin);
        b[48..80].copy_from_slice(&self.record_hash);
        b[80..144].copy_from_slice(&self.sig_member);
        b
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != SIDECAR_LEN
            || b[0] != SIDECAR_VERSION
            || !matches!(b[1], KIND_KEY | KIND_FILE)
            || !matches!(b[2], RANDOM_ID_LEN | INTRINSIC_ID_LEN)
        {
            return None;
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&b[4..24]);
        Some(Sidecar {
            kind: b[1],
            id: ObjectId { len: b[2], bytes },
            version: u64::from_be_bytes(b[24..32].try_into().ok()?),
            origin: b[32..48].try_into().ok()?,
            record_hash: b[48..80].try_into().ok()?,
            sig_member: b[80..144].try_into().ok()?,
        })
    }
}

/// The sidecar of `local`, `Ok(None)` if it has none.  One that does not
/// parse is a storage error (fail closed).
#[inline(never)] // keeps its KeyObject temporaries off the caller's frame (core1 stack)
pub fn load_sidecar(store: &mut dyn KeyStore, local: KeyId) -> Result<Option<Sidecar>, HsmError> {
    let Some(obj) = store.fetch_key(records::sidecar(local))? else {
        return Ok(None);
    };
    Sidecar::decode(&obj.private_key)
        .map(Some)
        .ok_or(HsmError::Storage(StorageError::IntegrityFailure))
}

/// Write `sidecar` for `local`.
#[inline(never)] // keeps its KeyObject temporaries off the caller's frame (core1 stack)
pub fn save_sidecar(
    store: &mut dyn KeyStore,
    local: KeyId,
    sidecar: &Sidecar,
) -> Result<(), HsmError> {
    let mut obj = KeyObject::new(
        KmType::Generic,
        records::sidecar(local).0,
        pico2hsm_core::key::AppletId::Domain,
        AlgorithmId::AesGcm,
    );
    obj.private_key
        .extend_from_slice(&sidecar.encode())
        .map_err(|_| HsmError::InvalidInput)?;
    store.save_key(&obj)
}

/// Give `local` a fresh random ID (a newly created object).
pub fn assign_random(
    store: &mut dyn KeyStore,
    local: KeyId,
    kind: u8,
) -> Result<ObjectId, HsmError> {
    let id = ObjectId::random();
    save_sidecar(store, local, &Sidecar::new(kind, id))?;
    Ok(id)
}

/// Remove the sidecar of `local`, if there is one.
#[inline(never)] // keeps its KeyObject temporaries off the caller's frame (core1 stack)
pub fn erase_sidecar(store: &mut dyn KeyStore, local: KeyId) -> Result<(), HsmError> {
    let kid = records::sidecar(local);
    if store.fetch_key(kid)?.is_some() {
        store.erase_key(kid)?;
    }
    Ok(())
}

/// The global ID of the key `obj` stored at `local`: intrinsic if it has
/// one, else its sidecar's — assigned now when `assign` and none exists.
pub fn of_key(
    store: &mut dyn KeyStore,
    local: KeyId,
    obj: &KeyObject,
    assign: bool,
) -> Result<Option<ObjectId>, HsmError> {
    if let Some(id) = intrinsic(obj) {
        return Ok(Some(id));
    }
    if let Some(sc) = load_sidecar(store, local)? {
        return Ok(Some(sc.id));
    }
    if assign {
        return assign_random(store, local, KIND_KEY).map(Some);
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico2hsm_core::key::AppletId;

    #[test]
    fn ec_id_is_sha1_of_x() {
        let mut obj = KeyObject::new(KmType::Ec, 1, AppletId::ScHsm, AlgorithmId::EcdsaP256);
        let mut q = [0u8; 65];
        q[0] = 0x04;
        for (i, b) in q[1..].iter_mut().enumerate() {
            *b = i as u8;
        }
        obj.public_key.extend_from_slice(&q).unwrap();
        let id = intrinsic(&obj).unwrap();
        assert_eq!(id.len, 20);
        assert_eq!(id.bytes, crate::crypto::symmetric::sha1(&q[1..33]));
    }

    #[test]
    fn rsa_id_is_sha1_of_modulus_from_either_form() {
        let n = [0x00u8, 0xC5, 0x01, 0x02, 0x03];
        let mut obj = KeyObject::new(KmType::Rsa, 1, AppletId::ScHsm, AlgorithmId::RsaDecrypt);
        obj.public_key.extend_from_slice(&[0, 5]).unwrap();
        obj.public_key.extend_from_slice(&n).unwrap();
        obj.public_key.extend_from_slice(&[1, 0, 1]).unwrap();
        let want = crate::crypto::symmetric::sha1(&n[1..]);
        assert_eq!(intrinsic(&obj).unwrap().bytes, want);

        // No public part: the modulus comes from the PKCS#1 DER.
        let mut der_only = KeyObject::new(KmType::Rsa, 1, AppletId::ScHsm, AlgorithmId::RsaDecrypt);
        let der = [
            0x30, 0x0A, 0x02, 0x01, 0x00, 0x02, 0x05, 0x00, 0xC5, 0x01, 0x02, 0x03,
        ];
        der_only.private_key.extend_from_slice(&der).unwrap();
        assert_eq!(intrinsic(&der_only).unwrap().bytes, want);
    }

    #[test]
    fn aes_has_no_intrinsic_id() {
        let obj = KeyObject::new(KmType::Aes, 1, AppletId::ScHsm, AlgorithmId::AesGcm);
        assert_eq!(intrinsic(&obj), None);
    }

    #[test]
    fn sidecar_round_trips() {
        let mut sc = Sidecar::new(KIND_FILE, ObjectId::random());
        sc.version = 9;
        let b = sc.encode();
        assert_eq!(Sidecar::decode(&b), Some(sc));
        assert_eq!(Sidecar::decode(&b[..143]), None);
    }

    #[test]
    fn standalone_files() {
        for fid in [0xC801, 0xC902, 0xCA03, 0xCD04, 0xCF05] {
            assert!(is_standalone_ef(fid));
        }
        for fid in [0xC401, 0xCE01, 0x2F02, 0x2F10, 0xCC01] {
            assert!(!is_standalone_ef(fid));
        }
    }
}
