//! Member certificates and the on-device member list (cluster plan V3
//! §4.2–§4.4).
//!
//! # Member identity
//! A member's key is the device identity key (key ref 0xFE, the key
//! `GET_DEVICE_PUBLIC_KEY` returns).  Its **member ID** is
//! `SHA-256(member_pub)[0..16]`: derived, not assigned, so two devices
//! that formed a domain independently from the same shares never claim
//! the same identity, a re-issued certificate keeps it, and no sponsor
//! has to coordinate a counter.  (The plan's draft used a sponsor-assigned
//! `member_serial u32`, which two independently formed devices would both
//! have set to 1.)
//!
//! # Certificate (`CERT_LEN` = 187 bytes, fixed layout)
//! ```text
//! [0]        version         1
//! [1..17]    domain_id       SHA-256(Q_domain)[0..16]
//! [17..33]   member_id       SHA-256(member_pub)[0..16]
//! [33..98]   member_pub      uncompressed P-256 (04 || x || y)
//! [98..114]  sponsor_id      member ID of the issuer (= member_id when self-issued)
//! [114..122] issued_lamport  u64 BE, the issuer's Lamport counter
//! [122]      flags           bit 0 = may sponsor others
//! [123..187] sig_domain      ECDSA-P256(d_domain, r || s) over
//!                            SHA-256("pico2hsm-member-cert-v1" || [0..123])
//! ```
//! The signature input starts with a context string so that no other
//! message the domain key ever signs can be replayed as a certificate.
//!
//! # Member list
//! Up to [`MAX_MEMBERS`] entries, one keystore object per slot
//! (`records::member_slot`), filled densely from slot 0.  Revoked members
//! stay listed (P2).  Entry (`ENTRY_LEN` = 197 bytes):
//! ```text
//! [0]       entry version   1
//! [1]       status          0 = active, 1 = revoked
//! [2..10]   revoked_lamport u64 BE (0 while active)
//! [10..197] certificate
//! ```

use pico2hsm_core::error::HsmError;
use sha2::{Digest, Sha256};

use super::key::{domain_id, verify_prehash, DomainKey, DOMAIN_ID_LEN};
use super::records;
use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};
use crate::storage::KeyStore;

/// Certificate format version.
pub const CERT_VERSION: u8 = 1;
/// Signed part of a certificate.
pub const CERT_BODY_LEN: usize = 123;
/// Whole certificate.
pub const CERT_LEN: usize = CERT_BODY_LEN + 64;
/// Domain-separation prefix of the signature input.
pub const CERT_CONTEXT: &[u8] = b"pico2hsm-member-cert-v1";
/// `flags` bit: the member may sponsor (enroll) others.  Default on (§12.3).
pub const FLAG_MAY_SPONSOR: u8 = 0x01;
/// Length of a member ID.
pub const MEMBER_ID_LEN: usize = 16;

/// Member-list capacity.
pub const MAX_MEMBERS: u8 = 32;
/// Member-list entry format version.
pub const ENTRY_VERSION: u8 = 1;
/// Stored (and `GET_MEMBERS`) entry size.
pub const ENTRY_LEN: usize = 10 + CERT_LEN;
/// Entry status: active.
pub const STATUS_ACTIVE: u8 = 0;
/// Entry status: revoked (P2).
pub const STATUS_REVOKED: u8 = 1;

/// `SHA-256(member_pub)[0..16]`.
pub fn member_id(member_pub: &[u8; 65]) -> [u8; MEMBER_ID_LEN] {
    let h = Sha256::digest(member_pub);
    let mut id = [0u8; MEMBER_ID_LEN];
    id.copy_from_slice(&h[..MEMBER_ID_LEN]);
    id
}

/// Why a certificate was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertError {
    /// Wrong length or version.
    Format,
    /// `member_pub` is not a P-256 point, or `member_id` does not match it.
    MemberKey,
    /// Signed for another domain, or the signature does not verify.
    Signature,
}

/// A decoded member certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberCert {
    pub domain_id: [u8; DOMAIN_ID_LEN],
    pub member_id: [u8; MEMBER_ID_LEN],
    pub member_pub: [u8; 65],
    pub sponsor_id: [u8; MEMBER_ID_LEN],
    pub issued_lamport: u64,
    pub flags: u8,
    pub sig: [u8; 64],
}

impl MemberCert {
    /// The signed fields, `[0..123]`.
    pub fn body(&self) -> [u8; CERT_BODY_LEN] {
        let mut b = [0u8; CERT_BODY_LEN];
        b[0] = CERT_VERSION;
        b[1..17].copy_from_slice(&self.domain_id);
        b[17..33].copy_from_slice(&self.member_id);
        b[33..98].copy_from_slice(&self.member_pub);
        b[98..114].copy_from_slice(&self.sponsor_id);
        b[114..122].copy_from_slice(&self.issued_lamport.to_be_bytes());
        b[122] = self.flags;
        b
    }

    /// `SHA-256(CERT_CONTEXT || body)`, the digest the domain key signs.
    pub fn digest(body: &[u8; CERT_BODY_LEN]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(CERT_CONTEXT);
        h.update(body);
        h.finalize().into()
    }

    /// The 187-byte encoding.
    pub fn encode(&self) -> [u8; CERT_LEN] {
        let mut out = [0u8; CERT_LEN];
        out[..CERT_BODY_LEN].copy_from_slice(&self.body());
        out[CERT_BODY_LEN..].copy_from_slice(&self.sig);
        out
    }

    /// Parse a certificate and check its internal consistency (the member
    /// key is a P-256 point and `member_id` is its hash).  The signature is
    /// checked by [`Self::verify`].
    pub fn decode(b: &[u8]) -> Result<Self, CertError> {
        if b.len() != CERT_LEN || b[0] != CERT_VERSION {
            return Err(CertError::Format);
        }
        let take16 = |at: usize| {
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[at..at + 16]);
            a
        };
        let mut member_pub = [0u8; 65];
        member_pub.copy_from_slice(&b[33..98]);
        if p256::PublicKey::from_sec1_bytes(&member_pub).is_err() || member_pub[0] != 0x04 {
            return Err(CertError::MemberKey);
        }
        let cert = MemberCert {
            domain_id: take16(1),
            member_id: take16(17),
            member_pub,
            sponsor_id: take16(98),
            issued_lamport: u64::from_be_bytes(b[114..122].try_into().unwrap_or([0; 8])),
            flags: b[122],
            sig: b[CERT_BODY_LEN..].try_into().unwrap_or([0; 64]),
        };
        if cert.member_id != member_id(&cert.member_pub) {
            return Err(CertError::MemberKey);
        }
        Ok(cert)
    }

    /// Check that the certificate belongs to the domain of `q_domain` and
    /// that `sig_domain` verifies under it.
    pub fn verify(&self, q_domain: &[u8; 65]) -> Result<(), CertError> {
        if self.domain_id != domain_id(q_domain) {
            return Err(CertError::Signature);
        }
        if !verify_prehash(q_domain, &Self::digest(&self.body()), &self.sig) {
            return Err(CertError::Signature);
        }
        Ok(())
    }

    /// Issue (sign) a certificate for `member_pub` with the domain key.
    pub fn issue(
        domain: &DomainKey,
        member_pub: &[u8; 65],
        sponsor_id: &[u8; MEMBER_ID_LEN],
        issued_lamport: u64,
        flags: u8,
    ) -> Result<Self, ()> {
        let mut cert = MemberCert {
            domain_id: domain.id,
            member_id: member_id(member_pub),
            member_pub: *member_pub,
            sponsor_id: *sponsor_id,
            issued_lamport,
            flags,
            sig: [0u8; 64],
        };
        cert.sig = domain.sign_prehash(&Self::digest(&cert.body()))?;
        Ok(cert)
    }
}

/// One member-list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberEntry {
    pub status: u8,
    pub revoked_lamport: u64,
    pub cert: MemberCert,
}

impl MemberEntry {
    /// An active entry for `cert`.
    pub fn active(cert: MemberCert) -> Self {
        MemberEntry {
            status: STATUS_ACTIVE,
            revoked_lamport: 0,
            cert,
        }
    }

    /// The stored / wire encoding.
    pub fn encode(&self) -> [u8; ENTRY_LEN] {
        let mut out = [0u8; ENTRY_LEN];
        out[0] = ENTRY_VERSION;
        out[1] = self.status;
        out[2..10].copy_from_slice(&self.revoked_lamport.to_be_bytes());
        out[10..].copy_from_slice(&self.cert.encode());
        out
    }

    /// Parse a stored entry.
    pub fn decode(b: &[u8]) -> Result<Self, CertError> {
        if b.len() != ENTRY_LEN
            || b[0] != ENTRY_VERSION
            || !matches!(b[1], STATUS_ACTIVE | STATUS_REVOKED)
        {
            return Err(CertError::Format);
        }
        Ok(MemberEntry {
            status: b[1],
            revoked_lamport: u64::from_be_bytes(b[2..10].try_into().unwrap_or([0; 8])),
            cert: MemberCert::decode(&b[10..])?,
        })
    }
}

/// The entry in slot `slot`, `Ok(None)` if the slot is empty.  A stored
/// entry that does not parse is a storage error (fail closed).
#[inline(never)] // keeps its KeyObject temporaries off the caller's frame (core1 stack)
pub fn load(store: &mut dyn KeyStore, slot: u8) -> Result<Option<MemberEntry>, HsmError> {
    let Some(obj) = store.fetch_key(records::member_slot(slot))? else {
        return Ok(None);
    };
    MemberEntry::decode(&obj.private_key)
        .map(Some)
        .map_err(|_| HsmError::Storage(pico2hsm_core::error::StorageError::IntegrityFailure))
}

/// Number of entries (the list is dense from slot 0).
#[inline(never)] // keeps its KeyObject temporaries off the caller's frame (core1 stack)
pub fn count(store: &mut dyn KeyStore) -> Result<u8, HsmError> {
    for slot in 0..MAX_MEMBERS {
        if store.fetch_key(records::member_slot(slot))?.is_none() {
            return Ok(slot);
        }
    }
    Ok(MAX_MEMBERS)
}

/// Store `entry` in `slot`.
#[inline(never)] // keeps its KeyObject temporaries off the caller's frame (core1 stack)
pub fn save(store: &mut dyn KeyStore, slot: u8, entry: &MemberEntry) -> Result<(), HsmError> {
    if slot >= MAX_MEMBERS {
        return Err(HsmError::InvalidInput);
    }
    let kid = records::member_slot(slot);
    let mut obj = KeyObject::new(
        KmType::Generic,
        kid.0,
        pico2hsm_core::key::AppletId::Domain,
        AlgorithmId::EcdsaP256,
    );
    obj.private_key
        .extend_from_slice(&entry.encode())
        .map_err(|_| HsmError::InvalidInput)?;
    store.save_key(&obj)
}

/// Add `entry`: replace the entry with the same member ID, or append.
/// Returns the slot.  A full list is refused.
pub fn upsert(store: &mut dyn KeyStore, entry: &MemberEntry) -> Result<u8, HsmError> {
    for slot in 0..MAX_MEMBERS {
        match load(store, slot)? {
            Some(e) if e.cert.member_id == entry.cert.member_id => {
                save(store, slot, entry)?;
                return Ok(slot);
            }
            Some(_) => {}
            None => {
                save(store, slot, entry)?;
                return Ok(slot);
            }
        }
    }
    Err(HsmError::Storage(
        pico2hsm_core::error::StorageError::KeystoreFull,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member_pub(seed: u8) -> [u8; 65] {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let sk = p256::SecretKey::from_slice(&[seed; 32]).unwrap();
        let mut out = [0u8; 65];
        out.copy_from_slice(sk.public_key().to_encoded_point(false).as_bytes());
        out
    }

    #[test]
    fn issued_certificate_round_trips_and_verifies() {
        let domain = DomainKey::derive(&[7; 32]).unwrap();
        let pubk = member_pub(3);
        let id = member_id(&pubk);
        let cert = MemberCert::issue(&domain, &pubk, &id, 42, FLAG_MAY_SPONSOR).unwrap();
        let bytes = cert.encode();
        assert_eq!(bytes.len(), 187);
        let back = MemberCert::decode(&bytes).unwrap();
        assert_eq!(back, cert);
        assert_eq!(back.verify(&domain.q), Ok(()));

        let other = DomainKey::derive(&[8; 32]).unwrap();
        assert_eq!(back.verify(&other.q), Err(CertError::Signature));

        let mut tampered = bytes;
        tampered[121] ^= 1; // issued_lamport
        assert_eq!(
            MemberCert::decode(&tampered).unwrap().verify(&domain.q),
            Err(CertError::Signature)
        );
        let mut wrong_id = bytes;
        wrong_id[17] ^= 1;
        assert_eq!(MemberCert::decode(&wrong_id), Err(CertError::MemberKey));
        assert_eq!(MemberCert::decode(&bytes[..186]), Err(CertError::Format));
    }

    #[test]
    fn entries_round_trip() {
        let domain = DomainKey::derive(&[7; 32]).unwrap();
        let pubk = member_pub(5);
        let cert = MemberCert::issue(&domain, &pubk, &member_id(&pubk), 1, 0).unwrap();
        let e = MemberEntry::active(cert);
        let b = e.encode();
        assert_eq!(b.len(), ENTRY_LEN);
        assert_eq!(MemberEntry::decode(&b).unwrap(), e);
        let mut bad = b;
        bad[1] = 9;
        assert_eq!(MemberEntry::decode(&bad), Err(CertError::Format));
    }
}
