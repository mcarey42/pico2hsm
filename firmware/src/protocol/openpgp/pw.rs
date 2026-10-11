//! OpenPGP password (PW1/PW3) records.
//!
//! New passwords are stored as PBKDF2-HMAC-SHA256 with a random 16-byte
//! salt (the same KDF as SC-HSM PINs) and their length.  The length lets
//! CHANGE REFERENCE DATA split `old || new` at exactly one point, so one
//! attempt is one guess.
//!
//! `Legacy` records are unsalted SHA-256: the factory defaults (public
//! anyway, and cheap to set up at every boot) and records written by earlier
//! firmware.  A successful VERIFY upgrades a legacy record to PBKDF2.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// PBKDF2 context string (domain separation from SC-HSM and PIV PINs).
const PW_CONTEXT: &[u8] = b"pico2hsm-openpgp";

/// How a password record was derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PwKdf {
    /// Unsalted SHA-256 (factory defaults, pre-2026-10 records).
    Legacy = 0,
    /// PBKDF2-HMAC-SHA256 with a per-record salt.
    Pbkdf2 = 1,
}

/// A stored OpenPGP password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PwHash {
    pub digest: [u8; 32],
    pub salt: [u8; 16],
    /// Password length in bytes; 0 = unknown (legacy record from flash).
    pub len: u8,
    pub kdf: PwKdf,
}

impl PwHash {
    /// Salted PBKDF2 record for a newly set password.
    pub fn new(pw: &[u8]) -> Self {
        use rand_core::RngCore;
        let mut salt = [0u8; 16];
        crate::protocol::sc_hsm::FwRng.fill_bytes(&mut salt);
        PwHash {
            digest: crate::security::pin::PinState::hash_pin(pw, PW_CONTEXT, &salt),
            salt,
            len: pw.len().min(255) as u8,
            kdf: PwKdf::Pbkdf2,
        }
    }

    /// Legacy record for a factory-default password (length known).
    pub fn factory_default(pw: &[u8]) -> Self {
        PwHash {
            digest: sha256(pw),
            salt: [0u8; 16],
            len: pw.len() as u8,
            kdf: PwKdf::Legacy,
        }
    }

    /// Constant-time check of `pw` against this record.
    pub fn matches(&self, pw: &[u8]) -> bool {
        let mut computed = match self.kdf {
            PwKdf::Legacy => sha256(pw),
            PwKdf::Pbkdf2 => crate::security::pin::PinState::hash_pin(pw, PW_CONTEXT, &self.salt),
        };
        let ok = computed.ct_eq(&self.digest).into();
        computed.zeroize();
        ok
    }

    /// Stored password length, if known.
    pub fn len(&self) -> Option<usize> {
        (self.len != 0).then_some(self.len as usize)
    }
}

impl Zeroize for PwHash {
    fn zeroize(&mut self) {
        self.digest.zeroize();
        self.salt.zeroize();
        self.len = 0;
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_record_is_salted_and_matches() {
        let a = PwHash::new(b"654321");
        let b = PwHash::new(b"654321");
        assert_ne!(a.digest, b.digest, "random salt per record");
        assert!(a.matches(b"654321"));
        assert!(!a.matches(b"654322"));
        assert_eq!(a.len(), Some(6));
    }

    #[test]
    fn legacy_record_matches_sha256() {
        let d = PwHash::factory_default(b"123456");
        assert!(d.matches(b"123456"));
        assert_eq!(d.len(), Some(6));
    }
}
