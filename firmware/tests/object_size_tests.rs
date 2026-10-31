//! Large data objects store and read back in every build (audit R2-11).
//!
//! Builds without the `rsa` feature used to cap every stored object at
//! 512 bytes, so EC certificates (600–1500 bytes) failed closed: PIV
//! certificate objects, the OpenPGP cardholder certificate (7F21) and
//! SC-HSM certificate EFs (CExx).  These tests write such objects through
//! the applets' APDU handlers into a store that really encrypts them
//! (`KeyObject::encrypt` / `decrypt`, the on-flash blob format), then read
//! them back after a simulated reboot.  Run them with and without `rsa`:
//!
//! ```sh
//! cargo test --manifest-path firmware/Cargo.toml --test object_size_tests \
//!     --no-default-features --features pico2_4m,applet-piv,applet-openpgp-curve25519 \
//!     --target x86_64-unknown-linux-gnu
//! ```

use std::collections::BTreeMap;

use pico2hsm_core::error::HsmError;
use pico2hsm_core::key::{AppletId, KeyId};
use pico2hsm_firmware::security::key_management::{KeyObject, MAX_OBJECT_DATA_SIZE};
use pico2hsm_firmware::storage::retry_counter::{MemCounters, RetryCounterBackend};
use pico2hsm_firmware::storage::KeyStore;

/// Deterministic fake Storage Master Key (test use only).
const TEST_SMK: [u8; 32] = [0x5A; 32];

/// In-memory keystore holding the same encrypted blobs `FlashKeyStore`
/// writes to flash, so the plaintext / blob size limits are exercised.
#[derive(Default)]
struct EncryptingStore {
    blobs: BTreeMap<u32, Vec<u8>>,
    nonce_ctr: u64,
    /// Credential retry counters (the board keeps these in their own log).
    counters: MemCounters,
}

impl KeyStore for EncryptingStore {
    fn save_key(&mut self, obj: &KeyObject) -> Result<(), HsmError> {
        self.nonce_ctr += 1;
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.nonce_ctr.to_le_bytes());
        let blob = obj
            .encrypt(&TEST_SMK, &nonce)
            .map_err(|_| HsmError::InvalidInput)?;
        self.blobs.insert(obj.key_id, blob.to_vec());
        Ok(())
    }
    fn fetch_key(&mut self, key_id: KeyId) -> Result<Option<KeyObject>, HsmError> {
        match self.blobs.get(&key_id.0) {
            None => Ok(None),
            Some(blob) => KeyObject::decrypt(blob, key_id.0, &TEST_SMK)
                .map(Some)
                .map_err(|_| HsmError::InvalidInput),
        }
    }
    fn erase_key(&mut self, key_id: KeyId) -> Result<(), HsmError> {
        self.blobs.remove(&key_id.0);
        Ok(())
    }
    fn wipe_all(&mut self) -> Result<(), HsmError> {
        self.blobs.clear();
        Ok(())
    }
    fn wipe_by_owner(&mut self, owner: AppletId) -> Result<(), HsmError> {
        self.blobs
            .retain(|k, _| ((k >> 16) & 0xFF) as u8 != owner as u8);
        Ok(())
    }
    fn enumerate_keys(&self) -> heapless::Vec<KeyId, 64> {
        self.blobs.keys().take(64).map(|k| KeyId(*k)).collect()
    }
    fn for_each_key(&self, f: &mut dyn FnMut(KeyId)) {
        for k in self.blobs.keys() {
            f(KeyId(*k));
        }
    }
    fn retry_counters(&mut self) -> Option<&mut dyn RetryCounterBackend> {
        Some(&mut self.counters)
    }
}

/// Case 3E / 4E APDU: extended Lc, optional extended Le (`Some(0)` = 65536).
fn ext_apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: Option<u16>) -> Vec<u8> {
    let mut v = vec![cla, ins, p1, p2, 0x00];
    if !data.is_empty() {
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
    }
    if let Some(le) = le {
        v.extend_from_slice(&le.to_be_bytes());
    }
    v
}

fn sw(resp: &[u8]) -> u16 {
    let n = resp.len();
    assert!(n >= 2, "response too short: {resp:?}");
    u16::from_be_bytes([resp[n - 2], resp[n - 1]])
}

fn data_of(resp: &[u8]) -> &[u8] {
    &resp[..resp.len() - 2]
}

/// Append a DER/BER length.
fn push_len(v: &mut Vec<u8>, len: usize) {
    match len {
        0..=0x7F => v.push(len as u8),
        0x80..=0xFF => v.extend_from_slice(&[0x81, len as u8]),
        _ => v.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
    }
}

/// Stand-in for a DER certificate of `len` bytes: a SEQUENCE header and a
/// non-repeating body, so truncation or misplacement is detected.
fn fake_cert(len: usize) -> Vec<u8> {
    let body_len = len - 4;
    let mut v = vec![0x30, 0x82, (body_len >> 8) as u8, body_len as u8];
    v.extend((0..body_len).map(|i| (i * 7 + i / 251) as u8));
    assert_eq!(v.len(), len);
    v
}

#[test]
fn object_cap_does_not_depend_on_rsa() {
    // EC certificates are as valid as RSA ones; every build stores the same
    // object sizes.
    assert_eq!(MAX_OBJECT_DATA_SIZE, 2400);
}

/// PIV: a ~1.5 KB certificate in 5FC105 (slot 9A).
#[cfg(feature = "applet-piv")]
#[test]
fn piv_certificate_1500_bytes_round_trip() {
    use pico2hsm_firmware::protocol::piv::Piv;

    let cert = fake_cert(1500);
    // 53 { 70 cert  71 00  FE 00 } — SP 800-73-4 certificate container.
    let mut content = vec![0x70];
    push_len(&mut content, cert.len());
    content.extend_from_slice(&cert);
    content.extend_from_slice(&[0x71, 0x01, 0x00, 0xFE, 0x00]);
    let mut body = vec![0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53];
    push_len(&mut body, content.len());
    body.extend_from_slice(&content);
    assert!(body.len() > 1500);

    let mut store = EncryptingStore::default();
    let mut piv = Piv::new();
    piv.state.mgmt_key_authenticated = true;
    let r = piv.process_apdu_with_store(&ext_apdu(0x00, 0xDB, 0x3F, 0xFF, &body, None), &mut store);
    assert_eq!(sw(&r), 0x9000, "PUT DATA 5FC105 (1.5 KB)");

    // Reboot: a fresh applet loads the object from the encrypted store.
    let mut piv = Piv::new();
    piv.load_from_store(&mut store);
    let r = piv.process_apdu_with_store(
        &ext_apdu(
            0x00,
            0xCB,
            0x3F,
            0xFF,
            &[0x5C, 0x03, 0x5F, 0xC1, 0x05],
            Some(0),
        ),
        &mut store,
    );
    assert_eq!(sw(&r), 0x9000, "GET DATA 5FC105");
    let mut expected = vec![0x53];
    push_len(&mut expected, content.len());
    expected.extend_from_slice(&content);
    assert_eq!(data_of(&r), &expected[..]);
}

/// OpenPGP: a cardholder certificate (7F21) at the applet's 1024-byte limit.
#[cfg(feature = "applet-openpgp")]
#[test]
fn openpgp_cardholder_certificate_round_trip() {
    use pico2hsm_firmware::protocol::openpgp::OpenPgp;

    let cert = fake_cert(1024);
    let mut store = EncryptingStore::default();
    let mut pgp = OpenPgp::new();
    pgp.state.pw3_verified = true;
    let r = pgp.process_apdu_with_store(&ext_apdu(0x00, 0xDA, 0x7F, 0x21, &cert, None), &mut store);
    assert_eq!(sw(&r), 0x9000, "PUT DATA 7F21 (1 KB)");

    let mut pgp = OpenPgp::new();
    pgp.load_from_store(&mut store);
    let r =
        pgp.process_apdu_with_store(&ext_apdu(0x00, 0xCA, 0x7F, 0x21, &[], Some(0)), &mut store);
    assert_eq!(sw(&r), 0x9000, "GET DATA 7F21");
    assert_eq!(data_of(&r), &cert[..]);
}

/// SC-HSM: a ~1.5 KB certificate EF (CE01) written with WRITE DATA.
#[test]
fn sc_hsm_certificate_ef_round_trip() {
    use pico2hsm_firmware::protocol::sc_hsm::ScHsm;

    let cert = fake_cert(1500);
    let mut body = vec![0x54, 0x02, 0x00, 0x00, 0x53];
    push_len(&mut body, cert.len());
    body.extend_from_slice(&cert);

    let mut store = EncryptingStore::default();
    let mut hsm = ScHsm::new();
    hsm.state.pin_verified = true;
    let r = hsm.process_apdu_with_store(&ext_apdu(0x80, 0xD7, 0xCE, 0x01, &body, None), &mut store);
    assert_eq!(sw(&r), 0x9000, "WRITE DATA CE01 (1.5 KB)");

    // Drop the RAM copy so READ BINARY has to decrypt the stored object.
    hsm.state.ef_cache.clear();
    let r = hsm.process_apdu_with_store(
        &ext_apdu(0x00, 0xB1, 0xCE, 0x01, &[0x54, 0x02, 0x00, 0x00], Some(0)),
        &mut store,
    );
    assert_eq!(sw(&r), 0x9000, "READ BINARY CE01");
    assert_eq!(data_of(&r), &cert[..]);
}
