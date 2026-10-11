//! Host tests: OpenPGP Card 3.4 key roles, PW1 status byte (C4), the
//! signature counter (DO 93) and the no-button feature DOs (audit S-10).

use super::*;
use crate::protocol::sc_hsm::policy_tests::BlobStore;
use pico2hsm_core::apdu::SW_OK;

type Out = (u16, heapless::Vec<u8, 4098>);

fn send(pgp: &mut OpenPgp, store: &mut BlobStore, a: &[u8]) -> Out {
    let mut r = pgp.process_apdu_with_store(a, store);
    let n = r.len();
    let sw = u16::from_be_bytes([r[n - 2], r[n - 1]]);
    r.truncate(n - 2);
    (sw, r)
}

fn apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> heapless::Vec<u8, 300> {
    let mut v = heapless::Vec::new();
    v.extend_from_slice(&[0x00, ins, p1, p2]).unwrap();
    if !data.is_empty() {
        v.push(data.len() as u8).unwrap();
        v.extend_from_slice(data).unwrap();
    }
    v
}

fn sw(pgp: &mut OpenPgp, store: &mut BlobStore, a: &[u8]) -> u16 {
    send(pgp, store, a).0
}

const PW1: &[u8] = b"123456";
const PW3: &[u8] = b"12345678";

/// A card with SIG, DEC and AUT keys (defaults: ECDSA / ECDH / ECDSA P-256).
fn card() -> (OpenPgp, BlobStore) {
    let mut pgp = OpenPgp::new();
    let mut store = BlobStore::new();
    assert_eq!(sw(&mut pgp, &mut store, &apdu(0x20, 0, 0x83, PW3)), SW_OK);
    for crt in [0xB6, 0xB8, 0xA4] {
        assert_eq!(
            sw(&mut pgp, &mut store, &apdu(0x47, 0x80, 0, &[crt, 0x00])),
            SW_OK
        );
    }
    (pgp, store)
}

fn cds(pgp: &mut OpenPgp, store: &mut BlobStore) -> u16 {
    sw(pgp, store, &apdu(0x2A, 0x9E, 0x9A, &[0x42; 32]))
}

fn pw1(pgp: &mut OpenPgp, store: &mut BlobStore, mode: u8) -> u16 {
    sw(pgp, store, &apdu(0x20, 0, mode, PW1))
}

fn reload(store: &mut BlobStore) -> OpenPgp {
    let mut pgp = OpenPgp::new();
    pgp.load_from_store(store);
    pgp
}

#[test]
fn c4_00_allows_one_signature_per_verify() {
    let (mut pgp, mut store) = card();
    let (_, c4) = send(&mut pgp, &mut store, &apdu(0xCA, 0x00, 0xC4, &[]));
    assert_eq!(c4[0], 0x00, "default: one PSO:CDS per VERIFY");
    assert_eq!(pw1(&mut pgp, &mut store, 0x81), SW_OK);
    assert_eq!(cds(&mut pgp, &mut store), SW_OK);
    assert_eq!(cds(&mut pgp, &mut store), 0x6982);
    assert_eq!(pw1(&mut pgp, &mut store, 0x81), SW_OK);
    assert_eq!(cds(&mut pgp, &mut store), SW_OK);
}

#[test]
fn c4_01_allows_several_and_persists() {
    let (mut pgp, mut store) = card();
    // PW3 (from `card`) authorises PUT DATA C4.
    assert_eq!(
        sw(&mut pgp, &mut store, &apdu(0xDA, 0x00, 0xC4, &[0x01])),
        SW_OK
    );
    assert_eq!(pw1(&mut pgp, &mut store, 0x81), SW_OK);
    for _ in 0..3 {
        assert_eq!(cds(&mut pgp, &mut store), SW_OK);
    }
    // Survives a reset.
    let mut pgp = reload(&mut store);
    let (_, c4) = send(&mut pgp, &mut store, &apdu(0xCA, 0x00, 0xC4, &[]));
    assert_eq!(c4[0], 0x01);
    assert_eq!(pw1(&mut pgp, &mut store, 0x81), SW_OK);
    assert_eq!(cds(&mut pgp, &mut store), SW_OK);
    assert_eq!(cds(&mut pgp, &mut store), SW_OK);
    // Back to 00 (also persisted: the record is removed).
    assert_eq!(sw(&mut pgp, &mut store, &apdu(0x20, 0, 0x83, PW3)), SW_OK);
    assert_eq!(
        sw(&mut pgp, &mut store, &apdu(0xDA, 0x00, 0xC4, &[0x00])),
        SW_OK
    );
    let mut pgp = reload(&mut store);
    assert_eq!(pw1(&mut pgp, &mut store, 0x81), SW_OK);
    assert_eq!(cds(&mut pgp, &mut store), SW_OK);
    assert_eq!(cds(&mut pgp, &mut store), 0x6982);
}

#[test]
fn c4_write_needs_pw3_and_a_valid_value() {
    let (_, mut store) = card();
    let mut pgp = reload(&mut store);
    assert_eq!(
        sw(&mut pgp, &mut store, &apdu(0xDA, 0x00, 0xC4, &[0x01])),
        0x6982
    );
    assert_eq!(sw(&mut pgp, &mut store, &apdu(0x20, 0, 0x83, PW3)), SW_OK);
    assert_eq!(
        sw(&mut pgp, &mut store, &apdu(0xDA, 0x00, 0xC4, &[0x02])),
        0x6A80
    );
    // The extended capabilities say C4 is changeable.
    let (_, c0) = send(&mut pgp, &mut store, &apdu(0xCA, 0x00, 0xC0, &[]));
    assert_ne!(c0[0] & 0x10, 0);
}

#[test]
fn signature_counter_counts_persists_and_resets() {
    let (mut pgp, mut store) = card();
    assert_eq!(
        sw(&mut pgp, &mut store, &apdu(0xDA, 0x00, 0xC4, &[0x01])),
        SW_OK
    );
    assert_eq!(pw1(&mut pgp, &mut store, 0x81), SW_OK);
    for _ in 0..3 {
        assert_eq!(cds(&mut pgp, &mut store), SW_OK);
    }
    let counter = |pgp: &mut OpenPgp, store: &mut BlobStore| {
        let (_, t) = send(pgp, store, &apdu(0xCA, 0x00, 0x7A, &[]));
        t[4..7].to_vec()
    };
    assert_eq!(counter(&mut pgp, &mut store), [0, 0, 3]);
    let mut pgp = reload(&mut store);
    assert_eq!(counter(&mut pgp, &mut store), [0, 0, 3], "survives reset");
    // A signature whose count can't be stored is not returned.
    assert_eq!(pw1(&mut pgp, &mut store, 0x81), SW_OK);
    store.fail_saves = true;
    let (sw_, sig) = send(&mut pgp, &mut store, &apdu(0x2A, 0x9E, 0x9A, &[0x42; 32]));
    assert_eq!((sw_, sig.len()), (0x6581, 0));
    store.fail_saves = false;
    assert_eq!(counter(&mut pgp, &mut store), [0, 0, 3]);
    // Mode 82 does not sign, and does not count.
    let mut pgp = reload(&mut store);
    assert_eq!(pw1(&mut pgp, &mut store, 0x82), SW_OK);
    assert_eq!(cds(&mut pgp, &mut store), 0x6982);
    // A new signature key resets the counter (on flash too).
    assert_eq!(sw(&mut pgp, &mut store, &apdu(0x20, 0, 0x83, PW3)), SW_OK);
    assert_eq!(
        sw(&mut pgp, &mut store, &apdu(0x47, 0x80, 0, &[0xB6, 0x00])),
        SW_OK
    );
    assert_eq!(counter(&mut pgp, &mut store), [0, 0, 0]);
    let mut pgp = reload(&mut store);
    assert_eq!(counter(&mut pgp, &mut store), [0, 0, 0]);
    // A new DEC key does not.
    assert_eq!(pw1(&mut pgp, &mut store, 0x81), SW_OK);
    assert_eq!(cds(&mut pgp, &mut store), SW_OK);
    assert_eq!(sw(&mut pgp, &mut store, &apdu(0x20, 0, 0x83, PW3)), SW_OK);
    sw(&mut pgp, &mut store, &apdu(0x47, 0x80, 0, &[0xB8, 0x00]));
    assert_eq!(counter(&mut pgp, &mut store), [0, 0, 1]);
}

#[test]
fn each_key_has_exactly_its_role() {
    let (_, mut store) = card();
    let mut pgp = reload(&mut store);
    // Mode 81 only: signs, but neither deciphers nor authenticates.
    assert_eq!(pw1(&mut pgp, &mut store, 0x81), SW_OK);
    let peer = crate::crypto::asymmetric::generate_ec_keypair(
        pico2hsm_core::key::KeyType::EcPrivateP256,
        &mut crate::protocol::sc_hsm::FwRng,
    )
    .unwrap();
    let mut dec: heapless::Vec<u8, 80> = heapless::Vec::new();
    dec.extend_from_slice(&[0xA6, 0x46, 0x7F, 0x49, 0x43, 0x86, 0x41])
        .unwrap();
    dec.extend_from_slice(&peer.public_key).unwrap();
    assert_eq!(
        sw(&mut pgp, &mut store, &apdu(0x2A, 0x80, 0x86, &dec)),
        0x6982
    );
    assert_eq!(
        sw(&mut pgp, &mut store, &apdu(0x88, 0, 0, &[0x11; 32])),
        0x6982
    );
    assert_eq!(cds(&mut pgp, &mut store), SW_OK);
    // Mode 82: deciphers and authenticates, never signs.
    assert_eq!(pw1(&mut pgp, &mut store, 0x82), SW_OK);
    assert_eq!(
        sw(&mut pgp, &mut store, &apdu(0x2A, 0x80, 0x86, &dec)),
        SW_OK
    );
    assert_eq!(
        sw(&mut pgp, &mut store, &apdu(0x88, 0, 0, &[0x11; 32])),
        SW_OK
    );
    assert_eq!(cds(&mut pgp, &mut store), 0x6982);
}

#[test]
fn algorithm_attributes_must_fit_the_role() {
    let (mut pgp, mut store) = card();
    let ecdsa_p256 = [0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let ecdh_p256 = [0x12, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let put = |pgp: &mut OpenPgp, store: &mut BlobStore, tag: u8, v: &[u8]| {
        sw(pgp, store, &apdu(0xDA, 0x00, tag, v))
    };
    // A key-agreement algorithm for the signature / authentication key,
    // or a signature algorithm for the decryption key: refused.
    assert_eq!(put(&mut pgp, &mut store, 0xC1, &ecdh_p256), 0x6A80);
    assert_eq!(put(&mut pgp, &mut store, 0xC3, &ecdh_p256), 0x6A80);
    assert_eq!(put(&mut pgp, &mut store, 0xC2, &ecdsa_p256), 0x6A80);
    // RSA (01) and unknown curves are not offered.
    assert_eq!(
        put(
            &mut pgp,
            &mut store,
            0xC1,
            &[0x01, 0x08, 0x00, 0x00, 0x20, 0x00]
        ),
        0x6A80
    );
    assert_eq!(
        put(&mut pgp, &mut store, 0xC1, &[0x13, 0x2B, 0x24, 0x03]),
        0x6A80
    );
    // The right ones, with or without the trailing format byte.
    assert_eq!(put(&mut pgp, &mut store, 0xC1, &ecdsa_p256), SW_OK);
    let mut with_fmt = [0u8; 10];
    with_fmt[..9].copy_from_slice(&ecdh_p256);
    with_fmt[9] = 0xFF;
    assert_eq!(put(&mut pgp, &mut store, 0xC2, &with_fmt), SW_OK);
    #[cfg(feature = "applet-openpgp-curve25519")]
    {
        let eddsa = [0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
        assert_eq!(put(&mut pgp, &mut store, 0xC3, &eddsa), SW_OK);
        assert_eq!(put(&mut pgp, &mut store, 0xC2, &eddsa), 0x6A80);
    }
}

#[test]
fn no_button_no_uif() {
    let (mut pgp, mut store) = card();
    let (s, f) = send(&mut pgp, &mut store, &apdu(0xCA, 0x7F, 0x74, &[]));
    assert_eq!((s, &f[..]), (SW_OK, &[0x81, 0x01, 0x00][..]));
    for tag in [0xD6, 0xD7, 0xD8] {
        assert_eq!(
            sw(&mut pgp, &mut store, &apdu(0xCA, 0x00, tag, &[])),
            0x6A88
        );
        assert_eq!(
            sw(&mut pgp, &mut store, &apdu(0xDA, 0x00, tag, &[0x01, 0x20])),
            0x6A88
        );
    }
    // 6E carries 7F74 too.
    let (_, ard) = send(&mut pgp, &mut store, &apdu(0xCA, 0x00, 0x6E, &[]));
    assert!(ard
        .windows(6)
        .any(|w| w == [0x7F, 0x74, 0x03, 0x81, 0x01, 0x00]));
}
