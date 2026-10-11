//! Host tests: PIV key usage per SP 800-73-4 and the Yubico PIN / touch
//! policy extension (audit S-10).

use super::*;
use crate::protocol::sc_hsm::policy_tests::BlobStore;
use pico2hsm_core::apdu::SW_OK;

type Out = (u16, heapless::Vec<u8, 4098>);

fn send(piv: &mut Piv, store: &mut BlobStore, a: &[u8]) -> Out {
    let mut r = piv.process_apdu_with_store(a, store);
    let n = r.len();
    let sw = u16::from_be_bytes([r[n - 2], r[n - 1]]);
    r.truncate(n - 2);
    (sw, r)
}

fn apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> heapless::Vec<u8, 300> {
    let mut v = heapless::Vec::new();
    v.extend_from_slice(&[0x00, ins, p1, p2, data.len() as u8])
        .unwrap();
    v.extend_from_slice(data).unwrap();
    v
}

fn verify(piv: &mut Piv, store: &mut BlobStore) -> u16 {
    send(piv, store, &apdu(0x20, 0x00, 0x80, b"123456\xFF\xFF")).0
}

/// GENERATE (management key assumed authenticated) with extra AC TLVs.
fn generate(piv: &mut Piv, store: &mut BlobStore, slot: u8, extra: &[u8]) -> Out {
    piv.state.mgmt_key_authenticated = true;
    let mut ac: heapless::Vec<u8, 32> = heapless::Vec::new();
    ac.extend_from_slice(&[0xAC, 3 + extra.len() as u8, 0x80, 0x01, 0x11])
        .unwrap();
    ac.extend_from_slice(extra).unwrap();
    let r = send(piv, store, &apdu(0x47, 0x00, slot, &ac));
    piv.state.mgmt_key_authenticated = false;
    r
}

fn sign(piv: &mut Piv, store: &mut BlobStore, slot: u8) -> u16 {
    let mut d: heapless::Vec<u8, 64> = heapless::Vec::new();
    d.extend_from_slice(&[0x7C, 0x24, 0x82, 0x00, 0x81, 0x20])
        .unwrap();
    d.extend_from_slice(&[0x5A; 32]).unwrap();
    send(piv, store, &apdu(0x87, 0x11, slot, &d)).0
}

fn ecdh(piv: &mut Piv, store: &mut BlobStore, slot: u8, point: &[u8]) -> Out {
    let mut d: heapless::Vec<u8, 100> = heapless::Vec::new();
    d.extend_from_slice(&[
        0x7C,
        4 + point.len() as u8,
        0x82,
        0x00,
        0x85,
        point.len() as u8,
    ])
    .unwrap();
    d.extend_from_slice(point).unwrap();
    send(piv, store, &apdu(0x87, 0x11, slot, &d))
}

fn fresh() -> (Piv, BlobStore) {
    (Piv::new(), BlobStore::new())
}

#[test]
fn pin_policy_always_needs_a_verify_before_each_use() {
    let (mut piv, mut store) = fresh();
    assert_eq!(
        generate(&mut piv, &mut store, 0x9A, &[0xAA, 0x01, 0x03]).0,
        SW_OK
    );
    assert_eq!(generate(&mut piv, &mut store, 0x9E, &[]).0, SW_OK);
    assert_eq!(sign(&mut piv, &mut store, 0x9A), 0x6982);
    assert_eq!(verify(&mut piv, &mut store), SW_OK);
    assert_eq!(sign(&mut piv, &mut store, 0x9A), SW_OK);
    assert_eq!(sign(&mut piv, &mut store, 0x9A), 0x6982, "used up");
    // A VERIFY, then a use of another slot: no longer "right before".
    assert_eq!(verify(&mut piv, &mut store), SW_OK);
    assert_eq!(sign(&mut piv, &mut store, 0x9E), SW_OK);
    assert_eq!(sign(&mut piv, &mut store, 0x9A), 0x6982);
    // Survives a reset: the policy is stored with the key.
    let mut piv2 = Piv::new();
    piv2.load_from_store(&mut store);
    assert_eq!(verify(&mut piv2, &mut store), SW_OK);
    assert_eq!(sign(&mut piv2, &mut store, 0x9A), SW_OK);
    assert_eq!(sign(&mut piv2, &mut store, 0x9A), 0x6982);
}

#[test]
fn pin_policy_never_and_once() {
    let (mut piv, mut store) = fresh();
    assert_eq!(
        generate(&mut piv, &mut store, 0x9A, &[0xAA, 0x01, 0x01]).0,
        SW_OK
    );
    assert_eq!(sign(&mut piv, &mut store, 0x9A), SW_OK, "never: no PIN");
    assert_eq!(
        generate(&mut piv, &mut store, 0x9C, &[0xAA, 0x01, 0x02]).0,
        SW_OK
    );
    assert_eq!(sign(&mut piv, &mut store, 0x9C), 0x6982);
    assert_eq!(verify(&mut piv, &mut store), SW_OK);
    assert_eq!(sign(&mut piv, &mut store, 0x9C), SW_OK);
    assert_eq!(
        sign(&mut piv, &mut store, 0x9C),
        SW_OK,
        "once: whole session"
    );
    // VERIFY P1=FF resets the PIN status (SP 800-73-4 §3.2.1).
    assert_eq!(
        send(&mut piv, &mut store, &apdu(0x20, 0xFF, 0x80, &[])).0,
        SW_OK
    );
    assert_eq!(sign(&mut piv, &mut store, 0x9C), 0x6982);
}

#[test]
fn slot_defaults_follow_sp800_73_4() {
    let (mut piv, mut store) = fresh();
    for slot in [0x9A, 0x9C, 0x9D, 0x9E, 0x82, 0x95] {
        assert_eq!(
            generate(&mut piv, &mut store, slot, &[]).0,
            SW_OK,
            "{slot:02X}"
        );
    }
    // 9E: no PIN.  9A: PIN once.  9C: PIN always.
    assert_eq!(sign(&mut piv, &mut store, 0x9E), SW_OK);
    assert_eq!(sign(&mut piv, &mut store, 0x9A), 0x6982);
    assert_eq!(sign(&mut piv, &mut store, 0x9C), 0x6982);
    assert_eq!(verify(&mut piv, &mut store), SW_OK);
    assert_eq!(sign(&mut piv, &mut store, 0x9C), SW_OK);
    assert_eq!(sign(&mut piv, &mut store, 0x9A), SW_OK);
    assert_eq!(sign(&mut piv, &mut store, 0x9A), SW_OK);
    assert_eq!(sign(&mut piv, &mut store, 0x9C), 0x6982);
    // Key management keys (9D, retired 82..95) need the PIN too.
    let peer = crate::crypto::asymmetric::generate_ec_keypair(
        pico2hsm_core::key::KeyType::EcPrivateP256,
        &mut crate::protocol::sc_hsm::FwRng,
    )
    .unwrap();
    for slot in [0x9D, 0x82, 0x95] {
        let (sw, r) = ecdh(&mut piv, &mut store, slot, &peer.public_key);
        assert_eq!(sw, SW_OK, "{slot:02X}");
        assert_eq!(&r[..4], &[0x7C, 0x22, 0x82, 0x20]);
    }
    let mut p2 = Piv::new();
    p2.load_from_store(&mut store);
    assert_eq!(ecdh(&mut p2, &mut store, 0x9D, &peer.public_key).0, 0x6982);
}

#[test]
fn key_use_follows_the_slot() {
    let (mut piv, mut store) = fresh();
    for slot in [0x9A, 0x9D, 0x83] {
        assert_eq!(generate(&mut piv, &mut store, slot, &[]).0, SW_OK);
    }
    assert_eq!(verify(&mut piv, &mut store), SW_OK);
    let peer = crate::crypto::asymmetric::generate_ec_keypair(
        pico2hsm_core::key::KeyType::EcPrivateP256,
        &mut crate::protocol::sc_hsm::FwRng,
    )
    .unwrap();
    // Key management keys don't sign; signature keys don't agree keys.
    assert_eq!(sign(&mut piv, &mut store, 0x9D), 0x6A80);
    assert_eq!(sign(&mut piv, &mut store, 0x83), 0x6A80);
    assert_eq!(ecdh(&mut piv, &mut store, 0x9A, &peer.public_key).0, 0x6A80);
    assert_eq!(ecdh(&mut piv, &mut store, 0x9D, &peer.public_key).0, SW_OK);
    // The shared secret is the ECDH x-coordinate.
    let (_, r) = ecdh(&mut piv, &mut store, 0x83, &peer.public_key);
    let obj = store.load(pico2hsm_core::key::KeyId::piv(0x83)).unwrap();
    let z = crate::crypto::asymmetric::ecdh_agree(
        pico2hsm_core::key::KeyType::EcPrivateP256,
        &peer.private_key,
        &obj.public_key,
    )
    .unwrap();
    assert_eq!(&r[4..], &z[..]);
}

#[test]
fn unsupported_policies_are_refused() {
    let (mut piv, mut store) = fresh();
    for extra in [
        &[0xAB, 0x01, 0x02][..], // touch always: no button
        &[0xAB, 0x01, 0x03],     // touch cached
        &[0xAA, 0x01, 0x04],     // PIN match-once (biometric)
        &[0xAA, 0x02, 0x01, 0x01],
        &[0xAA, 0x01, 0x01, 0xAA, 0x01, 0x02], // repeated
    ] {
        assert_eq!(
            generate(&mut piv, &mut store, 0x9A, extra).0,
            0x6A80,
            "{extra:02X?}"
        );
    }
    assert!(piv.state.key_index.is_empty());
    // Touch "default" and "never" are accepted.
    assert_eq!(
        generate(&mut piv, &mut store, 0x9A, &[0xAB, 0x01, 0x01]).0,
        SW_OK
    );
    assert_eq!(
        generate(&mut piv, &mut store, 0x9C, &[0xAB, 0x01, 0x00]).0,
        SW_OK
    );
}

#[test]
fn get_metadata_reports_policy_and_credentials() {
    let (mut piv, mut store) = fresh();
    let (_, gen) = generate(&mut piv, &mut store, 0x9A, &[0xAA, 0x01, 0x03]);
    let (sw, m) = send(&mut piv, &mut store, &apdu(0xF7, 0x00, 0x9A, &[]));
    assert_eq!(sw, SW_OK);
    assert!(m.starts_with(&[0x01, 0x01, 0x11, 0x02, 0x02, 0x03, 0x01, 0x03, 0x01, 0x01]));
    // 04 carries the same point GENERATE returned.
    let point = &gen[gen.len() - 65..];
    assert!(m.ends_with(point));
    // Default policy reported as the effective one: 9C always.
    generate(&mut piv, &mut store, 0x9C, &[]);
    let (_, m) = send(&mut piv, &mut store, &apdu(0xF7, 0x00, 0x9C, &[]));
    assert_eq!(&m[3..7], &[0x02, 0x02, 0x03, 0x01]);
    // Empty slot.
    assert_eq!(
        send(&mut piv, &mut store, &apdu(0xF7, 0x00, 0x9D, &[])).0,
        0x6A88
    );
    // PIN: default, 3 of 3 retries.  Management key: 3DES, default.
    let (_, m) = send(&mut piv, &mut store, &apdu(0xF7, 0x00, 0x80, &[]));
    assert_eq!(
        &m[..],
        &[0x01, 0x01, 0xFF, 0x05, 0x01, 0x01, 0x06, 0x02, 0x03, 0x03]
    );
    let (_, m) = send(&mut piv, &mut store, &apdu(0xF7, 0x00, 0x9B, &[]));
    assert_eq!(&m[..3], &[0x01, 0x01, 0x03]);
    assert!(m.ends_with(&[0x05, 0x01, 0x01]));
}
