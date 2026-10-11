//! Host tests: cluster plan V3 phase P1 through the SC-HSM APDU path — the
//! Lamport counter numbering changes, object IDs following creation and
//! deletion, and the domain appearing when the DKEK is completed.

use super::policy_tests::BlobStore;
use super::*;
use crate::domain::{key::DomainKey, member, object_id, records};
use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
use crate::storage::KeyStore as _;

const P256_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> heapless::Vec<u8, 300> {
    let mut v = heapless::Vec::new();
    v.extend_from_slice(&[cla, ins, p1, p2, data.len() as u8])
        .unwrap();
    v.extend_from_slice(data).unwrap();
    v
}

fn run(hsm: &mut ScHsm, store: &mut BlobStore, a: &[u8]) -> (u16, heapless::Vec<u8, 4098>) {
    let mut r = hsm.process_apdu_with_store(a, store);
    let n = r.len();
    let sw = u16::from_be_bytes([r[n - 2], r[n - 1]]);
    r.truncate(n - 2);
    (sw, r)
}

fn logged_in() -> ScHsm {
    let mut hsm = ScHsm::new();
    hsm.state.initialized = true;
    hsm.state.pin_verified = true;
    hsm
}

fn gen_p256(hsm: &mut ScHsm, store: &mut BlobStore, key_ref: u8) -> u16 {
    let mut d: heapless::Vec<u8, 64> = heapless::Vec::new();
    d.extend_from_slice(&[0x5F, 0x29, 0x01, 0x00, 0x7F, 0x49, 0x22, 0x85, 0x20])
        .unwrap();
    d.extend_from_slice(&P256_ORDER).unwrap();
    run(hsm, store, &apdu(0x00, 0x46, key_ref, 0x00, &d)).0
}

fn gen_aes(hsm: &mut ScHsm, store: &mut BlobStore, key_ref: u8) -> u16 {
    run(hsm, store, &apdu(0x00, 0x48, key_ref, 0x00, &[0x84])).0
}

fn delete(hsm: &mut ScHsm, store: &mut BlobStore, fid: u16) -> u16 {
    run(
        hsm,
        store,
        &apdu(0x00, 0xE4, 0x02, 0x00, &fid.to_be_bytes()),
    )
    .0
}

fn write_ef(hsm: &mut ScHsm, store: &mut BlobStore, fid: u16, body: &[u8]) -> u16 {
    let mut d: heapless::Vec<u8, 200> = heapless::Vec::new();
    d.extend_from_slice(&[0x54, 0x02, 0x00, 0x00, 0x53, body.len() as u8])
        .unwrap();
    d.extend_from_slice(body).unwrap();
    let [hi, lo] = fid.to_be_bytes();
    run(hsm, store, &apdu(0x00, 0xD7, hi, lo, &d)).0
}

fn lamport(store: &mut BlobStore) -> u64 {
    store.counters.lamport
}

#[test]
fn lamport_numbers_each_change_and_ids_follow_the_objects() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    assert_eq!(lamport(&mut store), 0);

    // Asymmetric key: numbered, intrinsic ID, no sidecar.
    assert_eq!(gen_p256(&mut hsm, &mut store, 1), SW_OK);
    assert_eq!(lamport(&mut store), 1);
    let k1 = KeyId::sc_hsm(0, 1);
    assert!(store.load(records::sidecar(k1)).is_none());
    let obj = store.load(k1).unwrap();
    assert_eq!(
        object_id::intrinsic(&obj).unwrap().bytes,
        crate::crypto::symmetric::sha1(&obj.public_key[1..33])
    );

    // Symmetric key: numbered, random 16-byte ID in its sidecar.
    assert_eq!(gen_aes(&mut hsm, &mut store, 2), SW_OK);
    assert_eq!(lamport(&mut store), 2);
    let k2 = KeyId::sc_hsm(0, 2);
    let sc = object_id::load_sidecar(&mut store, k2).unwrap().unwrap();
    assert_eq!(sc.id.len, 16);
    assert_eq!(sc.kind, object_id::KIND_KEY);

    // A standalone EF gets an ID when created, not when rewritten; a
    // key's PRKD never gets one.
    assert_eq!(write_ef(&mut hsm, &mut store, 0xCD01, b"data"), SW_OK);
    assert_eq!(lamport(&mut store), 3);
    let ef = KeyId::sc_hsm_ef(0, 0xCD, 0x01);
    let id = object_id::load_sidecar(&mut store, ef).unwrap().unwrap().id;
    assert_eq!(write_ef(&mut hsm, &mut store, 0xCD01, b"more"), SW_OK);
    assert_eq!(
        object_id::load_sidecar(&mut store, ef).unwrap().unwrap().id,
        id
    );
    assert_eq!(write_ef(&mut hsm, &mut store, 0xC401, b"prkd"), SW_OK);
    assert!(store
        .load(records::sidecar(KeyId::sc_hsm_ef(0, 0xC4, 0x01)))
        .is_none());
    assert_eq!(lamport(&mut store), 5);

    // Deletion: numbered, sidecar gone.
    assert_eq!(delete(&mut hsm, &mut store, 0xCC02), SW_OK);
    assert_eq!(lamport(&mut store), 6);
    assert!(store.load(records::sidecar(k2)).is_none());
    assert_eq!(delete(&mut hsm, &mut store, 0xCD01), SW_OK);
    assert!(store.load(records::sidecar(ef)).is_none());
    assert_eq!(lamport(&mut store), 7);
}

#[test]
fn unauthenticated_commands_spend_no_counter() {
    let (mut hsm, mut store) = (ScHsm::new(), BlobStore::new());
    hsm.state.initialized = true;
    assert_ne!(gen_p256(&mut hsm, &mut store, 1), SW_OK);
    assert_ne!(delete(&mut hsm, &mut store, 0xCC01), SW_OK);
    assert_eq!(lamport(&mut store), 0);
}

#[test]
fn counter_that_cannot_be_written_refuses_the_change() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    store.counters.fail_lamport = true;
    assert_eq!(gen_p256(&mut hsm, &mut store, 1), SW_MEMORY_FAILURE);
    assert!(store.blobs.is_empty(), "nothing changed");
    assert!(hsm.state.key_index.is_empty());
}

#[test]
fn counter_never_goes_down_and_absorbs_seen_versions() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    hsm.state.lamport_seen = 40;
    assert_eq!(gen_p256(&mut hsm, &mut store, 1), SW_OK);
    assert_eq!(lamport(&mut store), 41, "max(counter, seen) + 1");
    hsm.state.lamport_seen = 3;
    assert_eq!(gen_p256(&mut hsm, &mut store, 2), SW_OK);
    assert_eq!(lamport(&mut store), 42);
}

/// Store the device identity key (0xFE) the way INITIALIZE does.
fn with_identity(store: &mut BlobStore) -> [u8; 65] {
    let pair =
        crate::crypto::asymmetric::generate_ec_keypair(CoreKeyType::EcPrivateP256, &mut FwRng)
            .unwrap();
    let mut obj = KeyObject::new(
        KmKeyType::Ec,
        KeyId::sc_hsm(0, 0xFE).0,
        AppletId::ScHsm,
        AlgorithmId::EcdsaP256,
    );
    obj.private_key
        .extend_from_slice(&pair.private_key)
        .unwrap();
    obj.public_key.extend_from_slice(&pair.public_key).unwrap();
    store.save_key(&obj).unwrap();
    pair.public_key.as_slice().try_into().unwrap()
}

fn import_shares(hsm: &mut ScHsm, store: &mut BlobStore, shares: &[[u8; 32]]) -> u16 {
    hsm.state.dkek.init_shares(shares.len() as u8);
    let mut last = 0;
    for s in shares {
        last = run(hsm, store, &apdu(0x80, 0x52, 0x00, 0x00, s)).0;
    }
    last
}

#[test]
fn completing_the_dkek_forms_the_domain_and_self_certifies() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    let own = with_identity(&mut store);
    let shares = [[0x0F; 32], [0xF0; 32]];
    assert_eq!(import_shares(&mut hsm, &mut store, &shares), SW_OK);

    let want = DomainKey::derive(&[0xFF; 32]).unwrap();
    let domain = hsm.state.domain.as_ref().expect("domain key derived");
    assert_eq!(domain.id, want.id);
    assert_eq!(member::count(&mut store).unwrap(), 1);
    let e = member::load(&mut store, 0).unwrap().unwrap();
    assert_eq!(e.cert.member_pub, own);
    assert_eq!(e.cert.verify(&want.q), Ok(()));
    assert_eq!(e.cert.flags, member::FLAG_MAY_SPONSOR);
    assert_eq!(lamport(&mut store), 1, "the certificate was numbered");

    // A reset re-derives the same key and issues nothing new.
    let mut fresh = ScHsm::new();
    ScHsm::load_dkek_from_store(&mut fresh.state, &mut store);
    ScHsm::load_domain_from_store(&mut fresh.state, &mut store);
    ScHsm::migrate_domain(&fresh.state, &mut store);
    assert_eq!(fresh.state.domain.as_ref().unwrap().q, want.q);
    assert_eq!(member::count(&mut store).unwrap(), 1);
    assert_eq!(lamport(&mut store), 1);
}

#[test]
fn two_devices_from_the_same_shares_share_the_domain_not_the_identity() {
    let shares = [[0x21; 32], [0x43; 32], [0x65; 32]];
    let mut ids = heapless::Vec::<([u8; 16], [u8; 16]), 2>::new();
    for _ in 0..2 {
        let (mut hsm, mut store) = (logged_in(), BlobStore::new());
        with_identity(&mut store);
        assert_eq!(import_shares(&mut hsm, &mut store, &shares), SW_OK);
        let e = member::load(&mut store, 0).unwrap().unwrap();
        ids.push((e.cert.domain_id, e.cert.member_id)).unwrap();
    }
    assert_eq!(ids[0].0, ids[1].0, "same domain_id");
    assert_ne!(ids[0].1, ids[1].1, "distinct member IDs, no serial clash");
}

#[test]
fn a_dkek_from_before_the_upgrade_self_certifies_at_boot() {
    let mut store = BlobStore::new();
    with_identity(&mut store);
    let mut old = ScHsm::new();
    old.state.dkek.set_dkek_direct(&[0x77; 32]);
    ScHsm::save_dkek_to_store(&old.state, &mut store).unwrap();
    assert_eq!(member::count(&mut store).unwrap(), 0);

    let mut hsm = ScHsm::new();
    ScHsm::load_dkek_from_store(&mut hsm.state, &mut store);
    ScHsm::load_domain_from_store(&mut hsm.state, &mut store);
    assert_eq!(
        member::count(&mut store).unwrap(),
        0,
        "loading writes nothing"
    );
    ScHsm::migrate_domain(&hsm.state, &mut store);
    assert_eq!(member::count(&mut store).unwrap(), 1);
    let q = DomainKey::derive(&[0x77; 32]).unwrap().q;
    assert_eq!(
        member::load(&mut store, 0)
            .unwrap()
            .unwrap()
            .cert
            .verify(&q),
        Ok(())
    );
}

#[test]
fn initialize_wipes_the_domain_but_not_the_counter() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    with_identity(&mut store);
    assert_eq!(import_shares(&mut hsm, &mut store, &[[0x0A; 32]]), SW_OK);
    assert!(hsm.state.domain.is_some());
    let before = lamport(&mut store);
    // INITIALIZE (fresh: no SO-PIN on record yet), init code 8 bytes.
    hsm.state.initialized = false;
    hsm.state.so_pin_hash = None;
    let init = [
        0x80, 0x50, 0x00, 0x00, 0x0A, 0x82, 0x08, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8',
    ];
    assert_eq!(run(&mut hsm, &mut store, &init).0, SW_OK);
    assert!(hsm.state.domain.is_none());
    assert_eq!(member::count(&mut store).unwrap(), 0);
    assert_eq!(lamport(&mut store), before);
}

fn read_prkd(
    hsm: &mut ScHsm,
    store: &mut BlobStore,
    key_ref: u8,
) -> (u16, heapless::Vec<u8, 4098>) {
    run(
        hsm,
        store,
        &apdu(
            0x00,
            0xB1,
            0x00,
            0x00,
            &[0x54, 0x04, 0xC4, key_ref, 0x00, 0x00],
        ),
    )
}

#[test]
fn synthesised_prkd_carries_the_intrinsic_ckaid() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    assert_eq!(gen_p256(&mut hsm, &mut store, 3), SW_OK);
    let obj = store.load(KeyId::sc_hsm(0, 3)).unwrap();
    let want = crate::crypto::symmetric::sha1(&obj.public_key[1..33]);
    let (sw, prkd) = read_prkd(&mut hsm, &mut store, 3);
    assert_eq!(sw, SW_OK);
    let mut id_tlv = [0u8; 22];
    id_tlv[0] = 0x04;
    id_tlv[1] = 0x14;
    id_tlv[2..].copy_from_slice(&want);
    assert!(
        prkd.windows(22).any(|w| w == id_tlv),
        "CKA_ID = SHA-1(x), not the slot"
    );
    // A PRKD written by OpenSC is served as written.
    assert_eq!(write_ef(&mut hsm, &mut store, 0xC403, b"\x30\x00"), SW_OK);
    let (_, prkd) = read_prkd(&mut hsm, &mut store, 3);
    assert_eq!(&prkd[..], b"\x30\x00");
}
