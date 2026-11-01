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

// ---------------------------------------------------------------------------
// Phase P2: enrollment — ISSUE_MEMBER_CERT (45), REVOKE_MEMBER (46),
// GET_MEMBERS v2 (47), IMPORT_MEMBER_CERT (49), IMPORT_REVOCATION (4A)
// ---------------------------------------------------------------------------

extern crate std;

use crate::domain::member::{MemberCert, MemberEntry, Revocation};
use pico2hsm_core::apdu::{
    SW_CONDITIONS_NOT_SATISFIED, SW_SECURITY_STATUS, SW_WRONG_DATA, SW_WRONG_LENGTH,
};

const SHARES: [[u8; 32]; 2] = [[0x3C; 32], [0x5A; 32]];

/// One simulated device: SO-PIN and user PIN verified, identity key set.
struct Dev {
    hsm: ScHsm,
    store: BlobStore,
    pubk: [u8; 65],
}

type Resp = (u16, heapless::Vec<u8, 4098>);

impl Dev {
    fn new() -> Self {
        let mut hsm = logged_in();
        hsm.state.so_pin_verified = true;
        let mut store = BlobStore::new();
        let pubk = with_identity(&mut store);
        Dev { hsm, store, pubk }
    }

    /// A device that formed the domain from `SHARES` (self-certified).
    fn from_shares() -> Self {
        let mut d = Self::new();
        assert_eq!(import_shares(&mut d.hsm, &mut d.store, &SHARES), SW_OK);
        d
    }

    fn id(&self) -> [u8; 16] {
        member::member_id(&self.pubk)
    }

    /// `80 54 p1 00 data` (extended length when the data needs it).
    fn x(&mut self, p1: u8, data: &[u8]) -> Resp {
        self.xp(p1, 0, data)
    }

    fn xp(&mut self, p1: u8, p2: u8, data: &[u8]) -> Resp {
        let mut a: heapless::Vec<u8, 600> = heapless::Vec::new();
        a.extend_from_slice(&[0x80, 0x54, p1, p2]).unwrap();
        if data.len() > 255 {
            a.extend_from_slice(&[0x00, (data.len() >> 8) as u8, data.len() as u8])
                .unwrap();
        } else if !data.is_empty() {
            a.push(data.len() as u8).unwrap();
        }
        a.extend_from_slice(data).unwrap();
        run(&mut self.hsm, &mut self.store, &a)
    }

    fn lamport(&mut self) -> u64 {
        lamport(&mut self.store)
    }

    /// The whole list through GET_MEMBERS v2.
    fn members(&mut self) -> std::vec::Vec<MemberEntry> {
        let mut out = std::vec::Vec::new();
        let mut first = 0u8;
        loop {
            let (sw, r) = self.xp(0x47, first, &[0x02]);
            assert_eq!(sw, SW_OK);
            let (total, n) = (r[0], r[2]);
            assert_eq!(r.len(), 3 + usize::from(n) * member::ENTRY_V2_LEN);
            for e in r[3..].chunks(member::ENTRY_V2_LEN) {
                out.push(MemberEntry::decode(e).unwrap());
            }
            first += n;
            if n == 0 || first >= total {
                return out;
            }
        }
    }

    fn entry(&mut self, id: &[u8; 16]) -> Option<MemberEntry> {
        self.members().into_iter().find(|e| e.cert.member_id == *id)
    }

    fn domain(&self) -> &DomainKey {
        self.hsm.state.domain.as_ref().unwrap()
    }
}

fn ok_with(b: u8) -> Resp {
    (SW_OK, heapless::Vec::from_slice(&[b]).unwrap())
}

/// Pin each other (3D) and run the V2 exchange `src` → `tgt` (35–38).
fn exchange(src: &mut Dev, tgt: &mut Dev) {
    let (sp, tp) = (src.pubk, tgt.pubk);
    assert_eq!(src.x(0x3D, &tp).0, SW_OK);
    assert_eq!(tgt.x(0x3D, &sp).0, SW_OK);
    let (sw, init) = tgt.x(0x35, &sp);
    assert_eq!(sw, SW_OK);
    let (sw, resp) = src.x(0x36, &init);
    assert_eq!(sw, SW_OK);
    let mut d: heapless::Vec<u8, 200> = heapless::Vec::new();
    d.extend_from_slice(&init[..65]).unwrap();
    d.extend_from_slice(&tp).unwrap();
    d.extend_from_slice(&init[65..97]).unwrap();
    let (sw, enc) = src.x(0x37, &d);
    assert_eq!(sw, SW_OK);
    let mut d: heapless::Vec<u8, 200> = heapless::Vec::new();
    d.extend_from_slice(&resp).unwrap();
    d.extend_from_slice(&enc).unwrap();
    assert_eq!(tgt.x(0x38, &d).0, SW_OK);
}

fn issue(sponsor: &mut Dev, subject: &[u8; 65]) -> Resp {
    sponsor.x(0x45, subject)
}

fn some_pub(seed: u8) -> [u8; 65] {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let sk = p256::SecretKey::from_slice(&[seed; 32]).unwrap();
    sk.public_key()
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}

/// `revocation || certificate`, for a member the importer has not seen.
fn rev_with_cert(rev: &[u8], cert: &MemberCert) -> std::vec::Vec<u8> {
    let mut v = rev.to_vec();
    v.extend_from_slice(&cert.encode());
    v
}

#[test]
fn issue_needs_the_so_pin_and_the_peer_the_exchange_just_served() {
    let (mut a, mut b) = (Dev::from_shares(), Dev::new());
    // Nothing exchanged or pinned yet: nothing to certify.
    assert_eq!(issue(&mut a, &b.pubk).0, SW_CONDITIONS_NOT_SATISFIED);
    exchange(&mut a, &mut b);
    assert_eq!(b.domain().id, a.domain().id, "same domain");
    assert_eq!(a.hsm.state.exchanged_peer, Some(b.pubk));

    a.hsm.state.so_pin_verified = false;
    assert_eq!(issue(&mut a, &b.pubk).0, SW_SECURITY_STATUS);
    a.hsm.state.so_pin_verified = true;
    // An arbitrary key is never certified, nor the sponsor itself.
    assert_eq!(issue(&mut a, &some_pub(9)).0, SW_SECURITY_STATUS);
    let own = a.pubk;
    assert_eq!(issue(&mut a, &own).0, SW_WRONG_DATA);
    let mut bad_flags: heapless::Vec<u8, 66> = heapless::Vec::new();
    bad_flags.extend_from_slice(&b.pubk).unwrap();
    bad_flags.push(0x02).unwrap();
    assert_eq!(a.x(0x45, &bad_flags).0, SW_WRONG_DATA);
    assert_eq!(a.x(0x45, &b.pubk[..64]).0, SW_WRONG_LENGTH);

    let before = a.lamport();
    let (sw, cert) = issue(&mut a, &b.pubk);
    assert_eq!(sw, SW_OK);
    let cert = MemberCert::decode(&cert).unwrap();
    assert_eq!(cert.verify(&a.domain().q), Ok(()));
    assert_eq!(cert.member_id, b.id());
    assert_eq!(cert.sponsor_id, a.id());
    assert_eq!(cert.flags, member::FLAG_MAY_SPONSOR, "default on (§12.3)");
    assert_eq!(cert.issued_lamport, before + 1, "numbered");
    assert_eq!(a.lamport(), before + 1);
    assert_eq!(a.entry(&b.id()).unwrap().cert, cert, "kept in the list");

    // Single use: the exchanged peer is spent.
    assert_eq!(a.hsm.state.exchanged_peer, None);
    assert_eq!(issue(&mut a, &b.pubk).0, SW_CONDITIONS_NOT_SATISFIED);
}

#[test]
fn issue_against_a_pinned_peer_spends_the_pin() {
    // §5.3: C formed from the same shares; A certifies it after pinning it.
    let (mut a, mut c) = (Dev::from_shares(), Dev::from_shares());
    assert_eq!(a.x(0x3D, &c.pubk).0, SW_OK);
    let (sw, cert) = issue(&mut a, &c.pubk);
    assert_eq!(sw, SW_OK);
    assert!(a.hsm.state.pinned_peer.is_none());
    assert!(a.store.load(records::PINNED_PEER).is_none(), "pin erased");
    // C replaces its self certificate with the sponsor's.
    assert_eq!(c.x(0x49, &cert), ok_with(0));
    let held = c.entry(&c.id()).unwrap().cert;
    assert_eq!(held.sponsor_id, a.id());
}

#[test]
fn only_a_member_that_may_sponsor_issues_or_revokes() {
    let (mut a, mut b) = (Dev::from_shares(), Dev::new());
    exchange(&mut a, &mut b);
    // B gets a certificate without the may-sponsor flag.
    let mut d: heapless::Vec<u8, 66> = heapless::Vec::new();
    d.extend_from_slice(&b.pubk).unwrap();
    d.push(0x00).unwrap();
    let (sw, cert) = a.x(0x45, &d);
    assert_eq!(sw, SW_OK);
    // B holds its own self certificate from the exchange; A's outranks it.
    assert!(b.entry(&b.id()).unwrap().cert.is_self_issued());
    assert_eq!(b.x(0x49, &cert).0, SW_OK);
    assert!(!b.entry(&b.id()).unwrap().cert.may_sponsor());

    let c = some_pub(4);
    assert_eq!(b.x(0x3D, &c).0, SW_OK);
    assert_eq!(issue(&mut b, &c).0, SW_SECURITY_STATUS);
    assert!(
        b.hsm.state.pinned_peer.is_some(),
        "a refused issue keeps the pin"
    );
    let aid = a.id();
    // B learns A's certificate, then still may not revoke it.
    let a_cert = a.entry(&aid).unwrap().cert.encode();
    assert_eq!(b.x(0x49, &a_cert).0, SW_OK);
    assert_eq!(b.x(0x46, &aid).0, SW_SECURITY_STATUS);
    // ...and without the SO-PIN nobody may.
    a.hsm.state.so_pin_verified = false;
    let bid = b.id();
    assert_eq!(a.x(0x46, &bid).0, SW_SECURITY_STATUS);
}

#[test]
fn import_checks_domain_signature_and_duplicates() {
    let (mut a, mut c) = (Dev::from_shares(), Dev::from_shares());
    let other = DomainKey::derive(&[0x99; 32]).unwrap();
    let p = some_pub(11);
    let pid = member::member_id(&p);

    // Another domain's certificate, and a tampered one.
    let foreign = MemberCert::issue(&other, &p, &pid, 5, 1).unwrap();
    assert_eq!(a.x(0x49, &foreign.encode()).0, SW_WRONG_DATA);
    let mut forged = MemberCert::issue(a.domain(), &p, &pid, 5, 1)
        .unwrap()
        .encode();
    forged[122] ^= 1;
    assert_eq!(a.x(0x49, &forged).0, SW_WRONG_DATA);
    assert_eq!(a.x(0x49, &forged[..186]).0, SW_WRONG_DATA);

    // C's self certificate: added once, then a duplicate.
    let cid = c.id();
    let c_self = c.entry(&cid).unwrap().cert.encode();
    assert_eq!(a.x(0x49, &c_self), ok_with(1));
    assert_eq!(a.x(0x49, &c_self).0, member::SW_ALREADY_HELD);
    // And A's self certificate goes into C: devices formed from the same
    // shares accept each other (§5.3).
    let aid = a.id();
    let a_self = a.entry(&aid).unwrap().cert.encode();
    assert_eq!(c.x(0x49, &a_self).0, SW_OK);
    assert_eq!(c.members().len(), 2);
    assert_eq!(a.members().len(), 2);

    // A higher self certificate replaces a lower one; a lower one is refused.
    let c_newer = MemberCert::issue(c.domain(), &c.pubk, &cid, 50, 1).unwrap();
    assert_eq!(a.x(0x49, &c_newer.encode()), ok_with(0));
    assert_eq!(a.x(0x49, &c_self).0, member::SW_ALREADY_HELD);
    // Import needs no PIN, but a domain.
    a.hsm.state.pin_verified = false;
    a.hsm.state.so_pin_verified = false;
    let q = MemberCert::issue(a.domain(), &some_pub(12), &pid, 1, 1).unwrap();
    assert_eq!(a.x(0x49, &q.encode()).0, SW_OK);
    let mut bare = Dev::new();
    assert_eq!(bare.x(0x49, &q.encode()).0, SW_CONDITIONS_NOT_SATISFIED);
    // Every certificate import fed the Lamport clock.
    assert!(a.hsm.state.lamport_seen >= 50);
}

#[test]
fn revoke_marks_the_member_and_the_revocation_travels() {
    let (mut a, mut b, mut c) = (Dev::from_shares(), Dev::new(), Dev::from_shares());
    exchange(&mut a, &mut b);
    let (_, b_cert) = issue(&mut a, &b.pubk);
    let b_cert = MemberCert::decode(&b_cert).unwrap();
    let (aid, bid, cid) = (a.id(), b.id(), c.id());

    assert_eq!(a.x(0x46, &aid).0, SW_WRONG_DATA, "no self-revocation");
    assert_eq!(a.x(0x46, &[0x77; 16]).0, member::SW_UNKNOWN_MEMBER);
    assert_eq!(a.x(0x46, &bid[..15]).0, SW_WRONG_LENGTH);
    let before = a.lamport();
    let (sw, rev) = a.x(0x46, &bid);
    assert_eq!(sw, SW_OK);
    assert_eq!(a.lamport(), before + 1, "numbered");
    let r = Revocation::decode(&rev).unwrap();
    assert_eq!(r.verify(&a.domain().q), Ok(()));
    assert_eq!(
        (r.member_id, r.revoker_id, r.revoked_lamport),
        (bid, aid, before + 1)
    );
    assert_eq!(a.x(0x46, &bid).0, member::SW_ALREADY_HELD);

    // GET_MEMBERS shows it: v2 with the record, v1 with the status.
    let e = a.entry(&bid).unwrap();
    assert_eq!(e.status(), member::STATUS_REVOKED);
    assert_eq!(e.revocation.as_ref().unwrap().encode()[..], rev[..]);
    let (_, v1) = a.x(0x47, &[]);
    assert_eq!(v1.len(), 3 + 2 * member::ENTRY_LEN);
    assert!(v1[3..]
        .chunks(member::ENTRY_LEN)
        .any(|c| c[1] == member::STATUS_REVOKED && c[27..43] == bid));

    // C has never seen B: the revocation alone is refused, with B's
    // certificate it is listed revoked.
    assert_eq!(c.x(0x4A, &rev).0, member::SW_UNKNOWN_MEMBER);
    assert_eq!(c.x(0x4A, &rev[..120]).0, SW_WRONG_LENGTH);
    let both = rev_with_cert(&rev, &b_cert);
    assert_eq!(c.x(0x4A, &both), ok_with(1));
    assert_eq!(c.x(0x4A, &both).0, member::SW_ALREADY_HELD);
    assert_eq!(c.entry(&bid).unwrap().status(), member::STATUS_REVOKED);
    // B itself accepts its own revocation (it learns it is revoked).
    assert_eq!(b.x(0x4A, &rev).0, SW_OK);
    let (_, st) = b.x(0x40, &[]);
    assert_ne!(st[1] & super::commands::extras::DS_SELF_REVOKED, 0);
    // A revoked device can no longer sponsor.
    assert_eq!(b.x(0x3D, &some_pub(3)).0, SW_OK);
    assert_eq!(issue(&mut b, &some_pub(3)).0, SW_SECURITY_STATUS);

    // Revocation is permanent for the member key: no certificate, however
    // new, brings B back — not imported, not issued.
    let newer = MemberCert::issue(c.domain(), &b.pubk, &aid, 1 << 40, 1).unwrap();
    assert_eq!(
        c.x(0x49, &newer.encode()).0,
        pico2hsm_core::apdu::SW_DATA_INVALID
    );
    assert_eq!(a.x(0x3D, &b.pubk).0, SW_OK);
    assert_eq!(
        issue(&mut a, &b.pubk).0,
        pico2hsm_core::apdu::SW_DATA_INVALID
    );

    // Of two revocations every device keeps the earliest.
    let earlier = Revocation::issue(c.domain(), &bid, &cid, 1).unwrap();
    assert_eq!(a.x(0x4A, &earlier.encode()), ok_with(0));
    assert_eq!(a.x(0x4A, &rev).0, member::SW_ALREADY_HELD);
    assert_eq!(a.entry(&bid).unwrap().revoked_lamport(), 1);

    // Forged or foreign revocations are refused.
    let mut bad = rev.clone();
    bad[60] ^= 1;
    assert_eq!(c.x(0x4A, &bad).0, SW_WRONG_DATA);
    let other = DomainKey::derive(&[0x98; 32]).unwrap();
    let foreign = Revocation::issue(&other, &aid, &cid, 3).unwrap();
    assert_eq!(c.x(0x4A, &foreign.encode()).0, SW_WRONG_DATA);
}

#[test]
fn certificates_from_a_revoked_sponsor_after_its_revocation_are_refused() {
    let mut a = Dev::from_shares();
    let s = some_pub(21);
    let sid = member::member_id(&s);
    let s_cert = MemberCert::issue(a.domain(), &s, &sid, 1, 1).unwrap();
    assert_eq!(a.x(0x49, &s_cert.encode()).0, SW_OK);
    let rev = Revocation::issue(a.domain(), &sid, &a.id(), 10).unwrap();
    assert_eq!(a.x(0x4A, &rev.encode()).0, SW_OK);
    let before = MemberCert::issue(a.domain(), &some_pub(22), &sid, 9, 1).unwrap();
    let after = MemberCert::issue(a.domain(), &some_pub(23), &sid, 11, 1).unwrap();
    assert_eq!(a.x(0x49, &before.encode()).0, SW_OK);
    assert_eq!(
        a.x(0x49, &after.encode()).0,
        pico2hsm_core::apdu::SW_DATA_INVALID
    );
}

#[test]
fn a_full_list_refuses_new_members_with_6a84() {
    let mut a = Dev::from_shares();
    for i in 1..member::MAX_MEMBERS {
        let p = some_pub(100 + i);
        let c = MemberCert::issue(a.domain(), &p, &member::member_id(&p), 1, 1).unwrap();
        assert_eq!(a.x(0x49, &c.encode()).0, SW_OK, "member {i}");
    }
    // Revoked entries count toward the cap (until P5 compaction).
    let first = member::member_id(&some_pub(101));
    assert_eq!(a.x(0x46, &first).0, SW_OK);
    assert_eq!(member::count(&mut a.store).unwrap(), member::MAX_MEMBERS);
    let (_, st) = a.x(0x40, &[]);
    assert_eq!((st[115], st[116]), (32, 32));

    let p = some_pub(200);
    let c = MemberCert::issue(a.domain(), &p, &member::member_id(&p), 1, 1).unwrap();
    assert_eq!(a.x(0x49, &c.encode()).0, member::SW_LIST_FULL);
    let r = Revocation::issue(a.domain(), &c.member_id, &a.id(), 4).unwrap();
    assert_eq!(
        a.x(0x4A, &rev_with_cert(&r.encode(), &c)).0,
        member::SW_LIST_FULL
    );
    // A known member still updates in place.
    let p1 = some_pub(102);
    let re = MemberCert::issue(a.domain(), &p1, &member::member_id(&p1), 9, 1).unwrap();
    assert_eq!(a.x(0x49, &re.encode()).0, SW_OK);
    // Issuing for a new member is refused before the counter moves.
    assert_eq!(a.x(0x3D, &p).0, SW_OK);
    let before = a.lamport();
    assert_eq!(issue(&mut a, &p).0, member::SW_LIST_FULL);
    assert_eq!(a.lamport(), before);
    assert!(a.hsm.state.pinned_peer.is_some(), "pin kept");
    // Paging: 14 entries per v2 page.
    assert_eq!(a.members().len(), 32);
    let (_, page) = a.xp(0x47, 0, &[0x02]);
    assert_eq!(page[2], 14);
    assert!(page.len() <= crate::apdu::dispatcher::MAX_RESPONSE_DATA);
    assert_eq!(a.xp(0x47, 0, &[0x03]).0, SW_WRONG_DATA);
}

#[test]
fn issue_and_revoke_fail_closed_when_flash_cannot_be_written() {
    let (mut a, mut b) = (Dev::from_shares(), Dev::new());
    exchange(&mut a, &mut b);
    let bid = b.id();
    a.store.counters.fail_lamport = true;
    assert_eq!(issue(&mut a, &b.pubk).0, SW_MEMORY_FAILURE);
    assert!(a.entry(&bid).is_none(), "nothing issued");
    assert_eq!(a.hsm.state.exchanged_peer, Some(b.pubk), "binding kept");
    a.store.counters.fail_lamport = false;
    assert_eq!(issue(&mut a, &b.pubk).0, SW_OK);
    a.store.counters.fail_lamport = true;
    assert_eq!(a.x(0x46, &bid).0, SW_MEMORY_FAILURE);
    a.store.counters.fail_lamport = false;
    assert_eq!(a.entry(&bid).unwrap().status(), member::STATUS_ACTIVE);
    // A list that cannot be written: 6581, and the entry stays active.
    a.store.fail_saves = true;
    assert_eq!(a.x(0x46, &bid).0, SW_MEMORY_FAILURE);
    a.store.fail_saves = false;
    assert_eq!(a.entry(&bid).unwrap().status(), member::STATUS_ACTIVE);
}

#[test]
fn the_list_and_revocations_survive_a_reload_but_the_binding_does_not() {
    let (mut a, mut b) = (Dev::from_shares(), Dev::new());
    exchange(&mut a, &mut b);
    let (_, cert) = issue(&mut a, &b.pubk);
    let bid = b.id();
    assert_eq!(a.x(0x46, &bid).0, SW_OK);
    let before = a.members();
    assert_eq!(before.len(), 2);

    // Exchange to a third device, then "reboot" A before issuing.
    let mut c = Dev::new();
    exchange(&mut a, &mut c);
    let mut fresh = ScHsm::new();
    ScHsm::load_dkek_from_store(&mut fresh.state, &mut a.store);
    ScHsm::load_domain_from_store(&mut fresh.state, &mut a.store);
    ScHsm::migrate_domain(&fresh.state, &mut a.store);
    fresh.state.initialized = true;
    fresh.state.so_pin_verified = true;
    a.hsm = fresh;
    assert_eq!(a.members(), before);
    assert_eq!(a.entry(&bid).unwrap().cert.encode()[..], cert[..]);
    assert_eq!(a.hsm.state.exchanged_peer, None, "session state");
    assert_eq!(issue(&mut a, &c.pubk).0, SW_CONDITIONS_NOT_SATISFIED);
}

#[test]
fn a_member_enrolled_through_b_is_accepted_by_a() {
    // A forms the domain, enrolls B; B enrolls C.  A never saw C's
    // enrollment, yet accepts C's certificate through the domain signature.
    let (mut a, mut b, mut c) = (Dev::from_shares(), Dev::new(), Dev::new());
    exchange(&mut a, &mut b);
    let (_, b_cert) = issue(&mut a, &b.pubk);
    assert_eq!(b.x(0x49, &b_cert).0, SW_OK);
    let aid = a.id();
    let a_self = a.entry(&aid).unwrap().cert.encode();
    assert_eq!(b.x(0x49, &a_self).0, SW_OK);
    exchange(&mut b, &mut c);
    let (sw, c_cert) = issue(&mut b, &c.pubk);
    assert_eq!(sw, SW_OK);
    assert_eq!(c.domain().id, a.domain().id);
    assert_eq!(a.x(0x49, &c_cert), ok_with(1));
    let cid = c.id();
    let held = a.entry(&cid).unwrap().cert;
    assert_eq!(held.sponsor_id, b.id());
    assert_eq!(held.verify(&a.domain().q), Ok(()));
    // C learns the rest of the list from B.
    for e in b.members() {
        let sw = c.x(0x49, &e.cert.encode()).0;
        assert!(sw == SW_OK || sw == member::SW_ALREADY_HELD, "{sw:04X}");
    }
    let mut ids: std::vec::Vec<[u8; 16]> = c.members().iter().map(|e| e.cert.member_id).collect();
    ids.sort();
    let mut want = std::vec![a.id(), b.id(), c.id()];
    want.sort();
    assert_eq!(ids, want);
}

// ---------------------------------------------------------------------------
// Security review of P2 (regressions)
// ---------------------------------------------------------------------------

#[test]
fn the_exchanged_peer_binding_ends_with_a_new_pin_or_a_new_exchange() {
    // A new pin (a new enrollment) ends it.
    let (mut a, mut b) = (Dev::from_shares(), Dev::new());
    exchange(&mut a, &mut b);
    assert_eq!(a.x(0x3D, &some_pub(31)).0, SW_OK);
    assert_eq!(a.hsm.state.exchanged_peer, None);
    assert_eq!(issue(&mut a, &b.pubk).0, SW_SECURITY_STATUS);

    // So does the start of another SOURCE run, even one that fails.
    let (mut a, mut b) = (Dev::from_shares(), Dev::new());
    exchange(&mut a, &mut b);
    assert_eq!(a.x(0x36, &[0u8; 161]).0, SW_CONDITIONS_NOT_SATISFIED);
    assert_eq!(a.hsm.state.exchanged_peer, None);
    assert_eq!(issue(&mut a, &b.pubk).0, SW_CONDITIONS_NOT_SATISFIED);
}

#[test]
fn imports_enforce_the_issuers_authority_where_it_is_known() {
    let (mut a, mut b) = (Dev::from_shares(), Dev::new());
    exchange(&mut a, &mut b);
    // A lists B without may-sponsor.
    let mut d: heapless::Vec<u8, 66> = heapless::Vec::new();
    d.extend_from_slice(&b.pubk).unwrap();
    d.push(0x00).unwrap();
    let (sw, b_cert) = a.x(0x45, &d);
    assert_eq!(sw, SW_OK);
    let b_cert = MemberCert::decode(&b_cert).unwrap();
    let (bid, aid) = (b.id(), a.id());

    // A certificate "issued by B" after that: refused.
    let p = some_pub(41);
    let by_b = MemberCert::issue(
        a.domain(),
        &p,
        &bid,
        b_cert.issued_lamport + 1,
        member::FLAG_MAY_SPONSOR,
    )
    .unwrap();
    assert_eq!(a.x(0x49, &by_b.encode()).0, SW_SECURITY_STATUS);
    assert!(a.entry(&by_b.member_id).is_none(), "nothing written");
    // A revocation "by B": refused too.
    let rev_by_b = Revocation::issue(a.domain(), &aid, &bid, b_cert.issued_lamport + 1).unwrap();
    assert_eq!(a.x(0x4A, &rev_by_b.encode()).0, SW_SECURITY_STATUS);
    assert_eq!(a.entry(&aid).unwrap().status(), member::STATUS_ACTIVE);
    // Acts older than B's demoting certificate are accepted (B may have
    // had the right then).
    let older = MemberCert::issue(a.domain(), &p, &bid, 1, 1).unwrap();
    assert!(b_cert.issued_lamport > 1);
    assert_eq!(a.x(0x49, &older.encode()).0, SW_OK);

    // A revoker revoked before its revocation: refused.
    let c = some_pub(42);
    let cid = member::member_id(&c);
    let c_cert = MemberCert::issue(a.domain(), &c, &cid, 1, 1).unwrap();
    assert_eq!(a.x(0x49, &c_cert.encode()).0, SW_OK);
    let (_, rev_c) = a.x(0x46, &cid);
    let rev_c = Revocation::decode(&rev_c).unwrap();
    let late = Revocation::issue(a.domain(), &bid, &cid, rev_c.revoked_lamport + 1).unwrap();
    assert_eq!(a.x(0x4A, &late.encode()).0, SW_SECURITY_STATUS);
    assert_eq!(a.entry(&bid).unwrap().status(), member::STATUS_ACTIVE);
}

#[test]
fn imports_cannot_push_the_lamport_counter_to_its_end() {
    let mut a = Dev::from_shares();
    let aid = a.id();
    let p = some_pub(51);
    let pid = member::member_id(&p);
    let seen = a.hsm.state.lamport_seen;
    for lamport in [u64::MAX, u64::MAX - 1, member::LAMPORT_CEILING + 1] {
        let c = MemberCert::issue(a.domain(), &p, &pid, lamport, 1).unwrap();
        assert_eq!(a.x(0x49, &c.encode()).0, SW_WRONG_DATA);
        let r = Revocation::issue(a.domain(), &pid, &aid, lamport).unwrap();
        let both = rev_with_cert(
            &r.encode(),
            &MemberCert::issue(a.domain(), &p, &pid, 1, 1).unwrap(),
        );
        assert_eq!(a.x(0x4A, &both).0, SW_WRONG_DATA);
    }
    assert_eq!(a.hsm.state.lamport_seen, seen, "the clock did not move");
    assert!(a.entry(&pid).is_none());
    // The ceiling itself is accepted, and numbered changes keep working.
    let c = MemberCert::issue(a.domain(), &p, &pid, member::LAMPORT_CEILING, 1).unwrap();
    assert_eq!(a.x(0x49, &c.encode()).0, SW_OK);
    assert_eq!(gen_p256(&mut a.hsm, &mut a.store, 1), SW_OK);
    assert_eq!(a.lamport(), member::LAMPORT_CEILING + 1);
    assert_eq!(a.x(0x46, &pid).0, SW_OK, "revoke numbers above it");
}

#[test]
fn duplicate_and_outranked_imports_cost_no_flash_write() {
    let (mut a, c) = (Dev::from_shares(), Dev::from_shares());
    let mut c = c;
    let cid = c.id();
    let c_self = c.entry(&cid).unwrap().cert.encode();
    assert_eq!(a.x(0x49, &c_self).0, SW_OK);
    let saves = a.store.saves;
    for _ in 0..5 {
        assert_eq!(a.x(0x49, &c_self).0, member::SW_ALREADY_HELD);
    }
    let r = Revocation::issue(a.domain(), &cid, &a.id(), 7).unwrap();
    assert_eq!(a.x(0x4A, &r.encode()).0, SW_OK);
    let saves_after_rev = a.store.saves;
    assert_eq!(saves_after_rev, saves + 1);
    for _ in 0..5 {
        assert_eq!(a.x(0x4A, &r.encode()).0, member::SW_ALREADY_HELD);
        assert_eq!(a.x(0x49, &c_self).0, pico2hsm_core::apdu::SW_DATA_INVALID);
    }
    assert_eq!(a.store.saves, saves_after_rev, "replays wrote nothing");
    let mut forged = c_self.clone();
    forged[150] ^= 1;
    assert_eq!(a.x(0x49, &forged).0, SW_WRONG_DATA);
    assert_eq!(a.store.saves, saves_after_rev);
}

/// Key reference 0 is the device key's (#36).  A booted device (key index
/// loaded from flash, no INITIALIZE this session) lists CC 00 without a
/// PRKD, so OpenSC's free-ID search starts user keys at 1; GENERATE KEY
/// PAIR refuses P1 = 00, and auto-assign (P1 = FF) picks 1.
#[test]
fn key_ref_zero_is_the_device_key() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    let list = |hsm: &mut ScHsm, store: &mut BlobStore| {
        let (sw, r) = run(hsm, store, &[0x80, 0x58, 0x00, 0x00, 0x00]);
        assert_eq!(sw, SW_OK);
        r.chunks(2)
            .map(|c| [c[0], c[1]])
            .collect::<std::vec::Vec<_>>()
    };
    assert_eq!(list(&mut hsm, &mut store), [[0xCC, 0x00]]);

    assert_eq!(gen_p256(&mut hsm, &mut store, 0x00), SW_INCORRECT_P1P2);
    assert!(hsm.state.key_index.is_empty());

    assert_eq!(gen_p256(&mut hsm, &mut store, 0xFF), SW_OK);
    let files = list(&mut hsm, &mut store);
    assert_eq!(files, [[0xCC, 0x00], [0xCC, 0x01], [0xC4, 0x01]]);
    assert!(!files.contains(&[0xC4, 0x00]));
}
