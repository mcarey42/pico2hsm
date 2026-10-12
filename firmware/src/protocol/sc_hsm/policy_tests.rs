//! Host tests: SmartCard-HSM key usage policy (audit S-10) end to end —
//! APDU in, encrypted object on "flash" out.

use super::*;
use crate::security::key_management::KeyObject;
use crate::security::key_policy::*;
use pico2hsm_core::apdu::{SW_CONDITIONS_NOT_SATISFIED, SW_MEMORY_FAILURE, SW_WRONG_DATA};

const SMK: [u8; 32] = [0x5A; 32];

/// Keeps every object as the encrypted blob the real keystore would write,
/// so policies go through the on-flash format on every save and load.
pub(crate) struct BlobStore {
    pub blobs: heapless::Vec<
        (
            u32,
            heapless::Vec<u8, { crate::security::key_management::MAX_BLOB_SIZE }>,
        ),
        48,
    >,
    /// Retry counters (PIN / PUK / PW1 / PW3).
    pub counters: crate::storage::retry_counter::MemCounters,
    /// Number of successful saves.
    pub saves: usize,
    /// Fail every save.
    pub fail_saves: bool,
}

impl BlobStore {
    pub fn new() -> Self {
        BlobStore {
            blobs: heapless::Vec::new(),
            counters: Default::default(),
            saves: 0,
            fail_saves: false,
        }
    }
    pub fn load(&self, kid: KeyId) -> Option<KeyObject> {
        self.blobs
            .iter()
            .find(|(k, _)| *k == kid.0)
            .map(|(_, b)| KeyObject::decrypt(b, kid.0, &SMK).unwrap())
    }
    pub fn magic(&self, kid: KeyId) -> [u8; 4] {
        let (_, b) = self.blobs.iter().find(|(k, _)| *k == kid.0).unwrap();
        b[..4].try_into().unwrap()
    }
}

impl crate::storage::KeyStore for BlobStore {
    fn save_key(&mut self, obj: &KeyObject) -> Result<(), HsmError> {
        if self.fail_saves {
            return Err(HsmError::NotSupported);
        }
        let blob = obj.encrypt(&SMK, &[7u8; 12]).unwrap();
        self.blobs.retain(|(k, _)| *k != obj.key_id);
        self.blobs.push((obj.key_id, blob)).unwrap();
        self.saves += 1;
        Ok(())
    }
    fn fetch_key(&mut self, kid: KeyId) -> Result<Option<KeyObject>, HsmError> {
        Ok(self.load(kid))
    }
    fn erase_key(&mut self, kid: KeyId) -> Result<(), HsmError> {
        self.blobs.retain(|(k, _)| *k != kid.0);
        Ok(())
    }
    fn wipe_all(&mut self) -> Result<(), HsmError> {
        self.blobs.clear();
        Ok(())
    }
    fn wipe_by_owner(&mut self, _: AppletId) -> Result<(), HsmError> {
        self.blobs.clear();
        Ok(())
    }
    fn enumerate_keys(&self) -> Vec<KeyId, 64> {
        self.blobs.iter().map(|(k, _)| KeyId(*k)).collect()
    }
    fn for_each_key(&self, f: &mut dyn FnMut(KeyId)) {
        for (k, _) in self.blobs.iter() {
            f(KeyId(*k));
        }
    }
    fn retry_counters(&mut self) -> Option<&mut dyn RetryCounterBackend> {
        Some(&mut self.counters)
    }
}

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

/// GAKP data for a P-256 key with the given attribute TLVs appended.
fn gakp(attrs: &[u8]) -> heapless::Vec<u8, 200> {
    let mut d = heapless::Vec::new();
    d.extend_from_slice(&[0x5F, 0x29, 0x01, 0x00, 0x7F, 0x49, 0x22, 0x85, 0x20])
        .unwrap();
    d.extend_from_slice(&P256_ORDER).unwrap();
    d.extend_from_slice(attrs).unwrap();
    d
}

fn generate(hsm: &mut ScHsm, store: &mut BlobStore, key_ref: u8, attrs: &[u8]) -> u16 {
    run(hsm, store, &apdu(0x00, 0x46, key_ref, 0x00, &gakp(attrs))).0
}

fn sign(hsm: &mut ScHsm, store: &mut BlobStore, key_ref: u8, algo: u8) -> u16 {
    let data = [0x11u8; 32];
    run(hsm, store, &apdu(0x80, 0x68, key_ref, algo, &data)).0
}

#[test]
fn algorithm_list_allows_listed_and_refuses_others() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    assert_eq!(
        generate(&mut hsm, &mut store, 1, &[0x91, 0x01, 0x73]),
        SW_OK
    );
    assert_eq!(store.magic(KeyId::sc_hsm(0, 1)), *b"P2KP");
    assert_eq!(sign(&mut hsm, &mut store, 1, ALGO_EC_SHA256), SW_OK);
    assert_eq!(
        sign(&mut hsm, &mut store, 1, ALGO_EC_RAW),
        SW_CONDITIONS_NOT_SATISFIED
    );
    // ECDH (DECIPHER 80) is not in the list either.
    let point = [0x04u8; 65];
    let (sw, _) = run(&mut hsm, &mut store, &apdu(0x80, 0x62, 1, 0x80, &point));
    assert_eq!(sw, SW_CONDITIONS_NOT_SATISFIED);
    // Nor is GENERAL AUTHENTICATE (ECDSA SHA-256 = 73: allowed) ...
    hsm.state.current_key_id = Some(1);
    let ga = [0x7C, 0x04, 0x81, 0x02, 0xAB, 0xCD];
    assert_eq!(
        run(&mut hsm, &mut store, &apdu(0x00, 0x86, 0, 0, &ga)).0,
        SW_OK
    );
    // ... but the proprietary HKDF derive has no CardContact ID: refused.
    let (sw, _) = run(&mut hsm, &mut store, &apdu(0x80, 0x62, 0x01, 0x00, b"info"));
    assert_eq!(sw, SW_CONDITIONS_NOT_SATISFIED);
    // PSO:CDS goes through the same check with the MSE algorithm.
    hsm.state.current_algo = Some(ALGO_EC_RAW);
    let (sw, _) = run(
        &mut hsm,
        &mut store,
        &apdu(0x00, 0x2A, 0x9E, 0x9A, &[0x22; 32]),
    );
    assert_eq!(sw, SW_CONDITIONS_NOT_SATISFIED);
    hsm.state.current_algo = Some(ALGO_EC_SHA256);
    let (sw, _) = run(
        &mut hsm,
        &mut store,
        &apdu(0x00, 0x2A, 0x9E, 0x9A, &[0x22; 32]),
    );
    assert_eq!(sw, SW_OK);
}

#[test]
fn use_counter_runs_out_and_persists() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    let attrs = [0x90, 0x04, 0, 0, 0, 2];
    assert_eq!(generate(&mut hsm, &mut store, 2, &attrs), SW_OK);
    assert_eq!(sign(&mut hsm, &mut store, 2, ALGO_EC_RAW), SW_OK);
    assert_eq!(
        store.load(KeyId::sc_hsm(0, 2)).unwrap().policy.use_counter,
        Some(1),
        "spent on flash"
    );
    // Reboot: a fresh applet over the same flash keeps the count.
    let mut fresh = logged_in();
    fresh.state.key_index = hsm.state.key_index.clone();
    assert_eq!(sign(&mut fresh, &mut store, 2, ALGO_EC_RAW), SW_OK);
    assert_eq!(
        sign(&mut fresh, &mut store, 2, ALGO_EC_RAW),
        SW_KEY_EXHAUSTED
    );
    assert_eq!(
        sign(&mut hsm, &mut store, 2, ALGO_EC_SHA256),
        SW_KEY_EXHAUSTED
    );
    assert_eq!(
        store.load(KeyId::sc_hsm(0, 2)).unwrap().policy.use_counter,
        Some(0)
    );
}

#[test]
fn malformed_request_spends_no_use() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    assert_eq!(
        generate(&mut hsm, &mut store, 3, &[0x90, 0x04, 0, 0, 0, 1]),
        SW_OK
    );
    // Unknown algorithm, empty data: refused before the key is used.
    assert_ne!(sign(&mut hsm, &mut store, 3, 0x7F), SW_OK);
    let (sw, _) = run(&mut hsm, &mut store, &apdu(0x80, 0x68, 3, 0x70, &[]));
    assert_ne!(sw, SW_OK);
    assert_eq!(
        store.load(KeyId::sc_hsm(0, 3)).unwrap().policy.use_counter,
        Some(1)
    );
}

#[test]
fn failed_counter_write_refuses_the_operation() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    assert_eq!(
        generate(&mut hsm, &mut store, 4, &[0x90, 0x04, 0, 0, 0, 5]),
        SW_OK
    );
    store.fail_saves = true;
    let (sw, data) = run(
        &mut hsm,
        &mut store,
        &apdu(0x80, 0x68, 4, ALGO_EC_RAW, &[0x11; 32]),
    );
    assert_eq!(sw, SW_MEMORY_FAILURE);
    assert!(data.is_empty(), "no signature without the spent use");
    assert_eq!(
        store.load(KeyId::sc_hsm(0, 4)).unwrap().policy.use_counter,
        Some(5)
    );
    // A key without a counter needs no write at all.
    store.fail_saves = false;
    assert_eq!(generate(&mut hsm, &mut store, 5, &[]), SW_OK);
    store.fail_saves = true;
    assert_eq!(sign(&mut hsm, &mut store, 5, ALGO_EC_RAW), SW_OK);
}

#[test]
fn legacy_key_without_policy_is_unrestricted() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    assert_eq!(generate(&mut hsm, &mut store, 6, &[]), SW_OK);
    // Byte-for-byte the P2K4 format older firmware writes and reads.
    assert_eq!(store.magic(KeyId::sc_hsm(0, 6)), *b"P2K4");
    let saves = store.saves;
    for algo in [ALGO_EC_RAW, ALGO_EC_SHA1, ALGO_EC_SHA256, ALGO_EC_SHA512] {
        assert_eq!(sign(&mut hsm, &mut store, 6, algo), SW_OK);
    }
    assert_eq!(store.saves, saves, "no counter, no writes");
}

#[test]
fn generate_refuses_bad_attributes_without_storing() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    for attrs in [
        &[0x90, 0x02, 0, 1][..], // counter not 4 bytes
        &[0x92, 0x01, 0x03],     // key domain that doesn't exist
        &[0x91, 0x05, 0x73],     // truncated
    ] {
        assert_ne!(
            generate(&mut hsm, &mut store, 7, attrs),
            SW_OK,
            "{attrs:02X?}"
        );
    }
    assert!(store.blobs.is_empty());
    assert!(hsm.state.key_index.is_empty());
}

#[test]
fn select_reports_the_policy_in_the_fcp() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    let attrs = [
        0x90, 0x04, 0, 0, 0, 9, 0x91, 0x02, 0x73, 0x92, 0x92, 0x01, 0x00,
    ];
    assert_eq!(generate(&mut hsm, &mut store, 8, &attrs), SW_OK);
    let (sw, fcp) = run(
        &mut hsm,
        &mut store,
        &apdu(0x00, 0xA4, 0x00, 0x04, &[0xCC, 0x08]),
    );
    assert_eq!(sw, SW_OK);
    let tail = [
        0xA5, 0x0D, 0x90, 0x04, 0, 0, 0, 9, 0x91, 0x02, 0x73, 0x92, 0x92, 0x01, 0x00,
    ];
    assert!(fcp.ends_with(&tail), "{fcp:02X?}");
    assert_eq!(fcp[0], 0x62);
    assert_eq!(fcp[1] as usize, fcp.len() - 2);
    // Key without a policy: counter reported as FFFFFFFF.
    assert_eq!(generate(&mut hsm, &mut store, 9, &[]), SW_OK);
    let (_, fcp) = run(
        &mut hsm,
        &mut store,
        &apdu(0x00, 0xA4, 0x00, 0x04, &[0xCC, 0x09]),
    );
    assert!(fcp.ends_with(&[0xA5, 0x06, 0x90, 0x04, 0xFF, 0xFF, 0xFF, 0xFF]));
}

fn with_dkek(hsm: &mut ScHsm) {
    hsm.state.dkek.set_dkek_direct(&[0x42; 32]);
}

fn import(hsm: &mut ScHsm, store: &mut BlobStore, key_ref: u8, blob: &[u8]) -> u16 {
    let mut a: heapless::Vec<u8, 600> = heapless::Vec::new();
    a.extend_from_slice(&[0x80, 0x74, key_ref, 0x93, 0x00])
        .unwrap();
    a.extend_from_slice(&(blob.len() as u16).to_be_bytes())
        .unwrap();
    a.extend_from_slice(blob).unwrap();
    run(hsm, store, &a).0
}

#[test]
fn policy_survives_wrap_and_unwrap() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    with_dkek(&mut hsm);
    let attrs = [0x91, 0x02, 0x73, 0x92, 0x92, 0x01, 0x00];
    assert_eq!(generate(&mut hsm, &mut store, 0x10, &attrs), SW_OK);
    let (sw, blob) = run(&mut hsm, &mut store, &apdu(0x80, 0x72, 0x10, 0x92, &[]));
    assert_eq!(sw, SW_OK);
    assert_eq!(blob[8], 12, "CardContact EC key blob");
    // Restore into another slot: same list and domain.
    assert_eq!(import(&mut hsm, &mut store, 0x11, &blob), SW_OK);
    let restored = store.load(KeyId::sc_hsm(0, 0x11)).unwrap();
    assert_eq!(&restored.policy.algorithms[..], &[0x73, 0x92]);
    assert_eq!(restored.policy.domain, Some(0));
    assert_eq!(restored.policy.use_counter, None);
    assert_eq!(
        sign(&mut hsm, &mut store, 0x11, ALGO_EC_RAW),
        SW_CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(sign(&mut hsm, &mut store, 0x11, ALGO_EC_SHA256), SW_OK);
}

#[test]
fn counter_limited_key_is_not_exportable() {
    // Regression (review): exporting a key with a use counter let every
    // re-import start again from the exported count.
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    with_dkek(&mut hsm);
    let attrs = [0x90, 0x04, 0, 0, 0, 3];
    assert_eq!(generate(&mut hsm, &mut store, 0x14, &attrs), SW_OK);
    let (sw, blob) = run(&mut hsm, &mut store, &apdu(0x80, 0x72, 0x14, 0x92, &[]));
    assert_eq!(sw, SW_CONDITIONS_NOT_SATISFIED);
    assert!(blob.is_empty());
    // Also with WRAP in its algorithm list.
    let attrs = [0x90, 0x04, 0, 0, 0, 3, 0x91, 0x02, 0x70, 0x92];
    assert_eq!(generate(&mut hsm, &mut store, 0x15, &attrs), SW_OK);
    let (sw, _) = run(&mut hsm, &mut store, &apdu(0x80, 0x72, 0x15, 0x92, &[]));
    assert_eq!(sw, SW_CONDITIONS_NOT_SATISFIED);
    // A (deprecated v3) blob that does carry a counter (made by a DKEK
    // holder) is imported with it: a counter in a blob can only restrict.
    let mut policy = KeyPolicy::default();
    policy.use_counter = Some(1);
    let key = store.load(KeyId::sc_hsm(0, 0x14)).unwrap();
    let blob = hsm
        .state
        .dkek
        .wrap_legacy(&key.private_key, 0x13, 0, &policy, &mut FwRng)
        .unwrap();
    assert_eq!(import(&mut hsm, &mut store, 0x16, &blob), SW_OK);
    assert_eq!(sign(&mut hsm, &mut store, 0x16, ALGO_EC_RAW), SW_OK);
    assert_eq!(
        sign(&mut hsm, &mut store, 0x16, ALGO_EC_RAW),
        SW_KEY_EXHAUSTED
    );
}

#[test]
fn proprietary_codes_are_checked_as_their_cardcontact_operation() {
    // Regression (review): the per-curve codes were checked as themselves,
    // and 23 (ECDH P-256 here) is CardContact's RSA-OAEP decrypt.
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    // List meant for an RSA key (OAEP decrypt) does not authorise ECDH.
    assert_eq!(
        generate(&mut hsm, &mut store, 0x17, &[0x91, 0x01, 0x23]),
        SW_OK
    );
    let point = [0x04u8; 65];
    let (sw, _) = run(&mut hsm, &mut store, &apdu(0x80, 0x62, 0x17, 0x23, &point));
    assert_eq!(sw, SW_CONDITIONS_NOT_SATISFIED);
    // ECDH (80) in the list covers the per-curve ECDH code too (the
    // garbage point is then refused by the ECDH itself, not the policy).
    assert_eq!(
        generate(&mut hsm, &mut store, 0x18, &[0x91, 0x01, 0x80]),
        SW_OK
    );
    let (sw, _) = run(&mut hsm, &mut store, &apdu(0x80, 0x62, 0x18, 0x23, &point));
    assert_ne!(sw, SW_OK);
    assert_ne!(sw, 0x6A84);
    let peer = crate::crypto::asymmetric::generate_ec_keypair(
        pico2hsm_core::key::KeyType::EcPrivateP256,
        &mut FwRng,
    )
    .unwrap();
    let (sw, _) = run(
        &mut hsm,
        &mut store,
        &apdu(0x80, 0x62, 0x18, 0x23, &peer.public_key),
    );
    assert_eq!(sw, SW_OK);
    // ...but not signing.
    assert_eq!(
        sign(&mut hsm, &mut store, 0x18, 0x13),
        SW_CONDITIONS_NOT_SATISFIED
    );
    // Pre-hashed ECDSA 13 is ALGO_EC_RAW (70) for the policy.
    assert_eq!(
        generate(&mut hsm, &mut store, 0x19, &[0x91, 0x01, 0x70]),
        SW_OK
    );
    assert_eq!(sign(&mut hsm, &mut store, 0x19, 0x13), SW_OK);
    assert_eq!(
        generate(&mut hsm, &mut store, 0x1A, &[0x91, 0x01, 0x13]),
        SW_OK
    );
    assert_eq!(
        sign(&mut hsm, &mut store, 0x1A, 0x13),
        SW_CONDITIONS_NOT_SATISFIED
    );
}

#[test]
fn list_without_wrap_forbids_export_and_plain_keys_export_cardcontact() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    with_dkek(&mut hsm);
    assert_eq!(
        generate(&mut hsm, &mut store, 0x12, &[0x91, 0x01, 0x73]),
        SW_OK
    );
    let (sw, _) = run(&mut hsm, &mut store, &apdu(0x80, 0x72, 0x12, 0x92, &[]));
    assert_eq!(sw, SW_CONDITIONS_NOT_SATISFIED);
    assert_eq!(generate(&mut hsm, &mut store, 0x13, &[]), SW_OK);
    let (sw, blob) = run(&mut hsm, &mut store, &apdu(0x80, 0x72, 0x13, 0x92, &[]));
    assert_eq!(sw, SW_OK);
    // CardContact EC blob, empty algorithm list and access conditions.
    assert_eq!(blob[8], 12);
    assert_eq!(&blob[9..11], &[0x00, 0x0A]);
    assert_eq!(&blob[21..27], &[0, 0, 0, 0, 0, 0]);
}

#[test]
fn symmetric_key_policy_spec_form() {
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    // SmartCard-HSM form: P2 = B2 (AES-256), data = attributes.
    let attrs = [0x91, 0x01, ALGO_AES_CBC_ENCRYPT];
    let (sw, _) = run(&mut hsm, &mut store, &apdu(0x00, 0x48, 0x20, 0xB2, &attrs));
    assert_eq!(sw, SW_OK);
    assert_eq!(
        store
            .load(KeyId::sc_hsm(0, 0x20))
            .unwrap()
            .private_key
            .len(),
        32
    );
    hsm.state.current_key_id = Some(0x20);
    let data = [0u8; 32];
    let enc = run(&mut hsm, &mut store, &apdu(0x80, 0x78, 0x01, 0x02, &data)).0;
    assert_eq!(enc, SW_OK);
    let dec = run(&mut hsm, &mut store, &apdu(0x80, 0x78, 0x02, 0x02, &data)).0;
    assert_eq!(dec, SW_CONDITIONS_NOT_SATISFIED);
    // CTR / GCM have no CardContact ID: refused under any list.
    let ctr = run(&mut hsm, &mut store, &apdu(0x80, 0x78, 0x01, 0x03, &data)).0;
    assert_eq!(ctr, SW_CONDITIONS_NOT_SATISFIED);
    // Legacy form still works, with attributes after the size tag.
    let (sw, _) = run(
        &mut hsm,
        &mut store,
        &apdu(0x00, 0x48, 0x21, 0x00, &[0x82, 0x90, 0x04, 0, 0, 0, 1]),
    );
    assert_eq!(sw, SW_OK);
    let k = store.load(KeyId::sc_hsm(0, 0x21)).unwrap();
    assert_eq!((k.private_key.len(), k.policy.use_counter), (16, Some(1)));
    let (sw, _) = run(&mut hsm, &mut store, &apdu(0x00, 0x48, 0x22, 0x00, &[0x99]));
    assert_eq!(sw, SW_WRONG_DATA);
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_card_hash_ids_follow_the_spec() {
    use crate::security::key_management::{AlgorithmId, KeyType as KmType};
    // A small RSA key (fast) placed directly in the store.
    let pair = crate::crypto::asymmetric::generate_rsa_keypair(
        pico2hsm_core::key::KeyType::RsaPrivate2048,
        &mut FwRng,
    )
    .unwrap();
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    let kid = KeyId::sc_hsm(0, 0x30);
    let mut obj = KeyObject::new(KmType::Rsa, kid.0, AppletId::ScHsm, AlgorithmId::RsaDecrypt);
    obj.private_key
        .extend_from_slice(&pair.private_key_der)
        .unwrap();
    obj.policy.algorithms.push(ALGO_RSA_PKCS1_SHA256).unwrap();
    crate::storage::KeyStore::save_key(&mut store, &obj).unwrap();
    hsm.state
        .key_index
        .push(KeyMeta {
            key_id: kid.0,
            key_type: CoreKeyType::RsaPrivate2048 as u8,
            algo: 0x05,
            key_flags: 0,
        })
        .unwrap();
    // 0x33 = PKCS#1 v1.5 with SHA-256 hashed by the card (CardContact).
    let msg = b"message to sign";
    let (sw, sig) = run(&mut hsm, &mut store, &apdu(0x80, 0x68, 0x30, 0x33, msg));
    assert_eq!(sw, SW_OK);
    {
        use ::rsa::pkcs1::DecodeRsaPrivateKey;
        use sha2::Digest;
        let pk = ::rsa::RsaPrivateKey::from_pkcs1_der(&pair.private_key_der)
            .unwrap()
            .to_public_key();
        let digest = sha2::Sha256::digest(msg);
        pk.verify(::rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &digest, &sig)
            .expect("SHA-256 PKCS#1 v1.5 signature over the message");
    }
    // Not in the list: refused.
    let (sw, _) = run(&mut hsm, &mut store, &apdu(0x80, 0x68, 0x30, 0x35, msg));
    assert_eq!(sw, SW_CONDITIONS_NOT_SATISFIED);
}

#[cfg(feature = "rsa")]
#[test]
fn rsa_decipher_has_no_padding_oracle() {
    // Regression (review): DECIPHER 22 first ran the raw operation of 21
    // (a key allowed only 22 was a raw RSA oracle), then — removing the
    // padding on the card — answered bad padding differently from good.
    // 22 is now refused before the key is touched, whatever the input.
    use crate::security::key_management::{AlgorithmId, KeyType as KmType};
    use ::rsa::pkcs1::DecodeRsaPrivateKey;
    let pair = crate::crypto::asymmetric::generate_rsa_keypair(
        pico2hsm_core::key::KeyType::RsaPrivate2048,
        &mut FwRng,
    )
    .unwrap();
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    let kid = KeyId::sc_hsm(0, 0x31);
    let mut obj = KeyObject::new(KmType::Rsa, kid.0, AppletId::ScHsm, AlgorithmId::RsaDecrypt);
    obj.private_key
        .extend_from_slice(&pair.private_key_der)
        .unwrap();
    obj.policy.use_counter = Some(5);
    obj.policy.algorithms.push(ALGO_RSA_DECRYPT_PKCS1).unwrap();
    crate::storage::KeyStore::save_key(&mut store, &obj).unwrap();
    hsm.state
        .key_index
        .push(KeyMeta {
            key_id: kid.0,
            key_type: CoreKeyType::RsaPrivate2048 as u8,
            algo: 0x05,
            key_flags: 0,
        })
        .unwrap();
    let pk = ::rsa::RsaPrivateKey::from_pkcs1_der(&pair.private_key_der)
        .unwrap()
        .to_public_key();
    let good = pk
        .encrypt(&mut FwRng, ::rsa::Pkcs1v15Encrypt, b"secret")
        .unwrap();
    let mut bad = good.clone();
    bad[255] ^= 1;
    let mut answers: heapless::Vec<(u16, usize), 2> = heapless::Vec::new();
    for ct in [&good[..], &bad[..]] {
        let mut a: heapless::Vec<u8, 300> = heapless::Vec::new();
        a.extend_from_slice(&[0x80, 0x62, 0x31, 0x22, 0x00, 0x01, 0x00])
            .unwrap();
        a.extend_from_slice(ct).unwrap();
        let (sw, data) = run(&mut hsm, &mut store, &a);
        answers.push((sw, data.len())).unwrap();
        // The raw operation (21) is not in the list either.
        a[3] = 0x21;
        assert_eq!(run(&mut hsm, &mut store, &a).0, SW_CONDITIONS_NOT_SATISFIED);
    }
    assert_eq!(answers[0], (pico2hsm_core::apdu::SW_INS_NOT_SUPPORTED, 0));
    assert_eq!(
        answers[0], answers[1],
        "same answer for good and bad padding"
    );
    assert_eq!(store.load(kid).unwrap().policy.use_counter, Some(5));
}

#[test]
fn cbc_decrypt_has_no_padding_oracle() {
    // Regression (review): CIPHER CBC decrypt stripped PKCS#7 and answered
    // 6985 on bad padding.  Now whole blocks in, whole blocks out.
    let (mut hsm, mut store) = (logged_in(), BlobStore::new());
    let (sw, _) = run(&mut hsm, &mut store, &apdu(0x00, 0x48, 0x40, 0xB2, &[]));
    assert_eq!(sw, SW_OK);
    hsm.state.current_key_id = Some(0x40);
    let mut msg = [0u8; 16 + 32];
    msg[16..].copy_from_slice(&[0xA7; 32]); // IV = 0, two blocks
    let (sw, ct) = run(&mut hsm, &mut store, &apdu(0x80, 0x78, 0x01, 0x02, &msg));
    assert_eq!((sw, ct.len()), (SW_OK, 32), "no padding added");
    let mut back = [0u8; 48];
    back[16..].copy_from_slice(&ct);
    let (sw, pt) = run(&mut hsm, &mut store, &apdu(0x80, 0x78, 0x02, 0x02, &back));
    assert_eq!((sw, &pt[..]), (SW_OK, &[0xA7u8; 32][..]));
    // Any ciphertext decrypts: no answer depends on padding.
    for flip in 0..32 {
        let mut t = back;
        t[16 + flip] ^= 0x5C;
        let (sw, pt) = run(&mut hsm, &mut store, &apdu(0x80, 0x78, 0x02, 0x02, &t));
        assert_eq!((sw, pt.len()), (SW_OK, 32));
    }
    // Not whole blocks: refused for the length alone.
    let (sw, _) = run(
        &mut hsm,
        &mut store,
        &apdu(0x80, 0x78, 0x02, 0x02, &back[..40]),
    );
    assert_eq!(sw, pico2hsm_core::apdu::SW_WRONG_LENGTH);
}
