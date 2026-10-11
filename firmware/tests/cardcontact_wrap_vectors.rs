//! Known-answer tests for the SmartCard-HSM (CardContact) key-backup blob.
//!
//! Two independent sources of vectors (`firmware/tests/vectors/`):
//!
//! - `cardcontact_wrap.txt`: written by the Python reference
//!   `tools/python/pico2hsm/cardcontact_wrap.py` (from the format
//!   description, not from this firmware).  The C reference firmware
//!   pico-hsm decodes every one of these blobs (checked with a host build of
//!   its `kek.c`).
//! - `picohsm_wrap.txt`: blobs written by pico-hsm's own `dkek_encode_key`
//!   (minimal-length integers, RSA as type 5, P-521 key size 528).
//!
//! Every blob must UNWRAP to the listed key.  Cases marked `exact 1` must
//! also come out of WRAP byte for byte, given the same 8-byte random prefix.

use pico2hsm_core::key::AppletId;
use pico2hsm_firmware::security::dkek::{DkekError, DkekImportResult, DkekManager};
use pico2hsm_firmware::security::key_management::{AlgorithmId, KeyObject, KeyType};

const CARDCONTACT: &str = include_str!("vectors/cardcontact_wrap.txt");
const PICOHSM: &str = include_str!("vectors/picohsm_wrap.txt");

struct Case<'a> {
    name: &'a str,
    fields: Vec<(&'a str, &'a str)>,
}

impl<'a> Case<'a> {
    fn get(&self, k: &str) -> &'a str {
        self.fields
            .iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| *v)
            .unwrap_or_else(|| panic!("{}: no field {k}", self.name))
    }
    fn bytes(&self, k: &str) -> Vec<u8> {
        hex::decode(self.get(k)).unwrap()
    }
}

/// `(globals, cases)` of a vector file.
fn parse(text: &str) -> (Vec<(&str, &str)>, Vec<Case<'_>>) {
    let mut globals = Vec::new();
    let mut cases = Vec::new();
    let mut cur: Option<Case<'_>> = None;
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line.split_once(' ').unwrap_or((line, ""));
        match (k, cur.as_mut()) {
            ("case", None) => {
                cur = Some(Case {
                    name: v,
                    fields: Vec::new(),
                })
            }
            ("end", Some(_)) => cases.push(cur.take().unwrap()),
            (_, Some(c)) => c.fields.push((k, v.trim())),
            (_, None) => globals.push((k, v.trim())),
        }
    }
    (globals, cases)
}

fn global<'a>(g: &[(&'a str, &'a str)], k: &str) -> Vec<u8> {
    hex::decode(g.iter().find(|(n, _)| *n == k).unwrap().1).unwrap()
}

fn manager(dkek: &[u8]) -> DkekManager {
    let mut m = DkekManager::new([0u8; 16]);
    m.set_dkek_direct(dkek.try_into().unwrap());
    m
}

/// An RNG that returns the case's random prefix.
struct Fixed(Vec<u8>);
impl rand_core::RngCore for Fixed {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }
    fn fill_bytes(&mut self, d: &mut [u8]) {
        let n = d.len();
        d.copy_from_slice(&self.0[..n]);
        self.0.drain(..n);
    }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(d);
        Ok(())
    }
}
impl rand_core::CryptoRng for Fixed {}

fn curve_algo(name: &str) -> AlgorithmId {
    match name {
        "P-256" => AlgorithmId::EcdsaP256,
        "P-384" => AlgorithmId::EcdsaP384,
        "P-521" => AlgorithmId::EcdsaP521,
        "secp256k1" => AlgorithmId::EcdsaK256,
        n => panic!("curve {n}"),
    }
}

fn blank() -> KeyObject {
    KeyObject::new(KeyType::Generic, 1, AppletId::ScHsm, AlgorithmId::AesGcm)
}

/// The key object WRAP would be given for this case.
fn key_of(c: &Case<'_>) -> KeyObject {
    let mut k = match c.get("kind") {
        "ec" => {
            let mut k = KeyObject::new(KeyType::Ec, 1, AppletId::ScHsm, curve_algo(c.get("curve")));
            k.private_key.extend_from_slice(&c.bytes("d")).unwrap();
            k.public_key.extend_from_slice(&c.bytes("q")).unwrap();
            k
        }
        "rsa-crt" => {
            let mut k = KeyObject::new(KeyType::Rsa, 1, AppletId::ScHsm, AlgorithmId::RsaDecrypt);
            k.private_key.extend_from_slice(&c.bytes("pkcs1")).unwrap();
            k
        }
        "aes" => {
            let mut k = KeyObject::new(KeyType::Aes, 1, AppletId::ScHsm, AlgorithmId::AesGcm);
            k.private_key.extend_from_slice(&c.bytes("key")).unwrap();
            k
        }
        other => panic!("{}: cannot wrap kind {other}", c.name),
    };
    k.policy
        .algorithms
        .extend_from_slice(&c.bytes("algorithms"))
        .unwrap();
    k
}

fn check_unwrap(mgr: &DkekManager, c: &Case<'_>) {
    let mut out = blank();
    let r = mgr.unwrap(&c.bytes("blob"), &mut out);
    let kind = c.get("kind");
    if kind.starts_with("rsa") && !cfg!(feature = "rsa") {
        assert_eq!(r.unwrap_err(), DkekError::UnsupportedKey, "{}", c.name);
        return;
    }
    let u = r.unwrap_or_else(|e| panic!("{}: {e:?}", c.name));
    assert!(!u.legacy);
    assert_eq!(
        &out.policy.algorithms[..],
        &c.bytes("algorithms")[..],
        "{}",
        c.name
    );
    let access = c.bytes("access");
    assert_eq!(
        u.key_flags,
        access.first().copied().unwrap_or(0),
        "{}",
        c.name
    );
    match kind {
        "ec" => {
            assert_eq!(out.algorithm, curve_algo(c.get("curve")), "{}", c.name);
            assert_eq!(&out.private_key[..], &c.bytes("d")[..], "{}", c.name);
            assert_eq!(&out.public_key[..], &c.bytes("q")[..], "{}", c.name);
        }
        "aes" => {
            assert_eq!(out.key_type, KeyType::Aes);
            assert_eq!(&out.private_key[..], &c.bytes("key")[..], "{}", c.name);
        }
        #[cfg(feature = "rsa")]
        "rsa" | "rsa-crt" => {
            use rsa::pkcs1::DecodeRsaPrivateKey;
            use rsa::traits::{PrivateKeyParts, PublicKeyParts};
            assert_eq!(out.key_type, KeyType::Rsa);
            let key = rsa::RsaPrivateKey::from_pkcs1_der(&out.private_key).unwrap();
            assert_eq!(key.n().to_bytes_be(), c.bytes("n"), "{}", c.name);
            assert_eq!(key.e().to_bytes_be(), c.bytes("e"), "{}", c.name);
            let mut primes: Vec<Vec<u8>> = key.primes().iter().map(|p| p.to_bytes_be()).collect();
            let mut want = vec![c.bytes("p"), c.bytes("q")];
            primes.sort();
            want.sort();
            assert_eq!(primes, want, "{}", c.name);
            // Stored as GENERATE KEY PAIR does: [len(2)] || n || e.
            let n = c.bytes("n");
            assert_eq!(&out.public_key[2..2 + n.len()], &n[..]);
        }
        k => panic!("kind {k}"),
    }
}

#[test]
fn kcv_kenc_kmac_and_share_combination() {
    let (g, _) = parse(CARDCONTACT);
    // Shares combine by XOR (sc-hsm-tool sends each 32-byte share).
    let mut mgr = DkekManager::new([0u8; 16]);
    mgr.init_shares(2);
    let s1 = global(&g, "share1");
    let s2 = global(&g, "share2");
    assert!(matches!(
        mgr.import_share_raw(s1.as_slice().try_into().unwrap()),
        Ok(DkekImportResult::MoreSharesNeeded { .. })
    ));
    assert_eq!(
        mgr.import_share_raw(s2.as_slice().try_into().unwrap()),
        Ok(DkekImportResult::Complete)
    );
    assert_eq!(&mgr.get_dkek().unwrap()[..], &global(&g, "dkek")[..]);
    assert_eq!(&mgr.compute_kcv().unwrap()[..], &global(&g, "kcv")[..]);
}

#[test]
fn reference_blobs_unwrap() {
    let (g, cases) = parse(CARDCONTACT);
    let mgr = manager(&global(&g, "dkek"));
    assert!(cases.len() >= 12);
    for c in &cases {
        check_unwrap(&mgr, c);
    }
}

#[test]
fn picohsm_blobs_unwrap() {
    let (g, cases) = parse(PICOHSM);
    let mgr = manager(&global(&g, "dkek"));
    assert_eq!(&mgr.compute_kcv().unwrap()[..], &global(&g, "kcv")[..]);
    assert_eq!(cases.len(), 12);
    for c in &cases {
        check_unwrap(&mgr, c);
    }
}

#[test]
fn wrap_matches_the_reference_byte_for_byte() {
    let (g, cases) = parse(CARDCONTACT);
    let mgr = manager(&global(&g, "dkek"));
    let mut n = 0;
    for c in cases.iter().filter(|c| c.get("exact") == "1") {
        let key = key_of(c);
        let flags = c.bytes("access").first().copied().unwrap_or(0);
        let blob = mgr
            .wrap(&key, flags, &mut Fixed(c.bytes("randomize")))
            .unwrap_or_else(|e| panic!("{}: {e:?}", c.name));
        assert_eq!(hex::encode(&blob[..]), c.get("blob"), "{}", c.name);
        // Without a stored public key the firmware computes the same Q.
        if c.get("kind") == "ec" {
            let mut k = key_of(c);
            k.public_key.clear();
            let blob = mgr
                .wrap(&k, flags, &mut Fixed(c.bytes("randomize")))
                .unwrap();
            assert_eq!(hex::encode(&blob[..]), c.get("blob"), "{}", c.name);
        }
        n += 1;
    }
    assert!(n >= 9, "exact cases: {n}");
}

#[test]
fn every_field_is_authenticated() {
    let (g, cases) = parse(CARDCONTACT);
    let mgr = manager(&global(&g, "dkek"));
    for c in cases.iter().filter(|c| c.get("kind") != "rsa-crt") {
        let blob = c.bytes("blob");
        for i in 0..blob.len() {
            let mut t = blob.clone();
            t[i] ^= 0x80;
            assert_eq!(
                mgr.unwrap(&t, &mut blank()).unwrap_err(),
                DkekError::InvalidWrapBlob,
                "{} byte {i}",
                c.name
            );
        }
    }
}
