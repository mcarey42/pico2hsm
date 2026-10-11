//! Known-answer tests for the domain key and member certificates (cluster
//! plan V3 §4.1, §4.3).
//!
//! `vectors/domain_v1.txt` is written by `vectors/gen_domain.py` from the
//! independent Python reference `tools/python/pico2hsm/domain.py` (using the
//! `cryptography` package), not from this firmware.  The host tool's
//! `pico2hsm-proto` crate checks itself against the same file.

use pico2hsm_firmware::domain::key::DomainKey;
use pico2hsm_firmware::domain::member::{self, MemberCert};
use pico2hsm_firmware::security::dkek::{DkekImportResult, DkekManager};

const VECTORS: &str = include_str!("vectors/domain_v1.txt");

struct Case<'a> {
    name: &'a str,
    fields: Vec<(&'a str, &'a str)>,
}

impl<'a> Case<'a> {
    fn get(&self, k: &str) -> Option<&'a str> {
        self.fields.iter().find(|(n, _)| *n == k).map(|(_, v)| *v)
    }
    fn bytes(&self, k: &str) -> Vec<u8> {
        hex::decode(
            self.get(k)
                .unwrap_or_else(|| panic!("{}: no {k}", self.name)),
        )
        .unwrap()
    }
    fn arr<const N: usize>(&self, k: &str) -> [u8; N] {
        self.bytes(k).try_into().unwrap()
    }
}

fn cases() -> Vec<Case<'static>> {
    let mut out = Vec::new();
    let mut cur: Option<Case<'static>> = None;
    for line in VECTORS.lines() {
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
            ("end", Some(_)) => out.push(cur.take().unwrap()),
            (_, Some(c)) => c.fields.push((k, v.trim())),
            _ => panic!("stray line {line}"),
        }
    }
    assert!(out.len() >= 5, "vector file read");
    out
}

#[test]
fn domain_key_matches_the_reference() {
    for c in cases() {
        let dkek: [u8; 32] = c.arr("dkek");
        let k = DomainKey::derive(&dkek).unwrap();
        assert_eq!(&k.q[..], &c.bytes("q")[..], "{}: Q_domain", c.name);
        assert_eq!(
            &k.id[..],
            &c.bytes("domain_id")[..],
            "{}: domain_id",
            c.name
        );
    }
}

#[test]
fn shares_combine_to_the_reference_dkek_and_kcv() {
    for c in cases() {
        let Some(shares) = c.get("shares") else {
            continue;
        };
        let shares: Vec<[u8; 32]> = shares
            .split(',')
            .map(|s| hex::decode(s).unwrap().try_into().unwrap())
            .collect();
        let mut m = DkekManager::new([0u8; 16]);
        m.init_shares(shares.len() as u8);
        let mut last = None;
        for s in &shares {
            last = Some(m.import_share_raw(s).unwrap());
        }
        assert!(matches!(last, Some(DkekImportResult::Complete)));
        assert_eq!(
            &m.get_dkek().unwrap()[..],
            &c.bytes("dkek")[..],
            "{}",
            c.name
        );
        assert_eq!(
            &m.compute_kcv().unwrap()[..],
            &c.bytes("kcv")[..],
            "{}",
            c.name
        );
    }
}

#[test]
fn member_certificates_match_the_reference_byte_for_byte() {
    for c in cases() {
        let dkek: [u8; 32] = c.arr("dkek");
        let domain = DomainKey::derive(&dkek).unwrap();
        let member_pub: [u8; 65] = c.arr("member_pub");
        assert_eq!(
            &member::member_id(&member_pub)[..],
            &c.bytes("member_id")[..],
            "{}",
            c.name
        );
        let sponsor: [u8; 16] = c.arr("sponsor_id");
        let lamport: u64 = c.get("lamport").unwrap().parse().unwrap();
        let flags = c.bytes("flags")[0];
        let cert = MemberCert::issue(&domain, &member_pub, &sponsor, lamport, flags).unwrap();
        let want = c.bytes("cert");
        assert_eq!(&cert.encode()[..], &want[..], "{}: certificate", c.name);

        let back = MemberCert::decode(&want).unwrap();
        assert_eq!(back.verify(&domain.q), Ok(()), "{}", c.name);
        assert_eq!(back.issued_lamport, lamport);
        assert_eq!(back.sponsor_id, sponsor);
    }
}
