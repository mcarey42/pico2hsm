//! Host tests: GENERATE KEY PAIR names its curve through explicit domain
//! parameters (issue #51).  OpenSC sends CPI `5F29 = 00` and the curve's
//! parameters in `7F49`; the firmware must generate a key on exactly that
//! curve or refuse with 6A80, never substitute a NIST curve.

use super::policy_tests::BlobStore;
use super::*;
use crate::crypto::ec_params::{ec_domain_params, EcDomainParams};

/// Extended-length APDU (OpenSC sends GAKP as extended).
fn apdu_ext(ins: u8, p1: u8, data: &[u8]) -> heapless::Vec<u8, 1024> {
    let mut v = heapless::Vec::new();
    let n = data.len() as u16;
    v.extend_from_slice(&[0x00, ins, p1, 0x00, 0x00]).unwrap();
    v.extend_from_slice(&n.to_be_bytes()).unwrap();
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

fn push_tlv(v: &mut heapless::Vec<u8, 1024>, tag: &[u8], value: &[u8]) {
    v.extend_from_slice(tag).unwrap();
    match value.len() {
        0..=0x7F => v.push(value.len() as u8).unwrap(),
        0x80..=0xFF => v.extend_from_slice(&[0x81, value.len() as u8]).unwrap(),
        n => v
            .extend_from_slice(&[0x82, (n >> 8) as u8, n as u8])
            .unwrap(),
    }
    v.extend_from_slice(value).unwrap();
}

/// Curve parameters as OpenSC's curve table carries them.
struct Curve<'a> {
    prime: &'a [u8],
    a: &'a [u8],
    b: &'a [u8],
    g: &'a [u8],
    order: &'a [u8],
}

impl<'a> From<&'a EcDomainParams> for Curve<'a> {
    fn from(p: &'a EcDomainParams) -> Self {
        Curve {
            prime: p.prime,
            a: p.coeff_a,
            b: p.coeff_b,
            g: p.base_g,
            order: p.order,
        }
    }
}

/// An OpenSC-style GAKP body (`sc_pkcs15emu_sc_hsm_encode_cvc_req`):
/// CPI, CAR, the 7F49 template with full domain parameters, CHR.
fn gakp(cpi: u8, c: &Curve<'_>) -> heapless::Vec<u8, 1024> {
    // id-TA-ECDSA-SHA-256
    const OID: &[u8] = &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03];
    let mut pk: heapless::Vec<u8, 1024> = heapless::Vec::new();
    push_tlv(&mut pk, &[0x06], OID);
    push_tlv(&mut pk, &[0x81], c.prime);
    push_tlv(&mut pk, &[0x82], c.a);
    push_tlv(&mut pk, &[0x83], c.b);
    push_tlv(&mut pk, &[0x84], c.g);
    push_tlv(&mut pk, &[0x85], c.order);
    push_tlv(&mut pk, &[0x87], &[0x01]);
    let mut d: heapless::Vec<u8, 1024> = heapless::Vec::new();
    push_tlv(&mut d, &[0x5F, 0x29], &[cpi]);
    push_tlv(&mut d, &[0x42], b"UTCA00001");
    push_tlv(&mut d, &[0x7F, 0x49], &pk);
    push_tlv(&mut d, &[0x5F, 0x20], b"UTTM00001");
    d
}

fn hex<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

// RFC 5639 (values from `openssl ecparam -param_enc explicit`).
struct Brainpool<const F: usize, const G: usize> {
    prime: [u8; F],
    a: [u8; F],
    b: [u8; F],
    g: [u8; G],
    order: [u8; F],
}

impl<const F: usize, const G: usize> Brainpool<F, G> {
    fn curve(&self) -> Curve<'_> {
        Curve {
            prime: &self.prime,
            a: &self.a,
            b: &self.b,
            g: &self.g,
            order: &self.order,
        }
    }
}

fn brainpool_p256r1() -> Brainpool<32, 65> {
    Brainpool {
        prime: hex("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"),
        a: hex("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"),
        b: hex("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"),
        g: hex(concat!(
            "04",
            "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
            "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"
        )),
        order: hex("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"),
    }
}

fn brainpool_p384r1() -> Brainpool<48, 97> {
    Brainpool {
        prime: hex(concat!(
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B4",
            "12B1DA197FB71123ACD3A729901D1A71874700133107EC53"
        )),
        a: hex(concat!(
            "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787",
            "139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826"
        )),
        b: hex(concat!(
            "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A6",
            "2E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11"
        )),
        g: hex(concat!(
            "04",
            "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3",
            "DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
            "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864",
            "E19C054FF99129280E4646217791811142820341263C5315"
        )),
        order: hex(concat!(
            "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B3",
            "1F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565"
        )),
    }
}

fn refused_without_a_key(hsm: &mut ScHsm, store: &mut BlobStore, body: &[u8]) {
    let before = hsm.state.key_index.len();
    let (sw, _) = run(hsm, store, &apdu_ext(0x46, 0x01, body));
    assert_eq!(sw, 0x6A80);
    assert_eq!(hsm.state.key_index.len(), before, "no key may be stored");
}

#[test]
fn brainpool_requests_are_refused() {
    let mut store = BlobStore::new();
    let mut hsm = logged_in();
    refused_without_a_key(
        &mut hsm,
        &mut store,
        &gakp(0x00, &brainpool_p256r1().curve()),
    );
    refused_without_a_key(
        &mut hsm,
        &mut store,
        &gakp(0x00, &brainpool_p384r1().curve()),
    );
}

#[test]
fn supported_curves_generate_on_the_named_curve() {
    for algo in [0x13u8, 0x15, 0x17, 0x19] {
        let mut store = BlobStore::new();
        let mut hsm = logged_in();
        let params = ec_domain_params(algo).unwrap();
        let (sw, cvc) = run(
            &mut hsm,
            &mut store,
            &apdu_ext(0x46, 0x01, &gakp(0x00, &Curve::from(&params))),
        );
        assert_eq!(sw, 0x9000, "algo {algo:#04x}");
        assert_eq!(hsm.state.key_index.len(), 1);
        assert_eq!(hsm.state.key_index[0].algo, algo);
        // The returned CVC carries the requested curve's prime.
        assert!(cvc.windows(params.prime.len()).any(|w| w == params.prime));
    }
}

#[test]
fn a_mixed_parameter_set_is_refused() {
    // NIST P-256 order with the brainpoolP256r1 field, and the reverse.
    let bp = brainpool_p256r1();
    let p256 = ec_domain_params(0x13).unwrap();
    let mut store = BlobStore::new();
    let mut hsm = logged_in();
    let mut c = Curve::from(&p256);
    c.prime = &bp.prime;
    refused_without_a_key(&mut hsm, &mut store, &gakp(0x00, &c));
    let mut c = bp.curve();
    c.order = p256.order;
    refused_without_a_key(&mut hsm, &mut store, &gakp(0x00, &c));
    // Right order and field, wrong generator.
    let mut c = Curve::from(&p256);
    c.g = &bp.g;
    refused_without_a_key(&mut hsm, &mut store, &gakp(0x00, &c));
}

#[test]
fn an_explicit_algorithm_must_agree_with_the_parameters() {
    let mut store = BlobStore::new();
    let mut hsm = logged_in();
    // CPI says P-256, the template names brainpoolP256r1.
    refused_without_a_key(
        &mut hsm,
        &mut store,
        &gakp(0x13, &brainpool_p256r1().curve()),
    );
    // CPI says P-384, the template names P-256.
    let p256 = ec_domain_params(0x13).unwrap();
    refused_without_a_key(&mut hsm, &mut store, &gakp(0x15, &Curve::from(&p256)));
    // Agreement is accepted.
    let (sw, _) = run(
        &mut hsm,
        &mut store,
        &apdu_ext(0x46, 0x01, &gakp(0x13, &Curve::from(&p256))),
    );
    assert_eq!(sw, 0x9000);
}
