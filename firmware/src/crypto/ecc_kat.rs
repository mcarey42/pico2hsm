//! Known-answer tests freezing the ECC behaviour of the RustCrypto 0.13 stack.
//!
//! Every expected value below was captured by running the code on
//! p256/p384/p521/k256 0.13 + ecdsa 0.16 and pasted in as a literal; nothing
//! is recomputed at test time. The 0.14 migration must keep all of these
//! passing without editing a single expected value.
//!
//! "Negative" cases (bad peer points, bad scalars, mangled signatures) record
//! whatever the 0.13 code returned, as the `Debug` string of the result, so an
//! accidental change in accept/reject behaviour is caught as well.

use super::asymmetric::{
    ecdh_agree, ecdsa_sign, ecdsa_sign_p521_with_ad, ecdsa_verify, generate_ec_keypair,
};
use super::kdf::{bip32_derive, slip10_derive};
use crate::domain::key::{domain_id, verify_prehash};
use crate::security::dkek::p256_ecdh;
use pico2hsm_core::error::CryptoError;
use pico2hsm_core::key::{KeyId, KeyMaterial, KeyType, MAX_KEY_BYTES};
use rand_core::{CryptoRng, RngCore};
extern crate std;

use std::string::String;
use std::vec::Vec;
use std::{format, vec};

const P256: KeyType = KeyType::EcPrivateP256;
const P384: KeyType = KeyType::EcPrivateP384;
const P521: KeyType = KeyType::EcPrivateP521;
const K256: KeyType = KeyType::EcPrivateK256;

// ---------------------------------------------------------------------------
// Captured vectors (private scalars and public points per curve, pair A and B)
// ---------------------------------------------------------------------------

const P256_A_PRIV: &str = "15f626457e812f40afc32db79523d52d39dd34e1b044fb9a53af3353aee5e007";
const P256_A_PUB: &str = "04af15578b2c38dd64978ecf99155d35463454c2fbd4e13e6d438a35678ba117840fe7ac16cdd6188034a80f687db9314c2cb5d6843e090240ffcb54d71463f080";
const P256_B_PRIV: &str = "57f1997d2caa81d4e1c260af4bcbb7417bdc6f19616c5d2d95a9764b9c8e429a";
const P256_B_PUB: &str = "0403a0aef3e85861a3cfe2c0aaeab08ebe7ccaee2c27e0cc5d4b1cae129c8200f0691db7eb837e59ff6e101ab429ce022b24d55be968c72c63336b6b11dd2d7b10";
const P384_A_PRIV: &str = "15f626457e812f40afc32db79523d52d39dd34e1b044fb9a53af3353aee5e007edb83abdc50696f4078a01efe0a7bb61";
const P384_A_PUB: &str = "04846a861ba043d3b4fb551ae12ee4aa1d98a760b5a97fddeba738815529d9ee522111a3f35dbd8b44037b1b82ff8ed74b0441c98a3520d7b6340b9ca1268f7f3790862d22c3d978a5ff8681a008336a468fb4fe9c2e347dfd09150c53b362267a";
const P384_B_PRIV: &str = "57f1997d2caa81d4e1c260af4bcbb7417bdc6f19616c5d2d95a9764b9c8e429a2fbb7db5bb2f6807b99444e7d6401ef4";
const P384_B_PUB: &str = "04c2801edef6e731488f21daa2f1848926029a5358b15890ab359fe8f2a38f25bf676ad99a9dbd21837002ee26d86f1599b3582c35be4e8ef21cdaa9597e9486de94c4ba5a6a40ed904d9485e749e8154aad01d90445f8f65b50990ed22f1aa4fe";
const P521_A_PRIV: &str = "01d3c839815ac0279bacd76bbcfbf59435beded5db1c9b014f88a507f1bd80eed965ac71ecdeb65b7377aba30b7f5cc78d40b20d219041b42752b97f5c317721b12f";
const P521_A_PUB: &str = "0400378bed0229d586e9838dd356c7f3400ac0fd62ab35f88746f629fe124e1e48653c298501e682e2d637c51cc5d54056391bede699c0820d80847c93b7f49eadcff2015a9e8ded3429fba1622dd95ba6a399552681b97ac5006e2937418b32cfad6e19434108950bf99d38d1f39de1308cb41a0164072f0066ebbae65b344d7e79e957ae";
const P521_B_PRIV: &str = "017a4a81a1b25bd19b5751f3dcd341be3521585dfa74772b4f33278f11951c98d90c2ef90c360205731e352b2a5728f28deb3d9541e8dd5f27c504c77c09c3ccb1d6";
const P521_B_PUB: &str = "040005783ec1eb215de20f0f0d21c939d966a624c4340bc9071b78391aea5816e915dbff92256d7b9bf152998a6a53d53ff33441694c873d77910d7bd0e1cac348e04a016e4389496bb0754dacb45b003f3f601bd6f46a011dddbf0e0f3eba6598d439b7d701f28ab6f6790af1b961aeba058fb011041936bf53603b47e1c7707dbd987942";
const K256_A_PRIV: &str = "15f626457e812f40afc32db79523d52d39dd34e1b044fb9a53af3353aee5e007";
const K256_A_PUB: &str = "041ce1c7fd429601cd7f5520ac8785178674bce23c974ea0a1fd37f66d6c537f3e74270154e26057ce8b02b4e34f354e2526eb61ac9585f6ff385c1ba6724faebb";
const K256_B_PRIV: &str = "57f1997d2caa81d4e1c260af4bcbb7417bdc6f19616c5d2d95a9764b9c8e429a";
const K256_B_PUB: &str = "0489d3d0d724a4508ac73bd50798e92ad2ff9004124166bcaaec0ffd5eab0574ebae8a84c1cd84233d69a5ef3c46585bc349200a6cc0040dadae94cdebccacfc69";

// ECDH shared secret (x-coordinate) of the A/B pair.
const P256_ECDH: &str = "e9ab500eb7fc602cb5e2cd95994a049fc5a9a2284780e25c66d6287443de02a8";
const P384_ECDH: &str = "adf0079ceb6239e3c3b61472fd6a9127319e6433b52b721b620d474a0eb1d98638ae5d4547745d7e98c18b6766e31595";
const P521_ECDH: &str = "0046d1963f3e13bd69dcef6848cd9ef22b61b3a423b275383ab79bd07e88aba2fec54c6fc2b23147ba5ed9bf5890e0b58a6dc21fc5dcf9889d8b3a8e610b7c4e4e82";
const K256_ECDH: &str = "06e538821aac0f4d680bbcb3a0f993c104738694cd9c27f90dd022458a960b82";

// DER ECDSA signatures by A over the fixed per-curve hash (see `hash_for`).
const P256_SIG: &str = "3045022100972c42bdec46a64908a7cbf7aa4f4f6aa70d82622b0ea73faf1039c7f1a3e6cb0220190e5735f69d6df054bc8be864da2ce95c7dd6a6279dd2e9892ff05d859c3807";
const P384_SIG: &str = "306502307a1ec7acebeb84b29e42f09194dc43b9cfb93eacde88da770327e9acab2933cf7c88d4a3213351fe2268146ac8858270023100c19276d788f86a7e385956249f4de1f48321bf2ea80764c476e2f3cd4b435936894ac79a3e9fde74566696bbf2a6406a";
const P521_SIG: &str = "3081880242013ac36b2b78c658217b27c3d90f8945b7c5f3f6388418601909da0ab2c80fbef961091f0f1dc0d46b94e210f0ba670279bbaad3a40fdaddf415ab0eb510d97a87fb024200c2c0164e2a3a99e2343adc13161b9a2c720bee543c0ba95daef7095d3453eef1d0c8df420a0d4f76665359a7c699b7bd74ff4cd87fe33ca1db38b5b9517d1047d5";
const P521_SIG_AD: &str = "30818802420173dc8a6af2a878da4616fc55c7edd9d03f6efc11b697951051fdfdd366dd9e776bca76cdc09b8d35d9dab8aa173ed75bf09f1d672e056a0ed38f43a391baf04f710242012547945fd0624d16992b00a3f7fc90de469126693ff525ab3de1544cec8f6089a74cb3f9eae1dad360ddbd48886f0d99e231ecc6f0cf607e55905f8058f612cc6f";
const K256_SIG: &str = "3045022100dce7353b4a16aff72f3d846147709be49bdee49a7f0d8b9eb29fcc1f62e6e1c402202e83005a8c5d959887423f4f026cc507316126f728f411727382157cc8f4d8fa";

// Short and long hashes (Review Focus 1): `Ok(sig)` as signed by A.
const P256_H16: &str = "Ok(3045022100d81dad5dad02cd02cfc5c043aaa9a9185c349b5ea7316edb8b83348f863f424e022020c8e5a5094eff29c9f54d1d8ba4919397ff2d320825dec43a0a8f46568dd542)";
const P256_H20: &str = "Ok(304402201b0c0d933b9fde4701371c382e44da767207a5daf1c54183e4defb27d0d09be4022068cc53f26b9af8a32b6047cca39319eaca9c7ce30cb7ff386442d730e5bbb915)";
const P256_H64: &str = "Ok(3046022100990010cba57e6b7023fea81860b5f75b9e3a02f96a488833bead233370c6b852022100ae472926162299108f9bc4a196b29658a8c78711ffa9d72488ba7cc9193baef8)";
// P-521 / 20-byte hash, left-padded to 66 bytes as `ecdsa_sign` does (the
// production path), signed with the deterministic `ad = &[]` entry point.
const P521_H20: &str = "Ok(30818802420113edf89ed6d0800fa99a59b9737a522ec090e4c78ac4b981c073501e74e25eb2dfe6e29e3034143bfea05f78d815bf7dc1caf97deda129bf90d94bb068fb9af6c602420171f544db4732315e315a0d540b2c5907acbd5755a9621070f05a388a03184f0191a94e67be72f5959caad2c1338cbfa26edb0252636e6d243f7769b861e1e38192)";
// Internal-API invariant, not a Review Focus case: the raw entry point does
// no padding of its own, so an unpadded 20-byte hash is refused.
const P521_H20_RAW: &str = "Err(SignFailure)";

// Domain key helpers.
const DOMAIN_ID: &str = "e1f2b60bf7bd82f9d20ab50612d3e100";
/// `r || s` of `P256_SIG`, as `verify_prehash` takes it.
const DOMAIN_SIG_RS: &str = "972c42bdec46a64908a7cbf7aa4f4f6aa70d82622b0ea73faf1039c7f1a3e6cb190e5735f69d6df054bc8be864da2ce95c7dd6a6279dd2e9892ff05d859c3807";

// HD derivation from `hd_seed()` over `HD_PATH`: private key || chain code,
// then the public point of the private key.
const BIP32_RAW: &str = "0a0e19a0bf70b9afee1d12d8b05608b1a6effafafa8fb63a0acbe11e00b6a7ba55d601a2188e88a86a815145641446af6d4d8c5a3ea36eb1dd57737eac4252b4";
const SLIP10_K256_RAW: &str = "0a0e19a0bf70b9afee1d12d8b05608b1a6effafafa8fb63a0acbe11e00b6a7ba55d601a2188e88a86a815145641446af6d4d8c5a3ea36eb1dd57737eac4252b4";
const SLIP10_P256_RAW: &str = "b5e86398dd68a66645c858f487deeb00f6bf0e8d808a84c85cc5c15bc9d76971593541268bb12b15840441910435cc41d03eff5fccf6af09e606131ce5ea52e0";
const BIP32_PUB: &str = "04a174b306c6463537d94fd21b33a2e545a32fc74edd21853b3b58880dc954146a314437060a51ee854d663a49f4fcc4d4ffa9a3d05ccee7abf0900643476b7319";
const SLIP10_K256_PUB: &str = "04a174b306c6463537d94fd21b33a2e545a32fc74edd21853b3b58880dc954146a314437060a51ee854d663a49f4fcc4d4ffa9a3d05ccee7abf0900643476b7319";
const SLIP10_P256_PUB: &str = "0474637dfbb4cb70bdc7b57813e2206857fda9bcbbf640d0612ad3b862b7bbcc8c0f8f61ea930fe4d45a33558ad76741f094928bd70dad1a49b538568dea00fffe";

// Negative cases: today's result for each input, as a string.
// Peer points: truncated, 0x04 || zeros, Y + 1, compressed, SEC1 identity (0x00).
const P256_BAD_PEER: [&str; 5] = [
    "Err(EcdhFailure)",
    "Err(EcdhFailure)",
    "Err(EcdhFailure)",
    "Ok(e9ab500eb7fc602cb5e2cd95994a049fc5a9a2284780e25c66d6287443de02a8)",
    "Err(EcdhFailure)",
];
const P384_BAD_PEER: [&str; 5] = [
    "Err(EcdhFailure)",
    "Err(EcdhFailure)",
    "Err(EcdhFailure)",
    "Ok(adf0079ceb6239e3c3b61472fd6a9127319e6433b52b721b620d474a0eb1d98638ae5d4547745d7e98c18b6766e31595)",
    "Err(EcdhFailure)",
];
const P521_BAD_PEER: [&str; 5] = [
    "Err(EcdhFailure)",
    "Err(EcdhFailure)",
    "Err(EcdhFailure)",
    "Ok(0046d1963f3e13bd69dcef6848cd9ef22b61b3a423b275383ab79bd07e88aba2fec54c6fc2b23147ba5ed9bf5890e0b58a6dc21fc5dcf9889d8b3a8e610b7c4e4e82)",
    "Err(EcdhFailure)",
];
const K256_BAD_PEER: [&str; 5] = [
    "Err(EcdhFailure)",
    "Err(EcdhFailure)",
    "Err(EcdhFailure)",
    "Ok(06e538821aac0f4d680bbcb3a0f993c104738694cd9c27f90dd022458a960b82)",
    "Err(EcdhFailure)",
];
// Scalars: zero, n, n + 1, one byte short.
const P256_BAD_SCALAR: [&str; 4] = [
    "Err(WrongKeyLength)",
    "Err(WrongKeyLength)",
    "Err(WrongKeyLength)",
    "Ok",
];
const P384_BAD_SCALAR: [&str; 4] = [
    "Err(WrongKeyLength)",
    "Err(WrongKeyLength)",
    "Err(WrongKeyLength)",
    "Ok",
];
const P521_BAD_SCALAR: [&str; 4] = [
    "Err(WrongKeyLength)",
    "Err(WrongKeyLength)",
    "Err(WrongKeyLength)",
    "Ok",
];
const K256_BAD_SCALAR: [&str; 4] = [
    "Err(WrongKeyLength)",
    "Err(WrongKeyLength)",
    "Err(WrongKeyLength)",
    "Ok",
];
// Signatures: truncated by a byte, high-S (s -> n - s), r = 0.
const P256_BAD_SIG: [&str; 3] = ["Err(VerifyFailure)", "Ok(true)", "Ok(false)"];
const P384_BAD_SIG: [&str; 3] = ["Err(VerifyFailure)", "Ok(true)", "Ok(false)"];
const P521_BAD_SIG: [&str; 3] = ["Err(VerifyFailure)", "Ok(true)", "Err(VerifyFailure)"];
const K256_BAD_SIG: [&str; 3] = ["Err(VerifyFailure)", "Ok(false)", "Ok(false)"];

// Group orders n, big-endian, field-length wide.
const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
const P384_N: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
const P521_N: &str = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
const K256_N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Counter-hash PRNG with a fixed output stream (same shape as the one in the
/// SC-HSM command tests); only used to capture the key vectors once.
struct CounterRng(u64);

impl RngCore for CounterRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15u64);
            let v = self.0.wrapping_mul(0x6c62272e07bb0142u64) ^ 0xbf58476d1ce4e5b9u64;
            let vb = v.to_le_bytes();
            chunk.copy_from_slice(&vb[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for CounterRng {}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex literal")
}

/// Assert `actual` equals the hex literal `expected`.
fn ck(label: &str, actual: &[u8], expected: &str) {
    assert_eq!(hex::encode(actual), expected, "{label}");
}

/// Assert the `Debug`/summary string `actual` equals `expected`.
fn cks(label: &str, actual: String, expected: &str) {
    assert_eq!(actual, expected, "{label}");
}

/// Render a byte-vector result as `Ok(hex)` / `Err(variant)`.
fn bytes_res<T: AsRef<[u8]>>(r: Result<T, CryptoError>) -> String {
    match r {
        Ok(v) => format!("Ok({})", hex::encode(v.as_ref())),
        Err(e) => format!("Err({e:?})"),
    }
}

/// Render a signing result without the (possibly randomised) bytes.
fn sign_res<T>(r: Result<T, CryptoError>) -> String {
    match r {
        Ok(_) => "Ok".into(),
        Err(e) => format!("Err({e:?})"),
    }
}

/// Everything the tests need to know about one curve.
struct Cv {
    kt: KeyType,
    tag: &'static str,
    a_priv: &'static str,
    a_pub: &'static str,
    b_priv: &'static str,
    b_pub: &'static str,
    n: &'static str,
    ecdh: &'static str,
    sig: &'static str,
    bad_peer: [&'static str; 5],
    bad_scalar: [&'static str; 4],
    bad_sig: [&'static str; 3],
}

fn curves() -> [Cv; 4] {
    [
        Cv {
            kt: P256,
            tag: "P256",
            a_priv: P256_A_PRIV,
            a_pub: P256_A_PUB,
            b_priv: P256_B_PRIV,
            b_pub: P256_B_PUB,
            n: P256_N,
            ecdh: P256_ECDH,
            sig: P256_SIG,
            bad_peer: P256_BAD_PEER,
            bad_scalar: P256_BAD_SCALAR,
            bad_sig: P256_BAD_SIG,
        },
        Cv {
            kt: P384,
            tag: "P384",
            a_priv: P384_A_PRIV,
            a_pub: P384_A_PUB,
            b_priv: P384_B_PRIV,
            b_pub: P384_B_PUB,
            n: P384_N,
            ecdh: P384_ECDH,
            sig: P384_SIG,
            bad_peer: P384_BAD_PEER,
            bad_scalar: P384_BAD_SCALAR,
            bad_sig: P384_BAD_SIG,
        },
        Cv {
            kt: P521,
            tag: "P521",
            a_priv: P521_A_PRIV,
            a_pub: P521_A_PUB,
            b_priv: P521_B_PRIV,
            b_pub: P521_B_PUB,
            n: P521_N,
            ecdh: P521_ECDH,
            sig: P521_SIG,
            bad_peer: P521_BAD_PEER,
            bad_scalar: P521_BAD_SCALAR,
            bad_sig: P521_BAD_SIG,
        },
        Cv {
            kt: K256,
            tag: "K256",
            a_priv: K256_A_PRIV,
            a_pub: K256_A_PUB,
            b_priv: K256_B_PRIV,
            b_pub: K256_B_PUB,
            n: K256_N,
            ecdh: K256_ECDH,
            sig: K256_SIG,
            bad_peer: K256_BAD_PEER,
            bad_scalar: K256_BAD_SCALAR,
            bad_sig: K256_BAD_SIG,
        },
    ]
}

/// The fixed hash signed on each curve.
fn hash_for(kt: KeyType) -> Vec<u8> {
    match kt {
        P256 => vec![0x11; 32],
        P384 => vec![0x22; 48],
        P521 => vec![0x44; 64],
        _ => vec![0x33; 32],
    }
}

/// Sign with A's key: deterministic RFC 6979 everywhere; P-521 goes through
/// the `ad` entry point because `ecdsa_sign` hedges it with random bytes.
fn sign_a(c: &Cv, hash: &[u8], ad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sk = h(c.a_priv);
    let sig = if c.kt == P521 {
        ecdsa_sign_p521_with_ad(&sk, hash, ad)?
    } else {
        ecdsa_sign(c.kt, &sk, hash, &mut CounterRng(7))?
    };
    Ok(sig.to_vec())
}

/// Big-endian `a - b` (same width, a >= b).
fn sub_be(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = a.to_vec();
    let mut borrow = 0i16;
    for i in (0..a.len()).rev() {
        let mut d = a[i] as i16 - b[i] as i16 - borrow;
        borrow = if d < 0 { 1 } else { 0 };
        if d < 0 {
            d += 256;
        }
        out[i] = d as u8;
    }
    out
}

/// Big-endian `a + 1` (wrapping at the width).
fn inc_be(a: &[u8]) -> Vec<u8> {
    let mut out = a.to_vec();
    for b in out.iter_mut().rev() {
        let (v, c) = b.overflowing_add(1);
        *b = v;
        if !c {
            break;
        }
    }
    out
}

/// Split a DER `SEQUENCE { INTEGER r, INTEGER s }` into its raw integers.
fn der_rs(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut i = 2;
    if der[1] & 0x80 != 0 {
        i += (der[1] & 0x7f) as usize;
    }
    assert_eq!(der[i], 0x02);
    let rl = der[i + 1] as usize;
    let r = der[i + 2..i + 2 + rl].to_vec();
    let j = i + 2 + rl;
    assert_eq!(der[j], 0x02);
    let sl = der[j + 1] as usize;
    let s = der[j + 2..j + 2 + sl].to_vec();
    (strip_zeros(&r), strip_zeros(&s))
}

/// Drop leading zero bytes (DER sign padding), keeping at least one byte.
fn strip_zeros(v: &[u8]) -> Vec<u8> {
    let first = v.iter().position(|&b| b != 0).unwrap_or(v.len() - 1);
    v[first..].to_vec()
}

fn der_int(v: &[u8]) -> Vec<u8> {
    let v = &strip_zeros(v)[..];
    let mut out = vec![0x02];
    if v[0] & 0x80 != 0 {
        out.push(v.len() as u8 + 1);
        out.push(0);
    } else {
        out.push(v.len() as u8);
    }
    out.extend_from_slice(v);
    out
}

/// DER `SEQUENCE { INTEGER r, INTEGER s }` from raw big-endian integers.
fn der_encode(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut body = der_int(r);
    body.extend(der_int(s));
    let mut out = vec![0x30];
    if body.len() > 127 {
        out.push(0x81);
    }
    out.push(body.len() as u8);
    out.extend(body);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn public_points_are_unchanged() {
    for c in curves() {
        for (seed, priv_hex, pub_hex, who) in
            [(1u64, c.a_priv, c.a_pub, "A"), (2, c.b_priv, c.b_pub, "B")]
        {
            let kp = generate_ec_keypair(c.kt, &mut CounterRng(seed)).unwrap();
            ck(&format!("{}_{who}_PRIV", c.tag), &kp.private_key, priv_hex);
            ck(&format!("{}_{who}_PUB", c.tag), &kp.public_key, pub_hex);
        }
    }
}

#[test]
fn signatures_are_unchanged() {
    for c in curves() {
        let hash = hash_for(c.kt);
        let sig = sign_a(&c, &hash, &[]).unwrap();
        ck(&format!("{}_SIG", c.tag), &sig, c.sig);
        assert_eq!(
            ecdsa_verify(c.kt, &h(c.a_pub), &hash, &sig),
            Ok(true),
            "{}",
            c.tag
        );
    }
    // P-521 with additional data mixed into the nonce derivation.
    let c = &curves()[2];
    let hash = hash_for(P521);
    let sig = sign_a(c, &hash, &[0x5A; 32]).unwrap();
    ck("P521_SIG_AD", &sig, P521_SIG_AD);
    assert_eq!(ecdsa_verify(P521, &h(P521_A_PUB), &hash, &sig), Ok(true));
}

#[test]
fn ecdh_is_unchanged() {
    for c in curves() {
        let ab = ecdh_agree(c.kt, &h(c.a_priv), &h(c.b_pub)).unwrap();
        let ba = ecdh_agree(c.kt, &h(c.b_priv), &h(c.a_pub)).unwrap();
        ck(&format!("{}_ECDH", c.tag), &ab, c.ecdh);
        assert_eq!(ab, ba, "{}", c.tag);
    }
    // The DKEK helper agrees with the generic one on P-256.
    let a: [u8; 32] = h(P256_A_PRIV).try_into().unwrap();
    let b_pub: [u8; 65] = h(P256_B_PUB).try_into().unwrap();
    let z = p256_ecdh(&a, &b_pub).unwrap();
    ck("P256_ECDH (dkek)", &z[..], P256_ECDH);
}

#[test]
fn domain_key_is_unchanged() {
    let q: [u8; 65] = h(P256_A_PUB).try_into().unwrap();
    ck("DOMAIN_ID", &domain_id(&q), DOMAIN_ID);

    // P256_SIG signs [0x11; 32], which is a valid SHA-256-sized digest.
    let digest = [0x11u8; 32];
    let rs: [u8; 64] = h(DOMAIN_SIG_RS).try_into().unwrap();
    assert!(verify_prehash(&q, &digest, &rs));
    let mut bad = rs;
    bad[63] ^= 1;
    assert!(!verify_prehash(&q, &digest, &bad));
    assert!(!verify_prehash(&q, &[0x12u8; 32], &rs));
}

const HD_PATH: [u32; 4] = [0x8000_002C, 0x8000_0000, 0, 1];

fn hd_master(kt: KeyType) -> KeyMaterial {
    let seed: Vec<u8> = (0u8..64).collect();
    let mut raw = heapless::Vec::<u8, MAX_KEY_BYTES>::new();
    raw.extend_from_slice(&seed).unwrap();
    KeyMaterial {
        key_type: kt,
        key_id: KeyId::sc_hsm(0, 1),
        raw,
    }
}

/// Uncompressed public point for a 32-byte private key on K-256 / P-256.
fn pub_of(kt: KeyType, sk: &[u8]) -> Vec<u8> {
    use elliptic_curve::sec1::ToSec1Point;
    if kt == K256 {
        let k = k256::SecretKey::from_slice(sk).unwrap();
        k.public_key().to_sec1_point(false).as_bytes().to_vec()
    } else {
        let k = p256::SecretKey::from_slice(sk).unwrap();
        k.public_key().to_sec1_point(false).as_bytes().to_vec()
    }
}

#[test]
fn hd_derivation_is_unchanged() {
    let bip = bip32_derive(&hd_master(KeyType::Bip32Master), &HD_PATH).unwrap();
    ck("BIP32_RAW", &bip.raw, BIP32_RAW);
    ck("BIP32_PUB", &pub_of(K256, &bip.raw[..32]), BIP32_PUB);

    let k = slip10_derive(&hd_master(K256), &HD_PATH).unwrap();
    ck("SLIP10_K256_RAW", &k.raw, SLIP10_K256_RAW);
    ck(
        "SLIP10_K256_PUB",
        &pub_of(K256, &k.raw[..32]),
        SLIP10_K256_PUB,
    );

    let p = slip10_derive(&hd_master(P256), &HD_PATH).unwrap();
    ck("SLIP10_P256_RAW", &p.raw, SLIP10_P256_RAW);
    ck(
        "SLIP10_P256_PUB",
        &pub_of(P256, &p.raw[..32]),
        SLIP10_P256_PUB,
    );
}

#[test]
fn hash_lengths_are_unchanged() {
    let p256 = &curves()[0];
    for (label, c, len, expected) in [
        ("P256_H16", p256, 16usize, P256_H16),
        ("P256_H20", p256, 20, P256_H20),
        ("P256_H64", p256, 64, P256_H64),
    ] {
        let hash = vec![0x55u8; len];
        let sig = sign_a(c, &hash, &[]);
        cks(label, bytes_res(sig.clone()), expected);
        if let Ok(sig) = sig {
            assert_eq!(
                ecdsa_verify(c.kt, &h(c.a_pub), &hash, &sig),
                Ok(true),
                "{label}"
            );
        }
    }

    // P-521 / SHA-1-sized hash. Production `ecdsa_sign` left-pads to the
    // 66-byte field and then signs; pin that through the deterministic entry.
    let p521 = &curves()[2];
    let hash = [0x55u8; 20];
    let mut padded = [0u8; 66];
    padded[46..].copy_from_slice(&hash);
    let sig = sign_a(p521, &padded, &[]);
    cks("P521_H20", bytes_res(sig.clone()), P521_H20);
    // The public API must accept the short hash and verify against it.
    let public = ecdsa_sign(P521, &h(P521_A_PRIV), &hash, &mut CounterRng(7)).unwrap();
    assert_eq!(ecdsa_verify(P521, &h(P521_A_PUB), &hash, &public), Ok(true));
    if let Ok(sig) = sig {
        assert_eq!(ecdsa_verify(P521, &h(P521_A_PUB), &hash, &sig), Ok(true));
    }
    // Internal-API invariant: the unpadded hash is refused by the raw entry.
    cks(
        "P521_H20_RAW",
        bytes_res(sign_a(p521, &hash, &[])),
        P521_H20_RAW,
    );
}

#[test]
fn bad_peer_points_are_refused() {
    for c in curves() {
        let a_priv = h(c.a_priv);
        let b_pub = h(c.b_pub);
        let coord = (b_pub.len() - 1) / 2;

        let truncated = b_pub[..b_pub.len() - 1].to_vec();
        let mut zeros = vec![0u8; b_pub.len()];
        zeros[0] = 0x04;
        // Y + 1: still the right length, almost surely not on the curve.
        let mut y_plus_one = b_pub.clone();
        let y = inc_be(&b_pub[1 + coord..]);
        y_plus_one[1 + coord..].copy_from_slice(&y);
        // SEC1 compressed form of the valid point.
        let mut compressed = vec![0x02 | (b_pub[b_pub.len() - 1] & 1)];
        compressed.extend_from_slice(&b_pub[1..1 + coord]);

        // SEC1 identity (point at infinity) encoding.
        let identity = vec![0x00];

        for (i, peer) in [truncated, zeros, y_plus_one, compressed, identity]
            .iter()
            .enumerate()
        {
            let r = bytes_res(ecdh_agree(c.kt, &a_priv, peer));
            cks(&format!("{}_BAD_PEER[{i}]", c.tag), r, c.bad_peer[i]);
        }
    }
}

#[test]
fn bad_private_scalars_are_refused() {
    for c in curves() {
        let n = h(c.n);
        let one_short = h(c.a_priv)[1..].to_vec();
        let n_plus_one = inc_be(&n);
        let hash = hash_for(c.kt);
        for (i, sk) in [vec![0u8; n.len()], n.clone(), n_plus_one, one_short]
            .iter()
            .enumerate()
        {
            let r = if c.kt == P521 {
                sign_res(ecdsa_sign(c.kt, sk, &hash, &mut CounterRng(9)))
            } else {
                sign_res(ecdsa_sign(c.kt, sk, &hash, &mut CounterRng(9)))
            };
            cks(&format!("{}_BAD_SCALAR[{i}]", c.tag), r, c.bad_scalar[i]);
        }
    }
}

#[test]
fn bad_signatures_verify_as_before() {
    for c in curves() {
        let hash = hash_for(c.kt);
        let pubkey = h(c.a_pub);
        let sig = h(c.sig);
        let (r, s) = der_rs(&sig);
        // Pad to the field width so the subtraction lines up with n.
        let n = h(c.n);
        let mut s_full = vec![0u8; n.len() - s.len()];
        s_full.extend_from_slice(&s);
        let high_s = der_encode(&r, &sub_be(&n, &s_full));
        let r_zero = der_encode(&[0], &s);
        let truncated = sig[..sig.len() - 1].to_vec();
        for (i, bad) in [truncated, high_s, r_zero].iter().enumerate() {
            let r = format!("{:?}", ecdsa_verify(c.kt, &pubkey, &hash, bad));
            cks(&format!("{}_BAD_SIG[{i}]", c.tag), r, c.bad_sig[i]);
        }
    }
}
