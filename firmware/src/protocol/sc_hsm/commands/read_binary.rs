//! READ BINARY command handler (INS = 0xB0).
//!
//! Reads bytes from the PKCS#15 virtual filesystem. File IDs are encoded
//! in P1P2. Supported EF identifiers:
//!
//! - `0x2F00`: EF.DIR
//! - `0x5031`: ODF
//! - `0x5032`: TokenInfo
//! - `0xC000`: AODF
//! - `0xC100`: PrKDF (dynamically built from in-memory keystore)
//! - `0xC200`: PuKDF
//! - `0xC400+key_id`: PRKD for a specific key (PKCS#15 PrivateECKey DER)
//! - `0xCC00+key_id`: Key blob (not yet supported — returns NOT FOUND)
//! - `0xCE00+key_id`: Certificate EF (not yet supported — returns NOT FOUND)

use heapless::Vec;
use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_FILE_NOT_FOUND, SW_OK, SW_WRONG_DATA};

use crate::protocol::sc_hsm::{pkcs15_objects, ScHsmState};

/// INS byte for READ BINARY (standard, P1P2 = file-id or offset).
pub const INS_READ_BINARY: u8 = 0xB0;

/// INS byte for READ BINARY ODD (SC-HSM proprietary).
/// File reference and optional offset are encoded in command data as TLV:
///   `54 02 <fid_hi> <fid_lo>`              — read from start of file
///   `54 04 <fid_hi> <fid_lo> <off_hi> <off_lo>` — read with offset
pub const INS_READ_BINARY_ODD: u8 = 0xB1;

// ---------------------------------------------------------------------------
// Curve OIDs (DER value bytes, without tag/length)
// ---------------------------------------------------------------------------

const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x23];
const OID_K256: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x0A];

fn algo_to_oid(algo: u8) -> Option<&'static [u8]> {
    match algo {
        0x13 | 0x23 => Some(OID_P256),
        0x15 | 0x25 => Some(OID_P384),
        0x17 | 0x27 => Some(OID_P521),
        0x19 | 0x29 => Some(OID_K256),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// DER helpers
// ---------------------------------------------------------------------------

fn push_der_len(buf: &mut Vec<u8, 256>, len: usize) {
    if len < 128 {
        let _ = buf.push(len as u8);
    } else {
        let _ = buf.push(0x81);
        let _ = buf.push(len as u8);
    }
}

fn push_tlv(buf: &mut Vec<u8, 256>, tag: u8, value: &[u8]) {
    let _ = buf.push(tag);
    push_der_len(buf, value.len());
    let _ = buf.extend_from_slice(value);
}

fn push_2byte_tag_tlv(buf: &mut Vec<u8, 256>, tag0: u8, tag1: u8, inner: &[u8]) {
    let _ = buf.push(tag0);
    let _ = buf.push(tag1);
    push_der_len(buf, inner.len());
    let _ = buf.extend_from_slice(inner);
}

// ---------------------------------------------------------------------------
// Build a PKCS#15 PrivateECKey descriptor (PRKD at EF 0xC4xx)
// ---------------------------------------------------------------------------
//
// Format (SC-HSM style):
//   30 xx                           -- outer SEQUENCE
//     A0 xx                         -- [0] CommonObjectAttributes
//       30 xx
//         03 02 06 C0               -- keyUsageFlags (sign + keyAgreement)
//     A1 xx                         -- [1] CommonKeyAttributes
//       30 xx
//         04 01 <key_id>            -- id
//         03 02 06 C0               -- keyUsageFlags
//         01 01 FF                  -- native TRUE
//     A3 xx                         -- [3] PrivateECKeyAttributes
//       30 xx
//         30 xx                     -- ecKeyType (AlgorithmIdentifier)
//           06 xx <curve_OID>
//         30 xx                     -- ecAttr (path)
//           04 02 C4 <key_id>

fn build_ec_prkd(key_id: u8, algo: u8) -> Option<Vec<u8, 256>> {
    let curve_oid = algo_to_oid(algo)?;

    // keyUsageFlags BIT STRING: sign + keyAgreement = 0xC0 (bits 1 and 5 set)
    let key_usage_bs: [u8; 4] = [0x03, 0x02, 0x06, 0xC0];

    // A0 content: 30 (03 02 06 C0)
    let mut coa_inner: Vec<u8, 32> = Vec::new();
    let _ = coa_inner.extend_from_slice(&key_usage_bs);
    let mut coa_seq: Vec<u8, 40> = Vec::new();
    let _ = coa_seq.push(0x30);
    let _ = coa_seq.push(coa_inner.len() as u8);
    let _ = coa_seq.extend_from_slice(&coa_inner);

    // A1 content: 30 (04 01 XX  03 02 06 C0  01 01 FF)
    let mut cka_inner: Vec<u8, 32> = Vec::new();
    // id
    let _ = cka_inner.extend_from_slice(&[0x04, 0x01, key_id]);
    // keyUsageFlags
    let _ = cka_inner.extend_from_slice(&key_usage_bs);
    // native
    let _ = cka_inner.extend_from_slice(&[0x01, 0x01, 0xFF]);
    let mut cka_seq: Vec<u8, 48> = Vec::new();
    let _ = cka_seq.push(0x30);
    let _ = cka_seq.push(cka_inner.len() as u8);
    let _ = cka_seq.extend_from_slice(&cka_inner);

    // A3 content:
    //   30 (30 (06 LL <oid>)  30 (04 02 C4 key_id))
    let mut alg_seq: Vec<u8, 24> = Vec::new();
    let _ = alg_seq.push(0x06);
    let _ = alg_seq.push(curve_oid.len() as u8);
    let _ = alg_seq.extend_from_slice(curve_oid);
    let mut alg_outer: Vec<u8, 28> = Vec::new();
    let _ = alg_outer.push(0x30);
    let _ = alg_outer.push(alg_seq.len() as u8);
    let _ = alg_outer.extend_from_slice(&alg_seq);

    let path_inner: [u8; 4] = [0x04, 0x02, 0xC4, key_id];
    let mut path_outer: Vec<u8, 8> = Vec::new();
    let _ = path_outer.push(0x30);
    let _ = path_outer.push(path_inner.len() as u8);
    let _ = path_outer.extend_from_slice(&path_inner);

    let a3_body_len = alg_outer.len() + path_outer.len();
    let mut a3_body: Vec<u8, 64> = Vec::new();
    let _ = a3_body.push(0x30);
    let _ = a3_body.push(a3_body_len as u8);
    let _ = a3_body.extend_from_slice(&alg_outer);
    let _ = a3_body.extend_from_slice(&path_outer);

    // Assemble outer SEQUENCE
    let outer_body_len = (2 + coa_seq.len()) + (2 + cka_seq.len()) + (2 + a3_body.len());
    let mut out: Vec<u8, 256> = Vec::new();
    let _ = out.push(0x30);
    let _ = out.push(outer_body_len as u8);
    // [0] EXPLICIT
    let _ = out.push(0xA0);
    let _ = out.push(coa_seq.len() as u8);
    let _ = out.extend_from_slice(&coa_seq);
    // [1] EXPLICIT
    let _ = out.push(0xA1);
    let _ = out.push(cka_seq.len() as u8);
    let _ = out.extend_from_slice(&cka_seq);
    // [3] EXPLICIT
    let _ = out.push(0xA3);
    let _ = out.push(a3_body.len() as u8);
    let _ = out.extend_from_slice(&a3_body);

    Some(out)
}

// ---------------------------------------------------------------------------
// Build a PKCS#15 PrivateRSAKey descriptor (PRKD at EF 0xC4xx)
// ---------------------------------------------------------------------------
//
// Format (SC-HSM style, mirrors EC PRKD but with [1] RSA attributes):
//   30 xx                           -- outer SEQUENCE
//     A0 xx                         -- [0] CommonObjectAttributes
//       30 xx
//         03 02 05 C0               -- keyUsageFlags (sign + decrypt, no keyAgreement)
//     A1 xx                         -- [1] CommonKeyAttributes
//       30 xx
//         04 01 <key_id>            -- id
//         03 02 05 C0               -- keyUsageFlags
//         01 01 FF                  -- native TRUE
//     A1 xx                         -- [1] PrivateRSAKeyAttributes
//       30 xx
//         30 xx                     -- rsaKeyType (AlgorithmIdentifier: RSA OID, no params)
//           06 09 2A 86 48 86 F7 0D 01 01 01
//         30 xx                     -- rsaAttr (path)
//           04 02 C4 <key_id>
//
// NOTE: PKCS#15 uses [1] CONTEXT tag for PrivateRSAKeyAttributes (rsaPrivateKey choice),
// which overlaps with [1] CommonKeyAttributes.  In the SC-HSM DER encoding the outer
// SEQUENCE uses the following tag ordering: A0, A1 (common key attrs), A1 (RSA attrs).
// OpenSC's sc-hsm driver accepts the flat PrivateKeyInfo path approach; the path
// `04 02 C4 <key_id>` tells OpenSC where to load the key descriptor.

/// OID for rsaEncryption: 1.2.840.113549.1.1.1
const OID_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];

#[cfg(feature = "rsa")]
fn build_rsa_prkd(key_id: u8, _algo: u8) -> Vec<u8, 256> {
    // keyUsageFlags BIT STRING: sign (bit 1) + decrypt (bit 3) = 0xC0 in the usage byte,
    // with 5 unused bits.  Value: 03 02 05 C0.
    let key_usage_bs: [u8; 4] = [0x03, 0x02, 0x05, 0xC0];

    // A0 content: 30 (03 02 05 C0)
    let coa_inner = key_usage_bs;
    let mut coa_seq: Vec<u8, 16> = Vec::new();
    let _ = coa_seq.push(0x30);
    let _ = coa_seq.push(coa_inner.len() as u8);
    let _ = coa_seq.extend_from_slice(&coa_inner);

    // A1 (CommonKeyAttributes) content: 30 (04 01 XX  03 02 05 C0  01 01 FF)
    let mut cka_inner: Vec<u8, 32> = Vec::new();
    let _ = cka_inner.extend_from_slice(&[0x04, 0x01, key_id]);
    let _ = cka_inner.extend_from_slice(&key_usage_bs);
    let _ = cka_inner.extend_from_slice(&[0x01, 0x01, 0xFF]);
    let mut cka_seq: Vec<u8, 40> = Vec::new();
    let _ = cka_seq.push(0x30);
    let _ = cka_seq.push(cka_inner.len() as u8);
    let _ = cka_seq.extend_from_slice(&cka_inner);

    // A1 (PrivateRSAKeyAttributes) content:
    //   30 (30 (06 09 <rsa_oid>  05 00)  30 (04 02 C4 key_id))
    let mut alg_seq: Vec<u8, 16> = Vec::new();
    let _ = alg_seq.push(0x06);
    let _ = alg_seq.push(OID_RSA.len() as u8);
    let _ = alg_seq.extend_from_slice(OID_RSA);
    // NULL params: 05 00
    let _ = alg_seq.push(0x05);
    let _ = alg_seq.push(0x00);
    let mut alg_outer: Vec<u8, 20> = Vec::new();
    let _ = alg_outer.push(0x30);
    let _ = alg_outer.push(alg_seq.len() as u8);
    let _ = alg_outer.extend_from_slice(&alg_seq);

    let path_inner: [u8; 4] = [0x04, 0x02, 0xC4, key_id];
    let mut path_outer: Vec<u8, 8> = Vec::new();
    let _ = path_outer.push(0x30);
    let _ = path_outer.push(path_inner.len() as u8);
    let _ = path_outer.extend_from_slice(&path_inner);

    let rsa_attr_inner_len = alg_outer.len() + path_outer.len();
    let mut rsa_attr_inner: Vec<u8, 40> = Vec::new();
    let _ = rsa_attr_inner.push(0x30);
    let _ = rsa_attr_inner.push(rsa_attr_inner_len as u8);
    let _ = rsa_attr_inner.extend_from_slice(&alg_outer);
    let _ = rsa_attr_inner.extend_from_slice(&path_outer);

    // Assemble outer SEQUENCE: A0, A1(common), A1(rsa)
    let outer_body_len = (2 + coa_seq.len()) + (2 + cka_seq.len()) + (2 + rsa_attr_inner.len());
    let mut out: Vec<u8, 256> = Vec::new();
    let _ = out.push(0x30);
    let _ = out.push(outer_body_len as u8);
    // [0] EXPLICIT — CommonObjectAttributes
    let _ = out.push(0xA0);
    let _ = out.push(coa_seq.len() as u8);
    let _ = out.extend_from_slice(&coa_seq);
    // [1] EXPLICIT — CommonKeyAttributes
    let _ = out.push(0xA1);
    let _ = out.push(cka_seq.len() as u8);
    let _ = out.extend_from_slice(&cka_seq);
    // [1] EXPLICIT — PrivateRSAKeyAttributes
    let _ = out.push(0xA1);
    let _ = out.push(rsa_attr_inner.len() as u8);
    let _ = out.extend_from_slice(&rsa_attr_inner);

    out
}

// ---------------------------------------------------------------------------
// Build PrKDF (EF 0xC100) — sequence of key pointers
// ---------------------------------------------------------------------------
//
// For each EC key in the store emit:
//   A0 06 30 04 04 02 C4 <key_id>   -- PrivateKeyChoice for EC key
// For each RSA key in the store emit:
//   A1 06 30 04 04 02 C4 <key_id>   -- PrivateKeyChoice for RSA key
// These are PrivateKeyChoice entries pointing at the per-key PRKD.
// EC keys use [0] (PrivateECKey choice); RSA keys use [1] (PrivateRSAKey choice).

fn build_prkdf(state: &ScHsmState) -> Vec<u8, 256> {
    let mut out: Vec<u8, 256> = Vec::new();
    for key in &state.keys {
        // A0 06  30 04  04 02 C4 <key_id>
        // key.key_id is u32; extract the proto_ref byte (low byte) for the file ID.
        let proto_ref = (key.key_id & 0xFF) as u8;
        let _ = out.extend_from_slice(&[0xA0, 0x06, 0x30, 0x04, 0x04, 0x02, 0xC4, proto_ref]);
    }
    #[cfg(feature = "rsa")]
    for key in &state.rsa_keys {
        // A1 06  30 04  04 02 C4 <key_id>  — RSA key (PrivateRSAKey choice = [1])
        let proto_ref = (key.key_id & 0xFF) as u8;
        let _ = out.extend_from_slice(&[0xA1, 0x06, 0x30, 0x04, 0x04, 0x02, 0xC4, proto_ref]);
    }
    out
}

// ---------------------------------------------------------------------------
// Static device certificate (EF.C.DevAut at 0x2F02)
// ---------------------------------------------------------------------------
//
// A minimal CVC in 7F21 format that satisfies OpenSC's
// sc_pkcs15emu_sc_hsm_decode_cvc: CPI=0, EC public key OID, CHR >= 8 chars.
// CHR "DESE00001" → serial = CHR[0..4] = "DESE", len-5=4 chars of serial.
//
// Structure:
//   7F 21 23                    -- CVC (35 bytes)
//     7F 4E 1C                  -- Certificate Body (28 bytes)
//       5F 29 01 00             -- CPI = 0
//       7F 49 09                -- Public Key (9 bytes)
//         06 07 2A 86 48 CE 3D 02 01  -- EC OID (1.2.840.10045.2.1)
//       5F 20 09                -- CHR (9 bytes)
//         44 45 53 45 30 30 30 30 31  -- "DESE00001"
//     5F 37 01 00               -- dummy signature
#[rustfmt::skip]
const EF_DEV_AUT: &[u8] = &[
    0x7F, 0x21, 0x23,
      0x7F, 0x4E, 0x1C,
        0x5F, 0x29, 0x01, 0x00,
        0x7F, 0x49, 0x09,
          0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x5F, 0x20, 0x09,
          0x44, 0x45, 0x53, 0x45, 0x30, 0x30, 0x30, 0x30, 0x31,
      0x5F, 0x37, 0x01, 0x00,
];

// ---------------------------------------------------------------------------
// Command handler
// ---------------------------------------------------------------------------

/// Inner read: return up to `max_len` bytes from file `file_id` starting at
/// byte `offset`. Used by both the standard (INS=0xB0) and odd (INS=0xB1)
/// READ BINARY handlers.
fn read_file(state: &ScHsmState, file_id: u16, offset: usize, max_len: usize) -> ApduResponse {
    // Static EFs
    let static_data: Option<&[u8]> = match file_id {
        0x2F00 => Some(pkcs15_objects::EF_DIR),
        0x2F02 => Some(EF_DEV_AUT),
        0x5031 => Some(pkcs15_objects::EF_ODF),
        0x5032 => Some(pkcs15_objects::EF_TOKEN_INFO),
        0xC000 => Some(pkcs15_objects::EF_AODF),
        0xC200 => Some(pkcs15_objects::EF_PUKDF),
        _ => None,
    };

    if let Some(d) = static_data {
        let start = offset.min(d.len());
        let slice = &d[start..d.len().min(start + max_len)];
        return ApduResponse::ok(slice);
    }

    // PrKDF (0xC100): dynamically built from in-memory key stores.
    // Returns pointers to all EC and RSA key descriptors (EF 0xC4xx).
    if file_id == 0xC100 {
        let prkdf = build_prkdf(state);
        let start = offset.min(prkdf.len());
        let slice = &prkdf[start..prkdf.len().min(start + max_len)];
        return ApduResponse::ok(slice);
    }

    // Check dynamic EF store (written via WRITE DATA INS=0xD7)
    if let Some(entry) = state.ef_files.iter().find(|e| e.file_id == file_id) {
        let start = offset.min(entry.data.len());
        let slice = &entry.data[start..entry.data.len().min(start + max_len)];
        return ApduResponse::ok(slice);
    }

    // Dynamic EFs by high byte
    let hi = file_id >> 8;
    let key_id_proto = (file_id & 0xFF) as u8;
    let full_key_id = pico2hsm_core::key::KeyId::sc_hsm(0, key_id_proto).0;

    match hi {
        0xC4 => {
            // First check EC key store.
            let ec_algo = state.keys.iter().find(|k| k.key_id == full_key_id).map(|k| k.algo);
            if let Some(algo) = ec_algo {
                return match build_ec_prkd(key_id_proto, algo) {
                    Some(prkd) => {
                        let start = offset.min(prkd.len());
                        let slice = &prkd[start..prkd.len().min(start + max_len)];
                        ApduResponse::ok(slice)
                    }
                    None => ApduResponse::err(SW_FILE_NOT_FOUND),
                };
            }
            // Then check RSA key store (feature-gated).
            #[cfg(feature = "rsa")]
            {
                let rsa_key = state.rsa_keys.iter().find(|k| k.key_id == full_key_id);
                if let Some(key) = rsa_key {
                    let prkd = build_rsa_prkd(key_id_proto, key.algo);
                    let start = offset.min(prkd.len());
                    let slice = &prkd[start..prkd.len().min(start + max_len)];
                    return ApduResponse::ok(slice);
                }
            }
            ApduResponse::err(SW_FILE_NOT_FOUND)
        }
        0xCC | 0xCE => ApduResponse::err(SW_FILE_NOT_FOUND),
        _ => ApduResponse::err(SW_FILE_NOT_FOUND),
    }
}

/// Handle a READ BINARY APDU (INS=0xB0).
/// P1P2 encodes the file identifier (SC-HSM convention: not an offset).
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    if cmd.p1 & 0x80 != 0 {
        return ApduResponse::err(SW_FILE_NOT_FOUND);
    }
    let file_id: u16 = (cmd.p1 as u16) << 8 | (cmd.p2 as u16);
    let max_len = match cmd.le {
        Some(0) | None => 256usize,
        Some(n) => n as usize,
    };
    read_file(state, file_id, 0, max_len)
}

/// Handle a READ BINARY ODD APDU (INS=0xB1) — SC-HSM proprietary.
///
/// Command data contains a file-reference TLV (tag 0x54):
///   `54 02 <off_hi> <off_lo>`                    — offset in currently selected EF
///   `54 04 <fid_hi> <fid_lo> <off_hi> <off_lo>`  — explicit file ID + offset
///
/// OpenSC's `sc_hsm_read_binary` always sends `54 02 <offset>` (implicit file,
/// selected by the preceding SELECT command).  It may send extended-length APDUs
/// (ISO 7816-4 Case 4E) so the parser must handle those too.
pub fn handle_odd(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    let data = cmd.data;
    // Minimum: tag(1) + len(1) + offset-or-fid(2) = 4 bytes
    if data.len() < 4 || data[0] != 0x54 {
        return ApduResponse::err(SW_WRONG_DATA);
    }
    let ref_len = data[1] as usize;
    if ref_len < 2 || data.len() < 2 + ref_len {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Decode file ID and offset from TLV value.
    let (file_id, offset): (u16, usize) = if ref_len == 2 {
        // `54 02 <off_hi> <off_lo>`: implicit file (use currently selected EF), explicit offset
        let offset = (data[2] as usize) << 8 | (data[3] as usize);
        let fid = match state.current_file {
            Some(id) => id,
            None => return ApduResponse::err(SW_FILE_NOT_FOUND),
        };
        (fid, offset)
    } else if ref_len >= 4 && data.len() >= 6 {
        // `54 04 <fid_hi> <fid_lo> <off_hi> <off_lo>`: explicit file + offset
        let fid = (data[2] as u16) << 8 | (data[3] as u16);
        let offset = (data[4] as usize) << 8 | (data[5] as usize);
        (fid, offset)
    } else {
        return ApduResponse::err(SW_WRONG_DATA);
    };

    // Le=0 in extended APDUs means 65536; cap to our buffer limit.
    let max_len = match cmd.le {
        None => 256usize,
        Some(0) => 4094usize, // extended Le=0x0000 means 65536; cap to max response
        Some(n) => n as usize,
    };
    read_file(state, file_id, offset, max_len)
}
