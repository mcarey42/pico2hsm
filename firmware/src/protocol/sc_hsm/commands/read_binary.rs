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
use pico2hsm_core::key::KeyId;

use crate::protocol::sc_hsm::{pkcs15_objects, ScHsmState};
use crate::storage::KeyStore;

/// INS byte for READ BINARY (standard, P1P2 = file-id or offset).
pub const INS_READ_BINARY: u8 = 0xB0;

/// INS byte for READ BINARY ODD (SC-HSM proprietary).
/// File reference and optional offset are encoded in command data as TLV:
///   `54 02 <fid_hi> <fid_lo>`              — read from start of file
///   `54 04 <fid_hi> <fid_lo> <off_hi> <off_lo>` — read with offset
pub const INS_READ_BINARY_ODD: u8 = 0xB1;

// ---------------------------------------------------------------------------
// Build a PKCS#15 PrivateECKey descriptor (PRKD at EF 0xC4xx)
// ---------------------------------------------------------------------------
//
// PKCS#15 PrivateKeyType is a CHOICE; each alternative has its own outer tag
// so that the ASN.1 decoder can distinguish them.  OpenSC uses:
//   0x30 (SEQUENCE)      → privateRSAKey
//   0xA0 (context [0])   → privateECKey
//   0xA4 (context [4])   → privateGOSTR3410Key
//
// Inside the CHOICE, the PKCS#15 Object template expects:
//   SEQUENCE (0x30)      — commonObjectAttributes  (all fields OPTIONAL)
//   SEQUENCE (0x30)      — classAttributes (CommonKeyAttributes: iD + usage required)
//   [0] (0xA0) OPTIONAL  — subClassAttributes (CommonPrivateKeyAttributes)
//   [1] (0xA1)           — typeAttributes (PrivateECKeyAttributes)
//
// OpenSC's c_asn1_prk_ec_attr template expects typeAttributes to contain only:
//   "value" — SC_ASN1_PATH (tag SEQUENCE): a PATH { OCTET STRING }
// No AlgorithmIdentifier — curve info comes from the public key, not the PRKD.
//
// Format matching what OpenSC writes after GENERATE KEYPAIR:
//   A0 xx                           -- outer: context [0] = PrivateECKey CHOICE
//     30 xx                         -- CommonObjectAttributes (SEQUENCE)
//       03 02 06 C0                 -- flags BIT STRING (sign + keyAgreement)
//     30 xx                         -- CommonKeyAttributes (SEQUENCE)
//       04 01 <key_id>              -- iD
//       03 02 06 C0                 -- usage BIT STRING
//       01 01 FF                    -- native TRUE
//     A1 xx                         -- [1] typeAttributes: PrivateECKeyAttributes
//       30 xx
//         30 xx                     -- value = PATH
//           04 02 C4 <key_id>       -- path OCTET STRING
//         02 02 xx xx               -- fieldSize INTEGER (bits)
//
// fieldSize is REQUIRED: OpenSC 0.25 has a bug where ec_domain_len is
// initialised to sizeof(buffer)=32 but never reset when ecDomain is absent,
// so `!info.field_length && ec_domain_len` fires and d2i_ASN1_OBJECT parses
// garbage → SC_ERROR_INVALID_ASN1_OBJECT (-1401).  Including fieldSize
// sets info.field_length, making the condition false and avoiding the crash.

/// Map EC algo byte to field size in bits.
fn ec_field_size(algo: u8) -> u16 {
    match algo {
        0x13 | 0x23 => 256, // P-256
        0x15 | 0x25 => 384, // P-384
        0x17 | 0x27 => 521, // P-521
        0x19 | 0x29 => 256, // secp256k1
        _ => 256,           // default
    }
}

fn build_ec_prkd(key_id: u8, algo: u8) -> Vec<u8, 256> {
    // CommonObjectFlags BIT STRING: private (bit 0) + modifiable (bit 1).
    let coa_flags: [u8; 4] = [0x03, 0x02, 0x06, 0xC0];

    // KeyUsageFlags BIT STRING: sign (bit 2) + signRecover (bit 3) + derive (bit 8).
    // ASN.1 BIT STRING: 7 unused bits, bytes 0x30 0x80.
    //   0x30 = bit2 (sign) + bit3 (signRecover), 0x80 = bit8 (derive).
    let key_usage: [u8; 5] = [0x03, 0x03, 0x07, 0x30, 0x80];

    // CommonObjectAttributes: raw SEQUENCE (tag 0x30)
    let mut coa_inner: Vec<u8, 32> = Vec::new();
    let _ = coa_inner.extend_from_slice(&coa_flags);
    let mut coa_seq: Vec<u8, 40> = Vec::new();
    let _ = coa_seq.push(0x30);
    let _ = coa_seq.push(coa_inner.len() as u8);
    let _ = coa_seq.extend_from_slice(&coa_inner);

    // CommonKeyAttributes: raw SEQUENCE (tag 0x30)
    let mut cka_inner: Vec<u8, 32> = Vec::new();
    // iD (required)
    let _ = cka_inner.extend_from_slice(&[0x04, 0x01, key_id]);
    // usage (required)
    let _ = cka_inner.extend_from_slice(&key_usage);
    // native (optional)
    let _ = cka_inner.extend_from_slice(&[0x01, 0x01, 0xFF]);
    let mut cka_seq: Vec<u8, 48> = Vec::new();
    let _ = cka_seq.push(0x30);
    let _ = cka_seq.push(cka_inner.len() as u8);
    let _ = cka_seq.extend_from_slice(&cka_inner);

    // typeAttributes [1]: PrivateECKeyAttributes
    // Contains: value = PATH { path OCTET STRING } + fieldSize INTEGER
    // No AlgorithmIdentifier — OpenSC's parser does not expect one.
    let field_sz = ec_field_size(algo);
    let field_sz_int: [u8; 4] = [0x02, 0x02, (field_sz >> 8) as u8, (field_sz & 0xFF) as u8];

    let path_inner: [u8; 4] = [0x04, 0x02, 0xC4, key_id];
    let mut path_seq: Vec<u8, 8> = Vec::new();
    let _ = path_seq.push(0x30);
    let _ = path_seq.push(path_inner.len() as u8);
    let _ = path_seq.extend_from_slice(&path_inner);

    // Wrap PATH + fieldSize in PrivateECKeyAttributes SEQUENCE
    let mut ec_attr: Vec<u8, 24> = Vec::new();
    let _ = ec_attr.push(0x30);
    let _ = ec_attr.push((path_seq.len() + field_sz_int.len()) as u8);
    let _ = ec_attr.extend_from_slice(&path_seq);
    let _ = ec_attr.extend_from_slice(&field_sz_int);

    // Assemble outer PrivateECKey CHOICE wrapper (tag 0xA0 = context [0] constructed)
    let outer_body_len = coa_seq.len() + cka_seq.len() + (2 + ec_attr.len());
    let mut out: Vec<u8, 256> = Vec::new();
    let _ = out.push(0xA0);
    let _ = out.push(outer_body_len as u8);
    // CommonObjectAttributes — raw SEQUENCE
    let _ = out.extend_from_slice(&coa_seq);
    // CommonKeyAttributes — raw SEQUENCE
    let _ = out.extend_from_slice(&cka_seq);
    // typeAttributes [1]
    let _ = out.push(0xA1);
    let _ = out.push(ec_attr.len() as u8);
    let _ = out.extend_from_slice(&ec_attr);

    out
}

// ---------------------------------------------------------------------------
// Build a PKCS#15 PrivateRSAKey descriptor (PRKD at EF 0xC4xx)
// ---------------------------------------------------------------------------
//
// PKCS#15 PrivateKeyType CHOICE tag for RSA is 0x30 (SEQUENCE).
// Inside, the PKCS#15 Object template uses raw SEQUENCE tags for the first
// two fields and context [1] for typeAttributes:
//
// OpenSC's c_asn1_prk_rsa_attr template expects:
//   "value"         — SC_ASN1_PATH (SEQUENCE): a PATH { OCTET STRING }
//   "modulusLength" — SC_ASN1_INTEGER (required!)
// No AlgorithmIdentifier — RSA is implied by the outer CHOICE tag.
//
// Format:
//   30 xx                           -- outer: SEQUENCE = PrivateRSAKey CHOICE
//     30 xx                         -- CommonObjectAttributes (SEQUENCE)
//       03 02 05 C0                 -- flags BIT STRING (sign + decrypt)
//     30 xx                         -- CommonKeyAttributes (SEQUENCE)
//       04 01 <key_id>              -- iD
//       03 02 05 C0                 -- usage BIT STRING
//       01 01 FF                    -- native TRUE
//     A1 xx                         -- [1] typeAttributes: PrivateRSAKeyAttributes
//       30 xx
//         30 xx                     -- value = PATH
//           04 02 C4 <key_id>       -- path OCTET STRING
//         02 02 xx xx               -- modulusLength INTEGER

/// Map RSA algo byte to modulus length in bits.
#[cfg(feature = "rsa")]
fn rsa_modulus_length(algo: u8) -> u16 {
    match algo {
        0x05 => 2048,
        0x06 => 3072,
        0x07 => 4096,
        _ => 2048,
    }
}

#[cfg(feature = "rsa")]
fn build_rsa_prkd(key_id: u8, algo: u8) -> Vec<u8, 256> {
    let modulus_len = rsa_modulus_length(algo);

    // keyUsageFlags BIT STRING: sign (bit 1) + decrypt (bit 3) = 0xC0 in the usage byte,
    // with 5 unused bits.  Value: 03 02 05 C0.
    let key_usage_bs: [u8; 4] = [0x03, 0x02, 0x05, 0xC0];

    // CommonObjectAttributes: raw SEQUENCE (tag 0x30)
    let coa_inner = key_usage_bs;
    let mut coa_seq: Vec<u8, 16> = Vec::new();
    let _ = coa_seq.push(0x30);
    let _ = coa_seq.push(coa_inner.len() as u8);
    let _ = coa_seq.extend_from_slice(&coa_inner);

    // CommonKeyAttributes: raw SEQUENCE (tag 0x30)
    let mut cka_inner: Vec<u8, 32> = Vec::new();
    let _ = cka_inner.extend_from_slice(&[0x04, 0x01, key_id]);
    let _ = cka_inner.extend_from_slice(&key_usage_bs);
    let _ = cka_inner.extend_from_slice(&[0x01, 0x01, 0xFF]);
    let mut cka_seq: Vec<u8, 40> = Vec::new();
    let _ = cka_seq.push(0x30);
    let _ = cka_seq.push(cka_inner.len() as u8);
    let _ = cka_seq.extend_from_slice(&cka_inner);

    // typeAttributes [1]: PrivateRSAKeyAttributes
    // Contains: value = PATH { OCTET STRING } + modulusLength INTEGER
    let path_inner: [u8; 4] = [0x04, 0x02, 0xC4, key_id];
    let mut path_seq: Vec<u8, 8> = Vec::new();
    let _ = path_seq.push(0x30);
    let _ = path_seq.push(path_inner.len() as u8);
    let _ = path_seq.extend_from_slice(&path_inner);

    // modulusLength as DER INTEGER
    let mut modlen_der: Vec<u8, 6> = Vec::new();
    let _ = modlen_der.push(0x02); // INTEGER tag
    if modulus_len <= 0x7F {
        let _ = modlen_der.push(0x01);
        let _ = modlen_der.push(modulus_len as u8);
    } else {
        let _ = modlen_der.push(0x02);
        let _ = modlen_der.push((modulus_len >> 8) as u8);
        let _ = modlen_der.push((modulus_len & 0xFF) as u8);
    }

    // Wrap in PrivateRSAKeyAttributes SEQUENCE
    let rsa_attr_len = path_seq.len() + modlen_der.len();
    let mut rsa_attr: Vec<u8, 20> = Vec::new();
    let _ = rsa_attr.push(0x30);
    let _ = rsa_attr.push(rsa_attr_len as u8);
    let _ = rsa_attr.extend_from_slice(&path_seq);
    let _ = rsa_attr.extend_from_slice(&modlen_der);

    // Assemble outer SEQUENCE (tag 0x30 = PrivateRSAKey CHOICE)
    let outer_body_len = coa_seq.len() + cka_seq.len() + (2 + rsa_attr.len());
    let mut out: Vec<u8, 256> = Vec::new();
    let _ = out.push(0x30);
    let _ = out.push(outer_body_len as u8);
    // CommonObjectAttributes — raw SEQUENCE
    let _ = out.extend_from_slice(&coa_seq);
    // CommonKeyAttributes — raw SEQUENCE
    let _ = out.extend_from_slice(&cka_seq);
    // typeAttributes [1]
    let _ = out.push(0xA1);
    let _ = out.push(rsa_attr.len() as u8);
    let _ = out.extend_from_slice(&rsa_attr);

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

/// Returns true if the SC-HSM algo byte represents an RSA algorithm.
fn is_rsa_algo(algo: u8) -> bool {
    // SC-HSM algo bytes: 0x05 = RSA-2048, 0x06 = RSA-3072, 0x07 = RSA-4096
    matches!(algo, 0x05..=0x07)
}

fn build_prkdf(state: &ScHsmState) -> Vec<u8, 256> {
    let mut out: Vec<u8, 256> = Vec::new();
    for meta in &state.key_index {
        // Skip EfFile entries (key_type == 16).
        if meta.key_type == 16 {
            continue;
        }
        let proto_ref = (meta.key_id & 0xFF) as u8;
        if is_rsa_algo(meta.algo) {
            // 30 06  30 04  04 02 C4 <key_id>  — RSA key (PrivateRSAKey choice = SEQUENCE)
            let _ = out.extend_from_slice(&[0x30, 0x06, 0x30, 0x04, 0x04, 0x02, 0xC4, proto_ref]);
        } else {
            // A0 06  30 04  04 02 C4 <key_id>  — EC key (PrivateECKey choice = [0])
            let _ = out.extend_from_slice(&[0xA0, 0x06, 0x30, 0x04, 0x04, 0x02, 0xC4, proto_ref]);
        }
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
fn read_file(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    file_id: u16,
    offset: usize,
    max_len: usize,
) -> ApduResponse {
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

    // PrKDF (0xC100): dynamically built from key_index metadata.
    // Returns pointers to all EC and RSA key descriptors (EF 0xC4xx).
    if file_id == 0xC100 {
        let prkdf = build_prkdf(state);
        let start = offset.min(prkdf.len());
        let slice = &prkdf[start..prkdf.len().min(start + max_len)];
        return ApduResponse::ok(slice);
    }

    // Check EF cache first, then fall back to flash via cross-core RPC.
    // EF files (CE certificates, DevAut, etc.) are stored in flash as KeyType::EfFile
    // entries and cached in RAM for fast reads.  After USB reconnect the cache is
    // empty, so we lazy-load from flash on the first miss.
    let file_id_hi = (file_id >> 8) as u8;
    let file_id_lo = (file_id & 0xFF) as u8;
    let ef_key_id = KeyId::sc_hsm_ef(0, file_id_hi, file_id_lo).0;
    if state
        .key_index
        .iter()
        .any(|m| m.key_type == 16 && m.key_id == ef_key_id)
    {
        if let Some(data) = state.ef_cache_get(ef_key_id) {
            let start = offset.min(data.len());
            let slice = &data[start..data.len().min(start + max_len)];
            return ApduResponse::ok(slice);
        }
        // Cache miss — lazy-load from flash via cross-core fetch_key RPC.
        if let Ok(Some(obj)) = store.fetch_key(KeyId(ef_key_id)) {
            // EF data is stored in private_key field (see write_data.rs).
            let data = &obj.private_key;
            // Populate ef_cache for subsequent reads in this session.
            state.ef_cache_put(ef_key_id, data);
            let start = offset.min(data.len());
            let slice = &data[start..data.len().min(start + max_len)];
            return ApduResponse::ok(slice);
        }
    }

    // Dynamic EFs by high byte
    let hi = file_id >> 8;
    let key_id_proto = (file_id & 0xFF) as u8;
    let full_key_id = KeyId::sc_hsm(0, key_id_proto).0;

    match hi {
        0xC4 => {
            // Look up key in key_index by key_id.
            let meta = state
                .key_index
                .iter()
                .find(|m| m.key_id == full_key_id && m.key_type != 16);
            if let Some(meta) = meta {
                if is_rsa_algo(meta.algo) {
                    #[cfg(feature = "rsa")]
                    {
                        let prkd = build_rsa_prkd(key_id_proto, meta.algo);
                        let start = offset.min(prkd.len());
                        let slice = &prkd[start..prkd.len().min(start + max_len)];
                        return ApduResponse::ok(slice);
                    }
                    #[cfg(not(feature = "rsa"))]
                    return ApduResponse::err(SW_FILE_NOT_FOUND);
                } else {
                    let prkd = build_ec_prkd(key_id_proto, meta.algo);
                    let start = offset.min(prkd.len());
                    let slice = &prkd[start..prkd.len().min(start + max_len)];
                    return ApduResponse::ok(slice);
                }
            }
            ApduResponse::err(SW_FILE_NOT_FOUND)
        }
        // CC/CE files without a key_index entry: not found.
        // (Files WITH a key_index entry are handled by the ef_cache/flash path above.)
        0xCC | 0xCE => ApduResponse::err(SW_FILE_NOT_FOUND),
        _ => ApduResponse::err(SW_FILE_NOT_FOUND),
    }
}

/// Handle a READ BINARY APDU (INS=0xB0).
/// P1P2 encodes the file identifier (SC-HSM convention: not an offset).
pub fn handle(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    if cmd.p1 & 0x80 != 0 {
        return ApduResponse::err(SW_FILE_NOT_FOUND);
    }
    let file_id: u16 = (cmd.p1 as u16) << 8 | (cmd.p2 as u16);
    let max_len = match cmd.le {
        Some(0) | None => 256usize,
        Some(n) => n as usize,
    };
    read_file(state, store, file_id, 0, max_len)
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
pub fn handle_odd(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
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
    read_file(state, store, file_id, offset, max_len)
}
