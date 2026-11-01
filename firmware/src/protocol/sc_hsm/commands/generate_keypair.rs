//! GENERATE KEY PAIR command handler (INS = 0x46).
//!
//! Generates an asymmetric key pair on-device. The private key is stored
//! in the volatile keystore; the public key is returned in the response.
//!
//! # Command format (OpenSC PKCS#15-SC-HSM path)
//! - CLA=0x00, INS=0x46, P1=key_id 0x01..0xFB (or 0xFF for auto-assign), P2=0x00
//! - Data: GAK parameters (extended APDU):
//!   - Tag 5F29 (two-byte): algorithm byte (SC-HSM AlgorithmId; 0x00 = infer from params)
//!   - Tag 42: key reference/label (optional)
//!   - Tag 7F49: EC domain parameters containing tag 85 (order n)
//!   - Tag 5F20: CA reference (optional)
//!
//! # Response data
//! A minimal Card Verifiable Certificate (CVC, ISO 7816-8 / BSI TR-03110):
//!   `7F21 [ 7F4E [ 5F29 CPI  7F49 [OID + domain_params + 86 pubkey]  5F20 CHR ]  5F37 sig ]`
//! OpenSC's sc_pkcs15emu_sc_hsm_decode_cvc() requires this structure to
//! extract the public key and store the device EE certificate.
//!
//! The 7F49 block must include full EC domain parameters (81 prime, 82 coeff_a,
//! 83 coeff_b, 84 base_G, 85 order_n) so that sc_pkcs15emu_sc_hsm_get_curve_oid()
//! can identify the curve by matching primeOrModulus against its lookup table.

use pico2hsm_core::{
    apdu::{
        ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
        SW_SECURITY_STATUS, SW_WRONG_DATA,
    },
    key::KeyType as CoreKeyType,
};

use crate::protocol::sc_hsm::{FwRng, KeyMeta, ScHsmState};

/// INS byte for GENERATE KEY PAIR.
pub const INS_GENERATE_KEYPAIR: u8 = 0x46;

use crate::crypto::ec_params::ec_domain_params;

// ---------------------------------------------------------------------------
// TLV / DER helpers
// ---------------------------------------------------------------------------

/// Search `data` for single-byte tag `tag`; return its value slice or `None`.
///
/// Correctly skips multi-byte tags (ISO 7816-4: first byte has lower 5 bits
/// all set → second byte is part of the tag number) so that subsequent TLV
/// entries are found even when preceded by two-byte tags like `5F 29`.
fn find_tlv(data: &[u8], tag: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i < data.len() {
        let t = data[i];
        i += 1;
        // Multi-byte tag: if lower 5 bits of the first byte are all set,
        // the next byte(s) are part of the tag number.  For simplicity we
        // handle the common two-byte case (one continuation byte).
        if t & 0x1F == 0x1F {
            if i >= data.len() {
                return None;
            }
            i += 1; // skip second tag byte
        }
        // Length byte(s).
        if i >= data.len() {
            return None;
        }
        let len = if data[i] < 0x80 {
            let l = data[i] as usize;
            i += 1;
            l
        } else if data[i] == 0x81 {
            if i + 1 >= data.len() {
                return None;
            }
            let l = data[i + 1] as usize;
            i += 2;
            l
        } else {
            return None; // unsupported length encoding
        };
        if i + len > data.len() {
            return None;
        }
        if t == tag {
            return Some(&data[i..i + len]);
        }
        i += len;
    }
    None
}

/// Search `data` for two-byte tag `[tag0, tag1]`; return its value slice or `None`.
fn find_tlv_2(data: &[u8], tag0: u8, tag1: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i + 2 < data.len() {
        if data[i] != tag0 || data[i + 1] != tag1 {
            i += 1;
            continue;
        }
        i += 2;
        if i >= data.len() {
            return None;
        }
        let (len, skip) = if data[i] < 0x80 {
            (data[i] as usize, 1)
        } else if data[i] == 0x81 && i + 1 < data.len() {
            (data[i + 1] as usize, 2)
        } else {
            return None;
        };
        i += skip;
        if i + len > data.len() {
            return None;
        }
        return Some(&data[i..i + len]);
    }
    None
}

/// Infer EC algorithm byte from the EC domain parameter order length (tag 0x85 inside data).
///
/// Searches `data` for EC domain parameter tags:
/// - Tag 0x81 (prime): captured to distinguish P-256 from K-256
/// - Tag 0x85 (order) length maps to the SC-HSM AlgorithmId:
///   - 0x20 (32 bytes) → P-256 (0x13) or K-256 (0x19) — disambiguated by prime
///   - 0x30 (48 bytes) → P-384  → 0x15
///   - 0x42 (66 bytes) → P-521  → 0x17
///
/// P-256 and K-256 both have 32-byte orders; the prime distinguishes them:
/// - P-256 prime[4] == 0x00 (`FFFFFFFF 00000001 ...`)
/// - K-256 prime[4] == 0xFF (`FFFFFFFF FFFFFFFF ...`)
fn algo_from_order_tag(data: &[u8]) -> Option<u8> {
    let mut prime32: Option<u8> = None; // byte[4] of a 32-byte prime field
    let mut i = 0;
    while i + 1 < data.len() {
        match data[i] {
            0x81 if data[i + 1] == 0x20 && i + 2 + 32 <= data.len() => {
                // 32-byte prime field — save byte[4] to distinguish P-256 vs K-256
                prime32 = Some(data[i + 2 + 4]);
            }
            0x85 => match data[i + 1] {
                0x20 => {
                    // 32-byte order: P-256 or K-256
                    // P-256 prime byte[4] == 0x00; K-256 prime byte[4] == 0xFF
                    return match prime32 {
                        Some(0xFF) => Some(0x19), // K-256 (secp256k1)
                        _ => Some(0x13),          // P-256 (default)
                    };
                }
                0x30 => return Some(0x15), // P-384
                0x42 => return Some(0x17), // P-521
                _ => {}
            },
            // Tag 0x02 with a 2-byte length field = RSA modulusSize (bits).
            // OpenSC encodes the requested key size as `02 02 <hi> <lo>` inside
            // the 7F49 public-key template when the CPI (5F29) byte is 0x00.
            0x02 if i + 3 < data.len() && data[i + 1] == 0x02 => {
                let bits = ((data[i + 2] as u16) << 8) | (data[i + 3] as u16);
                match bits {
                    0x0800 => return Some(0x05), // RSA-2048
                    0x0C00 => return Some(0x06), // RSA-3072
                    0x1000 => return Some(0x07), // RSA-4096
                    _ => {}
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Map SC-HSM AlgorithmId byte to the `pico2hsm_core` KeyType.
fn algo_to_key_type(algo: u8) -> Option<CoreKeyType> {
    match algo {
        0x13 | 0x23 => Some(CoreKeyType::EcPrivateP256), // ECDSA/ECDH P-256
        0x15 | 0x25 => Some(CoreKeyType::EcPrivateP384), // ECDSA/ECDH P-384
        0x17 | 0x27 => Some(CoreKeyType::EcPrivateP521), // ECDSA/ECDH P-521
        0x19 | 0x29 => Some(CoreKeyType::EcPrivateK256), // ECDSA/ECDH K-256
        #[cfg(feature = "rsa")]
        0x05 => Some(CoreKeyType::RsaPrivate2048), // RSA-2048
        #[cfg(feature = "rsa")]
        0x06 => Some(CoreKeyType::RsaPrivate3072), // RSA-3072
        #[cfg(feature = "rsa")]
        0x07 => Some(CoreKeyType::RsaPrivate4096), // RSA-4096
        _ => None,
    }
}

/// Returns true when `key_type` is an RSA type.
#[allow(dead_code)]
fn is_rsa_key_type(kt: CoreKeyType) -> bool {
    matches!(
        kt,
        CoreKeyType::RsaPrivate2048 | CoreKeyType::RsaPrivate3072 | CoreKeyType::RsaPrivate4096
    )
}

/// Number of bytes needed to DER-encode a length value.
fn der_len_size(len: usize) -> usize {
    if len < 0x80 {
        1
    } else if len <= 0xFF {
        2
    } else {
        3
    }
}

/// Append a DER length to `buf` (up to 3-byte encoding).
fn push_der_len<const N: usize>(buf: &mut heapless::Vec<u8, N>, len: usize) {
    if len < 0x80 {
        let _ = buf.push(len as u8);
    } else if len <= 0xFF {
        let _ = buf.push(0x81);
        let _ = buf.push(len as u8);
    } else {
        let _ = buf.push(0x82);
        let _ = buf.push((len >> 8) as u8);
        let _ = buf.push(len as u8);
    }
}

/// Append a single-byte context tag TLV (tag + DER-length + value).
fn push_ctx_tlv<const N: usize>(buf: &mut heapless::Vec<u8, N>, tag: u8, value: &[u8]) {
    let _ = buf.push(tag);
    push_der_len(buf, value.len());
    let _ = buf.extend_from_slice(value);
}

/// Append a two-byte APPLICATION tag + DER-encoded length.
fn push_app_hdr<const N: usize>(
    buf: &mut heapless::Vec<u8, N>,
    tag1: u8,
    tag2: u8,
    content_len: usize,
) {
    let _ = buf.push(tag1);
    let _ = buf.push(tag2);
    push_der_len(buf, content_len);
}

/// Build a Card Verifiable Certificate response for GENERATE KEY PAIR.
///
/// Uses the BSI TR-03110 "authenticated request" format (outer tag 0x67) so
/// that OpenSC's `sc_pkcs15emu_sc_hsm_add_prkd` recognises the EE certificate
/// file (CExx) and creates a PKCS#11 public-key object.  Without the 0x67
/// outer tag OpenSC silently skips public-key creation.
///
/// Structure:
/// ```text
/// 67 LL              -- authenticated request
///   7F21 LL          -- inner CVC
///     7F4E LL        -- Certificate Body
///       5F29 01 00   -- Certificate Profile Identifier = 0
///       7F49 LL      -- Public Key
///         06 LL OID  -- Curve OID
///         81 LL p    -- EC prime field
///         82 LL a    -- Coefficient a
///         83 LL b    -- Coefficient b
///         84 LL G    -- Base point
///         85 LL n    -- Group order
///         86 LL pt   -- EC public point (04 || X || Y)
///         87 01 01   -- Cofactor
///       5F20 LL CHR  -- Certificate Holder Reference
///     5F37 LL sig    -- inner signature (dummy zeros)
///   42 LL outerCAR   -- outer CA reference (dummy)
///   5F37 LL outerSig -- outer signature (dummy)
/// ```
fn build_gakp_cvc(algo: u8, pub_key: &[u8]) -> Option<heapless::Vec<u8, 2048>> {
    let dp = ec_domain_params(algo)?;

    // Dummy signature length: raw r||s, padded to curve coordinate size.
    let sig_len: usize = match algo {
        0x13 | 0x23 | 0x19 | 0x29 => 64, // P-256 / K-256: 32+32
        0x15 | 0x25 => 96,               // P-384: 48+48
        0x17 | 0x27 => 132,              // P-521: 66+66
        _ => return None,
    };

    // Certificate Holder Reference — fixed device label used by OpenSC.
    let chr: &[u8] = b"UTDV00001";

    // ---- Compute 7F49 content length ----
    // 06 <oid_len> <oid>
    let oid_field = 1 + der_len_size(dp.curve_oid.len()) + dp.curve_oid.len();
    // 81 <len> <prime>
    let prime_field = 1 + der_len_size(dp.prime.len()) + dp.prime.len();
    // 82 <len> <coeff_a>
    let a_field = 1 + der_len_size(dp.coeff_a.len()) + dp.coeff_a.len();
    // 83 <len> <coeff_b>
    let b_field = 1 + der_len_size(dp.coeff_b.len()) + dp.coeff_b.len();
    // 84 <len> <base_g>
    let g_field = 1 + der_len_size(dp.base_g.len()) + dp.base_g.len();
    // 85 <len> <order>
    let order_field = 1 + der_len_size(dp.order.len()) + dp.order.len();
    // 86 <len> <pubkey>
    let pk_field = 1 + der_len_size(pub_key.len()) + pub_key.len();
    // 87 01 01  (cofactor = 1)
    let cofactor_field = 3usize;

    let pk49_content = oid_field
        + prime_field
        + a_field
        + b_field
        + g_field
        + order_field
        + pk_field
        + cofactor_field;

    // ---- Compute body content length ----
    // 5F29 01 00
    let cpi_field = 4usize;
    // 5F20 <len> <chr>
    let chr_field = 2 + der_len_size(chr.len()) + chr.len();
    // 7F49 TLV total (2-byte tag)
    let pk49_total = 2 + der_len_size(pk49_content) + pk49_content;

    let body_content = cpi_field + pk49_total + chr_field;

    // ---- Compute outer lengths ----
    // 5F37 <len> <zeros>  (2-byte tag, inner signature)
    let sig_field = 2 + der_len_size(sig_len) + sig_len;
    // 7F4E TLV total (2-byte tag)
    let body_total = 2 + der_len_size(body_content) + body_content;
    // 7F21 content (body + inner sig)
    let inner_cvc_content = body_total + sig_field;
    // 7F21 TLV total
    let inner_cvc_total = 2 + der_len_size(inner_cvc_content) + inner_cvc_content;
    // 42 09 "DESE00001"  (outerCAR, 1-byte tag + 1-byte len + 9 bytes data)
    let outer_car_field = 1 + 1 + 9usize;
    // 5F 37 01 00  (dummy outerSignature, 2-byte tag + 1-byte len + 1 byte data)
    let outer_sig_field = 2 + 1 + 1usize;
    // 0x67 content
    let wrapper_content = inner_cvc_total + outer_car_field + outer_sig_field;

    // ---- Encode ----
    let mut buf: heapless::Vec<u8, 2048> = heapless::Vec::new();

    // 0x67 LL  (authenticated request outer wrapper — required by OpenSC)
    let _ = buf.push(0x67);
    push_der_len(&mut buf, wrapper_content);

    // 7F21 LL  (inner CVC)
    push_app_hdr(&mut buf, 0x7F, 0x21, inner_cvc_content);

    // 7F4E LL  (APPLICATION CONSTRUCTED — Certificate Body)
    push_app_hdr(&mut buf, 0x7F, 0x4E, body_content);

    // 5F29 01 00  (CPI = 0)
    let _ = buf.extend_from_slice(&[0x5F, 0x29, 0x01, 0x00]);

    // 7F49 LL  (Public Key template)
    push_app_hdr(&mut buf, 0x7F, 0x49, pk49_content);

    // 06 <oid_len> <curve_oid>
    push_ctx_tlv(&mut buf, 0x06, dp.curve_oid);

    // 81 <len> <prime>   — sc_pkcs15emu_sc_hsm_get_curve_oid matches this
    push_ctx_tlv(&mut buf, 0x81, dp.prime);

    // 82 <len> <coeff_a>
    push_ctx_tlv(&mut buf, 0x82, dp.coeff_a);

    // 83 <len> <coeff_b>
    push_ctx_tlv(&mut buf, 0x83, dp.coeff_b);

    // 84 <len> <base_G>
    push_ctx_tlv(&mut buf, 0x84, dp.base_g);

    // 85 <len> <order_n>
    push_ctx_tlv(&mut buf, 0x85, dp.order);

    // 86 <len> <public_point>
    push_ctx_tlv(&mut buf, 0x86, pub_key);

    // 87 01 01  (cofactor h = 1)
    let _ = buf.extend_from_slice(&[0x87, 0x01, 0x01]);

    // 5F20 <len> <chr>
    let _ = buf.extend_from_slice(&[0x5F, 0x20]);
    push_der_len(&mut buf, chr.len());
    let _ = buf.extend_from_slice(chr);

    // 5F37 <len> <zeros>  (dummy inner signature)
    let _ = buf.extend_from_slice(&[0x5F, 0x37]);
    push_der_len(&mut buf, sig_len);
    for _ in 0..sig_len {
        let _ = buf.push(0x00);
    }

    // 42 09 "DESE00001"  (outerCAR — dummy, not cryptographically verified by OpenSC)
    push_ctx_tlv(&mut buf, 0x42, b"DESE00001");

    // 5F 37 01 00  (dummy outerSignature)
    let _ = buf.extend_from_slice(&[0x5F, 0x37, 0x01, 0x00]);

    Some(buf)
}

/// Build a Card Verifiable Certificate response for RSA GENERATE KEY PAIR.
///
/// The 7F49 public-key block mirrors the EC CVC structure: it starts with the
/// algorithm OID (tag 0x06), then the RSA modulus (tag 0x81) and public
/// exponent (tag 0x82).  OpenSC's `sc_pkcs15emu_sc_hsm_decode_cvc` requires
/// the OID to identify the key type; without it the decoder returns
/// SC_ERROR_ASN1_OBJECT_NOT_FOUND (-1402) and the keygen fails.
///
/// Structure (identical outer wrapper to the EC CVC):
/// ```text
/// 67 LL
///   7F21 LL
///     7F4E LL
///       5F29 01 00
///       7F49 LL
///         06 LL algo_oid    -- RSA algorithm OID (echoed from request)
///         81 LL modulus     -- RSA modulus n (big-endian)
///         82 LL exponent    -- RSA public exponent e (big-endian)
///       5F20 LL CHR
///     5F37 LL sig           -- dummy zeros (modulus-length)
///   42 LL outerCAR
///   5F37 01 00
/// ```
#[cfg(feature = "rsa")]
fn build_rsa_gakp_cvc(
    modulus: &[u8],
    exponent: &[u8],
    sig_len: usize,
    algo_oid: &[u8],
) -> Option<heapless::Vec<u8, 2048>> {
    let chr: &[u8] = b"UTDV00001";

    // 7F49 content: 06 LL OID + 81 LL modulus + 82 LL exponent
    let oid_field = 1 + der_len_size(algo_oid.len()) + algo_oid.len();
    let mod_field = 1 + der_len_size(modulus.len()) + modulus.len();
    let exp_field = 1 + der_len_size(exponent.len()) + exponent.len();
    let pk49_content = oid_field + mod_field + exp_field;

    // Certificate Body content
    let cpi_field = 4usize; // 5F29 01 00
    let chr_field = 2 + der_len_size(chr.len()) + chr.len(); // 5F20 CHR
    let pk49_total = 2 + der_len_size(pk49_content) + pk49_content; // 7F49 TLV
    let body_content = cpi_field + pk49_total + chr_field;

    let sig_field = 2 + der_len_size(sig_len) + sig_len; // 5F37 inner sig
    let body_total = 2 + der_len_size(body_content) + body_content; // 7F4E TLV
    let inner_cvc_content = body_total + sig_field;
    let inner_cvc_total = 2 + der_len_size(inner_cvc_content) + inner_cvc_content; // 7F21
    let outer_car_field = 1 + 1 + 9usize; // 42 09 "DESE00001"
    let outer_sig_field = 2 + 1 + 1usize; // 5F37 01 00
    let wrapper_content = inner_cvc_total + outer_car_field + outer_sig_field;

    let mut buf: heapless::Vec<u8, 2048> = heapless::Vec::new();

    // 67 LL
    let _ = buf.push(0x67);
    push_der_len(&mut buf, wrapper_content);

    // 7F21 LL
    push_app_hdr(&mut buf, 0x7F, 0x21, inner_cvc_content);

    // 7F4E LL
    push_app_hdr(&mut buf, 0x7F, 0x4E, body_content);

    // 5F29 01 00
    let _ = buf.extend_from_slice(&[0x5F, 0x29, 0x01, 0x00]);

    // 7F49 LL
    push_app_hdr(&mut buf, 0x7F, 0x49, pk49_content);

    // 06 LL algo_oid (RSA algorithm OID, required by OpenSC CVC decoder)
    let _ = buf.push(0x06);
    push_der_len(&mut buf, algo_oid.len());
    let _ = buf.extend_from_slice(algo_oid);

    // 81 LL modulus
    push_ctx_tlv(&mut buf, 0x81, modulus);

    // 82 LL exponent
    push_ctx_tlv(&mut buf, 0x82, exponent);

    // 5F20 LL CHR
    let _ = buf.extend_from_slice(&[0x5F, 0x20]);
    push_der_len(&mut buf, chr.len());
    let _ = buf.extend_from_slice(chr);

    // 5F37 LL zeros (dummy inner signature, sig_len = modulus_len)
    let _ = buf.extend_from_slice(&[0x5F, 0x37]);
    push_der_len(&mut buf, sig_len);
    for _ in 0..sig_len {
        let _ = buf.push(0x00);
    }

    // 42 09 "DESE00001"
    push_ctx_tlv(&mut buf, 0x42, b"DESE00001");

    // 5F37 01 00 (dummy outer signature)
    let _ = buf.extend_from_slice(&[0x5F, 0x37, 0x01, 0x00]);

    Some(buf)
}

/// Handle a GENERATE KEY PAIR APDU command.
pub fn handle(
    state: &mut ScHsmState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    crate::cdc_log!("SC-HSM GENERATE KEY PAIR start");
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // key_id: P1=0xFF means auto-assign (first free slot below the reserved range).
    // P1=0x01..0xFB is used directly as the key reference — OpenSC's
    // sc_hsm_determine_free_id() pre-computes the free slot and passes it
    // as P1.  0x00 is the device key's reference (LIST KEYS reports it, so
    // OpenSC never picks it) and is refused before this handler.
    let key_id_proto: u8 = if cmd.p1 != 0xFF {
        cmd.p1
    } else {
        let limit = crate::protocol::sc_hsm::RESERVED_KEY_REF_MIN;
        let mut id = 1u8;
        while id < limit
            && state
                .key_index
                .iter()
                .any(|m| m.key_id == pico2hsm_core::key::KeyId::sc_hsm(0, id).0)
        {
            id = id.wrapping_add(1);
        }
        if id == limit {
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
        id
    };
    let key_id = pico2hsm_core::key::KeyId::sc_hsm(0, key_id_proto).0; // u32 full internal ID

    // Determine algorithm byte: try two-byte tag 5F29 first, then single-byte 0x41,
    // then fall back to inferring from EC order length (tag 0x85) in the data.
    let algo: u8 = {
        let from_5f29 = find_tlv_2(cmd.data, 0x5F, 0x29)
            .and_then(|v| v.first().copied())
            .filter(|&a| a != 0x00);

        let from_41 = find_tlv(cmd.data, 0x41)
            .and_then(|v| v.first().copied())
            .filter(|&a| a != 0x00);

        match from_5f29.or(from_41) {
            Some(a) => a,
            None => match algo_from_order_tag(cmd.data) {
                Some(a) => a,
                None => return ApduResponse::err(SW_WRONG_DATA),
            },
        }
    };

    let key_type = match algo_to_key_type(algo) {
        Some(kt) => kt,
        None => return ApduResponse::err(SW_INS_NOT_SUPPORTED),
    };

    // Parse key flags from TLV tag 0xD4 (SC-HSM key access conditions).
    // Bit 3 = NO_EXPORT: if set, EXPORT KEY (INS=0x72) will reject wrapping.
    // Default 0x00 = all operations allowed, exportable.
    let key_flags: u8 = find_tlv(cmd.data, 0xD4)
        .and_then(|v| v.first().copied())
        .unwrap_or(0x00);

    // CardContact key attributes after the CVC request body: 90 key use
    // counter, 91 algorithm list, 92 key domain.  Parsed strictly (a
    // malformed request is refused, never stored without its policy) and
    // before the key is generated.
    let policy = match crate::security::key_policy::KeyPolicy::from_creation_tlvs(cmd.data) {
        Ok(p) => p,
        Err(sw) => return ApduResponse::err(sw),
    };

    // ---- RSA key generation (feature-gated) ---------------------------------
    #[cfg(feature = "rsa")]
    if is_rsa_key_type(key_type) {
        // Extract the RSA algorithm OID from the incoming 7F49 block so we can
        // echo it back in the response CVC.  OpenSC's sc_pkcs15emu_sc_hsm_decode_cvc
        // requires a tag-0x06 OID inside 7F49 to recognise the key type.
        // Fallback: id-TA-RSA-v1-5-SHA-256 (0.4.0.127.0.7.2.2.2.1.2)
        const RSA_V15_SHA256_OID: &[u8] =
            &[0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x02];
        let rsa_oid: &[u8] = find_tlv_2(cmd.data, 0x7F, 0x49)
            .and_then(|pk49| find_tlv(pk49, 0x06))
            .unwrap_or(RSA_V15_SHA256_OID);

        // A pre-generated key from the RSA key pool when there is one
        // (marked taken on flash before it gets here), else a live one from
        // the sliced generator, which keeps the watchdog heartbeat moving —
        // no stall-detector suppression.  Either way the key is stored
        // below exactly as a freshly generated key.
        let mut pair = crate::rsa_pool::empty_pair(key_type);
        match crate::rsa_pool::obtain(store, key_type, &mut FwRng, &mut pair) {
            Ok(()) => {}
            Err(crate::rsa_pool::IssueError::Storage) => {
                return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE)
            }
            Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
        }

        // Dummy RSA signature length = modulus length
        let sig_len = pair.modulus.len(); // 256 for RSA-2048

        // Build CVC with RSA public key (OID + modulus + exponent)
        let cvc = match build_rsa_gakp_cvc(&pair.modulus, &pair.exponent, sig_len, rsa_oid) {
            Some(c) => c,
            None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
        };

        // Persist RSA key to flash BEFORE adding to RAM.
        // On flash failure, abort — keeps flash/RAM consistent.
        {
            use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};
            // Map algo byte to AlgorithmId — RSA-2048 keygen uses algo 0x05.
            // Store PKCS#1 DER in private_key; modulus+exponent in public_key.
            let km_algo = match algo {
                0x05 => AlgorithmId::RsaDecrypt,
                0x07 => AlgorithmId::RsaDecrypt,
                _ => AlgorithmId::RsaDecrypt,
            };
            let mut key_obj = KeyObject::new(
                KmType::Rsa,
                key_id,
                pico2hsm_core::key::AppletId::ScHsm,
                km_algo,
            );
            key_obj.key_flags = key_flags;
            key_obj.key_domain = policy.domain.unwrap_or(0);
            key_obj.policy = policy.clone();
            let _ = key_obj.private_key.extend_from_slice(&pair.private_key_der);
            // Store modulus || exponent in public_key for future reconstruction.
            // Layout: [2-byte modulus_len BE] || modulus || exponent
            let mod_len = pair.modulus.len() as u16;
            let _ = key_obj.public_key.push((mod_len >> 8) as u8);
            let _ = key_obj.public_key.push(mod_len as u8);
            let _ = key_obj.public_key.extend_from_slice(&pair.modulus);
            let _ = key_obj.public_key.extend_from_slice(&pair.exponent);
            if store.save_key(&key_obj).is_err() {
                return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
            }
        }

        // Store metadata in key_index (replacing any existing entry with the same key_id)
        state.key_index.retain(|m| m.key_id != key_id);

        if state
            .key_index
            .push(KeyMeta {
                key_id,
                key_type: key_type as u8,
                algo,
                key_flags,
            })
            .is_err()
        {
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }

        crate::cdc_log!(
            "SC-HSM GENERATE KEY PAIR done key=0x{:08x} algo=0x{:02x}",
            key_id,
            algo
        );
        return ApduResponse::ok(&cvc);
    }

    // ---- EC key generation --------------------------------------------------

    // Generate the key pair using the firmware RNG
    let pair = match crate::crypto::asymmetric::generate_ec_keypair(key_type, &mut FwRng) {
        Ok(p) => p,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Persist EC key to flash. On flash failure, continue in degraded mode
    // (key lives in RAM for this session but won't survive power cycle).
    {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};
        // Map algo byte to AlgorithmId.
        let km_algo = match AlgorithmId::from_u8(algo) {
            Some(a) => a,
            None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
        };
        let mut key_obj = KeyObject::new(
            KmType::Ec,
            key_id,
            pico2hsm_core::key::AppletId::ScHsm,
            km_algo,
        );
        key_obj.key_flags = key_flags;
        key_obj.key_domain = policy.domain.unwrap_or(0);
        key_obj.policy = policy;
        let _ = key_obj.private_key.extend_from_slice(&pair.private_key);
        let _ = key_obj.public_key.extend_from_slice(&pair.public_key);
        // Persist before indexing: a key the host is told about must survive reset.
        if store.save_key(&key_obj).is_err() {
            return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
        }
    }

    // Store metadata in key_index (replacing any existing entry with the same key_id)
    state.key_index.retain(|m| m.key_id != key_id);

    if state
        .key_index
        .push(KeyMeta {
            key_id,
            key_type: key_type as u8,
            algo,
            key_flags,
        })
        .is_err()
    {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Build CVC response that OpenSC's sc_pkcs15emu_sc_hsm_decode_cvc() can parse.
    let cvc = match build_gakp_cvc(algo, &pair.public_key) {
        Some(c) => c,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    crate::cdc_log!(
        "SC-HSM GENERATE KEY PAIR done key=0x{:08x} algo=0x{:02x}",
        key_id,
        algo
    );
    ApduResponse::ok(&cvc)
}
