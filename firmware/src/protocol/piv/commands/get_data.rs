//! GET DATA command handler (INS = 0xCB) for PIV.
//!
//! Retrieves PIV data objects by their BER-TLV tag.
//!
//! # Supported objects
//! - CHUID (tag 5FC102) — Card Holder Unique Identifier
//! - CCC (tag 5FC107) — Card Capability Container
//! - Discovery Object (tag 7E) — PIN policies
//! - X.509 certificates for slots 9A, 9C, 9D, 9E (stored via PUT DATA)
//!
//! Returns SW 6A82 for unrecognised tags.

use pico2hsm_core::apdu::{ApduCommand, ApduResponse};

use crate::protocol::piv::PivState;

/// INS byte for GET DATA.
pub const INS_GET_DATA: u8 = 0xCB;

/// Handle a GET DATA APDU.
pub fn handle(state: &PivState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // P1=0x3F, P2=0xFF per NIST SP 800-73-4
    if cmd.p1 != 0x3F || cmd.p2 != 0xFF {
        return ApduResponse::err(0x6A86);
    }

    // Command data: 5C <len> <tag bytes>
    let data = cmd.data;
    if data.len() < 3 || data[0] != 0x5C {
        return ApduResponse::err(0x6A80); // wrong data
    }

    let tag_len = data[1] as usize;
    if data.len() < 2 + tag_len {
        return ApduResponse::err(0x6A80);
    }

    let tag = &data[2..2 + tag_len];

    // A stored object wins over the built-in defaults, for any tag.
    if let Some(low) = super::put_data::object_tag_low(data) {
        if !readable(state, low) {
            return ApduResponse::err(0x6982);
        }
        if let Some(obj) = state.data_objects.iter().find(|o| o.tag_low == low) {
            return ApduResponse::ok(&obj.data);
        }
    }

    match tag {
        // CHUID: 5FC102
        [0x5F, 0xC1, 0x02] => build_chuid(state),
        // CCC: 5FC107
        [0x5F, 0xC1, 0x07] => build_ccc(),
        // Discovery Object: 7E
        [0x7E] => build_discovery(),
        // X.509 Certificate for PIV Authentication (9A): 5FC105
        [0x5F, 0xC1, 0x05] => get_stored_object(state, 0x05),
        // X.509 Certificate for Digital Signature (9C): 5FC10A
        [0x5F, 0xC1, 0x0A] => get_stored_object(state, 0x0A),
        // X.509 Certificate for Key Management (9D): 5FC10B
        [0x5F, 0xC1, 0x0B] => get_stored_object(state, 0x0B),
        // X.509 Certificate for Card Authentication (9E): 5FC101
        [0x5F, 0xC1, 0x01] => get_stored_object(state, 0x01),
        // Security Object: 5FC106
        [0x5F, 0xC1, 0x06] => build_security_object(),
        // Key History Object: 5FC10C
        [0x5F, 0xC1, 0x0C] => ApduResponse::err(0x6A82),
        // Retired slots (5FC10D - 5FC120): not found
        _ => ApduResponse::err(0x6A82), // object not found
    }
}

/// Build a synthetic CHUID (Card Holder Unique Identifier).
///
/// Per NIST SP 800-73-4, the CHUID contains:
/// - FASC-N (tag 0x30) - 25 bytes (we use a fixed test value)
/// - GUID (tag 0x34) - 16 bytes (from device_id)
/// - Expiration Date (tag 0x35) - 8 bytes ASCII "YYYYMMDD"
/// - Issuer Asymmetric Signature (tag 0x3E) - empty (no PKI)
/// - Error Detection Code (tag 0xFE) - empty
/// Per-device CHUID GUID: SHA-256("pico2hsm-piv-guid" || chip id), first
/// 16 bytes, with RFC 4122 version-4/variant bits.  (Was `device_id`, which
/// is all zeros on every device; `device_id` stays the PIN KDF context so
/// stored PIV PINs keep verifying.)
fn chuid_guid() -> [u8; 16] {
    use sha2::{Digest, Sha256};
    #[cfg(target_arch = "arm")]
    let chip_id = embassy_rp::otp::get_chipid().unwrap_or(0);
    #[cfg(not(target_arch = "arm"))]
    let chip_id = 0u64;
    let mut h = Sha256::new();
    h.update(b"pico2hsm-piv-guid");
    h.update(chip_id.to_be_bytes());
    let digest = h.finalize();
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&digest[..16]);
    guid[6] = (guid[6] & 0x0F) | 0x40;
    guid[8] = (guid[8] & 0x3F) | 0x80;
    guid
}

fn build_chuid(_state: &PivState) -> ApduResponse {
    let mut resp = heapless::Vec::<u8, 256>::new();

    // Outer tag 0x53 (content wrapper)
    let _ = resp.push(0x53);
    // We'll fill the length after building the inner content
    let len_pos = resp.len();
    let _ = resp.push(0x00); // placeholder

    // FASC-N (tag 0x30) - 25 bytes.
    // FIPS 201-2 Appendix B non-federal agency test FASC-N:
    //   Agency Code = 9999, System Code = 9999, Credential Number = 999999,
    //   CS = 0, ICI = 0, PI = 9999999999, OC = 1, OI = 9999, POA = 1.
    // Encoded per ANSI/INCITS 225 4-bit BCD packing with SS/FS/ES sentinels
    // and LRC as defined in FIPS 201-2 Appendix B.
    let _ = resp.push(0x30);
    let _ = resp.push(25);
    let fascn: [u8; 25] = [
        0xD4, 0xE7, 0x39, 0xDA, 0x73, 0x9C, 0xED, 0x39, 0xCE, 0x73, 0x9D, 0x83, 0x68, 0x58, 0x21,
        0x08, 0x42, 0x10, 0x84, 0x21, 0xC8, 0x42, 0x10, 0xC3, 0xEB,
    ];
    let _ = resp.extend_from_slice(&fascn);

    // GUID (tag 0x34) - 16 bytes, unique per device (hosts cache by CHUID)
    let _ = resp.push(0x34);
    let _ = resp.push(16);
    let _ = resp.extend_from_slice(&chuid_guid());

    // Expiration Date (tag 0x35) - 8 bytes ASCII "20301231"
    let _ = resp.push(0x35);
    let _ = resp.push(8);
    let _ = resp.extend_from_slice(b"20301231");

    // Issuer Asymmetric Signature (tag 0x3E) - empty
    let _ = resp.push(0x3E);
    let _ = resp.push(0x00);

    // Error Detection Code (tag 0xFE) - empty
    let _ = resp.push(0xFE);
    let _ = resp.push(0x00);

    // Patch the outer length
    let inner_len = resp.len() - len_pos - 1;
    resp[len_pos] = inner_len as u8;

    ApduResponse::ok(&resp)
}

/// Build a synthetic CCC (Card Capability Container).
///
/// Minimal CCC per NIST SP 800-73-4.
fn build_ccc() -> ApduResponse {
    let mut resp = heapless::Vec::<u8, 128>::new();

    // Outer tag 0x53
    let _ = resp.push(0x53);
    let len_pos = resp.len();
    let _ = resp.push(0x00); // placeholder

    // Card Identifier (tag 0xF0) - 21 bytes
    let _ = resp.push(0xF0);
    let _ = resp.push(21);
    // GSC-RID (5) + card type (1) + card id (14) + checksum (1)
    // Use a fixed test identifier
    let card_id: [u8; 21] = [
        0xA0, 0x00, 0x00, 0x01, 0x16, // GSC-RID
        0xFF, // card type = unknown
        0x02, // CHUID
        // 14 bytes card identifier (fixed)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let _ = resp.extend_from_slice(&card_id);

    // Capability Container version (tag 0xF1) - 1 byte
    let _ = resp.push(0xF1);
    let _ = resp.push(0x01);
    let _ = resp.push(0x21); // version 2.1

    // Capability Grammar version (tag 0xF2) - 1 byte
    let _ = resp.push(0xF2);
    let _ = resp.push(0x01);
    let _ = resp.push(0x21); // version 2.1

    // Applications CardURL (tag 0xF3) - empty (no URLs)
    // Skipped for minimal CCC

    // PKCS#15 (tag 0xF4) — 0 (no PKCS#15)
    // Skipped

    // Registered Data Model (tag 0xF5) - 1 byte
    let _ = resp.push(0xF5);
    let _ = resp.push(0x01);
    let _ = resp.push(0x10); // 0x10 = PIV data model

    // Error Detection Code (tag 0xFE) - empty
    let _ = resp.push(0xFE);
    let _ = resp.push(0x00);

    // Patch the outer length
    let inner_len = resp.len() - len_pos - 1;
    resp[len_pos] = inner_len as u8;

    ApduResponse::ok(&resp)
}

/// Build the Discovery Object (tag 0x7E).
///
/// ```text
/// 7E <len>
///   4F 0B <PIV AID>
///   5F 2F 02 <pin_policy> <puk_byte>
/// ```
fn build_discovery() -> ApduResponse {
    use crate::protocol::piv::PIV_AID;

    let mut resp = heapless::Vec::<u8, 32>::new();

    // Outer tag 0x7E
    let _ = resp.push(0x7E);
    let inner_len = 2 + PIV_AID.len() + 4; // 4F TLV + 5F2F TLV
    let _ = resp.push(inner_len as u8);

    // 4F: PIV AID
    let _ = resp.push(0x4F);
    let _ = resp.push(PIV_AID.len() as u8);
    let _ = resp.extend_from_slice(PIV_AID);

    // 5F 2F: PIN Usage Policy
    let _ = resp.push(0x5F);
    let _ = resp.push(0x2F);
    let _ = resp.push(0x02);
    let _ = resp.push(0x40); // bit 6 = global PIN is primary
    let _ = resp.push(0x20); // PUK available

    ApduResponse::ok(&resp)
}

/// Build a synthetic Security Object (tag 5FC106).
///
/// Per NIST SP 800-73-4 Part 1 §3.2 the Security Object contains a mapping of
/// content signing certificate slots to their SHA-1 hashes.  This minimal
/// implementation returns an empty mapping (no content signing certificates),
/// which is compliant for a device with no content signing certificates loaded.
///
/// Encoding (wrapped in tag 0x53):
///   BA <len> <mapping_data>  — mapping-of-DG, empty for no certs
///   BB <len> <security_object_data> — currently empty
///   FE 00  — Error Detection Code
fn build_security_object() -> ApduResponse {
    let mut resp = heapless::Vec::<u8, 64>::new();

    // Outer tag 0x53 (content wrapper)
    let _ = resp.push(0x53);
    let len_pos = resp.len();
    let _ = resp.push(0x00); // placeholder length

    // Mapping of Data Elements (tag 0xBA) — empty (no content signing certs)
    let _ = resp.push(0xBA);
    let _ = resp.push(0x00);

    // Security Object (tag 0xBB) — empty
    let _ = resp.push(0xBB);
    let _ = resp.push(0x00);

    // Error Detection Code (tag 0xFE) — empty
    let _ = resp.push(0xFE);
    let _ = resp.push(0x00);

    // Patch the outer length
    let inner_len = resp.len() - len_pos - 1;
    resp[len_pos] = inner_len as u8;

    ApduResponse::ok(&resp)
}

/// Whether the object `5FC1<low>` may be read now: biometrics (03, 08,
/// 21) and printed information (09) need the PIN (SP 800-73-4 Table 3).
pub fn readable(state: &PivState, low: u8) -> bool {
    !matches!(low, 0x03 | 0x08 | 0x09 | 0x21) || state.pin_verified
}

/// Retrieve a stored data object (certificate etc.) by its tag low byte.
fn get_stored_object(state: &PivState, tag_low: u8) -> ApduResponse {
    match state.data_objects.iter().find(|obj| obj.tag_low == tag_low) {
        Some(obj) => ApduResponse::ok(&obj.data),
        None => ApduResponse::err(0x6A82), // not found
    }
}
