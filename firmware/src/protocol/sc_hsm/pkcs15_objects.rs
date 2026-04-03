//! Static PKCS#15 data structures for the SC-HSM virtual filesystem.
//!
//! These EF bodies are returned verbatim by READ BINARY. They describe the
//! SC-HSM application to OpenSC / pkcs11-tool in standard PKCS#15 format.

// ---------------------------------------------------------------------------
// EF.DIR (0x2F00) — Application template pointing to PKCS#15 DF
// ---------------------------------------------------------------------------

/// EF.DIR — Application Directory (ISO 7816-4 §8.4.1)
/// Points to the PKCS#15 application using the SC-HSM AID.
pub const EF_DIR: &[u8] = &[
    0x61, 0x11, // Application template tag + length (17 bytes)
    0x4F, 0x0B, // Application ID tag + length
    0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01, // SC-HSM AID
    0x50, 0x02, // Application label tag + length
    0x48, 0x53, // "HS" (short for HSM)
];

// ---------------------------------------------------------------------------
// EF.ODF (0x5031) — Object Directory File
// Points to AODF, PrKDF, PuKDF
// ---------------------------------------------------------------------------

/// EF.ODF — Object Directory File (PKCS#15 §6.7)
/// Entries in ascending CHOICE tag order: [0] privateKeys, [1] publicKeys, [8] authObjects.
/// Each entry is: `[N] 06  30 04  04 02 <fid_hi> <fid_lo>` = 8 bytes.
/// Total: 3 × 8 = 24 bytes.
pub const EF_ODF: &[u8] = &[
    // PrivateKeys (PrKDF) at EF 0xC100 — [0] CHOICE
    0xA0, 0x06, // [0] CONTEXT CONSTRUCTED, 6 bytes
    0x30, 0x04, // Path SEQUENCE, 4 bytes
    0x04, 0x02, // path OCTET STRING, 2 bytes
    0xC1, 0x00, // file ID = 0xC100

    // PublicKeys (PuKDF) at EF 0xC200 — [1] CHOICE
    0xA1, 0x06, // [1] CONTEXT CONSTRUCTED, 6 bytes
    0x30, 0x04,
    0x04, 0x02,
    0xC2, 0x00, // file ID = 0xC200

    // AuthObjects (AODF) at EF 0xC000 — [8] CHOICE
    0xA8, 0x06, // [8] CONTEXT CONSTRUCTED, 6 bytes
    0x30, 0x04,
    0x04, 0x02,
    0xC0, 0x00, // file ID = 0xC000
];

// ---------------------------------------------------------------------------
// EF.TokenInfo (0x5032) — Token information
// ---------------------------------------------------------------------------

/// EF.TokenInfo — TokenInfo (PKCS#15 §6.8)
/// Describes the token to the PKCS#15 library.
/// Structure: version, serialNumber, manufacturerID, label[0], tokenflags
/// Total: 2 (header) + 40 (content) = 42 bytes.
pub const EF_TOKEN_INFO: &[u8] = &[
    0x30, 0x28, // SEQUENCE, 40 bytes of content
    // version INTEGER 0
    0x02, 0x01, 0x00,
    // serialNumber OCTET STRING "pico2hsm" (8 bytes)
    0x04, 0x08,
    0x70, 0x69, 0x63, 0x6F, 0x32, 0x68, 0x73, 0x6D,
    // manufacturerID UTF8String "pico2hsm"
    0x0C, 0x08,
    0x70, 0x69, 0x63, 0x6F, 0x32, 0x68, 0x73, 0x6D,
    // label [0] EXPLICIT UTF8String "SmartHSM"
    0xA0, 0x0A,
    0x0C, 0x08,
    0x53, 0x6D, 0x61, 0x72, 0x74, 0x48, 0x53, 0x4D,
    // tokenflags BIT STRING { loginRequired(0), prnGeneration(2) }
    0x03, 0x03, 0x07, 0x60, 0x00,
];

// ---------------------------------------------------------------------------
// EF.AODF (0xC000) — Authentication Object Directory File
// Describes the User PIN and SO-PIN objects
// ---------------------------------------------------------------------------

/// EF.AODF — Authentication Object Directory File (PKCS#15)
///
/// User PIN object — 40 bytes total.
///
/// Structure:
///   30 26  outer SEQUENCE (38 bytes content)
///     30 0A  CommonObjectAttributes (10 bytes)
///       0C 08 "User PIN"
///     30 03  CommonAuthenticationObjectAttributes (3 bytes)
///       04 01 01  authId OCTET STRING = 0x01
///     A1 13  typeAttributes [1] (19 bytes)
///       30 11  PinAttributes SEQUENCE (17 bytes)
///         03 02 03 48  pinFlags: local(bit1) | initialized(bit4)
///         02 01 01     pinType: ascii-numeric
///         02 01 04     minLength: 4
///         02 01 10     storedLength: 16
///         02 02 00 81  pinReference: 0x81 (SC-HSM User PIN P2)
pub const EF_AODF: &[u8] = &[
    // User PIN object — outer SEQUENCE
    0x30, 0x26, // SEQUENCE, 38 bytes of content
    // CommonObjectAttributes — label only, no flags/authId
    0x30, 0x0A, // SEQUENCE, 10 bytes
    0x0C, 0x08, // UTF8String, 8 bytes
    0x55, 0x73, 0x65, 0x72, 0x20, 0x50, 0x49, 0x4E, // "User PIN"
    // CommonAuthenticationObjectAttributes
    0x30, 0x03, // SEQUENCE, 3 bytes
    0x04, 0x01, 0x01, // authId OCTET STRING = 0x01
    // typeAttributes [1] PinAttributes
    0xA1, 0x13, // [1] CONTEXT CONSTRUCTED, 19 bytes
    0x30, 0x11, // PinAttributes SEQUENCE, 17 bytes
    0x03, 0x02, 0x03, 0x48, // pinFlags: local (bit1=0x40) | initialized (bit4=0x08)
    0x0A, 0x01, 0x01, // pinType: ENUMERATED ascii-numeric (1)
    0x02, 0x01, 0x04, // minLength: 4
    0x02, 0x01, 0x10, // storedLength: 16
    0x80, 0x02, 0x00, 0x81, // pinReference: [0] IMPLICIT INTEGER 0x81 (SC-HSM User PIN P2)
];

// ---------------------------------------------------------------------------
// EF.PrKDF (0xC100) — Private Key Directory File (empty initially)
// ---------------------------------------------------------------------------

/// EF.PrKDF — Private Key Directory File (PKCS#15).
/// Empty until keys are generated/imported.
pub const EF_PRKDF: &[u8] = &[];

// ---------------------------------------------------------------------------
// EF.PuKDF (0xC200) — Public Key Directory File (empty initially)
// ---------------------------------------------------------------------------

/// EF.PuKDF — Public Key Directory File (PKCS#15).
/// Empty until keys are generated/imported.
pub const EF_PUKDF: &[u8] = &[];
