//! APDU types and status word constants (ISO 7816-4).
//!
//! This module provides `ApduCommand` (zero-copy parse over a borrowed slice)
//! and `ApduResponse` (owned heapless buffer + SW1/SW2). All protocol
//! implementations use these types as their I/O currency.

use heapless::Vec;

use crate::error::ProtocolError;

// ---------------------------------------------------------------------------
// Status word constants (ISO 7816-4 §5.1.3)
// ---------------------------------------------------------------------------

/// Normal processing — no further qualification.
pub const SW_OK: u16 = 0x9000;

/// Wrong length (Lc or Le).
pub const SW_WRONG_LENGTH: u16 = 0x6700;

/// Security status not satisfied (authentication required).
/// Memory failure — a persistent write did not complete.
pub const SW_MEMORY_FAILURE: u16 = 0x6581;

pub const SW_SECURITY_STATUS: u16 = 0x6982;

/// Authentication method blocked (PIN locked).
pub const SW_AUTH_BLOCKED: u16 = 0x6983;

/// Referenced data invalid (integrity check failed).
pub const SW_DATA_INVALID: u16 = 0x6984;

/// Conditions of use not satisfied.
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;

/// Wrong data in command data field.
pub const SW_WRONG_DATA: u16 = 0x6A80;

/// Function not supported (e.g. a key type a format cannot express).
pub const SW_FUNC_NOT_SUPPORTED: u16 = 0x6A81;

/// File or application not found.
pub const SW_FILE_NOT_FOUND: u16 = 0x6A82;

/// INS not supported.
/// Incorrect P1/P2 parameters.
pub const SW_INCORRECT_P1P2: u16 = 0x6A86;

pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;

/// CLA not supported.
pub const SW_CLASS_NOT_SUPPORTED: u16 = 0x6E00;

// ---------------------------------------------------------------------------
// ApduCommand — zero-copy, borrows from the raw buffer
// ---------------------------------------------------------------------------

/// A parsed ISO 7816-4 APDU command.
///
/// The `data` field borrows directly from the input buffer — no copy is made.
/// `le` is `None` when no Le byte is present, `Some(n)` for a specific
/// limit.  Short APDU Le=0x00 is pre-resolved to `Some(256)`.  Extended
/// APDU Le=0x0000 is stored as `Some(0)`, meaning 65536 ("return all data").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduCommand<'a> {
    /// Class byte (CLA).
    pub cla: u8,
    /// Instruction byte (INS).
    pub ins: u8,
    /// Parameter byte 1.
    pub p1: u8,
    /// Parameter byte 2.
    pub p2: u8,
    /// Command data field (may be empty).
    pub data: &'a [u8],
    /// Expected response length. `None` = no Le field present.
    pub le: Option<u16>,
}

impl<'a> ApduCommand<'a> {
    /// Parse a raw APDU byte slice into an `ApduCommand`.
    ///
    /// Supports:
    /// - Case 1: `[CLA INS P1 P2]`
    /// - Case 2S: `[CLA INS P1 P2 Le]`
    /// - Case 3S: `[CLA INS P1 P2 Lc data…]`
    /// - Case 4S: `[CLA INS P1 P2 Lc data… Le]`
    /// - Extended length (3-byte Lc/Le) is NOT supported on this device.
    ///
    /// Returns `Err(ProtocolError::ApduTooShort)` if `raw.len() < 4`.
    pub fn parse(raw: &'a [u8]) -> Result<Self, ProtocolError> {
        if raw.len() < 4 {
            return Err(ProtocolError::ApduTooShort);
        }
        let cla = raw[0];
        let ins = raw[1];
        let p1 = raw[2];
        let p2 = raw[3];

        if raw.len() == 4 {
            // Case 1 — no Lc, no Le
            return Ok(ApduCommand {
                cla,
                ins,
                p1,
                p2,
                data: &[],
                le: None,
            });
        }

        // Extended APDU: first byte after header is 0x00.
        // Case 2E: [CLA INS P1 P2 00 Le_hi Le_lo]  (7 bytes)
        // Case 3E: [CLA INS P1 P2 00 Nc_hi Nc_lo data…]  (7+Nc bytes)
        // Case 4E: [CLA INS P1 P2 00 Nc_hi Nc_lo data… Le_hi Le_lo]  (7+Nc+2 bytes)
        if raw[4] == 0x00 && raw.len() != 5 {
            if raw.len() == 7 {
                // Case 2E — two-byte Le; 0x0000 means 65536 (stored as 0)
                let le = u16::from(raw[5]) << 8 | u16::from(raw[6]);
                return Ok(ApduCommand {
                    cla,
                    ins,
                    p1,
                    p2,
                    data: &[],
                    le: Some(le),
                });
            }
            if raw.len() >= 7 {
                let nc = (raw[5] as usize) << 8 | (raw[6] as usize);
                let data_end = 7 + nc;
                if raw.len() < data_end {
                    return Err(ProtocolError::LcMismatch);
                }
                let data = &raw[7..data_end];
                let le = if raw.len() == data_end {
                    // Case 3E — no Le
                    None
                } else if raw.len() == data_end + 2 {
                    // Case 4E — two-byte Le; 0x0000 means 65536 (stored as 0)
                    let le = u16::from(raw[data_end]) << 8 | u16::from(raw[data_end + 1]);
                    Some(le)
                } else {
                    return Err(ProtocolError::InvalidLe);
                };
                return Ok(ApduCommand {
                    cla,
                    ins,
                    p1,
                    p2,
                    data,
                    le,
                });
            }
        }

        let lc = raw[4] as usize;

        if raw.len() == 5 {
            // Case 2S — Le only (Lc byte is actually Le)
            let le = if lc == 0 { 256 } else { lc as u16 };
            return Ok(ApduCommand {
                cla,
                ins,
                p1,
                p2,
                data: &[],
                le: Some(le),
            });
        }

        // Case 3S or 4S
        let data_end = 5 + lc;
        if raw.len() < data_end {
            return Err(ProtocolError::LcMismatch);
        }
        let data = &raw[5..data_end];

        let le = if raw.len() == data_end {
            // Case 3S — no Le
            None
        } else if raw.len() == data_end + 1 {
            // Case 4S — one Le byte
            let le_byte = raw[data_end];
            Some(if le_byte == 0 {
                256
            } else {
                u16::from(le_byte)
            })
        } else {
            return Err(ProtocolError::InvalidLe);
        };

        Ok(ApduCommand {
            cla,
            ins,
            p1,
            p2,
            data,
            le,
        })
    }
}

// ---------------------------------------------------------------------------
// ApduResponse — owned response buffer
// ---------------------------------------------------------------------------

/// An ISO 7816-4 APDU response.
///
/// `data` contains the response body (may be empty). `sw` is the 2-byte
/// status word (SW1 << 8 | SW2).
#[derive(Debug)]
pub struct ApduResponse {
    /// Response data field (may be empty for error responses).
    pub data: Vec<u8, 4096>,
    /// Status word: SW1 in the high byte, SW2 in the low byte.
    pub sw: u16,
}

impl ApduResponse {
    /// Construct a successful response with data.
    pub fn ok(data: &[u8]) -> Self {
        let mut buf: Vec<u8, 4096> = Vec::new();
        // Truncate silently if data exceeds buffer — callers must check capacity.
        let _ = buf.extend_from_slice(&data[..data.len().min(4096)]);
        ApduResponse {
            data: buf,
            sw: SW_OK,
        }
    }

    /// Construct an error response with no data.
    pub fn err(sw: u16) -> Self {
        ApduResponse {
            data: Vec::new(),
            sw,
        }
    }

    /// Construct a SW=61xx response indicating more data is available.
    ///
    /// `next_len` is the number of bytes available in the next chunk (SW2 of 0x61xx).
    /// A value of 0 means "more than 255 bytes remaining" and is sent as 0x6100.
    pub fn ok_more(data: &[u8], next_len: u8) -> Self {
        let mut buf: Vec<u8, 4096> = Vec::new();
        let _ = buf.extend_from_slice(&data[..data.len().min(4096)]);
        ApduResponse {
            data: buf,
            sw: 0x6100 | u16::from(next_len),
        }
    }

    /// Serialize the response to bytes: `data || SW1 || SW2`.
    ///
    /// The returned buffer is at most 4098 bytes (4096 data + 2 status).
    pub fn serialize(&self) -> Vec<u8, 4098> {
        let mut out: Vec<u8, 4098> = Vec::new();
        self.serialize_into(&mut out);
        out
    }

    /// Serialize into `out` (cleared first), without a 4 KB temporary.
    pub fn serialize_into(&self, out: &mut Vec<u8, 4098>) {
        out.clear();
        let _ = out.extend_from_slice(&self.data);
        let _ = out.push((self.sw >> 8) as u8);
        let _ = out.push((self.sw & 0xFF) as u8);
    }
}
