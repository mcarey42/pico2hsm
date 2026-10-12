//! Operation classification for the status display.
//!
//! The display shows *what kind* of operation the host last asked for
//! ("Sign", "Verify", ...).  This module is the single table that maps an
//! APDU of any applet to an [`OpCode`]; the firmware's core1 dispatcher
//! calls it before every command (`docs/DISPLAY_ARCHITECTURE.md`).
//!
//! Only the command header and the shape of the data are looked at, never
//! its content: nothing here can carry host-supplied bytes to the screen.

// Applet and command names (OpenPGP, DERIVE_ASYM) read better unquoted.
#![allow(clippy::doc_markdown)]

/// The applet a command was sent to (the dispatcher's active applet).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum Applet {
    /// No applet selected yet.
    #[default]
    None = 0,
    /// SmartCard-HSM.
    Hsm = 1,
    /// PIV (NIST SP 800-73-4).
    Piv = 2,
    /// OpenPGP card.
    Pgp = 3,
}

impl Applet {
    /// The applet with discriminant `v` (two bits; anything else is `None`).
    pub fn from_bits(v: u32) -> Self {
        match v & 0x3 {
            1 => Applet::Hsm,
            2 => Applet::Piv,
            3 => Applet::Pgp,
            _ => Applet::None,
        }
    }
}

/// Operation category shown on the display.  Five bits on the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    /// No operation yet.
    #[default]
    None = 0,
    /// Signature (SC-HSM SIGN, PIV GENERAL AUTHENTICATE on 9A/9C/9E,
    /// OpenPGP PSO:CDS).
    Sign = 1,
    /// RSA decryption (SC-HSM DECIPHER with an RSA algorithm, PIV 9D).
    Decrypt = 2,
    /// Key agreement / derivation (SC-HSM DECIPHER ECDH, DERIVE_ASYM, PIV 9D ECDH).
    Derive = 3,
    /// OpenPGP INTERNAL AUTHENTICATE.
    Auth = 4,
    /// OpenPGP PSO:DECIPHER.
    Decipher = 5,
    /// Key generation.
    KeyGen = 6,
    /// SC-HSM key import / unwrap.
    Import = 7,
    /// SC-HSM DELETE FILE.
    Delete = 8,
    /// PIN verification (not a status query, not a logout).
    Verify = 9,
    /// CHANGE REFERENCE DATA.
    ChangePin = 10,
    /// RESET RETRY COUNTER.
    Unblock = 11,
    /// SC-HSM INITIALIZE.
    Initialize = 12,
    /// Domain enrollment steps (vendor EXTRAS 0x37 / 0x3D / 0x45).
    Enroll = 13,
    /// Anything else: SELECT, GET DATA, READ BINARY, GET RESPONSE, ...
    /// Never changes the "last operation" shown.
    Other = 31,
}

impl OpCode {
    /// Decode five wire bits (unknown values read as `Other`).
    pub fn from_bits(v: u32) -> Self {
        match v & 0x1F {
            0 => OpCode::None,
            1 => OpCode::Sign,
            2 => OpCode::Decrypt,
            3 => OpCode::Derive,
            4 => OpCode::Auth,
            5 => OpCode::Decipher,
            6 => OpCode::KeyGen,
            7 => OpCode::Import,
            8 => OpCode::Delete,
            9 => OpCode::Verify,
            10 => OpCode::ChangePin,
            11 => OpCode::Unblock,
            12 => OpCode::Initialize,
            13 => OpCode::Enroll,
            _ => OpCode::Other,
        }
    }

    /// Display name (firmware-static text).
    pub fn name(self) -> &'static str {
        match self {
            OpCode::None | OpCode::Other => "--",
            OpCode::Sign => "Sign",
            OpCode::Decrypt => "Decrypt",
            OpCode::Derive => "Derive",
            OpCode::Auth => "Auth",
            OpCode::Decipher => "Decipher",
            OpCode::KeyGen => "Key gen",
            OpCode::Import => "Import",
            OpCode::Delete => "Delete",
            OpCode::Verify => "Verify PIN",
            OpCode::ChangePin => "Change PIN",
            OpCode::Unblock => "Unblock",
            OpCode::Initialize => "Initialize",
            OpCode::Enroll => "Enroll",
        }
    }

    /// Whether a successful run of this operation wrote persistent state
    /// (a key, a credential or its retry counter).  A success of such an
    /// operation clears the sticky "store write failed" health flag.
    pub fn writes_storage(self) -> bool {
        matches!(
            self,
            OpCode::KeyGen
                | OpCode::Import
                | OpCode::Delete
                | OpCode::Verify
                | OpCode::ChangePin
                | OpCode::Unblock
                | OpCode::Initialize
                | OpCode::Enroll
        )
    }
}

/// Outcome class of a status word, two bits on the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum OpResult {
    /// 9000, or 61xx (more data follows via GET RESPONSE).
    #[default]
    Ok = 0,
    /// The card refused the request: wrong PIN (63xx), security status /
    /// conditions (69xx), wrong data or parameters (6Axx, 67xx, 6Bxx, ...).
    Refused = 1,
    /// The device failed: memory / storage (65xx), execution error
    /// (64xx), or no precise diagnosis (6Fxx).
    Error = 2,
}

impl OpResult {
    /// Classify a status word.
    pub fn of_sw(sw: u16) -> Self {
        match sw >> 8 {
            0x90 if sw == 0x9000 => OpResult::Ok,
            0x61 => OpResult::Ok,
            0x64 | 0x65 | 0x6F => OpResult::Error,
            _ => OpResult::Refused,
        }
    }

    /// Decode two wire bits.
    pub fn from_bits(v: u32) -> Self {
        match v & 0x3 {
            0 => OpResult::Ok,
            1 => OpResult::Refused,
            _ => OpResult::Error,
        }
    }
}

/// Whether a PIV GENERAL AUTHENTICATE dynamic authentication template
/// (`7C len { tag len value }*`) carries a non-empty element `want`.
/// Tolerates a truncated template (the first block of a chained command):
/// only tags and lengths are read.
fn piv_template_has(data: &[u8], want: u8) -> bool {
    if data.first() != Some(&0x7C) {
        return false;
    }
    let mut i = match data.get(1) {
        Some(0x81) => 3,
        Some(0x82) => 4,
        Some(_) => 2,
        None => return false,
    };
    while i + 1 < data.len() {
        let tag = data[i];
        let (len, hdr) = match data[i + 1] {
            0x81 => (data.get(i + 2).map_or(0, |&b| usize::from(b)), 3),
            0x82 => {
                let hi = data.get(i + 2).map_or(0, |&b| usize::from(b));
                let lo = data.get(i + 3).map_or(0, |&b| usize::from(b));
                ((hi << 8) | lo, 4)
            }
            b => (usize::from(b), 2),
        };
        if tag == want && len > 0 {
            return true;
        }
        i += hdr + len;
    }
    false
}

/// SC-HSM DECIPHER algorithm bytes that are RSA decryption (the others,
/// 0x23/0x25/0x27/0x29/0x80, are ECDH).
const HSM_RSA_DECRYPT_ALGOS: [u8; 2] = [0x21, 0x22];

/// The operation category of one command sent to `applet`.
///
/// `data` is the command data field; only its shape is examined.
pub fn classify_op(applet: Applet, ins: u8, p1: u8, p2: u8, data: &[u8]) -> OpCode {
    // Interindustry PIN commands, the same INS in all three applets.
    match ins {
        // VERIFY: an empty body is a retry-count query, P1=FF a logout
        // (PIV); neither verifies anything.
        0x20 if applet != Applet::None => {
            return if data.is_empty() || p1 == 0xFF {
                OpCode::Other
            } else {
                OpCode::Verify
            };
        }
        0x24 if applet != Applet::None => return OpCode::ChangePin,
        0x2C if applet != Applet::None => return OpCode::Unblock,
        _ => {}
    }
    match applet {
        Applet::None => OpCode::Other,
        Applet::Hsm => match ins {
            0x68 => OpCode::Sign,
            0x62 if HSM_RSA_DECRYPT_ALGOS.contains(&p2) => OpCode::Decrypt,
            // ECDH algorithm codes, and DERIVE_ASYM (P1=01, P2=00).
            0x62 => OpCode::Derive,
            0x46 | 0x48 => OpCode::KeyGen,
            0x74 => OpCode::Import,
            0xE4 => OpCode::Delete,
            0x50 => OpCode::Initialize,
            0x54 if matches!(p1, 0x37 | 0x3D | 0x45) => OpCode::Enroll,
            _ => OpCode::Other,
        },
        Applet::Piv => match ins {
            0x87 if matches!(p2, 0x9A | 0x9C | 0x9E) && piv_template_has(data, 0x81) => {
                OpCode::Sign
            }
            0x87 if p2 == 0x9D && piv_template_has(data, 0x85) => OpCode::Derive,
            0x87 if p2 == 0x9D && piv_template_has(data, 0x81) => OpCode::Decrypt,
            0x47 => OpCode::KeyGen,
            _ => OpCode::Other,
        },
        Applet::Pgp => match (ins, p1, p2) {
            (0x2A, 0x9E, 0x9A) => OpCode::Sign,
            (0x2A, 0x80, 0x86) => OpCode::Decipher,
            (0x88, _, _) => OpCode::Auth,
            // P1=0x81 only reads the public key.
            (0x47, 0x80, _) => OpCode::KeyGen,
            _ => OpCode::Other,
        },
    }
}

/// Follows ISO 7816 command chaining (CLA bit 0x10) so a chained command
/// counts once, as the operation its first block announced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpTracker {
    /// INS and operation of a chain in progress.
    pending: Option<(u8, OpCode)>,
}

impl OpTracker {
    /// A tracker with no chain in progress.
    pub const fn new() -> Self {
        OpTracker { pending: None }
    }

    /// Forget any chain in progress (session end).
    pub fn reset(&mut self) {
        self.pending = None;
    }

    /// The operation this command performs: `Other` for every block of a
    /// chain except the last, which reports the chain's operation.
    pub fn observe(
        &mut self,
        applet: Applet,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> OpCode {
        let op = classify_op(applet, ins, p1, p2, data);
        if cla & 0x10 != 0 {
            let first = match self.pending {
                Some((i, o)) if i == ins => o,
                _ => op,
            };
            self.pending = Some((ins, first));
            return OpCode::Other;
        }
        match self.pending.take() {
            Some((i, o)) if i == ins && o != OpCode::Other => o,
            _ => op,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGN_TEMPLATE: [u8; 8] = [0x7C, 0x06, 0x82, 0x00, 0x81, 0x02, 0xAA, 0xBB];

    #[test]
    fn hsm_table() {
        let a = Applet::Hsm;
        assert_eq!(classify_op(a, 0x68, 0x03, 0x70, &[1]), OpCode::Sign);
        assert_eq!(classify_op(a, 0x62, 0x03, 0x21, &[1]), OpCode::Decrypt);
        assert_eq!(classify_op(a, 0x62, 0x03, 0x80, &[4]), OpCode::Derive);
        assert_eq!(classify_op(a, 0x62, 0x01, 0x00, &[4]), OpCode::Derive);
        assert_eq!(classify_op(a, 0x46, 0x02, 0x00, &[]), OpCode::KeyGen);
        assert_eq!(classify_op(a, 0x48, 0x02, 0xB0, &[]), OpCode::KeyGen);
        assert_eq!(classify_op(a, 0x74, 0x02, 0x93, &[1]), OpCode::Import);
        assert_eq!(classify_op(a, 0xE4, 0x02, 0x00, &[0xCC, 2]), OpCode::Delete);
        assert_eq!(classify_op(a, 0x50, 0, 0, &[1]), OpCode::Initialize);
        for p1 in [0x37, 0x3D, 0x45] {
            assert_eq!(classify_op(a, 0x54, p1, 0, &[]), OpCode::Enroll);
        }
        assert_eq!(classify_op(a, 0x54, 0x40, 0, &[]), OpCode::Other);
        assert_eq!(classify_op(a, 0x20, 0, 0x81, b"648219"), OpCode::Verify);
        assert_eq!(classify_op(a, 0x20, 0, 0x81, &[]), OpCode::Other);
        assert_eq!(classify_op(a, 0x24, 0, 0x81, b"x"), OpCode::ChangePin);
        assert_eq!(classify_op(a, 0x2C, 0, 0x81, b"x"), OpCode::Unblock);
        for ins in [0xA4, 0xB1, 0xC0, 0xCA, 0x58] {
            assert_eq!(classify_op(a, ins, 0, 0, &[]), OpCode::Other);
        }
    }

    #[test]
    fn piv_table() {
        let a = Applet::Piv;
        for slot in [0x9A, 0x9C, 0x9E] {
            assert_eq!(
                classify_op(a, 0x87, 0x11, slot, &SIGN_TEMPLATE),
                OpCode::Sign
            );
        }
        // Management-key authentication is not a signature.
        let mgmt = [0x7C, 0x02, 0x80, 0x00];
        assert_eq!(classify_op(a, 0x87, 0x03, 0x9B, &mgmt), OpCode::Other);
        assert_eq!(classify_op(a, 0x87, 0x11, 0x9A, &mgmt), OpCode::Other);
        let ecdh = [0x7C, 0x05, 0x82, 0x00, 0x85, 0x01, 0x04];
        assert_eq!(classify_op(a, 0x87, 0x11, 0x9D, &ecdh), OpCode::Derive);
        assert_eq!(
            classify_op(a, 0x87, 0x07, 0x9D, &SIGN_TEMPLATE),
            OpCode::Decrypt
        );
        assert_eq!(classify_op(a, 0x47, 0x00, 0x9A, &[0xAC]), OpCode::KeyGen);
        assert_eq!(classify_op(a, 0x20, 0x00, 0x80, b"123456"), OpCode::Verify);
        // Logout and status query.
        assert_eq!(classify_op(a, 0x20, 0xFF, 0x80, &[]), OpCode::Other);
        assert_eq!(classify_op(a, 0x20, 0x00, 0x80, &[]), OpCode::Other);
        assert_eq!(classify_op(a, 0x2C, 0x00, 0x80, b"x"), OpCode::Unblock);
        assert_eq!(classify_op(a, 0xCB, 0x3F, 0xFF, &[]), OpCode::Other);
    }

    #[test]
    fn piv_long_form_lengths() {
        // 7C 82 01 06 { 82 00, 81 82 01 00 <256 bytes> } — RSA-2048, truncated.
        let mut d = [0u8; 40];
        d[..10].copy_from_slice(&[0x7C, 0x82, 0x01, 0x06, 0x82, 0x00, 0x81, 0x82, 0x01, 0x00]);
        assert_eq!(classify_op(Applet::Piv, 0x87, 0x07, 0x9A, &d), OpCode::Sign);
        assert!(!piv_template_has(&[], 0x81));
        assert!(!piv_template_has(&[0x7C], 0x81));
    }

    #[test]
    fn pgp_table() {
        let a = Applet::Pgp;
        assert_eq!(classify_op(a, 0x2A, 0x9E, 0x9A, &[1]), OpCode::Sign);
        assert_eq!(classify_op(a, 0x2A, 0x80, 0x86, &[1]), OpCode::Decipher);
        assert_eq!(classify_op(a, 0x88, 0x00, 0x00, &[1]), OpCode::Auth);
        assert_eq!(classify_op(a, 0x47, 0x80, 0x00, &[0xB6, 0]), OpCode::KeyGen);
        assert_eq!(classify_op(a, 0x47, 0x81, 0x00, &[0xB6, 0]), OpCode::Other);
        assert_eq!(classify_op(a, 0x20, 0x00, 0x81, b"123456"), OpCode::Verify);
        assert_eq!(classify_op(a, 0x24, 0x00, 0x83, b"x"), OpCode::ChangePin);
        assert_eq!(classify_op(a, 0xCA, 0x00, 0x6E, &[]), OpCode::Other);
    }

    #[test]
    fn no_applet_is_other() {
        assert_eq!(
            classify_op(Applet::None, 0x20, 0, 0x81, b"123456"),
            OpCode::Other
        );
        assert_eq!(classify_op(Applet::None, 0x68, 0, 0, &[1]), OpCode::Other);
    }

    #[test]
    fn sw_classes() {
        assert_eq!(OpResult::of_sw(0x9000), OpResult::Ok);
        assert_eq!(OpResult::of_sw(0x6110), OpResult::Ok);
        assert_eq!(OpResult::of_sw(0x6100), OpResult::Ok);
        assert_eq!(OpResult::of_sw(0x6982), OpResult::Refused);
        assert_eq!(OpResult::of_sw(0x6A80), OpResult::Refused);
        assert_eq!(OpResult::of_sw(0x63C2), OpResult::Refused);
        assert_eq!(OpResult::of_sw(0x6581), OpResult::Error);
        assert_eq!(OpResult::of_sw(0x6F00), OpResult::Error);
        assert_eq!(OpResult::of_sw(0x9001), OpResult::Refused);
    }

    #[test]
    fn wire_round_trip() {
        for v in 0..32u32 {
            let op = OpCode::from_bits(v);
            if op != OpCode::Other {
                assert_eq!(op as u32, v);
            }
        }
        for v in 0..4u32 {
            assert_eq!(Applet::from_bits(v) as u32, v);
        }
    }

    #[test]
    fn chained_command_counts_once() {
        let mut t = OpTracker::new();
        let first = [0x7C, 0x82, 0x01, 0x06, 0x82, 0x00, 0x81, 0x82, 0x01, 0x00];
        assert_eq!(
            t.observe(Applet::Piv, 0x10, 0x87, 0x07, 0x9A, &first),
            OpCode::Other
        );
        assert_eq!(
            t.observe(Applet::Piv, 0x10, 0x87, 0x07, 0x9A, &[0; 8]),
            OpCode::Other
        );
        assert_eq!(
            t.observe(Applet::Piv, 0x00, 0x87, 0x07, 0x9A, &[0; 8]),
            OpCode::Sign
        );
        // The chain is over: the next block stands alone.
        assert_eq!(
            t.observe(Applet::Piv, 0x00, 0x87, 0x07, 0x9A, &[0; 8]),
            OpCode::Other
        );
        // A different INS abandons the chain.
        t.observe(Applet::Pgp, 0x10, 0x2A, 0x80, 0x86, &[1]);
        assert_eq!(
            t.observe(Applet::Pgp, 0x00, 0xCA, 0x00, 0x6E, &[]),
            OpCode::Other
        );
    }
}
