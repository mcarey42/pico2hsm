//! APDU dispatcher — routes commands to the active `HsmProtocol` implementation.
//!
//! The dispatcher holds references to all registered protocol implementations.
//! On receiving a SELECT AID command (INS=0xA4, P1=0x04), it iterates the
//! registered protocols and activates the first one that returns `true` from
//! `handles_aid()`. Subsequent commands are forwarded to the active protocol
//! until the next SELECT AID.
//!
//! # Protocol priority
//! 1. SC-HSM (primary — always registered)
//! 2. PIV (stub)
//! 3. OpenPGP (stub)
//!
//! # AID routing
//! - SC-HSM AID `E8 2B 06 01 04 01 81 C3 1F 02 01` → ScHsm, returns FCI
//! - PIV AID     `A0 00 00 03 08 00 00 10 00 01 00` → Piv stub
//! - OpenPGP AID `D2 76 00 01 24 01 ...`            → OpenPgp stub
//! - Any other AID                                   → SW_FILE_NOT_FOUND

use heapless::Vec;
use pico2hsm_core::{
    apdu::{
        ApduCommand, ApduResponse, SW_CLASS_NOT_SUPPORTED, SW_FILE_NOT_FOUND,
        SW_INS_NOT_SUPPORTED, SW_OK,
    },
    protocol::HsmProtocol,
};

use crate::protocol::{
    openpgp::{OpenPgp, OPENPGP_AID_PREFIX},
    piv::{Piv, PIV_AID},
    sc_hsm::{ScHsm, SC_HSM_AID},
};

/// INS byte for SELECT (ISO 7816-4).
const INS_SELECT: u8 = 0xA4;
/// P1 value for SELECT by AID.
const P1_SELECT_BY_AID: u8 = 0x04;

/// Active protocol discriminant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ActiveProtocol {
    /// No protocol selected (pre-SELECT state).
    None,
    /// SC-HSM is the active protocol.
    ScHsm,
    /// PIV stub is the active protocol.
    Piv,
    /// OpenPGP stub is the active protocol.
    OpenPgp,
}

/// APDU dispatcher.
///
/// Holds one instance of each registered protocol and routes APDUs to
/// the currently active one. The active protocol starts as `None` until
/// a SELECT AID command is received.
pub struct Dispatcher {
    active: ActiveProtocol,
    sc_hsm: ScHsm,
    piv: Piv,
    openpgp: OpenPgp,
}

impl Dispatcher {
    /// Create a new dispatcher with all protocols initialised.
    pub fn new() -> Self {
        Dispatcher {
            active: ActiveProtocol::None,
            sc_hsm: ScHsm::new(),
            piv: Piv::new(),
            openpgp: OpenPgp::new(),
        }
    }

    /// Dispatch a raw APDU byte slice.
    ///
    /// Handles SELECT AID (INS=0xA4, P1=0x04) by switching the active
    /// protocol. All other commands are forwarded to the active protocol.
    ///
    /// Returns the serialized response bytes (data + SW1 + SW2).
    pub fn dispatch(&mut self, raw_apdu: &[u8]) -> Vec<u8, 4098> {
        // Parse the APDU
        let cmd = match ApduCommand::parse(raw_apdu) {
            Ok(c) => c,
            Err(_) => return ApduResponse::err(SW_INS_NOT_SUPPORTED).serialize(),
        };

        // Intercept SELECT by AID before forwarding to the active protocol.
        if cmd.ins == INS_SELECT && cmd.p1 == P1_SELECT_BY_AID {
            let resp = self.select_aid(cmd.data);
            return resp.serialize();
        }

        // Forward to the active protocol.
        let raw_resp: Vec<u8, 4096> = match self.active {
            ActiveProtocol::ScHsm => self.sc_hsm.process_apdu(raw_apdu),
            ActiveProtocol::Piv => self.piv.process_apdu(raw_apdu),
            ActiveProtocol::OpenPgp => self.openpgp.process_apdu(raw_apdu),
            ActiveProtocol::None => {
                // No AID selected yet — return INS not supported
                return ApduResponse::err(SW_INS_NOT_SUPPORTED).serialize();
            }
        };

        // Convert 4096-byte Vec to 4098-byte Vec (add room for SW if needed).
        let mut out: Vec<u8, 4098> = Vec::new();
        let _ = out.extend_from_slice(&raw_resp);
        out
    }

    /// Route a SELECT-by-AID command and return the appropriate FCI response.
    fn select_aid(&mut self, aid: &[u8]) -> ApduResponse {
        // SC-HSM AID
        if aid == SC_HSM_AID {
            self.active = ActiveProtocol::ScHsm;
            return build_sc_hsm_fci();
        }

        // PIV AID
        if aid == PIV_AID {
            self.active = ActiveProtocol::Piv;
            return ApduResponse::ok(&[]);
        }

        // OpenPGP AID (prefix match)
        if aid.len() >= OPENPGP_AID_PREFIX.len()
            && &aid[..OPENPGP_AID_PREFIX.len()] == OPENPGP_AID_PREFIX
        {
            self.active = ActiveProtocol::OpenPgp;
            return ApduResponse::ok(&[]);
        }

        // Unknown AID
        ApduResponse::err(SW_FILE_NOT_FOUND)
    }
}

/// Build the FCI (File Control Information) template returned on SELECT SC-HSM AID.
///
/// Structure matches a real SmartCard-HSM 2 SELECT response so that OpenSC's
/// `iso7816_select_file` accepts it (it requires the outer tag to be 0x6F):
///
/// ```text
/// 6F 16          FCI template (ISO 7816-4 §7.1.1)
///   84 0B [AID]  DF name (tag 0x84 = DF name in FCI context)
///   A5 07        Proprietary information
///     9F 6E 04 [4 bytes]  COS/HW version (SmartCard-HSM convention)
/// ```
fn build_sc_hsm_fci() -> ApduResponse {
    let aid: &[u8] = SC_HSM_AID; // 11 bytes
    // 4 version bytes: [cwa_major, cwa_minor, hw_major, hw_minor]
    let version: &[u8] = &[0x20, 0x00, 0x00, 0x00];

    // A5 inner: 9F 6E 04 + 4 bytes = 7 bytes
    let a5_inner_len: u8 = 2 + 1 + version.len() as u8; // tag(2) + len(1) + data(4) = 7
    // 6F inner: 84 TLV (13 bytes) + A5 TLV (2+7 = 9 bytes) = 22 bytes
    let outer_len: u8 = (2 + aid.len() as u8) + (2 + a5_inner_len);

    let mut fci: Vec<u8, 32> = Vec::new();
    let _ = fci.push(0x6F);
    let _ = fci.push(outer_len);

    // 84: DF name (AID)
    let _ = fci.push(0x84);
    let _ = fci.push(aid.len() as u8);
    let _ = fci.extend_from_slice(aid);

    // A5: proprietary — contains 9F6E version TLV
    let _ = fci.push(0xA5);
    let _ = fci.push(a5_inner_len);
    let _ = fci.push(0x9F);
    let _ = fci.push(0x6E);
    let _ = fci.push(version.len() as u8);
    let _ = fci.extend_from_slice(version);

    ApduResponse::ok(&fci)
}
