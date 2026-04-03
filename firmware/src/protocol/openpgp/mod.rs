//! OpenPGP Card 3.4 protocol stub.
//!
//! Implements the OpenPGP card application specification v3.4. The device
//! switches to this protocol when a SELECT AID command presents the
//! OpenPGP AID.
//!
//! # AID
//! `D2 76 00 01 24 01 03 04 XX XX 00 00 00 00 00 00`
//! (XX XX = manufacturer + serial number)
//!
//! # Commands to implement (future)
//! - SELECT (0xA4)
//! - GET DATA (0xCA)
//! - PUT DATA (0xDA / 0xDB)
//! - VERIFY (0x20) — PW1 / PW3
//! - CHANGE REFERENCE DATA (0x24)
//! - COMPUTE DIGITAL SIGNATURE (0x2A, PSO:CDS)
//! - DECIPHER (0x2A, PSO:DEC)
//! - AUTHENTICATE (0x88)
//! - GENERATE KEY PAIR (0x47)
//! - GET CHALLENGE (0x84)
//!
//! # TODO (OpenPGP specialist agent — future phase)
//! This is a placeholder stub. No OpenPGP commands are implemented yet.

use heapless::Vec;
use pico2hsm_core::{
    apdu::{ApduResponse, SW_INS_NOT_SUPPORTED},
    protocol::HsmProtocol,
};

/// OpenPGP AID prefix (first 6 bytes; remaining bytes are version + serial).
pub const OPENPGP_AID_PREFIX: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// OpenPGP Card protocol stub.
pub struct OpenPgp;

impl OpenPgp {
    /// Create a new OpenPGP Card protocol stub instance.
    pub fn new() -> Self {
        OpenPgp
    }
}

impl HsmProtocol for OpenPgp {
    fn process_apdu(&mut self, _apdu: &[u8]) -> Vec<u8, 4096> {
        // TODO: implement — OpenPGP command dispatch
        let resp = ApduResponse::err(SW_INS_NOT_SUPPORTED);
        let s = resp.serialize();
        let mut out = Vec::new();
        let _ = out.extend_from_slice(&s);
        out
    }

    fn handles_aid(&self, aid: &[u8]) -> bool {
        aid.len() >= OPENPGP_AID_PREFIX.len()
            && &aid[..OPENPGP_AID_PREFIX.len()] == OPENPGP_AID_PREFIX
    }

    fn protocol_name(&self) -> &'static str {
        "OpenPGP"
    }
}
