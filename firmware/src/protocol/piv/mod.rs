//! PIV (Personal Identity Verification) protocol stub.
//!
//! Implements NIST SP 800-73-4 PIV card commands over USB CCID. This
//! protocol is a secondary implementation; the device switches to it
//! when a SELECT AID command presents the PIV AID.
//!
//! # AID
//! `A0 00 00 03 08 00 00 10 00 01 00` — NIST PIV
//!
//! # Commands to implement (future)
//! - SELECT (0xA4)
//! - GET DATA (0xCB)
//! - PUT DATA (0xDB)
//! - VERIFY (0x20) — PIN
//! - CHANGE REFERENCE DATA (0x24)
//! - RESET RETRY COUNTER (0x2C)
//! - GENERAL AUTHENTICATE (0x87)
//! - GENERATE KEY PAIR (0x47)
//!
//! # TODO (PIV specialist agent — future phase)
//! This is a placeholder stub. No PIV commands are implemented yet.
//! The struct implements `HsmProtocol` so the dispatcher can register it.

use heapless::Vec;
use pico2hsm_core::{
    apdu::{ApduResponse, SW_INS_NOT_SUPPORTED},
    protocol::HsmProtocol,
};

/// AID for NIST PIV.
pub const PIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00];

/// PIV protocol stub.
pub struct Piv;

impl Piv {
    /// Create a new PIV protocol stub instance.
    pub fn new() -> Self {
        Piv
    }
}

impl HsmProtocol for Piv {
    fn process_apdu(&mut self, _apdu: &[u8]) -> Vec<u8, 4096> {
        // TODO: implement — PIV command dispatch
        let resp = ApduResponse::err(SW_INS_NOT_SUPPORTED);
        let s = resp.serialize();
        let mut out = Vec::new();
        let _ = out.extend_from_slice(&s);
        out
    }

    fn handles_aid(&self, aid: &[u8]) -> bool {
        aid == PIV_AID
    }

    fn protocol_name(&self) -> &'static str {
        "PIV"
    }
}
