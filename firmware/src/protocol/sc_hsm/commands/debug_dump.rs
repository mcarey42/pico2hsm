//! Debug memory dump APDU handler.
//! Only compiled when `#[cfg(feature = "debug")]` — gated at module declaration in mod.rs.
//!
//! # Security warning
//! Including this command in a production build would constitute a
//! critical security vulnerability. The `debug` feature MUST NOT be
//! enabled for devices deployed in production.
//!
//! # Command data
//! - P1=0x00: Dump RAM region (address in data[0..4], length in data[4..6])
//! - P1=0x01: Dump flash region (address in data[0..4], length in data[4..6])
//! - P1=0x02: Dump OTP region (page in data[0], row in data[1])

use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_WRONG_DATA};

/// INS byte for DEBUG MEMORY DUMP.
pub const INS_DEBUG_DUMP: u8 = 0xFE;

/// Handle a DEBUG MEMORY DUMP APDU command.
pub fn handle(cmd: &ApduCommand<'_>) -> ApduResponse {
    // TODO: implement — read memory region and return raw bytes.
    // NOTE: This is a debug-only stub. Production builds never compile this.
    ApduResponse::err(SW_WRONG_DATA)
}
