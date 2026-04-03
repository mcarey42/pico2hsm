//! DERIVE ASYMMETRIC KEY command handler (INS = 0x62, P1 = 0x01).
//!
//! Note: INS=0x62 is shared with DECIPHER. The P1 byte distinguishes:
//! - P1=0x00 (default): Decipher → decrypt.rs handler
//! - P1=0x01: Derive asymmetric key → this handler
//!
//! Derives a new asymmetric key pair from a stored master key using
//! a KDF-based deterministic derivation (X9.63 or HKDF).

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for DERIVE ASYMMETRIC KEY (shared with DECIPHER).
pub const INS_DERIVE_ASYM: u8 = 0x62;

/// P1 value that selects DERIVE ASYMMETRIC over DECIPHER.
pub const P1_DERIVE: u8 = 0x01;

/// Handle a DERIVE ASYMMETRIC KEY APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let source_key_id = match state.current_key_id {
        Some(k) => k,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // TODO (Agent 7): call crypto::kdf::x963_derive() or hkdf_derive()
    // with source_key_id and derivation info from cmd.data.
    ApduResponse::err(SW_INS_NOT_SUPPORTED)
}
