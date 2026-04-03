//! BIP32/SLIP-0010 HD KEY DERIVE command handler (INS = 0x60).
//!
//! Derives a child key from a stored BIP32 master key using BIP32 or SLIP-0010.
//!
//! # Command data
//! - P1: source master key ID
//! - P2: flags (bit 0 = store derived key, bit 1 = return public key)
//! - Data: derivation path (sequence of 4-byte index values, MSB = hardened)

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for BIP32/SLIP-0010 HD KEY DERIVE.
pub const INS_BIP_SLIP: u8 = 0x60;

/// Handle a BIP32/SLIP-0010 HD KEY DERIVE APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let master_key_id = cmd.p1;
    let flags = cmd.p2;

    // Derivation path must be multiple of 4 bytes
    if cmd.data.len() % 4 != 0 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // TODO (Agent 7): call crypto::kdf::bip32_derive() or slip10_derive().
    ApduResponse::err(SW_INS_NOT_SUPPORTED)
}
