//! SYMMETRIC CIPHER command handler (INS = 0x78).
//!
//! Performs symmetric encrypt or decrypt using an AES key stored in the
//! keystore. The operation and mode are specified via the preceding MSE SET.
//!
//! Supported modes:
//! - AES-CBC (P2=0x02)
//! - AES-CTR (P2=0x03)
//! - AES-GCM (P2=0x05)
//! - AES-CMAC (P2=0x06)

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_SECURITY_STATUS,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for SYMMETRIC CIPHER.
pub const INS_CIPHER_SYM: u8 = 0x78;

/// Handle a SYMMETRIC CIPHER APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // Require MSE SET
    let _key_id = match state.current_key_id {
        Some(k) => k,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };
    let _algo = match state.current_algo {
        Some(a) => a,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // TODO (Agent 7): dispatch to crypto::symmetric based on MSE state.
    ApduResponse::err(SW_INS_NOT_SUPPORTED)
}
