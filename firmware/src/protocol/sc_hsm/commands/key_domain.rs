//! KEY DOMAIN command handler (INS = 0x52).
//!
//! Manages DKEK (Device Key Encryption Key) domains.
//!
//! # Operations (P1 values)
//! - P1=0x01: Create key domain
//! - P1=0x02: Delete key domain
//! - P1=0x03: Import DKEK share into domain
//! - P1=0x04: Query domain status
//! - P1=0x05: Assign key to domain

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INS_NOT_SUPPORTED,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for KEY DOMAIN.
pub const INS_KEY_DOMAIN: u8 = 0x52;

/// Handle a KEY DOMAIN APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require SO-PIN for domain management
    if !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    match cmd.p1 {
        0x01 => {
            // Create key domain
            // TODO (Agent 7): allocate domain in storage
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        0x02 => {
            // Delete key domain
            // TODO (Agent 7): erase domain and all associated keys
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        0x03 => {
            // Import DKEK share
            if cmd.data.is_empty() {
                return ApduResponse::err(SW_WRONG_DATA);
            }
            state.dkek_shares_imported = state.dkek_shares_imported.saturating_add(1);
            // TODO (Agent 7): process DKEK share, derive DKEK if all shares received
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        0x04 => {
            // Query domain status — return share count info
            let resp_data = [
                state.dkek_shares_required,
                state.dkek_shares_imported,
            ];
            ApduResponse::ok(&resp_data)
        }
        0x05 => {
            // Assign key to domain
            // TODO (Agent 7): update key domain assignment in storage
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        _ => ApduResponse::err(SW_WRONG_DATA),
    }
}
