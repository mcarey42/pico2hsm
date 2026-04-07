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
use crate::security::dkek::SHARE_BLOB_SIZE;

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
            // Create key domain — reset DKEK state and begin share collection.
            state.dkek.init_shares(state.dkek_shares_required);
            state.dkek_shares_imported = 0;
            ApduResponse::ok(&[])
        }
        0x02 => {
            // Delete key domain — clear DKEK state.
            state.dkek.clear();
            state.dkek_shares_imported = 0;
            ApduResponse::ok(&[])
        }
        0x03 => {
            // Import DKEK share. Data must be exactly SHARE_BLOB_SIZE (80) bytes.
            if cmd.data.len() != SHARE_BLOB_SIZE {
                return ApduResponse::err(SW_WRONG_DATA);
            }
            // Password is empty (shares are pre-encrypted by the host ceremony tool).
            match state.dkek.import_share(cmd.data, b"") {
                Ok(crate::security::dkek::DkekImportResult::Complete) => {
                    state.dkek_shares_imported = state.dkek.shares_total();
                    ApduResponse::ok(&[])
                }
                Ok(crate::security::dkek::DkekImportResult::MoreSharesNeeded { received, .. }) => {
                    state.dkek_shares_imported = received;
                    // SW_6985 = conditions not satisfied (more shares needed)
                    ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED)
                }
                Err(_) => ApduResponse::err(SW_WRONG_DATA),
            }
        }
        0x04 => {
            // Query domain status — return share count info + readiness.
            let resp_data = [
                state.dkek_shares_required,
                state.dkek_shares_imported,
                if state.dkek.is_ready() { 0x01 } else { 0x00 },
            ];
            ApduResponse::ok(&resp_data)
        }
        0x05 => {
            // Assign key to domain — reserved for v2 (per-key domain assignment).
            ApduResponse::err(SW_INS_NOT_SUPPORTED)
        }
        _ => ApduResponse::err(SW_WRONG_DATA),
    }
}
