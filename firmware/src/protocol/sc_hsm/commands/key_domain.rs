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
use crate::security::dkek::{DkekImportResult, SHARE_BLOB_SIZE};

/// INS byte for KEY DOMAIN.
pub const INS_KEY_DOMAIN: u8 = 0x52;

/// Handle a KEY DOMAIN APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // P1=0x00: IMPORT DKEK SHARE (raw 32-byte share, no auth required).
    // sc-hsm-tool decrypts the PBE-protected share on the host and sends
    // the raw 32-byte value with CLA=0x80 INS=0x52 P1=0x00 P2=0x00.
    if cmd.p1 == 0x00 {
        if cmd.data.len() != 32 {
            return ApduResponse::err(SW_WRONG_DATA);
        }
        let raw: &[u8; 32] = cmd.data.try_into().unwrap();
        match state.dkek.import_share_raw(raw) {
            Ok(DkekImportResult::Complete) => {
                state.dkek_shares_imported = state.dkek.shares_total();
                // Response: [0x00, shares_total] — 0 remaining, DKEK ready
                let resp = [0u8, state.dkek.shares_total()];
                return ApduResponse::ok(&resp);
            }
            Ok(DkekImportResult::MoreSharesNeeded { received, total }) => {
                state.dkek_shares_imported = received;
                let remaining = total - received;
                let resp = [remaining, total];
                return ApduResponse::ok(&resp);
            }
            Err(_) => return ApduResponse::err(SW_WRONG_DATA),
        }
    }

    // All other P1 values require SO-PIN for domain management
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

#[cfg(test)]
mod tests {
    use super::*;
    use pico2hsm_core::apdu::{ApduCommand, SW_OK, SW_SECURITY_STATUS, SW_WRONG_DATA};

    use crate::protocol::sc_hsm::ScHsmState;

    fn make_state_with_dkek_shares(n: u8) -> ScHsmState {
        let mut state = ScHsmState::new();
        state.dkek_shares_required = n;
        state.dkek.init_shares(n);
        state
    }

    /// Build a raw APDU byte vector: CLA=0x80 INS=0x52 P1 P2 Lc data.
    fn build_apdu(p1: u8, p2: u8, data: &[u8]) -> heapless::Vec<u8, 256> {
        let mut buf = heapless::Vec::<u8, 256>::new();
        let _ = buf.push(0x80); // CLA
        let _ = buf.push(INS_KEY_DOMAIN); // INS
        let _ = buf.push(p1);
        let _ = buf.push(p2);
        let _ = buf.push(data.len() as u8); // Lc
        let _ = buf.extend_from_slice(data);
        buf
    }

    #[test]
    fn test_import_share_raw_p1_0x00_no_so_pin_required() {
        let mut state = make_state_with_dkek_shares(1);
        // SO-PIN is NOT verified
        assert!(!state.so_pin_verified);

        let share = [0xAAu8; 32];
        let apdu = build_apdu(0x00, 0x00, &share);
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &cmd);

        // Should succeed (SW_OK = 0x9000), not SW_SECURITY_STATUS
        assert_eq!(resp.sw, SW_OK, "P1=0x00 raw share import must not require SO-PIN");
    }

    #[test]
    fn test_import_share_raw_wrong_length_rejected() {
        let mut state = make_state_with_dkek_shares(1);

        // 33 bytes — one too many
        let bad_data = [0xBBu8; 33];
        let apdu = build_apdu(0x00, 0x00, &bad_data);
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &cmd);

        assert_eq!(resp.sw, SW_WRONG_DATA, "wrong-length share must be rejected");
    }

    #[test]
    fn test_import_share_raw_complete() {
        let mut state = make_state_with_dkek_shares(1);

        let share = [0x42u8; 32];
        let apdu = build_apdu(0x00, 0x00, &share);
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &cmd);

        assert_eq!(resp.sw, SW_OK);
        // Response data: [remaining=0x00, total=0x01]
        assert_eq!(resp.data.len(), 2);
        assert_eq!(resp.data[0], 0x00, "remaining shares should be 0");
        assert_eq!(resp.data[1], 0x01, "total shares should be 1");
        // DKEK should now be ready
        assert!(state.dkek.is_ready());
        assert_eq!(state.dkek_shares_imported, 1);
    }
}
