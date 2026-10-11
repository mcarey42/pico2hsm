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

use crate::security::key_policy::SW_REFERENCE_NOT_FOUND;
use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INCORRECT_P1P2,
    SW_INS_NOT_SUPPORTED, SW_SECURITY_STATUS, SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::ScHsmState;
use crate::security::dkek::{DkekImportResult, SHARE_BLOB_SIZE};

/// INS byte for KEY DOMAIN.
pub const INS_KEY_DOMAIN: u8 = 0x52;

/// `[shares, missing, KCV(8)]` for key domain 0.
fn domain_status(state: &ScHsmState) -> [u8; 10] {
    let mut resp = [0u8; 10];
    if state.dkek.is_ready() {
        resp[0] = state.dkek.shares_total();
        resp[1] = 0;
        if let Ok(kcv) = state.dkek.compute_kcv() {
            resp[2..10].copy_from_slice(&kcv);
        }
    } else {
        let total = state.dkek.shares_total();
        resp[0] = total;
        resp[1] = total.saturating_sub(state.dkek.shares_received());
    }
    resp
}

/// Handle a KEY DOMAIN APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // P1=0x00: key domain status (no data) or IMPORT DKEK SHARE (raw
    // 32-byte share, no auth required).  sc-hsm-tool decrypts the
    // PBE-protected share on the host and sends the raw value with
    // CLA=0x80 INS=0x52 P1=0x00 P2=<domain>; without data it asks for the
    // status (`sc-hsm-tool` with no command, for each domain 0..255).
    //
    // Response, as OpenSC `sc_hsm_manage_key_domain` reads it:
    //   [shares in the DKEK(1), shares still missing(1), KCV(8)]
    // KCV = SHA-256(DKEK)[0..8] (CardContact), zeros until complete.
    if cmd.p1 == 0x00 {
        // One key domain (0).  6A86 ends sc-hsm-tool's domain loop.
        if cmd.p2 != 0x00 {
            return ApduResponse::err(SW_INCORRECT_P1P2);
        }
        if cmd.data.is_empty() {
            if !state.dkek.is_ready() && state.dkek_shares_required == 0 {
                // No DKEK configured: sc-hsm-tool prints "Empty".
                return ApduResponse::err(SW_REFERENCE_NOT_FOUND);
            }
            return ApduResponse::ok(&domain_status(state));
        }
        if cmd.data.len() != 32 {
            return ApduResponse::err(SW_WRONG_DATA);
        }
        let raw: &[u8; 32] = cmd.data.try_into().unwrap();
        crate::cdc_log!(
            "KEY_DOMAIN import_share_raw: required={} imported={}",
            state.dkek_shares_required,
            state.dkek_shares_imported
        );
        match state.dkek.import_share_raw(raw) {
            Ok(DkekImportResult::Complete) => {
                state.dkek_shares_imported = state.dkek.shares_total();
                crate::cdc_log!(
                    "KEY_DOMAIN DKEK Complete: is_ready={}",
                    state.dkek.is_ready()
                );
            }
            Ok(DkekImportResult::MoreSharesNeeded { received, .. }) => {
                state.dkek_shares_imported = received;
            }
            Err(_) => return ApduResponse::err(SW_WRONG_DATA),
        }
        return ApduResponse::ok(&domain_status(state));
    }

    // All other P1 values require SO-PIN for domain management
    if !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // An established DKEK is never replaced or cleared here — the same
    // invariant as the DKEK exchange (S-02).  Wrapped backups depend on
    // it; INITIALIZE (which wipes every key) is the only way to start over.
    if matches!(cmd.p1, 0x01 | 0x02) && state.dkek.is_ready() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
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
                Ok(DkekImportResult::Complete) => {
                    state.dkek_shares_imported = state.dkek.shares_total();
                    ApduResponse::ok(&[])
                }
                Ok(DkekImportResult::MoreSharesNeeded { received, .. }) => {
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

    #[test]
    fn established_dkek_cannot_be_reset_or_deleted() {
        let mut state = make_state_with_dkek_shares(1);
        let share = build_apdu(0x00, 0x00, &[0x11; 32]);
        let cmd = ApduCommand::parse(&share).unwrap();
        assert_eq!(handle(&mut state, &cmd).sw, SW_OK);
        assert!(state.dkek.is_ready());
        state.so_pin_verified = true;
        for p1 in [0x01, 0x02] {
            let apdu = build_apdu(p1, 0x00, &[]);
            let cmd = ApduCommand::parse(&apdu).unwrap();
            assert_eq!(handle(&mut state, &cmd).sw, SW_CONDITIONS_NOT_SATISFIED);
            assert!(state.dkek.is_ready(), "DKEK kept (P1={p1:02X})");
        }
    }

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
        assert_eq!(
            resp.sw, SW_OK,
            "P1=0x00 raw share import must not require SO-PIN"
        );
    }

    #[test]
    fn test_import_share_raw_wrong_length_rejected() {
        let mut state = make_state_with_dkek_shares(1);

        // 33 bytes — one too many
        let bad_data = [0xBBu8; 33];
        let apdu = build_apdu(0x00, 0x00, &bad_data);
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &cmd);

        assert_eq!(
            resp.sw, SW_WRONG_DATA,
            "wrong-length share must be rejected"
        );
    }

    #[test]
    fn test_import_share_raw_complete() {
        let mut state = make_state_with_dkek_shares(1);

        let share = [0x42u8; 32];
        let apdu = build_apdu(0x00, 0x00, &share);
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &cmd);

        assert_eq!(resp.sw, SW_OK);
        // Response: [remaining(1), total(1), kcv(8)] = 10 bytes minimum
        // sc-hsm-tool asserts apdu.resplen >= sizeof(key_check_value) + 2 (8+2=10)
        assert_eq!(
            resp.data.len(),
            10,
            "response must be 10 bytes for sc-hsm-tool compatibility"
        );
        assert_eq!(resp.data[0], 0x01, "shares in the DKEK");
        assert_eq!(resp.data[1], 0x00, "no shares missing");
        // CardContact KCV: SHA-256(DKEK)[0..8]; one share, so DKEK = share.
        let h = <sha2::Sha256 as sha2::Digest>::digest([0x42u8; 32]);
        assert_eq!(&resp.data[2..10], &h[..8]);
        // DKEK should now be ready
        assert!(state.dkek.is_ready());
        assert_eq!(state.dkek_shares_imported, 1);
    }

    #[test]
    fn status_and_two_share_import_match_opensc_layout() {
        let mut state = make_state_with_dkek_shares(2);
        let status = |state: &mut ScHsmState| {
            let apdu = build_apdu(0x00, 0x00, &[]);
            let cmd = ApduCommand::parse(&apdu[..4]).unwrap();
            handle(state, &cmd)
        };
        let r = status(&mut state);
        assert_eq!(r.sw, SW_OK);
        assert_eq!(&r.data[..], &[2, 2, 0, 0, 0, 0, 0, 0, 0, 0]);

        let s1 = [0x11u8; 32];
        let s2 = [0x5Cu8; 32];
        let apdu = build_apdu(0x00, 0x00, &s1);
        let r = handle(&mut state, &ApduCommand::parse(&apdu).unwrap());
        assert_eq!(&r.data[..2], &[2, 1]);
        assert_eq!(&r.data[2..], &[0u8; 8]);
        let apdu = build_apdu(0x00, 0x00, &s2);
        let r = handle(&mut state, &ApduCommand::parse(&apdu).unwrap());
        // Shares combine by XOR.
        let dkek = [0x11u8 ^ 0x5C; 32];
        let h = <sha2::Sha256 as sha2::Digest>::digest(dkek);
        assert_eq!(&r.data[..2], &[2, 0]);
        assert_eq!(&r.data[2..], &h[..8]);
        assert_eq!(status(&mut state).data, r.data);
    }

    #[test]
    fn status_of_other_domains_and_no_dkek() {
        let mut state = make_state_with_dkek_shares(1);
        let apdu = build_apdu(0x00, 0x01, &[]);
        let r = handle(&mut state, &ApduCommand::parse(&apdu[..4]).unwrap());
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
        let mut state = ScHsmState::new();
        let apdu = build_apdu(0x00, 0x00, &[]);
        let r = handle(&mut state, &ApduCommand::parse(&apdu[..4]).unwrap());
        assert_eq!(r.sw, SW_REFERENCE_NOT_FOUND);
    }
}
