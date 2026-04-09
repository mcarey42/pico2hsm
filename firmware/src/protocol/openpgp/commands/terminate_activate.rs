//! TERMINATE DF (INS=0xE6) and ACTIVATE FILE (INS=0x44) command handlers for OpenPGP.
//!
//! These commands implement the factory-reset flow (OpenPGP Card spec §12).
//!
//! TERMINATE DF (INS=0xE6):
//!   - Requires PW3 (admin) verified.
//!   - Sets `terminated = true` on `OpenPgpState`.
//!   - Clears all key material and PIN state.
//!
//! ACTIVATE FILE (INS=0x44):
//!   - Only allowed when `terminated == true`.
//!   - Resets OpenPGP state to factory defaults.
//!   - Returns SW=9000.
//!
//! When `terminated == true`, all other commands (except ACTIVATE FILE and SELECT)
//! must return SW=6285 (selected file in termination state). This is enforced in the
//! dispatch table in `openpgp/mod.rs`.

use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_SECURITY_STATUS};

use crate::protocol::openpgp::OpenPgpState;

/// INS byte for TERMINATE DF.
pub const INS_TERMINATE_DF: u8 = 0xE6;

/// INS byte for ACTIVATE FILE.
pub const INS_ACTIVATE_FILE: u8 = 0x44;

/// SW for "selected file in termination state" (ISO 7816-4).
pub const SW_FILE_TERMINATED: u16 = 0x6285;

/// Handle TERMINATE DF — mark card as terminated, wipe keys and PINs.
pub fn handle_terminate(state: &mut OpenPgpState, _cmd: &ApduCommand<'_>) -> ApduResponse {
    // Requires PW3 authenticated
    if !state.pw3_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // Wipe all key material
    state.sig_private = None;
    state.sig_public = None;
    state.dec_private = None;
    state.dec_public = None;
    state.auth_private = None;
    state.auth_public = None;
    state.sig_key_type = None;
    state.dec_key_type = None;
    state.auth_key_type = None;

    // Clear fingerprints and timestamps
    state.fp_sig = [0u8; 20];
    state.fp_dec = [0u8; 20];
    state.fp_auth = [0u8; 20];
    state.ca_fp1 = [0u8; 20];
    state.ca_fp2 = [0u8; 20];
    state.ca_fp3 = [0u8; 20];
    state.ts_sig = [0u8; 4];
    state.ts_dec = [0u8; 4];
    state.ts_auth = [0u8; 4];

    // Clear PIN hashes to block all PIN verification
    state.pw1_hash = None;
    state.pw3_hash = None;
    state.pw1_retries = 0;
    state.pw3_retries = 0;
    state.pw1_verified_sign = false;
    state.pw1_verified_other = false;
    state.pw3_verified = false;

    // Clear cardholder data
    state.cardholder_name.clear();
    state.login_data.clear();
    state.language.clear();
    state.sex = 0x39;

    // Clear URL and cardholder cert
    state.url.clear();
    state.cardholder_cert.clear();

    // Mark terminated
    state.terminated = true;

    ApduResponse::ok(&[])
}

/// Handle ACTIVATE FILE — restore card to factory defaults.
pub fn handle_activate(state: &mut OpenPgpState, _cmd: &ApduCommand<'_>) -> ApduResponse {
    // Only allowed when in terminated state
    if !state.terminated {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Reset to factory defaults — create a fresh state and copy it in
    *state = OpenPgpState::new();

    ApduResponse::ok(&[])
}
