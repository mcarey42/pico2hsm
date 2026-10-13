//! TERMINATE DF (INS=0xE6) and ACTIVATE FILE (INS=0x44) command handlers for OpenPGP.
//!
//! These commands implement the factory-reset flow (OpenPGP Card spec §12).
//!
//! TERMINATE DF (INS=0xE6):
//!   - Requires PW3 (admin) verified.
//!   - Sets `terminated = true` on `OpenPgpState`.
//!   - Clears all key material and PIN state, and (store path) erases every
//!     OpenPGP record from flash.  The terminated flag itself is not
//!     persisted: after a reset the card comes up factory-fresh, which is
//!     what ACTIVATE FILE would produce anyway.
//!
//! ACTIVATE FILE (INS=0x44):
//!   - Only allowed when `terminated == true`.
//!   - Resets OpenPGP state to factory defaults.
//!   - Returns SW=9000.
//!
//! When `terminated == true`, all other commands (except ACTIVATE FILE and SELECT)
//! must return SW=6285 (selected file in termination state). This is enforced in the
//! dispatch table in `openpgp/mod.rs`.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_SECURITY_STATUS,
};

use crate::protocol::openpgp::OpenPgpState;

/// INS byte for TERMINATE DF.
pub const INS_TERMINATE_DF: u8 = 0xE6;

/// INS byte for ACTIVATE FILE.
pub const INS_ACTIVATE_FILE: u8 = 0x44;

/// SW for "selected file in termination state" (ISO 7816-4).
pub const SW_FILE_TERMINATED: u16 = 0x6285;

/// TERMINATE DF with persistence: erase every OpenPGP record (keys, PW1/PW3)
/// from flash first, so a reset cannot bring the old keys back under the
/// default PINs.  RAM is wiped only once the erase succeeded; a failed erase
/// returns 6581 and leaves the card unchanged, so RAM and flash never drift.
pub fn handle_terminate_with_store(
    state: &mut OpenPgpState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    // PW3 verified, or blocked (OpenPGP 3.4 §7.2.16): otherwise anyone
    // could lock the card for good with three wrong admin PINs.
    if !state.pw3_verified && state.pw3_retries != 0 {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }
    if store
        .wipe_by_owner(pico2hsm_core::key::AppletId::OpenPgp)
        .is_err()
    {
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    }
    let resp = handle_terminate(state, cmd);
    // After a reset the card comes up factory-fresh, so its retry counters
    // go back to the factory allowance too — only now that the old
    // passwords and keys are gone.  RAM keeps 0 until ACTIVATE.
    use crate::protocol::openpgp::{PW1_MAX_RETRIES, PW3_MAX_RETRIES};
    use crate::storage::retry_counter::{set, Credential};
    if set(store, Credential::OpenPgpPw1, PW1_MAX_RETRIES).is_err()
        || set(store, Credential::OpenPgpPw3, PW3_MAX_RETRIES).is_err()
        // The signature counter lives in the counter log, not in the
        // wiped keystore records: reset it with the passwords.
        || super::put_data::save_sig_counter(0, store).is_err()
    {
        // Terminated and wiped all the same; a later TERMINATE (allowed
        // while PW3 is blocked) or ACTIVATE retries the reset.
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    }
    resp
}

/// ACTIVATE FILE with persistence: the factory counters go to the log too.
pub fn handle_activate_with_store(
    state: &mut OpenPgpState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    let resp = handle_activate(state, cmd);
    if resp.sw == pico2hsm_core::apdu::SW_OK
        && crate::protocol::openpgp::OpenPgp::sync_counters(state, store).is_err()
    {
        // RAM follows the log rather than promising tries flash lacks.
        crate::protocol::openpgp::OpenPgp::load_counters(state, store, false);
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    }
    resp
}

/// Handle TERMINATE DF — mark card as terminated, wipe keys and PINs.
pub fn handle_terminate(state: &mut OpenPgpState, _cmd: &ApduCommand<'_>) -> ApduResponse {
    // PW3 verified, or blocked (OpenPGP 3.4 §7.2.16): otherwise anyone
    // could lock the card for good with three wrong admin PINs.
    if !state.pw3_verified && state.pw3_retries != 0 {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // Wipe all key material (zeroized in place, not just dropped).
    crate::protocol::openpgp::wipe_key(&mut state.sig_private);
    crate::protocol::openpgp::wipe_key(&mut state.dec_private);
    crate::protocol::openpgp::wipe_key(&mut state.auth_private);
    state.sig_public = None;
    state.dec_public = None;
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
    for hash in [&mut state.pw1_hash, &mut state.pw3_hash] {
        if let Some(h) = hash.as_mut() {
            zeroize::Zeroize::zeroize(h);
        }
        *hash = None;
    }
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
