//! INTERNAL AUTHENTICATE command handler (INS = 0x88) for OpenPGP.
//!
//! Signs with the AUTH key. Used for SSH authentication and TLS client auth.
//! Requires PW1 verified with P2=0x82 (mode 82, session-persistent).
//! Does NOT increment the signature counter.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_SECURITY_STATUS, SW_WRONG_DATA,
};

use crate::protocol::openpgp::commands::pso::der_to_raw_rs;
use crate::protocol::openpgp::OpenPgpState;

/// INS byte for INTERNAL AUTHENTICATE.
pub const INS_AUTHENTICATE: u8 = 0x88;

/// Handle an INTERNAL AUTHENTICATE APDU command.
pub fn handle(state: &mut OpenPgpState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Requires PW1 mode 82
    if !state.pw1_verified_other {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // Retrieve AUTH key
    let priv_key = match &state.auth_private {
        Some(k) => k,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    let key_type = match state.auth_key_type {
        Some(kt) => kt,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Copy private key
    let priv_len = priv_key.len();
    let Some(priv_buf) = crate::security::zeroize::key_buf::<66>(priv_key) else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };

    // Ed25519 (EdDSA signs the challenge itself; raw 64-byte R||S).  It
    // went through ecdsa_sign, which rejects Ed25519: always 6985.
    #[cfg(feature = "applet-openpgp-curve25519")]
    if key_type == pico2hsm_core::key::KeyType::Ed25519 {
        return match crate::crypto::asymmetric::ed25519_sign(&priv_buf[..priv_len], cmd.data) {
            Ok(sig) => ApduResponse::ok(&sig),
            Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
        };
    }

    // Sign: input is the hash/challenge
    let mut rng = crate::protocol::sc_hsm::FwRng;
    let der_sig = match crate::crypto::asymmetric::ecdsa_sign(
        key_type,
        &priv_buf[..priv_len],
        cmd.data,
        &mut rng,
    ) {
        Ok(s) => s,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Convert DER to raw r||s (OpenPGP format)
    let raw_sig = match der_to_raw_rs(&der_sig, key_type) {
        Some(s) => s,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // No signature counter increment for INTERNAL AUTHENTICATE
    ApduResponse::ok(&raw_sig)
}

#[cfg(all(test, feature = "applet-openpgp-curve25519"))]
mod tests {
    use super::*;

    #[test]
    fn ed25519_auth_key_signs() {
        let mut state = OpenPgpState::new();
        state.pw1_verified_other = true;
        let mut seed = heapless::Vec::new();
        seed.extend_from_slice(&[7u8; 32]).unwrap();
        state.auth_private = Some(seed);
        state.auth_key_type = Some(pico2hsm_core::key::KeyType::Ed25519);
        let apdu = [0x00, 0x88, 0x00, 0x00, 0x04, 1, 2, 3, 4, 0x00];
        let cmd = ApduCommand::parse(&apdu).unwrap();
        let r = handle(&mut state, &cmd);
        assert_eq!(r.sw, 0x9000);
        assert_eq!(r.data.len(), 64);
    }
}
