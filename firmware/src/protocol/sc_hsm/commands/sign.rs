//! COMPUTE DIGITAL SIGNATURE command handler (INS = 0x68).
//!
//! Computes an ECDSA signature using the private key selected by the
//! preceding MSE SET command.
//!
//! Two algorithm families are supported:
//! - **0x13/0x15/0x17/0x19** (ECDSA with hash): command data is already the
//!   message digest; passed directly to the signing primitive.
//! - **0x71/0x73/0x75/0x77** (ECDSA raw / OpenSC PKCS#15 path): command data
//!   is the raw message; the card must compute the hash before signing.
//!   0x71/0x73 → SHA-256, 0x75 → SHA-384, 0x77 → SHA-512.

use sha2::Digest as _;

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND,
    SW_INS_NOT_SUPPORTED, SW_SECURITY_STATUS,
};

use crate::protocol::sc_hsm::{FwRng, ScHsmState};

/// INS byte for COMPUTE DIGITAL SIGNATURE.
pub const INS_SIGN: u8 = 0x68;

/// Handle a COMPUTE DIGITAL SIGNATURE APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // SC-HSM encodes the key reference in P1 and the algorithm in P2 directly
    // in the SIGN APDU (no preceding MSE SET required).
    let key_id = cmd.p1;
    let algo = cmd.p2;

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Only ECDSA algorithms are supported.
    // 0x13/0x15/0x17/0x19 = ECDSA with pre-hashed digest (hash-before-send on host).
    // 0x70 = EC Raw pre-hashed (OpenSC hashes on host; data is already the digest).
    // 0x71/0x73/0x75/0x77 = ECDSA with hash (OpenSC sends raw message; card must hash).
    match algo {
        0x13 | 0x15 | 0x17 | 0x19 | 0x70 | 0x71 | 0x73 | 0x75 | 0x77 => {}
        _ => return ApduResponse::err(SW_INS_NOT_SUPPORTED),
    }

    // Look up the key in the in-memory store
    let key = match state.keys.iter().find(|k| k.key_id == key_id) {
        Some(k) => k,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    let key_type = key.key_type;
    // Copy private key bytes to a local buffer to avoid holding reference into `state`
    let mut priv_buf = [0u8; 66];
    let priv_len = key.private_key.len();
    priv_buf[..priv_len].copy_from_slice(&key.private_key);

    // For EC-Raw algorithms (0x71/0x73/0x75/0x77) the host sends the raw message;
    // we must hash it here before passing to the sign_prehash primitive.
    // Use a fixed-size stack buffer large enough for SHA-512 (64 bytes).
    let mut hash_buf = [0u8; 64];
    let hash: &[u8] = match algo {
        0x71 | 0x73 => {
            // SHA-256
            let digest = sha2::Sha256::digest(cmd.data);
            hash_buf[..32].copy_from_slice(&digest);
            &hash_buf[..32]
        }
        0x75 => {
            // SHA-384
            let digest = sha2::Sha384::digest(cmd.data);
            hash_buf[..48].copy_from_slice(&digest);
            &hash_buf[..48]
        }
        0x77 => {
            // SHA-512
            let digest = sha2::Sha512::digest(cmd.data);
            hash_buf[..64].copy_from_slice(&digest);
            &hash_buf[..64]
        }
        _ => {
            // 0x13/0x15/0x17/0x19: data is already the digest
            cmd.data
        }
    };

    let sig = match crate::crypto::asymmetric::ecdsa_sign(
        key_type,
        &priv_buf[..priv_len],
        hash,
        &mut FwRng,
    ) {
        Ok(s) => s,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    ApduResponse::ok(&sig)
}
