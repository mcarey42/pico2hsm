//! DECIPHER command handler (INS = 0x62, P1 = 0x00).
//!
//! For EC key agreement (ECDH) algorithms, the command data contains the
//! peer's uncompressed public key point (`04 || X || Y`). The response is
//! the raw shared secret X-coordinate.
//!
//! SC-HSM AlgorithmId bytes for ECDH:
//! - `0x23` — ECDH P-256
//! - `0x25` — ECDH P-384
//! - `0x27` — ECDH P-521
//! - `0x29` — ECDH K-256 (secp256k1)
//!
//! RSA decryption is not yet implemented (requires an allocator).

use pico2hsm_core::{
    apdu::{
        ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND,
        SW_INS_NOT_SUPPORTED, SW_SECURITY_STATUS,
    },
    key::KeyType,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for DECIPHER.
pub const INS_DECRYPT: u8 = 0x62;

/// Map an ECDH AlgorithmId byte to the expected `KeyType`.
///
/// Returns `None` for unknown or non-ECDH algorithm codes.
fn algo_to_key_type(algo: u8) -> Option<KeyType> {
    match algo {
        0x23 => Some(KeyType::EcPrivateP256),
        0x25 => Some(KeyType::EcPrivateP384),
        0x27 => Some(KeyType::EcPrivateP521),
        0x29 => Some(KeyType::EcPrivateK256),
        _ => None,
    }
}

/// Handle a DECIPHER APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // SC-HSM encodes the key reference in P1 and the algorithm in P2 directly
    // in the DECIPHER APDU (no preceding MSE SET required).
    let key_id = cmd.p1;
    let algo = cmd.p2;

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Validate algorithm byte and resolve expected key type.
    let expected_key_type = match algo_to_key_type(algo) {
        Some(kt) => kt,
        None => return ApduResponse::err(SW_INS_NOT_SUPPORTED),
    };

    // Look up the key
    let key = match state.keys.iter().find(|k| k.key_id == key_id) {
        Some(k) => k,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // Confirm the stored key's curve matches the requested algorithm.
    if key.key_type != expected_key_type {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    let key_type = key.key_type;
    let mut priv_buf = [0u8; 66];
    let priv_len = key.private_key.len();
    priv_buf[..priv_len].copy_from_slice(&key.private_key);

    let shared = match crate::crypto::asymmetric::ecdh_agree(
        key_type,
        &priv_buf[..priv_len],
        cmd.data,
    ) {
        Ok(s) => s,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    ApduResponse::ok(&shared)
}
