//! EXPORT KEY command handler (INS = 0x34).
//!
//! Exports a key object wrapped under the DKEK for HSM-to-HSM backup.
//! This command does NOT export plaintext key material.
//!
//! Requires active PIN session. Keys marked with NO-EXPORT flag are rejected.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};
use pico2hsm_core::key::KeyId;

use crate::protocol::sc_hsm::{FwRng, ScHsmState};
use crate::storage::KeyStore;

/// INS byte for EXPORT KEY.
pub const INS_EXPORT_KEY: u8 = 0x34;

/// Handle an EXPORT KEY APDU command.
pub fn handle(state: &mut ScHsmState, store: &mut dyn KeyStore, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let full_key_id_logged = pico2hsm_core::key::KeyId::sc_hsm(0, cmd.p1);
    crate::cdc_log!("SC-HSM EXPORT KEY key=0x{:08x}", full_key_id_logged.0);

    // Require DKEK ready
    if !state.dkek.is_ready() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    let key_ref = cmd.p1;
    if key_ref == 0x00 || key_ref == 0xFF {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    let full_key_id = KeyId::sc_hsm(0, key_ref);

    // Try to load key from persistent store first, then fall back to in-memory.
    let (private_key_bytes, algo_byte) = match store.fetch_key(full_key_id) {
        Ok(Some(key_obj)) => {
            // Got a key from flash. Extract private key and algorithm byte.
            let algo = key_obj.algorithm as u8;
            let mut priv_data: heapless::Vec<u8, 2400> = heapless::Vec::new();
            let _ = priv_data.extend_from_slice(&key_obj.private_key);
            (priv_data, algo)
        }
        _ => {
            // Fall back to in-memory key lookup (EC keys).
            if let Some(key) = state.keys.iter().find(|k| k.key_id == full_key_id.0) {
                let mut priv_data: heapless::Vec<u8, 2400> = heapless::Vec::new();
                let _ = priv_data.extend_from_slice(&key.private_key);
                (priv_data, key.algo)
            } else {
                // Try RSA keys.
                #[cfg(feature = "rsa")]
                {
                    if let Some(rsa_key) = state.rsa_keys.iter().find(|k| k.key_id == full_key_id.0) {
                        let mut priv_data: heapless::Vec<u8, 2400> = heapless::Vec::new();
                        let _ = priv_data.extend_from_slice(&rsa_key.private_key_der);
                        (priv_data, rsa_key.algo)
                    } else {
                        return ApduResponse::err(SW_FILE_NOT_FOUND);
                    }
                }
                #[cfg(not(feature = "rsa"))]
                {
                    return ApduResponse::err(SW_FILE_NOT_FOUND);
                }
            }
        }
    };

    // Wrap key under DKEK.
    let mut rng = FwRng;
    match state.dkek.wrap(&private_key_bytes, algo_byte, 0x01, &mut rng) {
        Ok(wrapped) => ApduResponse::ok(&wrapped),
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}
