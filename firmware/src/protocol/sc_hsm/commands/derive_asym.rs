//! DERIVE ASYMMETRIC KEY command handler (INS = 0x62, P1 = 0x01).
//!
//! Note: INS=0x62 is shared with DECIPHER. The P1 byte distinguishes:
//! - P1=0x00 (default): Decipher → decrypt.rs handler
//! - P1=0x01: Derive asymmetric key → this handler
//!
//! Derives a new asymmetric key pair from a stored master key using
//! a KDF-based deterministic derivation (X9.63 or HKDF).

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for DERIVE ASYMMETRIC KEY (shared with DECIPHER).
pub const INS_DERIVE_ASYM: u8 = 0x62;

/// P1 value that selects DERIVE ASYMMETRIC over DECIPHER.
pub const P1_DERIVE: u8 = 0x01;

/// Handle a DERIVE ASYMMETRIC KEY APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let source_key_id = match state.current_key_id {
        Some(k) => k,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    let full_key_id = pico2hsm_core::key::KeyId::sc_hsm(0, source_key_id).0;

    // Try EC key first, then symmetric key.
    let key_bytes_opt: Option<heapless::Vec<u8, 66>> = if let Some(k) =
        state.keys.iter().find(|k| k.key_id == full_key_id)
    {
        let mut v: heapless::Vec<u8, 66> = heapless::Vec::new();
        if v.extend_from_slice(&k.private_key).is_err() {
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
        Some(v)
    } else if let Some(k) = state.sym_keys.iter().find(|k| k.key_id == full_key_id) {
        let mut v: heapless::Vec<u8, 66> = heapless::Vec::new();
        if v.extend_from_slice(&k.raw_key).is_err() {
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
        Some(v)
    } else {
        None
    };

    let key_bytes = match key_bytes_opt {
        Some(b) => b,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    let mut output = [0u8; 32];
    match crate::crypto::kdf::hkdf_sha256(&[], &key_bytes, cmd.data, &mut output) {
        Ok(()) => ApduResponse::ok(&output),
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pico2hsm_core::{
        apdu::{SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND, SW_OK, SW_SECURITY_STATUS},
        key::{KeyId, KeyType as CoreKeyType},
    };

    use crate::protocol::sc_hsm::{InMemoryKey, InMemorySymKey, ScHsmState};

    /// Build a minimal APDU raw buffer: [CLA, INS, P1, P2, Lc, data...]
    fn make_apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> heapless::Vec<u8, 128> {
        let mut v: heapless::Vec<u8, 128> = heapless::Vec::new();
        v.push(0x00).unwrap(); // CLA
        v.push(ins).unwrap();  // INS
        v.push(p1).unwrap();   // P1
        v.push(p2).unwrap();   // P2
        v.push(data.len() as u8).unwrap(); // Lc
        v.extend_from_slice(data).unwrap();
        v
    }

    fn derive_apdu(info: &[u8]) -> heapless::Vec<u8, 128> {
        make_apdu(INS_DERIVE_ASYM, P1_DERIVE, 0x00, info)
    }

    fn make_state_with_ec_key(key_proto_ref: u8) -> ScHsmState {
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        state.current_key_id = Some(key_proto_ref);

        let full_key_id = KeyId::sc_hsm(0, key_proto_ref).0;
        let mut private_key: heapless::Vec<u8, 66> = heapless::Vec::new();
        // 32 bytes of fake EC private key
        for i in 0..32u8 {
            private_key.push(i + 1).unwrap();
        }
        let key = InMemoryKey {
            key_id: full_key_id,
            key_type: CoreKeyType::EcPrivateP256,
            algo: 0x13,
            key_flags: 0,
            private_key,
            public_key: heapless::Vec::new(),
        };
        state.keys.push(key).unwrap();
        state
    }

    fn make_state_with_sym_key(key_proto_ref: u8) -> ScHsmState {
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        state.current_key_id = Some(key_proto_ref);

        let full_key_id = KeyId::sc_hsm(0, key_proto_ref).0;
        let mut raw_key: heapless::Vec<u8, 32> = heapless::Vec::new();
        // 32 bytes of fake AES-256 key
        for i in 0..32u8 {
            raw_key.push(0xA0 ^ i).unwrap();
        }
        let sym_key = InMemorySymKey {
            key_id: full_key_id,
            raw_key,
        };
        state.sym_keys.push(sym_key).unwrap();
        state
    }

    #[test]
    fn test_derive_requires_pin() {
        let mut state = ScHsmState::new();
        // pin_verified = false (default)
        state.current_key_id = Some(0x01);
        let raw = derive_apdu(b"test-info");
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_SECURITY_STATUS);
    }

    #[test]
    fn test_derive_no_mse_key_id() {
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        // current_key_id = None (default)
        let raw = derive_apdu(b"test-info");
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_derive_key_not_found() {
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        state.current_key_id = Some(0x01);
        // No key inserted into state.keys or state.sym_keys
        let raw = derive_apdu(b"test-info");
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_FILE_NOT_FOUND);
    }

    #[test]
    fn test_derive_ec_key_returns_32_bytes() {
        let mut state = make_state_with_ec_key(0x01);
        let raw = derive_apdu(b"app-context");
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_OK);
        assert_eq!(resp.data.len(), 32, "derived output must be 32 bytes");
    }

    #[test]
    fn test_derive_sym_key_returns_32_bytes() {
        let mut state = make_state_with_sym_key(0x02);
        let raw = derive_apdu(b"sym-context");
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_OK);
        assert_eq!(resp.data.len(), 32, "derived output must be 32 bytes");
    }

    #[test]
    fn test_derive_different_info_different_output() {
        let mut state1 = make_state_with_ec_key(0x01);
        let mut state2 = make_state_with_ec_key(0x01);

        let raw1 = derive_apdu(b"context-A");
        let raw2 = derive_apdu(b"context-B");

        let cmd1 = pico2hsm_core::apdu::ApduCommand::parse(&raw1).unwrap();
        let cmd2 = pico2hsm_core::apdu::ApduCommand::parse(&raw2).unwrap();

        let resp1 = handle(&mut state1, &cmd1);
        let resp2 = handle(&mut state2, &cmd2);

        assert_eq!(resp1.sw, SW_OK);
        assert_eq!(resp2.sw, SW_OK);
        assert_ne!(
            resp1.data, resp2.data,
            "different info bytes must produce different derived output"
        );
    }
}
