//! BIP32/SLIP-0010 HD KEY DERIVE command handler (INS = 0x60).
//!
//! Derives a child key from a stored BIP32 master key using BIP32 or SLIP-0010.
//!
//! # Command data
//! - P1: source master key ID
//! - P2: flags (bit 0 = store derived key, bit 1 = return public key)
//! - Data: derivation path (sequence of 4-byte index values, MSB = hardened)

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};
use pico2hsm_core::key::{KeyId, KeyMaterial, KeyType};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for BIP32/SLIP-0010 HD KEY DERIVE.
pub const INS_BIP_SLIP: u8 = 0x60;

/// Handle a BIP32/SLIP-0010 HD KEY DERIVE APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let master_key_id = cmd.p1;

    // Derivation path must be a multiple of 4 bytes
    if cmd.data.len() % 4 != 0 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Locate the master key in the in-memory EC key store
    let full_key_id = KeyId::sc_hsm(0, master_key_id).0;

    let (key_type, raw_key): (KeyType, heapless::Vec<u8, 66>) =
        if let Some(k) = state.keys.iter().find(|k| k.key_id == full_key_id) {
            let mut v: heapless::Vec<u8, 66> = heapless::Vec::new();
            if v.extend_from_slice(&k.private_key).is_err() {
                return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
            }
            (k.key_type, v)
        } else {
            return ApduResponse::err(SW_FILE_NOT_FOUND);
        };

    // BIP32 master keys must be exactly 64 bytes (key || chain_code)
    if raw_key.len() != 64 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Parse the derivation path
    let mut path: heapless::Vec<u32, 16> = heapless::Vec::new();
    for chunk in cmd.data.chunks(4) {
        let index = u32::from_be_bytes(chunk.try_into().unwrap());
        if path.push(index).is_err() {
            return ApduResponse::err(SW_WRONG_DATA);
        }
    }

    // Build a KeyMaterial for the master key
    let mut master_raw: heapless::Vec<u8, { pico2hsm_core::key::MAX_KEY_BYTES }> =
        heapless::Vec::new();
    if master_raw.extend_from_slice(&raw_key).is_err() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    let master = KeyMaterial {
        key_type,
        key_id: KeyId(full_key_id),
        raw: master_raw,
    };

    // Dispatch to BIP32 or SLIP-0010 based on key type
    let derived = match key_type {
        KeyType::Bip32Master | KeyType::EcPrivateK256 => {
            crate::crypto::kdf::bip32_derive(&master, &path)
        }
        KeyType::EcPrivateP256 => crate::crypto::kdf::slip10_derive(&master, &path),
        _ => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    match derived {
        Ok(km) => ApduResponse::ok(&km.raw),
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
        apdu::{SW_FILE_NOT_FOUND, SW_OK, SW_SECURITY_STATUS, SW_WRONG_DATA},
        key::{KeyId, KeyType as CoreKeyType},
    };

    use crate::protocol::sc_hsm::{InMemoryKey, ScHsmState};

    /// Build a minimal APDU raw buffer: [CLA, INS, P1, P2, Lc, data...]
    fn make_apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> heapless::Vec<u8, 256> {
        let mut v: heapless::Vec<u8, 256> = heapless::Vec::new();
        v.push(0x00).unwrap(); // CLA
        v.push(ins).unwrap();  // INS
        v.push(p1).unwrap();   // P1
        v.push(p2).unwrap();   // P2
        v.push(data.len() as u8).unwrap(); // Lc
        v.extend_from_slice(data).unwrap();
        v
    }

    /// Build a BIP/SLIP APDU with a given master key ID and path bytes.
    fn bip_apdu(master_id: u8, path_bytes: &[u8]) -> heapless::Vec<u8, 256> {
        make_apdu(INS_BIP_SLIP, master_id, 0x00, path_bytes)
    }

    /// Encode a derivation path (slice of u32) as big-endian bytes.
    fn encode_path(path: &[u32]) -> heapless::Vec<u8, 64> {
        let mut v: heapless::Vec<u8, 64> = heapless::Vec::new();
        for &index in path {
            v.extend_from_slice(&index.to_be_bytes()).unwrap();
        }
        v
    }

    /// Build a state with a BIP32 master key (64 bytes = key || chain).
    fn make_state_with_bip32_master(key_proto_ref: u8, key_bytes: &[u8]) -> ScHsmState {
        let mut state = ScHsmState::new();
        state.pin_verified = true;

        let full_key_id = KeyId::sc_hsm(0, key_proto_ref).0;
        let mut private_key: heapless::Vec<u8, 66> = heapless::Vec::new();
        private_key.extend_from_slice(key_bytes).unwrap();

        let key = InMemoryKey {
            key_id: full_key_id,
            key_type: CoreKeyType::Bip32Master,
            algo: 0x00,
            key_flags: 0,
            private_key,
            public_key: heapless::Vec::new(),
        };
        state.keys.push(key).unwrap();
        state
    }

    /// SLIP-0010 test vector 1 master (seed = 000102030405060708090a0b0c0d0e0f)
    fn slip10_tv1_master() -> ([u8; 32], [u8; 32]) {
        let master_key = hex::decode(
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        )
        .unwrap();
        let master_chain = hex::decode(
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        )
        .unwrap();
        let mut k = [0u8; 32];
        let mut c = [0u8; 32];
        k.copy_from_slice(&master_key);
        c.copy_from_slice(&master_chain);
        (k, c)
    }

    fn make_state_tv1(proto_ref: u8) -> ScHsmState {
        let (k, c) = slip10_tv1_master();
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&k);
        combined[32..].copy_from_slice(&c);
        make_state_with_bip32_master(proto_ref, &combined)
    }

    // -----------------------------------------------------------------------
    // Error path tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_bip_slip_requires_pin() {
        let mut state = ScHsmState::new();
        // pin_verified = false (default)
        let raw = bip_apdu(0x01, &[]);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_SECURITY_STATUS);
    }

    #[test]
    fn test_bip_slip_wrong_data_len() {
        let (k, c) = slip10_tv1_master();
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&k);
        combined[32..].copy_from_slice(&c);
        let mut state = make_state_with_bip32_master(0x01, &combined);

        // 3 bytes — not a multiple of 4
        let raw = bip_apdu(0x01, &[0x80, 0x00, 0x00]);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_WRONG_DATA);
    }

    #[test]
    fn test_bip_slip_key_not_found() {
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        // No key in state — P1=0x01 references nothing
        let raw = bip_apdu(0x01, &[]);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_FILE_NOT_FOUND);
    }

    #[test]
    fn test_bip_slip_wrong_key_length() {
        let mut state = ScHsmState::new();
        state.pin_verified = true;

        let full_key_id = KeyId::sc_hsm(0, 0x01).0;
        // Store only 32 bytes (wrong — BIP32 master must be 64 bytes)
        let mut private_key: heapless::Vec<u8, 66> = heapless::Vec::new();
        for i in 0..32u8 {
            private_key.push(i).unwrap();
        }
        let key = InMemoryKey {
            key_id: full_key_id,
            key_type: CoreKeyType::Bip32Master,
            algo: 0x00,
            key_flags: 0,
            private_key,
            public_key: heapless::Vec::new(),
        };
        state.keys.push(key).unwrap();

        let raw = bip_apdu(0x01, &[]);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_WRONG_DATA);
    }

    // -----------------------------------------------------------------------
    // Success path tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_bip_slip_empty_path() {
        // Empty path: should return the master key material unchanged (64 bytes)
        let mut state = make_state_tv1(0x01);
        let raw = bip_apdu(0x01, &[]);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_OK);
        assert_eq!(resp.data.len(), 64, "response must be 64 bytes (key || chain_code)");

        // Verify the bytes match the original master
        let (k, c) = slip10_tv1_master();
        assert_eq!(&resp.data[..32], &k, "first 32 bytes must be master key");
        assert_eq!(&resp.data[32..], &c, "last 32 bytes must be master chain code");
    }

    #[test]
    fn test_bip_slip_hardened_child() {
        // SLIP-0010 test vector 1: m/0'
        // Expected child_key   = edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
        // Expected child_chain = 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
        let mut state = make_state_tv1(0x01);

        let path_bytes = encode_path(&[0x8000_0000u32]);
        let raw = bip_apdu(0x01, &path_bytes);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);

        assert_eq!(resp.sw, SW_OK, "expected SW_OK");
        assert_eq!(resp.data.len(), 64);

        let expected_key = hex::decode(
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
        )
        .unwrap();
        let expected_chain = hex::decode(
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
        )
        .unwrap();

        assert_eq!(&resp.data[..32], expected_key.as_slice(), "child key mismatch");
        assert_eq!(&resp.data[32..], expected_chain.as_slice(), "child chain mismatch");
    }

    #[test]
    fn test_bip_slip_multi_hop() {
        // SLIP-0010 test vector 1: m/0'/1
        // Expected child_key   = 3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368
        // Expected child_chain = 2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19
        let mut state = make_state_tv1(0x01);

        let path_bytes = encode_path(&[0x8000_0000u32, 1u32]);
        let raw = bip_apdu(0x01, &path_bytes);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);

        assert_eq!(resp.sw, SW_OK, "expected SW_OK");
        assert_eq!(resp.data.len(), 64);

        let expected_key = hex::decode(
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
        )
        .unwrap();
        let expected_chain = hex::decode(
            "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
        )
        .unwrap();

        assert_eq!(&resp.data[..32], expected_key.as_slice(), "child key mismatch (m/0'/1)");
        assert_eq!(&resp.data[32..], expected_chain.as_slice(), "child chain mismatch (m/0'/1)");
    }
}
