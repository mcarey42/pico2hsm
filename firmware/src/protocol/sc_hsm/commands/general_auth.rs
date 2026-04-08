//! GENERAL AUTHENTICATE command handler (INS = 0x86).
//!
//! Implements the single-step challenge-response path using a Dynamic
//! Authentication Template (DAT, tag 0x7C):
//!
//! - Command: `7C [len] 81 [len] [challenge_bytes]`
//! - Response: `7C [len] 82 [len] [signature_bytes]`
//!
//! The key and algorithm must be pre-selected by a preceding MSE SET command
//! (stored in `state.current_key_id` and `state.current_algo`). The challenge
//! is hashed with SHA-256 before signing.

use sha2::Digest as _;

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND,
    SW_SECURITY_STATUS, SW_WRONG_DATA,
};

use crate::protocol::sc_hsm::{FwRng, ScHsmState};

/// INS byte for GENERAL AUTHENTICATE.
pub const INS_GENERAL_AUTH: u8 = 0x86;

/// Scan a flat TLV list and return the value slice for the first matching tag.
///
/// Uses simple one-byte tag / one-byte length encoding (BER-TLV subset).
fn find_tlv<'a>(data: &'a [u8], tag: u8) -> Option<&'a [u8]> {
    let mut i = 0;
    while i + 1 < data.len() {
        let t = data[i];
        i += 1;
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() {
            return None;
        }
        if t == tag {
            return Some(&data[i..i + len]);
        }
        i += len;
    }
    None
}

/// Encode a two-level TLV: `outer [inner_content_len] inner [value_len] value`.
///
/// Returns `None` if the output buffer is too small.
fn encode_tlv(
    outer: u8,
    inner: u8,
    value: &[u8],
    out: &mut heapless::Vec<u8, 512>,
) -> Option<()> {
    out.push(outer).ok()?;
    out.push((value.len() + 2) as u8).ok()?;
    out.push(inner).ok()?;
    out.push(value.len() as u8).ok()?;
    out.extend_from_slice(value).ok()?;
    Some(())
}

/// Handle a GENERAL AUTHENTICATE APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require PIN authentication.
    if !state.pin_verified && !state.so_pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // Parse outer 0x7C (Dynamic Authentication Template) tag.
    let dat = match find_tlv(cmd.data, 0x7C) {
        Some(v) => v,
        None => return ApduResponse::err(SW_WRONG_DATA),
    };

    // Parse inner 0x81 (challenge from host) tag.
    let challenge = match find_tlv(dat, 0x81) {
        Some(v) => v,
        None => return ApduResponse::err(SW_WRONG_DATA),
    };

    // Require an MSE-selected key.
    let key_id_proto = match state.current_key_id {
        Some(k) => k,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Look up the EC key in the in-memory store.
    let full_key_id = pico2hsm_core::key::KeyId::sc_hsm(0, key_id_proto).0;
    let key = match state.keys.iter().find(|k| k.key_id == full_key_id) {
        Some(k) => k,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // Copy key data to local stack buffers to release the borrow on `state`.
    let key_type = key.key_type;
    let priv_len = key.private_key.len();
    let mut priv_buf = [0u8; 66];
    priv_buf[..priv_len].copy_from_slice(&key.private_key);

    // Hash the challenge with SHA-256 before signing.
    let hash = sha2::Sha256::digest(challenge);

    // ECDSA-sign the hash.
    let sig = match crate::crypto::asymmetric::ecdsa_sign(
        key_type,
        &priv_buf[..priv_len],
        &hash,
        &mut FwRng,
    ) {
        Ok(s) => s,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Build the response: 7C [len] 82 [sig_len] [sig_bytes].
    let mut resp_buf: heapless::Vec<u8, 512> = heapless::Vec::new();
    if encode_tlv(0x7C, 0x82, &sig, &mut resp_buf).is_none() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    ApduResponse::ok(&resp_buf)
}

// ---------------------------------------------------------------------------
// Host-side unit tests (cargo test --target x86_64-unknown-linux-gnu)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pico2hsm_core::{
        apdu::{SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND, SW_OK, SW_SECURITY_STATUS, SW_WRONG_DATA},
        key::KeyType,
    };
    use rand_core::RngCore;

    use crate::crypto::asymmetric::generate_ec_keypair;
    use crate::protocol::sc_hsm::{InMemoryKey, ScHsmState};

    /// Simple counter-hash PRNG adequate for tests (no hardware TRNG needed).
    struct CounterRng(u64);

    impl RngCore for CounterRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15u64);
                let v = self
                    .0
                    .wrapping_mul(0x6c62272e07bb0142u64)
                    ^ 0xbf58476d1ce4e5b9u64;
                chunk.copy_from_slice(&v.to_le_bytes()[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl rand_core::CryptoRng for CounterRng {}

    /// Build an APDU byte buffer for GENERAL AUTHENTICATE with the given data payload.
    fn make_apdu(data: &[u8]) -> heapless::Vec<u8, 512> {
        let mut buf: heapless::Vec<u8, 512> = heapless::Vec::new();
        let _ = buf.push(0x00);
        let _ = buf.push(INS_GENERAL_AUTH);
        let _ = buf.push(0x00);
        let _ = buf.push(0x00);
        let _ = buf.push(data.len() as u8);
        let _ = buf.extend_from_slice(data);
        buf
    }

    /// Build a well-formed 7C(81(challenge)) payload.
    fn make_7c_challenge(challenge: &[u8]) -> heapless::Vec<u8, 128> {
        let mut inner: heapless::Vec<u8, 128> = heapless::Vec::new();
        let _ = inner.push(0x81);
        let _ = inner.push(challenge.len() as u8);
        let _ = inner.extend_from_slice(challenge);

        let mut outer: heapless::Vec<u8, 128> = heapless::Vec::new();
        let _ = outer.push(0x7C);
        let _ = outer.push(inner.len() as u8);
        let _ = outer.extend_from_slice(&inner);
        outer
    }

    #[test]
    fn test_general_auth_requires_auth() {
        // No pin_verified and no so_pin_verified → SW_SECURITY_STATUS.
        let mut state = ScHsmState::new();
        let dat = make_7c_challenge(&[0xAA; 16]);
        let raw = make_apdu(&dat);
        let cmd = ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_SECURITY_STATUS);
    }

    #[test]
    fn test_general_auth_no_7c_tag() {
        // Data that does not contain a 0x7C outer tag → SW_WRONG_DATA.
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        // Send garbage data with no 0x7C tag.
        let garbage = [0xDE, 0x04, 0xBE, 0xEF, 0xCA, 0xFE];
        let raw = make_apdu(&garbage);
        let cmd = ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_WRONG_DATA);
    }

    #[test]
    fn test_general_auth_no_81_tag() {
        // 7C tag present but inner 0x81 tag is missing → SW_WRONG_DATA.
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        // 7C wrapping tag 0x82 (wrong inner tag).
        let inner = [0x82u8, 0x04, 0x01, 0x02, 0x03, 0x04];
        let mut dat: heapless::Vec<u8, 64> = heapless::Vec::new();
        let _ = dat.push(0x7C);
        let _ = dat.push(inner.len() as u8);
        let _ = dat.extend_from_slice(&inner);
        let raw = make_apdu(&dat);
        let cmd = ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_WRONG_DATA);
    }

    #[test]
    fn test_general_auth_no_mse_key() {
        // Valid 7C(81(challenge)) but no MSE-selected key → SW_CONDITIONS_NOT_SATISFIED.
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        // current_key_id is None by default.
        let dat = make_7c_challenge(&[0xBB; 32]);
        let raw = make_apdu(&dat);
        let cmd = ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn test_general_auth_key_not_found() {
        // current_key_id set but no matching key in state.keys → SW_FILE_NOT_FOUND.
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        state.current_key_id = Some(0x01);
        // No keys added.
        let dat = make_7c_challenge(&[0xCC; 32]);
        let raw = make_apdu(&dat);
        let cmd = ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);
        assert_eq!(resp.sw, SW_FILE_NOT_FOUND);
    }

    #[test]
    fn test_general_auth_success() {
        // Full happy-path: P-256 key in state, valid 7C(81) challenge → SW_OK,
        // response starts with 0x7C.
        let mut rng = CounterRng(42);
        let kp = generate_ec_keypair(KeyType::EcPrivateP256, &mut rng)
            .expect("P-256 keygen");

        let mut state = ScHsmState::new();
        state.pin_verified = true;
        state.current_key_id = Some(0x01);
        state.current_algo = Some(0x13); // ECDSA-P256

        let key = InMemoryKey {
            key_id: pico2hsm_core::key::KeyId::sc_hsm(0, 0x01).0,
            key_type: KeyType::EcPrivateP256,
            algo: 0x13,
            key_flags: 0,
            private_key: kp.private_key.clone(),
            public_key: kp.public_key.clone(),
        };
        assert!(state.keys.push(key).is_ok());

        let challenge = [0x42u8; 32];
        let dat = make_7c_challenge(&challenge);
        let raw = make_apdu(&dat);
        let cmd = ApduCommand::parse(&raw).unwrap();
        let resp = handle(&mut state, &cmd);

        assert_eq!(resp.sw, SW_OK);
        assert!(!resp.data.is_empty());
        // Response must be wrapped in 0x7C DAT.
        assert_eq!(resp.data[0], 0x7C);
        // Inner tag must be 0x82.
        assert!(resp.data.len() >= 4);
        assert_eq!(resp.data[2], 0x82);
    }
}
