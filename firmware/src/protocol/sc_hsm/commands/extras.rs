//! EXTRAS command handler (INS = 0x54).
//!
//! Additional cryptographic primitives dispatched by P1 sub-command:
//! - P1=0x01: HKDF-Extract
//! - P1=0x02: HKDF-Expand
//! - P1=0x03: PBKDF2-SHA256
//! - P1=0x04: X9.63-KDF
//! - P1=0x05: AES-CMAC
//! - P1=0x06: HMAC-SHA256
//! - P1=0x30: GET_DEVICE_PUBLIC_KEY
//! - P1=0x31: NOISE_INITIATE
//! - P1=0x32: NOISE_FINALIZE_SEND
//! - P1=0x33: NOISE_FINALIZE_RECV
//! - P1=0x34: GET_GENERATION

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_SECURITY_STATUS, SW_WRONG_DATA,
    SW_WRONG_LENGTH,
};
use pico2hsm_core::key::KeyId;

use crate::protocol::sc_hsm::{FwRng, ScHsmState};
use crate::storage::KeyStore;

/// INS byte for EXTRAS.
pub const INS_EXTRAS: u8 = 0x54;

/// Handle an EXTRAS APDU command.
pub fn handle(state: &mut ScHsmState, store: &mut dyn KeyStore, cmd: &ApduCommand<'_>) -> ApduResponse {
    match cmd.p1 {
        // P1=0x30..0x34: DKEK exchange sub-commands (some don't require PIN).
        0x30 => handle_get_device_public_key(state, store, cmd),
        0x34 => handle_get_generation(state, cmd),

        // All remaining sub-commands require PIN authentication.
        _ => {
            if !state.pin_verified {
                return ApduResponse::err(SW_SECURITY_STATUS);
            }
            match cmd.p1 {
                0x01 => hkdf_extract(cmd.data),
                0x02 => hkdf_expand(cmd.data),
                0x03 => pbkdf2(cmd.data),
                0x04 => x963_kdf(cmd.data),
                0x05 => aes_cmac(cmd.data),
                0x06 => hmac_sha256(cmd.data),
                0x31 => handle_noise_initiate(state, cmd),
                0x32 => handle_noise_finalize_send(state, cmd),
                0x33 => handle_noise_finalize_recv(state, cmd),
                _ => ApduResponse::err(SW_WRONG_DATA),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// P1=0x30  GET_DEVICE_PUBLIC_KEY
// ---------------------------------------------------------------------------

fn handle_get_device_public_key(state: &mut ScHsmState, store: &mut dyn KeyStore, _cmd: &ApduCommand<'_>) -> ApduResponse {
    let dev_key_id = KeyId::sc_hsm(0, 0xFE);

    // Try in-memory key store first.
    if let Some(key) = state.keys.iter().find(|k| k.key_id == dev_key_id.0) {
        if !key.public_key.is_empty() {
            return ApduResponse::ok(&key.public_key);
        }
    }

    // Try EF 0x2F02 (public key stored during INITIALIZE).
    if let Some(ef) = state.ef_files.iter().find(|ef| ef.file_id == 0x2F02) {
        if !ef.data.is_empty() {
            return ApduResponse::ok(&ef.data);
        }
    }

    // Try persistent store.
    if let Ok(Some(key_obj)) = store.fetch_key(dev_key_id) {
        if !key_obj.public_key.is_empty() {
            return ApduResponse::ok(&key_obj.public_key);
        }
    }

    // Device not initialized or no identity key.
    ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED)
}

// ---------------------------------------------------------------------------
// P1=0x31  NOISE_INITIATE
// ---------------------------------------------------------------------------

fn handle_noise_initiate(state: &mut ScHsmState, _cmd: &ApduCommand<'_>) -> ApduResponse {
    use crate::crypto::asymmetric::generate_ec_keypair;
    use pico2hsm_core::key::KeyType as CoreKeyType;
    use zeroize::Zeroizing;

    let mut rng = FwRng;
    let pair = match generate_ec_keypair(CoreKeyType::EcPrivateP256, &mut rng) {
        Ok(p) => p,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Store ephemeral private key.
    let mut priv_bytes = Zeroizing::new([0u8; 32]);
    if pair.private_key.len() != 32 {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }
    priv_bytes.copy_from_slice(&pair.private_key);
    state.exchange_ephem_priv = Some(priv_bytes);

    // Store ephemeral public key.
    if pair.public_key.len() != 65 {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }
    let mut pub_bytes = [0u8; 65];
    pub_bytes.copy_from_slice(&pair.public_key);
    state.exchange_ephem_pub = Some(pub_bytes);

    // Return our ephemeral public key (65 bytes).
    ApduResponse::ok(&pub_bytes)
}

// ---------------------------------------------------------------------------
// P1=0x32  NOISE_FINALIZE_SEND
// ---------------------------------------------------------------------------

fn handle_noise_finalize_send(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require DKEK ready.
    if !state.dkek.is_ready() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Require ephemeral private key from a prior NOISE_INITIATE.
    let ephem_priv = match &state.exchange_ephem_priv {
        Some(p) => **p, // copy the 32-byte array
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // cmd.data = peer's ephemeral public key (65 bytes).
    if cmd.data.len() != 65 {
        return ApduResponse::err(SW_WRONG_DATA);
    }
    let peer_ephem_pub: &[u8; 65] = cmd.data.try_into().unwrap_or_else(|_| unreachable!());

    let mut rng = FwRng;
    let result = state.dkek.noise_send_dkek_data(peer_ephem_pub, &ephem_priv, &mut rng);

    // Clear ephemeral state regardless of outcome.
    state.exchange_ephem_priv = None;
    state.exchange_ephem_pub = None;

    match result {
        Ok(encrypted_blob) => ApduResponse::ok(&encrypted_blob),
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}

// ---------------------------------------------------------------------------
// P1=0x33  NOISE_FINALIZE_RECV
// ---------------------------------------------------------------------------

fn handle_noise_finalize_recv(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Require ephemeral private key from a prior NOISE_INITIATE.
    let ephem_priv = match &state.exchange_ephem_priv {
        Some(p) => **p, // copy the 32-byte array
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // cmd.data = initiator_ephem_pub(65) || encrypted_dkek(60) || initiator_device_id(16) = 141 bytes.
    if cmd.data.len() != 141 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    let initiator_ephem_pub: &[u8; 65] = cmd.data[..65].try_into().unwrap();
    let encrypted_dkek: &[u8; 60] = cmd.data[65..125].try_into().unwrap();
    let initiator_device_id: &[u8; 16] = cmd.data[125..141].try_into().unwrap();

    let result = state.dkek.noise_recv_dkek_data(
        initiator_ephem_pub,
        &ephem_priv,
        encrypted_dkek,
        initiator_device_id,
    );

    // Clear ephemeral state regardless of outcome.
    state.exchange_ephem_priv = None;
    state.exchange_ephem_pub = None;

    match result {
        Ok(()) => {
            state.dkek_shares_imported = state.dkek.shares_total();
            ApduResponse::ok(&[])
        }
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}

// ---------------------------------------------------------------------------
// P1=0x34  GET_GENERATION
// ---------------------------------------------------------------------------

fn handle_get_generation(_state: &mut ScHsmState, _cmd: &ApduCommand<'_>) -> ApduResponse {
    // TODO: Return the max generation counter across all stored keys.
    // For now, return placeholder zeros.
    ApduResponse::ok(&[0u8; 4])
}

// ---------------------------------------------------------------------------
// P1=0x01  HKDF-Extract
// ---------------------------------------------------------------------------
// data[0]           = salt_len (0 = no salt)
// data[1..1+sl]     = salt bytes
// data[1+sl..]      = IKM bytes
// Response: 32-byte PRK

fn hkdf_extract(data: &[u8]) -> ApduResponse {
    if data.is_empty() {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let salt_len = data[0] as usize;
    if data.len() < 1 + salt_len {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let salt = &data[1..1 + salt_len];
    let ikm = &data[1 + salt_len..];

    let prk = crate::crypto::kdf::hkdf_extract(salt, ikm);
    ApduResponse::ok(&prk)
}

// ---------------------------------------------------------------------------
// P1=0x02  HKDF-Expand
// ---------------------------------------------------------------------------
// data[0..32]  = PRK (32 bytes)
// data[32]     = output_length (1–255)
// data[33..]   = info bytes (may be empty)
// Response: output_length bytes of OKM

fn hkdf_expand(data: &[u8]) -> ApduResponse {
    if data.len() < 33 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let prk_arr: [u8; 32] = match data[..32].try_into() {
        Ok(a) => a,
        Err(_) => return ApduResponse::err(SW_WRONG_LENGTH),
    };
    let output_length = data[32] as usize;
    if output_length == 0 || output_length > 255 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let info = &data[33..];

    let mut out: heapless::Vec<u8, 256> = heapless::Vec::new();
    match crate::crypto::kdf::hkdf_expand(&prk_arr, info, output_length, &mut out) {
        Ok(()) => {}
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }

    ApduResponse::ok(&out[..output_length])
}

// ---------------------------------------------------------------------------
// P1=0x03  PBKDF2-SHA256
// ---------------------------------------------------------------------------
// data[0]                          = password_len
// data[1..1+pw_len]                = password
// data[1+pw_len]                   = salt_len
// data[2+pw_len..2+pw_len+sl]      = salt
// data[2+pw_len+sl..6+pw_len+sl]   = iterations (4-byte big-endian)
// data[6+pw_len+sl]                = dklen (1–64)
// Response: dklen derived key bytes

fn pbkdf2(data: &[u8]) -> ApduResponse {
    if data.is_empty() {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let pw_len = data[0] as usize;
    let needed = 1 + pw_len + 1;
    if data.len() < needed {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let password = &data[1..1 + pw_len];
    let salt_len = data[1 + pw_len] as usize;
    let needed = 2 + pw_len + salt_len + 4 + 1;
    if data.len() < needed {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let salt = &data[2 + pw_len..2 + pw_len + salt_len];
    let iter_start = 2 + pw_len + salt_len;
    let iterations = u32::from_be_bytes([
        data[iter_start],
        data[iter_start + 1],
        data[iter_start + 2],
        data[iter_start + 3],
    ]);
    let dklen = data[iter_start + 4] as usize;
    if dklen == 0 || dklen > 64 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }

    let mut buf = [0u8; 64];
    match crate::crypto::kdf::pbkdf2_hmac_sha256(password, salt, iterations, &mut buf[..dklen]) {
        Ok(()) => {}
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }

    ApduResponse::ok(&buf[..dklen])
}

// ---------------------------------------------------------------------------
// P1=0x04  X9.63-KDF
// ---------------------------------------------------------------------------
// data[0]              = Z_len
// data[1..1+Z_len]     = Z (shared secret)
// data[1+Z_len]        = key_len (1–64)
// data[2+Z_len..]      = SharedInfo (may be empty)
// Response: key_len derived key bytes

fn x963_kdf(data: &[u8]) -> ApduResponse {
    if data.is_empty() {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let z_len = data[0] as usize;
    if data.len() < 1 + z_len + 1 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let z = &data[1..1 + z_len];
    let key_len = data[1 + z_len] as usize;
    if key_len == 0 || key_len > 64 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let shared_info = &data[2 + z_len..];

    let mut out: heapless::Vec<u8, 64> = heapless::Vec::new();
    match crate::crypto::kdf::x963_kdf(z, shared_info, key_len, &mut out) {
        Ok(()) => {}
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }

    ApduResponse::ok(&out)
}

// ---------------------------------------------------------------------------
// P1=0x05  AES-CMAC
// ---------------------------------------------------------------------------
// data[0]               = key_len (16, 24, or 32)
// data[1..1+key_len]    = AES key bytes
// data[1+key_len..]     = message
// Response: 16-byte CMAC tag

fn aes_cmac(data: &[u8]) -> ApduResponse {
    use pico2hsm_core::key::{KeyId as CoreKeyId, KeyMaterial, KeyType};

    if data.is_empty() {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let key_len = data[0] as usize;
    if data.len() < 1 + key_len {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let key_bytes = &data[1..1 + key_len];
    let message = &data[1 + key_len..];

    let key_type = match key_len {
        16 => KeyType::Aes128,
        24 => KeyType::Aes192,
        32 => KeyType::Aes256,
        _ => return ApduResponse::err(SW_WRONG_DATA),
    };

    let mut raw: heapless::Vec<u8, { pico2hsm_core::key::MAX_KEY_BYTES }> = heapless::Vec::new();
    if raw.extend_from_slice(key_bytes).is_err() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }
    let km = KeyMaterial {
        key_type,
        key_id: CoreKeyId(0x0100),
        raw,
    };

    match crate::crypto::symmetric::aes_cmac(&km, message) {
        Ok(tag) => ApduResponse::ok(&tag),
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}

// ---------------------------------------------------------------------------
// P1=0x06  HMAC-SHA256
// ---------------------------------------------------------------------------
// data[0]               = key_len
// data[1..1+key_len]    = HMAC key
// data[1+key_len..]     = message
// Response: 32-byte HMAC tag

fn hmac_sha256(data: &[u8]) -> ApduResponse {
    if data.is_empty() {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let key_len = data[0] as usize;
    if data.len() < 1 + key_len {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let key = &data[1..1 + key_len];
    let message = &data[1 + key_len..];

    let tag = crate::crypto::kdf::hmac_sha256(key, message);
    ApduResponse::ok(&tag)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build an APDU-style data buffer from parts
    fn make_data(parts: &[&[u8]]) -> heapless::Vec<u8, 512> {
        let mut v: heapless::Vec<u8, 512> = heapless::Vec::new();
        for p in parts {
            v.extend_from_slice(p).unwrap();
        }
        v
    }

    // -----------------------------------------------------------------------
    // HKDF-Extract — RFC 5869 Test Case A.1
    // salt = 0x000102...0x0c (13 bytes)
    // IKM  = 0x0b0b...0b (22 bytes)
    // Expected PRK = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
    // -----------------------------------------------------------------------
    #[test]
    fn test_hkdf_extract_rfc5869_a1() {
        let salt: [u8; 13] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let ikm: [u8; 22] = [0x0b; 22];

        let data = make_data(&[&[salt.len() as u8], &salt, &ikm]);
        let resp = hkdf_extract(&data);

        let expected = hex_to_32(
            b"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        );
        assert_eq!(resp.sw, 0x9000, "expected SW_OK");
        assert_eq!(&resp.data[..], &expected[..]);
    }

    // -----------------------------------------------------------------------
    // HKDF-Expand — use A.1 PRK, expand 42 bytes, verify non-zero
    // -----------------------------------------------------------------------
    #[test]
    fn test_hkdf_expand_produces_output() {
        // PRK from A.1
        let prk = hex_to_32(
            b"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        );
        let info: &[u8] = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let output_len: u8 = 42;

        let data = make_data(&[&prk, &[output_len], info]);
        let resp = hkdf_expand(&data);

        assert_eq!(resp.sw, 0x9000, "expected SW_OK");
        assert_eq!(resp.data.len(), 42);
        assert!(resp.data.iter().any(|&b| b != 0), "output should be non-zero");
    }

    // -----------------------------------------------------------------------
    // PBKDF2-SHA256 — known inputs, check length
    // -----------------------------------------------------------------------
    #[test]
    fn test_pbkdf2_correct_length() {
        let password = b"password";
        let salt = b"salt";
        let iterations: u32 = 1;
        let dklen: u8 = 32;

        let mut data: heapless::Vec<u8, 64> = heapless::Vec::new();
        data.push(password.len() as u8).unwrap();
        data.extend_from_slice(password).unwrap();
        data.push(salt.len() as u8).unwrap();
        data.extend_from_slice(salt).unwrap();
        data.extend_from_slice(&iterations.to_be_bytes()).unwrap();
        data.push(dklen).unwrap();

        let resp = pbkdf2(&data);
        assert_eq!(resp.sw, 0x9000, "expected SW_OK");
        assert_eq!(resp.data.len(), 32);
    }

    // -----------------------------------------------------------------------
    // X9.63-KDF — check output length
    // -----------------------------------------------------------------------
    #[test]
    fn test_x963_kdf_correct_length() {
        let z: [u8; 32] = [0xca; 32];
        let key_len: u8 = 32;
        let shared_info: &[u8] = b"test";

        let data = make_data(&[&[z.len() as u8], &z, &[key_len], shared_info]);
        let resp = x963_kdf(&data);

        assert_eq!(resp.sw, 0x9000, "expected SW_OK");
        assert_eq!(resp.data.len(), 32);
    }

    // -----------------------------------------------------------------------
    // AES-CMAC — key [0x01;16] + message [0x00;16] → 16-byte tag
    // -----------------------------------------------------------------------
    #[test]
    fn test_aes_cmac_returns_16_bytes() {
        let key = [0x01u8; 16];
        let message = [0x00u8; 16];

        let data = make_data(&[&[key.len() as u8], &key, &message]);
        let resp = aes_cmac(&data);

        assert_eq!(resp.sw, 0x9000, "expected SW_OK");
        assert_eq!(resp.data.len(), 16);
    }

    // -----------------------------------------------------------------------
    // HMAC-SHA256 — RFC 2202 test vector 1
    // key = 0x0b×20, message = "Hi There"
    // expected = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    // -----------------------------------------------------------------------
    #[test]
    fn test_hmac_sha256_rfc2202_vector1() {
        let key = [0x0bu8; 20];
        let message = b"Hi There";

        let data = make_data(&[&[key.len() as u8], &key, message]);
        let resp = hmac_sha256(&data);

        let expected = hex_to_32(
            b"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        );
        assert_eq!(resp.sw, 0x9000, "expected SW_OK");
        assert_eq!(&resp.data[..], &expected[..]);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Decode a 64-hex-char lowercase string into a [u8; 32].
    fn hex_to_32(hex: &[u8]) -> [u8; 32] {
        assert_eq!(hex.len(), 64);
        let mut out = [0u8; 32];
        for i in 0..32 {
            let hi = nibble(hex[2 * i]);
            let lo = nibble(hex[2 * i + 1]);
            out[i] = (hi << 4) | lo;
        }
        out
    }

    fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid hex nibble"),
        }
    }
}
