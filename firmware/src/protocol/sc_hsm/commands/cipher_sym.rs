//! SYMMETRIC CIPHER command handler (INS = 0x78).
//!
//! Performs symmetric encrypt or decrypt using an AES key stored in the
//! keystore. The operation and mode are specified via P1/P2.
//!
//! Supported modes:
//! - AES-CBC (P2=0x02): `[IV:16][plaintext or ciphertext]`
//! - AES-CTR (P2=0x03): `[nonce:16][data]`  (AES-256 only)
//! - AES-GCM (P2=0x05): encrypt `[nonce:12][aad_len:2 BE][aad][plaintext]`
//!                       decrypt `[nonce:12][aad_len:2 BE][aad][ct||tag]`
//! - AES-CMAC (P2=0x06): `[message]`, P1 ignored; response is 16-byte tag

use pico2hsm_core::{
    apdu::{
        ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_FILE_NOT_FOUND,
        SW_INS_NOT_SUPPORTED, SW_OK, SW_SECURITY_STATUS, SW_WRONG_DATA, SW_WRONG_LENGTH,
    },
    key::{KeyId, KeyMaterial, KeyType},
};

use crate::crypto::symmetric;
use crate::protocol::sc_hsm::ScHsmState;
use crate::storage::KeyStore;

/// INS byte for SYMMETRIC CIPHER.
pub const INS_CIPHER_SYM: u8 = 0x78;

/// P1: encrypt
const P1_ENCRYPT: u8 = 0x01;
/// P1: decrypt
const P1_DECRYPT: u8 = 0x02;

/// P2: AES-CBC
const P2_AES_CBC: u8 = 0x02;
/// P2: AES-CTR
const P2_AES_CTR: u8 = 0x03;
/// P2: AES-GCM
const P2_AES_GCM: u8 = 0x05;
/// P2: AES-CMAC
const P2_AES_CMAC: u8 = 0x06;

/// Build a `KeyMaterial` from the raw bytes in an `InMemorySymKey`.
///
/// Infers AES-128/192/256 from key length.
fn make_key_material(key_id: u32, raw: &[u8]) -> Option<KeyMaterial> {
    let key_type = match raw.len() {
        16 => KeyType::Aes128,
        24 => KeyType::Aes192,
        32 => KeyType::Aes256,
        _ => return None,
    };
    let mut km_raw: heapless::Vec<u8, { pico2hsm_core::key::MAX_KEY_BYTES }> = heapless::Vec::new();
    km_raw.extend_from_slice(raw).ok()?;
    Some(KeyMaterial {
        key_type,
        key_id: KeyId(key_id),
        raw: km_raw,
    })
}

/// Handle a SYMMETRIC CIPHER APDU command.
///
/// P1 = direction (0x01 = encrypt, 0x02 = decrypt)
/// P2 = mode (0x02=CBC, 0x03=CTR, 0x05=GCM, 0x06=CMAC)
pub fn handle(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    // Require PIN authentication
    if !state.pin_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    // Require MSE SET key selection
    let key_id_proto = match state.current_key_id {
        Some(k) => k,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };
    let full_key_id = KeyId::sc_hsm(0, key_id_proto).0; // u32 internal ID

    if cmd.data.is_empty() {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Check metadata index for the key
    let _meta = match state.key_index.iter().find(|m| m.key_id == full_key_id) {
        Some(m) => *m,
        None => return ApduResponse::err(SW_FILE_NOT_FOUND),
    };

    // Load key material from flash
    let key_obj = match store.fetch_key(KeyId(full_key_id)) {
        Ok(Some(obj)) => obj,
        _ => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Wiped on drop; a key that doesn't fit is refused, not truncated.
    let mut raw_key = crate::security::zeroize::WipeOnDrop::<32>::new();
    if raw_key.0.extend_from_slice(&key_obj.private_key).is_err() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    let km = match make_key_material(full_key_id, &raw_key.0) {
        Some(k) => k,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    let mode = cmd.p2;
    let direction = cmd.p1;
    let data = cmd.data;

    match mode {
        P2_AES_CBC => handle_cbc(&km, direction, data),
        P2_AES_CTR => handle_ctr(&raw_key, data),
        P2_AES_GCM => handle_gcm(&km, direction, data),
        P2_AES_CMAC => handle_cmac(&km, data),
        _ => ApduResponse::err(SW_INS_NOT_SUPPORTED),
    }
}

// ---------------------------------------------------------------------------
// AES-CBC
// ---------------------------------------------------------------------------

fn handle_cbc(km: &KeyMaterial, direction: u8, data: &[u8]) -> ApduResponse {
    // Wire format: [IV: 16 bytes][plaintext or ciphertext]
    if data.len() < symmetric::AES_BLOCK_SIZE {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let iv: &[u8; 16] = match data[..16].try_into() {
        Ok(v) => v,
        Err(_) => return ApduResponse::err(SW_WRONG_DATA),
    };
    let payload = &data[16..];

    let mut out: heapless::Vec<u8, 4096> = heapless::Vec::new();

    match direction {
        P1_ENCRYPT => {
            if symmetric::aes_cbc_encrypt(km, iv, payload, &mut out).is_err() {
                return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        P1_DECRYPT => {
            if symmetric::aes_cbc_decrypt(km, iv, payload, &mut out).is_err() {
                return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
            }
        }
        _ => return ApduResponse::err(SW_INS_NOT_SUPPORTED),
    }

    ApduResponse::ok(&out)
}

// ---------------------------------------------------------------------------
// AES-CTR (AES-256 only)
// ---------------------------------------------------------------------------

fn handle_ctr(raw_key: &[u8], data: &[u8]) -> ApduResponse {
    // Wire format: [nonce: 16 bytes][data]
    // CTR is symmetric — same operation for encrypt and decrypt.
    if data.len() < symmetric::AES_BLOCK_SIZE {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }

    // AES-CTR is only supported with AES-256 (32-byte key) due to the
    // crypto function signature requiring `&[u8; 32]`.
    if raw_key.len() != symmetric::AES256_KEY_SIZE {
        return ApduResponse::err(SW_INS_NOT_SUPPORTED);
    }
    let key_arr: &[u8; 32] = match raw_key.try_into() {
        Ok(k) => k,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };
    let nonce: &[u8; 16] = match data[..16].try_into() {
        Ok(v) => v,
        Err(_) => return ApduResponse::err(SW_WRONG_DATA),
    };

    // Copy payload into a mutable buffer on the stack; 4080 bytes max
    // (MAX_CIPHER_BLOCK(4096) - nonce(16)).
    let payload = &data[16..];
    if payload.len() > 4080 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let mut buf = [0u8; 4080];
    buf[..payload.len()].copy_from_slice(payload);
    let work = &mut buf[..payload.len()];

    if symmetric::aes_ctr_crypt(key_arr, nonce, work).is_err() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    ApduResponse::ok(work)
}

// ---------------------------------------------------------------------------
// AES-GCM
// ---------------------------------------------------------------------------

fn handle_gcm(km: &KeyMaterial, direction: u8, data: &[u8]) -> ApduResponse {
    // Wire format:
    //   [nonce: 12 bytes][aad_len: 2 BE bytes][aad: aad_len bytes][payload]
    const NONCE_LEN: usize = symmetric::AES_GCM_NONCE_SIZE; // 12
    const AAD_LEN_FIELD: usize = 2;
    let min_hdr = NONCE_LEN + AAD_LEN_FIELD;

    if data.len() < min_hdr {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }

    let nonce: &[u8; 12] = match data[..NONCE_LEN].try_into() {
        Ok(v) => v,
        Err(_) => return ApduResponse::err(SW_WRONG_DATA),
    };
    let aad_len = u16::from_be_bytes([data[NONCE_LEN], data[NONCE_LEN + 1]]) as usize;
    let hdr_end = min_hdr + aad_len;
    if data.len() < hdr_end {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let aad = &data[min_hdr..hdr_end];
    let payload = &data[hdr_end..];

    match direction {
        P1_ENCRYPT => {
            let mut out: heapless::Vec<u8, 4112> = heapless::Vec::new();
            if symmetric::aes_gcm_encrypt(km, nonce, aad, payload, &mut out).is_err() {
                return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
            }
            ApduResponse::ok(&out)
        }
        P1_DECRYPT => {
            // For decrypt, payload is ciphertext || tag (at least 16 tag bytes)
            if payload.len() < symmetric::AES_GCM_TAG_SIZE {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            let mut out: heapless::Vec<u8, 4096> = heapless::Vec::new();
            if symmetric::aes_gcm_decrypt(km, nonce, aad, payload, &mut out).is_err() {
                return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
            }
            ApduResponse::ok(&out)
        }
        _ => ApduResponse::err(SW_INS_NOT_SUPPORTED),
    }
}

// ---------------------------------------------------------------------------
// AES-CMAC
// ---------------------------------------------------------------------------

fn handle_cmac(km: &KeyMaterial, data: &[u8]) -> ApduResponse {
    // Direction is ignored for CMAC; response is always the 16-byte tag.
    match symmetric::aes_cmac(km, data) {
        Ok(tag) => ApduResponse::ok(&tag),
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}

// ---------------------------------------------------------------------------
// Unit tests (host only, no hardware required)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sc_hsm::{KeyMeta, ScHsmState};
    use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};
    use pico2hsm_core::apdu::{ApduCommand, SW_OK};
    use pico2hsm_core::key::AppletId;

    /// Test key store that holds a single KeyObject and returns it on fetch_key.
    struct TestStore {
        obj: Option<KeyObject>,
    }

    impl TestStore {
        fn new(obj: KeyObject) -> Self {
            Self { obj: Some(obj) }
        }
    }

    impl crate::storage::KeyStore for TestStore {
        fn save_key(&mut self, _: &KeyObject) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn fetch_key(
            &mut self,
            key_id: KeyId,
        ) -> Result<Option<KeyObject>, pico2hsm_core::error::HsmError> {
            if let Some(ref obj) = self.obj {
                if obj.key_id == key_id.0 {
                    let mut clone =
                        KeyObject::new(obj.key_type, obj.key_id, obj.owner, obj.algorithm);
                    clone.key_flags = obj.key_flags;
                    let _ = clone.private_key.extend_from_slice(&obj.private_key);
                    let _ = clone.public_key.extend_from_slice(&obj.public_key);
                    return Ok(Some(clone));
                }
            }
            Ok(None)
        }
        fn erase_key(&mut self, _: KeyId) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn wipe_all(&mut self) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn wipe_by_owner(&mut self, _: AppletId) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn enumerate_keys(&self) -> heapless::Vec<KeyId, 64> {
            heapless::Vec::new()
        }
        fn for_each_key(&self, _f: &mut dyn FnMut(KeyId)) {}
    }

    /// Build a minimal ScHsmState + TestStore with a single AES-256 key at slot `key_id`.
    fn make_state_and_store(key_id: u8, key_bytes: &[u8]) -> (ScHsmState, TestStore) {
        let mut state = ScHsmState::new();
        state.pin_verified = true;
        state.current_key_id = Some(key_id);
        state.current_algo = None;

        let full_key_id = pico2hsm_core::key::KeyId::sc_hsm(0, key_id).0;

        let meta = KeyMeta {
            key_id: full_key_id,
            key_type: 0,
            algo: 0x61,
            key_flags: 0,
        };
        state.key_index.push(meta).unwrap();

        let mut key_obj = KeyObject::new(
            KmType::Aes,
            full_key_id,
            AppletId::ScHsm,
            AlgorithmId::AesCbc,
        );
        let _ = key_obj.private_key.extend_from_slice(key_bytes);

        (state, TestStore::new(key_obj))
    }

    fn parse_sw(resp: &[u8]) -> u16 {
        let len = resp.len();
        assert!(len >= 2, "response too short");
        u16::from_be_bytes([resp[len - 2], resp[len - 1]])
    }

    fn resp_data(resp: &[u8]) -> &[u8] {
        let len = resp.len();
        &resp[..len - 2]
    }

    // -----------------------------------------------------------------------
    // Helper: build a raw APDU and dispatch through handle()
    // -----------------------------------------------------------------------

    fn run_cmd(
        state: &mut ScHsmState,
        store: &mut dyn KeyStore,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> heapless::Vec<u8, 4200> {
        // Build: CLA=0x00 INS=0x78 P1 P2 Lc data
        let mut apdu: heapless::Vec<u8, 4200> = heapless::Vec::new();
        apdu.push(0x00).unwrap();
        apdu.push(INS_CIPHER_SYM).unwrap();
        apdu.push(p1).unwrap();
        apdu.push(p2).unwrap();
        apdu.push(data.len() as u8).unwrap();
        apdu.extend_from_slice(data).unwrap();
        apdu.push(0x00).unwrap(); // Le

        let cmd = ApduCommand::parse(&apdu).unwrap();
        let resp = handle(state, store, &cmd);
        let serialized = resp.serialize();
        let mut out: heapless::Vec<u8, 4200> = heapless::Vec::new();
        out.extend_from_slice(&serialized).unwrap();
        out
    }

    // -----------------------------------------------------------------------
    // AES-CBC round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_aes_cbc_roundtrip() {
        let key = [0x42u8; 32]; // AES-256
        let (mut state, mut store) = make_state_and_store(0x01, &key);

        let iv = [0xABu8; 16];
        let plaintext = b"Hello, World! AES-CBC test data!"; // 32 bytes, block-aligned

        // Build encrypt payload: IV || plaintext
        let mut enc_data: heapless::Vec<u8, 64> = heapless::Vec::new();
        enc_data.extend_from_slice(&iv).unwrap();
        enc_data.extend_from_slice(plaintext).unwrap();

        let enc_resp = run_cmd(&mut state, &mut store, P1_ENCRYPT, P2_AES_CBC, &enc_data);
        assert_eq!(parse_sw(&enc_resp), SW_OK, "CBC encrypt should succeed");
        let mut ciphertext: heapless::Vec<u8, 64> = heapless::Vec::new();
        ciphertext.extend_from_slice(resp_data(&enc_resp)).unwrap();

        // Now decrypt: IV || ciphertext
        let mut dec_data: heapless::Vec<u8, 64> = heapless::Vec::new();
        dec_data.extend_from_slice(&iv).unwrap();
        dec_data.extend_from_slice(&ciphertext).unwrap();

        let dec_resp = run_cmd(&mut state, &mut store, P1_DECRYPT, P2_AES_CBC, &dec_data);
        assert_eq!(parse_sw(&dec_resp), SW_OK, "CBC decrypt should succeed");
        let recovered = resp_data(&dec_resp);

        assert_eq!(
            recovered, plaintext,
            "AES-CBC round-trip should recover plaintext"
        );
    }

    // -----------------------------------------------------------------------
    // AES-GCM round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0x11u8; 32]; // AES-256
        let (mut state, mut store) = make_state_and_store(0x01, &key);

        let nonce = [0x01u8; 12];
        let aad = b"assoc data";
        let plaintext = b"secret message!!"; // 16 bytes

        // Encrypt: nonce(12) || aad_len_be(2) || aad || plaintext
        let mut enc_data: heapless::Vec<u8, 128> = heapless::Vec::new();
        enc_data.extend_from_slice(&nonce).unwrap();
        let aad_len = aad.len() as u16;
        enc_data.extend_from_slice(&aad_len.to_be_bytes()).unwrap();
        enc_data.extend_from_slice(aad).unwrap();
        enc_data.extend_from_slice(plaintext).unwrap();

        let enc_resp = run_cmd(&mut state, &mut store, P1_ENCRYPT, P2_AES_GCM, &enc_data);
        assert_eq!(parse_sw(&enc_resp), SW_OK, "GCM encrypt should succeed");
        let ct_and_tag = resp_data(&enc_resp);
        // ciphertext + 16-byte tag
        assert_eq!(ct_and_tag.len(), plaintext.len() + 16);

        // Decrypt: nonce(12) || aad_len_be(2) || aad || ciphertext_and_tag
        let mut dec_data: heapless::Vec<u8, 128> = heapless::Vec::new();
        dec_data.extend_from_slice(&nonce).unwrap();
        dec_data.extend_from_slice(&aad_len.to_be_bytes()).unwrap();
        dec_data.extend_from_slice(aad).unwrap();
        dec_data.extend_from_slice(ct_and_tag).unwrap();

        let dec_resp = run_cmd(&mut state, &mut store, P1_DECRYPT, P2_AES_GCM, &dec_data);
        assert_eq!(parse_sw(&dec_resp), SW_OK, "GCM decrypt should succeed");
        let recovered = resp_data(&dec_resp);

        assert_eq!(
            recovered, plaintext,
            "AES-GCM round-trip should recover plaintext"
        );
    }

    // -----------------------------------------------------------------------
    // AES-CMAC: tag is 16 bytes
    // -----------------------------------------------------------------------

    #[test]
    fn test_aes_cmac_tag_length() {
        let key = [0x55u8; 32];
        let (mut state, mut store) = make_state_and_store(0x01, &key);
        let message = b"test message for CMAC";

        // P1 is ignored for CMAC
        let resp = run_cmd(&mut state, &mut store, P1_ENCRYPT, P2_AES_CMAC, message);
        assert_eq!(parse_sw(&resp), SW_OK, "CMAC should succeed");
        let tag = resp_data(&resp);
        assert_eq!(tag.len(), 16, "CMAC tag must be 16 bytes");
    }

    // -----------------------------------------------------------------------
    // Missing PIN → SW_SECURITY_STATUS
    // -----------------------------------------------------------------------

    #[test]
    fn test_missing_pin_returns_security_status() {
        let key = [0x42u8; 32];
        let (mut state, mut store) = make_state_and_store(0x01, &key);
        state.pin_verified = false; // override

        let mut data: heapless::Vec<u8, 48> = heapless::Vec::new();
        data.extend_from_slice(&[0u8; 32]).unwrap(); // IV + some data

        let resp = run_cmd(&mut state, &mut store, P1_ENCRYPT, P2_AES_CBC, &data);
        assert_eq!(parse_sw(&resp), SW_SECURITY_STATUS);
    }

    // -----------------------------------------------------------------------
    // Unknown sym key → SW_FILE_NOT_FOUND
    // -----------------------------------------------------------------------

    #[test]
    fn test_missing_sym_key_returns_file_not_found() {
        let key = [0x42u8; 32];
        let (mut state, mut store) = make_state_and_store(0x01, &key);
        // Point MSE to a key_id that isn't in key_index
        state.current_key_id = Some(0x02);

        let mut data: heapless::Vec<u8, 48> = heapless::Vec::new();
        data.extend_from_slice(&[0u8; 32]).unwrap();

        let resp = run_cmd(&mut state, &mut store, P1_ENCRYPT, P2_AES_CBC, &data);
        assert_eq!(parse_sw(&resp), SW_FILE_NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // No MSE key selected → SW_CONDITIONS_NOT_SATISFIED
    // -----------------------------------------------------------------------

    #[test]
    fn test_no_key_selected_returns_conditions_not_satisfied() {
        let mut state = ScHsmState::new();
        let (_, mut store) = make_state_and_store(0x01, &[0u8; 32]);
        state.pin_verified = true;
        state.current_key_id = None; // no MSE

        let mut data: heapless::Vec<u8, 48> = heapless::Vec::new();
        data.extend_from_slice(&[0u8; 32]).unwrap();

        let resp = run_cmd(&mut state, &mut store, P1_ENCRYPT, P2_AES_CBC, &data);
        assert_eq!(parse_sw(&resp), SW_CONDITIONS_NOT_SATISFIED);
    }
}
