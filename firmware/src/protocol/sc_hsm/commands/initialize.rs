//! INITIALIZE DEVICE command handler (INS = 0x50).
//!
//! Formats the keystore and sets the initial SO-PIN and optionally the
//! User PIN. Also writes the EF.DevAut and EF.C.DevAut files.
//!
//! # Command data TLV structure (SC-HSM spec §7.1)
//! - Tag 0x80: SO-PIN (6–16 bytes)
//! - Tag 0x81: User PIN (optional, 6–16 bytes)
//! - Tag 0x82: Label bytes (1–32 UTF-8)
//! - Tag 0x91: DKEK share count (1 byte, 0–8; 0 = no DKEK)
//! - Tag 0x92: Options bitmask (2 bytes LE16)

use subtle::ConstantTimeEq;

use pico2hsm_core::{
    apdu::{ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_OK, SW_SECURITY_STATUS,
        SW_WRONG_DATA, SW_WRONG_LENGTH},
    key::AppletId,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for INITIALIZE DEVICE.
pub const INS_INITIALIZE: u8 = 0x50;

/// Parse a BER-TLV primitive tag (single byte) from `data` starting at `pos`.
/// Returns `(value_slice, new_pos)` or `None` if malformed / missing.
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

/// Compute PBKDF2-HMAC-SHA256 of `pin` with the given salt, writing into `out[..32]`.
///
/// Uses `PinState::hash_pin` so the hash format is identical to what VERIFY uses.
/// Salt composition: device_id (fallback [0;16]) || "pin" || extra_salt.
fn hash_pin_pbkdf2(pin: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    use crate::security::pin::PinState;
    // Use a fixed device_id fallback for INITIALIZE-time hashing.
    // The salt already contains per-device randomness via `salt`.
    PinState::hash_pin(pin, b"pico2hsm-device", salt)
}

/// Compute PBKDF2-HMAC-SHA256 of `puk` with the given salt.
fn hash_puk_pbkdf2(puk: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    use crate::security::pin::PinState;
    PinState::hash_puk(puk, b"pico2hsm-device", salt)
}

/// Generate 16 random bytes for a salt using the firmware RNG.
fn gen_salt() -> [u8; 16] {
    use crate::protocol::sc_hsm::FwRng;
    use rand_core::RngCore;
    let mut rng = FwRng;
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    salt
}

/// Handle an INITIALIZE DEVICE APDU command.
///
/// Tag layout per SC-HSM / OpenSC sc-hsm-tool convention:
///   0x80  Options bitmask (2 bytes LE)
///   0x81  User PIN (6–16 raw bytes)
///   0x82  Init code / SO-PIN (always exactly 8 bytes, hex-decoded by the tool)
///   0x91  User PIN retry counter (1 byte)
///   0x92  DKEK share count (1 byte, 0 = no DKEK)
pub fn handle(state: &mut ScHsmState, store: &mut dyn crate::storage::KeyStore, cmd: &ApduCommand<'_>) -> ApduResponse {
    crate::CORE1_PROGRESS.store(30, core::sync::atomic::Ordering::Relaxed);
    // cdc_log removed — CriticalSectionRawMutex is single-core only, unsafe on core1
    if cmd.p1 != 0x00 || cmd.p2 != 0x00 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    let data = cmd.data;

    // Tag 0x82: Init code (SO-PIN), mandatory, must be exactly 8 bytes.
    let init_code = match find_tlv(data, 0x82) {
        Some(v) => v,
        None => return ApduResponse::err(SW_WRONG_DATA),
    };
    if init_code.len() != 8 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }

    // Re-initialization: the provided init code must match the stored hash.
    // The real SmartCard-HSM authenticates re-init via the init code in the
    // command itself — no prior VERIFY is required.
    if state.initialized {
        if let Some(stored_hash) = state.so_pin_hash {
            let provided_hash = hash_pin_pbkdf2(init_code, &state.so_pin_salt);
            if !bool::from(provided_hash.ct_eq(&stored_hash)) {
                return ApduResponse::err(SW_SECURITY_STATUS);
            }
        }
    }

    // Tag 0x81: User PIN (optional, 6–16 bytes).
    let user_pin = find_tlv(data, 0x81);
    if let Some(up) = user_pin {
        if up.len() < 6 || up.len() > 16 {
            return ApduResponse::err(SW_WRONG_LENGTH);
        }
    }

    // Tag 0x80: Options bitmask (optional, 2 bytes LE).
    let options = find_tlv(data, 0x80).and_then(|v| {
        if v.len() >= 2 { Some(u16::from_le_bytes([v[0], v[1]])) } else { None }
    });

    // Tag 0x91: User PIN retry counter (optional).
    let retry_counter = find_tlv(data, 0x91).and_then(|v| v.first().copied()).unwrap_or(3);

    // Tag 0x92: DKEK share count (optional, 0 = no DKEK).
    let dkek_count = find_tlv(data, 0x92).and_then(|v| v.first().copied()).unwrap_or(0);

    // Generate fresh random salts for all credentials.
    let so_salt = gen_salt();
    let user_salt = gen_salt();
    let puk_salt_bytes = gen_salt();

    // Store SO-PIN (init code) hash using PBKDF2.
    state.so_pin_salt = so_salt;
    state.so_pin_hash = Some(hash_pin_pbkdf2(init_code, &so_salt));

    // Store User PIN hash if provided, using PBKDF2.
    if let Some(up) = user_pin {
        state.user_pin_salt = user_salt;
        state.user_pin_hash = Some(hash_pin_pbkdf2(up, &user_salt));
        state.pin_retry_count = retry_counter;
    }

    // Tag 0x93: PUK (optional, 8–16 bytes), using PBKDF2.
    if let Some(puk) = find_tlv(data, 0x93) {
        if puk.len() < 8 || puk.len() > 16 {
            return ApduResponse::err(SW_WRONG_LENGTH);
        }
        state.puk_salt = puk_salt_bytes;
        state.puk_hash = Some(hash_puk_pbkdf2(puk, &puk_salt_bytes));
        state.puk_retry_count = 10;
    } else {
        state.puk_hash = None;
        state.puk_retry_count = 10;
    }

    state.options = options.unwrap_or(0);
    state.dkek_shares_required = dkek_count;
    state.dkek_shares_imported = 0;

    // Reset auth state.
    state.pin_verified = false;
    state.so_pin_verified = false;
    state.so_pin_retry_count = 5;

    // Reset MSE state.
    state.current_key_id = None;
    state.current_algo = None;
    state.current_se_op = None;
    state.challenge = None;

    state.initialized = true;
    state.keys.clear();
    #[cfg(feature = "rsa")]
    state.rsa_keys.clear();
    state.ef_files.clear();

    // Slot 0 is reserved for the device authentication key on SC-HSM.
    // Pre-populate a sentinel entry so sc_hsm_determine_free_id skips it
    // and assigns user keys starting at slot 1.
    let dev_key = crate::protocol::sc_hsm::InMemoryKey {
        key_id: pico2hsm_core::key::KeyId::sc_hsm(0, 0).0,
        key_type: pico2hsm_core::key::KeyType::EcPrivateP256,
        algo: 0x13,
        key_flags: 0,
        private_key: heapless::Vec::new(),
        public_key: heapless::Vec::new(),
    };
    let _ = state.keys.push(dev_key);

    // Reset DKEK state: init share collection for the requested count.
    state.dkek.init_shares(dkek_count);

    // Clear ephemeral exchange state.
    state.exchange_ephem_priv = None;
    state.exchange_ephem_pub = None;

    // Wipe only SC-HSM-owned keys from persistent flash keystore.
    // Degraded flash does not fail the INITIALIZE command.
    crate::CORE1_PROGRESS.store(31, core::sync::atomic::Ordering::Relaxed);
    let _ = store.wipe_by_owner(AppletId::ScHsm); // best-effort; InvalidCore returns Ok(()) on Core1

    // Generate device identity P-256 keypair for DKEK exchange.
    // Stored at reserved slot 0xFE; public key written to EF 0x2F02.
    crate::CORE1_PROGRESS.store(32, core::sync::atomic::Ordering::Relaxed);
    {
        use crate::crypto::asymmetric::generate_ec_keypair;
        use crate::protocol::sc_hsm::{FwRng, InMemoryKey, EfEntry};
        use pico2hsm_core::key::KeyType as CoreKeyType;

        let mut rng = FwRng;
        if let Ok(pair) = generate_ec_keypair(CoreKeyType::EcPrivateP256, &mut rng) {
            let dev_identity_key_id = pico2hsm_core::key::KeyId::sc_hsm(0, 0xFE).0;

            // Persist to flash.
            {
                use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};
                let mut key_obj = KeyObject::new(KmType::Ec, dev_identity_key_id, AppletId::ScHsm, AlgorithmId::EcdsaP256);
                let _ = key_obj.private_key.extend_from_slice(&pair.private_key);
                let _ = key_obj.public_key.extend_from_slice(&pair.public_key);
                crate::CORE1_PROGRESS.store(80, core::sync::atomic::Ordering::Relaxed);
                let _ = store.save_key(&key_obj); // best-effort
                crate::CORE1_PROGRESS.store(81, core::sync::atomic::Ordering::Relaxed);
            }

            // Store in in-memory key store.
            state.keys.retain(|k| k.key_id != dev_identity_key_id);
            let mut entry = InMemoryKey {
                key_id: dev_identity_key_id,
                key_type: CoreKeyType::EcPrivateP256,
                algo: 0x13, // EcdsaP256
                key_flags: 0,
                private_key: heapless::Vec::new(),
                public_key: heapless::Vec::new(),
            };
            let _ = entry.private_key.extend_from_slice(&pair.private_key);
            let _ = entry.public_key.extend_from_slice(&pair.public_key);
            let _ = state.keys.push(entry);

            // Store public key in EF 0x2F02 (EF.C.DevAut).
            state.ef_files.retain(|ef| ef.file_id != 0x2F02);
            let mut ef = EfEntry {
                file_id: 0x2F02,
                data: heapless::Vec::new(),
            };
            let _ = ef.data.extend_from_slice(&pair.public_key);
            let _ = state.ef_files.push(ef);
        }
    }

    // Persist PIN/SO-PIN/PUK state to flash.
    crate::CORE1_PROGRESS.store(33, core::sync::atomic::Ordering::Relaxed);
    crate::protocol::sc_hsm::ScHsm::save_pin_to_store(state, store);
    crate::CORE1_PROGRESS.store(39, core::sync::atomic::Ordering::Relaxed);

    // cdc_log removed — CriticalSectionRawMutex is single-core only, unsafe on core1
    ApduResponse::ok(&[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sc_hsm::ScHsmState;
    use pico2hsm_core::apdu::{SW_OK, SW_SECURITY_STATUS};

    /// Build a minimal INITIALIZE APDU with the given TLV-encoded data.
    fn make_initialize(data: &[u8]) -> heapless::Vec<u8, 128> {
        let mut apdu: heapless::Vec<u8, 128> = heapless::Vec::new();
        let _ = apdu.extend_from_slice(&[0x00, INS_INITIALIZE, 0x00, 0x00]);
        if !data.is_empty() {
            let _ = apdu.push(data.len() as u8);
            let _ = apdu.extend_from_slice(data);
        }
        apdu
    }

    /// Encode a single TLV primitive: tag + length + value.
    fn tlv(tag: u8, value: &[u8]) -> heapless::Vec<u8, 64> {
        let mut v: heapless::Vec<u8, 64> = heapless::Vec::new();
        let _ = v.push(tag);
        let _ = v.push(value.len() as u8);
        let _ = v.extend_from_slice(value);
        v
    }

    #[test]
    fn test_reinit_wrong_sopin_rejected() {
        let mut state = ScHsmState::new();
        let mut store = crate::storage::NullKeyStore;

        // First INITIALIZE with SO-PIN "12345678"
        let init_code = b"12345678";
        let data = tlv(0x82, init_code);
        let apdu = make_initialize(&data);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_OK);
        assert!(state.initialized);
        assert!(state.so_pin_hash.is_some());

        // Re-INITIALIZE with wrong SO-PIN must be rejected
        let wrong_code = b"XXXXXXXX";
        let data2 = tlv(0x82, wrong_code);
        let apdu2 = make_initialize(&data2);
        let cmd2 = pico2hsm_core::apdu::ApduCommand::parse(&apdu2).unwrap();
        let resp2 = handle(&mut state, &mut store, &cmd2);
        assert_eq!(resp2.sw, SW_SECURITY_STATUS);
    }

    #[test]
    fn test_reinit_correct_sopin_accepted() {
        let mut state = ScHsmState::new();
        let mut store = crate::storage::NullKeyStore;

        // First INITIALIZE with SO-PIN "12345678"
        let init_code = b"12345678";
        let data = tlv(0x82, init_code);
        let apdu = make_initialize(&data);
        let cmd = pico2hsm_core::apdu::ApduCommand::parse(&apdu).unwrap();
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_OK);

        // Re-INITIALIZE with correct SO-PIN must succeed
        let data2 = tlv(0x82, init_code);
        let apdu2 = make_initialize(&data2);
        let cmd2 = pico2hsm_core::apdu::ApduCommand::parse(&apdu2).unwrap();
        let resp2 = handle(&mut state, &mut store, &cmd2);
        assert_eq!(resp2.sw, SW_OK);
    }
}
