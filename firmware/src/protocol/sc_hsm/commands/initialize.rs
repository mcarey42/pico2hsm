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

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_OK, SW_SECURITY_STATUS,
    SW_WRONG_DATA, SW_WRONG_LENGTH,
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

/// Compute a naive SHA-256 of `input` into `out[..32]`.
/// We use a manual constant since `sha2` is not usable without the crypto agent wiring.
/// For now store raw PIN bytes hashed via SHA-256.
/// TODO (Agent 7): replace with proper zeroizing hash call.
fn hash_pin(pin: &[u8], out: &mut [u8; 32]) {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(pin);
    let result = h.finalize();
    out.copy_from_slice(&result);
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
            let mut provided_hash = [0u8; 32];
            hash_pin(init_code, &mut provided_hash);
            if provided_hash != stored_hash {
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

    // Store SO-PIN (init code) hash.
    let mut so_hash = [0u8; 32];
    hash_pin(init_code, &mut so_hash);
    state.so_pin_hash = Some(so_hash);

    // Store User PIN hash if provided.
    if let Some(up) = user_pin {
        let mut u_hash = [0u8; 32];
        hash_pin(up, &mut u_hash);
        state.user_pin_hash = Some(u_hash);
        state.pin_retry_count = retry_counter;
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
        key_id: 0,
        key_type: pico2hsm_core::key::KeyType::EcPrivateP256,
        algo: 0x13,
        private_key: heapless::Vec::new(),
        public_key: heapless::Vec::new(),
    };
    let _ = state.keys.push(dev_key);

    // Wipe persistent flash keystore.
    // Degraded flash does not fail the INITIALIZE command.
    let _ = store.wipe_all(); // best-effort; InvalidCore returns Ok(()) on Core1
    ApduResponse::ok(&[])
}
