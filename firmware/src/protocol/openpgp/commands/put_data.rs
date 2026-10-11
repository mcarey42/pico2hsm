//! PUT DATA command handler (INS = 0xDA / 0xDB) for OpenPGP.
//!
//! Writes Data Objects. Most require PW3 (admin) to be verified.
//!
//! Supported DOs:
//! - 005B: Cardholder Name
//! - 005E: Login Data
//! - 5F2D: Language Preference
//! - 5F35: Sex
//! - 00C1/C2/C3: Algorithm Attributes
//! - 00C7/C8/C9: Key Fingerprints (SIG, DEC, AUTH)
//! - 00CA/CB/CC: CA Fingerprints
//! - 00CE/CF/D0: Generation Timestamps

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_SECURITY_STATUS, SW_WRONG_DATA, SW_WRONG_LENGTH,
};

use crate::protocol::openpgp::OpenPgpState;

/// The value being set; lets the per-tag arms below keep reading `cmd.data`.
struct SetDo<'a> {
    data: &'a [u8],
}

/// INS byte for PUT DATA (even).
pub const INS_PUT_DATA: u8 = 0xDA;

/// INS byte for PUT DATA (odd, for constructed DOs).
pub const INS_PUT_DATA_ODD: u8 = 0xDB;

/// DO tag not found.
const SW_DO_NOT_FOUND: u16 = 0x6A88;

/// Handle a PUT DATA APDU command.
pub fn handle(state: &mut OpenPgpState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // Most PUT DATA operations require PW3
    let tag = ((cmd.p1 as u16) << 8) | cmd.p2 as u16;

    // All writable DOs require PW3 verification
    if !state.pw3_verified {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }
    set_do(state, tag, cmd.data)
}

/// The DOs PUT DATA can write; each is persisted as its own record.
pub const PERSISTED_TAGS: [u16; 18] = [
    0x005B, 0x005E, 0x5F2D, 0x5F35, 0x00C1, 0x00C2, 0x00C3, 0x00C7, 0x00C8, 0x00C9, 0x00CA, 0x00CB,
    0x00CC, 0x00CE, 0x00CF, 0x00D0, 0x5F50, 0x7F21,
];

/// KeyId of a persisted DO: 0xD0 in bits 15–8 keeps these apart from the
/// key slots (0x90–0x92) and PW records (0xFE/0xFF); the low byte is the
/// tag's low byte, unique across `PERSISTED_TAGS`.
pub fn do_key_id(tag: u16) -> pico2hsm_core::key::KeyId {
    pico2hsm_core::key::KeyId(0x0002_D000 | (tag & 0xFF) as u32)
}

/// The DO tag a persisted record belongs to, if it is one.
pub fn tag_of_record(kid: pico2hsm_core::key::KeyId) -> Option<u16> {
    if kid.0 & 0xFFFF_FF00 != 0x0002_D000 {
        return None;
    }
    PERSISTED_TAGS
        .iter()
        .copied()
        .find(|t| (t & 0xFF) as u8 == kid.proto_ref())
}

/// Current value of a writable DO (what `set_do` would have to be given
/// to restore it).
pub fn get_do(state: &OpenPgpState, tag: u16, out: &mut heapless::Vec<u8, 1024>) {
    out.clear();
    let v: &[u8] = match tag {
        0x005B => &state.cardholder_name,
        0x005E => &state.login_data,
        0x5F2D => &state.language,
        0x5F35 => core::slice::from_ref(&state.sex),
        0x00C1 => &state.algo_sig,
        0x00C2 => &state.algo_dec,
        0x00C3 => &state.algo_auth,
        0x00C7 => &state.fp_sig,
        0x00C8 => &state.fp_dec,
        0x00C9 => &state.fp_auth,
        0x00CA => &state.ca_fp1,
        0x00CB => &state.ca_fp2,
        0x00CC => &state.ca_fp3,
        0x00CE => &state.ts_sig,
        0x00CF => &state.ts_dec,
        0x00D0 => &state.ts_auth,
        0x5F50 => &state.url,
        0x7F21 => &state.cardholder_cert,
        _ => &[],
    };
    let _ = out.extend_from_slice(v);
}

/// PUT DATA with persistence: the DO is saved to flash, and if that fails
/// RAM goes back to the old value (6581) so a reset can't silently undo
/// what the host was told succeeded — e.g. the key fingerprints gpg
/// writes after generating a key.
pub fn handle_with_store(
    state: &mut OpenPgpState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
    let tag = ((cmd.p1 as u16) << 8) | cmd.p2 as u16;
    let mut old = heapless::Vec::new();
    get_do(state, tag, &mut old);
    let resp = handle(state, cmd);
    if resp.sw != pico2hsm_core::apdu::SW_OK {
        return resp;
    }
    let mut rec = KeyObject::new(
        KmKeyType::Generic,
        do_key_id(tag).0,
        pico2hsm_core::key::AppletId::OpenPgp,
        AlgorithmId::AesGcm,
    );
    let mut value = heapless::Vec::new();
    get_do(state, tag, &mut value);
    if rec.private_key.extend_from_slice(&value).is_err() || store.save_key(&rec).is_err() {
        let _ = set_do(state, tag, &old);
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    }
    resp
}

/// Validate and store one DO value (no access check — see `handle`).
pub fn set_do(state: &mut OpenPgpState, tag: u16, data: &[u8]) -> ApduResponse {
    let cmd = SetDo { data };
    match tag {
        // 005B — Cardholder Name (max 39 bytes)
        0x005B => {
            if cmd.data.len() > 39 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.cardholder_name.clear();
            let _ = state.cardholder_name.extend_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 005E — Login Data (max 254 bytes)
        0x005E => {
            if cmd.data.len() > 254 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.login_data.clear();
            let _ = state.login_data.extend_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 5F2D — Language Preference (max 8 bytes)
        0x5F2D => {
            if cmd.data.len() > 8 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.language.clear();
            let _ = state.language.extend_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 5F35 — Sex (1 byte)
        0x5F35 => {
            if cmd.data.len() != 1 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.sex = cmd.data[0];
            ApduResponse::ok(&[])
        }

        // 00C1 — Algorithm Attributes SIG
        0x00C1 => {
            if cmd.data.is_empty() || cmd.data.len() > 12 {
                return ApduResponse::err(SW_WRONG_DATA);
            }
            state.algo_sig.clear();
            let _ = state.algo_sig.extend_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 00C2 — Algorithm Attributes DEC
        0x00C2 => {
            if cmd.data.is_empty() || cmd.data.len() > 12 {
                return ApduResponse::err(SW_WRONG_DATA);
            }
            state.algo_dec.clear();
            let _ = state.algo_dec.extend_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 00C3 — Algorithm Attributes AUTH
        0x00C3 => {
            if cmd.data.is_empty() || cmd.data.len() > 12 {
                return ApduResponse::err(SW_WRONG_DATA);
            }
            state.algo_auth.clear();
            let _ = state.algo_auth.extend_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 00C7 — Fingerprint SIG (20 bytes)
        0x00C7 => {
            if cmd.data.len() != 20 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.fp_sig.copy_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 00C8 — Fingerprint DEC (20 bytes)
        0x00C8 => {
            if cmd.data.len() != 20 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.fp_dec.copy_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 00C9 — Fingerprint AUTH (20 bytes)
        0x00C9 => {
            if cmd.data.len() != 20 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.fp_auth.copy_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 00CA — CA Fingerprint 1 (20 bytes)
        0x00CA => {
            if cmd.data.len() != 20 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.ca_fp1.copy_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 00CB — CA Fingerprint 2 (20 bytes)
        0x00CB => {
            if cmd.data.len() != 20 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.ca_fp2.copy_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 00CC — CA Fingerprint 3 (20 bytes)
        0x00CC => {
            if cmd.data.len() != 20 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.ca_fp3.copy_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 00CE — Generation Timestamp SIG (4 bytes)
        0x00CE => {
            if cmd.data.len() != 4 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.ts_sig.copy_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 00CF — Generation Timestamp DEC (4 bytes)
        0x00CF => {
            if cmd.data.len() != 4 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.ts_dec.copy_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 00D0 — Generation Timestamp AUTH (4 bytes)
        0x00D0 => {
            if cmd.data.len() != 4 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.ts_auth.copy_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 5F50 — URL of public key server (max 254 bytes)
        0x5F50 => {
            if cmd.data.len() > 254 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.url.clear();
            let _ = state.url.extend_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 7F21 — Cardholder Certificate (max 1024 bytes)
        0x7F21 => {
            if cmd.data.len() > 1024 {
                return ApduResponse::err(SW_WRONG_LENGTH);
            }
            state.cardholder_cert.clear();
            let _ = state.cardholder_cert.extend_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        _ => ApduResponse::err(SW_DO_NOT_FOUND),
    }
}
