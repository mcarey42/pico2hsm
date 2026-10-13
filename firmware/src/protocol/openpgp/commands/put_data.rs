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
//! - 00C4: PW Status Bytes — byte 1 only (00 = PW1 valid for one PSO:CDS,
//!   01 = for several); OpenPGP Card 3.4 §4.4.3.6
//!
//! Not writable (6A88): the UIF DOs D6–D8 — this device has no button, so
//! user interaction flags are not supported.

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
pub const PERSISTED_TAGS: [u16; 19] = [
    0x005B, 0x005E, 0x5F2D, 0x5F35, 0x00C1, 0x00C2, 0x00C3, 0x00C7, 0x00C8, 0x00C9, 0x00CA, 0x00CB,
    0x00CC, 0x00CE, 0x00CF, 0x00D0, 0x5F50, 0x7F21, 0x00C4,
];

/// Largest digital signature counter (DO 93 is 3 bytes); it saturates.
pub const SIG_COUNTER_MAX: u32 = 0x00FF_FFFF;

/// KeyId of the 1.x keystore record of the digital signature counter
/// (DO 93).  2.0 keeps the counter in the counter log
/// (`ValueId::SignatureCounter`, STORAGE_V2 F2: a keystore write per
/// signature wore the directory out); a 1.x record is moved there once by
/// [`load_sig_counter`] and deleted.
pub fn sig_counter_key_id() -> pico2hsm_core::key::KeyId {
    do_key_id(0x0093)
}

/// Persist the signature counter in the counter log (one 16-byte record,
/// no keystore write).
pub fn save_sig_counter(
    count: u32,
    store: &mut dyn crate::storage::KeyStore,
) -> Result<(), pico2hsm_core::error::HsmError> {
    use crate::storage::retry_counter::ValueId;
    let log = store
        .retry_counters()
        .ok_or(pico2hsm_core::error::HsmError::Storage(
            pico2hsm_core::error::StorageError::NotFormatted,
        ))?;
    log.put_value(
        ValueId::SignatureCounter,
        u64::from(count.min(SIG_COUNTER_MAX)),
    )?;
    Ok(())
}

/// The persisted signature counter.  The counter log's value wins; with
/// none there, a 1.x keystore record is moved into the log and deleted
/// (the log write first, so a cut leaves the record to move again).  An
/// unreadable counter loads as the largest count rather than 0: the counter
/// must never go back.
pub fn load_sig_counter(store: &mut dyn crate::storage::KeyStore) -> u32 {
    use crate::storage::retry_counter::ValueId;
    let logged = match store.retry_counters() {
        Some(log) => log.value(ValueId::SignatureCounter),
        None => return SIG_COUNTER_MAX,
    };
    let legacy =
        |store: &mut dyn crate::storage::KeyStore| match store.fetch_key(sig_counter_key_id()) {
            Ok(None) => Ok(None),
            Ok(Some(rec)) => Ok(Some(match rec.private_key[..] {
                [a, b, c] => u32::from_be_bytes([0, a, b, c]),
                _ => SIG_COUNTER_MAX,
            })),
            Err(_) => Err(()),
        };
    match logged {
        Ok(Some(v)) => {
            // A leftover 1.x record (a cut after the move): drop it.
            if let Ok(Some(_)) = legacy(store) {
                let _ = store.erase_key(sig_counter_key_id());
            }
            (v.min(u64::from(SIG_COUNTER_MAX))) as u32
        }
        Ok(None) => match legacy(store) {
            Ok(None) => 0,
            Ok(Some(v)) => {
                let moved = store
                    .retry_counters()
                    .map(|log| {
                        log.put_value(ValueId::SignatureCounter, u64::from(v))
                            .is_ok()
                    })
                    .unwrap_or(false);
                if moved {
                    let _ = store.erase_key(sig_counter_key_id());
                }
                v
            }
            Err(()) => SIG_COUNTER_MAX,
        },
        Err(_) => SIG_COUNTER_MAX,
    }
}

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
        // PW1 status byte; 00 (the default) is stored as no record.
        0x00C4 if state.pw1_status != 0 => core::slice::from_ref(&state.pw1_status),
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
    // An empty value (cleared name, URL, ...) is the default: delete the
    // record rather than store a zero-length one, which can't be decrypted.
    let saved = if value.is_empty() {
        match store.fetch_key(do_key_id(tag)) {
            Ok(None) => Ok(()),
            Ok(Some(_)) => store.erase_key(do_key_id(tag)),
            Err(e) => Err(e),
        }
    } else if rec.private_key.extend_from_slice(&value).is_err() {
        Err(pico2hsm_core::error::HsmError::InvalidInput)
    } else {
        store.save_key(&rec)
    };
    if saved.is_err() {
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

        // 00C4 — PW Status Bytes: only byte 1 (PW1 for one / several
        // PSO:CDS) is writable.  An empty value restores the default
        // (loading a deleted record).
        0x00C4 => {
            match cmd.data {
                [] => state.pw1_status = 0x00,
                [b @ (0x00 | 0x01), ..] if cmd.data.len() == 1 || cmd.data.len() == 7 => {
                    state.pw1_status = *b
                }
                _ => return ApduResponse::err(SW_WRONG_DATA),
            }
            ApduResponse::ok(&[])
        }

        // 00C1 — Algorithm Attributes SIG
        0x00C1 => {
            if !role_allows(Role::Sig, cmd.data) {
                return ApduResponse::err(SW_WRONG_DATA);
            }
            state.algo_sig.clear();
            let _ = state.algo_sig.extend_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 00C2 — Algorithm Attributes DEC
        0x00C2 => {
            if !role_allows(Role::Dec, cmd.data) {
                return ApduResponse::err(SW_WRONG_DATA);
            }
            state.algo_dec.clear();
            let _ = state.algo_dec.extend_from_slice(cmd.data);
            ApduResponse::ok(&[])
        }

        // 00C3 — Algorithm Attributes AUTH
        0x00C3 => {
            if !role_allows(Role::Aut, cmd.data) {
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

/// The three key roles of OpenPGP Card 3.4.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Sig,
    Dec,
    Aut,
}

/// Whether algorithm attributes `attrs` (DO C1/C2/C3) are valid for `role`
/// on this card (OpenPGP Card 3.4 §4.4.3.10): the signature and
/// authentication keys sign (ECDSA 13, EdDSA 16), the decryption key does
/// key agreement (ECDH 12).  Only the curves the card can generate are
/// accepted (RSA is not offered by this applet).  A trailing format byte
/// (00 / FF, "with public key") is allowed after the OID.
fn role_allows(role: Role, attrs: &[u8]) -> bool {
    const P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    const P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
    const P521: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x23];
    const ED25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
    const X25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
    let Some((&algo, oid)) = attrs.split_first() else {
        return false;
    };
    let oid = match oid {
        [rest @ .., 0x00 | 0xFF] if !rest.is_empty() && [P256, P384, P521].contains(&rest) => rest,
        [rest @ .., 0x00 | 0xFF] if rest == ED25519 || rest == X25519 => rest,
        o => o,
    };
    let nist = [P256, P384, P521].contains(&oid);
    let curve25519 = cfg!(feature = "applet-openpgp-curve25519");
    match (role, algo) {
        (Role::Sig | Role::Aut, 0x13) => nist,
        (Role::Sig | Role::Aut, 0x16) => curve25519 && oid == ED25519,
        (Role::Dec, 0x12) => nist || (curve25519 && oid == X25519),
        _ => false,
    }
}
