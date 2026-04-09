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
