//! GET DATA command handler (INS = 0xCA) for OpenPGP.
//!
//! Returns Data Objects required by `gpg --card-status`:
//! - 004F: Application Identifier (full AID)
//! - 005E: Login data
//! - 0065: Cardholder Related Data (constructed)
//! - 006E: Application Related Data (constructed)
//! - 007A: Security Support Template (sig counter)
//! - 00C4: PW Status Bytes
//! - 00C5: Key Fingerprints (3x20 bytes)
//! - 00C6: CA Fingerprints (3x20 bytes)
//! - 00CD: Generation Timestamps (3x4 bytes)
//! - 00C1/C2/C3: Algorithm attributes per slot
//! - 00C0: Extended Capabilities
//! - 00DE: Key Information

use pico2hsm_core::apdu::{ApduCommand, ApduResponse};

use crate::protocol::openpgp::{openpgp_aid, OpenPgpState};

/// INS byte for GET DATA.
pub const INS_GET_DATA: u8 = 0xCA;

/// DO tag not found.
const SW_DO_NOT_FOUND: u16 = 0x6A88;

/// Handle a GET DATA APDU command.
pub fn handle(state: &mut OpenPgpState, cmd: &ApduCommand<'_>) -> ApduResponse {
    let tag = ((cmd.p1 as u16) << 8) | cmd.p2 as u16;

    match tag {
        // 004F — Application Identifier (full AID)
        0x004F => ApduResponse::ok(&openpgp_aid()),

        // 005B — Cardholder Name
        0x005B => ApduResponse::ok(&state.cardholder_name),

        // 005E — Login Data
        0x005E => ApduResponse::ok(&state.login_data),

        // 0065 — Cardholder Related Data (constructed)
        0x0065 => build_cardholder_related(state),

        // 006E — Application Related Data (constructed)
        0x006E => build_application_related(state),

        // 007A — Security Support Template
        0x007A => build_security_support(state),

        // 00C0 — Extended Capabilities
        0x00C0 => ApduResponse::ok(&extended_capabilities()),

        // 00C1 — Algorithm Attributes SIG
        0x00C1 => ApduResponse::ok(&state.algo_sig),

        // 00C2 — Algorithm Attributes DEC
        0x00C2 => ApduResponse::ok(&state.algo_dec),

        // 00C3 — Algorithm Attributes AUTH
        0x00C3 => ApduResponse::ok(&state.algo_auth),

        // 00C4 — PW Status Bytes
        0x00C4 => ApduResponse::ok(&pw_status_bytes(state)),

        // 00C5 — Key Fingerprints (SIG + DEC + AUTH = 60 bytes)
        0x00C5 => {
            let mut fp = [0u8; 60];
            fp[0..20].copy_from_slice(&state.fp_sig);
            fp[20..40].copy_from_slice(&state.fp_dec);
            fp[40..60].copy_from_slice(&state.fp_auth);
            ApduResponse::ok(&fp)
        }

        // 00C6 — CA Fingerprints (3x20 = 60 bytes)
        0x00C6 => {
            let mut fp = [0u8; 60];
            fp[0..20].copy_from_slice(&state.ca_fp1);
            fp[20..40].copy_from_slice(&state.ca_fp2);
            fp[40..60].copy_from_slice(&state.ca_fp3);
            ApduResponse::ok(&fp)
        }

        // 00C7/C8/C9 — Individual key fingerprints
        0x00C7 => ApduResponse::ok(&state.fp_sig),
        0x00C8 => ApduResponse::ok(&state.fp_dec),
        0x00C9 => ApduResponse::ok(&state.fp_auth),

        // 00CA/CB/CC — Individual CA fingerprints
        0x00CA => ApduResponse::ok(&state.ca_fp1),
        0x00CB => ApduResponse::ok(&state.ca_fp2),
        0x00CC => ApduResponse::ok(&state.ca_fp3),

        // 00CD — Key Generation Timestamps (3x4 = 12 bytes)
        0x00CD => {
            let mut ts = [0u8; 12];
            ts[0..4].copy_from_slice(&state.ts_sig);
            ts[4..8].copy_from_slice(&state.ts_dec);
            ts[8..12].copy_from_slice(&state.ts_auth);
            ApduResponse::ok(&ts)
        }

        // 00CE/CF/D0 — Individual timestamps
        0x00CE => ApduResponse::ok(&state.ts_sig),
        0x00CF => ApduResponse::ok(&state.ts_dec),
        0x00D0 => ApduResponse::ok(&state.ts_auth),

        // 00DE — Key Information (v3.4+): 6 bytes, each pair = (key_ref, status)
        // status: 0x00 = not present, 0x01 = generated on card
        0x00DE => {
            let sig_status = if state.sig_private.is_some() {
                0x01
            } else {
                0x00
            };
            let dec_status = if state.dec_private.is_some() {
                0x01
            } else {
                0x00
            };
            let auth_status = if state.auth_private.is_some() {
                0x01
            } else {
                0x00
            };
            ApduResponse::ok(&[0x01, sig_status, 0x02, dec_status, 0x03, auth_status])
        }

        // 5F2D — Language Preference
        0x5F2D => ApduResponse::ok(&state.language),

        // 5F35 — Sex
        0x5F35 => ApduResponse::ok(&[state.sex]),

        // 5F50 — URL of public key server
        0x5F50 => ApduResponse::ok(&state.url),

        // 7F21 — Cardholder Certificate (AUT key cert)
        0x7F21 => ApduResponse::ok(&state.cardholder_cert),

        // 7F74 — General Feature Management (§4.1.3.2): 81 01 <features>.
        // No display, biometric sensor, button, keypad, LED, loudspeaker,
        // microphone or touchscreen is used by this application, so all
        // bits are 0 — in particular no button for user interaction.
        0x7F74 => ApduResponse::ok(&GENERAL_FEATURES),

        // D6/D7/D8 — User Interaction Flags: not supported (no button);
        // they fall through to 6A88 below, as for a card without UIF.
        _ => ApduResponse::err(SW_DO_NOT_FOUND),
    }
}

/// DO 7F74 content: `81 01 00` — no user-interaction hardware.
const GENERAL_FEATURES: [u8; 3] = [0x81, 0x01, 0x00];

/// Extended Capabilities (DO C0) — 10 bytes.
fn extended_capabilities() -> [u8; 10] {
    // Byte 0: feature flags (OpenPGP Card 3.4 §4.4.3.7; as GnuPG reads them)
    //   0x80 = Secure Messaging — NO
    //   0x40 = GET CHALLENGE — YES
    //   0x20 = Key import (PUT DATA 3FFF / 4D) — NO (not implemented)
    //   0x10 = PW1 status byte changeable — YES (PUT DATA C4, PW3)
    //   0x08 = Private DOs — NO
    //   0x04 = Algorithm attributes changeable — YES
    //   0x02 = PSO:DEC/ENC with AES — NO
    //   0x01 = KDF-DO — NO
    // (0x10 was advertised once by mistake under the name "key import",
    // then cleared while C4 was read-only; it is now true.)
    let byte0: u8 = 0x54;
    // Byte 1: 0x00 (no SM, no MSE, no PIN block 2)
    let byte1: u8 = 0x00;
    // Bytes 2-3: max GET CHALLENGE length = 0x00FF (255 bytes)
    // Bytes 4-5: max certificate length = 0x0400 (1024 bytes, per cardholder_cert field size)
    // Bytes 6-7: max special DO size = 0x00FE (254 bytes, per url/login_data field size)
    // Bytes 8-9: reserved = 0x0000
    [byte0, byte1, 0x00, 0xFF, 0x04, 0x00, 0x00, 0xFE, 0x00, 0x00]
}

/// PW Status Bytes (DO C4) — 7 bytes.
fn pw_status_bytes(state: &OpenPgpState) -> [u8; 7] {
    [
        state.pw1_status,  // 00: PW1 valid for one PSO:CDS, 01: several
        0x7F,              // max PW1 length (127)
        0x7F,              // max Reset Code length (127)
        0x7F,              // max PW3 length (127)
        state.pw1_retries, // PW1 retry counter
        0x00,              // RC retry counter (no reset code set)
        state.pw3_retries, // PW3 retry counter
    ]
}

/// Build Cardholder Related Data (DO 0065) — constructed TLV.
fn build_cardholder_related(state: &OpenPgpState) -> ApduResponse {
    // 65 [ 5B [name]  5F2D [lang]  5F35 [sex] ]
    let mut buf = heapless::Vec::<u8, 128>::new();

    // 5B — Cardholder Name
    let _ = buf.push(0x5B);
    let _ = buf.push(state.cardholder_name.len() as u8);
    let _ = buf.extend_from_slice(&state.cardholder_name);

    // 5F 2D — Language Preference
    let _ = buf.push(0x5F);
    let _ = buf.push(0x2D);
    let _ = buf.push(state.language.len() as u8);
    let _ = buf.extend_from_slice(&state.language);

    // 5F 35 — Sex
    let _ = buf.push(0x5F);
    let _ = buf.push(0x35);
    let _ = buf.push(0x01);
    let _ = buf.push(state.sex);

    // Wrap in 65 tag
    let mut out = heapless::Vec::<u8, 140>::new();
    let _ = out.push(0x65);
    let _ = out.push(buf.len() as u8);
    let _ = out.extend_from_slice(&buf);

    ApduResponse::ok(&out)
}

/// Build Application Related Data (DO 006E) — the most complex constructed TLV.
fn build_application_related(state: &OpenPgpState) -> ApduResponse {
    // 006E contains:
    //   4F — AID
    //   5F52 — Historical Bytes
    //   73 — Discretionary DOs:
    //     C0 — Extended Capabilities
    //     C1 — Algo Attrs SIG
    //     C2 — Algo Attrs DEC
    //     C3 — Algo Attrs AUTH
    //     C4 — PW Status Bytes
    //     C5 — Key Fingerprints (60 bytes)
    //     C6 — CA Fingerprints (60 bytes)
    //     CD — Generation Timestamps (12 bytes)

    // Build inner content of tag 73 (Discretionary DOs)
    let mut disc = heapless::Vec::<u8, 512>::new();

    // C0 — Extended Capabilities
    let ext_caps = extended_capabilities();
    let _ = disc.push(0xC0);
    let _ = disc.push(ext_caps.len() as u8);
    let _ = disc.extend_from_slice(&ext_caps);

    // C1 — Algo Attrs SIG
    let _ = disc.push(0xC1);
    let _ = disc.push(state.algo_sig.len() as u8);
    let _ = disc.extend_from_slice(&state.algo_sig);

    // C2 — Algo Attrs DEC
    let _ = disc.push(0xC2);
    let _ = disc.push(state.algo_dec.len() as u8);
    let _ = disc.extend_from_slice(&state.algo_dec);

    // C3 — Algo Attrs AUTH
    let _ = disc.push(0xC3);
    let _ = disc.push(state.algo_auth.len() as u8);
    let _ = disc.extend_from_slice(&state.algo_auth);

    // C4 — PW Status Bytes
    let pw_status = pw_status_bytes(state);
    let _ = disc.push(0xC4);
    let _ = disc.push(pw_status.len() as u8);
    let _ = disc.extend_from_slice(&pw_status);

    // C5 — Key Fingerprints (3x20 = 60)
    let _ = disc.push(0xC5);
    let _ = disc.push(60);
    let _ = disc.extend_from_slice(&state.fp_sig);
    let _ = disc.extend_from_slice(&state.fp_dec);
    let _ = disc.extend_from_slice(&state.fp_auth);

    // C6 — CA Fingerprints (3x20 = 60)
    let _ = disc.push(0xC6);
    let _ = disc.push(60);
    let _ = disc.extend_from_slice(&state.ca_fp1);
    let _ = disc.extend_from_slice(&state.ca_fp2);
    let _ = disc.extend_from_slice(&state.ca_fp3);

    // CD — Generation Timestamps (3x4 = 12)
    let _ = disc.push(0xCD);
    let _ = disc.push(12);
    let _ = disc.extend_from_slice(&state.ts_sig);
    let _ = disc.extend_from_slice(&state.ts_dec);
    let _ = disc.extend_from_slice(&state.ts_auth);

    // Build outer 006E content
    let mut content = heapless::Vec::<u8, 600>::new();

    // 4F — AID
    let _ = content.push(0x4F);
    let aid = openpgp_aid();
    let _ = content.push(aid.len() as u8);
    let _ = content.extend_from_slice(&aid);

    // 5F52 — Historical Bytes (minimal compact-TLV for card capabilities)
    // This is a minimal set: category indicator (0x00), then compact-TLV
    // 73 = card capabilities, C0 = card service data, 01 = status indicator
    let hist_bytes: &[u8] = &[0x00, 0x31, 0xC5, 0x73, 0xC0, 0x01, 0x80, 0x00, 0x90, 0x00];
    let _ = content.push(0x5F);
    let _ = content.push(0x52);
    let _ = content.push(hist_bytes.len() as u8);
    let _ = content.extend_from_slice(hist_bytes);

    // 7F74 — General Feature Management: no button (nor other UI device).
    let _ = content.extend_from_slice(&[0x7F, 0x74, GENERAL_FEATURES.len() as u8]);
    let _ = content.extend_from_slice(&GENERAL_FEATURES);

    // 73 — Discretionary DOs
    let _ = content.push(0x73);
    // Use 2-byte length if needed (disc can exceed 127 bytes)
    if disc.len() > 127 {
        let _ = content.push(0x81);
        let _ = content.push(disc.len() as u8);
    } else {
        let _ = content.push(disc.len() as u8);
    }
    let _ = content.extend_from_slice(&disc);

    // Wrap in 6E tag
    let mut out = heapless::Vec::<u8, 700>::new();
    let _ = out.push(0x6E);
    // Use 2-byte length if needed
    if content.len() > 127 {
        let _ = out.push(0x81);
        let _ = out.push(content.len() as u8);
    } else {
        let _ = out.push(content.len() as u8);
    }
    let _ = out.extend_from_slice(&content);

    ApduResponse::ok(&out)
}

/// Build Security Support Template (DO 007A).
fn build_security_support(state: &OpenPgpState) -> ApduResponse {
    // 7A [ 93 03 <sig_counter_3bytes> ]
    let counter_bytes = [
        ((state.sig_counter >> 16) & 0xFF) as u8,
        ((state.sig_counter >> 8) & 0xFF) as u8,
        (state.sig_counter & 0xFF) as u8,
    ];

    let mut out = heapless::Vec::<u8, 16>::new();
    let _ = out.push(0x7A);
    let _ = out.push(0x05); // 93 03 + 3 counter bytes = 5 bytes
    let _ = out.push(0x93);
    let _ = out.push(0x03);
    let _ = out.extend_from_slice(&counter_bytes);

    ApduResponse::ok(&out)
}
