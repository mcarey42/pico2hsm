//! OpenPGP Card 3.4 protocol implementation.
//!
//! Implements the OpenPGP card application specification v3.4 for NIST-curve
//! ECC (P-256, P-384, P-521). The device switches to this protocol when a
//! SELECT AID command presents the OpenPGP AID prefix.
//!
//! # AID
//! `D2 76 00 01 24 01 03 04 FF FF SS SS SS SS 00 00`
//! (FF FF = manufacturer, SS SS SS SS = serial number)
//!
//! # Implemented commands
//! - SELECT (0xA4) — return FCI with AID and version
//! - GET DATA (0xCA) — core DOs for `gpg --card-status`
//! - VERIFY (0x20) — PW1 (P2=0x81/0x82) and PW3 (P2=0x83)
//! - CHANGE REFERENCE DATA (0x24) — change PW1 or PW3
//! - GENERATE KEY PAIR (0x47) — generate P-256 key in SIG/DEC/AUTH slot
//! - PUT DATA (0xDA/0xDB) — store name, fingerprints, timestamps, algo attrs
//! - PSO:CDS (0x2A, P1=0x9E, P2=0x9A) — ECDSA sign with SIG key
//! - PSO:DECIPHER (0x2A, P1=0x80, P2=0x86) — ECDH with DEC key
//! - INTERNAL AUTHENTICATE (0x88) — sign with AUTH key
//! - GET CHALLENGE (0x84) — return random bytes

pub mod commands;
pub mod pw;

use heapless::Vec;
use pico2hsm_core::{
    apdu::{ApduCommand, ApduResponse, SW_INS_NOT_SUPPORTED},
    protocol::HsmProtocol,
};

use commands::*;

/// OpenPGP AID prefix (first 6 bytes; remaining bytes are version + serial).
pub const OPENPGP_AID_PREFIX: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// Full 16-byte OpenPGP AID.
/// D2 76 00 01 24 01 = RID + application
/// 03 04 = version 3.4
/// FF FF = manufacturer (test/unassigned)
/// 00 00 00 01 = serial number (placeholder)
/// 00 00 = RFU
pub const OPENPGP_AID: [u8; 16] = [
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
];

/// P-256 OID bytes (1.2.840.10045.3.1.7) — used in algorithm attributes.
pub const P256_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// Default algorithm attributes for ECDSA (SIG/AUTH): `13` + P-256 OID.
pub const DEFAULT_ECDSA_ALGO_ATTRS: &[u8] = &[0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// Default algorithm attributes for ECDH (DEC): `12` + P-256 OID.
pub const DEFAULT_ECDH_ALGO_ATTRS: &[u8] = &[0x12, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// Ed25519 OID: 1.3.6.1.4.1.11591.15.1
#[cfg(feature = "applet-openpgp-curve25519")]
pub const ED25519_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];

/// X25519 OID: 1.3.6.1.4.1.3029.1.5.1
#[cfg(feature = "applet-openpgp-curve25519")]
pub const X25519_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

/// Default algorithm attributes for EdDSA (SIG/AUTH): `16` + Ed25519 OID.
#[cfg(feature = "applet-openpgp-curve25519")]
pub const DEFAULT_EDDSA_ALGO_ATTRS: &[u8] =
    &[0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];

/// Default algorithm attributes for X25519 (DEC): `12` + X25519 OID.
#[cfg(feature = "applet-openpgp-curve25519")]
pub const DEFAULT_X25519_ALGO_ATTRS: &[u8] = &[
    0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
];

/// OpenPGP key slot indices (stored in the low byte of `KeyId::openpgp(slot)`).
pub const SLOT_SIG: u8 = 0x90;
pub const SLOT_DEC: u8 = 0x91;
pub const SLOT_AUTH: u8 = 0x92;

/// Maximum PW1 retries.
pub const PW1_MAX_RETRIES: u8 = 3;
/// Maximum PW3 retries.
pub const PW3_MAX_RETRIES: u8 = 3;

/// OpenPGP Card protocol state.
pub struct OpenPgpState {
    // --- PIN state (simple hash-based, matching SC-HSM pattern) ---
    /// PW1 hash (SHA-256). None if not yet initialized.
    pub pw1_hash: Option<pw::PwHash>,
    /// PW3 hash (SHA-256). None if not yet initialized.
    pub pw3_hash: Option<pw::PwHash>,
    /// PW1 remaining retries.
    pub pw1_retries: u8,
    /// PW3 remaining retries.
    pub pw3_retries: u8,
    /// PW1 and PW3 records are on flash.  They must be before any key is:
    /// on load, missing records next to stored keys mean tampering, not a
    /// fresh card (see `load_from_store`).
    pub credentials_persisted: bool,

    // --- PIN verification flags ---
    /// PW1 verified for signing (P2=0x81). Cleared after each PSO:CDS.
    pub pw1_verified_sign: bool,
    /// PW1 verified for other operations (P2=0x82). Stays until SELECT/reset.
    pub pw1_verified_other: bool,
    /// PW3 verified. Stays until SELECT/reset.
    pub pw3_verified: bool,

    // --- Signature counter ---
    /// Digital signature counter (incremented on each PSO:CDS). 3-byte BE.
    pub sig_counter: u32,

    // --- Key storage (in-memory volatile) ---
    /// SIG key: private scalar (up to 66 bytes for P-521).
    pub sig_private: Option<Vec<u8, 66>>,
    /// SIG key: uncompressed public point (04 || X || Y).
    pub sig_public: Option<Vec<u8, 133>>,
    /// DEC key: private scalar.
    pub dec_private: Option<Vec<u8, 66>>,
    /// DEC key: uncompressed public point.
    pub dec_public: Option<Vec<u8, 133>>,
    /// AUTH key: private scalar.
    pub auth_private: Option<Vec<u8, 66>>,
    /// AUTH key: uncompressed public point.
    pub auth_public: Option<Vec<u8, 133>>,

    // --- Key type per slot (used to select the right crypto primitive) ---
    pub sig_key_type: Option<pico2hsm_core::key::KeyType>,
    pub dec_key_type: Option<pico2hsm_core::key::KeyType>,
    pub auth_key_type: Option<pico2hsm_core::key::KeyType>,

    // --- Cardholder data (writable via PUT DATA) ---
    /// Cardholder name (DO 005B), up to 39 bytes.
    pub cardholder_name: Vec<u8, 39>,
    /// Login data (DO 005E), up to 254 bytes.
    pub login_data: Vec<u8, 254>,
    /// Language preference (DO 5F2D), up to 8 bytes.
    pub language: Vec<u8, 8>,
    /// Sex (DO 5F35), 1 byte.
    pub sex: u8,

    // --- Key fingerprints (20 bytes each, SHA-1) ---
    pub fp_sig: [u8; 20],
    pub fp_dec: [u8; 20],
    pub fp_auth: [u8; 20],

    // --- CA fingerprints ---
    pub ca_fp1: [u8; 20],
    pub ca_fp2: [u8; 20],
    pub ca_fp3: [u8; 20],

    // --- Key generation timestamps (4 bytes each, Unix time BE) ---
    pub ts_sig: [u8; 4],
    pub ts_dec: [u8; 4],
    pub ts_auth: [u8; 4],

    // --- Algorithm attributes per slot (writable via PUT DATA) ---
    /// SIG algorithm attributes (DO C1). Default: ECDSA P-256.
    pub algo_sig: Vec<u8, 12>,
    /// DEC algorithm attributes (DO C2). Default: ECDH P-256.
    pub algo_dec: Vec<u8, 12>,
    /// AUTH algorithm attributes (DO C3). Default: ECDSA P-256.
    pub algo_auth: Vec<u8, 12>,

    // --- DO 5F50: URL of public key server (up to 254 bytes) ---
    pub url: Vec<u8, 254>,

    // --- DO 7F21: Cardholder Certificate (up to 1024 bytes) ---
    pub cardholder_cert: Vec<u8, 1024>,

    // --- Termination flag (set by TERMINATE DF, cleared by ACTIVATE FILE) ---
    pub terminated: bool,
}

/// Zeroize a private key slot in place, then empty it.
///
/// Assigning `None` alone only changes the discriminant and leaves the key
/// bytes in RAM.
pub(crate) fn wipe_key(slot: &mut Option<Vec<u8, 66>>) {
    if let Some(key) = slot.as_mut() {
        zeroize::Zeroize::zeroize(key.as_mut_slice());
    }
    *slot = None;
}

impl Drop for OpenPgpState {
    /// Wipe private keys and password hashes when the state is dropped or
    /// replaced (ACTIVATE, `Dispatcher::reset_in_place`).
    fn drop(&mut self) {
        wipe_key(&mut self.sig_private);
        wipe_key(&mut self.dec_private);
        wipe_key(&mut self.auth_private);
        for hash in [&mut self.pw1_hash, &mut self.pw3_hash] {
            if let Some(h) = hash.as_mut() {
                zeroize::Zeroize::zeroize(h);
            }
            *hash = None;
        }
    }
}

/// Serialize a PW record.
///
/// `[0..32]` digest, `[32]` has_hash, `[33]` retries, `[34]` blocked,
/// `[35]` KDF (0 = legacy SHA-256, 1 = PBKDF2), `[36]` length (0 = unknown),
/// `[37..53]` salt.  Records written before 2026-10 stop at byte 35 and
/// load as legacy with unknown length.
fn encode_pw(buf: &mut Vec<u8, 64>, pw: Option<&pw::PwHash>, retries: u8) {
    let empty = pw::PwHash {
        digest: [0; 32],
        salt: [0; 16],
        len: 0,
        kdf: pw::PwKdf::Legacy,
    };
    let rec = pw.unwrap_or(&empty);
    let _ = buf.extend_from_slice(&rec.digest);
    let _ = buf.push(pw.is_some() as u8);
    let _ = buf.push(retries);
    let _ = buf.push((retries == 0) as u8);
    let _ = buf.push(rec.kdf as u8);
    let _ = buf.push(rec.len);
    let _ = buf.extend_from_slice(&rec.salt);
}

/// Parse a PW record (see `encode_pw`): `(hash, retries)`, or `None` if short.
fn decode_pw(b: &[u8]) -> Option<(Option<pw::PwHash>, u8)> {
    if b.len() < 35 {
        return None;
    }
    let retries = b[33];
    if b[32] == 0 {
        return Some((None, retries));
    }
    let mut rec = pw::PwHash {
        digest: b[0..32].try_into().ok()?,
        salt: [0; 16],
        len: 0,
        kdf: pw::PwKdf::Legacy,
    };
    if b.len() >= 53 {
        rec.kdf = if b[35] == 1 {
            pw::PwKdf::Pbkdf2
        } else {
            pw::PwKdf::Legacy
        };
        rec.len = b[36];
        rec.salt = b[37..53].try_into().ok()?;
    }
    Some((Some(rec), retries))
}

impl Default for OpenPgpState {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenPgpState {
    pub fn new() -> Self {
        // Compute default PW1 and PW3 hashes
        let pw1_hash = pw::PwHash::factory_default(b"123456");
        let pw3_hash = pw::PwHash::factory_default(b"12345678");

        let mut algo_sig = Vec::new();
        let _ = algo_sig.extend_from_slice(DEFAULT_ECDSA_ALGO_ATTRS);
        let mut algo_dec = Vec::new();
        let _ = algo_dec.extend_from_slice(DEFAULT_ECDH_ALGO_ATTRS);
        let mut algo_auth = Vec::new();
        let _ = algo_auth.extend_from_slice(DEFAULT_ECDSA_ALGO_ATTRS);

        OpenPgpState {
            pw1_hash: Some(pw1_hash),
            pw3_hash: Some(pw3_hash),
            pw1_retries: PW1_MAX_RETRIES,
            pw3_retries: PW3_MAX_RETRIES,
            credentials_persisted: false,
            pw1_verified_sign: false,
            pw1_verified_other: false,
            pw3_verified: false,
            sig_counter: 0,
            sig_private: None,
            sig_public: None,
            dec_private: None,
            dec_public: None,
            auth_private: None,
            auth_public: None,
            sig_key_type: None,
            dec_key_type: None,
            auth_key_type: None,
            cardholder_name: Vec::new(),
            login_data: Vec::new(),
            language: Vec::new(),
            sex: 0x39, // '9' = not stated
            fp_sig: [0u8; 20],
            fp_dec: [0u8; 20],
            fp_auth: [0u8; 20],
            ca_fp1: [0u8; 20],
            ca_fp2: [0u8; 20],
            ca_fp3: [0u8; 20],
            ts_sig: [0u8; 4],
            ts_dec: [0u8; 4],
            ts_auth: [0u8; 4],
            algo_sig,
            algo_dec,
            algo_auth,
            url: Vec::new(),
            cardholder_cert: Vec::new(),
            terminated: false,
        }
    }

    /// Reset all PIN verification flags (called on SELECT).
    pub fn reset_security_state(&mut self) {
        self.pw1_verified_sign = false;
        self.pw1_verified_other = false;
        self.pw3_verified = false;
    }
}

/// KeyId for the OpenPGP PW1 record sentinel.
pub const OPENPGP_PW1_KEY_ID: pico2hsm_core::key::KeyId = pico2hsm_core::key::KeyId(0x000200FE);
/// KeyId for the OpenPGP PW3 record sentinel.
pub const OPENPGP_PW3_KEY_ID: pico2hsm_core::key::KeyId = pico2hsm_core::key::KeyId(0x000200FF);

/// OpenPGP Card protocol implementation.
pub struct OpenPgp {
    pub state: OpenPgpState,
}

/// A persistent OpenPGP password retry counter spent by an APDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PwCounter {
    Pw1,
    Pw3,
}

impl PwCounter {
    /// The counter `cmd` would spend; malformed APDUs (rejected by the
    /// handler before any comparison) spend nothing.
    fn spent_by(cmd: &ApduCommand<'_>, state: &OpenPgpState) -> Option<Self> {
        let n = cmd.data.len();
        let well_formed = cmd.p1 == 0x00
            && match (cmd.ins, cmd.p2) {
                (verify::INS_VERIFY, _) => (6..=127).contains(&n),
                (change_pin::INS_CHANGE_PIN, 0x81) => change_pin::counts_as_attempt(
                    state.pw1_hash.as_ref(),
                    n,
                    change_pin::PW1_MIN_LEN,
                ),
                (change_pin::INS_CHANGE_PIN, 0x83) => change_pin::counts_as_attempt(
                    state.pw3_hash.as_ref(),
                    n,
                    change_pin::PW3_MIN_LEN,
                ),
                _ => false,
            };
        if !well_formed {
            return None;
        }
        match (cmd.ins, cmd.p2) {
            (verify::INS_VERIFY, 0x81 | 0x82) | (change_pin::INS_CHANGE_PIN, 0x81) => {
                Some(Self::Pw1)
            }
            (verify::INS_VERIFY, 0x83) | (change_pin::INS_CHANGE_PIN, 0x83) => Some(Self::Pw3),
            _ => None,
        }
    }

    fn get(self, state: &mut OpenPgpState) -> &mut u8 {
        match self {
            Self::Pw1 => &mut state.pw1_retries,
            Self::Pw3 => &mut state.pw3_retries,
        }
    }

    fn save(
        self,
        state: &OpenPgpState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        match self {
            Self::Pw1 => OpenPgp::save_pw1_to_store(state, store),
            Self::Pw3 => OpenPgp::save_pw3_to_store(state, store),
        }
    }
}

impl OpenPgp {
    /// Create a new OpenPGP Card protocol instance.
    pub fn new() -> Self {
        OpenPgp {
            state: OpenPgpState::new(),
        }
    }

    /// Dispatch an already-parsed APDU to the appropriate command handler.
    ///
    /// GET RESPONSE and Le-truncation are handled by the Dispatcher.
    fn dispatch(&mut self, cmd: &ApduCommand<'_>) -> ApduResponse {
        // When terminated, only ACTIVATE FILE and SELECT are allowed.
        if self.state.terminated {
            match cmd.ins {
                terminate_activate::INS_ACTIVATE_FILE => {
                    return terminate_activate::handle_activate(&mut self.state, cmd);
                }
                select::INS_SELECT => {
                    return select::handle(&mut self.state, cmd);
                }
                _ => return ApduResponse::err(terminate_activate::SW_FILE_TERMINATED),
            }
        }

        match cmd.ins {
            select::INS_SELECT => select::handle(&mut self.state, cmd),
            verify::INS_VERIFY => verify::handle(&mut self.state, cmd),
            change_pin::INS_CHANGE_PIN => change_pin::handle(&mut self.state, cmd),
            reset_retry_counter::INS_RESET_RETRY_COUNTER => {
                reset_retry_counter::handle(&mut self.state, cmd)
            }
            get_data::INS_GET_DATA => get_data::handle(&mut self.state, cmd),
            put_data::INS_PUT_DATA | put_data::INS_PUT_DATA_ODD => {
                put_data::handle(&mut self.state, cmd)
            }
            generate_keypair::INS_GENERATE_KEYPAIR => {
                generate_keypair::handle(&mut self.state, cmd)
            }
            pso::INS_PSO => pso::handle(&mut self.state, cmd),
            authenticate::INS_AUTHENTICATE => authenticate::handle(&mut self.state, cmd),
            challenge::INS_CHALLENGE => challenge::handle(&mut self.state, cmd),
            terminate_activate::INS_TERMINATE_DF => {
                terminate_activate::handle_terminate(&mut self.state, cmd)
            }
            _ => ApduResponse::err(SW_INS_NOT_SUPPORTED),
        }
    }

    /// Dispatch an APDU using the store-aware path for mutations.
    ///
    /// GET RESPONSE and Le-truncation are handled by the Dispatcher.
    fn dispatch_with_store(
        &mut self,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        // When terminated, only ACTIVATE FILE and SELECT are allowed.
        if self.state.terminated {
            match cmd.ins {
                terminate_activate::INS_ACTIVATE_FILE => {
                    return terminate_activate::handle_activate(&mut self.state, cmd);
                }
                select::INS_SELECT => {
                    return select::handle(&mut self.state, cmd);
                }
                _ => return ApduResponse::err(terminate_activate::SW_FILE_TERMINATED),
            }
        }

        if let Some(pw) = PwCounter::spent_by(cmd, &self.state) {
            return self.with_persisted_attempt(pw, cmd, store);
        }
        self.route_with_store(cmd, store)
    }

    /// Spend one PW1/PW3 retry on flash before the handler compares the
    /// password; see `ScHsm::with_persisted_attempt` for the rationale.
    fn with_persisted_attempt(
        &mut self,
        pw: PwCounter,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        let before = *pw.get(&mut self.state);
        if before == 0 {
            return self.route_with_store(cmd, store);
        }
        let spent = before - 1;
        *pw.get(&mut self.state) = spent;
        if pw.save(&self.state, store).is_err() {
            return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
        }
        *pw.get(&mut self.state) = before;
        let hashes_before = (self.state.pw1_hash, self.state.pw3_hash);

        let resp = self.route_with_store(cmd, store);

        let after = pw.get(&mut self.state);
        if resp.sw != pico2hsm_core::apdu::SW_OK && *after > spent {
            *after = spent;
        }
        if *after != spent && pw.save(&self.state, store).is_err() {
            // Keep RAM consistent with flash (spent counter, old password)
            // and fail closed; see ScHsm::with_persisted_attempt.
            *pw.get(&mut self.state) = spent;
            (self.state.pw1_hash, self.state.pw3_hash) = hashes_before;
            self.state.pw1_verified_sign = false;
            self.state.pw1_verified_other = false;
            self.state.pw3_verified = false;
            return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
        }
        resp
    }

    /// Route an APDU to its handler with persistent storage available.
    fn route_with_store(
        &mut self,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        match cmd.ins {
            generate_keypair::INS_GENERATE_KEYPAIR
                if cmd.p1 == 0x80 && self.state.pw3_verified && !self.state.credentials_persisted =>
            {
                // First key for this card: PW1/PW3 go to flash first (see
                // `OpenPgpState::credentials_persisted`).
                if Self::save_pw1_to_store(&self.state, store).is_err()
                    || Self::save_pw3_to_store(&self.state, store).is_err()
                {
                    return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
                }
                self.state.credentials_persisted = true;
                generate_keypair::handle_with_store(&mut self.state, store, cmd)
            }
            generate_keypair::INS_GENERATE_KEYPAIR => {
                generate_keypair::handle_with_store(&mut self.state, store, cmd)
            }
            terminate_activate::INS_TERMINATE_DF => {
                terminate_activate::handle_terminate_with_store(&mut self.state, store, cmd)
            }
            put_data::INS_PUT_DATA | put_data::INS_PUT_DATA_ODD => {
                put_data::handle_with_store(&mut self.state, store, cmd)
            }
            // Password checks: persistence is handled by with_persisted_attempt.
            verify::INS_VERIFY => verify::handle(&mut self.state, cmd),
            change_pin::INS_CHANGE_PIN => change_pin::handle(&mut self.state, cmd),
            reset_retry_counter::INS_RESET_RETRY_COUNTER => {
                reset_retry_counter::handle_with_store(&mut self.state, store, cmd)
            }
            _ => {
                // Fall through to the non-store dispatch.
                self.dispatch(cmd)
            }
        }
    }

    /// Process a raw APDU with access to persistent storage.
    pub fn process_apdu_with_store(
        &mut self,
        apdu: &[u8],
        store: &mut dyn crate::storage::KeyStore,
    ) -> Vec<u8, 4098> {
        let resp = match ApduCommand::parse(apdu) {
            Ok(cmd) => self.dispatch_with_store(&cmd, store),
            Err(_) => ApduResponse::err(SW_INS_NOT_SUPPORTED),
        };
        // Full serialized response: data (≤4096) + SW — never truncated.
        resp.serialize()
    }

    /// Serialize and persist PW1 state to flash.
    ///
    /// Layout (35 bytes):
    ///   [0..32] pw1_hash (32 bytes; all zeros if None)
    ///   [32]    has_pw1_hash (1 if Some, 0 if None)
    ///   [33]    pw1_retries
    ///   [34]    pw1_blocked as u8
    ///   [35..]  see `encode_pw` (KDF, length, salt)
    pub fn save_pw1_to_store(
        state: &OpenPgpState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
        use pico2hsm_core::key::AppletId;

        let mut buf: Vec<u8, 64> = Vec::new();
        encode_pw(&mut buf, state.pw1_hash.as_ref(), state.pw1_retries);

        let mut obj = KeyObject {
            key_type: KmKeyType::Generic,
            key_id: OPENPGP_PW1_KEY_ID.0,
            owner: AppletId::OpenPgp,
            algorithm: AlgorithmId::AesGcm,
            key_domain: 0,
            use_count: 0,
            generation: 0,
            key_flags: 0,
            timestamp_ms: 0,
            private_key: Vec::new(),
            public_key: Vec::new(),
        };
        let _ = obj.private_key.extend_from_slice(&buf);
        store.save_key(&obj)
    }

    /// Serialize and persist PW3 state to flash.
    ///
    /// Layout (35 bytes):
    ///   [0..32] pw3_hash (32 bytes; all zeros if None)
    ///   [32]    has_pw3_hash (1 if Some, 0 if None)
    ///   [33]    pw3_retries
    ///   [34]    pw3_blocked as u8
    ///   [35..]  see `encode_pw` (KDF, length, salt)
    pub fn save_pw3_to_store(
        state: &OpenPgpState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
        use pico2hsm_core::key::AppletId;

        let mut buf: Vec<u8, 64> = Vec::new();
        encode_pw(&mut buf, state.pw3_hash.as_ref(), state.pw3_retries);

        let mut obj = KeyObject {
            key_type: KmKeyType::Generic,
            key_id: OPENPGP_PW3_KEY_ID.0,
            owner: AppletId::OpenPgp,
            algorithm: AlgorithmId::AesGcm,
            key_domain: 0,
            use_count: 0,
            generation: 0,
            key_flags: 0,
            timestamp_ms: 0,
            private_key: Vec::new(),
            public_key: Vec::new(),
        };
        let _ = obj.private_key.extend_from_slice(&buf);
        store.save_key(&obj)
    }

    /// Load persisted OpenPGP keys and PIN state from flash.
    pub fn load_from_store(&mut self, store: &mut dyn crate::storage::KeyStore) {
        use crate::security::key_management::{AlgorithmId, KeyType as KmKeyType};
        use pico2hsm_core::key::{AppletId, KeyType as CoreKeyType};

        // PW1/PW3.  A missing record is a fresh card only while no key is
        // stored (records are written before the first key).  Missing next
        // to a key, unreadable, or malformed means the flash was tampered
        // with: that password loads blocked instead of as the public
        // factory default.  TERMINATE (allowed once PW3 is blocked) is the
        // way out.
        let mut has_keys = false;
        // Persisted DOs (fingerprints, cardholder data) hold no secrets and
        // may be written before any key; they don't count.
        let mut do_ids: Vec<pico2hsm_core::key::KeyId, 18> = Vec::new();
        store.for_each_key(&mut |kid| {
            if kid.applet_byte() != AppletId::OpenPgp as u8 {
                return;
            }
            if put_data::tag_of_record(kid).is_some() {
                let _ = do_ids.push(kid);
            } else if kid != OPENPGP_PW1_KEY_ID && kid != OPENPGP_PW3_KEY_ID {
                has_keys = true;
            }
        });
        for kid in do_ids.iter() {
            if let (Some(tag), Ok(Some(rec))) = (put_data::tag_of_record(*kid), store.fetch_key(*kid)) {
                let _ = put_data::set_do(&mut self.state, tag, &rec.private_key);
            }
        }
        let mut persisted = true;
        for (kid, hash, retries) in [
            (OPENPGP_PW1_KEY_ID, &mut self.state.pw1_hash, &mut self.state.pw1_retries),
            (OPENPGP_PW3_KEY_ID, &mut self.state.pw3_hash, &mut self.state.pw3_retries),
        ] {
            match store.fetch_key(kid) {
                Ok(Some(obj)) => match decode_pw(&obj.private_key) {
                    Some((h, r)) => {
                        *hash = h;
                        *retries = r;
                    }
                    None => *retries = 0,
                },
                Ok(None) if !has_keys => persisted = false,
                _ => *retries = 0,
            }
        }
        self.state.credentials_persisted = persisted;

        // Load key objects for OpenPGP slots.
        let mut openpgp_ids: Vec<pico2hsm_core::key::KeyId, 8> = Vec::new();
        store.for_each_key(&mut |kid| {
            if kid.applet_byte() == AppletId::OpenPgp as u8 {
                let slot = kid.proto_ref();
                if matches!(slot, SLOT_SIG | SLOT_DEC | SLOT_AUTH) && kid.0 & 0xFF00 == 0 {
                    let _ = openpgp_ids.push(kid);
                }
            }
        });
        for kid in openpgp_ids.iter() {
            let slot = kid.proto_ref();

            if let Ok(Some(obj)) = store.fetch_key(*kid) {
                if !matches!(obj.key_type, KmKeyType::Ec) {
                    continue;
                }

                let key_type = match obj.algorithm {
                    AlgorithmId::EcdsaP256 | AlgorithmId::EcdhP256 => CoreKeyType::EcPrivateP256,
                    AlgorithmId::EcdsaP384 | AlgorithmId::EcdhP384 => CoreKeyType::EcPrivateP384,
                    AlgorithmId::EcdsaP521 | AlgorithmId::EcdhP521 => CoreKeyType::EcPrivateP521,
                    #[cfg(feature = "applet-openpgp-curve25519")]
                    AlgorithmId::Ed25519 => CoreKeyType::Ed25519,
                    #[cfg(feature = "applet-openpgp-curve25519")]
                    AlgorithmId::X25519 => CoreKeyType::X25519,
                    _ => continue,
                };

                let mut priv_vec: Vec<u8, 66> = Vec::new();
                let _ = priv_vec.extend_from_slice(&obj.private_key);
                let mut pub_vec: Vec<u8, 133> = Vec::new();
                let _ = pub_vec.extend_from_slice(&obj.public_key);

                match slot {
                    s if s == SLOT_SIG => {
                        self.state.sig_private = Some(priv_vec);
                        self.state.sig_public = Some(pub_vec);
                        self.state.sig_key_type = Some(key_type);
                    }
                    s if s == SLOT_DEC => {
                        self.state.dec_private = Some(priv_vec);
                        self.state.dec_public = Some(pub_vec);
                        self.state.dec_key_type = Some(key_type);
                    }
                    s if s == SLOT_AUTH => {
                        self.state.auth_private = Some(priv_vec);
                        self.state.auth_public = Some(pub_vec);
                        self.state.auth_key_type = Some(key_type);
                    }
                    _ => {}
                }
            }
        }
    }
}

impl HsmProtocol for OpenPgp {
    fn process_apdu(&mut self, apdu: &[u8]) -> Vec<u8, 4098> {
        let resp = match ApduCommand::parse(apdu) {
            Ok(cmd) => self.dispatch(&cmd),
            Err(_) => ApduResponse::err(SW_INS_NOT_SUPPORTED),
        };
        // Full serialized response: data (≤4096) + SW — never truncated.
        resp.serialize()
    }

    fn handles_aid(&self, aid: &[u8]) -> bool {
        aid.len() >= OPENPGP_AID_PREFIX.len()
            && &aid[..OPENPGP_AID_PREFIX.len()] == OPENPGP_AID_PREFIX
    }

    fn protocol_name(&self) -> &'static str {
        "OpenPGP"
    }
}

#[cfg(test)]
mod terminate_tests {
    use super::*;
    use crate::security::key_management::KeyObject;
    use pico2hsm_core::error::HsmError;
    use pico2hsm_core::key::{AppletId, KeyId};

    /// Records which owner was wiped; optionally fails the wipe.
    struct WipeStore {
        wiped: Option<AppletId>,
        fail: bool,
    }

    impl crate::storage::KeyStore for WipeStore {
        fn save_key(&mut self, _: &KeyObject) -> Result<(), HsmError> {
            Ok(())
        }
        fn fetch_key(&mut self, _: KeyId) -> Result<Option<KeyObject>, HsmError> {
            Ok(None)
        }
        fn erase_key(&mut self, _: KeyId) -> Result<(), HsmError> {
            Ok(())
        }
        fn wipe_all(&mut self) -> Result<(), HsmError> {
            Ok(())
        }
        fn wipe_by_owner(&mut self, owner: AppletId) -> Result<(), HsmError> {
            if self.fail {
                return Err(HsmError::NotSupported);
            }
            self.wiped = Some(owner);
            Ok(())
        }
        fn enumerate_keys(&self) -> heapless::Vec<KeyId, 64> {
            heapless::Vec::new()
        }
        fn for_each_key(&self, _: &mut dyn FnMut(KeyId)) {}
    }

    #[test]
    fn terminate_erases_flash_and_zeroizes_keys() {
        let pattern = [0xA5u8; 32];
        let mut pgp = OpenPgp::new();
        pgp.state.pw3_verified = true;
        let mut key = heapless::Vec::new();
        key.extend_from_slice(&pattern).unwrap();
        pgp.state.sig_private = Some(key);

        let mut store = WipeStore {
            wiped: None,
            fail: false,
        };
        let r = pgp.process_apdu_with_store(&[0x00, 0xE6, 0x00, 0x00], &mut store);
        assert_eq!(&r[r.len() - 2..], &[0x90, 0x00]);
        assert_eq!(store.wiped, Some(AppletId::OpenPgp), "flash records erased");

        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&pgp.state as *const OpenPgpState).cast::<u8>(),
                core::mem::size_of::<OpenPgpState>(),
            )
        };
        assert!(
            !bytes.windows(32).any(|w| w == pattern),
            "key bytes zeroized in place"
        );
    }

    #[test]
    fn failed_flash_wipe_leaves_card_unchanged() {
        let mut pgp = OpenPgp::new();
        pgp.state.pw3_verified = true;
        let mut key = heapless::Vec::new();
        key.extend_from_slice(&[0x11u8; 32]).unwrap();
        pgp.state.sig_private = Some(key);

        let mut store = WipeStore {
            wiped: None,
            fail: true,
        };
        let r = pgp.process_apdu_with_store(&[0x00, 0xE6, 0x00, 0x00], &mut store);
        assert_eq!(&r[r.len() - 2..], &[0x65, 0x81]);
        assert!(
            !pgp.state.terminated,
            "not terminated: flash still holds the keys"
        );
        assert!(pgp.state.sig_private.is_some(), "RAM still matches flash");
    }

    /// Store whose key writes fail.
    struct FailSaveStore;

    impl crate::storage::KeyStore for FailSaveStore {
        fn save_key(&mut self, _: &KeyObject) -> Result<(), HsmError> {
            Err(HsmError::NotSupported)
        }
        fn fetch_key(&mut self, _: KeyId) -> Result<Option<KeyObject>, HsmError> {
            Ok(None)
        }
        fn erase_key(&mut self, _: KeyId) -> Result<(), HsmError> {
            Ok(())
        }
        fn wipe_all(&mut self) -> Result<(), HsmError> {
            Ok(())
        }
        fn wipe_by_owner(&mut self, _: AppletId) -> Result<(), HsmError> {
            Ok(())
        }
        fn enumerate_keys(&self) -> heapless::Vec<KeyId, 64> {
            heapless::Vec::new()
        }
        fn for_each_key(&self, _: &mut dyn FnMut(KeyId)) {}
    }

    #[test]
    fn failed_keygen_save_drops_only_the_new_key() {
        let mut pgp = OpenPgp::new();
        pgp.state.pw3_verified = true;
        let mut auth = heapless::Vec::new();
        auth.extend_from_slice(&[0x77u8; 32]).unwrap();
        pgp.state.auth_private = Some(auth.clone());

        // GENERATE KEY PAIR for the signature slot (CRT B6).
        let r = pgp.process_apdu_with_store(
            &[0x00, 0x47, 0x80, 0x00, 0x02, 0xB6, 0x00],
            &mut FailSaveStore,
        );
        assert_eq!(&r[r.len() - 2..], &[0x65, 0x81]);
        assert!(
            pgp.state.sig_private.is_none(),
            "unsaved signature key dropped"
        );
        assert_eq!(
            pgp.state.auth_private,
            Some(auth),
            "authentication key untouched"
        );
    }
}

#[cfg(test)]
mod pw_tests {
    use super::*;
    use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
    use pico2hsm_core::error::HsmError;
    use pico2hsm_core::key::{AppletId, KeyId};

    /// Keeps the latest record per KeyId.
    struct MemStore {
        records: heapless::Vec<(KeyId, heapless::Vec<u8, 64>), 8>,
    }

    impl crate::storage::KeyStore for MemStore {
        fn save_key(&mut self, obj: &KeyObject) -> Result<(), HsmError> {
            let kid = KeyId(obj.key_id);
            self.records.retain(|(k, _)| *k != kid);
            let mut b = heapless::Vec::new();
            let _ = b.extend_from_slice(&obj.private_key[..obj.private_key.len().min(64)]);
            let _ = self.records.push((kid, b));
            Ok(())
        }
        fn fetch_key(&mut self, kid: KeyId) -> Result<Option<KeyObject>, HsmError> {
            Ok(self.records.iter().find(|(k, _)| *k == kid).map(|(_, b)| {
                let mut o = KeyObject::new(
                    KmKeyType::Generic,
                    kid.0,
                    AppletId::OpenPgp,
                    AlgorithmId::AesGcm,
                );
                o.private_key.extend_from_slice(b).unwrap();
                o
            }))
        }
        fn erase_key(&mut self, _: KeyId) -> Result<(), HsmError> {
            Ok(())
        }
        fn wipe_all(&mut self) -> Result<(), HsmError> {
            Ok(())
        }
        fn wipe_by_owner(&mut self, _: AppletId) -> Result<(), HsmError> {
            Ok(())
        }
        fn enumerate_keys(&self) -> heapless::Vec<KeyId, 64> {
            heapless::Vec::new()
        }
        fn for_each_key(&self, f: &mut dyn FnMut(KeyId)) {
            for (k, _) in self.records.iter() {
                f(*k);
            }
        }
    }

    fn sw(pgp: &mut OpenPgp, store: &mut MemStore, apdu: &[u8]) -> u16 {
        let r = pgp.process_apdu_with_store(apdu, store);
        u16::from_be_bytes([r[r.len() - 2], r[r.len() - 1]])
    }

    fn apdu(ins: u8, p2: u8, data: &[u8]) -> heapless::Vec<u8, 64> {
        let mut v = heapless::Vec::new();
        v.extend_from_slice(&[0x00, ins, 0x00, p2, data.len() as u8])
            .unwrap();
        v.extend_from_slice(data).unwrap();
        v
    }

    #[test]
    fn verify_upgrades_default_to_salted_record_on_flash() {
        let mut pgp = OpenPgp::new();
        let mut store = MemStore {
            records: heapless::Vec::new(),
        };
        assert_eq!(
            sw(&mut pgp, &mut store, &apdu(0x20, 0x81, b"123456")),
            0x9000
        );
        let rec = pgp.state.pw1_hash.unwrap();
        assert_eq!(rec.kdf, pw::PwKdf::Pbkdf2);
        assert_eq!(rec.len(), Some(6));
        let mut fresh = OpenPgp::new();
        fresh.load_from_store(&mut store);
        assert_eq!(fresh.state.pw1_hash, Some(rec), "upgrade persisted");
        assert_eq!(
            sw(&mut fresh, &mut store, &apdu(0x20, 0x81, b"123456")),
            0x9000
        );
    }

    #[test]
    fn missing_pw_record_next_to_a_key_loads_blocked() {
        let mut store = MemStore {
            records: heapless::Vec::new(),
        };
        // A stored signature key with no PW1/PW3 records: tampered flash.
        let sig = KeyId(OPENPGP_PW1_KEY_ID.0 & 0xFFFF_FF00 | SLOT_SIG as u32);
        store.records.push((sig, heapless::Vec::new())).unwrap();
        let mut pgp = OpenPgp::new();
        pgp.load_from_store(&mut store);
        assert_eq!(pgp.state.pw1_retries, 0);
        assert_eq!(pgp.state.pw3_retries, 0);
        assert_eq!(
            sw(&mut pgp, &mut store, &apdu(0x20, 0x81, b"123456")),
            0x6983,
            "factory default PIN must not work"
        );
        // ...but the card can still be reset.
        assert_eq!(
            sw(&mut pgp, &mut store, &[0x00, 0xE6, 0x00, 0x00]),
            0x9000,
            "TERMINATE allowed once PW3 is blocked"
        );
    }

    #[test]
    fn put_data_fingerprint_survives_reload() {
        let mut store = MemStore {
            records: heapless::Vec::new(),
        };
        let mut pgp = OpenPgp::new();
        assert_eq!(
            sw(&mut pgp, &mut store, &apdu(0x20, 0x83, b"12345678")),
            0x9000
        );
        let fp = [0x7Au8; 20];
        let mut put: heapless::Vec<u8, 64> = heapless::Vec::new();
        put.extend_from_slice(&[0x00, 0xDA, 0x00, 0xC7, 20]).unwrap();
        put.extend_from_slice(&fp).unwrap();
        assert_eq!(sw(&mut pgp, &mut store, &put), 0x9000);

        let mut fresh = OpenPgp::new();
        fresh.load_from_store(&mut store);
        assert_eq!(fresh.state.fp_sig, fp);
        // A DO record is not a key: PW defaults stay usable on this card.
        assert_eq!(fresh.state.pw1_retries, PW1_MAX_RETRIES);
    }

    #[test]
    fn empty_card_loads_factory_defaults() {
        let mut store = MemStore {
            records: heapless::Vec::new(),
        };
        let mut pgp = OpenPgp::new();
        pgp.load_from_store(&mut store);
        assert_eq!(pgp.state.pw1_retries, PW1_MAX_RETRIES);
        assert!(!pgp.state.credentials_persisted);
    }

    #[test]
    fn terminate_needs_pw3_unless_blocked() {
        let mut store = MemStore {
            records: heapless::Vec::new(),
        };
        let mut pgp = OpenPgp::new();
        assert_eq!(sw(&mut pgp, &mut store, &[0x00, 0xE6, 0x00, 0x00]), 0x6982);
    }

    #[test]
    fn change_pin_checks_exactly_one_candidate() {
        let mut pgp = OpenPgp::new();
        let mut store = MemStore {
            records: heapless::Vec::new(),
        };
        // Old PIN is 6 bytes; "1234561234567" would match under some other
        // split only if more than one were tried.
        let before = pgp.state.pw1_retries;
        assert_eq!(
            sw(&mut pgp, &mut store, &apdu(0x24, 0x81, b"12345X654321")),
            0x63C0 | (before - 1) as u16
        );
        assert_eq!(
            sw(&mut pgp, &mut store, &apdu(0x24, 0x81, b"123456654321")),
            0x9000
        );
        assert_eq!(
            sw(&mut pgp, &mut store, &apdu(0x20, 0x81, b"654321")),
            0x9000
        );
    }

    #[test]
    fn signing_needs_mode_81() {
        let mut pgp = OpenPgp::new();
        let mut store = MemStore {
            records: heapless::Vec::new(),
        };
        assert_eq!(
            sw(&mut pgp, &mut store, &apdu(0x20, 0x82, b"123456")),
            0x9000
        );
        let pso_cds = [
            0x00, 0x2A, 0x9E, 0x9A, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(sw(&mut pgp, &mut store, &pso_cds), 0x6982);
    }

    #[test]
    fn legacy_record_of_unknown_length_asks_for_verify_without_spending() {
        let mut pgp = OpenPgp::new();
        let mut store = MemStore {
            records: heapless::Vec::new(),
        };
        // A pre-2026-10 record: 35 bytes, SHA-256("123456"), no length.
        let mut old: heapless::Vec<u8, 64> = heapless::Vec::new();
        use sha2::Digest;
        old.extend_from_slice(&sha2::Sha256::digest(b"123456"))
            .unwrap();
        old.extend_from_slice(&[1, 3, 0]).unwrap();
        store.records.push((OPENPGP_PW1_KEY_ID, old)).unwrap();
        pgp.load_from_store(&mut store);
        assert_eq!(pgp.state.pw1_hash.unwrap().len(), None);

        assert_eq!(
            sw(&mut pgp, &mut store, &apdu(0x24, 0x81, b"123456654321")),
            0x6985
        );
        assert_eq!(pgp.state.pw1_retries, 3, "no retry spent");
        assert_eq!(
            sw(&mut pgp, &mut store, &apdu(0x20, 0x81, b"123456")),
            0x9000
        );
        assert_eq!(
            sw(&mut pgp, &mut store, &apdu(0x24, 0x81, b"123456654321")),
            0x9000
        );
    }

    #[test]
    fn change_pin_does_not_reveal_pin_length() {
        // Wrong total length and wrong old PIN must look identical: same SW,
        // same retry cost.  (Default PW1 is 6 bytes.)
        let mut pgp = OpenPgp::new();
        let mut store = MemStore {
            records: heapless::Vec::new(),
        };
        // Correct old PIN, but 134 trailing bytes: no valid split at length 6.
        let mut long = [b'9'; 140];
        long[..6].copy_from_slice(b"123456");
        let mut cmd: heapless::Vec<u8, 160> = heapless::Vec::new();
        cmd.extend_from_slice(&[0x00, 0x24, 0x00, 0x81, long.len() as u8])
            .unwrap();
        cmd.extend_from_slice(&long).unwrap();
        let r = pgp.process_apdu_with_store(&cmd, &mut store);
        let r1 = u16::from_be_bytes([r[r.len() - 2], r[r.len() - 1]]);
        assert_eq!(r1, 0x63C2, "bad split fails like a wrong PIN, not 6700");
        let r2 = sw(&mut pgp, &mut store, &apdu(0x24, 0x81, b"000000654321")); // right split, wrong PIN
        assert_eq!(r2, 0x63C1);
    }
}
