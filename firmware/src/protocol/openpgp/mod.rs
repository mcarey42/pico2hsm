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
    pub pw1_hash: Option<[u8; 32]>,
    /// PW3 hash (SHA-256). None if not yet initialized.
    pub pw3_hash: Option<[u8; 32]>,
    /// PW1 remaining retries.
    pub pw1_retries: u8,
    /// PW3 remaining retries.
    pub pw3_retries: u8,

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
    pub sig_private: Option<heapless::Vec<u8, 66>>,
    /// SIG key: uncompressed public point (04 || X || Y).
    pub sig_public: Option<heapless::Vec<u8, 133>>,
    /// DEC key: private scalar.
    pub dec_private: Option<heapless::Vec<u8, 66>>,
    /// DEC key: uncompressed public point.
    pub dec_public: Option<heapless::Vec<u8, 133>>,
    /// AUTH key: private scalar.
    pub auth_private: Option<heapless::Vec<u8, 66>>,
    /// AUTH key: uncompressed public point.
    pub auth_public: Option<heapless::Vec<u8, 133>>,

    // --- Key type per slot (used to select the right crypto primitive) ---
    pub sig_key_type: Option<pico2hsm_core::key::KeyType>,
    pub dec_key_type: Option<pico2hsm_core::key::KeyType>,
    pub auth_key_type: Option<pico2hsm_core::key::KeyType>,

    // --- Cardholder data (writable via PUT DATA) ---
    /// Cardholder name (DO 005B), up to 39 bytes.
    pub cardholder_name: heapless::Vec<u8, 39>,
    /// Login data (DO 005E), up to 254 bytes.
    pub login_data: heapless::Vec<u8, 254>,
    /// Language preference (DO 5F2D), up to 8 bytes.
    pub language: heapless::Vec<u8, 8>,
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
    pub algo_sig: heapless::Vec<u8, 12>,
    /// DEC algorithm attributes (DO C2). Default: ECDH P-256.
    pub algo_dec: heapless::Vec<u8, 12>,
    /// AUTH algorithm attributes (DO C3). Default: ECDSA P-256.
    pub algo_auth: heapless::Vec<u8, 12>,

    // --- DO 5F50: URL of public key server (up to 254 bytes) ---
    pub url: heapless::Vec<u8, 254>,

    // --- DO 7F21: Cardholder Certificate (up to 1024 bytes) ---
    pub cardholder_cert: heapless::Vec<u8, 1024>,

    // --- Termination flag (set by TERMINATE DF, cleared by ACTIVATE FILE) ---
    pub terminated: bool,
}

impl OpenPgpState {
    pub fn new() -> Self {
        // Compute default PW1 and PW3 hashes
        let pw1_hash = Self::hash_pin(b"123456");
        let pw3_hash = Self::hash_pin(b"12345678");

        let mut algo_sig = heapless::Vec::new();
        let _ = algo_sig.extend_from_slice(DEFAULT_ECDSA_ALGO_ATTRS);
        let mut algo_dec = heapless::Vec::new();
        let _ = algo_dec.extend_from_slice(DEFAULT_ECDH_ALGO_ATTRS);
        let mut algo_auth = heapless::Vec::new();
        let _ = algo_auth.extend_from_slice(DEFAULT_ECDSA_ALGO_ATTRS);

        OpenPgpState {
            pw1_hash: Some(pw1_hash),
            pw3_hash: Some(pw3_hash),
            pw1_retries: PW1_MAX_RETRIES,
            pw3_retries: PW3_MAX_RETRIES,
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
            cardholder_name: heapless::Vec::new(),
            login_data: heapless::Vec::new(),
            language: heapless::Vec::new(),
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
            url: heapless::Vec::new(),
            cardholder_cert: heapless::Vec::new(),
            terminated: false,
        }
    }

    /// Compute SHA-256 hash of a PIN (simple, same as SC-HSM verify pattern).
    pub fn hash_pin(pin: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(pin);
        let result = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
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
    fn spent_by(cmd: &ApduCommand<'_>) -> Option<Self> {
        if cmd.data.is_empty() {
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

        if let Some(pw) = PwCounter::spent_by(cmd) {
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

        let resp = self.route_with_store(cmd, store);

        let after = pw.get(&mut self.state);
        if resp.sw != pico2hsm_core::apdu::SW_OK && *after > spent {
            *after = spent;
        }
        if *after != spent {
            let _ = pw.save(&self.state, store);
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
            generate_keypair::INS_GENERATE_KEYPAIR => {
                generate_keypair::handle_with_store(&mut self.state, store, cmd)
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
    ) -> Vec<u8, 4096> {
        let resp = match pico2hsm_core::apdu::ApduCommand::parse(apdu) {
            Ok(cmd) => self.dispatch_with_store(&cmd, store),
            Err(_) => ApduResponse::err(SW_INS_NOT_SUPPORTED),
        };
        let serialized = resp.serialize();
        let mut out: Vec<u8, 4096> = Vec::new();
        let _ = out.extend_from_slice(&serialized[..serialized.len().min(4096)]);
        out
    }

    /// Serialize and persist PW1 state to flash.
    ///
    /// Layout (35 bytes):
    ///   [0..32] pw1_hash (32 bytes; all zeros if None)
    ///   [32]    has_pw1_hash (1 if Some, 0 if None)
    ///   [33]    pw1_retries
    ///   [34]    pw1_blocked as u8
    pub fn save_pw1_to_store(
        state: &OpenPgpState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
        use pico2hsm_core::key::AppletId;

        let mut buf: heapless::Vec<u8, 64> = heapless::Vec::new();
        let (hash_bytes, has_hash) = match &state.pw1_hash {
            Some(h) => (*h, 1u8),
            None => ([0u8; 32], 0u8),
        };
        let _ = buf.extend_from_slice(&hash_bytes);
        let _ = buf.push(has_hash);
        let _ = buf.push(state.pw1_retries);
        let blocked = if state.pw1_retries == 0 { 1u8 } else { 0u8 };
        let _ = buf.push(blocked);

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
            private_key: heapless::Vec::new(),
            public_key: heapless::Vec::new(),
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
    pub fn save_pw3_to_store(
        state: &OpenPgpState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
        use pico2hsm_core::key::AppletId;

        let mut buf: heapless::Vec<u8, 64> = heapless::Vec::new();
        let (hash_bytes, has_hash) = match &state.pw3_hash {
            Some(h) => (*h, 1u8),
            None => ([0u8; 32], 0u8),
        };
        let _ = buf.extend_from_slice(&hash_bytes);
        let _ = buf.push(has_hash);
        let _ = buf.push(state.pw3_retries);
        let blocked = if state.pw3_retries == 0 { 1u8 } else { 0u8 };
        let _ = buf.push(blocked);

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
            private_key: heapless::Vec::new(),
            public_key: heapless::Vec::new(),
        };
        let _ = obj.private_key.extend_from_slice(&buf);
        store.save_key(&obj)
    }

    /// Load persisted OpenPGP keys and PIN state from flash.
    pub fn load_from_store(&mut self, store: &mut dyn crate::storage::KeyStore) {
        use crate::security::key_management::{AlgorithmId, KeyType as KmKeyType};
        use pico2hsm_core::key::{AppletId, KeyType as CoreKeyType};

        // Load PW1 state.
        if let Ok(Some(obj)) = store.fetch_key(OPENPGP_PW1_KEY_ID) {
            let b = &obj.private_key;
            if b.len() >= 35 {
                let has_hash = b[32] != 0;
                if has_hash {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&b[0..32]);
                    self.state.pw1_hash = Some(h);
                } else {
                    self.state.pw1_hash = None;
                }
                self.state.pw1_retries = b[33];
                // b[34] is pw1_blocked but we derive it from retries
            }
        }

        // Load PW3 state.
        if let Ok(Some(obj)) = store.fetch_key(OPENPGP_PW3_KEY_ID) {
            let b = &obj.private_key;
            if b.len() >= 35 {
                let has_hash = b[32] != 0;
                if has_hash {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&b[0..32]);
                    self.state.pw3_hash = Some(h);
                } else {
                    self.state.pw3_hash = None;
                }
                self.state.pw3_retries = b[33];
            }
        }

        // Load key objects for OpenPGP slots.
        let mut openpgp_ids: heapless::Vec<pico2hsm_core::key::KeyId, 8> = heapless::Vec::new();
        store.for_each_key(&mut |kid| {
            if kid.applet_byte() == AppletId::OpenPgp as u8 {
                let slot = kid.proto_ref();
                if slot != 0xFE && slot != 0xFF {
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

                let mut priv_vec: heapless::Vec<u8, 66> = heapless::Vec::new();
                let _ = priv_vec.extend_from_slice(&obj.private_key);
                let mut pub_vec: heapless::Vec<u8, 133> = heapless::Vec::new();
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
    fn process_apdu(&mut self, apdu: &[u8]) -> Vec<u8, 4096> {
        let resp = match ApduCommand::parse(apdu) {
            Ok(cmd) => self.dispatch(&cmd),
            Err(_) => ApduResponse::err(SW_INS_NOT_SUPPORTED),
        };
        let serialized = resp.serialize();
        let mut out: Vec<u8, 4096> = Vec::new();
        let _ = out.extend_from_slice(&serialized[..serialized.len().min(4096)]);
        out
    }

    fn handles_aid(&self, aid: &[u8]) -> bool {
        aid.len() >= OPENPGP_AID_PREFIX.len()
            && &aid[..OPENPGP_AID_PREFIX.len()] == OPENPGP_AID_PREFIX
    }

    fn protocol_name(&self) -> &'static str {
        "OpenPGP"
    }
}
