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
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
    0x03, 0x04,
    0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00,
];

/// P-256 OID bytes (1.2.840.10045.3.1.7) — used in algorithm attributes.
pub const P256_OID: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// Default algorithm attributes for ECDSA (SIG/AUTH): `13` + P-256 OID.
pub const DEFAULT_ECDSA_ALGO_ATTRS: &[u8] = &[
    0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
];

/// Default algorithm attributes for ECDH (DEC): `12` + P-256 OID.
pub const DEFAULT_ECDH_ALGO_ATTRS: &[u8] = &[
    0x12, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
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

/// OpenPGP Card protocol implementation.
pub struct OpenPgp {
    pub state: OpenPgpState,
}

impl OpenPgp {
    /// Create a new OpenPGP Card protocol instance.
    pub fn new() -> Self {
        OpenPgp {
            state: OpenPgpState::new(),
        }
    }

    /// Dispatch an already-parsed APDU to the appropriate command handler.
    fn dispatch(&mut self, cmd: &ApduCommand<'_>) -> ApduResponse {
        match cmd.ins {
            select::INS_SELECT => select::handle(&mut self.state, cmd),
            verify::INS_VERIFY => verify::handle(&mut self.state, cmd),
            change_pin::INS_CHANGE_PIN => change_pin::handle(&mut self.state, cmd),
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
            _ => ApduResponse::err(SW_INS_NOT_SUPPORTED),
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
