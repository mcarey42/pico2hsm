//! PIV (Personal Identity Verification) protocol implementation.
//!
//! Implements NIST SP 800-73-4 PIV card commands over USB CCID. This
//! protocol is activated when a SELECT AID command presents the PIV AID.
//!
//! # AID
//! `A0 00 00 03 08 00 00 10 00 01 00` — NIST PIV
//!
//! # Implemented commands
//! - SELECT (0xA4) — returns Application Property Template
//! - GET DATA (0xCB) — CHUID, CCC, Discovery Object, certificates
//! - VERIFY (0x20) — PIV PIN verification (P2=0x80)
//! - GENERATE KEY PAIR (0x47) — ECC P-256 / P-384
//! - PUT DATA (0xDB) — store certificates and data objects
//! - GENERAL AUTHENTICATE (0x87) — ECDSA sign, 3DES mutual auth (9B)
//! - CHANGE REFERENCE DATA (0x24) — change PIN or PUK
//! - RESET RETRY COUNTER (0x2C) — PUK-based PIN unblock

#[cfg(feature = "applet-piv")]
pub mod commands;

use heapless::Vec;
use pico2hsm_core::{
    apdu::{ApduCommand, ApduResponse, SW_INS_NOT_SUPPORTED},
    key::KeyType as CoreKeyType,
    protocol::HsmProtocol,
};

/// AID for NIST PIV.
pub const PIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00];

/// Maximum number of in-memory PIV key slots.
pub const MAX_PIV_KEYS: usize = 4;

/// Maximum number of stored PIV data objects (certificates, CHUID, CCC, etc.).
pub const MAX_PIV_DATA_OBJECTS: usize = 8;

/// Maximum size of a single PIV data object in bytes.
pub const MAX_PIV_DATA_SIZE: usize = 2048;

/// Default PIV PIN: "123456" (ASCII).
const DEFAULT_PIV_PIN: &[u8] = b"123456";

/// Default PIV PUK: "12345678" (ASCII).
const DEFAULT_PIV_PUK: &[u8] = b"12345678";

/// Default 3DES management key (24 bytes, three identical 8-byte DES keys).
const DEFAULT_MGMT_KEY: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

/// An in-memory (volatile) PIV asymmetric key slot.
#[cfg(feature = "applet-piv")]
pub struct InMemoryPivKey {
    /// Full u32 internal key ID (from `KeyId::piv(key_ref)`).
    pub key_id: u32,
    /// Key type (EcPrivateP256 or EcPrivateP384).
    pub key_type: CoreKeyType,
    /// PIV algorithm ID (0x11 = P-256, 0x14 = P-384).
    pub alg_id: u8,
    /// Raw private key scalar (big-endian), up to 48 bytes for P-384.
    pub private_key: heapless::Vec<u8, 66>,
    /// Uncompressed public key `04 || X || Y`, up to 97 bytes for P-384.
    pub public_key: heapless::Vec<u8, 133>,
}

/// A stored PIV data object (certificate, CHUID, CCC, etc.).
#[cfg(feature = "applet-piv")]
pub struct PivDataObject {
    /// Low byte of the 3-byte tag (e.g. 0x02 for CHUID=5FC102, 0x05 for cert 9A=5FC105).
    pub tag_low: u8,
    /// Raw data content (including the 53 wrapper for GET DATA responses).
    pub data: heapless::Vec<u8, MAX_PIV_DATA_SIZE>,
}

/// PIV protocol state.
#[cfg(feature = "applet-piv")]
pub struct PivState {
    /// PIN state managed by the shared PinState struct.
    pub pin_state: crate::security::pin::PinState,
    /// True after a successful VERIFY (session-level).
    pub pin_verified: bool,
    /// Management key (3DES, 24 bytes).
    pub mgmt_key: [u8; 24],
    /// True after successful 3DES mutual auth with management key.
    pub mgmt_key_authenticated: bool,
    /// Pending management key challenge (for mutual auth round 1).
    pub mgmt_challenge: Option<[u8; 8]>,
    /// Device ID (16 bytes, used as CHUID GUID and PBKDF2 salt).
    pub device_id: [u8; 16],
    /// In-memory asymmetric key slots.
    pub keys: heapless::Vec<InMemoryPivKey, MAX_PIV_KEYS>,
    /// Stored data objects (certificates, etc.).
    pub data_objects: heapless::Vec<PivDataObject, MAX_PIV_DATA_OBJECTS>,
}

#[cfg(feature = "applet-piv")]
impl PivState {
    /// Create a new PIV state with default PIN/PUK and management key.
    pub fn new() -> Self {
        // Generate deterministic salts for the default state.
        // On real hardware, these would be random. For initial setup,
        // we use fixed salts that will be replaced on first PIN change.
        let pin_salt = [0x50, 0x49, 0x56, 0x2D, 0x70, 0x69, 0x6E, 0x2D,
                        0x73, 0x61, 0x6C, 0x74, 0x2D, 0x76, 0x31, 0x00]; // "PIV-pin-salt-v1\0"
        let puk_salt = [0x50, 0x49, 0x56, 0x2D, 0x70, 0x75, 0x6B, 0x2D,
                        0x73, 0x61, 0x6C, 0x74, 0x2D, 0x76, 0x31, 0x00]; // "PIV-puk-salt-v1\0"
        let device_id = [0u8; 16]; // Will be overwritten by caller

        let pin_state = crate::security::pin::PinState::new(
            DEFAULT_PIV_PIN,
            DEFAULT_PIV_PUK,
            &device_id,
            pin_salt,
            puk_salt,
            crate::security::pin::MAX_PIN_RETRIES,
            crate::security::pin::MAX_PUK_RETRIES,
        ).expect("default PIV PIN/PUK must be valid");

        PivState {
            pin_state,
            pin_verified: false,
            mgmt_key: DEFAULT_MGMT_KEY,
            mgmt_key_authenticated: false,
            mgmt_challenge: None,
            device_id,
            keys: heapless::Vec::new(),
            data_objects: heapless::Vec::new(),
        }
    }
}

/// PIV protocol implementation.
pub struct Piv {
    #[cfg(feature = "applet-piv")]
    pub state: PivState,
}

impl Piv {
    /// Create a new PIV protocol instance.
    pub fn new() -> Self {
        Piv {
            #[cfg(feature = "applet-piv")]
            state: PivState::new(),
        }
    }

    /// Dispatch a parsed APDU to the appropriate PIV command handler.
    #[cfg(feature = "applet-piv")]
    fn dispatch(&mut self, cmd: &ApduCommand<'_>) -> ApduResponse {
        use commands::*;

        match cmd.ins {
            select::INS_SELECT => select::handle(cmd),
            get_data::INS_GET_DATA => get_data::handle(&self.state, cmd),
            verify::INS_VERIFY => verify::handle(&mut self.state, cmd),
            generate_keypair::INS_GENERATE_KEYPAIR => {
                generate_keypair::handle(&mut self.state, cmd)
            }
            put_data::INS_PUT_DATA => put_data::handle(&mut self.state, cmd),
            general_authenticate::INS_GENERAL_AUTHENTICATE => {
                general_authenticate::handle(&mut self.state, cmd)
            }
            change_reference_data::INS_CHANGE_REFERENCE_DATA => {
                change_reference_data::handle(&mut self.state, cmd)
            }
            reset_retry_counter::INS_RESET_RETRY_COUNTER => {
                reset_retry_counter::handle(&mut self.state, cmd)
            }
            _ => ApduResponse::err(SW_INS_NOT_SUPPORTED),
        }
    }

    /// KeyId for the PIV PIN/PUK record sentinel.
    #[cfg(feature = "applet-piv")]
    pub fn piv_pin_key_id() -> pico2hsm_core::key::KeyId {
        pico2hsm_core::key::KeyId(0x000100FF)
    }

    /// Serialize and persist the PIV PIN/PUK state to flash.
    ///
    /// Stored as a Generic key object at `KeyId::piv(0xFF)`.
    /// Layout (101 bytes total):
    ///   [0..32]  pin_hash
    ///   [32..48] pin_salt
    ///   [48]     pin_retries_remaining
    ///   [49]     pin_max_retries
    ///   [50]     pin_blocked as u8
    ///   [51..83] puk_hash
    ///   [83..99] puk_salt
    ///   [99]     puk_retries_remaining
    ///   [100]    puk_blocked as u8
    #[cfg(feature = "applet-piv")]
    pub fn save_pin_to_store(state: &PivState, store: &mut dyn crate::storage::KeyStore) {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
        use pico2hsm_core::key::AppletId;

        let ps = &state.pin_state;
        let mut buf: heapless::Vec<u8, 128> = heapless::Vec::new();
        let _ = buf.extend_from_slice(&ps.pin_hash);
        let _ = buf.extend_from_slice(&ps.pin_salt);
        let _ = buf.push(ps.pin_retries_remaining);
        let _ = buf.push(ps.pin_max_retries);
        let _ = buf.push(ps.pin_blocked as u8);
        let _ = buf.extend_from_slice(&ps.puk_hash);
        let _ = buf.extend_from_slice(&ps.puk_salt);
        let _ = buf.push(ps.puk_retries_remaining);
        let _ = buf.push(ps.puk_blocked as u8);

        let mut obj = KeyObject {
            key_type: KmKeyType::Generic,
            key_id: Self::piv_pin_key_id().0,
            owner: AppletId::Piv,
            algorithm: AlgorithmId::AesGcm,
            key_domain: 0,
            use_count: 0,
            generation: 0,
            timestamp_ms: 0,
            private_key: heapless::Vec::new(),
            public_key: heapless::Vec::new(),
        };
        let _ = obj.private_key.extend_from_slice(&buf);
        let _ = store.save_key(&obj);
    }

    /// Load PIN/PUK state from flash into `state`.
    #[cfg(feature = "applet-piv")]
    fn load_pin_state_from_store(state: &mut PivState, store: &mut dyn crate::storage::KeyStore) {
        let kid = Self::piv_pin_key_id();
        if let Ok(Some(obj)) = store.fetch_key(kid) {
            let b = &obj.private_key;
            if b.len() >= 101 {
                state.pin_state.pin_hash.copy_from_slice(&b[0..32]);
                state.pin_state.pin_salt.copy_from_slice(&b[32..48]);
                state.pin_state.pin_retries_remaining = b[48];
                state.pin_state.pin_max_retries = b[49];
                state.pin_state.pin_blocked = b[50] != 0;
                state.pin_state.puk_hash.copy_from_slice(&b[51..83]);
                state.pin_state.puk_salt.copy_from_slice(&b[83..99]);
                state.pin_state.puk_retries_remaining = b[99];
                state.pin_state.puk_blocked = b[100] != 0;
            }
        }
    }

    /// Dispatch a parsed APDU using the store-aware path for mutations.
    #[cfg(feature = "applet-piv")]
    fn dispatch_with_store(
        &mut self,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        use commands::*;
        match cmd.ins {
            generate_keypair::INS_GENERATE_KEYPAIR => {
                generate_keypair::handle_with_store(&mut self.state, store, cmd)
            }
            verify::INS_VERIFY => {
                verify::handle_with_store(&mut self.state, store, cmd)
            }
            change_reference_data::INS_CHANGE_REFERENCE_DATA => {
                change_reference_data::handle_with_store(&mut self.state, store, cmd)
            }
            reset_retry_counter::INS_RESET_RETRY_COUNTER => {
                reset_retry_counter::handle_with_store(&mut self.state, store, cmd)
            }
            _ => self.dispatch(cmd),
        }
    }

    /// Process a raw APDU with access to persistent storage.
    pub fn process_apdu_with_store(
        &mut self,
        apdu: &[u8],
        store: &mut dyn crate::storage::KeyStore,
    ) -> Vec<u8, 4096> {
        #[cfg(feature = "applet-piv")]
        {
            let resp = match pico2hsm_core::apdu::ApduCommand::parse(apdu) {
                Ok(cmd) => self.dispatch_with_store(&cmd, store),
                Err(_) => ApduResponse::err(SW_INS_NOT_SUPPORTED),
            };
            let serialized = resp.serialize();
            let mut out: Vec<u8, 4096> = Vec::new();
            let _ = out.extend_from_slice(&serialized[..serialized.len().min(4096)]);
            out
        }
        #[cfg(not(feature = "applet-piv"))]
        {
            let resp = ApduResponse::err(SW_INS_NOT_SUPPORTED);
            let s = resp.serialize();
            let mut out: Vec<u8, 4096> = Vec::new();
            let _ = out.extend_from_slice(&s);
            out
        }
    }

    /// Load persisted PIV keys and PIN state from flash.
    pub fn load_from_store(&mut self, store: &mut dyn crate::storage::KeyStore) {
        #[cfg(feature = "applet-piv")]
        {
            // Load PIN state first.
            Self::load_pin_state_from_store(&mut self.state, store);

            // Load key objects for PIV slots.
            let ids = store.enumerate_keys();
            for kid in ids.iter() {
                // Only PIV keys (applet byte == 1), skip PIN sentinel (0xFF).
                if kid.applet_byte() != AppletId::Piv as u8 {
                    continue;
                }
                if kid.proto_ref() == 0xFF {
                    continue; // PIN record sentinel
                }

                if let Ok(Some(obj)) = store.fetch_key(*kid) {
                    use crate::security::key_management::{AlgorithmId, KeyType as KmKeyType};
                    use pico2hsm_core::key::KeyType as CoreKeyType;

                    if !matches!(obj.key_type, KmKeyType::Ec) {
                        continue;
                    }

                    let (key_type, alg_id) = match obj.algorithm {
                        AlgorithmId::EcdsaP256 | AlgorithmId::EcdhP256 => {
                            (CoreKeyType::EcPrivateP256, 0x11u8)
                        }
                        AlgorithmId::EcdsaP384 | AlgorithmId::EcdhP384 => {
                            (CoreKeyType::EcPrivateP384, 0x14u8)
                        }
                        _ => continue,
                    };

                    let mut entry = InMemoryPivKey {
                        key_id: kid.0,
                        key_type,
                        alg_id,
                        private_key: heapless::Vec::new(),
                        public_key: heapless::Vec::new(),
                    };
                    let _ = entry.private_key.extend_from_slice(&obj.private_key);
                    let _ = entry.public_key.extend_from_slice(&obj.public_key);
                    // Replace any existing key in this slot.
                    self.state.keys.retain(|k| k.key_id != kid.0);
                    let _ = self.state.keys.push(entry);
                }
            }
        }
    }
}

// Re-export AppletId for use in load_from_store.
#[cfg(feature = "applet-piv")]
use pico2hsm_core::key::AppletId;

impl HsmProtocol for Piv {
    fn process_apdu(&mut self, apdu: &[u8]) -> Vec<u8, 4096> {
        #[cfg(feature = "applet-piv")]
        {
            let resp = match ApduCommand::parse(apdu) {
                Ok(cmd) => self.dispatch(&cmd),
                Err(_) => ApduResponse::err(SW_INS_NOT_SUPPORTED),
            };
            let serialized = resp.serialize();
            let mut out: Vec<u8, 4096> = Vec::new();
            let _ = out.extend_from_slice(&serialized[..serialized.len().min(4096)]);
            out
        }

        #[cfg(not(feature = "applet-piv"))]
        {
            let resp = ApduResponse::err(SW_INS_NOT_SUPPORTED);
            let s = resp.serialize();
            let mut out = Vec::new();
            let _ = out.extend_from_slice(&s);
            out
        }
    }

    fn handles_aid(&self, aid: &[u8]) -> bool {
        aid == PIV_AID
    }

    fn protocol_name(&self) -> &'static str {
        "PIV"
    }
}
