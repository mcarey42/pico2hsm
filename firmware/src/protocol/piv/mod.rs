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
}

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
