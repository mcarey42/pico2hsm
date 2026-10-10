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
pub const PIV_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

/// Maximum number of in-memory PIV key slots.
pub const MAX_PIV_KEYS: usize = 4;

/// Maximum number of stored PIV data objects (certificates, CHUID, CCC, etc.).
/// Reduced from 8 to 4 to save ~8 KB BSS (each object contains a 2048-byte
/// inline Vec).  PIV only needs: CHUID, CCC, printed info, and one certificate.
pub const MAX_PIV_DATA_OBJECTS: usize = 4;

/// Maximum size of a single PIV data object in bytes.
pub const MAX_PIV_DATA_SIZE: usize = 2048;

/// Default PIV PIN: "123456" (ASCII).
const DEFAULT_PIV_PIN: &[u8] = b"123456";

/// Default PIV PUK: "12345678" (ASCII).
const DEFAULT_PIV_PUK: &[u8] = b"12345678";

/// Default 3DES management key (24 bytes, three identical 8-byte DES keys).
const DEFAULT_MGMT_KEY: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

/// An in-memory (volatile) PIV asymmetric key slot.
/// DEPRECATED: retained for type definition only; no longer used by command handlers.
#[cfg(feature = "applet-piv")]
#[allow(dead_code)]
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
    /// Lightweight metadata index for PIV key slots (mirrors SC-HSM key_index).
    pub key_index: heapless::Vec<crate::protocol::sc_hsm::KeyMeta, MAX_PIV_KEYS>,
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
        let pin_salt = [
            0x50, 0x49, 0x56, 0x2D, 0x70, 0x69, 0x6E, 0x2D, 0x73, 0x61, 0x6C, 0x74, 0x2D, 0x76,
            0x31, 0x00,
        ]; // "PIV-pin-salt-v1\0"
        let puk_salt = [
            0x50, 0x49, 0x56, 0x2D, 0x70, 0x75, 0x6B, 0x2D, 0x73, 0x61, 0x6C, 0x74, 0x2D, 0x76,
            0x31, 0x00,
        ]; // "PIV-puk-salt-v1\0"
        let device_id = [0u8; 16]; // Will be overwritten by caller

        let pin_state = crate::security::pin::PinState::new(
            DEFAULT_PIV_PIN,
            DEFAULT_PIV_PUK,
            &device_id,
            pin_salt,
            puk_salt,
            crate::security::pin::MAX_PIN_RETRIES,
            crate::security::pin::MAX_PUK_RETRIES,
        )
        .expect("default PIV PIN/PUK must be valid");

        PivState {
            pin_state,
            pin_verified: false,
            mgmt_key: DEFAULT_MGMT_KEY,
            mgmt_key_authenticated: false,
            mgmt_challenge: None,
            device_id,
            key_index: heapless::Vec::new(),
            data_objects: heapless::Vec::new(),
        }
    }
}

/// PIV protocol implementation.
pub struct Piv {
    #[cfg(feature = "applet-piv")]
    pub state: PivState,
}

/// A persistent PIV retry counter spent by a credential-checking APDU.
#[cfg(feature = "applet-piv")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PivRetryCounter {
    Pin,
    Puk,
}

#[cfg(feature = "applet-piv")]
impl PivRetryCounter {
    fn spent_by(cmd: &ApduCommand<'_>) -> Option<Self> {
        use commands::*;
        if cmd.data.is_empty() {
            return None;
        }
        match (cmd.ins, cmd.p2) {
            (verify::INS_VERIFY, 0x80) => Some(Self::Pin),
            (change_reference_data::INS_CHANGE_REFERENCE_DATA, 0x80) => Some(Self::Pin),
            (change_reference_data::INS_CHANGE_REFERENCE_DATA, 0x81) => Some(Self::Puk),
            (reset_retry_counter::INS_RESET_RETRY_COUNTER, _) => Some(Self::Puk),
            _ => None,
        }
    }

    /// (retries remaining, blocked flag) for this counter.
    fn get(self, state: &mut PivState) -> (&mut u8, &mut bool) {
        let ps = &mut state.pin_state;
        match self {
            Self::Pin => (&mut ps.pin_retries_remaining, &mut ps.pin_blocked),
            Self::Puk => (&mut ps.puk_retries_remaining, &mut ps.puk_blocked),
        }
    }
}

impl Piv {
    /// Create a new PIV protocol instance.
    pub fn new() -> Self {
        Piv {
            #[cfg(feature = "applet-piv")]
            state: PivState::new(),
        }
    }

    /// Initialise a `Piv` directly into a destination pointer, writing
    /// each field individually to avoid an ~8 KB stack temporary.
    ///
    /// `PivState` contains `data_objects: Vec<PivDataObject, 4>` where each
    /// element holds `Vec<u8, 2048>`.  Constructing the full struct via
    /// `PivState::new()` places ~8 KB on the caller's stack, which overflows
    /// core0 on boards with display framebuffers (observed on rp2350_geek_16m).
    ///
    /// `#[inline(never)]` ensures this frame stays separate from
    /// `Dispatcher::init_in_place`.
    #[cfg(feature = "applet-piv")]
    #[inline(never)]
    pub fn init_in_place(dest: *mut Self) {
        use core::ptr::addr_of_mut;

        let device_id = [0u8; 16];
        let pin_salt = [
            0x50, 0x49, 0x56, 0x2D, 0x70, 0x69, 0x6E, 0x2D, 0x73, 0x61, 0x6C, 0x74, 0x2D, 0x76,
            0x31, 0x00,
        ];
        let puk_salt = [
            0x50, 0x49, 0x56, 0x2D, 0x70, 0x75, 0x6B, 0x2D, 0x73, 0x61, 0x6C, 0x74, 0x2D, 0x76,
            0x31, 0x00,
        ];

        let pin_state = crate::security::pin::PinState::new(
            DEFAULT_PIV_PIN,
            DEFAULT_PIV_PUK,
            &device_id,
            pin_salt,
            puk_salt,
            crate::security::pin::MAX_PIN_RETRIES,
            crate::security::pin::MAX_PUK_RETRIES,
        )
        .expect("default PIV PIN/PUK must be valid");

        unsafe {
            let state = addr_of_mut!((*dest).state);
            addr_of_mut!((*state).pin_state).write(pin_state);
            addr_of_mut!((*state).pin_verified).write(false);
            addr_of_mut!((*state).mgmt_key).write(DEFAULT_MGMT_KEY);
            addr_of_mut!((*state).mgmt_key_authenticated).write(false);
            addr_of_mut!((*state).mgmt_challenge).write(None);
            addr_of_mut!((*state).device_id).write(device_id);
            addr_of_mut!((*state).key_index).write(heapless::Vec::new());
            addr_of_mut!((*state).data_objects).write(heapless::Vec::new());
        }
    }

    /// Initialise a `Piv` directly into a destination pointer (no-op without applet-piv).
    #[cfg(not(feature = "applet-piv"))]
    pub fn init_in_place(dest: *mut Self) {
        let _ = dest;
    }

    /// Dispatch a parsed APDU to the appropriate PIV command handler.
    ///
    /// GET RESPONSE and Le-truncation are handled by the Dispatcher.
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
    pub fn save_pin_to_store(
        state: &PivState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
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
            key_flags: 0,
            timestamp_ms: 0,
            private_key: heapless::Vec::new(),
            public_key: heapless::Vec::new(),
        };
        let _ = obj.private_key.extend_from_slice(&buf);
        store.save_key(&obj)
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
    ///
    /// GET RESPONSE and Le-truncation are handled by the Dispatcher.
    #[cfg(feature = "applet-piv")]
    fn dispatch_with_store(
        &mut self,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        match PivRetryCounter::spent_by(cmd) {
            Some(counter) => self.with_persisted_attempt(counter, cmd, store),
            None => self.route_with_store(cmd, store),
        }
    }

    /// Spend one PIN/PUK retry on flash before the handler compares the
    /// credential; see `ScHsm::with_persisted_attempt` for the rationale.
    #[cfg(feature = "applet-piv")]
    fn with_persisted_attempt(
        &mut self,
        counter: PivRetryCounter,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        let before = *counter.get(&mut self.state).0;
        if before == 0 {
            return self.route_with_store(cmd, store);
        }
        let spent = before - 1;
        *counter.get(&mut self.state).0 = spent;
        if Self::save_pin_to_store(&self.state, store).is_err() {
            return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
        }
        *counter.get(&mut self.state).0 = before;

        let resp = self.route_with_store(cmd, store);

        let (after, blocked) = counter.get(&mut self.state);
        if resp.sw != pico2hsm_core::apdu::SW_OK && *after > spent {
            *after = spent;
        }
        if *after == 0 {
            *blocked = true;
        }
        if *after != spent && Self::save_pin_to_store(&self.state, store).is_err() {
            // Keep RAM consistent with flash (spent counter, old PIN) and
            // fail closed; see ScHsm::with_persisted_attempt.
            Self::load_pin_state_from_store(&mut self.state, store);
            *counter.get(&mut self.state).0 = spent;
            self.state.pin_verified = false;
            self.state.pin_state.session_authenticated = false;
            return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
        }
        resp
    }

    /// Route an APDU to its handler with persistent storage available.
    #[cfg(feature = "applet-piv")]
    fn route_with_store(
        &mut self,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        use commands::*;

        match cmd.ins {
            generate_keypair::INS_GENERATE_KEYPAIR => {
                generate_keypair::handle_with_store(&mut self.state, store, cmd)
            }
            general_authenticate::INS_GENERAL_AUTHENTICATE => {
                general_authenticate::handle_with_store(&mut self.state, store, cmd)
            }
            // Credential checks: persistence is handled by with_persisted_attempt.
            verify::INS_VERIFY => verify::handle(&mut self.state, cmd),
            change_reference_data::INS_CHANGE_REFERENCE_DATA => {
                change_reference_data::handle(&mut self.state, cmd)
            }
            reset_retry_counter::INS_RESET_RETRY_COUNTER => {
                reset_retry_counter::handle(&mut self.state, cmd)
            }
            _ => {
                // Fall through to the non-store dispatch path.
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
            let mut piv_ids: heapless::Vec<pico2hsm_core::key::KeyId, 16> = heapless::Vec::new();
            store.for_each_key(&mut |kid| {
                if kid.applet_byte() == AppletId::Piv as u8 && kid.proto_ref() != 0xFF {
                    let _ = piv_ids.push(kid);
                }
            });
            for kid in piv_ids.iter() {
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

                    // Store lightweight metadata in key_index.
                    self.state.key_index.retain(|m| m.key_id != kid.0);
                    let meta = crate::protocol::sc_hsm::KeyMeta {
                        key_id: kid.0,
                        key_type: key_type as u8,
                        algo: alg_id,
                        key_flags: 0,
                    };
                    let _ = self.state.key_index.push(meta);
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

#[cfg(all(test, feature = "applet-piv"))]
mod retry_persistence_tests {
    use super::*;
    use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
    use pico2hsm_core::error::HsmError;
    use pico2hsm_core::key::{AppletId, KeyId};

    /// Records every PIV PIN-record write.
    struct PinStore {
        saves: heapless::Vec<heapless::Vec<u8, 128>, 16>,
    }

    impl crate::storage::KeyStore for PinStore {
        fn save_key(&mut self, obj: &KeyObject) -> Result<(), HsmError> {
            if obj.key_id == Piv::piv_pin_key_id().0 {
                let mut b = heapless::Vec::new();
                b.extend_from_slice(&obj.private_key).unwrap();
                self.saves.push(b).unwrap();
            }
            Ok(())
        }
        fn fetch_key(&mut self, kid: KeyId) -> Result<Option<KeyObject>, HsmError> {
            if kid != Piv::piv_pin_key_id() {
                return Ok(None);
            }
            Ok(self.saves.last().map(|b| {
                let mut obj = KeyObject::new(
                    KmKeyType::Generic,
                    kid.0,
                    AppletId::Piv,
                    AlgorithmId::AesGcm,
                );
                obj.private_key.extend_from_slice(b).unwrap();
                obj
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
        fn for_each_key(&self, _: &mut dyn FnMut(KeyId)) {}
    }

    fn verify(piv: &mut Piv, store: &mut PinStore, pin: &[u8]) -> u16 {
        let mut apdu: heapless::Vec<u8, 16> = heapless::Vec::new();
        apdu.extend_from_slice(&[0x00, 0x20, 0x00, 0x80, 0x08])
            .unwrap();
        apdu.extend_from_slice(pin).unwrap();
        for _ in pin.len()..8 {
            apdu.push(0xFF).unwrap();
        }
        let r = piv.process_apdu_with_store(&apdu, store);
        u16::from_be_bytes([r[r.len() - 2], r[r.len() - 1]])
    }

    #[test]
    fn piv_wrong_pin_is_spent_on_flash_and_survives_reset() {
        let mut piv = Piv::new();
        let mut store = PinStore {
            saves: heapless::Vec::new(),
        };
        let max = piv.state.pin_state.pin_retries_remaining;

        assert_ne!(verify(&mut piv, &mut store, b"999999"), 0x9000);
        assert_eq!(store.saves.len(), 1, "one write, before the compare");
        assert_eq!(store.saves[0][48], max - 1);

        let mut fresh = Piv::new();
        Piv::load_pin_state_from_store(&mut fresh.state, &mut store);
        assert_eq!(fresh.state.pin_state.pin_retries_remaining, max - 1);

        assert_eq!(verify(&mut fresh, &mut store, DEFAULT_PIV_PIN), 0x9000);
        let n = store.saves.len();
        assert_eq!(store.saves[n - 2][48], max - 2, "spent before the compare");
        assert_eq!(store.saves[n - 1][48], max, "restored after success");
    }
}
