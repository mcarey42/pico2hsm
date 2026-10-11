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

// Every PIV data object must fit a stored object, with or without `rsa`.
const _: () = assert!(MAX_PIV_DATA_SIZE <= crate::security::key_management::MAX_OBJECT_DATA_SIZE);

/// Default PIV PIN: "123456" (ASCII).
const DEFAULT_PIV_PIN: &[u8] = b"123456";

/// Default PIV PUK: "12345678" (ASCII).
const DEFAULT_PIV_PUK: &[u8] = b"12345678";

/// Default 3DES management key (24 bytes, three identical 8-byte DES keys).
/// PIV reset (Yubico extension; `ykman piv reset`).
pub const INS_PIV_RESET: u8 = 0xFB;

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
    pub private_key: Vec<u8, 66>,
    /// Uncompressed public key `04 || X || Y`, up to 97 bytes for P-384.
    pub public_key: Vec<u8, 133>,
}

/// PBKDF2 hashes of the factory-default PIN "123456" and PUK "12345678"
/// with PIV's fixed salts and an all-zero KDF context.  The inputs are all
/// constants, so these are precomputed rather than spending 2 × 10,000
/// PBKDF2 iterations at every boot and USB reset (the state is usually
/// replaced from flash immediately afterwards).  `default_hashes_match_kdf`
/// recomputes them.
const DEFAULT_PIN_HASH: [u8; 32] = [
    0x82, 0x10, 0x91, 0x6B, 0x11, 0x02, 0xE7, 0x8C, 0xB8, 0x15, 0xC7, 0xC9, 0xA8, 0x5F, 0xC7, 0xD6,
    0x63, 0xB7, 0x0C, 0xC7, 0xE9, 0x95, 0x6B, 0xF2, 0x5A, 0xCD, 0x3D, 0x3B, 0xC2, 0x9F, 0x2F, 0x74,
];
const DEFAULT_PUK_HASH: [u8; 32] = [
    0x22, 0x3B, 0x2A, 0x0C, 0x58, 0x58, 0x09, 0x21, 0xC8, 0x0E, 0x87, 0x33, 0x8E, 0x8B, 0xD6, 0x1B,
    0x90, 0x8A, 0x30, 0x5B, 0x2F, 0xC1, 0xB7, 0xFA, 0xAF, 0x4A, 0x81, 0x3F, 0xC9, 0x94, 0x60, 0xDB,
];
/// "PIV-pin-salt-v1\0" / "PIV-puk-salt-v1\0"
const DEFAULT_PIN_SALT: [u8; 16] = *b"PIV-pin-salt-v1\0";
const DEFAULT_PUK_SALT: [u8; 16] = *b"PIV-puk-salt-v1\0";

/// Factory-default PIN state, without running the KDF.
#[cfg(feature = "applet-piv")]
fn default_pin_state() -> crate::security::pin::PinState {
    use crate::security::pin::{PinState, MAX_PIN_RETRIES, MAX_PUK_RETRIES};
    PinState {
        pin_hash: DEFAULT_PIN_HASH,
        pin_salt: DEFAULT_PIN_SALT,
        pin_retries_remaining: MAX_PIN_RETRIES,
        pin_max_retries: MAX_PIN_RETRIES,
        pin_blocked: false,
        puk_hash: DEFAULT_PUK_HASH,
        puk_salt: DEFAULT_PUK_SALT,
        puk_retries_remaining: MAX_PUK_RETRIES,
        puk_blocked: false,
        session_authenticated: false,
        session_key: None,
    }
}

/// A stored PIV data object (certificate, CHUID, CCC, etc.).
#[cfg(feature = "applet-piv")]
#[derive(Clone)]
pub struct PivDataObject {
    /// Low byte of the 3-byte tag (e.g. 0x02 for CHUID=5FC102, 0x05 for cert 9A=5FC105).
    pub tag_low: u8,
    /// Raw data content (including the 53 wrapper for GET DATA responses).
    pub data: Vec<u8, MAX_PIV_DATA_SIZE>,
}

/// PIV protocol state.
#[cfg(feature = "applet-piv")]
pub struct PivState {
    /// PIN state managed by the shared PinState struct.
    pub pin_state: crate::security::pin::PinState,
    /// True after a successful VERIFY (session-level).
    pub pin_verified: bool,
    /// The PIN was verified by the immediately preceding command: slot 9C
    /// is "PIN always" (SP 800-73-4), one signature per VERIFY.
    pub pin_always_ok: bool,
    /// Management key (3DES, 24 bytes).
    pub mgmt_key: [u8; 24],
    /// True after successful 3DES mutual auth with management key.
    pub mgmt_key_authenticated: bool,
    /// Pending management key challenge (for mutual auth round 1).
    pub mgmt_challenge: Option<[u8; 8]>,
    /// Device ID (16 bytes, used as CHUID GUID and PBKDF2 salt).
    pub device_id: [u8; 16],
    /// Lightweight metadata index for PIV key slots (mirrors SC-HSM key_index).
    pub key_index: Vec<crate::protocol::sc_hsm::KeyMeta, MAX_PIV_KEYS>,
    /// Stored data objects (certificates, etc.).
    pub data_objects: Vec<PivDataObject, MAX_PIV_DATA_OBJECTS>,
    /// The PIN and management-key records are on flash.  They must be
    /// before any key or data object is: on load, missing records next to
    /// stored content mean tampering, not a fresh applet (see
    /// `load_pin_state_from_store`).
    pub credentials_persisted: bool,
}

#[cfg(feature = "applet-piv")]
impl PivState {
    /// Create a new PIV state with default PIN/PUK and management key.
    pub fn new() -> Self {
        // Generate deterministic salts for the default state.
        // On real hardware, these would be random. For initial setup,
        // we use fixed salts that will be replaced on first PIN change.
        let device_id = [0u8; 16]; // PIN KDF context (see chuid_guid for the GUID)
        let pin_state = default_pin_state();

        PivState {
            pin_state,
            pin_verified: false,
            pin_always_ok: false,
            mgmt_key: DEFAULT_MGMT_KEY,
            mgmt_key_authenticated: false,
            mgmt_challenge: None,
            device_id,
            key_index: Vec::new(),
            data_objects: Vec::new(),
            credentials_persisted: false,
        }
    }

    /// No credential is usable: PIN and PUK blocked, management key
    /// unknown.  The only way out is the PIV reset (INS FB), which wipes
    /// the applet.
    pub fn lock_out(&mut self) {
        let ps = &mut self.pin_state;
        ps.pin_retries_remaining = 0;
        ps.pin_blocked = true;
        ps.puk_retries_remaining = 0;
        ps.puk_blocked = true;
        self.pin_verified = false;
        self.mgmt_key_authenticated = false;
        // Not the public default: an unknown key nobody can authenticate with.
        #[cfg(target_arch = "arm")]
        crate::crypto::rng::fill_or_reset(&mut self.mgmt_key);
        #[cfg(not(target_arch = "arm"))]
        {
            self.mgmt_key = [0x5A; 24];
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
    /// The counter `cmd` would spend; malformed APDUs (rejected by the
    /// handler before any comparison) spend nothing.
    fn spent_by(cmd: &ApduCommand<'_>) -> Option<Self> {
        use commands::*;
        let n = cmd.data.len();
        match (cmd.ins, cmd.p1, cmd.p2) {
            (verify::INS_VERIFY, 0x00, 0x80)
                if n == 8 && change_reference_data::valid_new_pin(cmd.data) =>
            {
                Some(Self::Pin)
            }
            // Mirrors the handlers' checks before the compare, so a
            // malformed request is refused without spending a retry.
            (change_reference_data::INS_CHANGE_REFERENCE_DATA, 0x00, 0x80)
                if n == 16
                    && change_reference_data::valid_new_pin(&cmd.data[..8])
                    && change_reference_data::valid_new_pin(&cmd.data[8..]) =>
            {
                Some(Self::Pin)
            }
            (change_reference_data::INS_CHANGE_REFERENCE_DATA, 0x00, 0x81)
                if n == 16 && change_reference_data::valid_new_puk(&cmd.data[8..]) =>
            {
                Some(Self::Puk)
            }
            (reset_retry_counter::INS_RESET_RETRY_COUNTER, 0x00, 0x80)
                if n == 16 && change_reference_data::valid_new_pin(&cmd.data[8..]) =>
            {
                Some(Self::Puk)
            }
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

    /// Its entry in the retry-counter log.
    fn credential(self) -> Credential {
        match self {
            Self::Pin => Credential::PivPin,
            Self::Puk => Credential::PivPuk,
        }
    }

    const ALL: [Self; 2] = [Self::Pin, Self::Puk];
}

#[cfg(feature = "applet-piv")]
use crate::storage::retry_counter::{self, CounterState, Credential};

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
    ///
    /// # Safety
    /// `dest` must be non-null, aligned and valid for writes of `Self`.  Any
    /// value already there is overwritten without being dropped.
    #[cfg(feature = "applet-piv")]
    #[inline(never)]
    pub unsafe fn init_in_place(dest: *mut Self) {
        use core::ptr::addr_of_mut;

        let device_id = [0u8; 16]; // PIN KDF context (see chuid_guid for the GUID)
        let pin_state = default_pin_state();

        unsafe {
            let state = addr_of_mut!((*dest).state);
            addr_of_mut!((*state).pin_state).write(pin_state);
            addr_of_mut!((*state).pin_verified).write(false);
            addr_of_mut!((*state).pin_always_ok).write(false);
            addr_of_mut!((*state).credentials_persisted).write(false);
            addr_of_mut!((*state).mgmt_key).write(DEFAULT_MGMT_KEY);
            addr_of_mut!((*state).mgmt_key_authenticated).write(false);
            addr_of_mut!((*state).mgmt_challenge).write(None);
            addr_of_mut!((*state).device_id).write(device_id);
            addr_of_mut!((*state).key_index).write(Vec::new());
            addr_of_mut!((*state).data_objects).write(Vec::new());
        }
    }

    /// Initialise a `Piv` directly into a destination pointer (no-op without applet-piv).
    ///
    /// # Safety
    /// `dest` must be non-null, aligned and valid for writes of `Self`.  Any
    /// value already there is overwritten without being dropped.
    #[cfg(not(feature = "applet-piv"))]
    pub unsafe fn init_in_place(dest: *mut Self) {
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

    /// KeyId of a persisted PIV data object (`5FC1xx` / `7E`): 0xD0 in
    /// bits 15–8 keeps these apart from the key slots (bits 15–8 = 0).
    pub fn piv_data_object_key_id(tag_low: u8) -> pico2hsm_core::key::KeyId {
        pico2hsm_core::key::KeyId(pico2hsm_core::key::KeyId::piv(tag_low).0 | 0xD000)
    }

    /// Persist one PIV data object (keystore-encrypted like keys).
    #[cfg(feature = "applet-piv")]
    pub fn save_data_object_to_store(
        obj: &PivDataObject,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
        use pico2hsm_core::key::AppletId;
        let mut rec = KeyObject::new(
            KmKeyType::Generic,
            Self::piv_data_object_key_id(obj.tag_low).0,
            AppletId::Piv,
            AlgorithmId::AesGcm,
        );
        rec.private_key
            .extend_from_slice(&obj.data)
            .map_err(|_| pico2hsm_core::error::HsmError::InvalidInput)?;
        store.save_key(&rec)
    }

    /// KeyId of the persisted management key (slot reference 9B).
    pub fn piv_mgmt_key_id() -> pico2hsm_core::key::KeyId {
        pico2hsm_core::key::KeyId::piv(0x9B)
    }

    /// Persist the management key (keystore-encrypted, like any key).
    #[cfg(feature = "applet-piv")]
    pub fn save_mgmt_key_to_store(
        state: &PivState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
        use pico2hsm_core::key::AppletId;
        let mut obj = KeyObject::new(
            KmKeyType::Generic,
            Self::piv_mgmt_key_id().0,
            AppletId::Piv,
            AlgorithmId::AesGcm,
        );
        let _ = obj.private_key.extend_from_slice(&state.mgmt_key);
        store.save_key(&obj)
    }

    /// Serialize the PIV PIN/PUK record.
    ///
    /// Stored as a Generic key object at `KeyId::piv(0xFF)`.
    /// Layout (101 bytes total):
    ///   [0..32]  pin_hash
    ///   [32..48] pin_salt
    ///   [48]     0 (was pin_retries_remaining)
    ///   [49]     pin_max_retries
    ///   [50]     1 (was pin_blocked)
    ///   [51..83] puk_hash
    ///   [83..99] puk_salt
    ///   [99]     0 (was puk_retries_remaining)
    ///   [100]    1 (was puk_blocked)
    ///
    /// The retry counters live in the retry-counter log
    /// (`storage::retry_counter`); records from before it are migrated and
    /// zeroed at boot, so a record never carries a usable count.
    #[cfg(feature = "applet-piv")]
    fn pin_record(state: &PivState) -> zeroize::Zeroizing<Vec<u8, 128>> {
        let ps = &state.pin_state;
        let mut buf: zeroize::Zeroizing<Vec<u8, 128>> = zeroize::Zeroizing::new(Vec::new());
        let _ = buf.extend_from_slice(&ps.pin_hash);
        let _ = buf.extend_from_slice(&ps.pin_salt);
        let _ = buf.push(0);
        let _ = buf.push(ps.pin_max_retries);
        let _ = buf.push(1);
        let _ = buf.extend_from_slice(&ps.puk_hash);
        let _ = buf.extend_from_slice(&ps.puk_salt);
        let _ = buf.push(0);
        let _ = buf.push(1);
        buf
    }

    /// Byte offsets of the legacy (count, blocked flag) pairs in a record.
    #[cfg(feature = "applet-piv")]
    const LEGACY_COUNT_AT: [(PivRetryCounter, usize, usize); 2] = [
        (PivRetryCounter::Pin, 48, 50),
        (PivRetryCounter::Puk, 99, 100),
    ];

    /// Persist the PIV PIN/PUK state: the retry counters first, then the
    /// record (see `ScHsm::save_pin_to_store` for the order).
    #[cfg(feature = "applet-piv")]
    pub fn save_pin_to_store(
        state: &PivState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
        use pico2hsm_core::key::AppletId;

        Self::sync_counters(state, store)?;
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
            private_key: Vec::new(),
            public_key: Vec::new(),
            policy: Default::default(),
        };
        let _ = obj.private_key.extend_from_slice(&Self::pin_record(state));
        store.save_key(&obj)
    }

    /// Write the PIN and PUK counters where RAM differs from the log.
    #[cfg(feature = "applet-piv")]
    fn sync_counters(
        state: &PivState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        let ps = &state.pin_state;
        retry_counter::set(store, Credential::PivPin, ps.pin_retries_remaining)?;
        retry_counter::set(store, Credential::PivPuk, ps.puk_retries_remaining)
    }

    /// Set the RAM counters (and blocked flags) from the log; see
    /// `retry_counter::load` for `record_exists`.
    #[cfg(feature = "applet-piv")]
    fn load_counters(
        state: &mut PivState,
        store: &mut dyn crate::storage::KeyStore,
        record_exists: bool,
    ) {
        for c in PivRetryCounter::ALL {
            let (n, blocked) = c.get(state);
            *n = retry_counter::load(store, c.credential(), record_exists, *n);
            *blocked = *n == 0;
        }
    }

    /// Load PIN/PUK and management key from flash into `state` (boot and
    /// reset only: needs a store that can enumerate keys, i.e. core0's).
    #[cfg(feature = "applet-piv")]
    fn load_credentials_from_store(state: &mut PivState, store: &mut dyn crate::storage::KeyStore) {
        // A missing record is a fresh applet only while the applet stores
        // nothing; the records are written before its first key or object.
        // Missing next to stored content, unreadable, or malformed means
        // the flash was tampered with (the directory has no MAC): fail
        // closed instead of falling back to the public factory defaults.
        let mut has_content = false;
        let pin_kid = Self::piv_pin_key_id();
        let mgmt_kid = Self::piv_mgmt_key_id();
        store.for_each_key(&mut |kid| {
            if kid.applet_byte() == AppletId::Piv as u8 && kid != pin_kid && kid != mgmt_kid {
                has_content = true;
            }
        });
        let pin = store.fetch_key(pin_kid);
        let mgmt = store.fetch_key(mgmt_kid);
        let pin_ok = matches!(&pin, Ok(Some(o)) if o.private_key.len() >= 101);
        let mgmt_ok = matches!(&mgmt, Ok(Some(o)) if o.private_key.len() == 24);
        let pin_fresh = matches!(pin, Ok(None)) && !has_content;
        let mgmt_fresh = matches!(mgmt, Ok(None)) && !has_content;
        if !(pin_ok || pin_fresh) || !(mgmt_ok || mgmt_fresh) {
            state.lock_out();
            state.credentials_persisted = true;
            return;
        }
        state.credentials_persisted = pin_ok && mgmt_ok;
        if let Ok(Some(obj)) = mgmt {
            if mgmt_ok {
                state.mgmt_key.copy_from_slice(&obj.private_key);
            }
        }
        if let Ok(Some(obj)) = pin {
            Self::apply_pin_record(state, &obj.private_key);
        }
        Self::load_counters(state, store, pin_ok);
    }

    /// Runtime rollback after a failed save: put RAM back to what flash
    /// holds.  Only the PIN record and counters — the management key is
    /// untouched.  If the record can't be read, PIN and PUK are blocked
    /// rather than left at whatever the failed command put in RAM.
    #[cfg(feature = "applet-piv")]
    fn restore_pin_record(state: &mut PivState, store: &mut dyn crate::storage::KeyStore) {
        match store.fetch_key(Self::piv_pin_key_id()) {
            Ok(Some(obj)) if Self::apply_pin_record(state, &obj.private_key) => {
                Self::load_counters(state, store, false);
            }
            Ok(None) if !state.credentials_persisted => {
                // Never persisted: flash holds the factory credentials.
                let d = default_pin_state();
                let ps = &mut state.pin_state;
                (ps.pin_hash, ps.pin_salt) = (d.pin_hash, d.pin_salt);
                (ps.puk_hash, ps.puk_salt) = (d.puk_hash, d.puk_salt);
                ps.pin_max_retries = d.pin_max_retries;
                Self::load_counters(state, store, false);
            }
            _ => {
                let ps = &mut state.pin_state;
                ps.pin_retries_remaining = 0;
                ps.pin_blocked = true;
                ps.puk_retries_remaining = 0;
                ps.puk_blocked = true;
            }
        }
    }

    /// Decode a PIN record (layout: `pin_record`) into `state`.  The
    /// counters come from the retry-counter log, not from the record.
    #[cfg(feature = "applet-piv")]
    fn apply_pin_record(state: &mut PivState, b: &[u8]) -> bool {
        if b.len() < 101 {
            return false;
        }
        let ps = &mut state.pin_state;
        ps.pin_hash.copy_from_slice(&b[0..32]);
        ps.pin_salt.copy_from_slice(&b[32..48]);
        ps.pin_max_retries = b[49];
        ps.puk_hash.copy_from_slice(&b[51..83]);
        ps.puk_salt.copy_from_slice(&b[83..99]);
        true
    }

    /// Migration: seeds for the retry-counter log from a pre-log PIN
    /// record (see `ScHsm::legacy_retry_seeds`).
    #[cfg(feature = "applet-piv")]
    pub fn legacy_retry_seeds(
        store: &mut dyn crate::storage::KeyStore,
        seeds: &mut Vec<(Credential, CounterState), 8>,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        let Some(obj) = store.fetch_key(Self::piv_pin_key_id())? else {
            return Ok(());
        };
        let b = &obj.private_key;
        for (c, at, blocked_at) in Self::LEGACY_COUNT_AT {
            let n = if b.len() >= 101 && b[blocked_at] == 0 {
                b[at]
            } else {
                0
            };
            seeds
                .push((c.credential(), CounterState::fresh(n)))
                .map_err(|_| pico2hsm_core::error::HsmError::InvalidInput)?;
        }
        Ok(())
    }

    /// Migration, after the log is committed: zero the record's counts.
    #[cfg(feature = "applet-piv")]
    pub fn clear_legacy_retry_counts(
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), pico2hsm_core::error::HsmError> {
        let Some(mut obj) = store.fetch_key(Self::piv_pin_key_id())? else {
            return Ok(());
        };
        let b = &mut obj.private_key;
        let cleared = |b: &[u8]| {
            Self::LEGACY_COUNT_AT
                .iter()
                .all(|&(_, at, blocked_at)| b[at] == 0 && b[blocked_at] == 1)
        };
        if b.len() < 101 || cleared(b) {
            return Ok(());
        }
        for (_, at, blocked_at) in Self::LEGACY_COUNT_AT {
            b[at] = 0;
            b[blocked_at] = 1;
        }
        store.save_key(&obj)
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
        // "PIN always" covers only the command right after VERIFY.
        if cmd.ins != commands::verify::INS_VERIFY
            && cmd.ins != commands::general_authenticate::INS_GENERAL_AUTHENTICATE
        {
            self.state.pin_always_ok = false;
        }
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
        let ram = *counter.get(&mut self.state).0;
        if ram == 0 {
            // No retries left: blocked, whatever the flag says.  Never reach
            // a compare that would not be paid for.
            return ApduResponse::err(0x6983);
        }
        let before = match retry_counter::spend(store, counter.credential(), ram) {
            Ok(available) => available.min(ram),
            Err(_) => return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE),
        };
        if before == 0 {
            // The log says blocked: nothing spent, nothing compared.
            let (n, blocked) = counter.get(&mut self.state);
            (*n, *blocked) = (0, true);
            return ApduResponse::err(0x6983);
        }
        *counter.get(&mut self.state).0 = before;
        let spent = before - 1;
        let record_before = Self::pin_record(&self.state);

        let resp = self.route_with_store(cmd, store);

        if resp.sw != pico2hsm_core::apdu::SW_OK {
            // The failure is on flash already; RAM follows the log.
            Self::load_counters(&mut self.state, store, false);
            let (after, blocked) = counter.get(&mut self.state);
            if *after > spent {
                *after = spent;
            }
            *blocked = *after == 0;
            return resp;
        }
        let (after, blocked) = counter.get(&mut self.state);
        if *after == 0 {
            *blocked = true;
        }
        let persisted = if *Self::pin_record(&self.state) != *record_before {
            Self::save_pin_to_store(&self.state, store)
        } else {
            Self::sync_counters(&self.state, store)
        };
        if persisted.is_err() {
            // Keep RAM consistent with flash (spent counter, old PIN) and
            // fail closed; see ScHsm::with_persisted_attempt.
            Self::restore_pin_record(&mut self.state, store);
            self.state.pin_verified = false;
            self.state.pin_always_ok = false;
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
            set_management_key::INS_SET_MGMT_KEY => {
                // Wiped when dropped, like the key itself.
                let old = zeroize::Zeroizing::new(self.state.mgmt_key);
                let resp = set_management_key::handle(&mut self.state, cmd);
                if resp.sw == pico2hsm_core::apdu::SW_OK
                    && Self::save_mgmt_key_to_store(&self.state, store).is_err()
                {
                    // Keep RAM consistent with flash.
                    self.state.mgmt_key = *old;
                    return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
                }
                resp
            }
            put_data::INS_PUT_DATA | generate_keypair::INS_GENERATE_KEYPAIR
                if self.state.mgmt_key_authenticated && !self.state.credentials_persisted =>
            {
                // First content for this applet: its credentials go to flash
                // first (see `PivState::credentials_persisted`).
                if Self::save_pin_to_store(&self.state, store).is_err()
                    || Self::save_mgmt_key_to_store(&self.state, store).is_err()
                {
                    return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
                }
                self.state.credentials_persisted = true;
                self.route_with_store(cmd, store)
            }
            put_data::INS_PUT_DATA => put_data::handle_with_store(&mut self.state, store, cmd),
            get_data::INS_GET_DATA => {
                // RAM caches a few objects; the rest are read from flash —
                // before the built-in defaults (CHUID, CCC), which a stored
                // object overrides whether or not it is cached.
                if let Some(tag_low) = put_data::object_tag_low(cmd.data) {
                    let cached = self.state.data_objects.iter().any(|o| o.tag_low == tag_low);
                    let p1p2_ok = cmd.p1 == 0x3F && cmd.p2 == 0xFF;
                    if !cached && p1p2_ok && get_data::readable(&self.state, tag_low) {
                        match store.fetch_key(Self::piv_data_object_key_id(tag_low)) {
                            Ok(Some(rec)) => return ApduResponse::ok(&rec.private_key),
                            Ok(None) => {}
                            // Unreadable: not the built-in default instead
                            // (a CHUID with a different GUID).
                            Err(_) => {
                                return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE)
                            }
                        }
                    }
                }
                get_data::handle(&self.state, cmd)
            }
            generate_keypair::INS_GENERATE_KEYPAIR => {
                generate_keypair::handle_with_store(&mut self.state, store, cmd)
            }
            INS_PIV_RESET => self.reset_applet(cmd, store),
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

    /// PIV reset (Yubico extension, INS FB; `ykman piv reset`): wipe every
    /// PIV key, object and credential and return to factory defaults.
    /// Allowed only once both PIN and PUK are blocked, so it can't be used
    /// to get around them — only to recover a locked-out applet.
    #[cfg(feature = "applet-piv")]
    fn reset_applet(
        &mut self,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        if cmd.p1 != 0 || cmd.p2 != 0 {
            return ApduResponse::err(0x6A86);
        }
        let ps = &self.state.pin_state;
        if ps.pin_retries_remaining != 0 || ps.puk_retries_remaining != 0 {
            return ApduResponse::err(pico2hsm_core::apdu::SW_CONDITIONS_NOT_SATISFIED);
        }
        // Flash first: if the wipe fails, RAM still says "locked out".
        if store.wipe_by_owner(AppletId::Piv).is_err() {
            return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
        }
        let st = &mut self.state;
        st.pin_state = default_pin_state();
        st.pin_verified = false;
        st.mgmt_key = DEFAULT_MGMT_KEY;
        st.mgmt_key_authenticated = false;
        st.mgmt_challenge = None;
        st.key_index.clear();
        st.data_objects.clear();
        st.credentials_persisted = false;
        // Counters last: only once the old PIN and PUK are gone may their
        // blocked counters go back to the factory allowance.
        if Self::sync_counters(&self.state, store).is_err() {
            // Wiped, but still blocked on flash: say so in RAM too; the
            // reset can simply be repeated.
            Self::load_counters(&mut self.state, store, false);
            return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
        }
        ApduResponse::ok(&[])
    }

    /// Process a raw APDU with access to persistent storage.
    pub fn process_apdu_with_store(
        &mut self,
        apdu: &[u8],
        store: &mut dyn crate::storage::KeyStore,
    ) -> Vec<u8, 4098> {
        #[cfg(feature = "applet-piv")]
        {
            let resp = match ApduCommand::parse(apdu) {
                Ok(cmd) => self.dispatch_with_store(&cmd, store),
                Err(_) => ApduResponse::err(SW_INS_NOT_SUPPORTED),
            };
            // Full serialized response: data (≤4096) + SW — never truncated.
            resp.serialize()
        }
        #[cfg(not(feature = "applet-piv"))]
        {
            let resp = ApduResponse::err(SW_INS_NOT_SUPPORTED);
            resp.serialize()
        }
    }

    /// Load persisted PIV keys and PIN state from flash.
    pub fn load_from_store(&mut self, store: &mut dyn crate::storage::KeyStore) {
        #[cfg(feature = "applet-piv")]
        {
            // PIN, PUK and management key (fail closed on tampering).
            Self::load_credentials_from_store(&mut self.state, store);

            // Load key objects for PIV slots.
            let mut piv_ids: Vec<pico2hsm_core::key::KeyId, 16> = Vec::new();
            let mut object_ids: Vec<pico2hsm_core::key::KeyId, MAX_PIV_DATA_OBJECTS> = Vec::new();
            store.for_each_key(&mut |kid| {
                if kid.applet_byte() != AppletId::Piv as u8 {
                    return;
                }
                match (kid.0 >> 8) & 0xFF {
                    0xD0 => {
                        let _ = object_ids.push(kid);
                    }
                    0x00 if kid.proto_ref() != 0xFF => {
                        let _ = piv_ids.push(kid);
                    }
                    _ => {}
                }
            });
            for kid in object_ids.iter() {
                if let Ok(Some(rec)) = store.fetch_key(*kid) {
                    let mut data = Vec::new();
                    if data.extend_from_slice(&rec.private_key).is_ok() {
                        let tag_low = kid.proto_ref();
                        self.state.data_objects.retain(|o| o.tag_low != tag_low);
                        let _ = self
                            .state
                            .data_objects
                            .push(PivDataObject { tag_low, data });
                    }
                }
            }
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
    fn process_apdu(&mut self, apdu: &[u8]) -> Vec<u8, 4098> {
        #[cfg(feature = "applet-piv")]
        {
            let resp = match ApduCommand::parse(apdu) {
                Ok(cmd) => self.dispatch(&cmd),
                Err(_) => ApduResponse::err(SW_INS_NOT_SUPPORTED),
            };
            // Full serialized response: data (≤4096) + SW — never truncated.
            resp.serialize()
        }

        #[cfg(not(feature = "applet-piv"))]
        {
            let resp = ApduResponse::err(SW_INS_NOT_SUPPORTED);
            resp.serialize()
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
        counters: retry_counter::MemCounters,
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
        fn retry_counters(&mut self) -> Option<&mut dyn retry_counter::RetryCounterBackend> {
            Some(&mut self.counters)
        }
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
            counters: Default::default(),
            saves: heapless::Vec::new(),
        };
        let max = piv.state.pin_state.pin_retries_remaining;
        let pin = |s: &PinStore| -> heapless::Vec<u8, 16> {
            s.counters
                .puts
                .iter()
                .filter(|(c, _)| *c == Credential::PivPin)
                .map(|(_, st)| st.remaining())
                .collect()
        };

        assert_ne!(verify(&mut piv, &mut store, b"999999"), 0x9000);
        assert_eq!(
            &pin(&store)[..],
            &[max - 1],
            "one record, before the compare"
        );
        assert!(store.saves.is_empty(), "no PIN-record write");

        // Reset: a fresh applet (no PIN record) takes its count from the log.
        let mut fresh = Piv::new();
        Piv::load_credentials_from_store(&mut fresh.state, &mut store);
        assert_eq!(fresh.state.pin_state.pin_retries_remaining, max - 1);

        assert_eq!(verify(&mut fresh, &mut store, DEFAULT_PIV_PIN), 0x9000);
        assert_eq!(
            &pin(&store)[..],
            &[max - 1, max - 2, max],
            "spent before the compare, restored after success"
        );
        assert!(store.saves.is_empty(), "still no PIN-record write");
    }

    #[test]
    fn piv_record_never_carries_a_usable_count() {
        let mut piv = Piv::new();
        let mut store = PinStore {
            counters: Default::default(),
            saves: heapless::Vec::new(),
        };
        Piv::save_pin_to_store(&piv.state, &mut store).unwrap();
        let b = &store.saves[0];
        assert_eq!((b[48], b[50], b[99], b[100]), (0, 1, 0, 1));
        // Loaded with its counters from the log.
        let mut fresh = Piv::new();
        Piv::load_credentials_from_store(&mut fresh.state, &mut store);
        assert_eq!(
            fresh.state.pin_state.pin_retries_remaining,
            piv.state.pin_state.pin_retries_remaining
        );
        // ...and blocked if the log loses the entry.
        store.counters.entries = Default::default();
        Piv::load_credentials_from_store(&mut piv.state, &mut store);
        assert!(piv.state.pin_state.pin_blocked);
        assert!(piv.state.pin_state.puk_blocked);
    }

    #[test]
    fn piv_migration_seeds_from_legacy_record() {
        let piv = Piv::new();
        let mut store = PinStore {
            counters: retry_counter::MemCounters {
                unformatted: true,
                ..Default::default()
            },
            saves: heapless::Vec::new(),
        };
        // A pre-log record: PIN 2 left, PUK blocked.
        let mut rec = Piv::pin_record(&piv.state);
        (rec[48], rec[50], rec[99], rec[100]) = (2, 0, 1, 1);
        store.saves.push(rec.iter().copied().collect()).unwrap();
        assert_eq!(
            crate::apdu::dispatcher::Dispatcher::migrate_retry_counters(&mut store),
            Ok(true)
        );
        assert_eq!(store.counters.remaining(Credential::PivPin), Some(2));
        assert_eq!(
            store.counters.remaining(Credential::PivPuk),
            Some(0),
            "blocked flag wins over the count"
        );
        let b = store.saves.last().unwrap();
        assert_eq!((b[48], b[50], b[99], b[100]), (0, 1, 0, 1), "zeroed");
        let mut fresh = Piv::new();
        Piv::load_credentials_from_store(&mut fresh.state, &mut store);
        assert_eq!(fresh.state.pin_state.pin_retries_remaining, 2);
        assert!(fresh.state.pin_state.puk_blocked);
    }

    #[test]
    fn puk_block_survives_reload() {
        fn change_puk(piv: &mut Piv, store: &mut PinStore, old: &[u8]) -> u16 {
            let mut apdu: heapless::Vec<u8, 24> = heapless::Vec::new();
            apdu.extend_from_slice(&[0x00, 0x24, 0x00, 0x81, 16])
                .unwrap();
            apdu.extend_from_slice(old).unwrap();
            apdu.extend_from_slice(b"87654321").unwrap();
            let r = piv.process_apdu_with_store(&apdu, store);
            u16::from_be_bytes([r[r.len() - 2], r[r.len() - 1]])
        }
        let mut piv = Piv::new();
        let mut store = PinStore {
            counters: Default::default(),
            saves: heapless::Vec::new(),
        };
        for _ in 0..crate::security::pin::MAX_PUK_RETRIES {
            assert_ne!(change_puk(&mut piv, &mut store, b"00000000"), 0x9000);
        }
        // Reset: reload from flash, then try the right PUK.
        let mut fresh = Piv::new();
        Piv::restore_pin_record(&mut fresh.state, &mut store);
        assert!(fresh.state.pin_state.puk_blocked, "blocked after reload");
        assert_eq!(change_puk(&mut fresh, &mut store, b"12345678"), 0x6983);
    }

    #[test]
    fn mgmt_key_change_requires_mgmt_auth() {
        let mut piv = Piv::new();
        let mut store = PinStore {
            counters: Default::default(),
            saves: heapless::Vec::new(),
        };
        let new_key = [0x42u8; 24];
        let mut apdu: heapless::Vec<u8, 40> = heapless::Vec::new();
        apdu.extend_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 27, 0x03, 0x9B, 0x18])
            .unwrap();
        apdu.extend_from_slice(&new_key).unwrap();

        let r = piv.process_apdu_with_store(&apdu, &mut store);
        assert_eq!(
            &r[r.len() - 2..],
            &[0x69, 0x82],
            "needs management-key auth"
        );
        assert_ne!(piv.state.mgmt_key, new_key);

        piv.state.mgmt_key_authenticated = true;
        let r = piv.process_apdu_with_store(&apdu, &mut store);
        assert_eq!(&r[r.len() - 2..], &[0x90, 0x00]);
        assert_eq!(piv.state.mgmt_key, new_key);
    }

    #[test]
    fn generate_requires_mgmt_key_not_pin() {
        let mut piv = Piv::new();
        let mut store = PinStore {
            counters: Default::default(),
            saves: heapless::Vec::new(),
        };
        assert_eq!(verify(&mut piv, &mut store, DEFAULT_PIV_PIN), 0x9000);
        // GENERATE 9A, P-256.
        let apdu = [
            0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11, 0x00,
        ];
        let r = piv.process_apdu_with_store(&apdu, &mut store);
        assert_eq!(&r[r.len() - 2..], &[0x69, 0x82], "PIN alone is not enough");
    }
}

#[cfg(all(test, feature = "applet-piv"))]
mod data_object_tests {
    use super::*;
    use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
    use pico2hsm_core::error::HsmError;
    use pico2hsm_core::key::{AppletId, KeyId};

    struct MemStore {
        counters: retry_counter::MemCounters,
        records: heapless::Vec<(KeyId, heapless::Vec<u8, 2100>), 10>,
    }

    impl crate::storage::KeyStore for MemStore {
        fn save_key(&mut self, obj: &KeyObject) -> Result<(), HsmError> {
            let kid = KeyId(obj.key_id);
            self.records.retain(|(k, _)| *k != kid);
            let mut b = heapless::Vec::new();
            b.extend_from_slice(&obj.private_key)
                .map_err(|_| HsmError::InvalidInput)?;
            self.records
                .push((kid, b))
                .map_err(|_| HsmError::InvalidInput)
        }
        fn fetch_key(&mut self, kid: KeyId) -> Result<Option<KeyObject>, HsmError> {
            Ok(self.records.iter().find(|(k, _)| *k == kid).map(|(_, b)| {
                let mut o = KeyObject::new(
                    KmKeyType::Generic,
                    kid.0,
                    AppletId::Piv,
                    AlgorithmId::AesGcm,
                );
                o.private_key.extend_from_slice(b).unwrap();
                o
            }))
        }
        fn erase_key(&mut self, kid: KeyId) -> Result<(), HsmError> {
            self.records.retain(|(k, _)| *k != kid);
            Ok(())
        }
        fn wipe_all(&mut self) -> Result<(), HsmError> {
            Ok(())
        }
        fn wipe_by_owner(&mut self, owner: AppletId) -> Result<(), HsmError> {
            self.records.retain(|(k, _)| k.applet_byte() != owner as u8);
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
        fn retry_counters(&mut self) -> Option<&mut dyn retry_counter::RetryCounterBackend> {
            Some(&mut self.counters)
        }
    }

    /// Extended-length PUT DATA for tag 5FC1<low> with `content`.
    fn put_data(low: u8, content: &[u8]) -> heapless::Vec<u8, 2200> {
        let mut body: heapless::Vec<u8, 2100> = heapless::Vec::new();
        body.extend_from_slice(&[0x5C, 0x03, 0x5F, 0xC1, low, 0x53, 0x82])
            .unwrap();
        body.extend_from_slice(&(content.len() as u16).to_be_bytes())
            .unwrap();
        body.extend_from_slice(content).unwrap();
        let mut a = heapless::Vec::new();
        a.extend_from_slice(&[0x00, 0xDB, 0x3F, 0xFF, 0x00])
            .unwrap();
        a.extend_from_slice(&(body.len() as u16).to_be_bytes())
            .unwrap();
        a.extend_from_slice(&body).unwrap();
        a
    }

    fn sw(r: &[u8]) -> u16 {
        u16::from_be_bytes([r[r.len() - 2], r[r.len() - 1]])
    }

    #[test]
    fn put_data_survives_reset() {
        let mut piv = Piv::new();
        piv.state.mgmt_key_authenticated = true;
        let mut store = MemStore {
            counters: Default::default(),
            records: heapless::Vec::new(),
        };
        let cert = [0xC3u8; 300];
        assert_eq!(
            sw(&piv.process_apdu_with_store(&put_data(0x05, &cert), &mut store)),
            0x9000
        );

        let mut fresh = Piv::new();
        fresh.load_from_store(&mut store);
        let obj = fresh
            .state
            .data_objects
            .iter()
            .find(|o| o.tag_low == 0x05)
            .unwrap();
        assert_eq!(&obj.data[4..], &cert[..], "53 82 01 2C || cert");
    }

    #[test]
    fn oversized_object_is_refused_not_truncated() {
        let mut piv = Piv::new();
        piv.state.mgmt_key_authenticated = true;
        let mut store = MemStore {
            counters: Default::default(),
            records: heapless::Vec::new(),
        };
        // 2046 bytes of content + 4-byte 53 wrapper > 2048.
        let r = piv.process_apdu_with_store(&put_data(0x05, &[0u8; 2046]), &mut store);
        assert_eq!(sw(&r), 0x6A84);
        let obj_id = Piv::piv_data_object_key_id(0x05);
        assert!(store.records.iter().all(|(k, _)| *k != obj_id));
    }

    #[test]
    fn more_objects_than_ram_cache_and_53_00_deletes() {
        let mut piv = Piv::new();
        piv.state.mgmt_key_authenticated = true;
        let mut store = MemStore {
            counters: Default::default(),
            records: heapless::Vec::new(),
        };
        let get = |low: u8| {
            [
                0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, low, 0x00,
            ]
        };
        for low in 1..=6u8 {
            assert_eq!(
                sw(&piv.process_apdu_with_store(&put_data(low, &[low; 40]), &mut store)),
                0x9000,
                "object {low}"
            );
        }
        // 5FC103 (fingerprints) needs the PIN.
        assert_eq!(
            sw(&piv.process_apdu_with_store(&get(3), &mut store)),
            0x6982
        );
        piv.state.pin_verified = true;
        for low in 1..=6u8 {
            let r = piv.process_apdu_with_store(&get(low), &mut store);
            assert_eq!(sw(&r), 0x9000, "object {low} readable");
            assert_eq!(r[2], low, "content of object {low}");
        }
        // 53 00 deletes, from RAM and flash.
        assert_eq!(
            sw(&piv.process_apdu_with_store(&put_data(1, &[]), &mut store)),
            0x9000
        );
        assert_eq!(
            sw(&piv.process_apdu_with_store(&get(1), &mut store)),
            0x6A82
        );
    }

    #[test]
    fn only_sp800_73_objects_are_stored() {
        let mut piv = Piv::new();
        piv.state.mgmt_key_authenticated = true;
        let mut store = MemStore {
            counters: Default::default(),
            records: heapless::Vec::new(),
        };
        for low in [0x00u8, 0x24, 0x7E, 0xFF] {
            assert_eq!(
                sw(&piv.process_apdu_with_store(&put_data(low, &[1u8; 4]), &mut store)),
                0x6A82,
                "5FC1{low:02X}"
            );
        }
        assert!(store.records.iter().all(|(k, _)| (k.0 >> 8) & 0xFF != 0xD0));
    }

    #[test]
    fn credentials_reach_flash_before_first_object() {
        let mut piv = Piv::new();
        piv.state.mgmt_key_authenticated = true;
        let mut store = MemStore {
            counters: Default::default(),
            records: heapless::Vec::new(),
        };
        assert_eq!(
            sw(&piv.process_apdu_with_store(&put_data(0x05, &[1u8; 10]), &mut store)),
            0x9000
        );
        let ids: heapless::Vec<KeyId, 4> = store.records.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            &ids[..],
            &[
                Piv::piv_pin_key_id(),
                Piv::piv_mgmt_key_id(),
                Piv::piv_data_object_key_id(0x05)
            ]
        );
    }

    #[test]
    fn missing_pin_record_next_to_content_locks_out() {
        let mut piv = Piv::new();
        piv.state.mgmt_key_authenticated = true;
        let mut store = MemStore {
            counters: Default::default(),
            records: heapless::Vec::new(),
        };
        piv.process_apdu_with_store(&put_data(0x05, &[1u8; 10]), &mut store);
        // Attacker with flash access deletes the PIN record.
        store.records.retain(|(k, _)| *k != Piv::piv_pin_key_id());

        let mut fresh = Piv::new();
        fresh.load_from_store(&mut store);
        assert_eq!(fresh.state.pin_state.pin_retries_remaining, 0);
        assert_eq!(fresh.state.pin_state.puk_retries_remaining, 0);
        assert_ne!(fresh.state.mgmt_key, DEFAULT_MGMT_KEY);
    }

    #[test]
    fn empty_applet_loads_factory_defaults() {
        let mut store = MemStore {
            counters: Default::default(),
            records: heapless::Vec::new(),
        };
        let mut fresh = Piv::new();
        fresh.load_from_store(&mut store);
        assert!(fresh.state.pin_state.pin_retries_remaining > 0);
        assert_eq!(fresh.state.mgmt_key, DEFAULT_MGMT_KEY);
    }

    #[test]
    fn piv_reset_only_when_pin_and_puk_blocked() {
        let mut piv = Piv::new();
        piv.state.mgmt_key_authenticated = true;
        let mut store = MemStore {
            counters: Default::default(),
            records: heapless::Vec::new(),
        };
        piv.process_apdu_with_store(&put_data(0x05, &[1u8; 10]), &mut store);
        let reset = [0x00, 0xFB, 0x00, 0x00];
        assert_eq!(sw(&piv.process_apdu_with_store(&reset, &mut store)), 0x6985);
        assert!(!store.records.is_empty());

        piv.state.lock_out();
        assert_eq!(sw(&piv.process_apdu_with_store(&reset, &mut store)), 0x9000);
        assert!(store.records.is_empty(), "applet wiped");
        assert_eq!(piv.state.mgmt_key, DEFAULT_MGMT_KEY);
        assert!(piv.state.data_objects.is_empty());
    }

    fn verify(piv: &mut Piv, store: &mut MemStore, pin: &[u8]) -> u16 {
        let mut apdu: heapless::Vec<u8, 16> = heapless::Vec::new();
        apdu.extend_from_slice(&[0x00, 0x20, 0x00, 0x80, 0x08])
            .unwrap();
        apdu.extend_from_slice(pin).unwrap();
        for _ in pin.len()..8 {
            apdu.push(0xFF).unwrap();
        }
        sw(&piv.process_apdu_with_store(&apdu, store))
    }

    #[test]
    fn piv_reset_restores_the_counters_on_flash() {
        let mut piv = Piv::new();
        piv.state.mgmt_key_authenticated = true;
        let mut store = MemStore {
            counters: Default::default(),
            records: heapless::Vec::new(),
        };
        piv.process_apdu_with_store(&put_data(0x05, &[1u8; 10]), &mut store);
        // Block the PIN and the PUK the hard way.
        while piv.state.pin_state.pin_retries_remaining > 0 {
            verify(&mut piv, &mut store, b"999999");
        }
        let mut change_puk = [0u8; 21];
        change_puk[..5].copy_from_slice(&[0x00, 0x24, 0x00, 0x81, 16]);
        change_puk[5..13].copy_from_slice(b"00000000");
        change_puk[13..].copy_from_slice(b"87654321");
        while piv.state.pin_state.puk_retries_remaining > 0 {
            piv.process_apdu_with_store(&change_puk, &mut store);
        }
        assert_eq!(store.counters.remaining(Credential::PivPin), Some(0));
        assert_eq!(store.counters.remaining(Credential::PivPuk), Some(0));

        let reset = [0x00, 0xFB, 0x00, 0x00];
        assert_eq!(sw(&piv.process_apdu_with_store(&reset, &mut store)), 0x9000);
        let max = crate::security::pin::MAX_PIN_RETRIES;
        assert_eq!(store.counters.remaining(Credential::PivPin), Some(max));
        // After a power cycle the applet is factory-fresh and usable.
        let mut fresh = Piv::new();
        fresh.load_from_store(&mut store);
        assert_eq!(fresh.state.pin_state.pin_retries_remaining, max);
        assert_eq!(verify(&mut fresh, &mut store, DEFAULT_PIV_PIN), 0x9000);
    }

    #[test]
    fn piv_reset_with_failed_counter_write_stays_blocked() {
        let mut piv = Piv::new();
        let mut store = MemStore {
            counters: Default::default(),
            records: heapless::Vec::new(),
        };
        piv.state.lock_out();
        store.counters.fail_all = true;
        let reset = [0x00, 0xFB, 0x00, 0x00];
        assert_eq!(sw(&piv.process_apdu_with_store(&reset, &mut store)), 0x6581);
        // Fresh applet without entries: the RAM defaults stand only if the
        // log has nothing to say; a blocked entry would win.
        store.counters.fail_all = false;
        retry_counter::set(&mut store, Credential::PivPin, 0).unwrap();
        store.counters.fail_all = true;
        piv.state.lock_out();
        assert_eq!(sw(&piv.process_apdu_with_store(&reset, &mut store)), 0x6581);
        assert_eq!(piv.state.pin_state.pin_retries_remaining, 0);
        assert!(piv.state.pin_state.pin_blocked);
    }

    #[test]
    fn chuid_guid_is_not_all_zero() {
        let mut piv = Piv::new();
        let r = piv.process_apdu(&[
            0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x02, 0x00,
        ]);
        let guid_at = r.windows(2).position(|w| w == [0x34, 0x10]).unwrap() + 2;
        assert_ne!(&r[guid_at..guid_at + 16], &[0u8; 16]);
    }

    #[test]
    fn default_hashes_match_kdf() {
        let computed = crate::security::pin::PinState::new(
            DEFAULT_PIV_PIN,
            DEFAULT_PIV_PUK,
            &[0u8; 16],
            DEFAULT_PIN_SALT,
            DEFAULT_PUK_SALT,
            crate::security::pin::MAX_PIN_RETRIES,
            crate::security::pin::MAX_PUK_RETRIES,
        )
        .unwrap();
        assert_eq!(computed.pin_hash, DEFAULT_PIN_HASH);
        assert_eq!(computed.puk_hash, DEFAULT_PUK_HASH);
    }
}
