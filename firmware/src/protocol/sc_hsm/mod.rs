//! SC-HSM 2 protocol implementation.
//!
//! Implements the SmartCard-HSM 2 APDU command set as used by OpenSC,
//! pkcs11-tool, and the sc-hsm-embedded reference firmware. This is the
//! primary protocol for pico2hsm.
//!
//! # AID
//! `E8 2B 06 01 04 01 81 C3 1F 02 01` — SmartCard-HSM
//!
//! # Implemented commands (see commands/ sub-module)
//! SELECT, READ BINARY, UPDATE BINARY, VERIFY, CHANGE PIN, RESET RETRY,
//! INITIALIZE, GENERATE KEY PAIR, GENERATE SYMMETRIC KEY, IMPORT KEY,
//! EXPORT KEY, COMPUTE DIGITAL SIGNATURE, DECIPHER, SYMMETRIC CIPHER,
//! DELETE FILE, LIST KEYS, GET CHALLENGE, EXTERNAL AUTHENTICATE,
//! GENERAL AUTHENTICATE, MANAGE SECURITY ENVIRONMENT, PERFORM SECURITY
//! OPERATION, KEY DOMAIN, SESSION PIN, PUK AUTH, BIP/SLIP HD DERIVE,
//! DERIVE ASYMMETRIC KEY, EXTRAS, DEBUG DUMP (debug feature only).

pub mod commands;
pub mod pkcs15_objects;

use heapless::{String, Vec};
use pico2hsm_core::{
    apdu::{
        ApduCommand, ApduResponse, SW_CLASS_NOT_SUPPORTED, SW_INCORRECT_P1P2, SW_INS_NOT_SUPPORTED,
        SW_MEMORY_FAILURE, SW_OK,
    },
    error::HsmError,
    key::{AppletId, KeyId, KeyType as CoreKeyType},
    protocol::HsmProtocol,
};
use zeroize::Zeroizing;

use crate::security::dkek::DkekManager;

use commands::*;

/// Lowest SC-HSM key reference reserved for firmware records:
/// 0xFC enrolled peer key, 0xFD persisted DKEK, 0xFE device identity key,
/// 0xFF PIN record.  User keys use 0x00–0xFB.
pub const RESERVED_KEY_REF_MIN: u8 = 0xFC;

/// A persistent retry counter that a credential-checking APDU spends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetryCounter {
    UserPin,
    SoPin,
    Puk,
}

impl RetryCounter {
    /// The counter `cmd` would spend, or `None` if it compares no credential.
    ///
    /// Mirrors each handler's own pre-checks: retry-count queries (empty
    /// data) and malformed APDUs (bad P1/P2 or lengths) are rejected before
    /// any comparison, so they must not cost a retry — otherwise garbage
    /// APDUs could block the PINs without ever guessing one.
    fn spent_by(cmd: &ApduCommand<'_>, state: &ScHsmState) -> Option<Self> {
        let n = cmd.data.len();
        match cmd.ins {
            verify::INS_VERIFY if cmd.p1 == 0x00 => match cmd.p2 {
                verify::P2_USER_PIN if (verify::MIN_PIN_LEN..=16).contains(&n) => {
                    Some(Self::UserPin)
                }
                verify::P2_SO_PIN if (6..=16).contains(&n) => Some(Self::SoPin),
                _ => None,
            },
            change_pin::INS_CHANGE_PIN if change_pin::compares_credential(cmd) => match cmd.p2 {
                verify::P2_USER_PIN => Some(Self::UserPin),
                verify::P2_SO_PIN => Some(Self::SoPin),
                _ => None,
            },
            puk_auth::INS_PUK_AUTH if (8..=16).contains(&n) && state.puk_hash.is_some() => {
                Some(Self::Puk)
            }
            // Re-INITIALIZE is authorised by the SO-PIN carried in the command.
            initialize::INS_INITIALIZE
                if state.initialized
                    && state.so_pin_hash.is_some()
                    && initialize::init_code(cmd).is_some() =>
            {
                Some(Self::SoPin)
            }
            _ => None,
        }
    }

    fn get(self, state: &mut ScHsmState) -> &mut u8 {
        match self {
            Self::UserPin => &mut state.pin_retry_count,
            Self::SoPin => &mut state.so_pin_retry_count,
            Self::Puk => &mut state.puk_retry_count,
        }
    }
}

/// Local no-op `KeyStore` used by the legacy `dispatch()` path.
///
/// On the firmware this path is never reached for store-mutating commands
/// (they are intercepted by `dispatch_with_store`).  On host-side tests
/// the mutations are silently dropped, which is the desired behaviour.
struct LocalNullStore;

impl crate::storage::KeyStore for LocalNullStore {
    fn save_key(&mut self, _: &crate::security::key_management::KeyObject) -> Result<(), HsmError> {
        Ok(())
    }
    fn fetch_key(
        &mut self,
        _: KeyId,
    ) -> Result<Option<crate::security::key_management::KeyObject>, HsmError> {
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
    fn for_each_key(&self, _f: &mut dyn FnMut(KeyId)) {}
}

/// AID for SmartCard-HSM (pico2hsm variant).
pub const SC_HSM_AID: &[u8] = &[
    0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01,
];

/// Maximum PIN length in bytes.
pub const MAX_PIN_LEN: usize = 16;
/// Maximum SO-PIN length in bytes.
pub const MAX_SO_PIN_LEN: usize = 16;

/// Maximum number of entries in the V2 DKEK exchange challenge replay cache.
pub const MAX_EXCHANGE_CHALLENGE_CACHE: usize = 8;

/// What's currently in the operational buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpBufState {
    /// Buffer is empty / invalid.
    Empty,
    /// Buffer holds decrypted data for this key, read from flash. Not modified.
    Clean(u32),
    /// Buffer holds modified data for this key. Must be flushed to flash before
    /// loading a different object.
    Dirty(u32),
}

/// Lightweight metadata for a key or EF file stored in flash.
/// Kept in RAM so LIST KEYS, SELECT, MSE SET, and PRKD generation
/// can answer without touching flash.
#[derive(Debug, Clone, Copy)]
pub struct KeyMeta {
    /// Full structured KeyId (partition | applet | reserved | proto_ref).
    pub key_id: u32,
    /// CoreKeyType discriminant.
    pub key_type: u8,
    /// SC-HSM algorithm byte (e.g. 0x13 = EcdsaP256).
    pub algo: u8,
    /// SC-HSM key flags (sign/decrypt/derive/exportable).
    pub key_flags: u8,
}

/// Cached EF file entry — stores actual file data in RAM so READ BINARY
/// can serve it without flash access from Core1.
#[derive(Clone)]
pub struct EfCacheEntry {
    /// Full structured KeyId for this EF (from `KeyId::sc_hsm_ef`).
    pub key_id: u32,
    /// File data (certificates, PRKDs, etc.).  1024 bytes covers EC CVCs
    /// for all curves including P-521 (~700 bytes) and RSA-2048 (~900 bytes).
    pub data: heapless::Vec<u8, 1024>,
}

/// Single operational buffer for one-at-a-time key/EF access.
///
/// All key material and EF file data flows through this buffer.
/// Since Core1 processes one APDU at a time, there is never concurrent
/// access to multiple keys. The state machine ensures dirty data is
/// flushed before a new object is loaded.
pub struct OpBuffer {
    /// Current buffer state.
    pub state: OpBufState,
    /// Decrypted key material or EF file content.
    pub data: [u8; 4096],
    /// Number of valid bytes in `data`.
    pub len: usize,
}

impl OpBuffer {
    pub const fn new() -> Self {
        OpBuffer {
            state: OpBufState::Empty,
            data: [0u8; 4096],
            len: 0,
        }
    }

    /// Invalidate the buffer (set to Empty, zero data).
    pub fn invalidate(&mut self) {
        self.state = OpBufState::Empty;
        self.len = 0;
        // Zero the buffer to avoid leaking key material.
        self.data.fill(0);
    }

    /// Check if the buffer currently holds data for the given key_id.
    pub fn holds(&self, key_id: u32) -> bool {
        match self.state {
            OpBufState::Clean(id) | OpBufState::Dirty(id) => id == key_id,
            OpBufState::Empty => false,
        }
    }

    /// Check if the buffer is dirty (has unflushed modifications).
    pub fn is_dirty(&self) -> bool {
        matches!(self.state, OpBufState::Dirty(_))
    }

    /// Mark the current buffer contents as dirty (modified).
    /// Panics if buffer is Empty.
    pub fn mark_dirty(&mut self) {
        match self.state {
            OpBufState::Clean(id) => self.state = OpBufState::Dirty(id),
            OpBufState::Dirty(_) => {} // already dirty
            OpBufState::Empty => panic!("cannot mark empty buffer as dirty"),
        }
    }

    /// Mark the buffer as clean (just flushed or freshly loaded).
    pub fn mark_clean(&mut self, key_id: u32) {
        self.state = OpBufState::Clean(key_id);
    }

    /// Get a reference to the valid data bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// Get a mutable reference to the valid data bytes.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    /// Load raw data into the buffer, marking it as Clean for the given key_id.
    /// Caller is responsible for flushing any prior dirty state before calling this.
    pub fn load_raw(&mut self, key_id: u32, data: &[u8]) {
        let n = data.len().min(4096);
        self.data[..n].copy_from_slice(&data[..n]);
        self.len = n;
        self.state = OpBufState::Clean(key_id);
    }

    /// Store new data into the buffer, marking it as Dirty for the given key_id.
    pub fn store_dirty(&mut self, key_id: u32, data: &[u8]) {
        let n = data.len().min(4096);
        self.data[..n].copy_from_slice(&data[..n]);
        self.len = n;
        self.state = OpBufState::Dirty(key_id);
    }
}

/// Platform-specific firmware RNG.
///
/// On ARM (RP2350) delegates to the hardware TRNG via `crypto::rng::fill_random`.
/// On x86_64 (host tests) uses a counter-hash PRNG adequate for testing.
pub(crate) struct FwRng;

impl rand_core::RngCore for FwRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Bump the watchdog heartbeat so Core0 knows Core1 is making progress
        // during long-running crypto (RSA keygen, ECDSA sign, etc.).
        crate::WATCHDOG_HEARTBEAT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        #[cfg(target_arch = "arm")]
        {
            let _ = crate::crypto::rng::fill_random(dest);
        }
        #[cfg(not(target_arch = "arm"))]
        {
            use core::sync::atomic::{AtomicU64, Ordering};
            static CTR: AtomicU64 = AtomicU64::new(0x9e3779b97f4a7c15u64);
            for chunk in dest.chunks_mut(8) {
                let v = CTR
                    .fetch_add(0x6c62272e07bb0142u64, Ordering::Relaxed)
                    .wrapping_mul(0x94d049bb133111ebu64)
                    ^ 0xbf58476d1ce4e5b9u64;
                let vb = v.to_le_bytes();
                chunk.copy_from_slice(&vb[..chunk.len()]);
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for FwRng {}

/// Security environment operation type (set by MSE).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SeOperation {
    /// MSE for Computation/Signature (P2=0xA4).
    Computation,
    /// MSE for Decipherment (P2=0xB8).
    Decipherment,
    /// MSE for Confidentiality/SM (P2=0xB4).
    Confidentiality,
}

/// SC-HSM session / protocol state.
pub struct ScHsmState {
    /// Currently selected EF file identifier (set by SELECT, used by READ BINARY ODD).
    pub current_file: Option<u16>,

    /// True after a successful User PIN VERIFY.
    pub pin_verified: bool,
    /// True after a successful SO-PIN VERIFY.
    pub so_pin_verified: bool,
    /// Remaining User PIN retry attempts (0 = blocked).
    pub pin_retry_count: u8,
    /// Remaining SO-PIN retry attempts (0 = blocked).
    pub so_pin_retry_count: u8,

    /// Current key selected by MSE SET.
    pub current_key_id: Option<u8>,
    /// Algorithm byte selected by MSE SET.
    pub current_algo: Option<u8>,
    /// Current MSE operation type.
    pub current_se_op: Option<SeOperation>,

    /// 8-byte random challenge issued by GET CHALLENGE.
    pub challenge: Option<[u8; 8]>,

    /// One-time session PIN (raw 8 bytes). Cleared after first use.
    pub session_pin: Option<[u8; 8]>,

    /// True after INITIALIZE has been called at least once.
    pub initialized: bool,

    /// User-supplied HSM label (set during INITIALIZE).
    pub hsm_label: String<32>,

    /// Options bitmask from INITIALIZE (tag 0x92).
    pub options: u16,

    /// Number of DKEK shares required (from INITIALIZE tag 0x91).
    pub dkek_shares_required: u8,
    /// Number of DKEK shares already imported.
    pub dkek_shares_imported: u8,

    /// Stored User PIN hash (PBKDF2-HMAC-SHA256, 32 bytes). None if not set.
    ///
    /// NOTE: On-flash hash format changed from bare SHA-256 to PBKDF2 (P1-1 fix).
    /// Devices initialized on older firmware must be re-INITIALIZE'd.
    pub user_pin_hash: Option<[u8; 32]>,
    /// 16-byte random salt for the User PIN PBKDF2 hash.
    pub user_pin_salt: [u8; 16],
    /// Stored SO-PIN hash (PBKDF2-HMAC-SHA256, 32 bytes). None if not set.
    pub so_pin_hash: Option<[u8; 32]>,
    /// 16-byte random salt for the SO-PIN PBKDF2 hash.
    pub so_pin_salt: [u8; 16],

    /// Stored PUK hash (PBKDF2-HMAC-SHA256). None if no PUK is configured.
    pub puk_hash: Option<[u8; 32]>,
    /// 16-byte random salt for the PUK PBKDF2 hash.
    pub puk_salt: [u8; 16],
    /// Remaining PUK retry attempts (0 = blocked).
    pub puk_retry_count: u8,

    /// Lightweight metadata index for all keys and EF files in flash.
    /// Replaces the previous `keys`, `rsa_keys`, `sym_keys`, and `ef_files`
    /// Vec fields. Key material stays in flash; only metadata lives in RAM.
    pub key_index: heapless::Vec<KeyMeta, 32>,

    /// Single operational buffer for key/EF data access.
    /// Loaded on-demand from flash; flushed back when dirty.
    pub op_buf: OpBuffer,

    /// Last non-zero file ID targeted by WRITE DATA.  OpenSC's sc_hsm_update_ef
    /// uses a two-step write protocol: first `D7 fid_hi fid_lo data(N)` (small
    /// header write) followed by `D7 00 00 data(M)` (full content write, where
    /// P1=P2=0 means "write to the previously addressed file").
    pub write_target_file: Option<u16>,

    /// DKEK (Device Key Encryption Key) manager for key wrap/unwrap and exchange.
    pub dkek: DkekManager,

    /// Ephemeral P-256 private key for in-progress DKEK exchange (32-byte scalar).
    pub exchange_ephem_priv: Option<Zeroizing<[u8; 32]>>,
    /// Ephemeral P-256 public key for in-progress DKEK exchange (65-byte uncompressed).
    pub exchange_ephem_pub: Option<[u8; 65]>,

    /// Challenge for in-progress V2 DKEK exchange.
    pub exchange_challenge: Option<[u8; 32]>,
    /// Peer's ephemeral pub stored during V2 exchange for channel binding.
    pub exchange_peer_ephem_pub: Option<[u8; 65]>,
    /// Replay cache for V2 exchange challenges (RAM only, cleared on reset).
    pub exchange_challenge_cache: [[u8; 32]; MAX_EXCHANGE_CHALLENGE_CACHE],
    /// Number of valid entries in exchange_challenge_cache (capped at MAX_EXCHANGE_CHALLENGE_CACHE).
    pub exchange_challenge_cache_count: u8,
    /// Ring-buffer write pointer for the challenge replay cache.
    /// Incremented unconditionally on every write; mod 16 gives the slot.
    pub exchange_challenge_cache_write_idx: u8,

    /// Monotonic generation counter, incremented on key generate/import/delete.
    pub generation: u64,

    /// Enrolled peer device static public key (65-byte uncompressed P-256).
    /// Used by V2 DKEK exchange to verify the peer's ECDSA signature.
    /// None = unauthenticated mode (signature verification skipped).
    pub noise_enrolled_peer_pubkey: Option<[u8; 65]>,

    /// In-memory EF file data cache.
    ///
    /// Core1's `FlashQueueKeyStore::fetch_key()` always returns `Ok(None)` —
    /// flash reads aren't possible during synchronous APDU dispatch.  This
    /// cache stores EF file data written via WRITE DATA so that READ BINARY
    /// can serve it back without hitting flash.
    ///
    /// Populated by: `write_data::write_at_offset` (on write), and
    /// `load_keys_from_store` (on USB reconnect from flash).
    pub ef_cache: heapless::Vec<EfCacheEntry, 16>,
}

impl ScHsmState {
    pub fn new() -> Self {
        ScHsmState {
            current_file: None,
            pin_verified: false,
            so_pin_verified: false,
            pin_retry_count: 3,
            so_pin_retry_count: 5,
            current_key_id: None,
            current_algo: None,
            current_se_op: None,
            challenge: None,
            session_pin: None,
            initialized: false,
            hsm_label: String::new(),
            options: 0,
            dkek_shares_required: 0,
            dkek_shares_imported: 0,
            user_pin_hash: None,
            user_pin_salt: [0u8; 16],
            so_pin_hash: None,
            so_pin_salt: [0u8; 16],
            puk_hash: None,
            puk_salt: [0u8; 16],
            puk_retry_count: 10,
            key_index: heapless::Vec::new(),
            op_buf: OpBuffer::new(),
            write_target_file: None,
            dkek: DkekManager::new([0u8; 16]),
            exchange_ephem_priv: None,
            exchange_ephem_pub: None,
            exchange_challenge: None,
            exchange_peer_ephem_pub: None,
            exchange_challenge_cache: [[0u8; 32]; MAX_EXCHANGE_CHALLENGE_CACHE],
            exchange_challenge_cache_count: 0,
            exchange_challenge_cache_write_idx: 0,
            generation: 0,
            noise_enrolled_peer_pubkey: None,
            ef_cache: heapless::Vec::new(),
        }
    }

    /// Initialise an `ScHsmState` directly into a destination pointer,
    /// writing each field individually to avoid placing the full struct
    /// (~9 KB with OpBuffer + ef_cache) on the stack.
    pub fn init_in_place(dest: *mut Self) {
        use core::ptr::addr_of_mut;
        unsafe {
            addr_of_mut!((*dest).current_file).write(None);
            addr_of_mut!((*dest).pin_verified).write(false);
            addr_of_mut!((*dest).so_pin_verified).write(false);
            addr_of_mut!((*dest).pin_retry_count).write(3);
            addr_of_mut!((*dest).so_pin_retry_count).write(5);
            addr_of_mut!((*dest).current_key_id).write(None);
            addr_of_mut!((*dest).current_algo).write(None);
            addr_of_mut!((*dest).current_se_op).write(None);
            addr_of_mut!((*dest).challenge).write(None);
            addr_of_mut!((*dest).session_pin).write(None);
            addr_of_mut!((*dest).initialized).write(false);
            addr_of_mut!((*dest).hsm_label).write(String::new());
            addr_of_mut!((*dest).options).write(0);
            addr_of_mut!((*dest).dkek_shares_required).write(0);
            addr_of_mut!((*dest).dkek_shares_imported).write(0);
            addr_of_mut!((*dest).user_pin_hash).write(None);
            addr_of_mut!((*dest).user_pin_salt).write([0u8; 16]);
            addr_of_mut!((*dest).so_pin_hash).write(None);
            addr_of_mut!((*dest).so_pin_salt).write([0u8; 16]);
            addr_of_mut!((*dest).puk_hash).write(None);
            addr_of_mut!((*dest).puk_salt).write([0u8; 16]);
            addr_of_mut!((*dest).puk_retry_count).write(10);
            addr_of_mut!((*dest).key_index).write(heapless::Vec::new());
            addr_of_mut!((*dest).op_buf).write(OpBuffer::new());
            addr_of_mut!((*dest).write_target_file).write(None);
            addr_of_mut!((*dest).dkek).write(DkekManager::new([0u8; 16]));
            addr_of_mut!((*dest).exchange_ephem_priv).write(None);
            addr_of_mut!((*dest).exchange_ephem_pub).write(None);
            addr_of_mut!((*dest).exchange_challenge).write(None);
            addr_of_mut!((*dest).exchange_peer_ephem_pub).write(None);
            addr_of_mut!((*dest).exchange_challenge_cache)
                .write([[0u8; 32]; MAX_EXCHANGE_CHALLENGE_CACHE]);
            addr_of_mut!((*dest).exchange_challenge_cache_count).write(0);
            addr_of_mut!((*dest).exchange_challenge_cache_write_idx).write(0);
            addr_of_mut!((*dest).generation).write(0);
            addr_of_mut!((*dest).noise_enrolled_peer_pubkey).write(None);
            addr_of_mut!((*dest).ef_cache).write(heapless::Vec::new());
        }
    }

    /// Look up cached EF file data by key_id.
    pub fn ef_cache_get(&self, key_id: u32) -> Option<&[u8]> {
        self.ef_cache
            .iter()
            .find(|e| e.key_id == key_id)
            .map(|e| e.data.as_slice())
    }

    /// Insert or replace EF file data in the cache.
    pub fn ef_cache_put(&mut self, key_id: u32, data: &[u8]) {
        self.ef_cache.retain(|e| e.key_id != key_id);
        let mut entry = EfCacheEntry {
            key_id,
            data: heapless::Vec::new(),
        };
        // Truncate to cache entry capacity (1024 bytes).
        let len = data.len().min(entry.data.capacity());
        let _ = entry.data.extend_from_slice(&data[..len]);
        let _ = self.ef_cache.push(entry);
    }

    /// Remove an EF file from the cache.
    pub fn ef_cache_remove(&mut self, key_id: u32) {
        self.ef_cache.retain(|e| e.key_id != key_id);
    }

    /// Set the device ID on the DKEK manager.
    ///
    /// Called once at boot before any DKEK operations. Reinitializes the
    /// DkekManager with the real device_id.
    pub fn set_device_id(&mut self, device_id: [u8; 16]) {
        self.dkek = DkekManager::new(device_id);
    }
}

/// SC-HSM protocol implementation.
pub struct ScHsm {
    pub state: ScHsmState,
}

impl ScHsm {
    /// Create a new SC-HSM protocol instance.
    pub fn new() -> Self {
        ScHsm {
            state: ScHsmState::new(),
        }
    }

    /// Initialise an `ScHsm` directly into a destination pointer, avoiding
    /// a large stack temporary.  `ScHsmState` contains ~9 KB of inline
    /// buffers (OpBuffer 4 KB, ef_cache 4 KB) that overflow the stack
    /// when constructed via `ScHsm::new()` in debug builds.
    pub fn init_in_place(dest: *mut Self) {
        unsafe {
            ScHsmState::init_in_place(core::ptr::addr_of_mut!((*dest).state));
        }
    }

    /// Validate the CLA byte against the command's INS.
    ///
    /// ISO 7816-4 interindustry commands (VERIFY, SELECT, READ BINARY, etc.)
    /// require CLA=0x00. SC-HSM proprietary commands (INITIALIZE, EXTRAS,
    /// LIST KEYS, etc.) require CLA=0x80.
    fn validate_cla(cmd: &ApduCommand<'_>) -> Result<(), ApduResponse> {
        // The real SmartCard-HSM accepts CLA=0x00 for all commands, and OpenSC's
        // SC-HSM driver always sends CLA=0x00.  We accept both CLA=0x00 and
        // CLA=0x80 (the ISO 7816-4 proprietary range) for all known INS bytes,
        // rejecting only truly invalid class bytes (0x01–0x7F excluding 0x00,
        // and 0x81–0xFF excluding 0x80).
        if cmd.cla != 0x00 && cmd.cla != 0x80 {
            return Err(ApduResponse::err(SW_CLASS_NOT_SUPPORTED));
        }
        Ok(())
    }

    /// Dispatch an already-parsed APDU to the appropriate command handler,
    /// with access to persistent storage for key-mutating commands.
    ///
    /// Credential-checking commands go through [`Self::with_persisted_attempt`]
    /// so their retry counter is spent on flash before any comparison.
    fn dispatch_with_store(
        &mut self,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        if let Err(resp) = Self::validate_cla(cmd) {
            return resp;
        }
        match RetryCounter::spent_by(cmd, &self.state) {
            Some(counter) => self.with_persisted_attempt(counter, cmd, store),
            None => self.route_with_store(cmd, store),
        }
    }

    /// Whether `cmd` names a reserved key slot (`RESERVED_KEY_REF_MIN..`)
    /// through a user-facing key command.  Those slots hold the peer record,
    /// the DKEK, the device identity key and the PIN record; they are only
    /// ever touched by the firmware's own code paths.
    fn targets_reserved_slot(cmd: &ApduCommand<'_>) -> bool {
        let reserved = |r: u8| r >= RESERVED_KEY_REF_MIN;
        match cmd.ins {
            sign::INS_SIGN
            | decrypt::INS_DECRYPT
            | bip_slip::INS_BIP_SLIP
            | export_key::INS_EXPORT_KEY
            | 0x34
            | import_key::INS_IMPORT_KEY
            | generate_key::INS_GENERATE_KEY => reserved(cmd.p1),
            // P1=0xFF asks the card to pick a free slot.
            generate_keypair::INS_GENERATE_KEYPAIR => cmd.p1 != 0xFF && reserved(cmd.p1),
            _ => false,
        }
    }

    /// After a command that may complete or clear the DKEK, persist the
    /// change so wrap/unwrap keep working across resets.
    fn persist_dkek_change(
        &mut self,
        had_dkek: bool,
        resp: ApduResponse,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        if self.state.dkek.is_ready() != had_dkek
            && Self::save_dkek_to_store(&self.state, store).is_err()
        {
            return ApduResponse::err(SW_MEMORY_FAILURE);
        }
        resp
    }

    /// Spend one retry of `counter` on flash, run the command, then persist
    /// the outcome.
    ///
    /// The decremented counter is written *before* the handler compares the
    /// credential, so cutting power (or resetting USB) once the result is
    /// known cannot undo a failed guess.  The RAM counter is restored before
    /// the handler runs so its own retry logic is unchanged; afterwards a
    /// failed command can never leave the counter above the spent value.
    ///
    /// A failed pre-write refuses the attempt (SW 6581), failing closed.
    fn with_persisted_attempt(
        &mut self,
        counter: RetryCounter,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        let before = *counter.get(&mut self.state);
        if before == 0 {
            // Blocked: the handler reports it without comparing anything.
            return self.route_with_store(cmd, store);
        }
        let spent = before - 1;
        *counter.get(&mut self.state) = spent;
        if Self::save_pin_to_store(&self.state, store).is_err() {
            return ApduResponse::err(SW_MEMORY_FAILURE);
        }
        *counter.get(&mut self.state) = before;

        let resp = self.route_with_store(cmd, store);

        let after = counter.get(&mut self.state);
        if resp.sw != SW_OK && *after > spent {
            *after = spent;
        }
        if *after != spent && Self::save_pin_to_store(&self.state, store).is_err() {
            // Flash still holds the spent counter and the old credentials.
            // Make RAM match it rather than report a change that a reset
            // would silently undo, and fail closed.
            Self::load_pin_state_from_store(&mut self.state, store);
            *counter.get(&mut self.state) = spent;
            self.state.pin_verified = false;
            self.state.so_pin_verified = false;
            return ApduResponse::err(SW_MEMORY_FAILURE);
        }
        resp
    }

    /// Route an APDU to its handler with persistent storage available.
    fn route_with_store(
        &mut self,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        if Self::targets_reserved_slot(cmd) {
            return ApduResponse::err(SW_INCORRECT_P1P2);
        }
        match cmd.ins {
            initialize::INS_INITIALIZE => initialize::handle(&mut self.state, store, cmd),
            // Credential checks: persistence is handled by with_persisted_attempt.
            verify::INS_VERIFY => verify::handle(&mut self.state, cmd),
            puk_auth::INS_PUK_AUTH => puk_auth::handle(&mut self.state, cmd),
            generate_keypair::INS_GENERATE_KEYPAIR => {
                generate_keypair::handle(&mut self.state, store, cmd)
            }
            delete_file::INS_DELETE_FILE => delete_file::handle(&mut self.state, store, cmd),
            generate_key::INS_GENERATE_KEY => generate_key::handle(&mut self.state, store, cmd),
            // INS=0x72: pico2hsm proprietary EXPORT KEY (kept for custom tooling).
            // INS=0x34: standard SC-HSM WRAP KEY alias — same handler.
            export_key::INS_EXPORT_KEY | 0x34 => export_key::handle(&mut self.state, store, cmd),
            // INS=0x74: pico2hsm proprietary IMPORT KEY (kept for custom tooling).
            // NOTE: the standard SC-HSM IMPORT KEY uses INS=0x58, but that byte
            // is already claimed by LIST KEYS in this firmware.  INS=0x58 is NOT
            // aliased here to avoid routing LIST KEYS requests to the import
            // handler.  Standard tools that send INS=0x58 for import will receive
            // SW=9000 from LIST KEYS instead of import behaviour — this is a known
            // limitation.  Custom tooling should continue to use INS=0x74.
            import_key::INS_IMPORT_KEY => import_key::handle(&mut self.state, store, cmd),
            change_pin::INS_CHANGE_PIN => change_pin::handle(&mut self.state, cmd),
            reset_retry::INS_RESET_RETRY => {
                reset_retry::handle_with_store(&mut self.state, store, cmd)
            }
            extras::INS_EXTRAS => {
                let had_dkek = self.state.dkek.is_ready();
                let resp = extras::handle(&mut self.state, store, cmd);
                self.persist_dkek_change(had_dkek, resp, store)
            }
            key_domain::INS_KEY_DOMAIN => {
                let had_dkek = self.state.dkek.is_ready();
                let resp = key_domain::handle(&mut self.state, cmd);
                self.persist_dkek_change(had_dkek, resp, store)
            }
            // File commands that need flash access.
            read_binary::INS_READ_BINARY => read_binary::handle(&mut self.state, store, cmd),
            read_binary::INS_READ_BINARY_ODD => {
                read_binary::handle_odd(&mut self.state, store, cmd)
            }
            update_binary::INS_UPDATE_BINARY => update_binary::handle(&mut self.state, store, cmd),
            write_data::INS_WRITE_DATA => write_data::handle(&mut self.state, store, cmd),
            // Crypto operations that now load keys from flash on-demand.
            sign::INS_SIGN => sign::handle(&mut self.state, store, cmd),
            general_auth::INS_GENERAL_AUTH => general_auth::handle(&mut self.state, store, cmd),
            pso::INS_PSO => pso::handle(&mut self.state, store, cmd),
            cipher_sym::INS_CIPHER_SYM => cipher_sym::handle(&mut self.state, store, cmd),
            bip_slip::INS_BIP_SLIP => bip_slip::handle(&mut self.state, store, cmd),
            // INS 0x62: shared between DECIPHER (P1 = key_reference, P2 = algo)
            // and the proprietary DERIVE_ASYM (P1=0x01, P2=0x00).  P1 alone is
            // not a safe discriminator — SC-HSM uses P1 as the key reference,
            // and OpenSC assigns key_ref=0x01 to the first generated key, so a
            // legitimate DECIPHER on slot 1 (e.g. P-256 ECDH) would otherwise
            // be mis-routed to derive_asym.  Require P2=0x00 as well: DECIPHER
            // always sets P2 to an algo code (0x21/0x22/0x23/0x25/0x27/0x29/0x80),
            // never 0x00, so this cleanly separates the two.
            decrypt::INS_DECRYPT => {
                if cmd.p1 == derive_asym::P1_DERIVE && cmd.p2 == 0x00 {
                    derive_asym::handle(&mut self.state, store, cmd)
                } else {
                    decrypt::handle(&mut self.state, store, cmd)
                }
            }
            // All other commands fall through to the stateless dispatch.
            _ => self.dispatch(cmd),
        }
    }

    /// Dispatch an already-parsed APDU to the appropriate command handler.
    fn dispatch(&mut self, cmd: &ApduCommand<'_>) -> ApduResponse {
        if let Err(resp) = Self::validate_cla(cmd) {
            return resp;
        }
        match cmd.ins {
            // Commands that need flash access — use LocalNullStore in the
            // stateless dispatch path (host-side tests).  On firmware the
            // dispatch_with_store() route is taken instead.
            initialize::INS_INITIALIZE => {
                initialize::handle(&mut self.state, &mut LocalNullStore, cmd)
            }
            generate_keypair::INS_GENERATE_KEYPAIR => {
                generate_keypair::handle(&mut self.state, &mut LocalNullStore, cmd)
            }
            generate_key::INS_GENERATE_KEY => {
                generate_key::handle(&mut self.state, &mut LocalNullStore, cmd)
            }
            export_key::INS_EXPORT_KEY | 0x34 => {
                export_key::handle(&mut self.state, &mut LocalNullStore, cmd)
            }
            import_key::INS_IMPORT_KEY => {
                import_key::handle(&mut self.state, &mut LocalNullStore, cmd)
            }
            delete_file::INS_DELETE_FILE => {
                delete_file::handle(&mut self.state, &mut LocalNullStore, cmd)
            }
            extras::INS_EXTRAS => extras::handle(&mut self.state, &mut LocalNullStore, cmd),
            read_binary::INS_READ_BINARY => {
                read_binary::handle(&mut self.state, &mut LocalNullStore, cmd)
            }
            read_binary::INS_READ_BINARY_ODD => {
                read_binary::handle_odd(&mut self.state, &mut LocalNullStore, cmd)
            }
            update_binary::INS_UPDATE_BINARY => {
                update_binary::handle(&mut self.state, &mut LocalNullStore, cmd)
            }
            write_data::INS_WRITE_DATA => {
                write_data::handle(&mut self.state, &mut LocalNullStore, cmd)
            }
            sign::INS_SIGN => sign::handle(&mut self.state, &mut LocalNullStore, cmd),
            general_auth::INS_GENERAL_AUTH => {
                general_auth::handle(&mut self.state, &mut LocalNullStore, cmd)
            }
            pso::INS_PSO => pso::handle(&mut self.state, &mut LocalNullStore, cmd),
            cipher_sym::INS_CIPHER_SYM => {
                cipher_sym::handle(&mut self.state, &mut LocalNullStore, cmd)
            }
            bip_slip::INS_BIP_SLIP => bip_slip::handle(&mut self.state, &mut LocalNullStore, cmd),
            // See dispatch_with_store() above for the P1+P2 discrimination rationale.
            decrypt::INS_DECRYPT => {
                if cmd.p1 == derive_asym::P1_DERIVE && cmd.p2 == 0x00 {
                    derive_asym::handle(&mut self.state, &mut LocalNullStore, cmd)
                } else {
                    decrypt::handle(&mut self.state, &mut LocalNullStore, cmd)
                }
            }
            change_pin::INS_CHANGE_PIN => change_pin::handle(&mut self.state, cmd),
            reset_retry::INS_RESET_RETRY => {
                reset_retry::handle_with_store(&mut self.state, &mut LocalNullStore, cmd)
            }
            // Commands that don't need flash access (stateless dispatch).
            verify::INS_VERIFY => verify::handle(&mut self.state, cmd),
            mse::INS_MSE => mse::handle(&mut self.state, cmd),
            challenge::INS_CHALLENGE => challenge::handle(&mut self.state, cmd),
            list_keys::INS_LIST_KEYS => list_keys::handle(&mut self.state, cmd),
            create_file::INS_CREATE_FILE => create_file::handle(&mut self.state, cmd),
            key_domain::INS_KEY_DOMAIN => key_domain::handle(&mut self.state, cmd),
            session_pin::INS_SESSION_PIN => session_pin::handle(&mut self.state, cmd),
            puk_auth::INS_PUK_AUTH => puk_auth::handle(&mut self.state, cmd),
            select::INS_SELECT => select::handle(&mut self.state, cmd),
            provisioning::INS_PROV_GET_STATUS => {
                provisioning::handle_get_status(&mut self.state, cmd)
            }
            provisioning::INS_PROV_SET_PRODUCTION => {
                provisioning::handle_set_production_mode(&mut self.state, cmd)
            }
            provisioning::INS_PROV_LOCK_OTP_ROWS => {
                provisioning::handle_lock_otp_rows(&mut self.state, cmd)
            }
            provisioning::INS_PROV_WRITE_CRIT1 => {
                provisioning::handle_write_crit1(&mut self.state, cmd)
            }
            #[cfg(feature = "debug")]
            debug_dump::INS_DEBUG_DUMP => debug_dump::handle(cmd),
            _ => ApduResponse::err(SW_INS_NOT_SUPPORTED),
        }
    }
}

impl ScHsm {
    /// KeyId for the SC-HSM PIN state sentinel in flash.
    pub fn sc_hsm_pin_key_id() -> pico2hsm_core::key::KeyId {
        pico2hsm_core::key::KeyId::sc_hsm(0, 0xFF)
    }

    /// Serialize and persist the SC-HSM PIN/SO-PIN/PUK state to flash.
    ///
    /// Stored as a Generic key object at `KeyId::sc_hsm(0, 0xFF)`.
    /// Layout (149 bytes total — PBKDF2 + per-credential 16-byte salts):
    ///   [0..32]    user_pin_hash (PBKDF2, all zeros if None)
    ///   [32..48]   user_pin_salt (16 bytes)
    ///   [48]       pin_retry_count
    ///   [49..81]   so_pin_hash (PBKDF2, all zeros if None)
    ///   [81..97]   so_pin_salt (16 bytes)
    ///   [97]       so_pin_retry_count
    ///   [98..130]  puk_hash (PBKDF2, all zeros if None)
    ///   [130..146] puk_salt (16 bytes)
    ///   [146]      puk_retry_count
    ///   [147]      initialized (1 = true, 0 = false)
    ///   [148]      reserved (0)
    ///
    /// NOTE: Format changed from 101-byte (bare SHA-256, no salts) to 149-byte
    /// (PBKDF2 + per-credential salts).  Old flash blobs are ≤101 bytes and will
    /// be rejected by the length check in `load_pin_state_from_store`, requiring
    /// re-INITIALIZE.  This is intentional and acceptable for pre-production devices.
    pub fn save_pin_to_store(
        state: &ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), HsmError> {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
        use pico2hsm_core::key::AppletId;

        crate::CORE1_PROGRESS.store(34, core::sync::atomic::Ordering::Relaxed);
        let mut buf: heapless::Vec<u8, 256> = heapless::Vec::new();
        let user_hash = state.user_pin_hash.unwrap_or([0u8; 32]);
        let _ = buf.extend_from_slice(&user_hash);
        let _ = buf.extend_from_slice(&state.user_pin_salt);
        let _ = buf.push(state.pin_retry_count);
        let so_hash = state.so_pin_hash.unwrap_or([0u8; 32]);
        let _ = buf.extend_from_slice(&so_hash);
        let _ = buf.extend_from_slice(&state.so_pin_salt);
        let _ = buf.push(state.so_pin_retry_count);
        let puk_hash = state.puk_hash.unwrap_or([0u8; 32]);
        let _ = buf.extend_from_slice(&puk_hash);
        let _ = buf.extend_from_slice(&state.puk_salt);
        let _ = buf.push(state.puk_retry_count);
        let _ = buf.push(state.initialized as u8);
        let _ = buf.push(0); // reserved (was EXTERNAL AUTHENTICATE failures)

        crate::CORE1_PROGRESS.store(35, core::sync::atomic::Ordering::Relaxed);
        let kid = Self::sc_hsm_pin_key_id();
        let mut obj = KeyObject::new(
            KmKeyType::Generic,
            kid.0,
            AppletId::ScHsm,
            AlgorithmId::AesGcm,
        );
        crate::CORE1_PROGRESS.store(36, core::sync::atomic::Ordering::Relaxed);
        let _ = obj.private_key.extend_from_slice(&buf);
        crate::CORE1_PROGRESS.store(37, core::sync::atomic::Ordering::Relaxed);
        let result = store.save_key(&obj);
        crate::CORE1_PROGRESS.store(38, core::sync::atomic::Ordering::Relaxed);
        result
    }

    /// Load PIN/SO-PIN/PUK state from flash into `state`.
    pub fn load_pin_state_from_store(
        state: &mut ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
    ) {
        let kid = Self::sc_hsm_pin_key_id();
        if let Ok(Some(obj)) = store.fetch_key(kid) {
            let b = &obj.private_key;
            // Require the new 149-byte PBKDF2+salt format.
            // Blobs ≤101 bytes are old bare-SHA-256 format and are rejected,
            // requiring re-INITIALIZE (acceptable on pre-production devices).
            if b.len() >= 149 {
                let user_hash: [u8; 32] = b[0..32].try_into().unwrap_or([0u8; 32]);
                state.user_pin_hash = if user_hash == [0u8; 32] {
                    None
                } else {
                    Some(user_hash)
                };
                state.user_pin_salt = b[32..48].try_into().unwrap_or([0u8; 16]);
                state.pin_retry_count = b[48];
                let so_hash: [u8; 32] = b[49..81].try_into().unwrap_or([0u8; 32]);
                state.so_pin_hash = if so_hash == [0u8; 32] {
                    None
                } else {
                    Some(so_hash)
                };
                state.so_pin_salt = b[81..97].try_into().unwrap_or([0u8; 16]);
                state.so_pin_retry_count = b[97];
                let puk_hash: [u8; 32] = b[98..130].try_into().unwrap_or([0u8; 32]);
                state.puk_hash = if puk_hash == [0u8; 32] {
                    None
                } else {
                    Some(puk_hash)
                };
                state.puk_salt = b[130..146].try_into().unwrap_or([0u8; 16]);
                state.puk_retry_count = b[146];
                state.initialized = b[147] != 0;
            }
        }
    }

    /// KeyId for the persisted DKEK.
    pub fn sc_hsm_dkek_key_id() -> pico2hsm_core::key::KeyId {
        pico2hsm_core::key::KeyId::sc_hsm(0, 0xFD)
    }

    /// Persist the DKEK (or erase the record when there is none), encrypted
    /// by the keystore like every other key.
    ///
    /// Layout: `[0..32]` DKEK, `[32]` number of shares it was assembled from.
    pub fn save_dkek_to_store(
        state: &ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), HsmError> {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};

        let kid = Self::sc_hsm_dkek_key_id();
        let Some(dkek) = state.dkek.get_dkek() else {
            return store.erase_key(kid);
        };
        let mut obj = KeyObject::new(
            KmKeyType::Generic,
            kid.0,
            AppletId::ScHsm,
            AlgorithmId::AesGcm,
        );
        let _ = obj.private_key.extend_from_slice(dkek);
        let _ = obj.private_key.push(state.dkek.shares_total());
        store.save_key(&obj)
    }

    /// Restore a persisted DKEK into `state`.
    pub fn load_dkek_from_store(state: &mut ScHsmState, store: &mut dyn crate::storage::KeyStore) {
        if let Ok(Some(obj)) = store.fetch_key(Self::sc_hsm_dkek_key_id()) {
            let b = &obj.private_key;
            if let (Some(dkek), Some(&shares)) = (b.get(..32), b.get(32)) {
                if let Ok(dkek) = <&[u8; 32]>::try_from(dkek) {
                    state.dkek.restore_ready(dkek, shares);
                    state.dkek_shares_imported = shares;
                    state.dkek_shares_required = shares;
                }
            }
        }
    }

    /// KeyId for the enrolled peer public key in flash.
    pub fn sc_hsm_peer_pubkey_key_id() -> pico2hsm_core::key::KeyId {
        pico2hsm_core::key::KeyId::sc_hsm(0, 0xFC)
    }

    /// Persist the enrolled peer public key to flash.
    ///
    /// Stored as a Generic key object at `KeyId::sc_hsm(0, 0xFC)`.
    /// Layout:
    ///   [0..65]  peer P-256 uncompressed public key (04 || x || y)
    ///   [65]     reserved (0; formerly the unauthenticated-exchange flag)
    pub fn save_peer_pubkey_to_store(
        state: &ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), HsmError> {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
        use pico2hsm_core::key::AppletId;

        let kid = Self::sc_hsm_peer_pubkey_key_id();

        if let Some(ref pubkey) = state.noise_enrolled_peer_pubkey {
            let mut buf: heapless::Vec<u8, 128> = heapless::Vec::new();
            let _ = buf.extend_from_slice(pubkey);
            let _ = buf.push(0);

            let mut obj = KeyObject::new(
                KmKeyType::Generic,
                kid.0,
                AppletId::ScHsm,
                AlgorithmId::AesGcm,
            );
            let _ = obj.private_key.extend_from_slice(&buf);
            store.save_key(&obj)
        } else {
            // No peer enrolled — erase from flash if present.
            store.erase_key(kid)
        }
    }

    /// Load the enrolled peer public key from flash into `state`.
    pub fn load_peer_pubkey_from_store(
        state: &mut ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
    ) {
        let kid = Self::sc_hsm_peer_pubkey_key_id();
        if let Ok(Some(obj)) = store.fetch_key(kid) {
            let b = &obj.private_key;
            if b.len() >= 66 {
                let mut pubkey = [0u8; 65];
                pubkey.copy_from_slice(&b[0..65]);
                // Validate the key is still a valid P-256 point before trusting it.
                if p256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey).is_ok() {
                    state.noise_enrolled_peer_pubkey = Some(pubkey);
                }
            }
        }
    }

    /// Process a raw APDU with access to persistent storage.
    ///
    /// All key-mutating commands (INITIALIZE, GENERATE KEY PAIR, DELETE FILE)
    /// will persist/erase via `store`. Non-mutating commands fall through to
    /// the stateless dispatch path.
    ///
    /// GET RESPONSE chaining and Le-truncation are handled by the Dispatcher,
    /// not here. This method returns the full serialized response.
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
}

impl HsmProtocol for ScHsm {
    fn process_apdu(&mut self, apdu: &[u8]) -> Vec<u8, 4098> {
        // Used by the stateless dispatch path (host-side tests).
        // Key-mutating commands here use NullKeyStore (no-op flash writes).
        // GET RESPONSE chaining and Le-truncation are handled by the Dispatcher.
        let resp = match ApduCommand::parse(apdu) {
            Ok(cmd) => self.dispatch(&cmd),
            Err(_) => ApduResponse::err(SW_INS_NOT_SUPPORTED),
        };
        // Full serialized response: data (≤4096) + SW — never truncated.
        resp.serialize()
    }

    fn handles_aid(&self, aid: &[u8]) -> bool {
        aid == SC_HSM_AID
    }

    fn protocol_name(&self) -> &'static str {
        "SC-HSM"
    }
}

#[cfg(test)]
mod retry_persistence_tests {
    use super::*;
    use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
    use pico2hsm_core::apdu::SW_AUTH_BLOCKED;

    /// Records every PIN-record write; optionally fails the next one.
    struct PinStore {
        saves: heapless::Vec<heapless::Vec<u8, 160>, 32>,
        fail_next: bool,
        /// Fail the PIN-record write attempt with this index (0-based).
        fail_attempt: Option<usize>,
        attempts: usize,
    }

    impl PinStore {
        fn new() -> Self {
            PinStore {
                saves: heapless::Vec::new(),
                fail_next: false,
                fail_attempt: None,
                attempts: 0,
            }
        }
        /// (user, so, puk, ext-auth failures) from the record write `i`.
        fn counters(&self, i: usize) -> (u8, u8, u8, u8) {
            let b = &self.saves[i];
            (b[48], b[97], b[146], b[148])
        }
        fn last(&self) -> (u8, u8, u8, u8) {
            self.counters(self.saves.len() - 1)
        }
    }

    impl crate::storage::KeyStore for PinStore {
        fn save_key(&mut self, obj: &KeyObject) -> Result<(), HsmError> {
            if obj.key_id != ScHsm::sc_hsm_pin_key_id().0 {
                return Ok(());
            }
            let attempt = self.attempts;
            self.attempts += 1;
            if core::mem::take(&mut self.fail_next) || self.fail_attempt == Some(attempt) {
                return Err(HsmError::NotSupported);
            }
            let mut b = heapless::Vec::new();
            b.extend_from_slice(&obj.private_key).unwrap();
            self.saves.push(b).unwrap();
            Ok(())
        }
        fn fetch_key(&mut self, kid: KeyId) -> Result<Option<KeyObject>, HsmError> {
            if kid != ScHsm::sc_hsm_pin_key_id() {
                return Ok(None);
            }
            Ok(self.saves.last().map(|b| {
                let mut obj = KeyObject::new(
                    KmKeyType::Generic,
                    kid.0,
                    AppletId::ScHsm,
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

    const USER_PIN: &[u8] = b"648219";
    const SO_PIN: &[u8] = b"57621880";

    fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> heapless::Vec<u8, 300> {
        let mut v = heapless::Vec::new();
        v.extend_from_slice(&[cla, ins, p1, p2, data.len() as u8])
            .unwrap();
        v.extend_from_slice(data).unwrap();
        v
    }

    fn sw(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]])
    }

    fn init_data(so_pin: &[u8]) -> heapless::Vec<u8, 64> {
        let mut d = heapless::Vec::new();
        d.extend_from_slice(&[0x81, USER_PIN.len() as u8]).unwrap();
        d.extend_from_slice(USER_PIN).unwrap();
        d.extend_from_slice(&[0x82, so_pin.len() as u8]).unwrap();
        d.extend_from_slice(so_pin).unwrap();
        d
    }

    fn initialized() -> (ScHsm, PinStore) {
        let mut hsm = ScHsm::new();
        let mut store = PinStore::new();
        let r =
            hsm.process_apdu_with_store(&apdu(0x80, 0x50, 0, 0, &init_data(SO_PIN)), &mut store);
        assert_eq!(sw(&r), SW_OK);
        store.saves.clear();
        (hsm, store)
    }

    fn verify(hsm: &mut ScHsm, store: &mut PinStore, p2: u8, pin: &[u8]) -> u16 {
        sw(&hsm.process_apdu_with_store(&apdu(0x00, 0x20, 0, p2, pin), store))
    }

    #[test]
    fn failed_verify_is_on_flash_before_and_after() {
        let (mut hsm, mut store) = initialized();
        assert_eq!(verify(&mut hsm, &mut store, 0x81, b"000000"), 0x63C2);
        // Exactly one write, already carrying the spent retry.
        assert_eq!(store.saves.len(), 1);
        assert_eq!(store.last().0, 2);
    }

    #[test]
    fn successful_verify_spends_then_restores() {
        let (mut hsm, mut store) = initialized();
        assert_eq!(verify(&mut hsm, &mut store, 0x81, USER_PIN), SW_OK);
        assert_eq!(store.saves.len(), 2);
        assert_eq!(store.counters(0).0, 2, "retry spent before comparing");
        assert_eq!(store.counters(1).0, 3, "restored after success");
    }

    #[test]
    fn retries_survive_a_reset() {
        let (mut hsm, mut store) = initialized();
        verify(&mut hsm, &mut store, 0x81, b"000000");
        verify(&mut hsm, &mut store, 0x81, b"000000");
        // Power cycle / USB reset: fresh state reloaded from flash.
        let mut fresh = ScHsm::new();
        ScHsm::load_pin_state_from_store(&mut fresh.state, &mut store);
        assert_eq!(fresh.state.pin_retry_count, 1);
        assert_eq!(
            verify(&mut fresh, &mut store, 0x81, b"000000"),
            SW_AUTH_BLOCKED
        );
        assert_eq!(
            verify(&mut fresh, &mut store, 0x81, USER_PIN),
            SW_AUTH_BLOCKED
        );
        assert!(!fresh.state.pin_verified);
    }

    #[test]
    fn failed_pre_write_refuses_attempt() {
        let (mut hsm, mut store) = initialized();
        store.fail_next = true;
        assert_eq!(
            verify(&mut hsm, &mut store, 0x81, USER_PIN),
            SW_MEMORY_FAILURE
        );
        assert!(!hsm.state.pin_verified);
    }

    #[test]
    fn wrong_change_pin_spends_retry() {
        let (mut hsm, mut store) = initialized();
        let mut data: heapless::Vec<u8, 32> = heapless::Vec::new();
        data.extend_from_slice(b"000000").unwrap();
        data.extend_from_slice(b"111111").unwrap();
        let r = hsm.process_apdu_with_store(&apdu(0x00, 0x24, 0, 0x81, &data), &mut store);
        assert_ne!(sw(&r), SW_OK);
        assert_eq!(store.last().0, 2);
    }

    #[test]
    fn reinitialize_spends_so_retry_and_honours_block() {
        let (mut hsm, mut store) = initialized();
        let wrong = init_data(b"00000000");
        for left in (0..5u8).rev() {
            let r = hsm.process_apdu_with_store(&apdu(0x80, 0x50, 0, 0, &wrong), &mut store);
            assert_ne!(sw(&r), SW_OK);
            assert_eq!(store.last().1, left);
        }
        // Blocked: even the correct SO-PIN can no longer re-initialize.
        let r =
            hsm.process_apdu_with_store(&apdu(0x80, 0x50, 0, 0, &init_data(SO_PIN)), &mut store);
        assert_eq!(sw(&r), SW_AUTH_BLOCKED);
    }

    #[test]
    fn change_pin_with_failed_final_write_keeps_old_pin() {
        let (mut hsm, mut store) = initialized();
        // Attempt 0 = spend-before-compare, attempt 1 = persist the new PIN.
        store.fail_attempt = Some(store.attempts + 1);
        let mut data: heapless::Vec<u8, 32> = heapless::Vec::new();
        data.extend_from_slice(USER_PIN).unwrap();
        data.extend_from_slice(b"111111").unwrap();
        let r = hsm.process_apdu_with_store(&apdu(0x00, 0x24, 0, 0x81, &data), &mut store);
        assert_eq!(sw(&r), SW_MEMORY_FAILURE);
        // RAM matches flash: the old PIN still works, the new one does not.
        assert_eq!(verify(&mut hsm, &mut store, 0x81, b"111111"), 0x63C1);
        assert_eq!(verify(&mut hsm, &mut store, 0x81, USER_PIN), SW_OK);
    }

    #[test]
    fn short_user_pin_rejected() {
        let (mut hsm, mut store) = initialized();
        assert_eq!(verify(&mut hsm, &mut store, 0x81, b"1234"), 0x6700);
    }

    #[test]
    fn malformed_attempts_spend_nothing() {
        // The hardware fuzz suite (test_16) blocked both PINs this way.
        let (mut hsm, mut store) = initialized();
        let malformed: [&[u8]; 8] = [
            &[0x00, 0x20, 0x00, 0x81, 0x01, 0x41], // 1-byte PIN
            &[
                0x00, 0x20, 0xFF, 0x81, 0x06, b'6', b'4', b'8', b'2', b'1', b'9',
            ], // bad P1
            &[0x00, 0x20, 0x00, 0x88, 0x01, 0x00], // 1-byte SO-PIN
            &[0x00, 0x24, 0x00, 0xFF, 0x02, 0x31, 0x32], // CHANGE PIN, short new
            &[
                0x00, 0x24, 0x02, 0x81, 0x0C, b'1', b'2', b'3', b'4', b'5', b'6', b'1', b'2', b'3',
                b'4', b'5', b'6',
            ], // bad P1
            &[0x00, 0x28, 0x00, 0x00, 0x03, 0x41, 0x42, 0x43], // PUK too short
            &[
                0x00, 0x82, 0x00, 0x81, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            ], // no challenge
            &[0x80, 0x50, 0x00, 0x00, 0x04, 0x80, 0xFF, 0x01, 0x02], // INITIALIZE, no init code
        ];
        for a in malformed {
            let r = hsm.process_apdu_with_store(a, &mut store);
            assert_ne!(sw(&r), SW_OK, "{a:02X?}");
        }
        assert!(store.saves.is_empty(), "no retry spent on malformed APDUs");
        assert_eq!(
            (hsm.state.pin_retry_count, hsm.state.so_pin_retry_count),
            (3, 5)
        );
    }
}

#[cfg(test)]
mod reserved_slot_and_dkek_tests {
    use super::*;
    use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};

    /// Minimal in-memory store: keeps each record's private bytes by KeyId.
    struct MemStore {
        records: heapless::Vec<(KeyId, heapless::Vec<u8, 160>), 16>,
    }

    impl crate::storage::KeyStore for MemStore {
        fn save_key(&mut self, obj: &KeyObject) -> Result<(), HsmError> {
            let kid = KeyId(obj.key_id);
            self.records.retain(|(k, _)| *k != kid);
            let mut b = heapless::Vec::new();
            let _ = b.extend_from_slice(&obj.private_key[..obj.private_key.len().min(160)]);
            let _ = self.records.push((kid, b));
            Ok(())
        }
        fn fetch_key(&mut self, kid: KeyId) -> Result<Option<KeyObject>, HsmError> {
            Ok(self.records.iter().find(|(k, _)| *k == kid).map(|(_, b)| {
                let mut obj = KeyObject::new(
                    KmKeyType::Generic,
                    kid.0,
                    AppletId::ScHsm,
                    AlgorithmId::AesGcm,
                );
                obj.private_key.extend_from_slice(b).unwrap();
                obj
            }))
        }
        fn erase_key(&mut self, kid: KeyId) -> Result<(), HsmError> {
            self.records.retain(|(k, _)| *k != kid);
            Ok(())
        }
        fn wipe_all(&mut self) -> Result<(), HsmError> {
            self.records.clear();
            Ok(())
        }
        fn wipe_by_owner(&mut self, _: AppletId) -> Result<(), HsmError> {
            self.records.clear();
            Ok(())
        }
        fn enumerate_keys(&self) -> heapless::Vec<KeyId, 64> {
            heapless::Vec::new()
        }
        fn for_each_key(&self, _: &mut dyn FnMut(KeyId)) {}
    }

    fn sw(hsm: &mut ScHsm, store: &mut MemStore, apdu: &[u8]) -> u16 {
        let r = hsm.process_apdu_with_store(apdu, store);
        u16::from_be_bytes([r[r.len() - 2], r[r.len() - 1]])
    }

    fn logged_in() -> ScHsm {
        let mut hsm = ScHsm::new();
        hsm.state.initialized = true;
        hsm.state.pin_verified = true;
        hsm.state.so_pin_verified = true;
        hsm
    }

    #[test]
    fn key_commands_cannot_touch_reserved_slots() {
        let mut hsm = logged_in();
        let mut store = MemStore {
            records: heapless::Vec::new(),
        };
        for p1 in [0xFC, 0xFD, 0xFE] {
            // EXPORT KEY, IMPORT KEY, GENERATE KEY PAIR, SIGN, DECRYPT
            for ins in [0x72, 0x74, 0x46, 0x68, 0x62] {
                let apdu = [0x80, ins, p1, 0x92, 0x01, 0x00];
                assert_eq!(
                    sw(&mut hsm, &mut store, &apdu),
                    SW_INCORRECT_P1P2,
                    "ins {ins:02X} p1 {p1:02X}"
                );
            }
        }
        // MSE SET cannot select the device identity key either.
        assert_ne!(
            sw(
                &mut hsm,
                &mut store,
                &[0x00, 0x22, 0x41, 0xB6, 0x03, 0x84, 0x01, 0xFE]
            ),
            SW_OK
        );
        assert_eq!(hsm.state.current_key_id, None);
    }

    #[test]
    fn dkek_from_shares_survives_reset() {
        let mut hsm = logged_in();
        let mut store = MemStore {
            records: heapless::Vec::new(),
        };
        hsm.state.dkek.init_shares(2);
        let mut share = [0x80, 0x52, 0x00, 0x00, 0x20].to_vec();
        share.extend_from_slice(&[0x0Fu8; 32]);
        assert_eq!(sw(&mut hsm, &mut store, &share), SW_OK);
        assert!(
            store.records.is_empty(),
            "nothing to persist until complete"
        );
        share[5..].copy_from_slice(&[0xF0u8; 32]);
        assert_eq!(sw(&mut hsm, &mut store, &share), SW_OK);

        let mut fresh = ScHsm::new();
        ScHsm::load_dkek_from_store(&mut fresh.state, &mut store);
        assert_eq!(fresh.state.dkek.get_dkek(), Some(&[0xFFu8; 32]));
        assert_eq!(fresh.state.dkek.shares_total(), 2);
    }
}
