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
use crate::storage::retry_counter::{self, CounterState, Credential, RetryCounterBackend};
use crate::storage::{SoPin, SoPinHome};

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
            // INITIALIZE is authorised by the SO-PIN carried in the command
            // whenever one is set (re-INITIALIZE, or a store FORMAT STORE
            // emptied with the SO-PIN carried forward).
            initialize::INS_INITIALIZE
                if state.so_pin_hash.is_some() && initialize::well_formed(cmd) =>
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

    /// Its entry in the retry-counter log.
    fn credential(self) -> Credential {
        match self {
            Self::UserPin => Credential::ScHsmUserPin,
            Self::SoPin => Credential::ScHsmSoPin,
            Self::Puk => Credential::ScHsmPuk,
        }
    }

    const ALL: [Self; 3] = [Self::UserPin, Self::SoPin, Self::Puk];
}

/// A command that changes SC-HSM's objects, numbered by the Lamport
/// counter (see `ScHsm::numbered_change`).
#[derive(Clone, Copy, Debug)]
enum Change {
    /// GENERATE KEY PAIR, GENERATE KEY or UNWRAP into a key slot
    /// (`None`: the card picks the slot).
    Key { key_ref: Option<u8> },
    /// DELETE FILE of a key (CC xx) or an EF.
    Delete { local: KeyId },
    /// WRITE DATA / UPDATE BINARY of an EF, which `existed` before.
    WriteEf { local: KeyId, existed: bool },
}

impl Change {
    /// The change `cmd` would make, if its session may make one.  Mirrors
    /// each handler's own file addressing; a command it cannot address is
    /// left to the handler to refuse.
    fn of(cmd: &ApduCommand<'_>, state: &ScHsmState) -> Option<Self> {
        if !state.pin_verified && !state.so_pin_verified {
            return None;
        }
        let ef = |fid: u16| KeyId::sc_hsm_ef_checked(0, (fid >> 8) as u8, fid as u8);
        let existed = |kid: KeyId| {
            state
                .key_index
                .iter()
                .any(|m| m.key_type == 16 && m.key_id == kid.0)
        };
        match cmd.ins {
            generate_keypair::INS_GENERATE_KEYPAIR => Some(Change::Key {
                key_ref: (cmd.p1 != 0xFF).then_some(cmd.p1),
            }),
            generate_key::INS_GENERATE_KEY | import_key::INS_IMPORT_KEY => Some(Change::Key {
                key_ref: Some(cmd.p1),
            }),
            delete_file::INS_DELETE_FILE => {
                let fid = match cmd.p1 {
                    0x02 => u16::from_be_bytes([*cmd.data.first()?, *cmd.data.get(1)?]),
                    0x00 => state.current_file?,
                    _ => return None,
                };
                let local = if (fid >> 8) as u8 == delete_file::KEY_PREFIX {
                    KeyId::sc_hsm(0, fid as u8)
                } else {
                    ef(fid)?
                };
                Some(Change::Delete { local })
            }
            write_data::INS_WRITE_DATA => {
                let addressed = u16::from_be_bytes([cmd.p1, cmd.p2]);
                let fid = if addressed != 0 {
                    addressed
                } else {
                    state.current_file?
                };
                let local = ef(fid)?;
                Some(Change::WriteEf {
                    local,
                    existed: existed(local),
                })
            }
            update_binary::INS_UPDATE_BINARY => {
                let local = ef(state.current_file?)?;
                Some(Change::WriteEf {
                    local,
                    existed: existed(local),
                })
            }
            _ => None,
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
    fn enumerate_keys(&self) -> Vec<KeyId, 64> {
        Vec::new()
    }
    fn for_each_key(&self, _f: &mut dyn FnMut(KeyId)) {}
    fn retry_counters(&mut self) -> Option<&mut dyn RetryCounterBackend> {
        Some(self)
    }
}

/// No counters either: reads find no entry, writes succeed without effect.
impl RetryCounterBackend for LocalNullStore {
    fn get(
        &mut self,
        _: Credential,
    ) -> Result<Option<CounterState>, pico2hsm_core::error::StorageError> {
        Ok(None)
    }
    fn put(
        &mut self,
        _: Credential,
        _: CounterState,
    ) -> Result<(), pico2hsm_core::error::StorageError> {
        Ok(())
    }
    fn needs_migration(&mut self) -> bool {
        false
    }
    fn format(
        &mut self,
        _: &[(Credential, CounterState)],
    ) -> Result<(), pico2hsm_core::error::StorageError> {
        Ok(())
    }
    fn lamport(&mut self) -> Result<u64, pico2hsm_core::error::StorageError> {
        Ok(0)
    }
    fn put_lamport(&mut self, _: u64) -> Result<(), pico2hsm_core::error::StorageError> {
        Ok(())
    }
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

/// Capacity of the SC-HSM key/EF index (8 bytes per entry).  The store
/// refuses a new SC-HSM object past it (`keystore_v2`, 6A84): with a
/// smaller index than the store, an object was saved (9000) yet
/// unreachable until a reset.  Room for [`MAX_SC_HSM_KEYS`] keys with a
/// private key descriptor and a certificate each, the reserved objects and
/// at least 11 free-standing files, rounded up to 8 entries, and never
/// below the profile's 2.0.x index (boot skips objects past the index):
/// `pico2hsm_layout::geometry::key_index_size`.
pub const MAX_KEY_INDEX: usize = pico2hsm_layout::geometry::key_index_size(
    crate::storage::flash_layout::BOARD.profile,
    MAX_SC_HSM_KEYS as u32,
) as usize;

/// SC-HSM user keys a device holds (key refs below
/// [`RESERVED_KEY_REF_MIN`]); a key generation or import past it fails
/// with 6A84.  Computed by `build.rs` from the board's keystore size
/// (`pico2hsm_layout::geometry::max_sc_hsm_keys`; every key ref, 251, on
/// the 16 MB and SD boards), so that the keys with a descriptor and
/// certificate each fit next to everything PIV, OpenPGP and the domain
/// records can store, with the store's reserves intact.
/// `PICO2HSM_MAX_SC_HSM_KEYS` at build time may lower it.
pub const MAX_SC_HSM_KEYS: usize =
    crate::image_version::parse_u16(env!("PICO2HSM_SC_HSM_KEY_CAP")) as usize;

const _: () = assert!(MAX_SC_HSM_KEYS >= 1);
const _: () = assert!(MAX_SC_HSM_KEYS <= pico2hsm_layout::geometry::SC_HSM_KEY_REFS as usize);
const _: () = assert!(MAX_KEY_INDEX >= MAX_SC_HSM_KEYS * 3 + 4);

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
    pub data: Vec<u8, 1024>,
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

impl Default for OpBuffer {
    fn default() -> Self {
        Self::new()
    }
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
            // Never return unrandom bytes: a TRNG failure resets the chip.
            crate::crypto::rng::fill_or_reset(dest);
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
    /// The PIN record could not be loaded ([`ScHsm::lock_out`]): the user
    /// PIN and PUK are blocked in RAM only, their real counters stay in the
    /// log.  Only the SO-PIN (from the binding) is ever persisted in this
    /// state, until INITIALIZE replaces every credential.
    pub creds_locked: bool,

    /// Stored PUK hash (PBKDF2-HMAC-SHA256). None if no PUK is configured.
    pub puk_hash: Option<[u8; 32]>,
    /// 16-byte random salt for the PUK PBKDF2 hash.
    pub puk_salt: [u8; 16],
    /// Remaining PUK retry attempts (0 = blocked).
    pub puk_retry_count: u8,

    /// Lightweight metadata index for all keys and EF files in flash.
    /// Replaces the previous `keys`, `rsa_keys`, `sym_keys`, and `ef_files`
    /// Vec fields. Key material stays in flash; only metadata lives in RAM.
    pub key_index: Vec<KeyMeta, MAX_KEY_INDEX>,

    /// SC-HSM objects on flash that the last load could not index (the key
    /// index was full; #38).  They stay on flash.  GET PROVISIONING STATUS
    /// tag 86.
    pub skipped_at_boot: u32,

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

    /// Highest Lamport version seen in a record from another member
    /// (cluster plan V3 §6.1; raised by record import in P3).  The counter
    /// itself is persisted in the retry-counter log, never cached here.
    pub lamport_seen: u64,

    /// The domain key, derived from the DKEK whenever the DKEK is loaded
    /// or completed (`crate::domain::key`).  `None` without a DKEK.
    pub domain: Option<crate::domain::key::DomainKey>,

    /// The peer device's static public key (65-byte uncompressed P-256),
    /// pinned with ENROLL_PEER_PUBKEY for the next V2 DKEK exchange only
    /// (§5.2 step 3): the exchange that completes with it consumes it.
    /// Persisted at `domain::records::PINNED_PEER`.
    pub pinned_peer: Option<[u8; 65]>,

    /// The peer this device, as SOURCE, sent its DKEK to in a V2 exchange
    /// completed in this card session (step 3 spent the pin for it).
    /// ISSUE_MEMBER_CERT certifies only this key or a still-pinned peer —
    /// both operator-verified (§5.2).  Session state: cleared at session
    /// end, by INITIALIZE, and by the certificate it allows (single use).
    pub exchanged_peer: Option<[u8; 65]>,

    /// In-memory EF file data cache.
    ///
    /// Core1's `FlashQueueKeyStore::fetch_key()` always returns `Ok(None)` —
    /// flash reads aren't possible during synchronous APDU dispatch.  This
    /// cache stores EF file data written via WRITE DATA so that READ BINARY
    /// can serve it back without hitting flash.
    ///
    /// Populated by: `write_data::write_at_offset` (on write), and
    /// `load_keys_from_store` (on USB reconnect from flash).
    pub ef_cache: Vec<EfCacheEntry, 16>,
}

impl Default for ScHsmState {
    fn default() -> Self {
        Self::new()
    }
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
            creds_locked: false,
            puk_hash: None,
            puk_salt: [0u8; 16],
            puk_retry_count: 10,
            key_index: Vec::new(),
            skipped_at_boot: 0,
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
            lamport_seen: 0,
            domain: None,
            pinned_peer: None,
            exchanged_peer: None,
            ef_cache: Vec::new(),
        }
    }

    /// Initialise an `ScHsmState` directly into a destination pointer,
    /// writing each field individually to avoid placing the full struct
    /// (~9 KB with OpBuffer + ef_cache) on the stack.
    ///
    /// # Safety
    /// `dest` must be non-null, aligned and valid for writes of `Self`.  Any
    /// value already there is overwritten without being dropped.
    pub unsafe fn init_in_place(dest: *mut Self) {
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
            addr_of_mut!((*dest).creds_locked).write(false);
            addr_of_mut!((*dest).puk_hash).write(None);
            addr_of_mut!((*dest).puk_salt).write([0u8; 16]);
            addr_of_mut!((*dest).puk_retry_count).write(10);
            addr_of_mut!((*dest).key_index).write(Vec::new());
            addr_of_mut!((*dest).skipped_at_boot).write(0);
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
            addr_of_mut!((*dest).lamport_seen).write(0);
            addr_of_mut!((*dest).domain).write(None);
            addr_of_mut!((*dest).pinned_peer).write(None);
            addr_of_mut!((*dest).exchanged_peer).write(None);
            addr_of_mut!((*dest).ef_cache).write(Vec::new());
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
            data: Vec::new(),
        };
        // Files larger than an entry are not cached: READ BINARY serves the
        // cache first, so a truncated entry would be returned as the whole
        // file (an RSA-4096 certificate request is ~1.1 KB).  Uncached files
        // are read from flash.
        if entry.data.extend_from_slice(data).is_ok() {
            let _ = self.ef_cache.push(entry);
        }
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
    ///
    /// # Safety
    /// `dest` must be non-null, aligned and valid for writes of `Self`.  Any
    /// value already there is overwritten without being dropped.
    pub unsafe fn init_in_place(dest: *mut Self) {
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
    /// ever touched by the firmware's own code paths.  GENERATE KEY PAIR
    /// also refuses 0x00, the device key's reference (#36); GENERATE KEY
    /// and IMPORT KEY refuse it in their handlers.
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
            generate_keypair::INS_GENERATE_KEYPAIR => {
                cmd.p1 == 0x00 || (cmd.p1 != 0xFF && reserved(cmd.p1))
            }
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
        if self.state.dkek.is_ready() == had_dkek {
            return resp;
        }
        if Self::save_dkek_to_store(&self.state, store).is_err() {
            // A DKEK flash doesn't hold must not be used: anything wrapped
            // under it this session could never be unwrapped after a
            // reboot.  (A cleared DKEK stays cleared — the stricter side.)
            if self.state.dkek.is_ready() {
                self.state.dkek.clear();
                self.state.dkek_shares_imported = 0;
            }
            Self::derive_domain(&mut self.state);
            return ApduResponse::err(SW_MEMORY_FAILURE);
        }
        // The domain follows the DKEK (cluster plan V3 §4.1, §5.1).
        Self::derive_domain(&mut self.state);
        if Self::ensure_self_member(&self.state, store).is_err() {
            // The DKEK is on flash and stays; the self certificate is
            // retried at the next boot (`load_domain_from_store`).
            return ApduResponse::err(SW_MEMORY_FAILURE);
        }
        resp
    }

    /// Number a change with the Lamport counter (cluster plan V3 §6.1),
    /// then run it, then keep the object IDs (§6.2) in step with it.
    ///
    /// The counter is persisted *before* the change: a failure to persist
    /// refuses the command (6581) and nothing changes.  A refused or failed
    /// command leaves a gap in the numbering, which is harmless — the
    /// counter only has to grow.  Only sessions that may change something
    /// (user PIN or SO-PIN verified) spend a counter record, so
    /// unauthenticated APDUs cannot wear the log.
    fn numbered_change(
        &mut self,
        change: Change,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        use crate::domain::object_id;

        if retry_counter::advance_lamport(store, self.state.lamport_seen).is_err() {
            return ApduResponse::err(SW_MEMORY_FAILURE);
        }
        let resp = self.route_handler(cmd, store);
        if resp.sw != SW_OK {
            return resp;
        }
        match change {
            Change::Key { key_ref: Some(r) } => {
                let local = KeyId::sc_hsm(0, r);
                let symmetric = self.state.key_index.iter().any(|m| {
                    m.key_id == local.0
                        && (m.key_type == CoreKeyType::Aes128 as u8
                            || m.key_type == CoreKeyType::Aes192 as u8
                            || m.key_type == CoreKeyType::Aes256 as u8)
                });
                // Asymmetric keys have an intrinsic ID and need no sidecar.
                if symmetric && object_id::assign_random(store, local, object_id::KIND_KEY).is_err()
                {
                    self.undo_create(store, local);
                    return ApduResponse::err(SW_MEMORY_FAILURE);
                }
            }
            Change::Key { key_ref: None } => {}
            Change::Delete { local } => {
                // An orphaned sidecar is harmless: creating an object at
                // this address always writes a fresh one, and asymmetric
                // keys never read theirs.  The delete itself succeeded.
                match object_id::erase_sidecar(store, local) {
                    Ok(()) | Err(_) => {}
                }
            }
            Change::WriteEf { local, existed } => {
                let created = !existed
                    && self
                        .state
                        .key_index
                        .iter()
                        .any(|m| m.key_type == 16 && m.key_id == local.0);
                if created
                    && object_id::is_standalone_ef((local.0 & 0xFFFF) as u16)
                    && object_id::assign_random(store, local, object_id::KIND_FILE).is_err()
                {
                    self.undo_create(store, local);
                    return ApduResponse::err(SW_MEMORY_FAILURE);
                }
            }
        }
        resp
    }

    /// Roll back an object just created whose ID could not be stored.  If
    /// even the erase fails, the object stays and gets its ID lazily.
    fn undo_create(&mut self, store: &mut dyn crate::storage::KeyStore, local: KeyId) {
        if store.erase_key(local).is_ok() {
            self.state.key_index.retain(|m| m.key_id != local.0);
            self.state.ef_cache_remove(local.0);
        }
    }

    /// Spend one retry of `counter` on flash, run the command, then persist
    /// the outcome.
    ///
    /// The failure is appended to the retry-counter log *before* the
    /// handler compares the credential, so cutting power (or resetting USB)
    /// once the result is known cannot undo a failed guess.  The handler
    /// runs with the un-spent RAM counter so its own retry logic is
    /// unchanged; afterwards a failed command can never leave the counter
    /// above the spent value.
    ///
    /// A success costs one more counter record — the PIN record and the
    /// keystore directory are rewritten only when the command changed a
    /// credential (CHANGE PIN).  A failed pre-write refuses the attempt
    /// (SW 6581), failing closed.
    fn with_persisted_attempt(
        &mut self,
        counter: RetryCounter,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        let ram = *counter.get(&mut self.state);
        if ram == 0 {
            // Blocked: the handler reports it without comparing anything.
            return self.route_with_store(cmd, store);
        }
        let before = match retry_counter::spend(store, counter.credential(), ram) {
            Ok(available) => available.min(ram),
            Err(_) => return ApduResponse::err(SW_MEMORY_FAILURE),
        };
        *counter.get(&mut self.state) = before;
        if before == 0 {
            // The log says blocked: nothing was spent, nothing is compared.
            return self.route_with_store(cmd, store);
        }
        let spent = before - 1;
        let record_before = Self::pin_record(&self.state);

        let resp = self.route_with_store(cmd, store);

        let after = counter.get(&mut self.state);
        if resp.sw != SW_OK {
            if *after > spent {
                *after = spent;
            }
            // The failure is on flash already.  Whatever else a failed
            // handler touched in RAM goes back to what flash holds.
            Self::reload_counters(&mut self.state, store);
            return resp;
        }
        // INITIALIZE persists its own record (and counters).
        let changed = cmd.ins != initialize::INS_INITIALIZE
            && *Self::pin_record(&self.state) != *record_before;
        let persisted = if changed {
            Self::save_pin_to_store(&self.state, store)
        } else {
            Self::sync_counters(&self.state, store)
        };
        if persisted.is_err() {
            // Flash may hold the spent counter and the old credentials.
            // Make RAM match it rather than report a change that a reset
            // would silently undo, and fail closed.
            Self::restore_pin_record(&mut self.state, store);
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
        match Change::of(cmd, &self.state) {
            Some(change) => self.numbered_change(change, cmd, store),
            None => self.route_handler(cmd, store),
        }
    }

    /// The handler for `cmd`.
    fn route_handler(
        &mut self,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
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
            select::INS_SELECT => select::handle_with_store(&mut self.state, store, cmd),
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
            // Debug hooks that need the store (`debug` builds only).
            #[cfg(feature = "debug")]
            debug_dump::INS_DEBUG_DUMP if Self::validate_cla(cmd).is_ok() => {
                debug_dump::handle(cmd, store)
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
            debug_dump::INS_DEBUG_DUMP => debug_dump::handle(cmd, &mut LocalNullStore),
            _ => ApduResponse::err(SW_INS_NOT_SUPPORTED),
        }
    }
}

impl ScHsm {
    /// KeyId for the SC-HSM PIN state sentinel in flash.
    pub fn sc_hsm_pin_key_id() -> KeyId {
        KeyId::sc_hsm(0, 0xFF)
    }

    /// Serialize the SC-HSM PIN/SO-PIN/PUK record.
    ///
    /// Layout (149 bytes total — PBKDF2 + per-credential 16-byte salts):
    ///   [0..32]    user_pin_hash (PBKDF2, all zeros if None)
    ///   [32..48]   user_pin_salt (16 bytes)
    ///   [48]       0 (was pin_retry_count)
    ///   [49..81]   so_pin_hash (PBKDF2, all zeros if None)
    ///   [81..97]   so_pin_salt (16 bytes)
    ///   [97]       0 (was so_pin_retry_count)
    ///   [98..130]  puk_hash (PBKDF2, all zeros if None)
    ///   [130..146] puk_salt (16 bytes)
    ///   [146]      0 (was puk_retry_count)
    ///   [147]      initialized (1 = true, 0 = false)
    ///   [148]      reserved (0)
    ///
    /// The retry counters live in the retry-counter log
    /// (`storage::retry_counter`).  Records from before it held them in
    /// [48]/[97]/[146]; the boot migration copies them into the log and
    /// zeroes them, so a record never again carries a usable count — if
    /// the log is ever lost, these credentials load blocked.
    fn pin_record(state: &ScHsmState) -> Zeroizing<Vec<u8, 160>> {
        Self::pin_record_with(state, true)
    }

    /// [`Self::pin_record`]; without the SO-PIN (zeros) where the store
    /// keeps it in its binding block instead.
    fn pin_record_with(state: &ScHsmState, with_so_pin: bool) -> Zeroizing<Vec<u8, 160>> {
        let mut buf: Zeroizing<Vec<u8, 160>> = Zeroizing::new(Vec::new());
        let _ = buf.extend_from_slice(state.user_pin_hash.as_ref().unwrap_or(&[0u8; 32]));
        let _ = buf.extend_from_slice(&state.user_pin_salt);
        let _ = buf.push(0);
        let (so_hash, so_salt) = match state.so_pin_hash {
            Some(h) if with_so_pin => (h, state.so_pin_salt),
            _ => ([0u8; 32], [0u8; 16]),
        };
        let _ = buf.extend_from_slice(&so_hash);
        let _ = buf.extend_from_slice(&so_salt);
        let _ = buf.push(0);
        let _ = buf.extend_from_slice(state.puk_hash.as_ref().unwrap_or(&[0u8; 32]));
        let _ = buf.extend_from_slice(&state.puk_salt);
        let _ = buf.push(0);
        let _ = buf.push(state.initialized as u8);
        let _ = buf.push(0); // reserved (was EXTERNAL AUTHENTICATE failures)
        buf
    }

    /// Byte offsets of the legacy retry counts in a PIN record.
    const LEGACY_COUNT_AT: [(RetryCounter, usize); 3] = [
        (RetryCounter::UserPin, 48),
        (RetryCounter::SoPin, 97),
        (RetryCounter::Puk, 146),
    ];

    /// Persist the SC-HSM credentials: the retry counters first, then the
    /// PIN record at `KeyId::sc_hsm(0, 0xFF)`.
    ///
    /// Counters go first because every counter change made here was
    /// authorised (a verified old PIN, the SO-PIN or the PUK): if the
    /// record write then fails, the old credentials merely keep the reset
    /// counts they were entitled to.  The other order could leave a new
    /// PIN on flash with a stale count.
    pub fn save_pin_to_store(
        state: &ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), HsmError> {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
        use pico2hsm_core::key::AppletId;

        crate::CORE1_PROGRESS.store(34, core::sync::atomic::Ordering::Relaxed);
        Self::sync_counters(state, store)?;

        // The SO-PIN, where the store keeps it in its binding (STORAGE_V2
        // §8.1): written there before the record, which then holds none.
        let in_binding = match store.so_pin_home() {
            SoPinHome::Record => false,
            SoPinHome::Binding(cur) => {
                let want = state.so_pin_hash.map(|hash| SoPin {
                    salt: state.so_pin_salt,
                    hash,
                });
                if cur != want {
                    store.set_binding_so_pin(want.as_ref())?;
                }
                true
            }
        };

        if state.creds_locked && in_binding {
            // The record on flash stays as it is (see `creds_locked`).
            return Ok(());
        }

        crate::CORE1_PROGRESS.store(35, core::sync::atomic::Ordering::Relaxed);
        let kid = Self::sc_hsm_pin_key_id();
        let mut obj = KeyObject::new(
            KmKeyType::Generic,
            kid.0,
            AppletId::ScHsm,
            AlgorithmId::AesGcm,
        );
        crate::CORE1_PROGRESS.store(36, core::sync::atomic::Ordering::Relaxed);
        let _ = obj
            .private_key
            .extend_from_slice(&Self::pin_record_with(state, !in_binding));
        crate::CORE1_PROGRESS.store(37, core::sync::atomic::Ordering::Relaxed);
        let result = store.save_key(&obj);
        crate::CORE1_PROGRESS.store(38, core::sync::atomic::Ordering::Relaxed);
        result
    }

    /// Write every SC-HSM counter whose RAM value differs from the log.
    /// With the credentials locked out, only the SO-PIN's: the others are
    /// zero in RAM only (see `creds_locked`).
    fn sync_counters(
        state: &ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), HsmError> {
        for (cred, n) in [
            (Credential::ScHsmUserPin, state.pin_retry_count),
            (Credential::ScHsmSoPin, state.so_pin_retry_count),
            (Credential::ScHsmPuk, state.puk_retry_count),
        ] {
            if state.creds_locked && cred != Credential::ScHsmSoPin {
                continue;
            }
            retry_counter::set(store, cred, n)?;
        }
        Ok(())
    }

    /// Set the RAM counters from the log.  `record_exists`: the PIN record
    /// is on flash, so a missing entry means blocked (see
    /// `retry_counter::load`); otherwise the RAM value stands.
    fn load_counters(
        state: &mut ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
        record_exists: bool,
    ) {
        for c in RetryCounter::ALL {
            let fresh = *c.get(state);
            *c.get(state) = retry_counter::load(store, c.credential(), record_exists, fresh);
        }
    }

    /// Runtime: make the RAM counters what the log holds.  A credential the
    /// log has no entry for yet keeps its RAM count (boot loading already
    /// failed closed where an entry was missing).
    pub(crate) fn reload_counters(
        state: &mut ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
    ) {
        Self::load_counters(state, store, false);
    }

    /// Load PIN/SO-PIN/PUK state from flash into `state`.
    pub fn load_pin_state_from_store(
        state: &mut ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
    ) {
        // Boot / reset only (needs a store that can enumerate: core0's).
        // A missing record is a fresh device only while nothing else of
        // SC-HSM's is stored: INITIALIZE writes it together with the device
        // key.  Missing next to stored objects, unreadable, or malformed
        // means the flash was damaged or tampered with: lock out instead of
        // loading "uninitialized", which let INITIALIZE run without the
        // SO-PIN and the retry counters reset.
        let pin_kid = Self::sc_hsm_pin_key_id();
        let mut has_content = false;
        store.for_each_key(&mut |kid| {
            if kid.applet_byte() == AppletId::ScHsm as u8 && kid != pin_kid {
                has_content = true;
            }
        });
        let locked = match store.fetch_key(pin_kid) {
            Ok(Some(obj)) if Self::apply_pin_record(state, &obj.private_key) => {
                Self::load_counters(state, store, true);
                false
            }
            Ok(None) if !has_content => {
                Self::load_counters(state, store, false);
                false
            }
            _ => {
                Self::lock_out(state);
                true
            }
        };
        Self::apply_binding_so_pin(state, store, locked);
    }

    /// The SO-PIN from the binding block, where the store keeps it there
    /// (STORAGE_V2 §8.1).  It overrides the record, and stays usable when
    /// the record cannot be read (`locked`: a refused store, damage), so
    /// the SO-PIN can authenticate recovery and re-INITIALIZE; its retry
    /// counter is the log's (a missing entry is blocked).  A record from
    /// before 2.0's binding still carrying an SO-PIN moves it into the
    /// binding.
    fn apply_binding_so_pin(
        state: &mut ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
        locked: bool,
    ) {
        let SoPinHome::Binding(so) = store.so_pin_home() else {
            return;
        };
        match so {
            Some(so) => {
                state.so_pin_salt = so.salt;
                state.so_pin_hash = Some(so.hash);
                if locked {
                    state.so_pin_retry_count =
                        retry_counter::load(store, Credential::ScHsmSoPin, true, 0);
                }
            }
            None if locked => {}
            None => {
                if let Some(hash) = state.so_pin_hash {
                    let so = SoPin {
                        salt: state.so_pin_salt,
                        hash,
                    };
                    // On failure the record keeps it until the next boot.
                    let _ = store.set_binding_so_pin(Some(&so));
                }
            }
        }
    }

    /// Runtime rollback after a failed save: put RAM back to the record and
    /// counters on flash, or lock out if the record can't be read.
    fn restore_pin_record(state: &mut ScHsmState, store: &mut dyn crate::storage::KeyStore) {
        let locked = match store.fetch_key(Self::sc_hsm_pin_key_id()) {
            Ok(Some(obj)) if Self::apply_pin_record(state, &obj.private_key) => {
                Self::load_counters(state, store, false);
                false
            }
            Ok(None) if !state.initialized => {
                Self::load_counters(state, store, false);
                false
            }
            _ => {
                Self::lock_out(state);
                true
            }
        };
        Self::apply_binding_so_pin(state, store, locked);
    }

    /// Every credential blocked, SO-PIN included, so INITIALIZE refuses too.
    /// Recovery is a full flash erase (physical access), as on a real card.
    fn lock_out(state: &mut ScHsmState) {
        state.creds_locked = true;
        state.initialized = true;
        state.so_pin_hash = Some([0xA5; 32]);
        state.so_pin_retry_count = 0;
        state.user_pin_hash = Some([0xA5; 32]);
        state.pin_retry_count = 0;
        state.puk_retry_count = 0;
        state.pin_verified = false;
        state.so_pin_verified = false;
    }

    /// Decode a PIN record (149-byte PBKDF2+salt format) into `state`.
    /// Shorter (legacy bare-SHA-256) records are refused.  The counters
    /// come from the retry-counter log, not from the record.
    fn apply_pin_record(state: &mut ScHsmState, b: &[u8]) -> bool {
        if b.len() < 149 {
            return false;
        }
        let nonzero = |h: [u8; 32]| (h != [0u8; 32]).then_some(h);
        state.user_pin_hash = nonzero(b[0..32].try_into().unwrap_or([0u8; 32]));
        state.user_pin_salt = b[32..48].try_into().unwrap_or([0u8; 16]);
        state.so_pin_hash = nonzero(b[49..81].try_into().unwrap_or([0u8; 32]));
        state.so_pin_salt = b[81..97].try_into().unwrap_or([0u8; 16]);
        state.puk_hash = nonzero(b[98..130].try_into().unwrap_or([0u8; 32]));
        state.puk_salt = b[130..146].try_into().unwrap_or([0u8; 16]);
        state.initialized = b[147] != 0;
        state.creds_locked = false;
        true
    }

    /// Migration: the retry counts a pre-counter-log PIN record carries, as
    /// seeds for the log.  No record: nothing to seed.  A record that
    /// exists but can't be read aborts the migration (it runs again next
    /// boot) rather than seeding a log that would lock it out for good;
    /// a malformed one seeds 0 (it loads locked out anyway).
    pub fn legacy_retry_seeds(
        store: &mut dyn crate::storage::KeyStore,
        seeds: &mut Vec<(Credential, CounterState), 8>,
    ) -> Result<(), HsmError> {
        let Some(obj) = store.fetch_key(Self::sc_hsm_pin_key_id())? else {
            return Ok(());
        };
        let b = &obj.private_key;
        for (c, at) in Self::LEGACY_COUNT_AT {
            let n = if b.len() >= 149 { b[at] } else { 0 };
            seeds
                .push((c.credential(), CounterState::fresh(n)))
                .map_err(|_| HsmError::InvalidInput)?;
        }
        Ok(())
    }

    /// Migration, after the log is committed: zero the retry counts in the
    /// PIN record so it never again holds a usable count.
    pub fn clear_legacy_retry_counts(
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), HsmError> {
        let Some(mut obj) = store.fetch_key(Self::sc_hsm_pin_key_id())? else {
            return Ok(());
        };
        let b = &mut obj.private_key;
        if b.len() < 149 || Self::LEGACY_COUNT_AT.iter().all(|&(_, at)| b[at] == 0) {
            return Ok(());
        }
        for (_, at) in Self::LEGACY_COUNT_AT {
            b[at] = 0;
        }
        store.save_key(&obj)
    }

    /// KeyId for the persisted DKEK.
    pub fn sc_hsm_dkek_key_id() -> KeyId {
        KeyId::sc_hsm(0, 0xFD)
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

    /// KeyId of the legacy permanent peer slot (before the member list).
    /// Read once by the boot migration, then erased; still reserved.
    pub fn sc_hsm_peer_pubkey_key_id() -> KeyId {
        KeyId::sc_hsm(0, 0xFC)
    }

    /// Persist the pinned peer (or erase the record when there is none).
    ///
    /// Stored as a Generic key object at `domain::records::PINNED_PEER`:
    ///   [0..65]  peer P-256 uncompressed public key (04 || x || y)
    ///   [65]     reserved (0)
    #[inline(never)] // keeps its KeyObject temporaries off the caller's frame (core1 stack)
    pub fn save_pinned_peer(
        state: &ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), HsmError> {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};

        let kid = crate::domain::records::PINNED_PEER;
        let Some(ref pubkey) = state.pinned_peer else {
            if store.fetch_key(kid)?.is_some() {
                return store.erase_key(kid);
            }
            return Ok(());
        };
        let mut obj = KeyObject::new(
            KmKeyType::Generic,
            kid.0,
            AppletId::Domain,
            AlgorithmId::AesGcm,
        );
        let _ = obj.private_key.extend_from_slice(pubkey);
        let _ = obj.private_key.push(0);
        store.save_key(&obj)
    }

    /// Spend the pinned peer: erase it from flash, then from RAM.  Called
    /// by the exchange step that releases or installs the DKEK, *before*
    /// it does so — a pin that cannot be erased stops the exchange.
    #[inline(never)] // keeps its KeyObject temporaries off the caller's frame (core1 stack)
    pub fn consume_pinned_peer(
        state: &mut ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), HsmError> {
        // A legacy 0xFC record not yet moved (`migrate_domain`) is the
        // same pin and goes too, or it would come back at the next boot.
        for kid in [
            crate::domain::records::PINNED_PEER,
            Self::sc_hsm_peer_pubkey_key_id(),
        ] {
            if store.fetch_key(kid)?.is_some() {
                store.erase_key(kid)?;
            }
        }
        state.pinned_peer = None;
        Ok(())
    }

    /// A stored peer record's key, if it is a valid P-256 point.
    fn peer_from_record(b: &[u8]) -> Option<[u8; 65]> {
        let pubkey: [u8; 65] = b.get(..65)?.try_into().ok()?;
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey)
            .is_ok()
            .then_some(pubkey)
    }

    /// Load the pinned peer into `state` (read only).  A peer enrolled in
    /// the legacy permanent slot 0xFC, not yet moved by `migrate_domain`,
    /// is the pin for the next exchange.
    #[inline(never)] // keeps its KeyObject temporaries off the caller's frame (core1 stack)
    pub fn load_pinned_peer(state: &mut ScHsmState, store: &mut dyn crate::storage::KeyStore) {
        state.pinned_peer = None;
        for kid in [
            crate::domain::records::PINNED_PEER,
            Self::sc_hsm_peer_pubkey_key_id(),
        ] {
            if let Ok(Some(obj)) = store.fetch_key(kid) {
                state.pinned_peer = Self::peer_from_record(&obj.private_key);
                return;
            }
        }
    }

    /// Move a legacy 0xFC enrollment into the pinned-peer record: write
    /// the new record, then erase 0xFC.  Either step failing leaves a state
    /// `load_pinned_peer` reads the same way; the move is retried at the
    /// next boot.
    #[inline(never)]
    fn migrate_legacy_peer(state: &ScHsmState, store: &mut dyn crate::storage::KeyStore) {
        let legacy = Self::sc_hsm_peer_pubkey_key_id();
        if state.pinned_peer.is_none() || !matches!(store.fetch_key(legacy), Ok(Some(_))) {
            return;
        }
        if Self::save_pinned_peer(state, store).is_ok() {
            // If the erase fails both records hold the same key, and
            // consuming the pin erases both.
            match store.erase_key(legacy) {
                Ok(()) | Err(_) => {}
            }
        }
    }

    /// The device identity (member) public key, from key ref 0xFE.
    #[inline(never)] // keeps its KeyObject temporaries off the caller's frame (core1 stack)
    pub fn device_member_pub(store: &mut dyn crate::storage::KeyStore) -> Option<[u8; 65]> {
        match store.fetch_key(KeyId::sc_hsm(0, 0xFE)) {
            Ok(Some(obj)) => obj.public_key.as_slice().try_into().ok(),
            _ => None,
        }
    }

    /// Derive the domain key from the DKEK in `state` (or drop it if there
    /// is no DKEK).
    pub fn derive_domain(state: &mut ScHsmState) {
        state.domain = state
            .dkek
            .get_dkek()
            .and_then(|d| crate::domain::key::DomainKey::derive(d).ok());
    }

    /// A device that holds the DKEK and has no member list yet issues its
    /// own member certificate (§5.1): sponsor = itself, may sponsor.  The
    /// Lamport counter is advanced first; the certificate carries the new
    /// value.  `Ok(false)`: nothing to do (no domain key, no identity key,
    /// or a list already exists).
    pub fn ensure_self_member(
        state: &ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<bool, HsmError> {
        use crate::domain::member;

        let Some(domain) = state.domain.as_ref() else {
            return Ok(false);
        };
        let Some(own) = Self::device_member_pub(store) else {
            return Ok(false);
        };
        if member::count(store)? > 0 {
            return Ok(false);
        }
        let lamport = retry_counter::advance_lamport(store, state.lamport_seen)?;
        Self::save_self_cert(domain, &own, lamport, store)?;
        Ok(true)
    }

    #[inline(never)]
    fn save_self_cert(
        domain: &crate::domain::key::DomainKey,
        own: &[u8; 65],
        lamport: u64,
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<(), HsmError> {
        use crate::domain::member::{self, MemberCert, MemberEntry, FLAG_MAY_SPONSOR};
        let id = member::member_id(own);
        let cert = MemberCert::issue(domain, own, &id, lamport, FLAG_MAY_SPONSOR)
            .map_err(|_| HsmError::Crypto(pico2hsm_core::error::CryptoError::SignFailure))?;
        member::save(store, 0, &MemberEntry::active(cert))
    }

    /// Boot / reset, read only: the pinned peer and the domain key.  Runs
    /// after `load_dkek_from_store`.  (On the SD-card boards a USB reset
    /// reloads on core1, which must not write the counter log on internal
    /// flash — so all writes are in [`Self::migrate_domain`].)
    pub fn load_domain_from_store(
        state: &mut ScHsmState,
        store: &mut dyn crate::storage::KeyStore,
    ) {
        Self::load_pinned_peer(state, store);
        Self::derive_domain(state);
    }

    /// Boot only, on core0, after the load: move a legacy 0xFC enrollment
    /// into the pinned-peer record, and let a device that held a DKEK
    /// before this firmware certify itself.  Failures are retried at the
    /// next boot (DOMAIN_STATUS shows a missing self certificate).
    pub fn migrate_domain(state: &ScHsmState, store: &mut dyn crate::storage::KeyStore) {
        Self::migrate_legacy_peer(state, store);
        match Self::ensure_self_member(state, store) {
            Ok(_) | Err(_) => {}
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
    use crate::storage::retry_counter::MemCounters;
    use pico2hsm_core::apdu::SW_AUTH_BLOCKED;

    /// Keeps every PIN-record write (the last one is "on flash") and the
    /// retry-counter log; either can be made to fail.
    struct PinStore {
        counters: MemCounters,
        saves: heapless::Vec<heapless::Vec<u8, 160>, 32>,
        /// Fail the PIN-record write attempt with this index (0-based).
        fail_attempt: Option<usize>,
        attempts: usize,
    }

    impl PinStore {
        fn new() -> Self {
            PinStore {
                counters: MemCounters::default(),
                saves: heapless::Vec::new(),
                fail_attempt: None,
                attempts: 0,
            }
        }
        fn left(&self, cred: Credential) -> Option<u8> {
            self.counters.remaining(cred)
        }
        /// Remaining-count history of `cred` in the counter log.
        fn history(&self, cred: Credential) -> heapless::Vec<u8, 64> {
            self.counters
                .puts
                .iter()
                .filter(|(c, _)| *c == cred)
                .map(|(_, s)| s.remaining())
                .collect()
        }
    }

    impl crate::storage::KeyStore for PinStore {
        fn save_key(&mut self, obj: &KeyObject) -> Result<(), HsmError> {
            if obj.key_id != ScHsm::sc_hsm_pin_key_id().0 {
                return Ok(());
            }
            let attempt = self.attempts;
            self.attempts += 1;
            if self.fail_attempt == Some(attempt) {
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
        fn retry_counters(&mut self) -> Option<&mut dyn RetryCounterBackend> {
            Some(&mut self.counters)
        }
    }

    const USER_PIN: &[u8] = b"648219";
    const SO_PIN: &[u8] = b"57621880";
    const USER: Credential = Credential::ScHsmUserPin;
    const SO: Credential = Credential::ScHsmSoPin;

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

    /// An initialized device; the counter-log history and the record count
    /// are where tests start measuring.
    fn initialized() -> (ScHsm, PinStore, usize) {
        let mut hsm = ScHsm::new();
        let mut store = PinStore::new();
        let r =
            hsm.process_apdu_with_store(&apdu(0x80, 0x50, 0, 0, &init_data(SO_PIN)), &mut store);
        assert_eq!(sw(&r), SW_OK);
        assert_eq!(store.left(USER), Some(3), "INITIALIZE sets the log");
        assert_eq!(store.left(SO), Some(5));
        store.counters.puts.clear();
        let records = store.saves.len();
        (hsm, store, records)
    }

    fn verify(hsm: &mut ScHsm, store: &mut PinStore, p2: u8, pin: &[u8]) -> u16 {
        sw(&hsm.process_apdu_with_store(&apdu(0x00, 0x20, 0, p2, pin), store))
    }

    #[test]
    fn failed_verify_is_one_counter_record_and_no_pin_record() {
        let (mut hsm, mut store, records) = initialized();
        assert_eq!(verify(&mut hsm, &mut store, 0x81, b"000000"), 0x63C2);
        assert_eq!(&store.history(USER)[..], &[2], "spent before comparing");
        assert_eq!(store.saves.len(), records, "PIN record untouched");
    }

    #[test]
    fn successful_verify_spends_then_restores_without_pin_record() {
        let (mut hsm, mut store, records) = initialized();
        assert_eq!(verify(&mut hsm, &mut store, 0x81, USER_PIN), SW_OK);
        assert_eq!(
            &store.history(USER)[..],
            &[2, 3],
            "spent before comparing, restored after"
        );
        assert_eq!(store.counters.puts.len(), 2, "two counter records in all");
        assert_eq!(store.saves.len(), records, "no keystore write (R2-4)");
    }

    #[test]
    fn retries_survive_a_reset() {
        let (mut hsm, mut store, _) = initialized();
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
    fn pin_record_never_carries_a_usable_count() {
        let (_, store, _) = initialized();
        let b = store.saves.last().unwrap();
        assert_eq!((b[48], b[97], b[146]), (0, 0, 0));
    }

    #[test]
    fn record_without_counter_entry_loads_blocked() {
        let (_, mut store, _) = initialized();
        // The log lost the entries (the record is still there).
        store.counters.entries = Default::default();
        let mut fresh = ScHsm::new();
        ScHsm::load_pin_state_from_store(&mut fresh.state, &mut store);
        assert!(fresh.state.initialized);
        assert_eq!(
            (
                fresh.state.pin_retry_count,
                fresh.state.so_pin_retry_count,
                fresh.state.puk_retry_count
            ),
            (0, 0, 0)
        );
    }

    #[test]
    fn unreadable_log_loads_blocked() {
        let (_, mut store, _) = initialized();
        store.counters.unformatted = true;
        let mut fresh = ScHsm::new();
        ScHsm::load_pin_state_from_store(&mut fresh.state, &mut store);
        assert_eq!(fresh.state.pin_retry_count, 0);
        assert_eq!(fresh.state.so_pin_retry_count, 0);
    }

    #[test]
    fn failed_pre_write_refuses_attempt() {
        let (mut hsm, mut store, _) = initialized();
        store.counters.fail_put = Some(store.counters.attempts);
        assert_eq!(
            verify(&mut hsm, &mut store, 0x81, USER_PIN),
            SW_MEMORY_FAILURE
        );
        assert!(!hsm.state.pin_verified);
        assert_eq!(store.left(USER), Some(3));
    }

    #[test]
    fn failed_restore_after_success_fails_closed() {
        let (mut hsm, mut store, _) = initialized();
        // The spend lands, the restore doesn't.
        store.counters.fail_put = Some(store.counters.attempts + 1);
        assert_eq!(
            verify(&mut hsm, &mut store, 0x81, USER_PIN),
            SW_MEMORY_FAILURE
        );
        assert!(!hsm.state.pin_verified);
        assert_eq!(hsm.state.pin_retry_count, 2, "RAM follows the log");
        assert_eq!(store.left(USER), Some(2));
    }

    #[test]
    fn wrong_change_pin_spends_retry() {
        let (mut hsm, mut store, records) = initialized();
        let mut data: heapless::Vec<u8, 32> = heapless::Vec::new();
        data.extend_from_slice(b"000000").unwrap();
        data.extend_from_slice(b"111111").unwrap();
        let r = hsm.process_apdu_with_store(&apdu(0x00, 0x24, 0, 0x81, &data), &mut store);
        assert_ne!(sw(&r), SW_OK);
        assert_eq!(store.left(USER), Some(2));
        assert_eq!(store.saves.len(), records);
    }

    #[test]
    fn change_pin_rewrites_the_record_once() {
        let (mut hsm, mut store, records) = initialized();
        let mut data: heapless::Vec<u8, 32> = heapless::Vec::new();
        data.extend_from_slice(USER_PIN).unwrap();
        data.extend_from_slice(b"111111").unwrap();
        let r = hsm.process_apdu_with_store(&apdu(0x00, 0x24, 0, 0x81, &data), &mut store);
        assert_eq!(sw(&r), SW_OK);
        assert_eq!(store.saves.len(), records + 1);
        let mut fresh = ScHsm::new();
        ScHsm::load_pin_state_from_store(&mut fresh.state, &mut store);
        assert_eq!(verify(&mut fresh, &mut store, 0x81, b"111111"), SW_OK);
    }

    #[test]
    fn reinitialize_spends_so_retry_and_honours_block() {
        let (mut hsm, mut store, _) = initialized();
        let wrong = init_data(b"00000000");
        for left in (0..5u8).rev() {
            let r = hsm.process_apdu_with_store(&apdu(0x80, 0x50, 0, 0, &wrong), &mut store);
            assert_ne!(sw(&r), SW_OK);
            assert_eq!(store.left(SO), Some(left));
        }
        // Blocked: even the correct SO-PIN can no longer re-initialize.
        let r =
            hsm.process_apdu_with_store(&apdu(0x80, 0x50, 0, 0, &init_data(SO_PIN)), &mut store);
        assert_eq!(sw(&r), SW_AUTH_BLOCKED);
        // ...and a reset doesn't change that.
        let mut fresh = ScHsm::new();
        ScHsm::load_pin_state_from_store(&mut fresh.state, &mut store);
        assert_eq!(fresh.state.so_pin_retry_count, 0);
    }

    #[test]
    fn reinitialize_resets_every_counter() {
        let (mut hsm, mut store, _) = initialized();
        verify(&mut hsm, &mut store, 0x81, b"000000");
        let r =
            hsm.process_apdu_with_store(&apdu(0x80, 0x50, 0, 0, &init_data(SO_PIN)), &mut store);
        assert_eq!(sw(&r), SW_OK);
        assert_eq!(store.left(USER), Some(3));
        assert_eq!(store.left(SO), Some(5));
    }

    #[test]
    fn change_pin_with_failed_final_write_keeps_old_pin() {
        let (mut hsm, mut store, _) = initialized();
        // The record write for the new PIN fails.
        store.fail_attempt = Some(store.attempts);
        let mut data: heapless::Vec<u8, 32> = heapless::Vec::new();
        data.extend_from_slice(USER_PIN).unwrap();
        data.extend_from_slice(b"111111").unwrap();
        let r = hsm.process_apdu_with_store(&apdu(0x00, 0x24, 0, 0x81, &data), &mut store);
        assert_eq!(sw(&r), SW_MEMORY_FAILURE);
        // RAM matches flash: the old PIN still works, the new one does not.
        // (The old PIN was verified, so its counter reset stands.)
        assert_eq!(hsm.state.pin_retry_count, 3);
        assert_eq!(verify(&mut hsm, &mut store, 0x81, b"111111"), 0x63C2);
        assert_eq!(verify(&mut hsm, &mut store, 0x81, USER_PIN), SW_OK);
    }

    #[test]
    fn change_pin_with_failed_counter_write_keeps_old_pin() {
        let (mut hsm, mut store, records) = initialized();
        // The spend lands; resetting the counter for the new PIN fails.
        store.counters.fail_put = Some(store.counters.attempts + 1);
        let mut data: heapless::Vec<u8, 32> = heapless::Vec::new();
        data.extend_from_slice(USER_PIN).unwrap();
        data.extend_from_slice(b"111111").unwrap();
        let r = hsm.process_apdu_with_store(&apdu(0x00, 0x24, 0, 0x81, &data), &mut store);
        assert_eq!(sw(&r), SW_MEMORY_FAILURE);
        assert_eq!(store.saves.len(), records, "record not written");
        assert_eq!(hsm.state.pin_retry_count, 2);
        assert_eq!(verify(&mut hsm, &mut store, 0x81, b"111111"), 0x63C1);
        assert_eq!(verify(&mut hsm, &mut store, 0x81, USER_PIN), SW_OK);
    }

    #[test]
    fn short_user_pin_rejected() {
        let (mut hsm, mut store, _) = initialized();
        assert_eq!(verify(&mut hsm, &mut store, 0x81, b"1234"), 0x6700);
    }

    #[test]
    fn malformed_attempts_spend_nothing() {
        // The hardware fuzz suite (test_16) blocked both PINs this way.
        let (mut hsm, mut store, records) = initialized();
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
        assert!(
            store.counters.puts.is_empty(),
            "no retry spent on malformed APDUs"
        );
        assert_eq!(store.saves.len(), records);
        assert_eq!(
            (hsm.state.pin_retry_count, hsm.state.so_pin_retry_count),
            (3, 5)
        );
    }

    /// A PIN record as firmware before the counter log wrote it.
    fn legacy_store(user: u8, so: u8, puk: u8) -> PinStore {
        let (hsm, mut store, _) = initialized();
        let mut rec = ScHsm::pin_record(&hsm.state);
        (rec[48], rec[97], rec[146]) = (user, so, puk);
        store.saves.clear();
        store.saves.push(rec.iter().copied().collect()).unwrap();
        store.counters = MemCounters {
            unformatted: true,
            ..MemCounters::default()
        };
        store
    }

    #[test]
    fn migration_seeds_the_log_from_the_pin_record() {
        let mut store = legacy_store(1, 4, 9);
        let ran = crate::apdu::dispatcher::Dispatcher::migrate_retry_counters(&mut store);
        assert_eq!(ran, Ok(true));
        assert_eq!(store.left(USER), Some(1));
        assert_eq!(store.left(SO), Some(4));
        assert_eq!(store.left(Credential::ScHsmPuk), Some(9));
        // The record no longer holds a count.
        let b = store.saves.last().unwrap();
        assert_eq!((b[48], b[97], b[146]), (0, 0, 0));
        // Loading after the migration gives the migrated counts.
        let mut hsm = ScHsm::new();
        ScHsm::load_pin_state_from_store(&mut hsm.state, &mut store);
        assert_eq!(
            (hsm.state.pin_retry_count, hsm.state.so_pin_retry_count),
            (1, 4)
        );
        assert_eq!(verify(&mut hsm, &mut store, 0x81, USER_PIN), SW_OK);
        // Runs once.
        let again = crate::apdu::dispatcher::Dispatcher::migrate_retry_counters(&mut store);
        assert_eq!(again, Ok(false));
    }

    #[test]
    fn unmigrated_log_loads_blocked_and_migrates_next_time() {
        let mut store = legacy_store(3, 5, 10);
        // Migration did not run (or its commit failed): fail closed.
        let mut hsm = ScHsm::new();
        ScHsm::load_pin_state_from_store(&mut hsm.state, &mut store);
        assert_eq!(hsm.state.pin_retry_count, 0);
        assert_eq!(
            verify(&mut hsm, &mut store, 0x81, USER_PIN),
            SW_AUTH_BLOCKED
        );
        assert_eq!(store.saves.last().unwrap()[48], 3, "record untouched");
        // Next boot.
        assert_eq!(
            crate::apdu::dispatcher::Dispatcher::migrate_retry_counters(&mut store),
            Ok(true)
        );
        assert_eq!(store.left(USER), Some(3));
    }

    #[test]
    fn migrated_record_with_lost_log_stays_blocked() {
        // After migration the record holds zeros: if the log is ever wiped,
        // a re-migration seeds 0, never the old counts.
        let mut store = legacy_store(3, 5, 10);
        crate::apdu::dispatcher::Dispatcher::migrate_retry_counters(&mut store).unwrap();
        store.counters = MemCounters {
            unformatted: true,
            ..MemCounters::default()
        };
        crate::apdu::dispatcher::Dispatcher::migrate_retry_counters(&mut store).unwrap();
        assert_eq!(store.left(USER), Some(0));
        assert_eq!(store.left(SO), Some(0));
    }

    #[test]
    fn blank_device_migrates_to_an_empty_log() {
        let mut store = PinStore::new();
        store.counters.unformatted = true;
        assert_eq!(
            crate::apdu::dispatcher::Dispatcher::migrate_retry_counters(&mut store),
            Ok(true)
        );
        assert!(!store.counters.unformatted);
        assert!(store.counters.entries.iter().all(Option::is_none));
        let mut hsm = ScHsm::new();
        ScHsm::load_pin_state_from_store(&mut hsm.state, &mut store);
        assert!(!hsm.state.initialized);
        assert_eq!(hsm.state.so_pin_retry_count, 5, "fresh device defaults");
    }
}

#[cfg(test)]
mod reserved_slot_and_dkek_tests {
    use super::*;
    use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};

    /// Minimal in-memory store: keeps each record's private bytes by KeyId.
    struct MemStore {
        counters: retry_counter::MemCounters,
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
        fn for_each_key(&self, f: &mut dyn FnMut(KeyId)) {
            for (k, _) in self.records.iter() {
                f(*k);
            }
        }
        fn retry_counters(&mut self) -> Option<&mut dyn RetryCounterBackend> {
            Some(&mut self.counters)
        }
    }

    #[test]
    fn missing_pin_record_next_to_keys_locks_out() {
        let mut store = MemStore {
            counters: Default::default(),
            records: heapless::Vec::new(),
        };
        store
            .records
            .push((KeyId::sc_hsm(0, 0x01), heapless::Vec::new()))
            .unwrap();
        let mut hsm = ScHsm::new();
        ScHsm::load_pin_state_from_store(&mut hsm.state, &mut store);
        assert!(hsm.state.initialized);
        assert_eq!(hsm.state.so_pin_retry_count, 0);
        assert_eq!(hsm.state.pin_retry_count, 0);
        // INITIALIZE without the SO-PIN must not run.
        let init = [
            0x80, 0x50, 0x00, 0x00, 0x08, 0x81, 0x06, b'1', b'2', b'3', b'4', b'5', b'6',
        ];
        assert_eq!(ApduCommand::parse(&init).map(|c| c.data.len()), Ok(8));
        assert_ne!(sw(&mut hsm, &mut store, &init), 0x9000);
        assert!(!store.records.is_empty(), "keys not wiped");
    }

    #[test]
    fn empty_store_is_a_fresh_device() {
        let mut store = MemStore {
            counters: Default::default(),
            records: heapless::Vec::new(),
        };
        let mut hsm = ScHsm::new();
        ScHsm::load_pin_state_from_store(&mut hsm.state, &mut store);
        assert!(!hsm.state.initialized);
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
            counters: Default::default(),
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
            counters: Default::default(),
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

    /// Store whose writes all fail.
    struct FailStore;

    impl crate::storage::KeyStore for FailStore {
        fn save_key(&mut self, _: &KeyObject) -> Result<(), HsmError> {
            Err(HsmError::NotSupported)
        }
        fn fetch_key(&mut self, _: KeyId) -> Result<Option<KeyObject>, HsmError> {
            Ok(None)
        }
        fn erase_key(&mut self, _: KeyId) -> Result<(), HsmError> {
            Err(HsmError::NotSupported)
        }
        fn wipe_all(&mut self) -> Result<(), HsmError> {
            Err(HsmError::NotSupported)
        }
        fn wipe_by_owner(&mut self, _: AppletId) -> Result<(), HsmError> {
            Err(HsmError::NotSupported)
        }
        fn enumerate_keys(&self) -> heapless::Vec<KeyId, 64> {
            heapless::Vec::new()
        }
        fn for_each_key(&self, _: &mut dyn FnMut(KeyId)) {}
    }

    #[test]
    fn delete_keeps_key_when_flash_erase_fails() {
        let mut hsm = logged_in();
        let kid = KeyId::sc_hsm(0, 0x01).0;
        hsm.state
            .key_index
            .push(KeyMeta {
                key_id: kid,
                key_type: CoreKeyType::EcPrivateP256 as u8,
                algo: 0x13,
                key_flags: 0,
            })
            .unwrap();
        let r = hsm
            .process_apdu_with_store(&[0x00, 0xE4, 0x02, 0x00, 0x02, 0xCC, 0x01], &mut FailStore);
        assert_eq!(
            u16::from_be_bytes([r[r.len() - 2], r[r.len() - 1]]),
            SW_MEMORY_FAILURE
        );
        assert!(
            hsm.state.key_index.iter().any(|m| m.key_id == kid),
            "still indexed: still in flash"
        );
    }

    #[test]
    fn initialize_fails_when_old_keys_cannot_be_wiped() {
        let mut hsm = ScHsm::new();
        let apdu = [
            0x80, 0x50, 0x00, 0x00, 0x12, 0x81, 0x06, b'6', b'4', b'8', b'2', b'1', b'9', 0x82,
            0x08, b'5', b'7', b'6', b'2', b'1', b'8', b'8', b'0',
        ];
        let r = hsm.process_apdu_with_store(&apdu, &mut FailStore);
        assert_eq!(
            u16::from_be_bytes([r[r.len() - 2], r[r.len() - 1]]),
            SW_MEMORY_FAILURE
        );
    }

    #[test]
    fn oversized_ef_is_not_cached_truncated() {
        let mut st = ScHsmState::new();
        st.ef_cache_put(0xCE0C, &[0xAB; 1100]);
        assert!(
            st.ef_cache_get(0xCE0C).is_none(),
            "served from flash instead"
        );
        st.ef_cache_put(0xCE0D, &[0xCD; 200]);
        assert_eq!(st.ef_cache_get(0xCE0D).map(<[u8]>::len), Some(200));
    }
}

#[cfg(test)]
pub(crate) mod policy_tests;

#[cfg(test)]
mod domain_tests;

#[cfg(test)]
mod store_recovery_tests;
