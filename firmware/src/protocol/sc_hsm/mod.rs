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
    apdu::{ApduCommand, ApduResponse, SW_INS_NOT_SUPPORTED, SW_OK},
    error::HsmError,
    key::{AppletId, KeyId, KeyType as CoreKeyType},
    protocol::HsmProtocol,
};
use zeroize::Zeroizing;

/// INS byte for GET RESPONSE (ISO 7816-4 §7.6.1).
///
/// The host sends this to retrieve additional bytes when the card returned
/// SW=0x61xx indicating that `XX` bytes remain in the response buffer.
const INS_GET_RESPONSE: u8 = 0xC0;

use crate::security::dkek::DkekManager;

use commands::*;

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
    fn fetch_key(&mut self, _: KeyId) -> Result<Option<crate::security::key_management::KeyObject>, HsmError> {
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
    fn enumerate_keys(&self) -> heapless::Vec<KeyId, 512> {
        heapless::Vec::new()
    }
}

/// AID for SmartCard-HSM (pico2hsm variant).
pub const SC_HSM_AID: &[u8] =
    &[0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01];

/// Maximum PIN length in bytes.
pub const MAX_PIN_LEN: usize = 16;
/// Maximum SO-PIN length in bytes.
pub const MAX_SO_PIN_LEN: usize = 16;

/// Maximum number of in-memory EC key slots.
pub const MAX_IN_MEMORY_KEYS: usize = 16;

/// Maximum number of in-memory symmetric key slots.
pub const MAX_IN_MEMORY_SYM_KEYS: usize = 8;

/// Maximum number of in-memory RSA key slots (feature-gated).
#[cfg(feature = "rsa")]
pub const MAX_RSA_IN_MEMORY_KEYS: usize = 4;

/// Maximum number of EF (elementary file) entries stored in RAM.
pub const MAX_EF_FILES: usize = 16;
/// Maximum size of a single EF data blob (bytes).
pub const MAX_EF_DATA: usize = 2048;

/// An in-memory (volatile) EF (elementary file) entry.
///
/// Used by WRITE DATA (INS=0xD7) and READ BINARY (INS=0xB0) to store and
/// retrieve arbitrary data files written by the host (e.g. EF.C.DevAut).
pub struct EfEntry {
    /// File identifier (P1 || P2 from the write command).
    pub file_id: u16,
    /// Raw file contents.
    pub data: heapless::Vec<u8, MAX_EF_DATA>,
}

/// An in-memory (volatile) symmetric key slot.
///
/// Holds a raw AES key (16, 24, or 32 bytes for AES-128/192/256).
/// Keys are volatile — they are lost on reset and cleared on INITIALIZE.
#[derive(Debug)]
pub struct InMemorySymKey {
    /// Full u32 internal key ID (structured: partition | applet | reserved | proto_ref).
    pub key_id: u32,
    /// Raw key bytes: 16 (AES-128), 24 (AES-192), or 32 (AES-256).
    pub raw_key: heapless::Vec<u8, 32>,
}

/// An in-memory (volatile) RSA key slot.
///
/// Separate from `InMemoryKey` because RSA private keys are ~1200–2350 bytes
/// (PKCS#1 DER for RSA-2048/4096) — too large to fit in `InMemoryKey.private_key`
/// which is sized for the largest EC key (66 bytes for P-521).
#[cfg(feature = "rsa")]
pub struct RsaInMemoryKey {
    /// Full u32 internal key ID (structured: partition | applet | reserved | proto_ref).
    pub key_id: u32,
    /// Key type: `RsaPrivate2048`, `RsaPrivate3072`, or `RsaPrivate4096`.
    pub key_type: CoreKeyType,
    /// SC-HSM AlgorithmId byte used during keygen (e.g. 0x05 = RSA-2048, 0x07 = RSA-4096).
    pub algo: u8,
    /// SC-HSM key flags byte (see `InMemoryKey::key_flags` for bit layout).
    pub key_flags: u8,
    /// PKCS#1 DER-encoded `RSAPrivateKey` (≤1200 bytes for RSA-2048, ≤2350 bytes for RSA-4096).
    pub private_key_der: heapless::Vec<u8, 2400>,
    /// Raw RSA modulus, big-endian (256 bytes for RSA-2048, 512 bytes for RSA-4096).
    pub modulus: heapless::Vec<u8, 512>,
    /// Raw RSA public exponent, big-endian (3 bytes for e=65537).
    pub exponent: heapless::Vec<u8, 4>,
}

/// An in-memory (volatile) key slot.
///
/// Keys are held in RAM and lost on reset; flash persistence is a future
/// storage layer concern. This is sufficient for integration testing.
#[derive(Debug)]
pub struct InMemoryKey {
    /// Full u32 internal key ID (structured: partition | applet | reserved | proto_ref).
    pub key_id: u32,
    /// Key type used by the `crypto::asymmetric` functions.
    pub key_type: CoreKeyType,
    /// SC-HSM AlgorithmId byte (e.g. 0x13 = EcdsaP256, 0x23 = EcdhP256).
    pub algo: u8,
    /// SC-HSM key flags byte from GENERATE KEY PAIR TLV (tag 0xD4).
    ///
    /// Bit 0 = ALLOW_SIGN, Bit 1 = ALLOW_DECRYPT, Bit 2 = ALLOW_DERIVE,
    /// Bit 3 = NO_EXPORT (if set, EXPORT KEY must be rejected).
    /// Default 0x00 = all operations allowed, exportable.
    pub key_flags: u8,
    /// Raw private key scalar (big-endian), up to 66 bytes for P-521.
    pub private_key: heapless::Vec<u8, 66>,
    /// Uncompressed public key `04 || X || Y`, up to 133 bytes for P-521.
    pub public_key: heapless::Vec<u8, 133>,
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

    /// Remaining EXTERNAL AUTHENTICATE retry attempts (0 = blocked).
    ///
    /// Initialized to 5. Decremented on each failed EXTERNAL AUTH attempt.
    /// Resets to 5 on success. Returns SW_AUTH_BLOCKED (0x6983) when zero.
    pub ext_auth_retry_count: u8,

    /// When true, DKEK exchange is allowed without peer signature verification
    /// (bootstrapping mode before the first peer is enrolled).
    ///
    /// Set to false permanently once a peer public key has been enrolled via
    /// SIGN_ENROLLMENT, preventing unauthenticated exchanges after enrollment.
    pub dkek_unauthenticated_allowed: bool,

    /// In-memory (volatile) EC key store. Cleared on INITIALIZE.
    pub keys: heapless::Vec<InMemoryKey, MAX_IN_MEMORY_KEYS>,
    /// In-memory (volatile) RSA key store. Cleared on INITIALIZE.
    #[cfg(feature = "rsa")]
    pub rsa_keys: heapless::Vec<RsaInMemoryKey, MAX_RSA_IN_MEMORY_KEYS>,
    /// In-memory (volatile) symmetric key store. Cleared on INITIALIZE.
    pub sym_keys: heapless::Vec<InMemorySymKey, MAX_IN_MEMORY_SYM_KEYS>,
    /// In-memory (volatile) EF store (written via WRITE DATA INS=0xD7).
    pub ef_files: heapless::Vec<EfEntry, MAX_EF_FILES>,

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
    pub exchange_challenge_cache: [[u8; 32]; 16],
    /// Number of valid entries in exchange_challenge_cache (capped at 16).
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

    /// GET RESPONSE buffer (ISO 7816-4 §7.6.1).
    ///
    /// When a response data field exceeds the Le byte specified by the host,
    /// the full response is stored here and SW=0x61xx is returned.  The host
    /// then sends GET RESPONSE (INS=0xC0) to retrieve successive chunks.
    /// Cleared on every non-GET-RESPONSE command.
    pub pending_response: heapless::Vec<u8, 4096>,
    /// Byte offset into `pending_response` for the next GET RESPONSE chunk.
    pub pending_response_offset: usize,
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
            ext_auth_retry_count: 5,
            dkek_unauthenticated_allowed: true,
            keys: heapless::Vec::new(),
            #[cfg(feature = "rsa")]
            rsa_keys: heapless::Vec::new(),
            sym_keys: heapless::Vec::new(),
            ef_files: heapless::Vec::new(),
            write_target_file: None,
            dkek: DkekManager::new([0u8; 16]),
            exchange_ephem_priv: None,
            exchange_ephem_pub: None,
            exchange_challenge: None,
            exchange_peer_ephem_pub: None,
            exchange_challenge_cache: [[0u8; 32]; 16],
            exchange_challenge_cache_count: 0,
            exchange_challenge_cache_write_idx: 0,
            generation: 0,
            noise_enrolled_peer_pubkey: None,
            pending_response: heapless::Vec::new(),
            pending_response_offset: 0,
        }
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
        ScHsm { state: ScHsmState::new() }
    }

    /// Dispatch an already-parsed APDU to the appropriate command handler,
    /// with access to persistent storage for key-mutating commands.
    fn dispatch_with_store(
        &mut self,
        cmd: &ApduCommand<'_>,
        store: &mut dyn crate::storage::KeyStore,
    ) -> ApduResponse {
        // GET RESPONSE passes through to dispatch() which handles pending buffer.
        // All other commands routed here (which don't fall through to dispatch)
        // must clear the pending buffer so a stale buffer is not left around.
        if cmd.ins != INS_GET_RESPONSE {
            self.state.pending_response.clear();
            self.state.pending_response_offset = 0;
        }
        match cmd.ins {
            initialize::INS_INITIALIZE => initialize::handle(&mut self.state, store, cmd),
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
            change_pin::INS_CHANGE_PIN => change_pin::handle_with_store(&mut self.state, store, cmd),
            reset_retry::INS_RESET_RETRY => reset_retry::handle_with_store(&mut self.state, store, cmd),
            extras::INS_EXTRAS => extras::handle(&mut self.state, store, cmd),
            // All other commands fall through to the stateless dispatch.
            _ => self.dispatch(cmd),
        }
    }

    /// Dispatch an already-parsed APDU to the appropriate command handler.
    fn dispatch(&mut self, cmd: &ApduCommand<'_>) -> ApduResponse {
        // GET RESPONSE (INS=0xC0) is handled before clearing the pending buffer.
        // All other commands clear the pending buffer first.
        if cmd.ins != INS_GET_RESPONSE {
            self.state.pending_response.clear();
            self.state.pending_response_offset = 0;
        }
        match cmd.ins {
            // GET RESPONSE (ISO 7816-4 §7.6.1): return next chunk of pending response.
            INS_GET_RESPONSE => {
                let offset = self.state.pending_response_offset;
                let remaining = self.state.pending_response.len().saturating_sub(offset);
                if remaining == 0 {
                    // Nothing pending — return empty 9000 per ISO spec.
                    return ApduResponse::ok(&[]);
                }
                // Le=0 means 256 for short APDU; None means send all.
                let chunk_len = match cmd.le {
                    None => remaining,
                    Some(0) => remaining.min(256),
                    Some(n) => remaining.min(n as usize),
                };
                let chunk = &self.state.pending_response[offset..offset + chunk_len];
                let mut resp = ApduResponse::ok(chunk);
                self.state.pending_response_offset += chunk_len;
                let new_remaining = self.state.pending_response.len().saturating_sub(self.state.pending_response_offset);
                if new_remaining > 0 {
                    // More data still pending — SW=0x61xx.
                    let xx = new_remaining.min(0xFF) as u8;
                    resp.sw = 0x6100 | (xx as u16);
                }
                resp
            }
            initialize::INS_INITIALIZE => initialize::handle(&mut self.state, &mut LocalNullStore, cmd),
            verify::INS_VERIFY => verify::handle(&mut self.state, cmd),
            change_pin::INS_CHANGE_PIN => change_pin::handle(&mut self.state, cmd),
            reset_retry::INS_RESET_RETRY => reset_retry::handle(&mut self.state, cmd),
            mse::INS_MSE => mse::handle(&mut self.state, cmd),
            challenge::INS_CHALLENGE => challenge::handle(&mut self.state, cmd),
            external_auth::INS_EXTERNAL_AUTH => external_auth::handle(&mut self.state, cmd),
            general_auth::INS_GENERAL_AUTH => general_auth::handle(&mut self.state, cmd),
            generate_keypair::INS_GENERATE_KEYPAIR => generate_keypair::handle(&mut self.state, &mut LocalNullStore, cmd),
            generate_key::INS_GENERATE_KEY => generate_key::handle(&mut self.state, &mut LocalNullStore, cmd),
            sign::INS_SIGN => sign::handle(&mut self.state, cmd),
            // INS 0x62: shared between DECIPHER (P1 = key_reference) and
            // DERIVE_ASYM (P1 = 0x01). Route by P1.
            decrypt::INS_DECRYPT => {
                if cmd.p1 == derive_asym::P1_DERIVE {
                    derive_asym::handle(&mut self.state, cmd)
                } else {
                    decrypt::handle(&mut self.state, cmd)
                }
            }
            list_keys::INS_LIST_KEYS => list_keys::handle(&mut self.state, cmd),
            // INS=0x72: pico2hsm proprietary EXPORT KEY (kept for custom tooling).
            // INS=0x34: standard SC-HSM WRAP KEY alias — same handler.
            export_key::INS_EXPORT_KEY | 0x34 => export_key::handle(&mut self.state, &mut LocalNullStore, cmd),
            // INS=0x74: pico2hsm IMPORT KEY. INS=0x58 conflicts with LIST KEYS; see
            // dispatch_with_store for full explanation.
            import_key::INS_IMPORT_KEY => import_key::handle(&mut self.state, &mut LocalNullStore, cmd),
            read_binary::INS_READ_BINARY => read_binary::handle(&mut self.state, cmd),
            read_binary::INS_READ_BINARY_ODD => read_binary::handle_odd(&mut self.state, cmd),
            update_binary::INS_UPDATE_BINARY => update_binary::handle(&mut self.state, cmd),
            write_data::INS_WRITE_DATA => write_data::handle(&mut self.state, cmd),
            create_file::INS_CREATE_FILE => create_file::handle(&mut self.state, cmd),
            delete_file::INS_DELETE_FILE => delete_file::handle(&mut self.state, &mut LocalNullStore, cmd),
            pso::INS_PSO => pso::handle(&mut self.state, cmd),
            cipher_sym::INS_CIPHER_SYM => cipher_sym::handle(&mut self.state, cmd),
            key_domain::INS_KEY_DOMAIN => key_domain::handle(&mut self.state, cmd),
            session_pin::INS_SESSION_PIN => session_pin::handle(&mut self.state, cmd),
            puk_auth::INS_PUK_AUTH => puk_auth::handle(&mut self.state, cmd),
            bip_slip::INS_BIP_SLIP => bip_slip::handle(&mut self.state, cmd),
            extras::INS_EXTRAS => extras::handle(&mut self.state, &mut LocalNullStore, cmd),
            select::INS_SELECT => select::handle(&mut self.state, cmd),
            provisioning::INS_PROV_GET_STATUS => provisioning::handle_get_status(&mut self.state, cmd),
            provisioning::INS_PROV_SET_PRODUCTION => provisioning::handle_set_production_mode(&mut self.state, cmd),
            provisioning::INS_PROV_LOCK_OTP_ROWS => provisioning::handle_lock_otp_rows(&mut self.state, cmd),
            provisioning::INS_PROV_WRITE_CRIT0 => provisioning::handle_write_crit0(&mut self.state, cmd),
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
    ///   [148]      reserved (0x00)
    ///
    /// NOTE: Format changed from 101-byte (bare SHA-256, no salts) to 149-byte
    /// (PBKDF2 + per-credential salts).  Old flash blobs are ≤101 bytes and will
    /// be rejected by the length check in `load_pin_state_from_store`, requiring
    /// re-INITIALIZE.  This is intentional and acceptable for pre-production devices.
    pub fn save_pin_to_store(state: &ScHsmState, store: &mut dyn crate::storage::KeyStore) {
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
        let _ = buf.push(0x00); // reserved

        crate::CORE1_PROGRESS.store(35, core::sync::atomic::Ordering::Relaxed);
        let kid = Self::sc_hsm_pin_key_id();
        let mut obj = KeyObject::new(KmKeyType::Generic, kid.0, AppletId::ScHsm, AlgorithmId::AesGcm);
        crate::CORE1_PROGRESS.store(36, core::sync::atomic::Ordering::Relaxed);
        let _ = obj.private_key.extend_from_slice(&buf);
        crate::CORE1_PROGRESS.store(37, core::sync::atomic::Ordering::Relaxed);
        let _ = store.save_key(&obj);
        crate::CORE1_PROGRESS.store(38, core::sync::atomic::Ordering::Relaxed);
    }

    /// Load PIN/SO-PIN/PUK state from flash into `state`.
    pub fn load_pin_state_from_store(state: &mut ScHsmState, store: &mut dyn crate::storage::KeyStore) {
        let kid = Self::sc_hsm_pin_key_id();
        if let Ok(Some(obj)) = store.fetch_key(kid) {
            let b = &obj.private_key;
            // Require the new 149-byte PBKDF2+salt format.
            // Blobs ≤101 bytes are old bare-SHA-256 format and are rejected,
            // requiring re-INITIALIZE (acceptable on pre-production devices).
            if b.len() >= 149 {
                let user_hash: [u8; 32] = b[0..32].try_into().unwrap_or([0u8; 32]);
                state.user_pin_hash = if user_hash == [0u8; 32] { None } else { Some(user_hash) };
                state.user_pin_salt = b[32..48].try_into().unwrap_or([0u8; 16]);
                state.pin_retry_count = b[48];
                let so_hash: [u8; 32] = b[49..81].try_into().unwrap_or([0u8; 32]);
                state.so_pin_hash = if so_hash == [0u8; 32] { None } else { Some(so_hash) };
                state.so_pin_salt = b[81..97].try_into().unwrap_or([0u8; 16]);
                state.so_pin_retry_count = b[97];
                let puk_hash: [u8; 32] = b[98..130].try_into().unwrap_or([0u8; 32]);
                state.puk_hash = if puk_hash == [0u8; 32] { None } else { Some(puk_hash) };
                state.puk_salt = b[130..146].try_into().unwrap_or([0u8; 16]);
                state.puk_retry_count = b[146];
                state.initialized = b[147] != 0;
            }
        }
    }

    /// Process a raw APDU with access to persistent storage.
    ///
    /// All key-mutating commands (INITIALIZE, GENERATE KEY PAIR, DELETE FILE)
    /// will persist/erase via `store`. Non-mutating commands fall through to
    /// the stateless dispatch path.
    ///
    /// Implements ISO 7816-4 GET RESPONSE chaining: if the response data
    /// exceeds the Le byte, the first `Le` bytes are returned with SW=0x61xx
    /// and the remainder is buffered in `state.pending_response` for subsequent
    /// GET RESPONSE (INS=0xC0) calls.
    pub fn process_apdu_with_store(
        &mut self,
        apdu: &[u8],
        store: &mut dyn crate::storage::KeyStore,
    ) -> Vec<u8, 4096> {
        let resp = match ApduCommand::parse(apdu) {
            Ok(cmd) => {
                let le = cmd.le;
                let is_get_response = cmd.ins == INS_GET_RESPONSE;
                let mut r = self.dispatch_with_store(&cmd, store);
                // Apply Le truncation with GET RESPONSE chaining for successful
                // responses that have not already been chunked by the GET RESPONSE
                // handler itself.
                if !is_get_response && r.sw == SW_OK {
                    if let Some(le_val) = le {
                        // Short APDUs: parser already converts Le=0x00 → 256.
                        // Extended APDUs: Le=0x0000 stored as 0, meaning 65536
                        // ("return all data") — don't truncate.
                        let le_usize = if le_val == 0 { r.data.len() } else { le_val as usize };
                        if r.data.len() > le_usize {
                            // Store overflow bytes in pending buffer for GET RESPONSE.
                            self.state.pending_response.clear();
                            let _ = self.state.pending_response.extend_from_slice(&r.data[le_usize..]);
                            self.state.pending_response_offset = 0;
                            r.data.truncate(le_usize);
                            let remaining = self.state.pending_response.len();
                            let xx = remaining.min(0xFF) as u8;
                            r.sw = 0x6100 | (xx as u16);
                        }
                    }
                }
                r
            }
            Err(_) => ApduResponse::err(SW_INS_NOT_SUPPORTED),
        };
        let serialized = resp.serialize();
        let mut out: Vec<u8, 4096> = Vec::new();
        let _ = out.extend_from_slice(&serialized[..serialized.len().min(4096)]);
        out
    }
}

impl HsmProtocol for ScHsm {
    fn process_apdu(&mut self, apdu: &[u8]) -> Vec<u8, 4096> {
        // Used by the stateless dispatch path (host-side tests and non-ScHsm protocols).
        // Key-mutating commands here use NullKeyStore (no-op flash writes).
        let resp = match ApduCommand::parse(apdu) {
            Ok(cmd) => {
                let le = cmd.le;
                let is_get_response = cmd.ins == INS_GET_RESPONSE;
                let mut r = self.dispatch(&cmd);
                // Apply Le truncation with GET RESPONSE chaining for successful
                // responses that have not already been chunked by the GET RESPONSE
                // handler itself.
                if !is_get_response && r.sw == SW_OK {
                    if let Some(le_val) = le {
                        let le_usize = if le_val == 0 { r.data.len() } else { le_val as usize };
                        if r.data.len() > le_usize {
                            self.state.pending_response.clear();
                            self.state.pending_response_offset = 0;
                            let _ = self.state.pending_response.extend_from_slice(&r.data[le_usize..]);
                            r.data.truncate(le_usize);
                            let remaining = self.state.pending_response.len();
                            let xx = remaining.min(0xFF) as u8;
                            r.sw = 0x6100 | (xx as u16);
                        }
                    }
                }
                r
            }
            Err(_) => ApduResponse::err(SW_INS_NOT_SUPPORTED),
        };
        let serialized = resp.serialize();
        let mut out: Vec<u8, 4096> = Vec::new();
        // Serialize returns up to 4098 bytes; truncate the data portion to fit 4096.
        // In practice response data is ≤ 4094 bytes (4096 - 2 SW bytes).
        let _ = out.extend_from_slice(&serialized[..serialized.len().min(4096)]);
        out
    }

    fn handles_aid(&self, aid: &[u8]) -> bool {
        aid == SC_HSM_AID
    }

    fn protocol_name(&self) -> &'static str {
        "SC-HSM"
    }
}
