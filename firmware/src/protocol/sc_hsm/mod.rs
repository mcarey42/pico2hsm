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
    key::KeyType as CoreKeyType,
    protocol::HsmProtocol,
};

use commands::*;

/// AID for SmartCard-HSM (pico2hsm variant).
pub const SC_HSM_AID: &[u8] =
    &[0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01];

/// Maximum PIN length in bytes.
pub const MAX_PIN_LEN: usize = 16;
/// Maximum SO-PIN length in bytes.
pub const MAX_SO_PIN_LEN: usize = 16;

/// Maximum number of in-memory key slots.
pub const MAX_IN_MEMORY_KEYS: usize = 16;

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

/// An in-memory (volatile) key slot.
///
/// Keys are held in RAM and lost on reset; flash persistence is a future
/// storage layer concern. This is sufficient for integration testing.
pub struct InMemoryKey {
    /// SC-HSM key identifier (0x01–0xFE).
    pub key_id: u8,
    /// Key type used by the `crypto::asymmetric` functions.
    pub key_type: CoreKeyType,
    /// SC-HSM AlgorithmId byte (e.g. 0x13 = EcdsaP256, 0x23 = EcdhP256).
    pub algo: u8,
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

    /// Stored User PIN hash (SHA-256, 32 bytes). None if not set.
    pub user_pin_hash: Option<[u8; 32]>,
    /// Stored SO-PIN hash (SHA-256, 32 bytes). None if not set.
    pub so_pin_hash: Option<[u8; 32]>,

    /// In-memory (volatile) key store. Cleared on INITIALIZE.
    pub keys: heapless::Vec<InMemoryKey, MAX_IN_MEMORY_KEYS>,
    /// In-memory (volatile) EF store (written via WRITE DATA INS=0xD7).
    pub ef_files: heapless::Vec<EfEntry, MAX_EF_FILES>,

    /// Last non-zero file ID targeted by WRITE DATA.  OpenSC's sc_hsm_update_ef
    /// uses a two-step write protocol: first `D7 fid_hi fid_lo data(N)` (small
    /// header write) followed by `D7 00 00 data(M)` (full content write, where
    /// P1=P2=0 means "write to the previously addressed file").
    pub write_target_file: Option<u16>,
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
            initialized: false,
            hsm_label: String::new(),
            options: 0,
            dkek_shares_required: 0,
            dkek_shares_imported: 0,
            user_pin_hash: None,
            so_pin_hash: None,
            keys: heapless::Vec::new(),
            ef_files: heapless::Vec::new(),
            write_target_file: None,
        }
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

    /// Dispatch an already-parsed APDU to the appropriate command handler.
    fn dispatch(&mut self, cmd: &ApduCommand<'_>) -> ApduResponse {
        match cmd.ins {
            initialize::INS_INITIALIZE => initialize::handle(&mut self.state, cmd),
            verify::INS_VERIFY => verify::handle(&mut self.state, cmd),
            change_pin::INS_CHANGE_PIN => change_pin::handle(&mut self.state, cmd),
            reset_retry::INS_RESET_RETRY => reset_retry::handle(&mut self.state, cmd),
            mse::INS_MSE => mse::handle(&mut self.state, cmd),
            challenge::INS_CHALLENGE => challenge::handle(&mut self.state, cmd),
            external_auth::INS_EXTERNAL_AUTH => external_auth::handle(&mut self.state, cmd),
            general_auth::INS_GENERAL_AUTH => general_auth::handle(&mut self.state, cmd),
            generate_keypair::INS_GENERATE_KEYPAIR => generate_keypair::handle(&mut self.state, cmd),
            generate_key::INS_GENERATE_KEY => generate_key::handle(&mut self.state, cmd),
            sign::INS_SIGN => sign::handle(&mut self.state, cmd),
            // INS 0x62: DECIPHER (ECDH). P1 = key_reference, P2 = algo.
            // DERIVE_ASYM (pico2hsm extension) would also be INS=0x62 but
            // conflicts with user key IDs starting at 1; route all to decrypt.
            decrypt::INS_DECRYPT => decrypt::handle(&mut self.state, cmd),
            // INS 0x58 shared between LIST_KEYS (P2=0x00) and IMPORT_KEY (P2=0x93)
            list_keys::INS_LIST_KEYS => {
                if cmd.p2 == import_key::P2_IMPORT {
                    import_key::handle(&mut self.state, cmd)
                } else {
                    list_keys::handle(&mut self.state, cmd)
                }
            }
            export_key::INS_EXPORT_KEY => export_key::handle(&mut self.state, cmd),
            read_binary::INS_READ_BINARY => read_binary::handle(&mut self.state, cmd),
            read_binary::INS_READ_BINARY_ODD => read_binary::handle_odd(&mut self.state, cmd),
            update_binary::INS_UPDATE_BINARY => update_binary::handle(&mut self.state, cmd),
            write_data::INS_WRITE_DATA => write_data::handle(&mut self.state, cmd),
            create_file::INS_CREATE_FILE => create_file::handle(&mut self.state, cmd),
            delete_file::INS_DELETE_FILE => delete_file::handle(&mut self.state, cmd),
            pso::INS_PSO => pso::handle(&mut self.state, cmd),
            cipher_sym::INS_CIPHER_SYM => cipher_sym::handle(&mut self.state, cmd),
            key_domain::INS_KEY_DOMAIN => key_domain::handle(&mut self.state, cmd),
            session_pin::INS_SESSION_PIN => session_pin::handle(&mut self.state, cmd),
            puk_auth::INS_PUK_AUTH => puk_auth::handle(&mut self.state, cmd),
            bip_slip::INS_BIP_SLIP => bip_slip::handle(&mut self.state, cmd),
            extras::INS_EXTRAS => extras::handle(&mut self.state, cmd),
            select::INS_SELECT => select::handle(&mut self.state, cmd),
            #[cfg(feature = "debug")]
            debug_dump::INS_DEBUG_DUMP => debug_dump::handle(cmd),
            _ => ApduResponse::err(SW_INS_NOT_SUPPORTED),
        }
    }
}

impl HsmProtocol for ScHsm {
    fn process_apdu(&mut self, apdu: &[u8]) -> Vec<u8, 4096> {
        let resp = match ApduCommand::parse(apdu) {
            Ok(cmd) => self.dispatch(&cmd),
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
