//! APDU dispatcher — routes commands to the active `HsmProtocol` implementation.
//!
//! The dispatcher holds references to all registered protocol implementations.
//! On receiving a SELECT AID command (INS=0xA4, P1=0x04), it iterates the
//! registered protocols and activates the first one that returns `true` from
//! `handles_aid()`. Subsequent commands are forwarded to the active protocol
//! until the next SELECT AID.
//!
//! # Protocol priority
//! 1. SC-HSM (primary — always registered)
//! 2. PIV (stub)
//! 3. OpenPGP (stub)
//!
//! # AID routing
//! - SC-HSM AID `E8 2B 06 01 04 01 81 C3 1F 02 01` → ScHsm, returns FCI
//! - PIV AID     `A0 00 00 03 08 00 00 10 00 01 00` → Piv stub
//! - OpenPGP AID `D2 76 00 01 24 01 ...`            → OpenPgp stub
//! - Any other AID                                   → SW_FILE_NOT_FOUND

use heapless::Vec;
use pico2hsm_core::{
    apdu::{
        ApduCommand, ApduResponse, SW_CLASS_NOT_SUPPORTED, SW_FILE_NOT_FOUND, SW_INS_NOT_SUPPORTED,
        SW_OK,
    },
    protocol::HsmProtocol,
};

use super::shared_buffer::SharedResponseBuffer;

/// INS byte for GET RESPONSE (ISO 7816-4 §7.6.1).
const INS_GET_RESPONSE: u8 = 0xC0;

use crate::protocol::{
    openpgp::{OpenPgp, OPENPGP_AID_PREFIX},
    piv::{Piv, PIV_AID},
    sc_hsm::{ScHsm, SC_HSM_AID},
};

/// INS byte for SELECT (ISO 7816-4).
const INS_SELECT: u8 = 0xA4;
/// P1 value for SELECT by AID.
const P1_SELECT_BY_AID: u8 = 0x04;

/// Active protocol discriminant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ActiveProtocol {
    /// No protocol selected (pre-SELECT state).
    None,
    /// SC-HSM is the active protocol.
    ScHsm,
    /// PIV stub is the active protocol.
    Piv,
    /// OpenPGP stub is the active protocol.
    OpenPgp,
}

/// APDU dispatcher.
///
/// Holds one instance of each registered protocol and routes APDUs to
/// the currently active one. The active protocol starts as `None` until
/// a SELECT AID command is received.
pub struct Dispatcher {
    active: ActiveProtocol,
    sc_hsm: ScHsm,
    piv: Piv,
    openpgp: OpenPgp,
    /// Shared GET RESPONSE chaining buffer — replaces per-protocol buffers.
    shared_buf: SharedResponseBuffer,
}

impl Dispatcher {
    /// Create a new dispatcher with all protocols initialised.
    pub fn new() -> Self {
        Dispatcher {
            active: ActiveProtocol::None,
            sc_hsm: ScHsm::new(),
            piv: Piv::new(),
            openpgp: OpenPgp::new(),
            shared_buf: SharedResponseBuffer::new(),
        }
    }

    /// Initialise a Dispatcher directly in the provided `MaybeUninit` slot,
    /// avoiding a ~36 KB stack temporary.
    ///
    /// In debug builds the compiler does not perform Named Return Value
    /// Optimisation, so `Dispatcher::new()` would place the full ~36 KB
    /// struct on the Core0 machine stack before `memcpy`-ing it to the
    /// destination.  With only ~113 KB of stack this overflows into BSS
    /// and corrupts wakers / async state.
    ///
    /// This method uses `addr_of_mut!` to write each field individually
    /// into the destination, keeping peak stack usage under 512 bytes.
    ///
    /// Each field is written directly via `addr_of_mut!` — no intermediate
    /// struct is constructed on the stack.  Large fields (`SharedResponseBuffer`
    /// with a 4 KB inline array, `OpenPgp`) are initialised via separate
    /// `#[inline(never)]` helpers to avoid return-value stack temporaries.
    ///
    /// `#[inline(never)]` on this function itself ensures its frame is
    /// separate from the async state machine, preventing cumulative overflow.
    #[inline(never)]
    pub fn init_in_place(dest: &mut core::mem::MaybeUninit<Self>) -> &mut Self {
        let ptr = dest.as_mut_ptr();
        unsafe {
            core::ptr::addr_of_mut!((*ptr).active).write(ActiveProtocol::None);
            ScHsm::init_in_place(core::ptr::addr_of_mut!((*ptr).sc_hsm));
            Piv::init_in_place(core::ptr::addr_of_mut!((*ptr).piv));
            Self::init_openpgp_in_place(core::ptr::addr_of_mut!((*ptr).openpgp));
            // SharedResponseBuffer has a 4 KB inline [u8; 4096].
            // Write fields individually to keep it off the stack.
            {
                let sb = core::ptr::addr_of_mut!((*ptr).shared_buf);
                core::ptr::addr_of_mut!((*sb).data).write_bytes(0u8, 1);
                core::ptr::addr_of_mut!((*sb).len).write(0);
                core::ptr::addr_of_mut!((*sb).offset).write(0);
                core::ptr::addr_of_mut!((*sb).state)
                    .write(crate::apdu::shared_buffer::SharedBufState::Empty);
            }
            &mut *ptr
        }
    }

    /// Initialise `OpenPgp` in its own stack frame to avoid inflating
    /// `init_in_place`.  `OpenPgpState` is ~2 KB; `#[inline(never)]` keeps
    /// that temporary out of the caller's frame.
    #[inline(never)]
    fn init_openpgp_in_place(dest: *mut OpenPgp) {
        unsafe {
            dest.write(OpenPgp::new());
        }
    }

    /// Reset a live Dispatcher back to post-boot state **without** allocating
    /// a full ~36 KB Dispatcher on the stack.
    ///
    /// Used by the Core1 dispatcher loop on USB-reconnect reset signals.
    /// In debug builds `Dispatcher::new()` (and therefore `*self = Self::new()`)
    /// materialises the entire struct on the Core1 stack before `memcpy`ing
    /// into place; on the 128 KB Core1 stack this risks silent overflow when
    /// combined with the existing dispatch-chain temporaries.
    ///
    /// The old value is dropped in place first so that secret-bearing fields
    /// (`DkekManager`, `PinState`, cached `KeyObject`s, the ephemeral exchange
    /// key) run their zeroizing `Drop` impls — overwriting with `ptr::write`
    /// alone would leave that material in SRAM.  The fresh state is then
    /// written field-by-field via `init_in_place`, so peak added stack usage
    /// stays at a few hundred bytes.
    ///
    /// The caller is responsible for reloading flash-backed keys afterwards
    /// via `load_keys_from_store`; this method only resets in-memory state.
    #[inline(never)]
    pub fn reset_in_place(&mut self) {
        let ptr: *mut Self = self;
        // SAFETY: `self` is a valid, initialised Dispatcher.  After
        // `drop_in_place` the memory is logically uninitialised, and
        // `init_in_place` fully re-initialises every field before `self` is
        // used again.  None of the Drop impls or init helpers panic.
        unsafe {
            core::ptr::drop_in_place(ptr);
            Self::init_in_place(&mut *ptr.cast::<core::mem::MaybeUninit<Self>>());
        }
    }

    /// Return the total number of keys in the key_index, clamped to u8.
    ///
    /// Used by core1 to update the `KEY_COUNT` atomic without needing access
    /// to the flash keystore (which lives on core0).
    pub fn in_memory_key_count(&self) -> u8 {
        self.sc_hsm.state.key_index.len().min(255) as u8
    }

    /// Load all persisted keys from flash into the in-memory key cache.
    ///
    /// Called at session start and on USB reconnect (new Dispatcher).
    ///
    /// `#[inline(never)]` keeps the ~9 KB stack frame (from `KeyObject`
    /// temporaries in `fetch_key`) separate from the async state machine,
    /// preventing core0 stack overflow on display boards.
    #[inline(never)]
    pub fn load_keys_from_store(&mut self, store: &mut dyn crate::storage::KeyStore) {
        let mut sc_hsm_ids: Vec<pico2hsm_core::key::KeyId, 64> = Vec::new();
        store.for_each_key(&mut |kid| {
            // Skip firmware records that are not keys: PIN record (0xFF),
            // persisted DKEK (0xFD) and enrolled peer key (0xFC).  The
            // device identity key (0xFE) is a real key and stays listed.
            let is_ef = (kid.0 >> 8) & 0xFF != 0;
            let record = !is_ef && matches!(kid.proto_ref(), 0xFC | 0xFD | 0xFF);
            if kid.applet_byte() == 0 && !record {
                let _ = sc_hsm_ids.push(kid);
            }
        });
        let mut loaded = 0usize;
        for kid in sc_hsm_ids.iter() {
            match store.fetch_key(*kid) {
                Ok(Some(obj)) => {
                    // EF files (Generic/AesGcm stored via WRITE DATA) are
                    // identified by having file_id_hi in bits 15-8 of the
                    // key_id — normal SC-HSM keys have bits 15-8 = 0.
                    let is_ef = (kid.0 >> 8) & 0xFF != 0;
                    if is_ef {
                        push_ef_to_state(&mut self.sc_hsm.state, &obj);
                    } else {
                        push_key_object_to_state(&mut self.sc_hsm.state, obj);
                    }
                    loaded += 1;
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }
        let _ = loaded;

        #[cfg(feature = "applet-piv")]
        self.piv.load_from_store(store);
        self.openpgp.load_from_store(store);
        ScHsm::load_pin_state_from_store(&mut self.sc_hsm.state, store);
        ScHsm::load_peer_pubkey_from_store(&mut self.sc_hsm.state, store);
        ScHsm::load_dkek_from_store(&mut self.sc_hsm.state, store);
    }

    /// Dispatch a raw APDU byte slice with access to persistent storage.
    ///
    /// Centralizes GET RESPONSE (INS=0xC0) interception and Le-truncation
    /// chaining in the Dispatcher, so protocols just return full responses.
    pub fn dispatch_with_store(
        &mut self,
        raw_apdu: &[u8],
        store: &mut dyn crate::storage::KeyStore,
    ) -> Vec<u8, 4098> {
        // Parse the APDU
        let cmd = match ApduCommand::parse(raw_apdu) {
            Ok(c) => c,
            Err(_) => return ApduResponse::err(SW_INS_NOT_SUPPORTED).serialize(),
        };

        // Intercept SELECT by AID before forwarding.
        if cmd.ins == INS_SELECT && cmd.p1 == P1_SELECT_BY_AID {
            self.shared_buf.invalidate();
            let resp = self.select_aid(cmd.data);
            return resp.serialize();
        }

        // Intercept GET RESPONSE — serve from shared_buf, not protocols.
        if cmd.ins == INS_GET_RESPONSE {
            let resp = self.handle_get_response(cmd.le);
            return resp.serialize();
        }

        // Clear stale chaining data before routing to protocol.
        self.shared_buf.clear_if_not_get_response();

        // Route all active protocols through the storage-aware path.
        crate::CORE1_PROGRESS.store(20, core::sync::atomic::Ordering::Relaxed);
        let resp = match self.active {
            ActiveProtocol::ScHsm => self.sc_hsm.process_apdu_with_store(raw_apdu, store),
            ActiveProtocol::Piv => self.piv.process_apdu_with_store(raw_apdu, store),
            ActiveProtocol::OpenPgp => self.openpgp.process_apdu_with_store(raw_apdu, store),
            ActiveProtocol::None => return ApduResponse::err(SW_INS_NOT_SUPPORTED).serialize(),
        };

        // Apply Le-truncation with GET RESPONSE chaining.
        self.apply_le_truncation(resp, cmd.le)
    }

    /// Dispatch a raw APDU byte slice.
    ///
    /// Handles SELECT AID (INS=0xA4, P1=0x04) by switching the active
    /// protocol. GET RESPONSE (INS=0xC0) is intercepted and served from
    /// the shared buffer. All other commands are forwarded to the active
    /// protocol with Le-truncation applied afterward.
    ///
    /// Returns the serialized response bytes (data + SW1 + SW2).
    pub fn dispatch(&mut self, raw_apdu: &[u8]) -> Vec<u8, 4098> {
        // Parse the APDU
        let cmd = match ApduCommand::parse(raw_apdu) {
            Ok(c) => c,
            Err(_) => return ApduResponse::err(SW_INS_NOT_SUPPORTED).serialize(),
        };

        // Intercept SELECT by AID before forwarding to the active protocol.
        if cmd.ins == INS_SELECT && cmd.p1 == P1_SELECT_BY_AID {
            // SELECT is an interindustry command — CLA must be 0x00.
            if cmd.cla != 0x00 {
                return ApduResponse::err(SW_CLASS_NOT_SUPPORTED).serialize();
            }
            self.shared_buf.invalidate();
            let resp = self.select_aid(cmd.data);
            return resp.serialize();
        }

        // Intercept GET RESPONSE — serve from shared_buf.
        if cmd.ins == INS_GET_RESPONSE {
            let resp = self.handle_get_response(cmd.le);
            return resp.serialize();
        }

        // Clear stale chaining data before routing to protocol.
        self.shared_buf.clear_if_not_get_response();

        // Forward to the active protocol.
        let raw_resp: Vec<u8, 4098> = match self.active {
            ActiveProtocol::ScHsm => self.sc_hsm.process_apdu(raw_apdu),
            ActiveProtocol::Piv => self.piv.process_apdu(raw_apdu),
            ActiveProtocol::OpenPgp => self.openpgp.process_apdu(raw_apdu),
            ActiveProtocol::None => {
                // No AID selected yet — return INS not supported
                return ApduResponse::err(SW_INS_NOT_SUPPORTED).serialize();
            }
        };

        // Apply Le-truncation with GET RESPONSE chaining.
        self.apply_le_truncation(raw_resp, cmd.le)
    }

    /// Handle GET RESPONSE (INS=0xC0): serve the next chunk from `shared_buf`.
    fn handle_get_response(&mut self, le: Option<u16>) -> ApduResponse {
        let max_len = match le {
            None => 4096,   // no Le — return all remaining
            Some(0) => 256, // short APDU Le=0x00 → 256
            Some(n) => n as usize,
        };
        match self.shared_buf.get_response_chunk(max_len) {
            Some((chunk, more)) => {
                let mut resp = ApduResponse::ok(chunk);
                if more {
                    let remaining = self.shared_buf.len.saturating_sub(self.shared_buf.offset);
                    let xx = remaining.min(0xFF) as u8;
                    resp.sw = 0x6100 | (xx as u16);
                }
                resp
            }
            None => {
                // Nothing pending — return empty 9000 per ISO spec.
                ApduResponse::ok(&[])
            }
        }
    }

    /// Apply Le-truncation to a serialized protocol response.
    ///
    /// If the response data exceeds Le, the overflow is stored in `shared_buf`
    /// and the truncated response is returned with SW=0x61xx.
    ///
    /// `raw_resp` is the serialized response from the protocol (data + SW1 + SW2).
    fn apply_le_truncation(&mut self, raw_resp: Vec<u8, 4098>, le: Option<u16>) -> Vec<u8, 4098> {
        // Deserialize: last 2 bytes are SW, rest is data.
        if raw_resp.len() < 2 {
            let mut out: Vec<u8, 4098> = Vec::new();
            let _ = out.extend_from_slice(&raw_resp);
            return out;
        }
        let data_len = raw_resp.len() - 2;
        let sw = ((raw_resp[data_len] as u16) << 8) | (raw_resp[data_len + 1] as u16);

        // Only truncate successful responses (SW=9000).
        if sw != SW_OK {
            let mut out: Vec<u8, 4098> = Vec::new();
            let _ = out.extend_from_slice(&raw_resp);
            return out;
        }

        let le_val = match le {
            None => {
                // No Le — no truncation.
                let mut out: Vec<u8, 4098> = Vec::new();
                let _ = out.extend_from_slice(&raw_resp);
                return out;
            }
            Some(0) => {
                // Extended APDUs: Le=0x0000 stored as 0, meaning 65536 — don't truncate.
                // Short APDUs: Le=0x00 is pre-resolved to 256 by parser.
                // If we get 0 here it's from extended APDU → return all.
                let mut out: Vec<u8, 4098> = Vec::new();
                let _ = out.extend_from_slice(&raw_resp);
                return out;
            }
            Some(n) => n as usize,
        };

        if data_len <= le_val {
            // Response fits — no truncation needed.
            let mut out: Vec<u8, 4098> = Vec::new();
            let _ = out.extend_from_slice(&raw_resp);
            return out;
        }

        // Store overflow in shared_buf, return first le_val bytes + SW=0x61xx.
        self.shared_buf.store_response(&raw_resp[le_val..data_len]);
        let remaining = data_len - le_val;
        let xx = remaining.min(0xFF) as u8;
        let sw_chained = 0x6100 | (xx as u16);

        let mut out: Vec<u8, 4098> = Vec::new();
        let _ = out.extend_from_slice(&raw_resp[..le_val]);
        let _ = out.push((sw_chained >> 8) as u8);
        let _ = out.push((sw_chained & 0xFF) as u8);
        out
    }

    /// End the host session: drop every applet's authentication state and the
    /// selection, as a real card does on reset / power cycle.  Keys and
    /// persisted state are untouched (no reload needed).
    pub fn clear_session(&mut self) {
        self.active = ActiveProtocol::None;
        self.shared_buf.invalidate();
        let sc = &mut self.sc_hsm.state;
        sc.pin_verified = false;
        sc.so_pin_verified = false;
        sc.session_pin = None;
        sc.challenge = None;
        sc.current_key_id = None;
        sc.current_algo = None;
        sc.current_se_op = None;
        sc.exchange_ephem_priv = None;
        sc.exchange_ephem_pub = None;
        sc.exchange_challenge = None;
        sc.exchange_peer_ephem_pub = None;
        sc.op_buf.invalidate();
        #[cfg(feature = "applet-piv")]
        {
            let piv = &mut self.piv.state;
            piv.pin_verified = false;
            piv.pin_state.session_authenticated = false;
            piv.mgmt_key_authenticated = false;
            piv.mgmt_challenge = None;
        }
        let pgp = &mut self.openpgp.state;
        pgp.pw1_verified_sign = false;
        pgp.pw1_verified_other = false;
        pgp.pw3_verified = false;
    }

    /// Route a SELECT-by-AID command and return the appropriate FCI response.
    fn select_aid(&mut self, aid: &[u8]) -> ApduResponse {
        // SC-HSM AID
        if aid == SC_HSM_AID {
            self.active = ActiveProtocol::ScHsm;
            // Reset security state on each SELECT (mirrors PIV and OpenPGP
            // behaviour). A new SELECT must not inherit authentication from
            // a prior session — HIGH-1 security audit finding.
            self.sc_hsm.state.so_pin_verified = false;
            self.sc_hsm.state.pin_verified = false;
            return build_sc_hsm_fci();
        }

        // PIV AID
        if aid == PIV_AID {
            self.active = ActiveProtocol::Piv;
            // Reset security state on each SELECT (per NIST SP 800-73-4).
            // Gated on applet-piv: PivState fields don't exist without the feature.
            #[cfg(feature = "applet-piv")]
            {
                self.piv.state.pin_verified = false;
                self.piv.state.mgmt_key_authenticated = false;
                self.piv.state.mgmt_challenge = None;
            }
            return build_piv_fci();
        }

        // OpenPGP AID (prefix match)
        if aid.len() >= OPENPGP_AID_PREFIX.len()
            && &aid[..OPENPGP_AID_PREFIX.len()] == OPENPGP_AID_PREFIX
        {
            self.active = ActiveProtocol::OpenPgp;
            return build_openpgp_fci(&mut self.openpgp);
        }

        // Unknown AID
        ApduResponse::err(SW_FILE_NOT_FOUND)
    }
}

// ─── Key loader helpers ───────────────────────────────────────────────────────

/// Map a `security::key_management::AlgorithmId` to the `pico2hsm_core` `CoreKeyType`
/// used by `InMemoryKey.key_type`.
fn km_algo_to_core_key_type(
    algo: crate::security::key_management::AlgorithmId,
) -> pico2hsm_core::key::KeyType {
    use crate::security::key_management::AlgorithmId;
    use pico2hsm_core::key::KeyType as CoreKeyType;
    match algo {
        AlgorithmId::EcdsaP256 | AlgorithmId::EcdhP256 => CoreKeyType::EcPrivateP256,
        AlgorithmId::EcdsaP384 | AlgorithmId::EcdhP384 => CoreKeyType::EcPrivateP384,
        AlgorithmId::EcdsaP521 | AlgorithmId::EcdhP521 => CoreKeyType::EcPrivateP521,
        AlgorithmId::EcdsaK256 => CoreKeyType::EcPrivateK256,
        AlgorithmId::EcdsaBrainpool256 => CoreKeyType::EcPrivateBrainpoolP256,
        AlgorithmId::EcdsaBrainpool384 => CoreKeyType::EcPrivateBrainpoolP384,
        AlgorithmId::EcdsaBrainpool512 => CoreKeyType::EcPrivateBrainpoolP512,
        AlgorithmId::RsaPkcs1Sha256
        | AlgorithmId::RsaPkcs1Sha384
        | AlgorithmId::RsaPkcs1Sha512
        | AlgorithmId::RsaPss
        | AlgorithmId::RsaDecrypt => CoreKeyType::RsaPrivate2048,
        AlgorithmId::AesEcb | AlgorithmId::AesCbc | AlgorithmId::AesCtr | AlgorithmId::AesGcm => {
            CoreKeyType::Aes256
        }
        AlgorithmId::Ed25519 => CoreKeyType::Ed25519,
        AlgorithmId::X25519 => CoreKeyType::X25519,
    }
}

/// Convert a `KeyObject` (security layer) to a `KeyMeta` entry and push it
/// into `ScHsmState.key_index`. Key material stays in flash; only lightweight
/// metadata is kept in RAM.
fn push_key_object_to_state(
    state: &mut crate::protocol::sc_hsm::ScHsmState,
    obj: crate::security::key_management::KeyObject,
) {
    use crate::protocol::sc_hsm::KeyMeta;

    let algo = obj.algorithm as u8;
    let core_key_type = km_algo_to_core_key_type(obj.algorithm);

    // Avoid duplicate entries — replace any existing entry with the same key_id.
    state.key_index.retain(|m| m.key_id != obj.key_id);

    let meta = KeyMeta {
        key_id: obj.key_id,
        key_type: core_key_type as u8,
        algo,
        key_flags: obj.key_flags,
    };
    let _ = state.key_index.push(meta);
}

/// Convert a `KeyObject` representing an EF file (written via WRITE DATA) to
/// a `KeyMeta` entry + ef_cache data.  EF files are stored in flash with
/// `KmType::Generic` / `AlgorithmId::AesGcm`, but their key_index metadata
/// uses `key_type=16` (EfFile) and `algo=file_id_hi`.
fn push_ef_to_state(
    state: &mut crate::protocol::sc_hsm::ScHsmState,
    obj: &crate::security::key_management::KeyObject,
) {
    use crate::protocol::sc_hsm::KeyMeta;

    // Extract file_id_hi from key_id bits 15-8.
    let file_id_hi = ((obj.key_id >> 8) & 0xFF) as u8;

    // Avoid duplicate entries.
    state.key_index.retain(|m| m.key_id != obj.key_id);

    let meta = KeyMeta {
        key_id: obj.key_id,
        key_type: 16, // EfFile
        algo: file_id_hi,
        key_flags: 0,
    };
    let _ = state.key_index.push(meta);

    // Populate ef_cache so read_binary can serve the data.
    state.ef_cache_put(obj.key_id, &obj.private_key);
}

/// Build the FCI (File Control Information) template returned on SELECT SC-HSM AID.
///
/// Structure matches a real SmartCard-HSM 2 SELECT response so that OpenSC's
/// `iso7816_select_file` accepts it (it requires the outer tag to be 0x6F):
///
/// ```text
/// 6F 16          FCI template (ISO 7816-4 §7.1.1)
///   84 0B [AID]  DF name (tag 0x84 = DF name in FCI context)
///   A5 07        Proprietary information
///     9F 6E 04 [4 bytes]  COS/HW version (SmartCard-HSM convention)
/// ```
fn build_sc_hsm_fci() -> ApduResponse {
    let aid: &[u8] = SC_HSM_AID; // 11 bytes
                                 // 4 version bytes: [cwa_major, cwa_minor, hw_major, hw_minor]
    let version: &[u8] = &[0x20, 0x00, 0x00, 0x00];

    // A5 inner: 9F 6E 04 + 4 bytes = 7 bytes
    let a5_inner_len: u8 = 2 + 1 + version.len() as u8; // tag(2) + len(1) + data(4) = 7
                                                        // 6F inner: 84 TLV (13 bytes) + A5 TLV (2+7 = 9 bytes) = 22 bytes
    let outer_len: u8 = (2 + aid.len() as u8) + (2 + a5_inner_len);

    let mut fci: Vec<u8, 32> = Vec::new();
    let _ = fci.push(0x6F);
    let _ = fci.push(outer_len);

    // 84: DF name (AID)
    let _ = fci.push(0x84);
    let _ = fci.push(aid.len() as u8);
    let _ = fci.extend_from_slice(aid);

    // A5: proprietary — contains 9F6E version TLV
    let _ = fci.push(0xA5);
    let _ = fci.push(a5_inner_len);
    let _ = fci.push(0x9F);
    let _ = fci.push(0x6E);
    let _ = fci.push(version.len() as u8);
    let _ = fci.extend_from_slice(version);

    ApduResponse::ok(&fci)
}

/// Build the Application Property Template returned on SELECT PIV AID.
///
/// Structure per NIST SP 800-73-4:
/// ```text
/// 61 11
///   4F 0B <PIV AID>       — Application Identifier
///   50 03 50 49 56         — Application Label "PIV"
/// ```
fn build_piv_fci() -> ApduResponse {
    let label = b"PIV";
    let aid_tlv_len = 2 + PIV_AID.len();
    let label_tlv_len = 2 + label.len();
    let inner_len = aid_tlv_len + label_tlv_len;

    let mut fci: Vec<u8, 32> = Vec::new();
    let _ = fci.push(0x61);
    let _ = fci.push(inner_len as u8);

    let _ = fci.push(0x4F);
    let _ = fci.push(PIV_AID.len() as u8);
    let _ = fci.extend_from_slice(PIV_AID);

    let _ = fci.push(0x50);
    let _ = fci.push(label.len() as u8);
    let _ = fci.extend_from_slice(label);

    ApduResponse::ok(&fci)
}

/// Build the FCI returned on SELECT OpenPGP AID and reset security state.
///
/// Structure per OpenPGP Card 3.4:
/// ```text
/// 6F xx
///   84 10 <full 16-byte AID>
///   A5 xx
///     9F6E 04 03 04 00 00   — version 3.4
/// ```
fn build_openpgp_fci(openpgp: &mut OpenPgp) -> ApduResponse {
    use crate::protocol::openpgp::OPENPGP_AID;

    openpgp.state.reset_security_state();

    let aid = &OPENPGP_AID;
    let version: &[u8] = &[0x03, 0x04, 0x00, 0x00];

    let a5_inner_len: u8 = 2 + 1 + version.len() as u8;
    let outer_len: u8 = (2 + aid.len() as u8) + (2 + a5_inner_len);

    let mut fci: Vec<u8, 48> = Vec::new();
    let _ = fci.push(0x6F);
    let _ = fci.push(outer_len);

    let _ = fci.push(0x84);
    let _ = fci.push(aid.len() as u8);
    let _ = fci.extend_from_slice(aid);

    let _ = fci.push(0xA5);
    let _ = fci.push(a5_inner_len);
    let _ = fci.push(0x9F);
    let _ = fci.push(0x6E);
    let _ = fci.push(version.len() as u8);
    let _ = fci.extend_from_slice(version);

    ApduResponse::ok(&fci)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_in_place_zeroizes_dkek() {
        let mut slot = core::mem::MaybeUninit::<Dispatcher>::uninit();
        let d = Dispatcher::init_in_place(&mut slot);
        let pattern = [0xA5u8; 32];
        d.sc_hsm.state.dkek.set_dkek_direct(&pattern);
        assert!(d.sc_hsm.state.dkek.is_ready());

        d.reset_in_place();

        assert!(!d.sc_hsm.state.dkek.is_ready());
        // The old DKEK bytes must not survive anywhere in the struct.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (d as *const Dispatcher).cast::<u8>(),
                core::mem::size_of::<Dispatcher>(),
            )
        };
        assert!(!bytes.windows(32).any(|w| w == pattern));
    }

    #[test]
    fn clear_session_drops_all_authentication() {
        let mut slot = core::mem::MaybeUninit::<Dispatcher>::uninit();
        let d = Dispatcher::init_in_place(&mut slot);
        d.active = ActiveProtocol::ScHsm;
        d.sc_hsm.state.pin_verified = true;
        d.sc_hsm.state.so_pin_verified = true;
        d.sc_hsm.state.session_pin = Some([1; 8]);
        #[cfg(feature = "applet-piv")]
        {
            d.piv.state.pin_verified = true;
            d.piv.state.mgmt_key_authenticated = true;
        }
        d.openpgp.state.pw1_verified_sign = true;
        d.openpgp.state.pw3_verified = true;

        d.clear_session();

        assert_eq!(d.active, ActiveProtocol::None);
        assert!(!d.sc_hsm.state.pin_verified && !d.sc_hsm.state.so_pin_verified);
        assert!(d.sc_hsm.state.session_pin.is_none());
        #[cfg(feature = "applet-piv")]
        assert!(!d.piv.state.pin_verified && !d.piv.state.mgmt_key_authenticated);
        assert!(!d.openpgp.state.pw1_verified_sign && !d.openpgp.state.pw3_verified);
    }
}
