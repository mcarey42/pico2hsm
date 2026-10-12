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

/// Most response data one CCID message carries: dwMaxCCIDMessageLength
/// (4096) minus the 10-byte header and the 2-byte status word.
pub const MAX_RESPONSE_DATA: usize = 4096 - 10 - 2;

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
    /// What the status display is told (see [`DisplayBook`]).
    display: DisplayBook,
}

/// Core1's display bookkeeping: the operation in flight and the health and
/// inventory facts that cannot be read from applet state on every publish.
/// Survives [`Dispatcher::reset_in_place`] (boot health, op history).
#[derive(Clone, Copy, Debug)]
pub struct DisplayBook {
    /// Chained-command tracking for [`pico2hsm_core::op::classify_op`].
    tracker: pico2hsm_core::op::OpTracker,
    /// The last tracked operation (W1).
    activity: crate::display_snapshot::Activity,
    /// Its status word (W4).
    last_sw: u16,
    /// INS / P1 of the command being dispatched, and whether it is tracked.
    current: Option<(u8, u8, bool)>,
    /// `display_snapshot::oneshot` bits before that command.
    armed_before: u8,
    /// The session epoch core1 is in (all 32 bits).
    epoch: u32,
    /// The last tracked operation, or the GET RESPONSE that continued it,
    /// answered 61xx: the next GET RESPONSE completes it.
    awaiting_get_response: bool,
    /// `display_snapshot::health` bits.
    health: u8,
    /// Domain facts, refreshed from the store when they can change.
    domain: crate::display_snapshot::DomainState,
    members: u8,
    domain_id_hi16: u16,
    /// SC-HSM user-PIN allowance (tries granted at the last reset).
    hsm_pin_max: u8,
}

impl DisplayBook {
    const fn new() -> Self {
        DisplayBook {
            tracker: pico2hsm_core::op::OpTracker::new(),
            activity: crate::display_snapshot::Activity {
                op_seq: 0,
                op: pico2hsm_core::op::OpCode::None,
                state: crate::display_snapshot::OpState::Idle,
                result: pico2hsm_core::op::OpResult::Ok,
                algo: 0,
                key_ref: 0,
                hint: 0,
            },
            last_sw: 0,
            current: None,
            armed_before: 0,
            epoch: 0,
            awaiting_get_response: false,
            health: 0,
            domain: crate::display_snapshot::DomainState::None,
            members: 0,
            domain_id_hi16: 0,
            hsm_pin_max: 3,
        }
    }
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
            display: DisplayBook::new(),
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
            core::ptr::addr_of_mut!((*ptr).display).write(DisplayBook::new());
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
        // Boot health and the op history outlive the reset.
        let display = self.display;
        let ptr: *mut Self = self;
        // SAFETY: `self` is a valid, initialised Dispatcher.  After
        // `drop_in_place` the memory is logically uninitialised, and
        // `init_in_place` fully re-initialises every field before `self` is
        // used again.  None of the Drop impls or init helpers panic.
        unsafe {
            core::ptr::drop_in_place(ptr);
            Self::init_in_place(&mut *ptr.cast::<core::mem::MaybeUninit<Self>>());
        }
        self.display = DisplayBook {
            tracker: pico2hsm_core::op::OpTracker::new(),
            current: None,
            awaiting_get_response: false,
            ..display
        };
    }

    /// Return the total number of entries in SC-HSM's key_index (keys and
    /// files), clamped to u8.  The display counts user keys only
    /// ([`Self::display_snapshot`]).
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
        // Room for every SC-HSM object the directory can hold (~1.4 KB of
        // core0 stack); a 64-entry list silently skipped the rest.
        let mut sc_hsm_ids: Vec<
            pico2hsm_core::key::KeyId,
            { crate::protocol::sc_hsm::MAX_KEY_INDEX },
        > = Vec::new();
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
        ScHsm::load_dkek_from_store(&mut self.sc_hsm.state, store);
        ScHsm::load_domain_from_store(&mut self.sc_hsm.state, store);
        self.refresh_display_facts(store);
    }

    /// Boot-time domain migration (cluster plan V3 P1), after
    /// [`Self::load_keys_from_store`], on core0 only: see
    /// `ScHsm::migrate_domain`.
    #[inline(never)]
    pub fn migrate_domain(&mut self, store: &mut dyn crate::storage::KeyStore) {
        ScHsm::migrate_domain(&self.sc_hsm.state, store);
    }

    /// One-time migration of the PIN/PUK retry counts into the retry-counter
    /// log (`storage::retry_counter`).  Boot only, on core0, before
    /// [`Self::load_keys_from_store`].  `Ok(true)` if it ran.
    ///
    /// If the log is unformatted (first boot after the upgrade, or a blank
    /// device), it is seeded from the counts in the applets' PIN records and
    /// committed in one step; then those counts are zeroed in the records,
    /// so no record ever again holds a usable count.  Until the commit
    /// succeeds nothing changes on flash, every credential loads blocked
    /// (the log is unreadable) and the migration runs again at the next
    /// boot.  A failure while zeroing only leaves a legacy count behind,
    /// which the log overrides.
    #[inline(never)]
    pub fn migrate_retry_counters(
        store: &mut dyn crate::storage::KeyStore,
    ) -> Result<bool, pico2hsm_core::error::HsmError> {
        use crate::storage::retry_counter::{CounterState, Credential};
        use pico2hsm_core::error::{HsmError, StorageError};

        if !store
            .retry_counters()
            .is_some_and(|log| log.needs_migration())
        {
            return Ok(false);
        }
        let mut seeds: Vec<(Credential, CounterState), 8> = Vec::new();
        ScHsm::legacy_retry_seeds(store, &mut seeds)?;
        #[cfg(feature = "applet-piv")]
        Piv::legacy_retry_seeds(store, &mut seeds)?;
        OpenPgp::legacy_retry_seeds(store, &mut seeds)?;
        store
            .retry_counters()
            .ok_or(HsmError::Storage(StorageError::NotFormatted))?
            .format(&seeds)?;
        ScHsm::clear_legacy_retry_counts(store)?;
        #[cfg(feature = "applet-piv")]
        Piv::clear_legacy_retry_counts(store)?;
        OpenPgp::clear_legacy_retry_counts(store)?;
        Ok(true)
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
        let mut out = Vec::new();
        self.dispatch_into(raw_apdu, store, &mut out);
        out
    }

    /// [`dispatch_with_store`](Self::dispatch_with_store), writing the
    /// response into `out` (core1 passes the response mailbox, so the
    /// response is not copied again on its way out).
    pub fn dispatch_into(
        &mut self,
        raw_apdu: &[u8],
        store: &mut dyn crate::storage::KeyStore,
        out: &mut Vec<u8, 4098>,
    ) {
        // Parse the APDU
        let cmd = match ApduCommand::parse(raw_apdu) {
            Ok(c) => c,
            Err(_) => return ApduResponse::err(SW_INS_NOT_SUPPORTED).serialize_into(out),
        };

        // Intercept SELECT by AID before forwarding.
        if cmd.ins == INS_SELECT && cmd.p1 == P1_SELECT_BY_AID {
            self.shared_buf.invalidate();
            let resp = self.select_aid(cmd.data);
            return resp.serialize_into(out);
        }

        // Intercept GET RESPONSE — serve from shared_buf, not protocols.
        if cmd.ins == INS_GET_RESPONSE {
            let resp = self.handle_get_response(cmd.le);
            return resp.serialize_into(out);
        }

        // Clear stale chaining data before routing to protocol.
        self.shared_buf.clear_if_not_get_response();

        // Route all active protocols through the storage-aware path.
        crate::CORE1_PROGRESS.store(20, core::sync::atomic::Ordering::Relaxed);
        let mut resp = match self.active {
            ActiveProtocol::ScHsm => self.sc_hsm.process_apdu_with_store(raw_apdu, store),
            ActiveProtocol::Piv => self.piv.process_apdu_with_store(raw_apdu, store),
            ActiveProtocol::OpenPgp => self.openpgp.process_apdu_with_store(raw_apdu, store),
            ActiveProtocol::None => {
                return ApduResponse::err(SW_INS_NOT_SUPPORTED).serialize_into(out)
            }
        };
        out.clear();
        let _ = out.extend_from_slice(&resp);
        // The response may hold secrets (plaintext, ECDH output).
        zeroize::Zeroize::zeroize(resp.as_mut_slice());

        // Apply Le-truncation with GET RESPONSE chaining.
        self.truncate_for_le(out, cmd.le);
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
        // Capped like every response (see MAX_RESPONSE_DATA).  The parser
        // already turns a short Le=00 into 256, so 0 here is an extended
        // Le=0000: as much as fits.
        let max_len = match le {
            None | Some(0) => MAX_RESPONSE_DATA,
            Some(n) => (n as usize).min(MAX_RESPONSE_DATA),
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
    fn apply_le_truncation(
        &mut self,
        mut raw_resp: Vec<u8, 4098>,
        le: Option<u16>,
    ) -> Vec<u8, 4098> {
        self.truncate_for_le(&mut raw_resp, le);
        raw_resp
    }

    /// Le-truncation in place: a successful response with more data than
    /// Le (or than one CCID message) keeps the first part and SW 61xx; the
    /// rest goes to `shared_buf` for GET RESPONSE, and is wiped from `resp`.
    fn truncate_for_le(&mut self, resp: &mut Vec<u8, 4098>, le: Option<u16>) {
        // Last 2 bytes are SW, the rest is data.
        if resp.len() < 2 {
            return;
        }
        let data_len = resp.len() - 2;
        let sw = ((resp[data_len] as u16) << 8) | (resp[data_len + 1] as u16);

        // Only truncate successful responses (SW=9000).
        if sw != SW_OK {
            return;
        }

        // Never more data than one CCID message can carry: the descriptor
        // advertises dwMaxCCIDMessageLength 4096 (10-byte header + data +
        // SW).  Larger responses used to overflow the transport buffer and
        // were dropped, leaving the host waiting; the rest is now chained
        // with 61xx / GET RESPONSE, even when the host asked for "all".
        let le_val = match le {
            // No Le, or extended Le = 0x0000 (65536): as much as fits.
            None | Some(0) => MAX_RESPONSE_DATA,
            Some(n) => (n as usize).min(MAX_RESPONSE_DATA),
        };

        if data_len <= le_val {
            // Response fits — no truncation needed.
            return;
        }

        // Store overflow in shared_buf, keep the first le_val bytes + SW=0x61xx.
        self.shared_buf.store_response(&resp[le_val..data_len]);
        let remaining = data_len - le_val;
        let xx = remaining.min(0xFF) as u8;
        let sw_chained = 0x6100 | (xx as u16);

        zeroize::Zeroize::zeroize(&mut resp[le_val..]);
        resp.truncate(le_val);
        let _ = resp.push((sw_chained >> 8) as u8);
        let _ = resp.push((sw_chained & 0xFF) as u8);
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
        sc.exchanged_peer = None;
        sc.op_buf.invalidate();
        #[cfg(feature = "applet-piv")]
        {
            let piv = &mut self.piv.state;
            piv.pin_verified = false;
            piv.pin_always_ok = false;
            piv.pin_state.session_authenticated = false;
            piv.mgmt_key_authenticated = false;
            piv.mgmt_challenge = None;
        }
        let pgp = &mut self.openpgp.state;
        pgp.pw1_verified_sign = false;
        pgp.pw1_verified_other = false;
        pgp.pw3_verified = false;
        self.display.tracker.reset();
        self.display.awaiting_get_response = false;
        // A comparison code never outlives its session.
        crate::display_snapshot::sas_clear(crate::display_snapshot::SasState::Cancelled);
    }

    /// Route a SELECT-by-AID command and return the appropriate FCI response.
    fn select_aid(&mut self, aid: &[u8]) -> ApduResponse {
        let before = self.active;
        let resp = self.select_aid_inner(aid);
        if self.active != before {
            crate::display_snapshot::sas_clear(crate::display_snapshot::SasState::Cancelled);
        }
        resp
    }

    fn select_aid_inner(&mut self, aid: &[u8]) -> ApduResponse {
        // SC-HSM AID
        if aid == SC_HSM_AID {
            self.active = ActiveProtocol::ScHsm;
            // Reset security state on each SELECT (mirrors PIV and OpenPGP
            // behaviour). A new SELECT must not inherit authentication from
            // a prior session — HIGH-1 security audit finding.
            self.sc_hsm.state.so_pin_verified = false;
            self.sc_hsm.state.pin_verified = false;
            // Nor the right to certify a peer served earlier (another
            // client of a shared reader may be the one selecting).
            self.sc_hsm.state.exchanged_peer = None;
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
                self.piv.state.pin_always_ok = false;
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

// ─── Status display (core1 side) ─────────────────────────────────────────────

/// Status word the keystore layer reports for a failed write.
const SW_MEMORY_FAILURE: u16 = 0x6581;

/// Small display algorithm id for a `pico2hsm_core::key::KeyType`
/// discriminant (as stored in `KeyMeta::key_type`).
fn display_algo_of_key_type(key_type: u8) -> u8 {
    use crate::display_snapshot::algo;
    match key_type {
        0 | 1 | 15 => algo::RSA,
        2 => algo::P256,
        3 => algo::P384,
        4 => algo::P521,
        5 => algo::K256,
        6..=8 => algo::BRAINPOOL,
        9..=11 => algo::AES,
        13 => algo::ED25519,
        14 => algo::X25519,
        _ => algo::NONE,
    }
}

/// Small display algorithm id for a PIV algorithm reference (P1).
fn display_algo_of_piv(p1: u8) -> u8 {
    use crate::display_snapshot::algo;
    match p1 {
        0x05 | 0x06 | 0x07 | 0x16 => algo::RSA,
        0x11 => algo::P256,
        0x14 => algo::P384,
        0xE0 => algo::ED25519,
        0xE1 => algo::X25519,
        _ => algo::NONE,
    }
}

impl Dispatcher {
    fn display_applet(&self) -> pico2hsm_core::op::Applet {
        use pico2hsm_core::op::Applet;
        match self.active {
            ActiveProtocol::None => Applet::None,
            ActiveProtocol::ScHsm => Applet::Hsm,
            ActiveProtocol::Piv => Applet::Piv,
            ActiveProtocol::OpenPgp => Applet::Pgp,
        }
    }

    /// Boot-time health facts (`display_snapshot::health` bits), set by
    /// core0 before core1 starts.
    pub fn set_boot_health(&mut self, flags: u8) {
        use crate::display_snapshot::health::STORE_WRITE_FAILED;
        self.display.health = flags & !STORE_WRITE_FAILED;
    }

    /// Record the host session core1 now serves (after
    /// [`Self::clear_session`], and at boot).
    pub fn note_session(&mut self, epoch: u32) {
        self.display.epoch = epoch;
    }

    /// Debug detail for the activity line: (algorithm, key reference).
    fn op_subject(
        &self,
        applet: pico2hsm_core::op::Applet,
        op: pico2hsm_core::op::OpCode,
        cmd: &ApduCommand<'_>,
    ) -> (u8, u8) {
        use crate::display_snapshot::algo;
        use pico2hsm_core::op::{Applet, OpCode};
        match applet {
            Applet::Hsm => {
                let key_ref = match op {
                    OpCode::Sign
                    | OpCode::Decrypt
                    | OpCode::Derive
                    | OpCode::KeyGen
                    | OpCode::Import => cmd.p1,
                    _ => 0,
                };
                let algo = self
                    .sc_hsm
                    .state
                    .key_index
                    .iter()
                    .find(|m| (m.key_id >> 8) & 0xFF == 0 && m.key_id as u8 == key_ref)
                    .map_or(algo::NONE, |m| display_algo_of_key_type(m.key_type));
                (algo, key_ref)
            }
            Applet::Piv => match op {
                OpCode::Sign | OpCode::Decrypt | OpCode::Derive | OpCode::KeyGen => {
                    (display_algo_of_piv(cmd.p1), cmd.p2)
                }
                _ => (algo::NONE, 0),
            },
            Applet::Pgp => {
                let st = &self.openpgp.state;
                let (slot, kt) = match op {
                    OpCode::Sign => (0x90, st.sig_key_type),
                    OpCode::Decipher => (0x91, st.dec_key_type),
                    OpCode::Auth => (0x92, st.auth_key_type),
                    _ => return (algo::NONE, 0),
                };
                (
                    kt.map_or(algo::NONE, |k| display_algo_of_key_type(k as u8)),
                    slot,
                )
            }
            Applet::None => (algo::NONE, 0),
        }
    }

    /// Before dispatch (core1): classify the command.  Returns `true` if it
    /// is a tracked operation, now marked in progress — publish then.
    pub fn display_begin(&mut self, raw_apdu: &[u8]) -> bool {
        use crate::display_snapshot::OpState;
        use pico2hsm_core::op::{OpCode, OpResult};
        let Ok(cmd) = ApduCommand::parse(raw_apdu) else {
            self.display.current = None;
            return false;
        };
        let applet = self.display_applet();
        let op = self
            .display
            .tracker
            .observe(applet, cmd.cla, cmd.ins, cmd.p1, cmd.p2, cmd.data);
        let tracked = !matches!(op, OpCode::Other | OpCode::None);
        self.display.current = Some((cmd.ins, cmd.p1, tracked));
        self.display.armed_before = self.display_oneshot();
        if tracked {
            let (algo, key_ref) = self.op_subject(applet, op, &cmd);
            let a = &mut self.display.activity;
            a.op_seq = a.op_seq.wrapping_add(1);
            a.op = op;
            a.state = OpState::InProgress;
            a.result = OpResult::Ok;
            a.algo = algo;
            a.key_ref = key_ref;
            a.hint = 0;
        }
        tracked
    }

    /// The live one-shot authorisations (`display_snapshot::oneshot`).
    fn display_oneshot(&self) -> u8 {
        use crate::display_snapshot::oneshot;
        let mut one = 0;
        #[cfg(feature = "applet-piv")]
        if self.piv.state.pin_always_ok {
            one |= oneshot::PIV_9C_ARMED;
        }
        let pgp = &self.openpgp.state;
        if pgp.pw1_verified_sign && pgp.pw1_status == 0 {
            one |= oneshot::PGP_SIG_SINGLE;
        }
        one
    }

    /// After dispatch (core1): record the outcome of the command that
    /// [`Self::display_begin`] saw, and refresh what it may have changed.
    pub fn display_end(&mut self, response: &[u8], store: &mut dyn crate::storage::KeyStore) {
        use crate::display_snapshot::{health, hint, oneshot, OpState, SasState};
        use pico2hsm_core::op::OpResult;
        let Some((ins, p1, tracked)) = self.display.current.take() else {
            return;
        };
        let sw = match response {
            [.., a, b] => u16::from_be_bytes([*a, *b]),
            _ => 0x6F00,
        };
        let result = OpResult::of_sw(sw);
        // A GET RESPONSE that continues a tracked operation's 61xx answer
        // carries that operation's final status: record it (same op, same
        // op_seq, so the display keeps its age).
        let continues = !tracked && ins == 0xC0 && self.display.awaiting_get_response;
        self.display.awaiting_get_response = (tracked || continues) && sw >> 8 == 0x61;
        if continues {
            self.display.activity.result = result;
            self.display.last_sw = sw;
        }
        if tracked {
            // A signature that spent a one-shot authorisation says so.
            let spent = self.display.armed_before & !self.display_oneshot();
            let a = &mut self.display.activity;
            a.state = OpState::Done;
            a.result = result;
            a.hint = match (a.op, result) {
                (pico2hsm_core::op::OpCode::Sign, OpResult::Ok)
                    if spent & oneshot::PIV_9C_ARMED != 0 && a.key_ref == 0x9C =>
                {
                    hint::PIV_PIN_ALWAYS
                }
                (pico2hsm_core::op::OpCode::Sign, OpResult::Ok)
                    if spent & oneshot::PGP_SIG_SINGLE != 0 =>
                {
                    hint::PGP_SINGLE_USE
                }
                _ => hint::NONE,
            };
            self.display.last_sw = sw;
        }
        if sw == SW_MEMORY_FAILURE {
            self.display.health |= health::STORE_WRITE_FAILED;
        } else if result == OpResult::Ok && tracked && self.display.activity.op.writes_storage() {
            self.display.health &= !health::STORE_WRITE_FAILED;
        }
        if result != OpResult::Ok || self.active != ActiveProtocol::ScHsm {
            return;
        }
        match ins {
            // INITIALIZE: new credentials, no DKEK, no domain.
            0x50 => {
                self.display.hsm_pin_max = self.sc_hsm.state.pin_retry_count.max(1);
                crate::display_snapshot::sas_clear(SasState::Cancelled);
                self.refresh_display_facts(store);
            }
            // RESET RETRY COUNTER restores the allowance.
            0x2C => {
                self.display.hsm_pin_max = self
                    .display
                    .hsm_pin_max
                    .max(self.sc_hsm.state.pin_retry_count);
            }
            // DKEK import (KEY DOMAIN).
            0x52 => self.refresh_display_facts(store),
            // EXTRAS sub-commands that change the DKEK, the member list or
            // the pinned peer.  A newly pinned peer ends any pending code.
            0x54 if (0x35..=0x4F).contains(&p1)
                && !matches!(p1, 0x39 | 0x3A | 0x3C | 0x40 | 0x47) =>
            {
                if p1 == 0x3D {
                    crate::display_snapshot::sas_clear(SasState::Cancelled);
                }
                self.refresh_display_facts(store);
            }
            // Provisioning may have changed the OTP state.
            #[cfg(target_arch = "arm")]
            0xF0..=0xF2 => {
                if crate::security::otp::Otp::new().is_provisioned() {
                    self.display.health |= health::PROVISIONED;
                } else {
                    self.display.health &= !health::PROVISIONED;
                }
            }
            _ => {}
        }
    }

    /// Re-read the display facts that live on the store: domain membership
    /// and the SC-HSM user-PIN allowance.  Boot / reload, and after the
    /// commands that change them (never on every publish).
    #[inline(never)] // keeps the member-list KeyObject temporaries off the caller's frame
    fn refresh_display_facts(&mut self, store: &mut dyn crate::storage::KeyStore) {
        use crate::display_snapshot::DomainState;
        use crate::domain::member;
        use crate::storage::retry_counter::Credential;

        if let Some(Ok(Some(st))) = store
            .retry_counters()
            .map(|log| log.get(Credential::ScHsmUserPin))
        {
            self.display.hsm_pin_max = st.allowance.max(1);
        }

        let Some(domain) = self.sc_hsm.state.domain.as_ref() else {
            self.display.domain = DomainState::None;
            self.display.members = 0;
            self.display.domain_id_hi16 = 0;
            return;
        };
        self.display.domain_id_hi16 = u16::from_be_bytes([domain.id[0], domain.id[1]]);
        let members = member::count(store).unwrap_or(0);
        self.display.members = members;
        let mut state = DomainState::SelfOnly;
        if let Some(own) = ScHsm::device_member_pub(store).map(|p| member::member_id(&p)) {
            for slot in 0..members {
                if let Ok(Some(e)) = member::load(store, slot) {
                    if e.cert.member_id == own {
                        state = if e.status() == member::STATUS_REVOKED {
                            DomainState::Revoked
                        } else {
                            DomainState::Member
                        };
                        break;
                    }
                }
            }
        }
        self.display.domain = state;
    }

    /// The display snapshot (W0–W4) from the live applet state.  Reads RAM
    /// only: retry counts are the applets' RAM copies, which every
    /// `with_persisted_attempt` keeps equal to what flash holds.
    pub fn display_snapshot(&self) -> crate::display_snapshot::Snapshot {
        use crate::display_snapshot::{auth, blocked, Health, Inventory, Session, Snapshot};
        use pico2hsm_core::op::Applet;

        let sc = &self.sc_hsm.state;
        let pgp = &self.openpgp.state;
        let mut a = 0u8;
        let one = self.display_oneshot();
        let mut blk = 0u8;
        if sc.pin_verified {
            a |= auth::HSM_USER;
        }
        if sc.so_pin_verified {
            a |= auth::HSM_SO;
        }
        if sc.initialized && sc.user_pin_hash.is_some() && sc.pin_retry_count == 0 {
            blk |= blocked::HSM;
        }
        #[cfg(feature = "applet-piv")]
        let (piv_left, piv_max, piv_keys) = {
            let piv = &self.piv.state;
            if piv.pin_verified {
                a |= auth::PIV_PIN;
            }
            if piv.mgmt_key_authenticated {
                a |= auth::PIV_MGMT;
            }
            let ps = &piv.pin_state;
            if ps.pin_blocked || ps.pin_retries_remaining == 0 {
                blk |= blocked::PIV;
            }
            (
                ps.pin_retries_remaining,
                ps.pin_max_retries,
                piv.key_index.len(),
            )
        };
        #[cfg(not(feature = "applet-piv"))]
        let (piv_left, piv_max, piv_keys) = (0u8, 0u8, 0usize);
        if pgp.pw1_verified_sign {
            a |= auth::PGP_PW1_81;
        }
        if pgp.pw1_verified_other {
            a |= auth::PGP_PW1_82;
        }
        if pgp.pw3_verified {
            a |= auth::PGP_PW3;
        }
        if pgp.pw1_retries == 0 {
            blk |= blocked::PGP;
        }

        let applet = self.display_applet();
        let (left, max) = match applet {
            Applet::Hsm => (
                sc.pin_retry_count,
                self.display.hsm_pin_max.max(sc.pin_retry_count),
            ),
            Applet::Piv => (piv_left, piv_max.max(piv_left)),
            Applet::Pgp => (
                pgp.pw1_retries,
                crate::protocol::openpgp::PW1_MAX_RETRIES.max(pgp.pw1_retries),
            ),
            Applet::None => (0, 0),
        };

        // User keys only: no files (type 16), no firmware records.
        let keys_hsm = sc
            .key_index
            .iter()
            .filter(|m| {
                m.key_type != 16
                    && (m.key_id >> 8) & 0xFF == 0
                    && !matches!(m.key_id as u8, 0xFC..=0xFF)
            })
            .count();
        let keys_pgp = [pgp.sig_key_type, pgp.dec_key_type, pgp.auth_key_type]
            .iter()
            .filter(|k| k.is_some())
            .count();

        Snapshot {
            session: Session {
                epoch: self.display.epoch,
                applet,
                auth: a,
                oneshot: one,
                pri_left: left.min(15),
                pri_max: max.min(15),
                blocked: blk,
            },
            activity: self.display.activity,
            inventory: Inventory {
                keys_hsm: keys_hsm.min(255) as u8,
                keys_piv: piv_keys.min(15) as u8,
                keys_pgp: keys_pgp as u8,
                domain: self.display.domain,
                members: self.display.members.min(63),
            },
            health: Health {
                domain_id_hi16: self.display.domain_id_hi16,
                flags: self.display.health
                    | if crate::display_snapshot::SD_FAULT
                        .load(core::sync::atomic::Ordering::Acquire)
                    {
                        crate::display_snapshot::health::SD_MISSING
                    } else {
                        0
                    },
            },
            last_sw: self.display.last_sw,
        }
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
    use crate::protocol::openpgp::openpgp_aid;

    openpgp.state.reset_security_state();

    let aid = &openpgp_aid();
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
    fn oversized_response_is_chained_not_dropped() {
        let mut slot = core::mem::MaybeUninit::<Dispatcher>::uninit();
        let d = Dispatcher::init_in_place(&mut slot);
        let mut raw: Vec<u8, 4098> = Vec::new();
        raw.resize(4096, 0xAB).unwrap();
        raw.extend_from_slice(&[0x90, 0x00]).unwrap();
        for le in [None, Some(0)] {
            let out = d.apply_le_truncation(raw.clone(), le);
            assert_eq!(out.len(), MAX_RESPONSE_DATA + 2, "fits one CCID message");
            assert_eq!(
                &out[out.len() - 2..],
                &[0x61, 12],
                "12 bytes left for GET RESPONSE"
            );
        }
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
        d.sc_hsm.state.exchanged_peer = Some([4; 65]);

        d.clear_session();
        assert!(d.sc_hsm.state.exchanged_peer.is_none());

        assert_eq!(d.active, ActiveProtocol::None);
        assert!(!d.sc_hsm.state.pin_verified && !d.sc_hsm.state.so_pin_verified);
        assert!(d.sc_hsm.state.session_pin.is_none());
        #[cfg(feature = "applet-piv")]
        assert!(!d.piv.state.pin_verified && !d.piv.state.mgmt_key_authenticated);
        assert!(!d.openpgp.state.pw1_verified_sign && !d.openpgp.state.pw3_verified);
    }

    /// Run one APDU through the display hooks and the dispatcher, as
    /// core1's `dispatcher_loop` does.
    fn run(d: &mut Dispatcher, store: &mut crate::storage::NullKeyStore, apdu: &[u8]) -> u16 {
        d.display_begin(apdu);
        let resp = d.dispatch_with_store(apdu, store);
        d.display_end(&resp, store);
        u16::from_be_bytes([resp[resp.len() - 2], resp[resp.len() - 1]])
    }

    #[cfg(feature = "applet-piv")]
    #[test]
    fn display_snapshot_follows_session_auth() {
        use crate::display_snapshot::{auth, OpState};
        use pico2hsm_core::op::{Applet, OpCode};
        let mut slot = core::mem::MaybeUninit::<Dispatcher>::uninit();
        let d = Dispatcher::init_in_place(&mut slot);
        let mut store = crate::storage::NullKeyStore;
        d.note_session(7);
        let mut select = [0u8; 16];
        select[..5].copy_from_slice(&[0x00, 0xA4, 0x04, 0x00, 0x0B]);
        select[5..].copy_from_slice(PIV_AID);
        assert_eq!(run(d, &mut store, &select), 0x9000);
        assert_eq!(d.display_snapshot().session.applet, Applet::Piv);
        assert_eq!(
            d.display_snapshot().activity.op,
            OpCode::None,
            "SELECT is not an op"
        );

        let verify = [
            0x00, 0x20, 0x00, 0x80, 0x08, b'1', b'2', b'3', b'4', b'5', b'6', 0xFF, 0xFF,
        ];
        assert_eq!(run(d, &mut store, &verify), 0x9000);
        let snap = d.display_snapshot();
        assert_ne!(
            snap.session.auth & auth::PIV_PIN,
            0,
            "VERIFY 9000 shows the PIN"
        );
        assert_eq!(snap.activity.op, OpCode::Verify);
        assert_eq!(snap.activity.state, OpState::Done);
        let seq = snap.activity.op_seq;

        // VERIFY P1=FF logs out: PIV_PIN back to 0, and it is no operation.
        run(d, &mut store, &[0x00, 0x20, 0xFF, 0x80, 0x00]);
        let snap = d.display_snapshot();
        assert_eq!(
            snap.session.auth & auth::PIV_PIN,
            0,
            "logout leaves PIV_PIN at 0"
        );
        assert_eq!(snap.activity.op_seq, seq);

        // Verify again, then end the session.
        assert_eq!(run(d, &mut store, &verify), 0x9000);
        d.piv.state.mgmt_key_authenticated = true;
        d.sc_hsm.state.so_pin_verified = true;
        d.openpgp.state.pw3_verified = true;
        assert_ne!(d.display_snapshot().session.auth, 0);
        d.clear_session();
        d.note_session(8);
        let snap = d.display_snapshot();
        assert_eq!(
            snap.session.auth, 0,
            "every auth bit drops with the session"
        );
        assert_eq!(snap.session.oneshot, 0);
        assert_eq!(snap.session.epoch, 8);
        // All 32 bits: 256 silent power cycles later is another session.
        d.note_session(8 + 256);
        assert_eq!(d.display_snapshot().session.epoch, 264);
        assert_eq!(snap.session.applet, Applet::None);
    }

    #[test]
    fn display_counts_user_keys_only() {
        use crate::protocol::sc_hsm::KeyMeta;
        let mut slot = core::mem::MaybeUninit::<Dispatcher>::uninit();
        let d = Dispatcher::init_in_place(&mut slot);
        let key = |key_id: u32, key_type: u8| KeyMeta {
            key_id,
            key_type,
            algo: 0,
            key_flags: 0,
        };
        let index = &mut d.sc_hsm.state.key_index;
        index.push(key(0x01, 2)).unwrap();
        index.push(key(0x02, 0)).unwrap();
        index.push(key(0xFE, 2)).unwrap(); // device identity key
        index.push(key(0xC401, 16)).unwrap(); // a file
        assert_eq!(d.display_snapshot().inventory.keys_hsm, 2);
    }

    #[test]
    fn store_write_failure_is_sticky_until_a_write_succeeds() {
        use crate::display_snapshot::health;
        let mut slot = core::mem::MaybeUninit::<Dispatcher>::uninit();
        let d = Dispatcher::init_in_place(&mut slot);
        let mut store = crate::storage::NullKeyStore;
        d.active = ActiveProtocol::ScHsm;
        let failed =
            |d: &Dispatcher| d.display_snapshot().health.flags & health::STORE_WRITE_FAILED;
        assert!(d.display_begin(&[0x00, 0x46, 0x01, 0x00]));
        d.display_end(&[0x65, 0x81], &mut store);
        assert_ne!(failed(d), 0);
        // A read-only command does not clear it.
        assert!(!d.display_begin(&[0x00, 0xCA, 0x01, 0x00]));
        d.display_end(&[0x90, 0x00], &mut store);
        assert_ne!(failed(d), 0);
        // A successful write does.
        assert!(d.display_begin(&[0x00, 0x46, 0x01, 0x00]));
        d.display_end(&[0x90, 0x00], &mut store);
        assert_eq!(failed(d), 0);
        // Boot health survives a reset.
        d.set_boot_health(health::PROVISIONED);
        d.reset_in_place();
        assert_eq!(d.display_snapshot().health.flags, health::PROVISIONED);
    }

    #[test]
    fn chained_result_and_get_response_keep_the_op() {
        use pico2hsm_core::op::{OpCode, OpResult};
        let mut slot = core::mem::MaybeUninit::<Dispatcher>::uninit();
        let d = Dispatcher::init_in_place(&mut slot);
        let mut store = crate::storage::NullKeyStore;
        d.active = ActiveProtocol::ScHsm;
        assert!(d.display_begin(&[0x80, 0x68, 0x01, 0x70, 0x01, 0xAA]));
        d.display_end(&[0x01, 0x61, 0x10], &mut store);
        let a = d.display_snapshot().activity;
        assert_eq!(
            (a.op, a.result),
            (OpCode::Sign, OpResult::Ok),
            "61xx is success"
        );
        assert_eq!(d.display_snapshot().last_sw, 0x6110);
        // A GET RESPONSE that is itself cut short (61xx) keeps waiting.
        assert!(!d.display_begin(&[0x00, 0xC0, 0x00, 0x00, 0x10]));
        d.display_end(&[0x01, 0x61, 0x08], &mut store);
        assert_eq!(d.display_snapshot().last_sw, 0x6108);
        // The last one carries the final status into the same op.
        assert!(!d.display_begin(&[0x00, 0xC0, 0x00, 0x00, 0x08]));
        d.display_end(&[0x6F, 0x00], &mut store);
        let b = d.display_snapshot();
        assert_eq!(
            (
                b.activity.op_seq,
                b.activity.op,
                b.activity.result,
                b.last_sw
            ),
            (a.op_seq, OpCode::Sign, OpResult::Error, 0x6F00)
        );
        // Another GET RESPONSE has nothing to complete.
        assert!(!d.display_begin(&[0x00, 0xC0, 0x00, 0x00, 0x08]));
        d.display_end(&[0x6A, 0x86], &mut store);
        assert_eq!(d.display_snapshot().last_sw, 0x6F00);
        // Nor does one after an unrelated command broke the sequence.
        assert!(d.display_begin(&[0x80, 0x68, 0x01, 0x70, 0x01, 0xAA]));
        d.display_end(&[0x01, 0x61, 0x10], &mut store);
        assert!(!d.display_begin(&[0x00, 0xCA, 0x01, 0x00]));
        d.display_end(&[0x90, 0x00], &mut store);
        assert!(!d.display_begin(&[0x00, 0xC0, 0x00, 0x00, 0x10]));
        d.display_end(&[0x6F, 0x00], &mut store);
        assert_eq!(d.display_snapshot().activity.result, OpResult::Ok);
    }

    #[test]
    fn select_drops_the_right_to_certify_an_exchanged_peer() {
        let mut slot = core::mem::MaybeUninit::<Dispatcher>::uninit();
        let d = Dispatcher::init_in_place(&mut slot);
        d.sc_hsm.state.exchanged_peer = Some([4; 65]);
        d.sc_hsm.state.so_pin_verified = true;
        let resp = d.select_aid(SC_HSM_AID);
        assert_eq!(resp.sw, SW_OK);
        assert!(d.sc_hsm.state.exchanged_peer.is_none());
        assert!(!d.sc_hsm.state.so_pin_verified);
    }
}
