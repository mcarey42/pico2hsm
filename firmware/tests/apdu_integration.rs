//! SC-HSM APDU integration tests.
//!
//! These tests exercise the full APDU dispatch pipeline without hardware.
//! The `Dispatcher` is driven directly with raw APDU bytes. No embassy-rp,
//! embassy-executor or embassy-time is imported; all tests run on x86_64.

use pico2hsm_firmware::apdu::Dispatcher;

// ---------------------------------------------------------------------------
// APDU builder helpers
// ---------------------------------------------------------------------------

/// Build a Case 3S APDU (CLA INS P1 P2 Lc data).
fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 1 + data.len());
    v.push(cla);
    v.push(ins);
    v.push(p1);
    v.push(p2);
    if !data.is_empty() {
        v.push(data.len() as u8);
        v.extend_from_slice(data);
    }
    v
}

/// Build a Case 4S APDU (CLA INS P1 P2 Lc data Le).
fn apdu_le(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: u8) -> Vec<u8> {
    let mut v = apdu(cla, ins, p1, p2, data);
    v.push(le);
    v
}

/// Build a Case 1 APDU (no data, no Le).
fn apdu_bare(cla: u8, ins: u8, p1: u8, p2: u8) -> Vec<u8> {
    vec![cla, ins, p1, p2]
}

/// Build a Case 2 APDU (no data, with Le).
fn apdu_le_only(cla: u8, ins: u8, p1: u8, p2: u8, le: u8) -> Vec<u8> {
    vec![cla, ins, p1, p2, le]
}

/// Extract the 16-bit status word from the last 2 bytes of a response.
fn sw(resp: &[u8]) -> u16 {
    assert!(
        resp.len() >= 2,
        "response too short to contain SW: {:?}",
        resp
    );
    let n = resp.len();
    ((resp[n - 2] as u16) << 8) | (resp[n - 1] as u16)
}

/// Extract the data field from a response (everything except the last 2 SW bytes).
fn data_of(resp: &[u8]) -> &[u8] {
    assert!(resp.len() >= 2);
    &resp[..resp.len() - 2]
}

// ---------------------------------------------------------------------------
// AID constants
// ---------------------------------------------------------------------------

/// SmartCard-HSM AID  `E8 2B 06 01 04 01 81 C3 1F 02 01`.
const SC_HSM_AID: &[u8] = &[
    0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01,
];

/// PIV AID.
const PIV_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

/// A completely unknown AID.
const UNKNOWN_AID: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x01];

// ---------------------------------------------------------------------------
// INS constants (ISO 7816-4 / SC-HSM)
// ---------------------------------------------------------------------------
const INS_SELECT: u8 = 0xA4;
const INS_VERIFY: u8 = 0x20;
const INS_INITIALIZE: u8 = 0x50;
const INS_MSE: u8 = 0x22;
const INS_GET_CHALLENGE: u8 = 0x84;
const INS_READ_BINARY: u8 = 0xB0;
const INS_GENERATE_KEYPAIR: u8 = 0x46;
const INS_LIST_KEYS: u8 = 0x58;

// ---------------------------------------------------------------------------
// Shared helper: select SC-HSM and return the Dispatcher.
// ---------------------------------------------------------------------------

fn new_dispatcher_with_sc_hsm_selected() -> Dispatcher {
    let mut d = Dispatcher::new();
    let sel = apdu(0x00, INS_SELECT, 0x04, 0x00, SC_HSM_AID);
    let r = d.dispatch(&sel);
    assert_eq!(sw(&r), 0x9000, "SELECT SC-HSM should return 9000");
    d
}

/// Build a minimal valid INITIALIZE payload.
/// TLV per OpenSC sc-hsm-tool convention:
///   82 08 <8-byte init code>   -- mandatory init code (SO-PIN), exactly 8 bytes
///   81 LL <user-pin>           -- user PIN
fn initialize_data(init_code: &[u8], user_pin: &[u8]) -> Vec<u8> {
    assert_eq!(init_code.len(), 8, "init_code must be exactly 8 bytes");
    let mut v = Vec::new();
    // Tag 0x82: init code (exactly 8 bytes)
    v.push(0x82);
    v.push(init_code.len() as u8);
    v.extend_from_slice(init_code);
    // Tag 0x81: User PIN
    v.push(0x81);
    v.push(user_pin.len() as u8);
    v.extend_from_slice(user_pin);
    v
}

// ---------------------------------------------------------------------------
// Tests — SELECT AID
// ---------------------------------------------------------------------------

#[test]
fn test_select_sc_hsm_aid() {
    let mut d = Dispatcher::new();
    let sel = apdu(0x00, INS_SELECT, 0x04, 0x00, SC_HSM_AID);
    let r = d.dispatch(&sel);

    assert_eq!(sw(&r), 0x9000, "SELECT SC-HSM must return 9000");
    let body = data_of(&r);
    // FCI template starts with tag 0x6F (ISO 7816-4 §7.1.1)
    assert!(!body.is_empty(), "FCI body must be non-empty");
    assert_eq!(body[0], 0x6F, "FCI must start with tag 0x6F");
}

#[test]
fn test_select_sc_hsm_fci_contains_aid() {
    let mut d = Dispatcher::new();
    let sel = apdu(0x00, INS_SELECT, 0x04, 0x00, SC_HSM_AID);
    let r = d.dispatch(&sel);

    let body = data_of(&r);
    // The AID bytes should appear somewhere in the FCI.
    let aid_bytes = SC_HSM_AID;
    let found = body.windows(aid_bytes.len()).any(|w| w == aid_bytes);
    assert!(found, "FCI must embed the SC-HSM AID bytes");
}

#[test]
fn test_select_unknown_aid() {
    let mut d = Dispatcher::new();
    let sel = apdu(0x00, INS_SELECT, 0x04, 0x00, UNKNOWN_AID);
    let r = d.dispatch(&sel);

    // SW_FILE_NOT_FOUND = 0x6A82
    assert_eq!(
        sw(&r),
        0x6A82,
        "Unknown AID must return 6A82 (FILE NOT FOUND)"
    );
}

#[test]
fn test_select_piv_aid() {
    let mut d = Dispatcher::new();
    let sel = apdu(0x00, INS_SELECT, 0x04, 0x00, PIV_AID);
    let r = d.dispatch(&sel);

    // PIV stub returns 9000 with empty data
    assert_eq!(sw(&r), 0x9000, "PIV AID SELECT must return 9000");
}

#[test]
fn test_no_protocol_before_select() {
    // Fresh dispatcher with no SELECT issued yet — any INS should return 6D00
    let mut d = Dispatcher::new();
    let cmd = apdu_bare(0x00, INS_VERIFY, 0x00, 0x81);
    let r = d.dispatch(&cmd);

    // SW_INS_NOT_SUPPORTED = 0x6D00
    assert_eq!(
        sw(&r),
        0x6D00,
        "Command before SELECT must return 6D00 (INS NOT SUPPORTED)"
    );
}

// ---------------------------------------------------------------------------
// Tests — INITIALIZE
// ---------------------------------------------------------------------------

#[test]
fn test_initialize_basic() {
    let mut d = new_dispatcher_with_sc_hsm_selected();
    let data = initialize_data(b"sopin100", b"userpin1");
    let cmd = apdu(0x80, INS_INITIALIZE, 0x00, 0x00, &data);
    let r = d.dispatch(&cmd);

    assert_eq!(
        sw(&r),
        0x9000,
        "INITIALIZE with valid SO-PIN must return 9000"
    );
}

#[test]
fn test_initialize_with_label() {
    let mut d = new_dispatcher_with_sc_hsm_selected();
    let mut data = initialize_data(b"sopin100", b"userpin1");
    // Tag 0x82: label "TestHSM"
    data.push(0x82);
    data.push(7);
    data.extend_from_slice(b"TestHSM");

    let cmd = apdu(0x80, INS_INITIALIZE, 0x00, 0x00, &data);
    let r = d.dispatch(&cmd);

    assert_eq!(sw(&r), 0x9000, "INITIALIZE with label must return 9000");
}

#[test]
fn test_initialize_missing_so_pin_fails() {
    let mut d = new_dispatcher_with_sc_hsm_selected();
    // No tag 0x82 — missing init code
    let data: Vec<u8> = vec![0x81, 0x08, b'u', b's', b'e', b'r', b'p', b'i', b'n', b'1'];
    let cmd = apdu(0x80, INS_INITIALIZE, 0x00, 0x00, &data);
    let r = d.dispatch(&cmd);

    // SW_WRONG_DATA = 0x6A80
    assert_eq!(
        sw(&r),
        0x6A80,
        "INITIALIZE without init code (tag 0x82) must return 6A80 (WRONG DATA)"
    );
}

#[test]
fn test_initialize_so_pin_too_short_fails() {
    let mut d = new_dispatcher_with_sc_hsm_selected();
    // Init code (tag 0x82) with wrong length: must be exactly 8 bytes
    let data: Vec<u8> = vec![0x82, 0x04, 1, 2, 3, 4];
    let cmd = apdu(0x80, INS_INITIALIZE, 0x00, 0x00, &data);
    let r = d.dispatch(&cmd);

    // SW_WRONG_LENGTH = 0x6700
    assert_eq!(
        sw(&r),
        0x6700,
        "INITIALIZE with wrong-length init code must return 6700"
    );
}

// ---------------------------------------------------------------------------
// Tests — VERIFY
// ---------------------------------------------------------------------------

/// Initialize and return a dispatcher that is ready for VERIFY tests.
fn initialized_dispatcher() -> Dispatcher {
    let mut d = new_dispatcher_with_sc_hsm_selected();
    let data = initialize_data(b"sopin100", b"userpin1");
    let cmd = apdu(0x80, INS_INITIALIZE, 0x00, 0x00, &data);
    let r = d.dispatch(&cmd);
    assert_eq!(sw(&r), 0x9000);
    d
}

#[test]
fn test_verify_correct_pin() {
    let mut d = initialized_dispatcher();
    // VERIFY User PIN (P2=0x81)
    let cmd = apdu(0x00, INS_VERIFY, 0x00, 0x81, b"userpin1");
    let r = d.dispatch(&cmd);

    assert_eq!(sw(&r), 0x9000, "Correct PIN must return 9000");
}

#[test]
fn test_verify_wrong_pin() {
    let mut d = initialized_dispatcher();
    let cmd = apdu(0x00, INS_VERIFY, 0x00, 0x81, b"wrong1");
    let r = d.dispatch(&cmd);

    // SW 0x63Cn — wrong PIN with n retries remaining
    let status = sw(&r);
    assert_eq!(
        status & 0xFFF0,
        0x63C0,
        "Wrong PIN must return 63Cx, got {:#06x}",
        status
    );
    // Initial retry count is 3; first wrong attempt → 2 remaining
    assert_eq!(
        status & 0x000F,
        2,
        "Retries remaining should be 2 after first wrong PIN"
    );
}

#[test]
fn test_verify_pin_query_retry_count() {
    let mut d = initialized_dispatcher();
    // VERIFY with empty data = query retry count
    let cmd = apdu_bare(0x00, INS_VERIFY, 0x00, 0x81);
    let r = d.dispatch(&cmd);

    let status = sw(&r);
    // Should return 63C3 (3 retries remaining, no PIN submitted)
    assert_eq!(
        status & 0xFFF0,
        0x63C0,
        "Retry count query should return 63Cx"
    );
    assert_eq!(status & 0x000F, 3, "Initial retry count should be 3");
}

#[test]
fn test_pin_lockout() {
    let mut d = initialized_dispatcher();
    let wrong = apdu(0x00, INS_VERIFY, 0x00, 0x81, b"wrong1");

    // Three wrong PINs exhaust all retries
    for i in 0..3 {
        let r = d.dispatch(&wrong);
        let _ = sw(&r); // consume, don't assert mid-loop
        let _ = i;
    }

    // Fourth attempt: PIN should now be blocked → 6983
    let r = d.dispatch(&wrong);
    assert_eq!(
        sw(&r),
        0x6983,
        "PIN after lockout must return 6983 (AUTH BLOCKED)"
    );
}

#[test]
fn test_verify_no_pin_stored_returns_error() {
    // SELECT but do NOT initialize — user_pin_hash is None
    let mut d = new_dispatcher_with_sc_hsm_selected();
    let cmd = apdu(0x00, INS_VERIFY, 0x00, 0x81, b"anypin");
    let r = d.dispatch(&cmd);

    // SW_SECURITY_STATUS = 0x6982 — no PIN stored
    assert_eq!(
        sw(&r),
        0x6982,
        "VERIFY before INITIALIZE must return 6982 (SECURITY STATUS)"
    );
}

// ---------------------------------------------------------------------------
// Tests — MSE SET
// ---------------------------------------------------------------------------

#[test]
fn test_mse_set_computation() {
    let mut d = initialized_dispatcher();

    // Verify PIN first so we can test MSE in an authenticated context
    let ver = apdu(0x00, INS_VERIFY, 0x00, 0x81, b"userpin1");
    let _ = d.dispatch(&ver);

    // MSE SET for Computation: P1=0x41, P2=0xA4
    // Tag 0x84: key reference (key_id = 0x01), Tag 0x80: algo (0x13 = ECDSA-P256)
    let mse_data: Vec<u8> = vec![0x84, 0x01, 0x01, 0x80, 0x01, 0x13];
    let cmd = apdu(0x00, INS_MSE, 0x41, 0xA4, &mse_data);
    let r = d.dispatch(&cmd);

    assert_eq!(sw(&r), 0x9000, "MSE SET must return 9000");
}

#[test]
fn test_mse_set_decipherment() {
    let mut d = initialized_dispatcher();

    // MSE SET for Decipherment: P1=0x41, P2=0xB8
    let mse_data: Vec<u8> = vec![0x84, 0x01, 0x02, 0x80, 0x01, 0x23];
    let cmd = apdu(0x00, INS_MSE, 0x41, 0xB8, &mse_data);
    let r = d.dispatch(&cmd);

    assert_eq!(sw(&r), 0x9000, "MSE SET Decipherment must return 9000");
}

#[test]
fn test_mse_restore_default() {
    let mut d = initialized_dispatcher();

    // MSE RESTORE SE#3: P1=0xF3, P2=0x03 — resets current SE
    let cmd = apdu_bare(0x00, INS_MSE, 0xF3, 0x03);
    let r = d.dispatch(&cmd);

    assert_eq!(sw(&r), 0x9000, "MSE RESTORE must return 9000");
}

#[test]
fn test_mse_empty_data_fails() {
    let mut d = initialized_dispatcher();

    // MSE SET with no TLV data — neither key_id nor algo present
    let cmd = apdu(0x00, INS_MSE, 0x41, 0xA4, &[]);
    let r = d.dispatch(&cmd);

    // SW_WRONG_DATA = 0x6A80
    assert_eq!(
        sw(&r),
        0x6A80,
        "MSE with empty data must return 6A80 (WRONG DATA)"
    );
}

// ---------------------------------------------------------------------------
// Tests — GET CHALLENGE
// ---------------------------------------------------------------------------

#[test]
fn test_get_challenge_default_length() {
    let mut d = initialized_dispatcher();

    // GET CHALLENGE with no Le byte — default 8 bytes
    let cmd = apdu_bare(0x00, INS_GET_CHALLENGE, 0x00, 0x00);
    let r = d.dispatch(&cmd);

    assert_eq!(sw(&r), 0x9000, "GET CHALLENGE must return 9000");
    let body = data_of(&r);
    assert_eq!(
        body.len(),
        8,
        "Default GET CHALLENGE must return exactly 8 bytes"
    );
}

#[test]
fn test_get_challenge_with_le() {
    let mut d = initialized_dispatcher();

    // GET CHALLENGE with Le=16 — request 16 bytes
    let cmd = apdu_le_only(0x00, INS_GET_CHALLENGE, 0x00, 0x00, 16);
    let r = d.dispatch(&cmd);

    assert_eq!(sw(&r), 0x9000, "GET CHALLENGE Le=16 must return 9000");
    let body = data_of(&r);
    assert_eq!(
        body.len(),
        16,
        "GET CHALLENGE Le=16 must return exactly 16 bytes"
    );
}

#[test]
fn test_get_challenge_data_is_sequential_placeholder() {
    // The current implementation fills bytes with i & 0xFF.
    let mut d = initialized_dispatcher();
    let cmd = apdu_le_only(0x00, INS_GET_CHALLENGE, 0x00, 0x00, 8);
    let r = d.dispatch(&cmd);

    let body = data_of(&r);
    for (i, &b) in body.iter().enumerate() {
        assert_eq!(
            b,
            (i & 0xFF) as u8,
            "Challenge byte {i} should be {i} (deterministic placeholder)"
        );
    }
}

// ---------------------------------------------------------------------------
// Tests — READ BINARY
// ---------------------------------------------------------------------------

#[test]
fn test_read_binary_ef_dir() {
    let mut d = initialized_dispatcher();

    // READ BINARY EF.DIR  P1=0x2F, P2=0x00
    let cmd = apdu_le_only(0x00, INS_READ_BINARY, 0x2F, 0x00, 0x00);
    let r = d.dispatch(&cmd);

    assert_eq!(sw(&r), 0x9000, "READ BINARY EF.DIR must return 9000");
    let body = data_of(&r);
    assert!(!body.is_empty(), "EF.DIR data must be non-empty");
}

#[test]
fn test_read_binary_ef_token_info() {
    let mut d = initialized_dispatcher();

    // READ BINARY TokenInfo  P1=0x50, P2=0x32
    let cmd = apdu_le_only(0x00, INS_READ_BINARY, 0x50, 0x32, 0x00);
    let r = d.dispatch(&cmd);

    assert_eq!(sw(&r), 0x9000, "READ BINARY TokenInfo must return 9000");
    let body = data_of(&r);
    assert!(!body.is_empty(), "TokenInfo data must be non-empty");
}

#[test]
fn test_read_binary_ef_odf() {
    let mut d = initialized_dispatcher();

    // READ BINARY ODF  P1=0x50, P2=0x31
    let cmd = apdu_le_only(0x00, INS_READ_BINARY, 0x50, 0x31, 0x00);
    let r = d.dispatch(&cmd);

    assert_eq!(sw(&r), 0x9000, "READ BINARY ODF must return 9000");
}

#[test]
fn test_read_binary_unknown_ef() {
    let mut d = initialized_dispatcher();

    // READ BINARY with unknown file ID 0xFF 0xEE
    let cmd = apdu_le_only(0x00, INS_READ_BINARY, 0xFF, 0xEE, 0x00);
    let r = d.dispatch(&cmd);

    assert_eq!(
        sw(&r),
        0x6A82,
        "READ BINARY unknown EF must return 6A82 (FILE NOT FOUND)"
    );
}

#[test]
fn test_read_binary_short_ef_id_not_supported() {
    let mut d = initialized_dispatcher();

    // P1 bit7 = 1 means short EF ID — not supported → 6A82
    let cmd = apdu_le_only(0x00, INS_READ_BINARY, 0x80, 0x00, 0x00);
    let r = d.dispatch(&cmd);

    assert_eq!(
        sw(&r),
        0x6A82,
        "Short EF ID read must return 6A82 (FILE NOT FOUND)"
    );
}

// ---------------------------------------------------------------------------
// Tests — GENERATE KEY PAIR (requires PIN, currently returns 6D00 stub)
// ---------------------------------------------------------------------------

#[test]
fn test_command_requires_pin() {
    let mut d = initialized_dispatcher();

    // GENERATE KEY PAIR without PIN → 6982 (security status not satisfied)
    // P1=0x01 (key_id), P2=0x00, data = minimal CRT TLV
    let crt: Vec<u8> = vec![0x41, 0x01, 0x13]; // Tag 0x41: algo ECDSA-P256
    let cmd = apdu(0x00, INS_GENERATE_KEYPAIR, 0x01, 0x00, &crt);
    let r = d.dispatch(&cmd);

    assert_eq!(
        sw(&r),
        0x6982,
        "GENERATE KEY PAIR without PIN must return 6982"
    );
}

#[test]
fn test_generate_keypair_after_verify_returns_stub() {
    let mut d = initialized_dispatcher();

    // Verify PIN first
    let ver = apdu(0x00, INS_VERIFY, 0x00, 0x81, b"userpin1");
    let vr = d.dispatch(&ver);
    assert_eq!(sw(&vr), 0x9000);

    // GENERATE KEY PAIR — stub returns 6D00 (not yet implemented)
    let crt: Vec<u8> = vec![0x41, 0x01, 0x13];
    let cmd = apdu(0x00, INS_GENERATE_KEYPAIR, 0x01, 0x00, &crt);
    let r = d.dispatch(&cmd);

    // Current implementation is a stub — returns 6D00 (INS_NOT_SUPPORTED)
    // A future implementation will return 9000 with public key data.
    let status = sw(&r);
    assert!(
        status == 0x9000 || status == 0x6D00,
        "GENERATE KEY PAIR after PIN must return 9000 (done) or 6D00 (stub), got {:#06x}",
        status
    );
}

// ---------------------------------------------------------------------------
// Tests — LIST KEYS
// ---------------------------------------------------------------------------

#[test]
fn test_list_keys_without_pin_succeeds() {
    // LIST KEYS does NOT require a PIN. OpenSC's sc_pkcs15emu_sc_hsm_init
    // calls sc_list_files() before VERIFY to build the PKCS#15 tree, so
    // rejecting without PIN would make all keys invisible to pkcs11-tool.
    let mut d = initialized_dispatcher();

    let cmd = apdu_bare(0x00, INS_LIST_KEYS, 0x00, 0x00);
    let r = d.dispatch(&cmd);

    assert_eq!(
        sw(&r),
        0x9000,
        "LIST KEYS without PIN must return 9000 (no auth required)"
    );
}

#[test]
fn test_list_keys_after_init_shows_dev_auth_sentinel() {
    // After INITIALIZE, the device-auth sentinel (CC 00) is present so that
    // sc_hsm_determine_free_id skips slot 0 and assigns user keys from slot 1.
    let mut d = initialized_dispatcher();

    // Verify User PIN
    let ver = apdu(0x00, INS_VERIFY, 0x00, 0x81, b"userpin1");
    let vr = d.dispatch(&ver);
    assert_eq!(sw(&vr), 0x9000, "VERIFY must succeed before LIST KEYS");

    // LIST KEYS — the device-auth sentinel CC 00 (so OpenSC's free-slot search
    // skips slot 0), and no PRKD for it (it is not a usable key)
    let cmd = apdu_bare(0x00, INS_LIST_KEYS, 0x00, 0x00);
    let r = d.dispatch(&cmd);

    assert_eq!(sw(&r), 0x9000, "LIST KEYS must return 9000");
    let d_bytes = data_of(&r);
    assert_eq!(
        d_bytes,
        &[0xCC, 0x00],
        "LIST KEYS after init must contain the device-auth sentinel CC 00 and no PRKD for it"
    );
}

// ---------------------------------------------------------------------------
// Tests — Full INITIALIZE → VERIFY → READ pipeline
// ---------------------------------------------------------------------------

#[test]
fn test_full_init_verify_read_pipeline() {
    let mut d = new_dispatcher_with_sc_hsm_selected();

    // Step 1: INITIALIZE
    let init_data = initialize_data(b"sopin100", b"userpin1");
    let init_cmd = apdu(0x80, INS_INITIALIZE, 0x00, 0x00, &init_data);
    let ir = d.dispatch(&init_cmd);
    assert_eq!(sw(&ir), 0x9000, "INITIALIZE step failed");

    // Step 2: VERIFY User PIN
    let ver_cmd = apdu(0x00, INS_VERIFY, 0x00, 0x81, b"userpin1");
    let vr = d.dispatch(&ver_cmd);
    assert_eq!(sw(&vr), 0x9000, "VERIFY step failed");

    // Step 3: READ BINARY EF.DIR
    let read_cmd = apdu_le_only(0x00, INS_READ_BINARY, 0x2F, 0x00, 0x00);
    let rr = d.dispatch(&read_cmd);
    assert_eq!(sw(&rr), 0x9000, "READ BINARY after auth failed");
    assert!(!data_of(&rr).is_empty(), "EF.DIR should have data");
}

#[test]
fn test_select_unknown_aid_does_not_deactivate_current_protocol() {
    // Per the dispatcher implementation: a failed SELECT (unknown AID → 6A82)
    // does NOT change self.active.  The previously selected protocol remains
    // active, so commands continue to be forwarded to it.
    let mut d = new_dispatcher_with_sc_hsm_selected();

    // SELECT unknown AID — fails but leaves ScHsm active
    let unknown = apdu(0x00, INS_SELECT, 0x04, 0x00, UNKNOWN_AID);
    let r = d.dispatch(&unknown);
    assert_eq!(sw(&r), 0x6A82, "Unknown AID must return 6A82");

    // READ BINARY should still be routed to ScHsm (not return 6D00)
    let read_cmd = apdu_le_only(0x00, INS_READ_BINARY, 0x2F, 0x00, 0x00);
    let r2 = d.dispatch(&read_cmd);
    // ScHsm handles READ BINARY 0x2F00 → EF.DIR (9000), not 6D00
    assert_ne!(
        sw(&r2),
        0x6D00,
        "After failed SELECT, previously active ScHsm must still handle commands"
    );
}

#[test]
fn test_reselect_sc_hsm_succeeds() {
    // The Dispatcher routes all commands through a single ScHsm instance.
    // Re-selecting the same AID simply returns the FCI again; it does not
    // reinitialise the ScHsm instance or clear session state.
    let mut d = new_dispatcher_with_sc_hsm_selected();

    let init_data = initialize_data(b"sopin100", b"userpin1");
    d.dispatch(&apdu(0x80, INS_INITIALIZE, 0x00, 0x00, &init_data));
    d.dispatch(&apdu(0x00, INS_VERIFY, 0x00, 0x81, b"userpin1"));

    // Re-SELECT SC-HSM — must succeed and return FCI
    let sel = apdu(0x00, INS_SELECT, 0x04, 0x00, SC_HSM_AID);
    let r = d.dispatch(&sel);
    assert_eq!(sw(&r), 0x9000, "Re-SELECT SC-HSM must return 9000 with FCI");
    let body = data_of(&r);
    assert!(!body.is_empty(), "Re-SELECT must return FCI body");
    assert_eq!(body[0], 0x6F, "Re-SELECT FCI must start with 0x6F");
}

// ---------------------------------------------------------------------------
// Tests — Malformed APDU
// ---------------------------------------------------------------------------

#[test]
fn test_malformed_apdu_too_short() {
    let mut d = new_dispatcher_with_sc_hsm_selected();

    // Only 2 bytes — too short to parse
    let r = d.dispatch(&[0x00, 0xA4]);

    // SW_INS_NOT_SUPPORTED is returned on parse failure
    assert_eq!(sw(&r), 0x6D00, "Malformed APDU must return 6D00");
}

#[test]
fn test_unknown_ins_after_select() {
    let mut d = new_dispatcher_with_sc_hsm_selected();

    // INS 0x99 — completely undefined
    let cmd = apdu_bare(0x00, 0x99, 0x00, 0x00);
    let r = d.dispatch(&cmd);

    assert_eq!(
        sw(&r),
        0x6D00,
        "Unknown INS after SELECT must return 6D00 (INS NOT SUPPORTED)"
    );
}
