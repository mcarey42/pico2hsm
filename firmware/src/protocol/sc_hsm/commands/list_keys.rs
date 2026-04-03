//! LIST KEYS command handler (INS = 0x58, P2 = 0x00).
//!
//! Returns a list of all key objects stored in the keystore. The response
//! contains a sequence of key descriptor TLV structures.
//!
//! Note: INS=0x58 is shared with IMPORT KEY; the P2 byte distinguishes them:
//! - P2=0x00: List all keys → this handler
//! - P2=0x93: Import key → import_key handler

use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_OK};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for LIST KEYS (shared with IMPORT KEY).
pub const INS_LIST_KEYS: u8 = 0x58;

/// P1 value that distinguishes LIST KEYS from IMPORT KEY.
pub const P1_LIST: u8 = 0x00;

/// Handle a LIST KEYS APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // LIST KEYS does not require PIN — OpenSC's sc_pkcs15emu_sc_hsm_init calls
    // sc_list_files() before any VERIFY, so rejecting here prevents the PKCS#15
    // tree from being built and makes all key objects invisible to pkcs11-tool.

    // Return 2-byte file ID pairs per key slot: {0xCC, key_id}.
    // sc_hsm_determine_free_id uses KEY_PREFIX=0xCC to find occupied slots.
    // sc_pkcs15emu_sc_hsm_init also scans for 0xCC to call add_prkd per key.
    let mut resp: heapless::Vec<u8, 256> = heapless::Vec::new();
    for key in &state.keys {
        let _ = resp.push(0xCC);
        let _ = resp.push(key.key_id);
    }
    #[cfg(feature = "rsa")]
    for key in &state.rsa_keys {
        let _ = resp.push(0xCC);
        let _ = resp.push(key.key_id);
    }
    // Also expose PRKD (C4 xx) and EE-cert (CE xx) EF entries so that
    // SELECT by those file IDs succeeds and sc_pkcs15emu_sc_hsm_add_prkd
    // can read them via read_file().
    for ef in &state.ef_files {
        let hi = (ef.file_id >> 8) as u8;
        if hi == 0xC4 || hi == 0xCE {
            let _ = resp.push(hi);
            let _ = resp.push((ef.file_id & 0xFF) as u8);
        }
    }
    ApduResponse::ok(&resp)
}
