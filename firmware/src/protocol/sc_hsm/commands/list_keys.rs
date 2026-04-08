//! LIST KEYS command handler (INS = 0x58).
//!
//! Returns a list of all key objects stored in the keystore. The response
//! contains a sequence of key descriptor TLV structures.

use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_OK};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for LIST KEYS.
pub const INS_LIST_KEYS: u8 = 0x58;

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
        let proto_ref = (key.key_id & 0xFF) as u8;
        // Skip internal reserved slots (>= 0xF0): device identity key (0xFE),
        // device auth sentinel at 0xFF, etc. These must not appear in the
        // user-facing key enumeration or OpenSC will try to load PRKD for them.
        if proto_ref >= 0xF0 {
            continue;
        }
        let _ = resp.push(0xCC);
        let _ = resp.push(proto_ref);
    }
    #[cfg(feature = "rsa")]
    for key in &state.rsa_keys {
        let _ = resp.push(0xCC);
        let _ = resp.push((key.key_id & 0xFF) as u8); // proto_ref byte
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
