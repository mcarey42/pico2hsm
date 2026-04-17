//! LIST KEYS command handler (INS = 0x58).
//!
//! Returns a list of all key objects stored in the keystore. The response
//! contains a sequence of key descriptor TLV structures.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_INCORRECT_P1P2, SW_OK,
};

use crate::protocol::sc_hsm::ScHsmState;

/// INS byte for LIST KEYS.
pub const INS_LIST_KEYS: u8 = 0x58;

/// Handle a LIST KEYS APDU command.
pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse {
    // LIST KEYS does not require PIN — OpenSC's sc_pkcs15emu_sc_hsm_init calls
    // sc_list_files() before any VERIFY, so rejecting here prevents the PKCS#15
    // tree from being built and makes all key objects invisible to pkcs11-tool.

    // P1 and P2 must both be 0x00.
    if cmd.p1 != 0x00 || cmd.p2 != 0x00 {
        return ApduResponse::err(SW_INCORRECT_P1P2);
    }

    // Return 2-byte file ID pairs per key slot: {0xCC, key_id}.
    // sc_hsm_determine_free_id uses KEY_PREFIX=0xCC to find occupied slots.
    // sc_pkcs15emu_sc_hsm_init also scans for 0xCC to call add_prkd per key.
    let mut resp: heapless::Vec<u8, 256> = heapless::Vec::new();

    // Iterate key_index: emit CC xx for non-EfFile entries (crypto keys).
    for meta in &state.key_index {
        // Skip EfFile entries (key_type == 16).
        if meta.key_type == 16 {
            continue;
        }
        let proto_ref = (meta.key_id & 0xFF) as u8;
        // Skip internal reserved slots: device identity key (0xFE) and other
        // internal keys above 0xF0. These must not appear in the user-facing
        // key enumeration or OpenSC will try to load PRKD for them.
        //
        // Slot 0 (device auth sentinel) IS included: OpenSC's
        // sc_hsm_determine_free_id() scans LIST KEYS to find the first free
        // key reference. If slot 0 is hidden, OpenSC assigns keygen P1=0x00,
        // which overwrites the sentinel and then gets filtered — making the
        // generated key invisible.
        if proto_ref >= 0xF0 {
            continue;
        }
        let _ = resp.push(0xCC);
        let _ = resp.push(proto_ref);
    }

    // Emit C4 xx (PRKD) for every key — read_binary generates these
    // dynamically, so they always exist for any key in the keystore.
    // OpenSC's sc_pkcs15emu_sc_hsm_add_prkd needs them in the file list.
    // Include slot 0 so OpenSC can read PRKD for the sentinel too
    // (read_binary returns a valid descriptor for any key in key_index).
    for meta in &state.key_index {
        if meta.key_type == 16 {
            continue;
        }
        let proto_ref = (meta.key_id & 0xFF) as u8;
        if proto_ref >= 0xF0 {
            continue;
        }
        let _ = resp.push(0xC4);
        let _ = resp.push(proto_ref);
    }

    // Expose EE-cert (CE xx) EF entries from key_index.
    // EfFile entries store the file_id high byte in the `algo` field.
    // Only emit entries where algo == 0xCE (EE certificate files).
    for meta in &state.key_index {
        if meta.key_type == 16 && meta.algo == 0xCE {
            let proto_ref = (meta.key_id & 0xFF) as u8;
            let file_id_lo = proto_ref & 0x0F;
            let _ = resp.push(0xCE);
            let _ = resp.push(file_id_lo);
        }
    }

    ApduResponse::ok(&resp)
}
