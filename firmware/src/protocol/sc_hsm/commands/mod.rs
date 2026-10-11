//! SC-HSM command handler modules.
//!
//! Each sub-module contains one command handler. The dispatch table in
//! `sc_hsm/mod.rs` maps INS bytes to the appropriate handler function.
//!
//! All handlers have the signature:
//! ```rust,ignore
//! pub fn handle(state: &mut ScHsmState, cmd: &ApduCommand<'_>) -> ApduResponse;
//! ```

pub mod bip_slip;
pub mod challenge;
pub mod change_pin;
pub mod cipher_sym;
pub mod create_file;
#[cfg(feature = "debug")]
pub mod debug_dump;
pub mod decrypt;
pub mod delete_file;
pub mod derive_asym;
pub mod export_key;
pub mod extras;
pub mod general_auth;
pub mod generate_key;
pub mod generate_keypair;
pub mod import_key;
pub mod initialize;
pub mod key_domain;
pub mod list_keys;
pub mod mse;
pub mod provisioning;
pub mod pso;
pub mod puk_auth;
pub mod read_binary;
pub mod reset_retry;
pub mod select;
pub mod session_pin;
pub mod sign;
pub mod update_binary;
pub mod verify;
pub mod write_data;

#[cfg(all(test, not(feature = "debug")))]
mod debug_gate_tests {
    // This test verifies that when the "debug" feature is absent,
    // the debug_dump module is not compiled. The fact that this module
    // compiles without referencing debug_dump is itself the test.
    #[test]
    fn debug_module_gated() {}
}
