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
pub mod create_file;
pub mod cipher_sym;
pub mod debug_dump;
pub mod decrypt;
pub mod delete_file;
pub mod derive_asym;
pub mod export_key;
pub mod external_auth;
pub mod extras;
pub mod general_auth;
pub mod generate_key;
pub mod generate_keypair;
pub mod import_key;
pub mod initialize;
pub mod key_domain;
pub mod list_keys;
pub mod mse;
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
