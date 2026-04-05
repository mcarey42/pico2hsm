//! OpenPGP Card command handlers.
//!
//! Each command is implemented in its own sub-module, following the
//! SC-HSM `commands/` pattern.

pub mod authenticate;
pub mod challenge;
pub mod change_pin;
pub mod generate_keypair;
pub mod get_data;
pub mod pso;
pub mod put_data;
pub mod select;
pub mod verify;
