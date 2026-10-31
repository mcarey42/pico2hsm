//! HSM protocol implementations.
//!
//! This module contains one sub-module per supported card protocol. Each
//! sub-module implements the `pico2hsm_core::HsmProtocol` trait.
//!
//! # Sub-modules
//! - `sc_hsm`   — SC-HSM 2 (primary, fully implemented)
//! - `piv`      — NIST SP 800-73-4 PIV (a stub without `applet-piv`)
//! - `openpgp`  — OpenPGP Card 3.4 (compiled only with `applet-openpgp`)

#[cfg(feature = "applet-openpgp")]
pub mod openpgp;
pub mod piv;
pub mod sc_hsm;
