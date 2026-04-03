//! DKEK (Device Key Encryption Key) management.
//!
//! The DKEK is used to wrap key objects for HSM-to-HSM backup and restore.
//! It is NOT used for on-device storage encryption (which uses the SMK
//! derived from OTP).
//!
//! # DKEK derivation
//! The DKEK is a 32-byte key established via a Shamir Secret Sharing
//! ceremony or by importing individual DKEK shares:
//! ```text
//! DKEK = XOR(share_1, share_2, ..., share_n)
//! ```
//! Each share is 32 random bytes. The DKEK is only reconstructed in RAM
//! during a key import/export operation and is never stored on flash.
//!
//! # DKEK exchange
//! Two HSM devices can exchange DKEK shares via the Noise_XX protocol
//! over USB (local) or TCP (network). See `exchange.rs` for details.
//!
//! # Sub-modules
//! - `exchange` — Noise_XX DKEK share exchange over USB and TCP

pub mod exchange;

use pico2hsm_core::error::HsmError;
use zeroize::Zeroize;

/// Maximum number of DKEK shares.
pub const MAX_SHARES: usize = 16;

/// DKEK state held in RAM.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Dkek {
    /// Reconstructed DKEK (32 bytes), present only when shares have been loaded.
    key: Option<[u8; 32]>,
    /// Number of shares loaded so far.
    shares_loaded: u8,
    /// Threshold (minimum shares required to reconstruct).
    threshold: u8,
}

impl Dkek {
    /// Create a new empty DKEK state.
    pub fn new(threshold: u8) -> Self {
        Dkek { key: None, shares_loaded: 0, threshold }
    }

    /// Load one DKEK share (XOR accumulation).
    ///
    /// When `shares_loaded` reaches `threshold`, the DKEK is considered
    /// established and key wrap/unwrap operations are permitted.
    pub fn load_share(&mut self, share: &[u8; 32]) -> Result<(), HsmError> {
        // TODO: implement — XOR share into accumulated key material
        self.shares_loaded += 1;
        Ok(())
    }

    /// Returns `true` if enough shares have been loaded.
    pub fn is_established(&self) -> bool {
        self.shares_loaded >= self.threshold
    }

    /// Wrap a plaintext key blob under the DKEK (AES-256-CBC + CMAC).
    ///
    /// Returns the wrapped blob suitable for EXPORT KEY response data.
    pub fn wrap(&self, _plaintext: &[u8]) -> Result<heapless::Vec<u8, 2080>, HsmError> {
        if !self.is_established() {
            return Err(HsmError::Auth(pico2hsm_core::error::AuthError::NotAuthenticated));
        }
        // TODO: implement — AES-256-CBC encrypt + CMAC tag
        Err(HsmError::NotSupported)
    }

    /// Unwrap a key blob wrapped under the DKEK.
    ///
    /// Verifies the CMAC tag before decrypting. Returns the plaintext key material.
    pub fn unwrap(&self, _blob: &[u8]) -> Result<heapless::Vec<u8, 2048>, HsmError> {
        if !self.is_established() {
            return Err(HsmError::Auth(pico2hsm_core::error::AuthError::NotAuthenticated));
        }
        // TODO: implement — CMAC verify + AES-256-CBC decrypt
        Err(HsmError::NotSupported)
    }
}
