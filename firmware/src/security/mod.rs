//! Security hardening module.
//!
//! Implements RP2350-specific security features:
//!
//! # Sub-modules
//! - `otp`          — OTP (One-Time Programmable) fuse read/write/lock (ARM only)
//! - `boot`         — Secure boot configuration and verification (ARM only)
//! - `key_management` — Key object encryption/decryption, DKEK wrap/unwrap
//! - `dkek`         — DKEK share assembly and Noise-like DKEK exchange
//! - `pin`          — PIN management, hashing, retry counter
//! - `anti_glitch`  — Fault injection countermeasures
//! - `zeroize`      — Memory zeroization utilities
//!
//! # Security hardening applied at boot
//! 1. JTAG is disabled (OTP bit JTAG_DISABLE)
//! 2. Secure boot chain is verified (boot manifest hash check)
//! 3. Debug interfaces are locked if not in `debug` feature mode
//! 4. Watchdog is armed
//!
//! # Device-tied encryption
//! The Storage Master Key is derived at every boot via:
//! ```text
//! OTP[0..32] → HKDF-SHA256(salt="pico2hsm-smk", info=device_serial) → SMK[0..32]
//! ```
//! The SMK never leaves the device. All keystore sectors are encrypted
//! under the SMK using AES-256-GCM.

pub mod anti_glitch;
pub mod dkek;
pub mod key_blob;
pub mod key_management;
pub mod key_policy;
pub mod otp_layout;
pub mod pin;
pub mod zeroize;

// OTP and boot modules use embassy_rp PAC — only compile for ARM targets.
#[cfg(target_arch = "arm")]
pub mod boot;
#[cfg(target_arch = "arm")]
pub mod otp;
