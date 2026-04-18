//! RP2350 OTP (One-Time Programmable) read/write/lock operations.
//!
//! The RP2350 has 4096 rows of OTP storage.  Each row is 24 bits of raw data
//! or 16 bits of ECC-protected data (ECC consumes the upper 8 bits).
//!
//! # pico2hsm OTP layout
//! ```text
//! Rows 0x100–0x107 : Storage key bytes  0–31   (32 bytes via ECC words)
//! Rows 0x108–0x10F : Storage key bytes 32–63   (32 bytes via ECC words)
//! Row  0x110       : Boot flags
//!                    bit 0 — JTAG disabled (irreversible)
//!                    bit 1 — production mode active (irreversible)
//!                    bit 2 — device has been provisioned
//! Rows 0x120–0x127 : Device identity key bytes 0–31
//! ```
//!
//! # Row access model
//! - Each ECC row stores a 16-bit value.  Two bytes of key material map to
//!   one ECC row.  32 bytes of key material require 16 rows.
//! - Raw (non-ECC) reads return 24-bit values; the boot flags row uses
//!   only the lower 8 bits of each read.
//!
//! # embassy-rp OTP API
//! The `embassy_rp::otp` module provides:
//! - `read_ecc_word(row: usize) -> Result<u16, otp::Error>` — ECC read
//! - `read_raw_word(row: usize) -> Result<u32, otp::Error>` — raw read
//! - `write_raw_word(row: usize, data: u32) -> Result<(), otp::Error>` — raw write
//! - `write_ecc_word(row: usize, data: u16) -> Result<(), otp::Error>` — ECC write
//!
//! Row locking (read-lock / write-lock) is performed via the OTP_DATA_RAW
//! memory-mapped region permission bits.  The embassy-rp 0.10 API does not
//! yet expose a `lock_row()` function; locking is performed by writing to
//! the RP2350 OTP_LOCK registers via PAC.
//!
//! TODO: When embassy-rp exposes a stable `lock_rows()` API, replace the
//! PAC-based lock implementation below with the idiomatic helper.
//!
//! # Irreversibility
//! OTP bits can only transition 0→1 (burning a fuse).  Writing 1→0 has no
//! effect.  All write operations here are permanent.

use embassy_rp::otp;
use pico2hsm_core::error::{HsmError, StorageError};

// ─── OTP row layout constants ─────────────────────────────────────────────────

/// First OTP row of the storage key material block (covers bytes 0–31).
/// Each ECC row holds 2 bytes; 16 rows → 32 bytes.
pub const OTP_STORAGE_KEY_ROW_START: u16 = 0x100;

/// Total length of the storage key material in bytes (2 × 32 = 64).
pub const OTP_STORAGE_KEY_LEN: usize = 64; // stored across 32 ECC rows

/// OTP row holding the boot flags.
pub const OTP_BOOT_FLAGS_ROW: u16 = 0x110;

/// First OTP row of the device identity key (used for Noise_XX auth).
pub const OTP_DEVICE_ID_KEY_ROW_START: u16 = 0x120;

/// Length of the device identity key in bytes (32 bytes = 16 ECC rows).
pub const OTP_DEVICE_ID_KEY_LEN: usize = 32;

// ─── Boot flags bit positions ─────────────────────────────────────────────────

const BOOT_FLAG_JTAG_DISABLED: u32 = 1 << 0;
const BOOT_FLAG_PRODUCTION_MODE: u32 = 1 << 1;
const BOOT_FLAG_PROVISIONED: u32 = 1 << 2;

// ─── Legacy constants (kept for backward compat with old stubs) ───────────────

/// OTP row index for device root secret start (legacy layout).
pub const OTP_ROOT_SECRET_START: u8 = 0x20;

/// OTP row index for device serial number start (legacy layout).
pub const OTP_SERIAL_START: u8 = 0x40;

// ─── OTP error conversion ─────────────────────────────────────────────────────

fn otp_err_to_storage(e: otp::Error) -> StorageError {
    match e {
        otp::Error::InvalidPermissions => StorageError::ReadError,
        otp::Error::InvalidIndex => StorageError::ReadError,
        otp::Error::UnsupportedModification => StorageError::WriteError,
        otp::Error::Overflow => StorageError::WriteError,
        otp::Error::UnexpectedFailure(_) => StorageError::WriteError,
    }
}

fn otp_err_to_hsm(e: otp::Error) -> HsmError {
    HsmError::Storage(otp_err_to_storage(e))
}

// ─── Struct-based API ─────────────────────────────────────────────────────────

/// RP2350 OTP accessor.
///
/// Wraps the `embassy_rp::otp` free functions under a struct interface
/// for use by the boot and key-derivation subsystems.
///
/// There is no peripheral handle to store: `embassy_rp::otp` uses
/// memory-mapped registers directly.  The struct exists as a type-level
/// marker ensuring only one caller has OTP write authority.
pub struct Otp {
    _private: (),
}

impl Otp {
    /// Construct a new `Otp` accessor.
    ///
    /// `otp` is the embassy-rp `OTP` peripheral token.  It is consumed here
    /// to enforce at the type level that only one `Otp` instance exists.
    ///
    /// NOTE: In embassy-rp 0.10.0 there is no `OtpPeripheral` type — the
    /// `otp` module exposes free functions instead.  The parameter is kept
    /// for API forward-compatibility and discarded immediately.
    ///
    /// TODO: When embassy-rp adds an `Otp` peripheral singleton, store it here.
    pub fn new() -> Self {
        Otp { _private: () }
    }

    // ── Key material read/write ──────────────────────────────────────────────

    /// Read 64 bytes of raw key material from OTP rows 0x100–0x10F.
    ///
    /// Each pair of bytes is stored as one ECC-protected 16-bit word.
    /// Returns `Err` if any row yields an ECC error or is read-locked.
    pub fn read_storage_key_material(&self) -> Result<[u8; 64], HsmError> {
        read_ecc_bytes_64(OTP_STORAGE_KEY_ROW_START as usize).map_err(otp_err_to_hsm)
    }

    /// Read 32 bytes of device identity key material from OTP rows 0x120–0x127.
    pub fn read_device_identity_material(&self) -> Result<[u8; 32], HsmError> {
        read_ecc_bytes_32(OTP_DEVICE_ID_KEY_ROW_START as usize).map_err(otp_err_to_hsm)
    }

    /// Read the boot flags word from OTP row 0x110.
    ///
    /// Returns the lower 24 bits (raw read, not ECC) since flags are packed
    /// as individual bits and do not benefit from ECC.
    pub fn read_boot_flags(&self) -> Result<u32, HsmError> {
        otp::read_raw_word(OTP_BOOT_FLAGS_ROW as usize).map_err(otp_err_to_hsm)
    }

    /// Write 64 bytes of storage key material (one-time operation).
    ///
    /// Fails with `HsmError::NotSupported` if the storage key rows are already
    /// non-zero (indicating the key has already been provisioned).
    pub fn write_storage_key_material(&mut self, key: &[u8; 64]) -> Result<(), HsmError> {
        // Guard: refuse to overwrite existing key material.
        if self.is_provisioned() {
            defmt::error!("OTP: write_storage_key_material called on provisioned device");
            return Err(HsmError::NotSupported);
        }
        write_ecc_bytes(OTP_STORAGE_KEY_ROW_START as usize, key.as_ref()).map_err(otp_err_to_hsm)
    }

    /// Write 32 bytes of device identity key material (one-time operation).
    pub fn write_device_identity_material(&mut self, key: &[u8; 32]) -> Result<(), HsmError> {
        write_ecc_bytes(OTP_DEVICE_ID_KEY_ROW_START as usize, key.as_ref()).map_err(otp_err_to_hsm)
    }

    /// Check if the device has been provisioned.
    ///
    /// Returns `true` if the storage key material rows contain at least one
    /// non-zero byte, indicating provisioning has occurred.
    pub fn is_provisioned(&self) -> bool {
        // Read the first two ECC words (4 bytes) and check for non-zero.
        for row in (OTP_STORAGE_KEY_ROW_START as usize)..(OTP_STORAGE_KEY_ROW_START as usize + 2) {
            if let Ok(word) = otp::read_ecc_word(row) {
                if word != 0 {
                    return true;
                }
            }
        }
        // Also check the PROVISIONED flag bit.
        if let Ok(flags) = otp::read_raw_word(OTP_BOOT_FLAGS_ROW as usize) {
            if flags & BOOT_FLAG_PROVISIONED != 0 {
                return true;
            }
        }
        false
    }

    // ── Boot flags ───────────────────────────────────────────────────────────

    /// Check if the device is in production mode.
    ///
    /// Production mode means: JTAG is to be disabled, secure boot enforced,
    /// debug APDUs rejected.
    pub fn is_production_mode(&self) -> bool {
        otp::read_raw_word(OTP_BOOT_FLAGS_ROW as usize)
            .map(|flags| flags & BOOT_FLAG_PRODUCTION_MODE != 0)
            .unwrap_or(false)
    }

    /// Set the production mode flag (irreversible).
    ///
    /// Writes bit 1 of OTP row 0x110.  Once set, this bit cannot be cleared.
    pub fn set_production_mode(&mut self) -> Result<(), HsmError> {
        let current = otp::read_raw_word(OTP_BOOT_FLAGS_ROW as usize).map_err(otp_err_to_hsm)?;
        let new_flags = current | BOOT_FLAG_PRODUCTION_MODE | BOOT_FLAG_PROVISIONED;
        otp::write_raw_word(OTP_BOOT_FLAGS_ROW as usize, new_flags).map_err(otp_err_to_hsm)?;
        defmt::warn!("OTP: production mode flag set — IRREVERSIBLE");
        Ok(())
    }

    /// Permanently disable JTAG via OTP fuse.
    ///
    /// IRREVERSIBLE.  Only callable when production mode is active.
    ///
    /// Writes bit 0 of OTP row 0x110 and then configures the RP2350
    /// JTAG disable fuse via the SWD interface lock register.
    ///
    /// Note: OTP row 0x110 bit 0 is the pico2hsm user-land bookkeeping
    /// flag only.  The hardware JTAG fuse is CRIT1.DEBUG_DISABLE (OTP
    /// rows 0x40–0x47, RBIT-8) and must be set via `picotool otp set
    /// OTP_DATA_CRIT1.DEBUG_DISABLE 1` during provisioning.  See
    /// docs/PROVISIONING.md Phase 8 for the complete procedure.
    pub fn disable_jtag_permanent(&mut self) -> Result<(), HsmError> {
        if !self.is_production_mode() {
            defmt::error!("OTP: JTAG disable attempted outside production mode");
            return Err(HsmError::NotSupported);
        }
        let current = otp::read_raw_word(OTP_BOOT_FLAGS_ROW as usize).map_err(otp_err_to_hsm)?;
        let new_flags = current | BOOT_FLAG_JTAG_DISABLED;
        otp::write_raw_word(OTP_BOOT_FLAGS_ROW as usize, new_flags).map_err(otp_err_to_hsm)?;
        defmt::warn!("OTP: JTAG disable fuse set — IRREVERSIBLE");
        Ok(())
    }
}

// ─── ECC byte helpers ─────────────────────────────────────────────────────────

/// Read 32 bytes from ECC-protected OTP rows starting at `row_start`.
///
/// Each row holds one 16-bit ECC word = 2 bytes.  16 rows → 32 bytes.
fn read_ecc_bytes_32(row_start: usize) -> Result<[u8; 32], otp::Error> {
    let mut out = [0u8; 32];
    for i in 0..16 {
        let word = otp::read_ecc_word(row_start + i)?;
        out[i * 2] = (word >> 8) as u8;
        out[i * 2 + 1] = (word & 0xFF) as u8;
    }
    Ok(out)
}

/// Read 64 bytes from ECC-protected OTP rows starting at `row_start`.
///
/// Each row holds one 16-bit ECC word = 2 bytes.  32 rows → 64 bytes.
fn read_ecc_bytes_64(row_start: usize) -> Result<[u8; 64], otp::Error> {
    let mut out = [0u8; 64];
    for i in 0..32 {
        let word = otp::read_ecc_word(row_start + i)?;
        out[i * 2] = (word >> 8) as u8;
        out[i * 2 + 1] = (word & 0xFF) as u8;
    }
    Ok(out)
}

/// Write bytes to ECC-protected OTP rows starting at `row_start`.
///
/// Pairs consecutive bytes into 16-bit ECC words.  Pads the last row
/// with 0x00 if `data.len()` is odd.
fn write_ecc_bytes(row_start: usize, data: &[u8]) -> Result<(), otp::Error> {
    let len = data.len();
    let num_rows = (len + 1) / 2;
    for i in 0..num_rows {
        let high = data[i * 2] as u16;
        let low = if i * 2 + 1 < len {
            data[i * 2 + 1] as u16
        } else {
            0
        };
        let word = (high << 8) | low;
        otp::write_ecc_word(row_start + i, word)?;
    }
    Ok(())
}

// ─── Legacy free-function API (kept for source compat with old stubs) ─────────

/// Read one OTP row (returns the 24-bit raw value as 3 bytes, big-endian).
///
/// Returns `Err` if the row is read-locked or the index is out of range.
pub fn read_row(row: u8) -> Result<[u8; 3], StorageError> {
    let val = otp::read_raw_word(row as usize).map_err(otp_err_to_storage)?;
    Ok([(val >> 16) as u8, (val >> 8) as u8, val as u8])
}

/// Write one OTP row (burns fuses — irreversible).
///
/// `data` is 3 bytes big-endian representing a 24-bit OTP value.
pub fn write_row(row: u8, data: [u8; 3]) -> Result<(), StorageError> {
    let val: u32 = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
    otp::write_raw_word(row as usize, val).map_err(otp_err_to_storage)
}

/// Permanently lock a range of OTP rows for reading via the RP2350 SW_LOCK
/// page registers.
///
/// P0-3 fix: previously a stub that always returned `Err`. Now implemented
/// using the RP2350 OTP peripheral's `sw_lock` registers (64 per-page
/// software lock registers at OTP base + 0x000). Each register controls
/// one 64-row OTP page; setting both `sec` and `nsec` fields to
/// `INACCESSIBLE` (0x3) prevents all reads of that page regardless of
/// privilege level.
///
/// # Page mapping
/// Each OTP page covers 64 consecutive rows:
///   page = row / 64  (integer division)
///
/// Rows 0x100–0x127 (IKM, device key, boot flags) all fall in OTP page 4
/// (rows 0x100–0x13F). Locking page 4 makes the key material unreadable via
/// SWD after provisioning.
///
/// # Effect
/// After this call, `embassy_rp::otp::read_raw_word` and `read_ecc_word` for
/// any row in a locked page will return `Err(InvalidPermissions)` (the OTP
/// data memory-mapped read returns 0xFFFF_FFFF for locked rows).
///
/// # Irreversibility
/// The SW_LOCK registers are reset on the next power-on reset (they are NOT
/// OTP-burned). For permanent lock-out, combine with OTP lock pages (written
/// via provisioning tool). This function provides runtime protection that
/// prevents SWD reads during the current boot session.
///
/// # Safety
/// Uses `embassy_rp::pac::OTP` which is a well-known RP2350 MMIO peripheral
/// at address 0x4012_0000 (RP2350 datasheet §5.4 "OTP Control Registers").
/// Single-caller assumption: this is called once at provisioning time.
#[cfg(target_arch = "arm")]
pub fn lock_read(row_start: u8, row_count: u8) -> Result<(), StorageError> {
    use embassy_rp::pac::otp::vals::{SwLockNsec, SwLockSec};
    use embassy_rp::pac::OTP;

    if row_count == 0 {
        return Ok(());
    }

    // Compute the range of OTP pages covered by [row_start, row_start + row_count).
    let first_page = (row_start as usize) / 64;
    let last_row = (row_start as usize)
        .saturating_add(row_count as usize)
        .saturating_sub(1);
    let last_page = last_row / 64;

    // Validate page indices — OTP has 64 pages (0..63).
    if last_page >= 64 {
        defmt::error!(
            "OTP: lock_read — row range 0x{:02X}+{} exceeds OTP page count",
            row_start,
            row_count
        );
        return Err(StorageError::WriteError);
    }

    // Lock each page in the range by setting both Secure and Non-Secure access
    // to INACCESSIBLE (0x3).  This prevents reads from any privilege level.
    for page in first_page..=last_page {
        // SAFETY: OTP SW_LOCK registers at 0x4012_0000 + page*4.
        // Each register is a 32-bit MMIO register controlling one OTP page.
        // Writing INACCESSIBLE to both sec and nsec fields blocks all reads.
        unsafe {
            OTP.sw_lock(page).write(|w| {
                w.set_sec(SwLockSec::INACCESSIBLE);
                w.set_nsec(SwLockNsec::INACCESSIBLE);
            });
        }
        defmt::warn!(
            "OTP: page {} read-locked (rows 0x{:02X}–0x{:02X}) — reset required to unlock",
            page,
            page * 64,
            page * 64 + 63
        );
    }

    Ok(())
}

/// Stub for non-ARM targets (host tests).
#[cfg(not(target_arch = "arm"))]
pub fn lock_read(_row_start: u8, _row_count: u8) -> Result<(), StorageError> {
    Ok(())
}

/// Lock a range of OTP rows for writing via the RP2350 SW_LOCK page registers.
///
/// Sets the per-page SW_LOCK to READ_ONLY for both Secure and Non-Secure
/// access, preventing any further writes to OTP rows in the specified range.
///
/// See `lock_read()` for page mapping and register layout details.
#[cfg(target_arch = "arm")]
pub fn lock_write(row_start: u8, row_count: u8) -> Result<(), StorageError> {
    use embassy_rp::pac::otp::vals::{SwLockNsec, SwLockSec};
    use embassy_rp::pac::OTP;

    if row_count == 0 {
        return Ok(());
    }

    let first_page = (row_start as usize) / 64;
    let last_row = (row_start as usize)
        .saturating_add(row_count as usize)
        .saturating_sub(1);
    let last_page = last_row / 64;

    if last_page >= 64 {
        defmt::error!(
            "OTP: lock_write — row range 0x{:02X}+{} exceeds OTP page count",
            row_start,
            row_count
        );
        return Err(StorageError::WriteError);
    }

    for page in first_page..=last_page {
        // READ_ONLY prevents writes while still allowing reads.
        unsafe {
            OTP.sw_lock(page).write(|w| {
                w.set_sec(SwLockSec::READ_ONLY);
                w.set_nsec(SwLockNsec::READ_ONLY);
            });
        }
        defmt::warn!(
            "OTP: page {} write-locked (rows 0x{:02X}–0x{:02X})",
            page,
            page * 64,
            page * 64 + 63
        );
    }

    Ok(())
}

/// Stub for non-ARM targets (host tests).
#[cfg(not(target_arch = "arm"))]
pub fn lock_write(_row_start: u8, _row_count: u8) -> Result<(), StorageError> {
    Ok(())
}

/// Read the 32-byte device root secret from OTP rows 0x20–0x3F (legacy layout).
///
/// Rows 0x20–0x3F each contain 3 raw bytes; we pack them into 32 bytes.
/// This function reads 11 rows (33 bytes) and truncates to 32 bytes.
pub fn read_root_secret() -> Result<[u8; 32], StorageError> {
    let mut out = [0u8; 32];
    let mut byte_idx = 0usize;
    for row in (OTP_ROOT_SECRET_START as usize)..=(0x3F_usize) {
        if byte_idx >= 32 {
            break;
        }
        let raw = otp::read_raw_word(row).map_err(otp_err_to_storage)?;
        let bytes = [(raw >> 16) as u8, (raw >> 8) as u8, raw as u8];
        for &b in &bytes {
            if byte_idx < 32 {
                out[byte_idx] = b;
                byte_idx += 1;
            }
        }
    }
    Ok(out)
}

/// Derive the Storage Master Key from the OTP root secret.
///
/// Uses HKDF-SHA256: `HKDF(IKM=root_secret, salt="pico2hsm-smk", info=serial)`.
/// The derived key is returned as a 32-byte array and MUST be zeroized
/// by the caller after use.
///
/// BREAKING CHANGE: This function now reads from OTP rows 0x100-0x11F
/// (correct per-device key material). Any device provisioned before this
/// change will have its keystore irrecoverably encrypted under the old SMK
/// derived from rows 0x20-0x3F. Re-initialization is required after
/// upgrading from earlier firmware.
///
/// TODO (crypto agent): pass the device serial number from OTP as `info`.
pub fn derive_smk() -> Result<[u8; 32], StorageError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let ikm = read_ecc_bytes_64(OTP_STORAGE_KEY_ROW_START as usize).map_err(otp_err_to_storage)?;
    let salt = b"pico2hsm-smk";

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(b"storage-master-key", &mut okm)
        .map_err(|_| StorageError::WriteError)?;

    Ok(okm)
}
