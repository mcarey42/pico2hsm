//! pico2hsm OTP row layout — the single source of truth.
//!
//! ```text
//! Page 4 (rows 0x100–0x13F) — secrets; read-locked after boot
//!   0x100–0x11F  Storage key IKM, 64 bytes as 32 ECC words
//!   0x120–0x12F  Device identity key, 32 bytes as 16 ECC words
//! Page 5 (rows 0x140–0x17F)
//!   0x140        Boot flags (raw 24-bit word, bits below)
//! ```
//!
//! Rows 0x0C0–0xF3F are free for applications on the RP2350 (the bootrom
//! defines rows below 0xC0 and from 0xF48).  Earlier firmware put the boot
//! flags at 0x110, *inside* the storage-key rows; the assertions below keep
//! that from happening again.

/// One OTP page is 64 rows; page locks apply per page.
pub const ROWS_PER_PAGE: u16 = 64;

/// First row of the storage key IKM (64 bytes = 32 ECC rows).
pub const STORAGE_KEY_ROW_START: u16 = 0x100;
/// Rows used by the storage key IKM.
pub const STORAGE_KEY_ROWS: u16 = 32;

/// First row of the device identity key (32 bytes = 16 ECC rows).
pub const DEVICE_ID_KEY_ROW_START: u16 = 0x120;
/// Rows used by the device identity key.
pub const DEVICE_ID_KEY_ROWS: u16 = 16;

/// OTP page holding both secrets.
pub const KEY_PAGE: u16 = STORAGE_KEY_ROW_START / ROWS_PER_PAGE;

/// Raw row holding the pico2hsm boot flags.  Deliberately outside
/// [`KEY_PAGE`] so locking the key page never hides the flags.
pub const BOOT_FLAGS_ROW: u16 = 0x140;

/// Boot flag: JTAG-disabled bookkeeping bit (irreversible).
pub const BOOT_FLAG_JTAG_DISABLED: u32 = 1 << 0;
/// Boot flag: production mode active (irreversible).
pub const BOOT_FLAG_PRODUCTION_MODE: u32 = 1 << 1;
/// Boot flag: device has been provisioned.
pub const BOOT_FLAG_PROVISIONED: u32 = 1 << 2;

const fn end(start: u16, rows: u16) -> u16 {
    start + rows
}

// Layout invariants, checked at compile time.
const _: () = {
    // Inside the application area.
    assert!(STORAGE_KEY_ROW_START >= 0x0C0 && BOOT_FLAGS_ROW < 0xF40);
    // No overlaps, in ascending order.
    assert!(end(STORAGE_KEY_ROW_START, STORAGE_KEY_ROWS) <= DEVICE_ID_KEY_ROW_START);
    assert!(end(DEVICE_ID_KEY_ROW_START, DEVICE_ID_KEY_ROWS) <= BOOT_FLAGS_ROW);
    // Both secrets in the key page; the flags outside it.
    assert!((end(DEVICE_ID_KEY_ROW_START, DEVICE_ID_KEY_ROWS) - 1) / ROWS_PER_PAGE == KEY_PAGE);
    assert!(BOOT_FLAGS_ROW / ROWS_PER_PAGE != KEY_PAGE);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_flags_row_is_not_a_key_row() {
        let key_rows = STORAGE_KEY_ROW_START..end(DEVICE_ID_KEY_ROW_START, DEVICE_ID_KEY_ROWS);
        assert!(!key_rows.contains(&BOOT_FLAGS_ROW));
        assert!(!key_rows.contains(&0x140));
        // The pre-fix location must stay inside the key rows (never reused).
        assert!(key_rows.contains(&0x110));
    }
}
