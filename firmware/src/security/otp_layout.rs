//! pico2hsm OTP row layout — the single source of truth.
//!
//! ```text
//! Page 4 (rows 0x100–0x13F) — the storage secret; read-locked after boot
//!   0x100–0x11F  Storage key IKM, 64 bytes as 32 ECC words
//!   0x120–0x13F  Chaff: the 24-bit complement of each raw IKM row
//! Page 5 (rows 0x140–0x17F)
//!   0x140        Boot flags (raw 24-bit word, bits below)
//! Page 6 (rows 0x180–0x1BF) — reserved, not provisioned
//!   0x180–0x18F  Device identity key, 32 bytes as 16 ECC words
//!   0x1A0–0x1AF  its chaff
//! ```
//!
//! Chaff (RP2350 datasheet §13.8.2): in each 64-row page, rows i and 32 + i
//! share physical bit cells.  A secret whose partner rows are blank (or hold
//! another secret) can be read from a passive-voltage-contrast image of a
//! decapsulated chip; storing the bitwise complement of each raw row (ECC
//! bits included) in its partner defeats that.  The firmware never reads
//! the chaff rows; `tools/provision-device.sh` writes them.
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

/// First chaff row of the storage key IKM (32 raw rows, row 0x120 + i holds
/// the complement of row 0x100 + i).
pub const STORAGE_KEY_CHAFF_ROW_START: u16 = 0x120;

/// First row of the device identity key (32 bytes = 16 ECC rows).  Reserved
/// on page 6, not provisioned: nothing uses it yet.  If it ever is, it needs
/// its chaff at 0x1A0, a page-6 hard lock and the page-6 soft lock at boot.
pub const DEVICE_ID_KEY_ROW_START: u16 = 0x180;
/// Rows used by the device identity key.
pub const DEVICE_ID_KEY_ROWS: u16 = 16;

/// OTP page holding the storage secret (and its chaff).
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
    assert!(STORAGE_KEY_ROW_START >= 0x0C0 && DEVICE_ID_KEY_ROW_START + DEVICE_ID_KEY_ROWS < 0xF40);
    // The IKM fills the lower half of the key page, its chaff the upper half
    // (rows i and 32 + i share bit cells).
    assert!(STORAGE_KEY_ROW_START % ROWS_PER_PAGE == 0 && STORAGE_KEY_ROWS == ROWS_PER_PAGE / 2);
    assert!(STORAGE_KEY_CHAFF_ROW_START == STORAGE_KEY_ROW_START + ROWS_PER_PAGE / 2);
    // The boot flags are outside the key page, and not on the device-id page.
    assert!(BOOT_FLAGS_ROW / ROWS_PER_PAGE == KEY_PAGE + 1);
    assert!(DEVICE_ID_KEY_ROW_START / ROWS_PER_PAGE == KEY_PAGE + 2);
    assert!(DEVICE_ID_KEY_ROW_START % ROWS_PER_PAGE == 0);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_flags_row_is_not_a_key_row() {
        let key_page = STORAGE_KEY_ROW_START..STORAGE_KEY_ROW_START + ROWS_PER_PAGE;
        assert!(!key_page.contains(&BOOT_FLAGS_ROW));
        assert!(!key_page.contains(&0x140));
        // The pre-fix location must stay inside the key rows (never reused).
        assert!(key_page.contains(&0x110));
        // Every IKM row's bit-cell partner is its chaff row.
        for i in 0..STORAGE_KEY_ROWS {
            assert_eq!(
                STORAGE_KEY_ROW_START + i + 32,
                STORAGE_KEY_CHAFF_ROW_START + i
            );
        }
    }
}
