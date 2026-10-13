//! Internal (QMI) flash map — the single source of truth for what lives
//! where on the RP2350's own flash chip.
//!
//! Offsets are from the start of flash (XIP address 0x1000_0000).
//!
//! ```text
//! 0x000000 – 0x1F0000  firmware image      (linker FLASH region, boards/*.x)
//! 0x1F0000 – 0x1FC000  RSA key pool        (12 sectors, every board, `rsa`)
//! 0x1FC000 – 0x200000  retry-counter log   (4 sectors, every board)
//! 0x200000 – 0x400000  keystore partition  (QMI boards; unused on SD boards)
//! ```
//!
//! The retry-counter log lives on internal flash on *every* board, the
//! SD-card boards included: a removable card must not hold the PIN retry
//! counters.  It sits at the top of the 2 MB firmware partition rather than
//! inside the keystore partition, so it can never collide with key-object
//! sectors already allocated on existing devices, and it exists on the
//! 4 MB boards as well as the 16 MB ones.  The linker scripts end the
//! firmware's FLASH region at [`FIRMWARE_END`]: an image that grew into the
//! counter log fails to link instead of being overwritten (or overwriting
//! the counters) — `boards_reserve_the_counter_region` checks that every
//! board script agrees with the constants here.
//!
//! The RSA key pool (`storage::rsa_pool`) sits directly below the counter
//! log, for the same reasons: internal flash on every board (never the
//! removable card), and never on top of keystore sectors that existing
//! devices may already use.  It took the top 48 KB of the firmware
//! partition (2026-10); the largest image (debug, all applets) is far
//! below the new end.

/// Erase-sector size of the QMI flash.
pub const SECTOR: u32 = 4096;

/// Exclusive end of the firmware image (end of the linker FLASH region).
pub const FIRMWARE_END: u32 = 0x001F_0000;

/// First byte of the RSA key pool region.
pub const RSA_POOL_OFFSET: u32 = 0x001F_0000;

/// Sectors in the RSA key pool (one pooled key per sector).
pub const RSA_POOL_SECTORS: u32 = 12;

/// Bytes in the RSA key pool region.
pub const RSA_POOL_SIZE: u32 = RSA_POOL_SECTORS * SECTOR;

/// First byte of the retry-counter log.
pub const RETRY_COUNTER_OFFSET: u32 = 0x001F_C000;

/// Sectors in the retry-counter log (rotated; at least two, so the sector
/// being erased is never the one holding the current counters).
pub const RETRY_COUNTER_SECTORS: u32 = 4;

/// Bytes in the retry-counter log.
pub const RETRY_COUNTER_SIZE: u32 = RETRY_COUNTER_SECTORS * SECTOR;

/// Start of the keystore partition on the QMI boards.
pub const QMI_KEYSTORE_OFFSET: u32 = 0x0020_0000;

/// Flash size of the smallest supported board (Pico 2, RP2350-One: 4 MB).
pub const QMI_FLASH_SIZE: u32 = 0x0040_0000;

// Layout invariants, checked at compile time.
const _: () = {
    // Sector aligned.
    assert!(RETRY_COUNTER_OFFSET % SECTOR == 0);
    assert!(QMI_KEYSTORE_OFFSET % SECTOR == 0);
    assert!(RSA_POOL_OFFSET % SECTOR == 0);
    // Rotation needs a spare sector.
    assert!(RETRY_COUNTER_SECTORS >= 2);
    // Firmware, RSA pool, counter log and keystore are disjoint and in
    // this order.
    assert!(FIRMWARE_END <= RSA_POOL_OFFSET);
    assert!(RSA_POOL_OFFSET + RSA_POOL_SIZE <= RETRY_COUNTER_OFFSET);
    assert!(RETRY_COUNTER_OFFSET + RETRY_COUNTER_SIZE <= QMI_KEYSTORE_OFFSET);
    assert!(QMI_KEYSTORE_OFFSET < QMI_FLASH_SIZE);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// `(origin, length)` of a MEMORY region in a linker script.
    fn region(script: &str, name: &str) -> Option<(u32, u32)> {
        let line = script
            .lines()
            .map(str::trim)
            .find(|l| l.split_whitespace().next() == Some(name) && l.contains("ORIGIN"))?;
        let hex = |key: &str| {
            let rest = &line[line.find(key)? + key.len()..];
            let rest = rest.trim_start_matches([' ', '=']).trim_start();
            let rest = rest.strip_prefix("0x")?;
            let end = rest
                .find(|c: char| !c.is_ascii_hexdigit())
                .unwrap_or(rest.len());
            u32::from_str_radix(&rest[..end], 16).ok()
        };
        Some((hex("ORIGIN")?, hex("LENGTH")?))
    }

    const XIP_BASE: u32 = 0x1000_0000;

    #[test]
    fn boards_reserve_the_counter_region() {
        let boards: [(&str, &str); 5] = [
            ("pico2_4m", include_str!("../../../boards/pico2_4m.x")),
            (
                "rp2350_one_4m",
                include_str!("../../../boards/rp2350_one_4m.x"),
            ),
            (
                "rp2350_geek_16m",
                include_str!("../../../boards/rp2350_geek_16m.x"),
            ),
            (
                "rp2350_geek_sdcard",
                include_str!("../../../boards/rp2350_geek_sdcard.x"),
            ),
            (
                "waveshare_rp2350_lcd_16m",
                include_str!("../../../boards/waveshare_rp2350_lcd_16m.x"),
            ),
        ];
        for (name, script) in boards {
            let (fo, fl) = region(script, "FLASH").expect(name);
            assert_eq!(fo + fl, XIP_BASE + FIRMWARE_END, "{name}: FLASH end");
            let (co, cl) = region(script, "RETRY_COUNTERS").expect(name);
            assert_eq!(
                co,
                XIP_BASE + RETRY_COUNTER_OFFSET,
                "{name}: counter origin"
            );
            assert_eq!(cl, RETRY_COUNTER_SIZE, "{name}: counter length");
            let (ko, _) = region(script, "KEYSTORE").expect(name);
            assert!(co + cl <= ko, "{name}: counters overlap the keystore");
            let (po, pl) = region(script, "RSA_POOL").expect(name);
            assert_eq!(po, XIP_BASE + RSA_POOL_OFFSET, "{name}: pool origin");
            assert_eq!(pl, RSA_POOL_SIZE, "{name}: pool length");
            assert!(fo + fl <= po, "{name}: firmware overlaps the pool");
            assert!(po + pl <= co, "{name}: pool overlaps the counters");
        }
    }
}
