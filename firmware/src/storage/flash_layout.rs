//! Internal (QMI) flash map — the single source of truth for what lives
//! where on the RP2350's own flash chip.
//!
//! Offsets are from the start of flash (XIP address 0x1000_0000).
//!
//! ```text
//! 0x000000 – 0x1D8000  firmware image      (linker FLASH region, boards/*.x)
//! 0x1D8000 – 0x1E0000  binding block ring  (8 sectors, Storage V2 §8.1)
//! 0x1E0000 – 0x1F0000  counter log v2      (16 sectors, every board)
//! 0x1F0000 – 0x1FC000  RSA key pool        (12 sectors, every board, `rsa`)
//! 0x1FC000 – 0x200000  counter log v1      (4 sectors: migrated once, then
//!                                           erased and left spare)
//! 0x200000 – 0x400000  keystore partition  (QMI boards; unused on SD boards)
//! ```
//!
//! Storage V2 (2026-10, phase 1) took the binding ring and the 16-sector
//! counter log from the top of the firmware region, not from the keystore
//! (the 1.x filesystem allocates anywhere above 0x200000).  The debug image
//! (all applets) is ~1.3 MB of the 1.84 MB left.  The 2.0 layout with the
//! bootrom partition table (STORAGE_V2 §3, phase 6) replaces this map.
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

/// One flash size's map.  Every store region is a fixed offset from
/// `store_base`, so the two maps differ only in where the store starts,
/// where the firmware must end, and the chip size.
#[derive(Clone, Copy)]
pub struct Map {
    /// Exclusive end of the firmware image (end of the linker FLASH region,
    /// in the address space the image runs in).
    pub firmware_end: u32,
    /// First byte of the store regions (the binding ring).
    pub store_base: u32,
    /// Flash size.
    pub flash_size: u32,
}

/// The 4 MB boards (Pico 2, RP2350-One): flat, no partition table.  The
/// firmware runs from 0; the store regions follow it at 0x1D8000.
pub const MAP_4M: Map = Map {
    firmware_end: 0x001D_8000,
    store_base: 0x001D_8000,
    flash_size: 0x0040_0000,
};

/// The 16 MB boards (Geek, Waveshare LCD; QMI and SD variants): a
/// partition table with A/B firmware slots of 4 MB each
/// (FLASH_LAYOUT_2_0.md), the store regions from 8 MB.  An image runs
/// from either slot at 0x1000_0000 (bootrom address translation), so it
/// links against the slot's size; flashed flat (no partition table), it
/// runs from 0 and stays below the store all the same.
pub const MAP_16M: Map = Map {
    firmware_end: SLOT_SIZE_16M,
    store_base: 0x0080_0000,
    flash_size: 0x0100_0000,
};

/// The partition table's own space at the start of flash (16 MB boards).
pub const PT_SIZE_16M: u32 = 0x2000;
/// Each firmware slot on the 16 MB boards: slot A at `PT_SIZE_16M`, slot B
/// at 4 MB, the same size.
pub const SLOT_SIZE_16M: u32 = 0x0040_0000 - PT_SIZE_16M;
/// Physical start of slot A (16 MB boards).
pub const SLOT_A_16M: u32 = PT_SIZE_16M;
/// Physical start of slot B (16 MB boards).
pub const SLOT_B_16M: u32 = 0x0040_0000;

/// Whether this build is for a 16 MB board.
pub const FLASH_16M: bool = cfg!(any(
    feature = "rp2350_geek_16m",
    feature = "rp2350_geek_sdcard",
    feature = "waveshare_rp2350_lcd_16m",
    feature = "waveshare_rp2350_lcd_sdcard",
));

/// This build's map.
pub const MAP: Map = if FLASH_16M { MAP_16M } else { MAP_4M };

/// Exclusive end of the firmware image (end of the linker FLASH region).
pub const FIRMWARE_END: u32 = MAP.firmware_end;

/// First byte of the Storage V2 binding block ring (STORAGE_V2 §8.1).
pub const BINDING_OFFSET: u32 = MAP.store_base;

/// Sectors in the binding block ring (R8: host-drivable resets each write
/// the binding; eight sectors last ~800 000 writes).
pub const BINDING_SECTORS: u32 = 8;

/// Bytes in the binding block ring.
pub const BINDING_SIZE: u32 = BINDING_SECTORS * SECTOR;

/// First byte of the counter log (version 2: retry counters, device
/// values, the keystore anchor).
pub const RETRY_COUNTER_OFFSET: u32 = MAP.store_base + 0x8000;

/// Sectors in the counter log (rotated; at least two, so the sector being
/// erased is never the one holding the current records).
pub const RETRY_COUNTER_SECTORS: u32 = 16;

/// Bytes in the counter log.
pub const RETRY_COUNTER_SIZE: u32 = RETRY_COUNTER_SECTORS * SECTOR;

/// First byte of the RSA key pool region.
pub const RSA_POOL_OFFSET: u32 = MAP.store_base + 0x1_8000;

/// Sectors in the RSA key pool (one pooled key per sector).
pub const RSA_POOL_SECTORS: u32 = 12;

/// Bytes in the RSA key pool region.
pub const RSA_POOL_SIZE: u32 = RSA_POOL_SECTORS * SECTOR;

/// First byte of the version-1 counter log (1.x layout), migrated into the
/// version-2 log once at boot and then erased.  On the 16 MB boards it is
/// a blank placeholder (no 1.x log was ever there).
pub const LEGACY_COUNTER_OFFSET: u32 = MAP.store_base + 0x2_4000;

/// Sectors in the version-1 counter log.
pub const LEGACY_COUNTER_SECTORS: u32 = 4;

/// Bytes in the version-1 counter log.
pub const LEGACY_COUNTER_SIZE: u32 = LEGACY_COUNTER_SECTORS * SECTOR;

/// Start of the keystore partition on the QMI boards.
pub const QMI_KEYSTORE_OFFSET: u32 = MAP.store_base + 0x2_8000;

/// Flash size of this build's board.
pub const QMI_FLASH_SIZE: u32 = MAP.flash_size;

// Layout invariants, checked at compile time.
const _: () = {
    // Sector aligned.
    assert!(BINDING_OFFSET % SECTOR == 0);
    assert!(RETRY_COUNTER_OFFSET % SECTOR == 0);
    assert!(LEGACY_COUNTER_OFFSET % SECTOR == 0);
    assert!(QMI_KEYSTORE_OFFSET % SECTOR == 0);
    assert!(RSA_POOL_OFFSET % SECTOR == 0);
    // Rotation needs a spare sector.
    assert!(RETRY_COUNTER_SECTORS >= 2);
    assert!(BINDING_SECTORS >= 2);
    // Firmware, binding ring, counter log, RSA pool, the version-1 log and
    // the keystore are disjoint and in this order.
    assert!(FIRMWARE_END <= BINDING_OFFSET);
    assert!(BINDING_OFFSET + BINDING_SIZE <= RETRY_COUNTER_OFFSET);
    assert!(RETRY_COUNTER_OFFSET + RETRY_COUNTER_SIZE <= RSA_POOL_OFFSET);
    assert!(RSA_POOL_OFFSET + RSA_POOL_SIZE <= LEGACY_COUNTER_OFFSET);
    assert!(LEGACY_COUNTER_OFFSET + LEGACY_COUNTER_SIZE <= QMI_KEYSTORE_OFFSET);
    assert!(QMI_KEYSTORE_OFFSET < QMI_FLASH_SIZE);
    // The 4 MB map is the one boards already use.
    assert!(MAP_4M.store_base == 0x001D_8000 && MAP_4M.store_base + 0x2_8000 == 0x0020_0000);
    // 16 MB: both slots end below the store; slots are sector aligned.
    assert!(SLOT_A_16M + SLOT_SIZE_16M <= SLOT_B_16M);
    assert!(SLOT_B_16M + SLOT_SIZE_16M <= MAP_16M.store_base);
    assert!(SLOT_A_16M % SECTOR == 0 && SLOT_B_16M % SECTOR == 0);
    assert!(MAP_16M.firmware_end <= MAP_16M.store_base);
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
    fn boards_reserve_the_storage_regions() {
        let boards: [(&str, &str, Map); 5] = [
            (
                "pico2_4m",
                include_str!("../../../boards/pico2_4m.x"),
                MAP_4M,
            ),
            (
                "rp2350_one_4m",
                include_str!("../../../boards/rp2350_one_4m.x"),
                MAP_4M,
            ),
            (
                "rp2350_geek_16m",
                include_str!("../../../boards/rp2350_geek_16m.x"),
                MAP_16M,
            ),
            (
                "rp2350_geek_sdcard",
                include_str!("../../../boards/rp2350_geek_sdcard.x"),
                MAP_16M,
            ),
            (
                "waveshare_rp2350_lcd_16m",
                include_str!("../../../boards/waveshare_rp2350_lcd_16m.x"),
                MAP_16M,
            ),
        ];
        for (name, script, map) in boards {
            let at = |region_name: &str| region(script, region_name).expect(name);
            let (fo, fl) = at("FLASH");
            assert_eq!(fo + fl, XIP_BASE + map.firmware_end, "{name}: FLASH end");
            // Every reserved region where the constants say, in order.
            let base = map.store_base;
            let regions = [
                ("BINDING", base, BINDING_SIZE),
                ("RETRY_COUNTERS", base + 0x8000, RETRY_COUNTER_SIZE),
                ("RSA_POOL", base + 0x1_8000, RSA_POOL_SIZE),
                ("LEGACY_COUNTERS", base + 0x2_4000, LEGACY_COUNTER_SIZE),
            ];
            let mut end = fo + fl;
            for (rname, offset, size) in regions {
                let (o, l) = at(rname);
                assert_eq!(o, XIP_BASE + offset, "{name}: {rname} origin");
                assert_eq!(l, size, "{name}: {rname} length");
                assert!(end <= o, "{name}: {rname} overlaps what precedes it");
                end = o + l;
            }
            let (ko, kl) = at("KEYSTORE");
            assert_eq!(ko, XIP_BASE + base + 0x2_8000, "{name}: KEYSTORE origin");
            assert!(end <= ko, "{name}: reserved regions overlap the keystore");
            assert_eq!(ko + kl, XIP_BASE + map.flash_size, "{name}: KEYSTORE end");
        }
    }
}
