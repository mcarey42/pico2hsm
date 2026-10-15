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

/// One flash size's map.  Every board boots through a bootrom partition
/// table (FLASH_LAYOUT_2_0.md): the table in the first 8 KB, firmware
/// slot A after it (and slot B on the 16 MB boards), then the store
/// regions, each a fixed offset from `store_base`, as closed partitions.
/// An image runs from its slot at 0x1000_0000 (bootrom address
/// translation), so it links against the slot's size.
#[derive(Clone, Copy)]
pub struct Map {
    /// Size of each firmware slot: the end of the linker FLASH region, in
    /// the address space the image runs in.
    pub slot_size: u32,
    /// Physical start of slot B (0: no slot B).
    pub slot_b: u32,
    /// First byte of the store regions (the binding ring).
    pub store_base: u32,
    /// First byte of the keystore partition.
    pub keystore_start: u32,
    /// Exclusive end of the keystore partition.
    pub keystore_end: u32,
    /// Flash size.
    pub flash_size: u32,
}

/// Found on hardware (2026-10-14, LCD board 16 MB, RP2350-One 4 MB): if a
/// partition closed to the bootloader contains the flash's midpoint (8 MB,
/// 2 MB), the bootrom refuses every BOOTSEL write, anywhere in flash —
/// whether the partition starts there or straddles it; one starting a
/// sector past it does not.  So the sector at the midpoint stays outside
/// every closed partition (the host test checks the tables).
pub const MIDPOINT_RULE: () = ();

/// The partition table's own space at the start of flash (every board).
pub const PT_SIZE: u32 = 0x2000;
/// Physical start of slot A (every board).
pub const SLOT_A: u32 = PT_SIZE;

/// The 4 MB boards (Pico 2, RP2350-One): one slot of 1.83 MB, the store
/// regions where the flat 1.x/2.0 interim layout had them (0x1D8000),
/// except the keystore, which starts a sector past the midpoint (see
/// [`MIDPOINT_RULE`]).  No slot B: the room goes to the firmware
/// (post-quantum algorithms).
pub const MAP_4M: Map = Map {
    slot_size: 0x001D_8000 - SLOT_A,
    slot_b: 0,
    store_base: 0x001D_8000,
    keystore_start: 0x0020_1000,
    keystore_end: 0x0040_0000,
    flash_size: 0x0040_0000,
};

/// The 16 MB boards (Geek, Waveshare LCD, RP2350-One with a 16 MB chip;
/// QMI and SD variants): A/B slots of 4 MB less the table, the store
/// regions from 8 MB + 4 KB, so no closed partition holds the midpoint
/// (see [`MIDPOINT_RULE`]).  The keystore stops one sector short of the
/// end: picotool keeps the last sector out of every partition (erratum
/// RP2350-E10's absolute block).
pub const MAP_16M: Map = Map {
    slot_size: 0x0040_0000 - SLOT_A,
    slot_b: 0x0040_0000,
    store_base: 0x0080_1000,
    keystore_start: 0x0080_1000 + 0x2_8000,
    keystore_end: 0x0100_0000 - SECTOR,
    flash_size: 0x0100_0000,
};

/// Whether this build is for a 16 MB board.
pub const FLASH_16M: bool = cfg!(any(
    feature = "rp2350_one_16m",
    feature = "rp2350_geek_16m",
    feature = "rp2350_geek_sdcard",
    feature = "waveshare_rp2350_lcd_16m",
    feature = "waveshare_rp2350_lcd_sdcard",
));

/// This build's map.
pub const MAP: Map = if FLASH_16M { MAP_16M } else { MAP_4M };

/// Exclusive end of the firmware image (end of the linker FLASH region).
pub const FIRMWARE_END: u32 = MAP.slot_size;

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
pub const QMI_KEYSTORE_OFFSET: u32 = MAP.keystore_start;

/// Exclusive end of the keystore partition on the QMI boards.
pub const QMI_KEYSTORE_END: u32 = MAP.keystore_end;

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
    // The 4 MB store regions stay where boards already have them.
    assert!(MAP_4M.store_base == 0x001D_8000);
    // The keystore follows the other regions, and no closed region holds
    // the midpoint (MIDPOINT_RULE).
    assert!(MAP_4M.store_base + 0x2_8000 <= MAP_4M.keystore_start);
    assert!(MAP_16M.store_base + 0x2_8000 <= MAP_16M.keystore_start);
    assert!(MAP_4M.keystore_start > MAP_4M.flash_size / 2);
    assert!(MAP_4M.store_base + 0x2_8000 <= MAP_4M.flash_size / 2);
    assert!(MAP_16M.store_base > MAP_16M.flash_size / 2);
    // Slots: sector aligned, below the store, B after A.
    assert!(SLOT_A % SECTOR == 0 && PT_SIZE % SECTOR == 0);
    assert!(SLOT_A + MAP_4M.slot_size <= MAP_4M.store_base);
    assert!(SLOT_A + MAP_16M.slot_size <= MAP_16M.slot_b);
    assert!(MAP_16M.slot_b % SECTOR == 0);
    assert!(MAP_16M.slot_b + MAP_16M.slot_size <= MAP_16M.store_base);
    assert!(QMI_KEYSTORE_END <= QMI_FLASH_SIZE);
};

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;
    use std::string::{String, ToString};
    use std::vec;
    use std::vec::Vec;

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
        let boards: [(&str, &str, Map); 6] = [
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
                "rp2350_one_16m",
                include_str!("../../../boards/rp2350_one_16m.x"),
                MAP_16M,
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
            assert_eq!(fo + fl, XIP_BASE + map.slot_size, "{name}: FLASH end");
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
            assert_eq!(ko, XIP_BASE + map.keystore_start, "{name}: KEYSTORE origin");
            assert!(end <= ko, "{name}: reserved regions overlap the keystore");
            assert_eq!(ko + kl, XIP_BASE + map.keystore_end, "{name}: KEYSTORE end");
        }
    }

    /// `(name, start, size, bootloader permissions)` of every partition in
    /// a picotool partition-table JSON (`"start"`/`"size"` in KB).
    fn partitions(json: &str) -> Vec<(String, u32, u32, String)> {
        let field = |obj: &str, key: &str| -> Option<String> {
            let at = obj.find(&format!("\"{key}\""))? + key.len() + 2;
            let rest = obj[at..].trim_start().strip_prefix(':')?.trim_start();
            let rest = rest.strip_prefix('"')?;
            Some(rest[..rest.find('"')?].to_string())
        };
        let kb = |v: String| v.trim_end_matches(['K', 'k']).parse::<u32>().unwrap() * 1024;
        let list = &json[json.find("\"partitions\"").unwrap()..];
        list.split("\"name\"")
            .skip(1)
            .map(|obj| {
                let obj = format!("\"name\"{obj}");
                let perms = &obj[obj.find("\"permissions\"").unwrap()..];
                (
                    field(&obj, "name").unwrap(),
                    kb(field(&obj, "start").unwrap()),
                    kb(field(&obj, "size").unwrap()),
                    field(perms, "bootloader").unwrap(),
                )
            })
            .collect()
    }

    #[test]
    fn partition_tables_match_the_maps() {
        // Development tables leave the table's own sector (unpartitioned
        // space) open, so a dev board can always be taken back.  Production
        // tables make it read-only to the bootloader: BOOTSEL can neither
        // erase nor replace the table, yet can still program the firmware
        // slots (on RP2350 A2, BOOTSEL refuses every flash program unless
        // the bootloader can read unpartitioned space; FLASH_LAYOUT_2_0 §5.5).
        let tables: [(&str, &str, Map, &str); 4] = [
            (
                "pt_4m",
                include_str!("../../../boards/pt_4m.json"),
                MAP_4M,
                "rw",
            ),
            (
                "pt_16m",
                include_str!("../../../boards/pt_16m.json"),
                MAP_16M,
                "rw",
            ),
            (
                "pt_4m_prod",
                include_str!("../../../boards/pt_4m_prod.json"),
                MAP_4M,
                "r",
            ),
            (
                "pt_16m_prod",
                include_str!("../../../boards/pt_16m_prod.json"),
                MAP_16M,
                "r",
            ),
        ];
        for (name, json, map, unpartitioned_bl) in tables {
            let un = &json
                [json.find("\"unpartitioned\"").unwrap()..json.find("\"partitions\"").unwrap()];
            let bl = &un[un.find("\"bootloader\"").unwrap() + 12..];
            let bl = &bl[bl.find('"').unwrap() + 1..];
            assert_eq!(
                &bl[..bl.find('"').unwrap()],
                unpartitioned_bl,
                "{name}: unpartitioned bootloader access"
            );
            let parts = partitions(json);
            let get = |p: &str| {
                parts
                    .iter()
                    .find(|e| e.0 == p)
                    .unwrap_or_else(|| panic!("{name}: no {p}"))
                    .clone()
            };
            let mut slots = vec![("fw-a", SLOT_A)];
            if map.slot_b != 0 {
                slots.push(("fw-b", map.slot_b));
            } else {
                assert!(
                    parts.iter().all(|e| e.0 != "fw-b"),
                    "{name}: unexpected fw-b"
                );
            }
            for (slot, start) in slots {
                let (_, s, l, _) = get(slot);
                assert_eq!((s, l), (start, map.slot_size), "{name}: {slot}");
            }
            let b = map.store_base;
            let store = [
                ("binding", b, BINDING_SIZE),
                ("counters", b + 0x8000, RETRY_COUNTER_SIZE),
                ("rsa-pool", b + 0x1_8000, RSA_POOL_SIZE),
                ("spare", b + 0x2_4000, LEGACY_COUNTER_SIZE),
                (
                    "keystore",
                    map.keystore_start,
                    map.keystore_end - map.keystore_start,
                ),
            ];
            for (p, start, size) in store {
                let (_, s, l, bl) = get(p);
                assert_eq!((s, l), (start, size), "{name}: {p}");
                // Closed to BOOTSEL (picotool, UF2 writes).
                assert_eq!(bl, "", "{name}: {p} open to the bootloader");
            }
            // MIDPOINT_RULE: no closed partition holds the flash midpoint.
            let mid = map.flash_size / 2;
            for (p, s, l, bl) in &parts {
                assert!(
                    bl != "" || !(*s <= mid && mid < s + l),
                    "{name}: {p} holds the midpoint {mid:#x}"
                );
            }
        }
    }
}
