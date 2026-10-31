//! The single definition of every board's internal (QMI) flash map.
//!
//! A [`Profile`] is one flash size's map (4 MB or 16 MB); a [`Board`] names
//! the profile and storage media it uses.  Linker scripts and partition
//! tables are rendered from these values, and [`validate`] checks them at
//! compile time.  Offsets are physical, from the start of flash.
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
pub mod render;

use core::fmt;

/// Erase-sector size of the QMI flash.
pub const SECTOR: u32 = 4096;
/// The partition table's own space at the start of flash (every board).
pub const PT_SIZE: u32 = 0x2000;
/// Physical start of slot A (every board).
pub const SLOT_A: u32 = PT_SIZE;
/// Partition id of the keystore partition (the store regions are 16..=19).
pub const KEYSTORE_ID: u8 = 20;

/// MIDPOINT_RULE.  Found on hardware (2026-10-14, LCD board 16 MB,
/// RP2350-One 4 MB): if a partition closed to the bootloader contains the
/// flash's midpoint (8 MB, 2 MB), the bootrom refuses every BOOTSEL write,
/// anywhere in flash, whether the partition starts there or straddles it;
/// one starting a sector past it does not.  So the sector at the midpoint
/// stays outside every closed partition.  [`validate`] enforces it.
pub const MIDPOINT_RULE: () = ();

/// RP2350-E10.  Erratum RP2350-E10's absolute block: picotool keeps the
/// last sector of flash out of every partition, so on the 16 MB profile the
/// keystore ends at least one [`SECTOR`] before `flash_size`.  [`validate`]
/// enforces it.
pub const RP2350_E10: () = ();

/// One closed store region.
#[derive(Clone, Copy, Debug)]
pub struct Region {
    /// Linker region name, e.g. `"BINDING"`.
    pub name: &'static str,
    /// Partition-table name, e.g. `"binding"`.
    pub partition: &'static str,
    /// Partition id.
    pub id: u8,
    /// Size in bytes.
    pub size: u32,
}

/// One flash size's map: table, firmware slot(s), store regions, keystore.
#[derive(Clone, Copy, Debug)]
pub struct Profile {
    /// `"4m"` or `"16m"`.
    pub name: &'static str,
    /// Flash size in bytes.
    pub flash_size: u32,
    /// Size of each firmware slot (the linker FLASH region length).
    pub slot_size: u32,
    /// Physical start of slot B (0: no slot B).
    pub slot_b: u32,
    /// First byte of the store regions (the binding ring).
    pub store_base: u32,
    /// Store regions in order from `store_base`: binding, counters,
    /// rsa-pool, spare.
    pub regions: &'static [Region],
    /// First byte of the keystore partition.
    pub keystore_start: u32,
    /// Exclusive end of the keystore partition.
    pub keystore_end: u32,
}

const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

impl Profile {
    /// Offset of the region whose partition name is `partition`:
    /// `store_base` plus the sizes of the regions before it.  Panics (a
    /// compile error in const context) on an unknown name.
    pub const fn region_offset(&self, partition: &str) -> u32 {
        let mut off = self.store_base;
        let mut i = 0;
        while i < self.regions.len() {
            if str_eq(self.regions[i].partition, partition) {
                return off;
            }
            off += self.regions[i].size;
            i += 1;
        }
        panic!("unknown region");
    }

    /// Sectors in the keystore partition.
    pub const fn keystore_sectors(&self) -> u32 {
        (self.keystore_end - self.keystore_start) / SECTOR
    }
}

const STORE_REGIONS: [Region; 4] = [
    Region {
        name: "BINDING",
        partition: "binding",
        id: 16,
        size: 8 * SECTOR,
    },
    Region {
        name: "RETRY_COUNTERS",
        partition: "counters",
        id: 17,
        size: 16 * SECTOR,
    },
    Region {
        name: "RSA_POOL",
        partition: "rsa-pool",
        id: 18,
        size: 12 * SECTOR,
    },
    // The version-1 counter log: migrated once, then erased and left spare.
    Region {
        name: "LEGACY_COUNTERS",
        partition: "spare",
        id: 19,
        size: 4 * SECTOR,
    },
];

/// Total size of the store regions (binding, counters, rsa-pool, spare).
const STORE_SIZE: u32 = 0x2_8000;

/// The 4 MB boards: one slot, the store regions at 0x1D8000, the keystore a
/// sector past the midpoint (MIDPOINT_RULE).  No slot B.
pub const PROFILE_4M: Profile = Profile {
    name: "4m",
    flash_size: 0x0040_0000,
    slot_size: 0x001D_8000 - SLOT_A,
    slot_b: 0,
    store_base: 0x001D_8000,
    regions: &STORE_REGIONS,
    keystore_start: 0x0020_1000,
    keystore_end: 0x0040_0000,
};

/// The 16 MB boards (QMI and SD variants): A/B slots of 4 MB less the
/// table, the store from 8 MB + 4 KB (MIDPOINT_RULE), the keystore one
/// sector short of the end (RP2350-E10).
pub const PROFILE_16M: Profile = Profile {
    name: "16m",
    flash_size: 0x0100_0000,
    slot_size: 0x0040_0000 - SLOT_A,
    slot_b: 0x0040_0000,
    store_base: 0x0080_1000,
    regions: &STORE_REGIONS,
    keystore_start: 0x0080_1000 + STORE_SIZE,
    keystore_end: 0x0100_0000 - SECTOR,
};

/// Every profile.
pub const PROFILES: [&Profile; 2] = [&PROFILE_4M, &PROFILE_16M];

const fn closed_ok(start: u32, end: u32, mid: u32) -> bool {
    !(start <= mid && mid < end)
}

/// Check a profile's invariants; panics (a compile error in const context)
/// on any violation.
pub const fn validate(p: &Profile) {
    // Sector aligned.
    assert!(p.slot_size % SECTOR == 0);
    assert!(p.store_base % SECTOR == 0);
    assert!(p.keystore_start % SECTOR == 0 && p.keystore_end % SECTOR == 0);
    // Slots: below the store, B after A.
    assert!(SLOT_A + p.slot_size <= p.store_base);
    if p.slot_b != 0 {
        assert!(p.slot_b % SECTOR == 0);
        assert!(SLOT_A + p.slot_size <= p.slot_b);
        assert!(p.slot_b + p.slot_size <= p.store_base);
    }
    // Regions: sector aligned, in order and disjoint (each starts where the
    // last ended), none holding the midpoint (MIDPOINT_RULE).
    let mid = p.flash_size / 2;
    let mut off = p.store_base;
    let mut i = 0;
    while i < p.regions.len() {
        let r = &p.regions[i];
        assert!(r.size % SECTOR == 0 && r.size > 0);
        assert!(closed_ok(off, off + r.size, mid));
        if str_eq(r.partition, "binding") {
            assert!(r.size / SECTOR >= 2); // BINDING_SECTORS >= 2
        }
        if str_eq(r.partition, "counters") {
            assert!(r.size / SECTOR >= 2); // RETRY_COUNTER_SECTORS >= 2
        }
        off += r.size;
        i += 1;
    }
    // The keystore follows the regions, lies inside flash, and does not
    // hold the midpoint.
    assert!(off <= p.keystore_start);
    assert!(p.keystore_start < p.keystore_end);
    assert!(p.keystore_end <= p.flash_size);
    assert!(closed_ok(p.keystore_start, p.keystore_end, mid));
    // RP2350-E10: on 16 MB the last sector stays out of the keystore.
    if p.flash_size >= 0x0100_0000 {
        assert!(p.keystore_end + SECTOR <= p.flash_size);
    }
}

const _: () = assert!(PT_SIZE % SECTOR == 0 && SLOT_A % SECTOR == 0);
const _: () = validate(&PROFILE_4M);
const _: () = validate(&PROFILE_16M);

/// Where a board keeps its keystore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Media {
    /// Internal QMI flash.
    Nor,
    /// Removable SD card (counters and RSA pool stay on internal flash).
    Sd,
}

/// A supported board, selected by its Cargo feature.
#[derive(Clone, Copy, Debug)]
pub struct Board {
    /// Cargo feature name.
    pub feature: &'static str,
    /// Flash map.
    pub profile: &'static Profile,
    /// Keystore media.
    pub media: Media,
    /// Wins over a lower-precedence board named at the same time.
    pub precedence: u8,
}

const fn b(
    feature: &'static str,
    profile: &'static Profile,
    media: Media,
    precedence: u8,
) -> Board {
    Board {
        feature,
        profile,
        media,
        precedence,
    }
}

/// Every board.
pub const BOARDS: [Board; 7] = [
    b("pico2_4m", &PROFILE_4M, Media::Nor, 0),
    b("rp2350_one_4m", &PROFILE_4M, Media::Nor, 0),
    // The firmware feature `rp2350_one_16m` turns on `rp2350_one_4m`.
    b("rp2350_one_16m", &PROFILE_16M, Media::Nor, 1),
    b("rp2350_geek_16m", &PROFILE_16M, Media::Nor, 0),
    b("rp2350_geek_sdcard", &PROFILE_16M, Media::Sd, 0),
    b("waveshare_rp2350_lcd_16m", &PROFILE_16M, Media::Nor, 0),
    b("waveshare_rp2350_lcd_sdcard", &PROFILE_16M, Media::Sd, 0),
];

/// The board with this feature name.
pub fn board(feature: &str) -> Option<&'static Board> {
    BOARDS.iter().find(|b| b.feature == feature)
}

/// The board with this feature name, in const context: panics (a compile
/// error in a const item) on an unknown name.
pub const fn board_const(feature: &str) -> &'static Board {
    let mut i = 0;
    while i < BOARDS.len() {
        if str_eq(BOARDS[i].feature, feature) {
            return &BOARDS[i];
        }
        i += 1;
    }
    panic!("unknown board feature");
}

/// Why no single board could be chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoardError {
    /// No board feature is active.
    None,
    /// Several unrelated board features are active (the names, in
    /// `BOARDS` order).
    Several([Option<&'static str>; 7]),
}

impl fmt::Display for BoardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoardError::None => f.write_str("no board feature is active"),
            BoardError::Several(names) => {
                f.write_str("several board features are active:")?;
                for n in names.iter().flatten() {
                    write!(f, " {n}")?;
                }
                Ok(())
            }
        }
    }
}

/// Pick the one board named by `active` (feature names; non-board names are
/// ignored).  `rp2350_one_16m` outranks `rp2350_one_4m`; any other pair is
/// an error.
pub fn resolve_board(active: &[&str]) -> Result<&'static Board, BoardError> {
    let mut found = [None::<&'static Board>; 7];
    let mut n = 0;
    for (i, bd) in BOARDS.iter().enumerate() {
        if active.contains(&bd.feature) {
            found[i] = Some(bd);
            n += 1;
        }
    }
    if n == 0 {
        return Err(BoardError::None);
    }
    // A board is shadowed by an active rp2350_one_16m only when it is the
    // 4 MB RP2350-One it implies.
    if let (Some(big), Some(_)) = (found[2], found[1]) {
        if big.precedence > BOARDS[1].precedence {
            found[1] = None;
            n -= 1;
        }
    }
    if n == 1 {
        return Ok(found.iter().flatten().next().unwrap());
    }
    let mut names = [None; 7];
    for (i, f) in found.iter().enumerate() {
        names[i] = f.map(|b| b.feature);
    }
    Err(BoardError::Several(names))
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    extern crate std;
    use super::*;
    use std::string::ToString;

    #[test]
    fn profile_4m_matches_the_shipped_map() {
        let p = &PROFILE_4M;
        assert_eq!(
            (p.flash_size, p.slot_size, p.slot_b, p.store_base),
            (0x40_0000, 0x1D_6000, 0, 0x1D_8000)
        );
        assert_eq!((p.keystore_start, p.keystore_end), (0x20_1000, 0x40_0000));
        assert_eq!(p.region_offset("binding"), 0x1D_8000);
        assert_eq!(p.region_offset("counters"), 0x1E_0000);
        assert_eq!(p.region_offset("rsa-pool"), 0x1F_0000);
        assert_eq!(p.region_offset("spare"), 0x1F_C000);
    }
    #[test]
    fn profile_16m_matches_the_shipped_map() {
        let p = &PROFILE_16M;
        assert_eq!(
            (p.flash_size, p.slot_size, p.slot_b, p.store_base),
            (0x100_0000, 0x3F_E000, 0x40_0000, 0x80_1000)
        );
        assert_eq!((p.keystore_start, p.keystore_end), (0x82_9000, 0xFF_F000));
        assert_eq!(p.region_offset("counters"), 0x80_9000);
        assert_eq!(p.region_offset("rsa-pool"), 0x81_9000);
        assert_eq!(p.region_offset("spare"), 0x82_5000);
    }
    #[test]
    fn region_sizes_and_ids() {
        for p in PROFILES {
            let r = p.regions;
            #[allow(unused_qualifications)]
            let got: std::vec::Vec<_> = r
                .iter()
                .map(|r| (r.name, r.partition, r.id, r.size))
                .collect();
            assert_eq!(
                got,
                std::vec![
                    ("BINDING", "binding", 16, 0x8000),
                    ("RETRY_COUNTERS", "counters", 17, 0x10000),
                    ("RSA_POOL", "rsa-pool", 18, 0xC000),
                    ("LEGACY_COUNTERS", "spare", 19, 0x4000),
                ]
            );
            assert_eq!(KEYSTORE_ID, 20);
        }
        assert_eq!(PROFILE_4M.keystore_sectors(), 0x1FF000 / SECTOR);
    }
    #[test]
    fn every_board_has_its_profile() {
        let want = [
            ("pico2_4m", "4m", Media::Nor),
            ("rp2350_one_4m", "4m", Media::Nor),
            ("rp2350_one_16m", "16m", Media::Nor),
            ("rp2350_geek_16m", "16m", Media::Nor),
            ("waveshare_rp2350_lcd_16m", "16m", Media::Nor),
            ("rp2350_geek_sdcard", "16m", Media::Sd),
            ("waveshare_rp2350_lcd_sdcard", "16m", Media::Sd),
        ];
        assert_eq!(BOARDS.len(), want.len());
        for (f, prof, media) in want {
            let b = board(f).unwrap();
            assert_eq!((b.profile.name, b.media), (prof, media), "{f}");
        }
    }
    #[test]
    fn one_16m_wins_over_one_4m() {
        assert_eq!(
            resolve_board(&["rp2350_one_4m", "rp2350_one_16m"])
                .unwrap()
                .feature,
            "rp2350_one_16m"
        );
    }
    #[test]
    fn no_board_is_an_error() {
        assert!(matches!(resolve_board(&[]), Err(BoardError::None)));
    }
    #[test]
    fn unknown_names_are_not_boards() {
        assert!(matches!(
            resolve_board(&["rsa", "applet-piv"]),
            Err(BoardError::None)
        ));
        assert_eq!(
            resolve_board(&["rsa", "pico2_4m"]).unwrap().feature,
            "pico2_4m"
        );
    }
    #[test]
    fn two_boards_are_an_error_naming_both() {
        let e = resolve_board(&["pico2_4m", "rp2350_geek_16m"]).unwrap_err();
        let s = e.to_string();
        assert!(s.contains("pico2_4m") && s.contains("rp2350_geek_16m"));
    }
    #[test]
    fn board_const_finds_every_board() {
        const B: &Board = board_const("rp2350_geek_sdcard");
        assert_eq!((B.profile.name, B.media), ("16m", Media::Sd));
        for bd in &BOARDS {
            assert_eq!(board_const(bd.feature).feature, bd.feature);
        }
    }
    #[test]
    #[should_panic(expected = "unknown board feature")]
    fn board_const_panics_on_unknown() {
        board_const("pico2_4mm");
    }
    #[test]
    fn unknown_feature_is_ignored_by_lookup() {
        assert!(board("pico2_4mm").is_none());
    }
}
