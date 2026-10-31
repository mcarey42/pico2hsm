//! Internal (QMI) flash map of this build's board.
//!
//! The map is defined once, in the `pico2hsm-layout` crate (profiles,
//! boards, compile-time validation; docs/FLASH_LAYOUT_2_0.md describes
//! it).  `build.rs` resolves the active board feature and passes it as
//! `PICO2HSM_BOARD`; the constants here are that board's profile, under the
//! names the firmware has always used.  The same crate renders `memory.x`
//! (the linker FLASH region ends at the slot's end, [`FIRMWARE_END`], so an
//! image that grew into the store fails to link) and the partition tables
//! under `boards/`.
//!
//! The retry-counter log and the RSA key pool live on internal flash on
//! *every* board, the SD-card boards included: a removable card must not
//! hold the PIN retry counters.

use pico2hsm_layout::Board;

pub use pico2hsm_layout::{MIDPOINT_RULE, PT_SIZE, SECTOR, SLOT_A};

/// One flash size's map (a `pico2hsm-layout` profile).
pub type Map = pico2hsm_layout::Profile;

/// The 4 MB map (Pico 2, RP2350-One).
pub const MAP_4M: Map = pico2hsm_layout::PROFILE_4M;

/// The 16 MB map (Geek, Waveshare LCD, RP2350-One 16 MB; QMI and SD).
pub const MAP_16M: Map = pico2hsm_layout::PROFILE_16M;

/// This build's board, resolved by `build.rs`.
pub const BOARD: &Board = pico2hsm_layout::board_const(env!("PICO2HSM_BOARD"));

/// This build's map.
pub const MAP: Map = *BOARD.profile;

/// Whether this build is for a 16 MB board.
pub const FLASH_16M: bool = BOARD.profile.flash_size == 0x100_0000;

/// Exclusive end of the firmware image (end of the linker FLASH region).
pub const FIRMWARE_END: u32 = MAP.slot_size;

/// Size of the store region whose partition name is `partition` (a
/// compile error if there is none).
const fn region_size(partition: &str) -> u32 {
    let (want, mut i) = (partition.as_bytes(), 0);
    while i < MAP.regions.len() {
        let r = &MAP.regions[i];
        let name = r.partition.as_bytes();
        if name.len() == want.len() {
            let mut j = 0;
            while j < name.len() && name[j] == want[j] {
                j += 1;
            }
            if j == name.len() {
                return r.size;
            }
        }
        i += 1;
    }
    panic!("unknown region");
}

/// First byte of the Storage V2 binding block ring (STORAGE_V2 §8.1).
pub const BINDING_OFFSET: u32 = MAP.region_offset("binding");

/// Bytes in the binding block ring.
pub const BINDING_SIZE: u32 = region_size("binding");

/// Sectors in the binding block ring (R8: host-drivable resets each write
/// the binding; eight sectors last ~800 000 writes).
pub const BINDING_SECTORS: u32 = BINDING_SIZE / SECTOR;

/// First byte of the counter log (version 2: retry counters, device
/// values, the keystore anchor).
pub const RETRY_COUNTER_OFFSET: u32 = MAP.region_offset("counters");

/// Bytes in the counter log.
pub const RETRY_COUNTER_SIZE: u32 = region_size("counters");

/// Sectors in the counter log (rotated; at least two, so the sector being
/// erased is never the one holding the current records).
pub const RETRY_COUNTER_SECTORS: u32 = RETRY_COUNTER_SIZE / SECTOR;

/// First byte of the RSA key pool region.
pub const RSA_POOL_OFFSET: u32 = MAP.region_offset("rsa-pool");

/// Bytes in the RSA key pool region.
pub const RSA_POOL_SIZE: u32 = region_size("rsa-pool");

/// Sectors in the RSA key pool (one pooled key per sector).
pub const RSA_POOL_SECTORS: u32 = RSA_POOL_SIZE / SECTOR;

/// First byte of the version-1 counter log (1.x layout), migrated into the
/// version-2 log once at boot and then erased.  On the 16 MB boards it is
/// a blank placeholder (no 1.x log was ever there).
pub const LEGACY_COUNTER_OFFSET: u32 = MAP.region_offset("spare");

/// Bytes in the version-1 counter log.
pub const LEGACY_COUNTER_SIZE: u32 = region_size("spare");

/// Sectors in the version-1 counter log.
pub const LEGACY_COUNTER_SECTORS: u32 = LEGACY_COUNTER_SIZE / SECTOR;

/// Start of the keystore partition on the QMI boards.
pub const QMI_KEYSTORE_OFFSET: u32 = MAP.keystore_start;

/// Exclusive end of the keystore partition on the QMI boards.
pub const QMI_KEYSTORE_END: u32 = MAP.keystore_end;

/// Flash size of this build's board.
pub const QMI_FLASH_SIZE: u32 = MAP.flash_size;

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use pico2hsm_layout::render::{partition_json, table_file_name, Table};
    use pico2hsm_layout::{PROFILE_16M, PROFILE_4M};

    #[test]
    fn this_board_matches_its_profile() {
        let p = BOARD.profile;
        assert_eq!(BOARD.feature, env!("PICO2HSM_BOARD"));
        assert_eq!(FLASH_16M, p.flash_size == 0x100_0000);
        assert_eq!(MAP.flash_size, p.flash_size);
        assert_eq!(MAP.slot_size, p.slot_size);
        assert_eq!(MAP.slot_b, p.slot_b);
        assert_eq!(FIRMWARE_END, p.slot_size);
        assert_eq!(BINDING_OFFSET, p.region_offset("binding"));
        assert_eq!(BINDING_OFFSET, p.store_base);
        assert_eq!(RETRY_COUNTER_OFFSET, p.region_offset("counters"));
        assert_eq!(RSA_POOL_OFFSET, p.region_offset("rsa-pool"));
        assert_eq!(LEGACY_COUNTER_OFFSET, p.region_offset("spare"));
        let size = |part: &str| {
            p.regions
                .iter()
                .find(|r| r.partition == part)
                .expect(part)
                .size
        };
        assert_eq!(BINDING_SIZE, size("binding"));
        assert_eq!(RETRY_COUNTER_SIZE, size("counters"));
        assert_eq!(RSA_POOL_SIZE, size("rsa-pool"));
        assert_eq!(LEGACY_COUNTER_SIZE, size("spare"));
        assert_eq!(BINDING_SIZE, BINDING_SECTORS * SECTOR);
        assert_eq!(RETRY_COUNTER_SIZE, RETRY_COUNTER_SECTORS * SECTOR);
        assert_eq!(RSA_POOL_SIZE, RSA_POOL_SECTORS * SECTOR);
        assert_eq!(LEGACY_COUNTER_SIZE, LEGACY_COUNTER_SECTORS * SECTOR);
        assert_eq!(QMI_KEYSTORE_OFFSET, p.keystore_start);
        assert_eq!(QMI_KEYSTORE_END, p.keystore_end);
        assert_eq!(QMI_FLASH_SIZE, p.flash_size);
        assert_eq!((SECTOR, PT_SIZE, SLOT_A), (4096, 0x2000, 0x2000));
        assert_eq!(MAP_4M.flash_size, PROFILE_4M.flash_size);
        assert_eq!(MAP_16M.flash_size, PROFILE_16M.flash_size);
    }

    #[test]
    fn committed_tables_match_the_generator() {
        let committed = [
            ("pt_4m.json", include_str!("../../../boards/pt_4m.json")),
            ("pt_16m.json", include_str!("../../../boards/pt_16m.json")),
            (
                "pt_4m_prod.json",
                include_str!("../../../boards/pt_4m_prod.json"),
            ),
            (
                "pt_16m_prod.json",
                include_str!("../../../boards/pt_16m_prod.json"),
            ),
        ];
        for p in [&PROFILE_4M, &PROFILE_16M] {
            for t in [Table::Dev, Table::Prod] {
                let name = table_file_name(p, t);
                let (_, json) = committed
                    .iter()
                    .find(|(n, _)| *n == name)
                    .unwrap_or_else(|| panic!("no committed {name}"));
                assert_eq!(*json, partition_json(p, t), "{name}");
            }
        }
    }
}
