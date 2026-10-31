//! Keystore geometry, shared with the Storage V2 engine
//! (`firmware/src/storage/store_v2.rs` uses these constants), and the
//! SC-HSM key cap computed from it.
//!
//! # What the cap promises
//! [`max_sc_hsm_keys`] is the number of SC-HSM user keys a board can hold,
//! each with [`OBJECTS_PER_KEY`] objects (the key, its descriptor and its
//! certificate; a symmetric key has a sidecar instead of a certificate),
//! while every other object the firmware can store is present too
//! ([`NON_SC_HSM_OBJECTS`]), and with the store still able to replace any
//! object and complete a checkpoint.  Every object takes one sector.
//!
//! # The store's reserves (store_v2: `put`, `checkpoint`)
//! With `M` live objects and `D` data sectors:
//! - the current snapshot holds `ceil(M / 168)` sectors, and a checkpoint
//!   writes the new one before it erases the old: another `ceil(M / 168)`
//!   ([`snapshot_reserve`]);
//! - a PUT writes the new version before it erases the old one, and it
//!   first checks `free >= ceil((live_estimate + 1) / 168) + 1 (+ 1 for a
//!   new key ID)`, where `live_estimate` adds the tail's records (fewer
//!   than the checkpoint threshold, 128 on NOR / 64 on SD, both below 168)
//!   to the snapshot's entries: at most one snapshot sector more than
//!   `ceil(M / 168)`.  For the `M`-th object (from `M - 1` live) and for a
//!   replacement at `M` live this asks `D >= M + 2 * ceil(M / 168) + 2`:
//!   [`MAINTENANCE_RESERVE`] is that 2 (one sector for the new version,
//!   one for the over-estimate).
//!
//! # Not covered
//! A host that spends key slots on standalone files instead (each with a
//! sidecar), or gives symmetric keys certificates, can fill the store
//! before the cap: the next new object fails with 6A84 (the store's own
//! reserve check), nothing is lost.

use core::fmt;

use crate::{Board, Media};

// ─── Engine geometry ─────────────────────────────────────────────────────────

/// Journal ring sectors on NOR flash.
pub const NOR_RING_SECTORS: u32 = 16;
/// Journal ring sectors on an SD card.
pub const SD_RING_SECTORS: u32 = 64;
/// Snapshot entries per sector: (4096 - 64-byte header) / 24-byte entry.
pub const SNAP_ENTRIES_PER_SECTOR: u32 = 168;
/// Most snapshot sectors in a chain.
pub const MAX_SNAPSHOT_SECTORS: u32 = 32;
/// Most data sectors the allocation bitmap tracks.
pub const MAX_DATA_SECTORS: u32 = 4096;
/// Tail records that trigger a checkpoint on NOR flash.
pub const NOR_CHECKPOINT_TAIL: u32 = 128;
/// Tail records that trigger a checkpoint on an SD card.
pub const SD_CHECKPOINT_TAIL: u32 = 64;

// MAINTENANCE_RESERVE relies on the tail adding at most one snapshot
// sector to a PUT's estimate.
const _: () = assert!(NOR_CHECKPOINT_TAIL <= SNAP_ENTRIES_PER_SECTOR);
const _: () = assert!(SD_CHECKPOINT_TAIL <= SNAP_ENTRIES_PER_SECTOR);
const _: () = assert!(SNAP_ENTRIES_PER_SECTOR == (crate::SECTOR - 64) / 24);

/// Sectors past the two snapshots a full store keeps free (module docs).
pub const MAINTENANCE_RESERVE: u32 = 2;

// ─── Object budget ───────────────────────────────────────────────────────────

/// Objects per SC-HSM key: the key, its descriptor (C4), its certificate
/// (CE) — or, for a symmetric key, its object-ID sidecar instead.
pub const OBJECTS_PER_KEY: u32 = 3;
/// SC-HSM user key refs 0x01..=0xFB (below the reserved 0xFC..=0xFF): the
/// highest cap.
pub const SC_HSM_KEY_REFS: u32 = 251;

// Each term below is asserted against the firmware's own constants (the
// firmware's `storage::cap_budget`).
//
// | term                       | n  | source                                 |
// |----------------------------|----|----------------------------------------|
// | PIV key slots              | 24 | MAX_PIV_KEYS (9A 9C 9D 9E, 82..=95)    |
// | PIV data objects on flash  | 36 | 5FC101..=5FC123 and 7E (put_data; RAM  |
// |                            |    | caches MAX_PIV_DATA_OBJECTS = 4)       |
// | PIV PIN/PUK record, 9B key |  2 | piv_pin_key_id, piv_mgmt_key_id        |
// | OpenPGP key slots          |  3 | SLOT_SIG, SLOT_DEC, SLOT_AUTH          |
// | OpenPGP data objects       | 20 | PERSISTED_TAGS (19) + the legacy       |
// |                            |    | signature-counter record               |
// | OpenPGP PW1, PW3 records   |  2 | OPENPGP_PW1_KEY_ID, OPENPGP_PW3_KEY_ID |
// | SC-HSM reserved refs       |  4 | RESERVED_KEY_REF_MIN..=0xFF            |
// | SC-HSM standalone files    | 18 | key index room past keys and reserved  |
// |                            |    | refs: SC_HSM_FREE_FILES + rounding     |
// | domain member slots        | 32 | MAX_MEMBERS                            |
// | domain pinned peer         |  1 | PINNED_PEER                            |
// | domain file sidecars       | 18 | one per standalone file                |

/// PIV key slots.
pub const PIV_KEY_SLOTS: u32 = 24;
/// PIV data objects flash can hold (5FC101..=5FC123, 7E).
pub const PIV_DATA_OBJECTS: u32 = 0x23 + 1;
/// PIV records: PIN/PUK, management key.
pub const PIV_RECORDS: u32 = 2;
/// Everything PIV stores.
pub const PIV_OBJECTS: u32 = PIV_KEY_SLOTS + PIV_DATA_OBJECTS + PIV_RECORDS;

/// OpenPGP key slots.
pub const OPENPGP_KEY_SLOTS: u32 = 3;
/// OpenPGP data objects: the persisted DOs and the legacy signature
/// counter record.
pub const OPENPGP_DATA_OBJECTS: u32 = 19 + 1;
/// OpenPGP PW1 and PW3 records.
pub const OPENPGP_PW_RECORDS: u32 = 2;
/// Everything OpenPGP stores.
pub const OPENPGP_OBJECTS: u32 = OPENPGP_KEY_SLOTS + OPENPGP_DATA_OBJECTS + OPENPGP_PW_RECORDS;

/// SC-HSM reserved records at key refs 0xFC..=0xFF.
pub const SC_HSM_RESERVED_OBJECTS: u32 = 4;
/// Free-standing SC-HSM files the key index always has room for.
pub const SC_HSM_FREE_FILES: u32 = 11;
/// The key index is sized in multiples of this many entries.
pub const KEY_INDEX_ROUND: u32 = 8;
/// Standalone SC-HSM files the index can admit past the keys and the
/// reserved records: the free files plus up to `KEY_INDEX_ROUND - 1` from
/// rounding.
pub const SC_HSM_FILE_OBJECTS: u32 = SC_HSM_FREE_FILES + KEY_INDEX_ROUND - 1;

/// Domain member-list slots.
pub const DOMAIN_MEMBERS: u32 = 32;
/// Domain records: member slots, the pinned peer, and a sidecar for each
/// standalone SC-HSM file.
pub const DOMAIN_OBJECTS: u32 = DOMAIN_MEMBERS + 1 + SC_HSM_FILE_OBJECTS;

/// Every object that is not one of an SC-HSM key's [`OBJECTS_PER_KEY`].
pub const NON_SC_HSM_OBJECTS: u32 =
    PIV_OBJECTS + OPENPGP_OBJECTS + SC_HSM_RESERVED_OBJECTS + SC_HSM_FILE_OBJECTS + DOMAIN_OBJECTS;

/// Capacity of the SC-HSM key/EF index for a key cap: every key's
/// objects, the reserved records and [`SC_HSM_FREE_FILES`], rounded up to
/// [`KEY_INDEX_ROUND`] (400 for 128 keys, 768 for 251).
pub const fn key_index_capacity(cap: u32) -> u32 {
    let n = cap * OBJECTS_PER_KEY + SC_HSM_RESERVED_OBJECTS + SC_HSM_FREE_FILES;
    n.div_ceil(KEY_INDEX_ROUND) * KEY_INDEX_ROUND
}

// The index never admits more SC-HSM objects than the budget counts.
const _: () = {
    let mut cap = 0;
    while cap <= SC_HSM_KEY_REFS {
        assert!(
            key_index_capacity(cap)
                <= cap * OBJECTS_PER_KEY + SC_HSM_RESERVED_OBJECTS + SC_HSM_FILE_OBJECTS
        );
        cap += 1;
    }
};

// ─── The cap ─────────────────────────────────────────────────────────────────

/// Most live objects with `cap` SC-HSM keys.
pub const fn max_live_objects(cap: u32) -> u32 {
    cap * OBJECTS_PER_KEY + NON_SC_HSM_OBJECTS
}

/// Sectors the snapshots of `live` objects need: the current one and the
/// one a checkpoint writes before erasing it.
pub const fn snapshot_reserve(live: u32) -> u32 {
    2 * live.div_ceil(SNAP_ENTRIES_PER_SECTOR)
}

/// Data sectors the store needs for `cap` keys (module docs).
pub const fn sectors_needed(cap: u32) -> u32 {
    let live = max_live_objects(cap);
    live + snapshot_reserve(live) + MAINTENANCE_RESERVE
}

/// Data sectors of a board's keystore: past the journal ring, at most
/// what the bitmap tracks.  An SD card's size is not known at build time:
/// its keystore is taken as `MAX_DATA_SECTORS - SD_RING_SECTORS` (cards
/// are far larger).
pub const fn data_sectors(b: &Board) -> u32 {
    match b.media {
        Media::Sd => MAX_DATA_SECTORS - SD_RING_SECTORS,
        Media::Nor => {
            let d = b.profile.keystore_sectors() - NOR_RING_SECTORS;
            if d < MAX_DATA_SECTORS {
                d
            } else {
                MAX_DATA_SECTORS
            }
        }
    }
}

/// SC-HSM user keys `b` can hold: the largest cap, at most
/// [`SC_HSM_KEY_REFS`], whose [`sectors_needed`] fit [`data_sectors`] —
/// `min(251, (D - snapshot_reserve - MAINTENANCE_RESERVE -
/// NON_SC_HSM_OBJECTS) / OBJECTS_PER_KEY)` with the snapshot reserve taken
/// at that cap.
pub const fn max_sc_hsm_keys(b: &Board) -> u32 {
    let d = data_sectors(b);
    let mut cap = SC_HSM_KEY_REFS;
    while cap > 0 && sectors_needed(cap) > d {
        cap -= 1;
    }
    cap
}

// SD boards hold every key ref; no board's snapshot outgrows its chain.
const _: () = assert!(sectors_needed(SC_HSM_KEY_REFS) <= MAX_DATA_SECTORS - SD_RING_SECTORS);
const _: () =
    assert!(max_live_objects(SC_HSM_KEY_REFS) <= MAX_SNAPSHOT_SECTORS * SNAP_ENTRIES_PER_SECTOR);
const _: () = {
    let mut i = 0;
    while i < crate::BOARDS.len() {
        assert!(max_sc_hsm_keys(&crate::BOARDS[i]) > 0);
        i += 1;
    }
};

/// A `PICO2HSM_MAX_SC_HSM_KEYS` value the board cannot take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapError {
    /// Not a decimal number.
    NotANumber {
        /// The board's cap.
        bound: u32,
    },
    /// 0, or past the board's cap.
    OutOfRange {
        /// The value given.
        value: u32,
        /// The board's cap.
        bound: u32,
    },
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapError::NotANumber { bound } => write!(
                f,
                "PICO2HSM_MAX_SC_HSM_KEYS is not a number: give 1 to {bound} (this board's cap)"
            ),
            CapError::OutOfRange { value, bound } => write!(
                f,
                "PICO2HSM_MAX_SC_HSM_KEYS={value} is out of range: give 1 to {bound} (this board's cap)"
            ),
        }
    }
}

/// The key cap: `bound`, or a lower `override_value`
/// (`PICO2HSM_MAX_SC_HSM_KEYS`) from 1 to `bound`.
pub fn checked_cap(override_value: Option<&str>, bound: u32) -> Result<u32, CapError> {
    let Some(s) = override_value else {
        return Ok(bound);
    };
    let value: u32 = s
        .trim()
        .parse()
        .map_err(|_| CapError::NotANumber { bound })?;
    if value == 0 || value > bound {
        return Err(CapError::OutOfRange { value, bound });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    extern crate std;
    use super::*;
    use crate::{Media, BOARDS};
    use std::string::ToString;

    #[test]
    fn checked_cap_takes_the_bound_or_a_lower_override() {
        assert_eq!(checked_cap(None, 140), Ok(140));
        assert_eq!(checked_cap(Some("100"), 140), Ok(100));
        assert_eq!(checked_cap(Some("140"), 140), Ok(140));
    }
    #[test]
    fn checked_cap_refuses_zero_too_large_and_junk_naming_the_bound() {
        for bad in ["0", "141", "x", "", "-1"] {
            let e = checked_cap(Some(bad), 140).unwrap_err();
            assert!(e.to_string().contains("140"), "{bad}: {e}");
        }
    }
    #[test]
    fn caps_per_board() {
        for b in &BOARDS {
            let cap = max_sc_hsm_keys(b);
            std::println!("{}: SC-HSM key cap {cap}", b.feature);
            if b.media == Media::Sd || b.profile.name == "16m" {
                assert_eq!(cap, 251, "{}", b.feature);
            } else {
                assert!((100..=251).contains(&cap), "{}: {cap}", b.feature);
            }
        }
    }
    #[test]
    fn key_index_keeps_todays_sizes() {
        assert_eq!(key_index_capacity(128), 400);
        assert_eq!(key_index_capacity(251), 768);
        for cap in 0..=SC_HSM_KEY_REFS {
            assert!(key_index_capacity(cap) >= cap * OBJECTS_PER_KEY + 4);
        }
    }
}
