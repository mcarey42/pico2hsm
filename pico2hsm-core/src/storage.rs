//! On-flash storage layout constants and metadata structures.
//!
//! Defines the binary format of every persistent structure written to flash.
//! All multi-byte integers are little-endian. Structures are `#[repr(C)]` to
//! give a stable ABI that the integrity checker can hash deterministically.
//!
//! Sector layout per chip (4 KiB sectors):
//!   Sector 0  — Directory (list of DirectoryEntry records)
//!   Sector 1  — WAL slot 0 (write-ahead log)
//!   Sector 2  — WAL slot 1 (write-ahead log, alternate)
//!   Sector 3+ — Key object data sectors

/// Magic bytes that begin every key object sector header.
///
/// ASCII "P2HM" (pico2hsm marker). Checked by the integrity scanner at boot
/// and after every RAID resync.
pub const SECTOR_MAGIC: [u8; 4] = *b"P2HM";

/// Sector number of the keystore directory within each chip.
pub const DIRECTORY_SECTOR: u32 = 0;

/// Sector number of WAL slot 0 within each chip.
pub const WAL_SECTOR_0: u32 = 1;

/// Sector number of WAL slot 1 within each chip.
pub const WAL_SECTOR_1: u32 = 2;

/// First sector available for key object data.
pub const DATA_START_SECTOR: u32 = 3;

// ---------------------------------------------------------------------------
// ObjectHeader — first 48 bytes of every key object sector
// ---------------------------------------------------------------------------

/// On-flash header for a key object sector chain.
///
/// Immediately follows the `SECTOR_MAGIC` at byte 0 of the first sector
/// assigned to this key object. The encrypted ciphertext follows immediately
/// after this structure (no padding).
///
/// Total header size: 4 (magic) + 44 bytes = 48 bytes.
/// The magic is NOT included in this struct; it is checked separately.
#[repr(C)]
pub struct ObjectHeader {
    /// SECTOR_MAGIC — *b"P2HM". Redundantly stored for alignment convenience.
    pub magic: [u8; 4],
    /// Key object identifier (matches DirectoryEntry::key_id).
    pub key_id: u16,
    /// Algorithm tag byte (see KeyType discriminant mapping in firmware).
    pub key_type: u8,
    /// Access flags bitfield.
    pub flags: u8,
    /// Length of the plaintext key material in bytes.
    pub plaintext_len: u16,
    /// Number of consecutive sectors allocated to this object (1 for most keys,
    /// 2 for RSA-4096 which exceeds a single 4 KiB sector after encryption).
    pub sector_count: u8,
    /// Monotonic sequence number (0–255, wraps). Used by WAL replay to
    /// identify the most recent committed version of a key object.
    pub seq_no: u8,
    /// CRC32 of (ObjectHeader bytes 0..12 || ciphertext). Checked on every read.
    pub crc32: u32,
    /// BLAKE2s-256 digest of the *decrypted* plaintext. Checked after decrypt.
    pub blake2s: [u8; 32],
}

// ---------------------------------------------------------------------------
// DirectoryEntry — entry in the per-chip directory sector
// ---------------------------------------------------------------------------

/// One entry in the keystore directory (Sector 0 of each chip).
///
/// The directory sector holds up to `(SECTOR_SIZE - 8) / size_of::<DirectoryEntry>()`
/// entries, preceded by an 8-byte header (magic + entry count + CRC16).
/// A `key_id` of `0xFFFF` marks an empty/erased slot.
#[repr(C)]
pub struct DirectoryEntry {
    /// Key object identifier. `0xFFFF` = empty slot.
    pub key_id: u16,
    /// Index of the chip that holds this key's data sectors (0–7).
    pub chip_index: u8,
    /// First data sector number on that chip (relative to chip base).
    pub sector_index: u32,
    /// Number of consecutive sectors allocated to this object.
    pub sector_count: u8,
    /// Flags (bit 0 = tombstone/deleted, bits 1–7 reserved).
    pub flags: u8,
    /// Alignment padding — must be written as 0x00.
    pub _pad: [u8; 1],
}

// ---------------------------------------------------------------------------
// Chip and mirror state
// ---------------------------------------------------------------------------

/// Health state of a single flash chip as tracked by the StorageManager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipState {
    /// Chip is present, responding, and passing all integrity checks.
    Healthy,
    /// Chip is present but has exceeded erase-cycle estimates or has bad sectors.
    Degraded,
    /// Chip is present and a resync from its mirror partner is in progress.
    Resyncing {
        /// The last sector that was successfully written during resync.
        progress_sector: u32,
    },
    /// Chip is permanently dead and cannot be used.
    Dead,
    /// Chip is not electrically present (SPI not responding, JEDEC ID fails).
    NotPresent,
    /// Chip is present and responding but has never been formatted.
    Blank,
}

/// State of a RAID-1 mirror pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorState {
    /// Both members are healthy and in sync.
    InSync,
    /// One member has failed; operating in single-copy mode.
    Degraded {
        /// Index of the chip that has failed (0–7).
        failed_member: u8,
    },
    /// A previously failed/replaced member is being resynchronised.
    Resyncing {
        /// Sector number last successfully written to the recovering member.
        progress_sector: u32,
    },
}

/// A RAID-1 mirror pair definition.
///
/// The storage manager maintains one `MirrorPair` per pair of chips.
/// The primary is always on SPI0 (chip indices 0–3) and the mirror is on
/// SPI1 (chip indices 4–7) at the matching bus position.
pub struct MirrorPair {
    /// Chip index of the primary (SPI0 side, 0–3).
    pub primary: u8,
    /// Chip index of the mirror (SPI1 side, 4–7).
    pub mirror: u8,
    /// Current synchronisation state of this pair.
    pub state: MirrorState,
}
