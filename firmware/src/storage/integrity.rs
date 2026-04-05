//! BLAKE2s + CRC32 + seq_no integrity verification for keystore objects.
//!
//! Every key object stored on flash has two levels of integrity protection:
//!
//! 1. **CRC32** — covers the `ObjectHeader` bytes (excluding the crc32 field
//!    itself) plus the ciphertext. Detected during sector read without
//!    decryption. Fast to compute; catches bit errors and most corruption.
//!
//! 2. **BLAKE2s-256** — covers the *decrypted* plaintext. Verified after
//!    AES-GCM decryption. Catches fault injection or key-replacement attacks
//!    that might produce valid AES-GCM tags on wrong ciphertext.
//!
//! 3. **seq_no** — monotonic sequence number (0–255, wrapping). The storage
//!    manager tracks the last seen seq_no per key slot. A lower seq_no on
//!    read indicates a rollback attack attempt and is rejected.
//!
//! # On-disk sector layout
//! ```text
//! [0..4]    SECTOR_MAGIC (*b"P2HM")
//! [4..50]   ObjectHeader (magic, key_id, key_type, flags, plaintext_len,
//!                         sector_count, seq_no, crc32, blake2s[32])
//! [48..N]   AES-256-CTR ciphertext (N = 48 + roundup(plaintext_len, PAGE_SIZE))
//! ```
//! The `crc32` field in `ObjectHeader` covers bytes [0..header_end] (excluding
//! the crc32 field itself, i.e., bytes [0..40]) concatenated with the
//! ciphertext.  The blake2s field covers the decrypted plaintext only and is
//! verified by the key management layer after decryption.

use blake2::{Blake2s256, Digest};
use crc32fast::Hasher as Crc32Hasher;
use pico2hsm_core::{error::StorageError, storage::ObjectHeader};

// Byte offset of the `crc32` field within a serialised `ObjectHeader`.
// Layout: magic[4] + key_id[4] + key_type[1] + flags[1] + plaintext_len[2] +
//         sector_count[1] + seq_no[1]  = 14 bytes before crc32.
const HEADER_CRC32_OFFSET: usize = 14;
/// Total serialised header size in bytes.
///
/// Manual layout (not mem::size_of — repr(C) may insert padding):
///   magic[4] + key_id[4] + key_type[1] + flags[1] + plaintext_len[2]
///   + sector_count[1] + seq_no[1] + crc32[4] + blake2s[32] = 50 bytes.
pub const HEADER_SIZE: usize = 50;

// ─── Header serialisation helpers ────────────────────────────────────────────

/// Serialise an `ObjectHeader` into the first `HEADER_SIZE` bytes of `buf`.
///
/// Fields are stored little-endian as required by the on-disk format.
pub fn write_header(buf: &mut [u8], header: &ObjectHeader) {
    assert!(buf.len() >= HEADER_SIZE, "buffer too small for ObjectHeader");
    buf[0..4].copy_from_slice(&header.magic);
    buf[4..8].copy_from_slice(&header.key_id.to_le_bytes());
    buf[8] = header.key_type;
    buf[9] = header.flags;
    buf[10..12].copy_from_slice(&header.plaintext_len.to_le_bytes());
    buf[12] = header.sector_count;
    buf[13] = header.seq_no;
    buf[14..18].copy_from_slice(&header.crc32.to_le_bytes());
    buf[18..50].copy_from_slice(&header.blake2s);
}

/// Deserialise an `ObjectHeader` from the first `HEADER_SIZE` bytes of `buf`.
pub fn read_header(buf: &[u8]) -> Result<ObjectHeader, StorageError> {
    if buf.len() < HEADER_SIZE {
        return Err(StorageError::ReadError);
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&buf[0..4]);
    let key_id = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let key_type = buf[8];
    let flags = buf[9];
    let plaintext_len = u16::from_le_bytes([buf[10], buf[11]]);
    let sector_count = buf[12];
    let seq_no = buf[13];
    let crc32 = u32::from_le_bytes([buf[14], buf[15], buf[16], buf[17]]);
    let mut blake2s = [0u8; 32];
    blake2s.copy_from_slice(&buf[18..50]);

    Ok(ObjectHeader {
        magic,
        key_id,
        key_type,
        flags,
        plaintext_len,
        sector_count,
        seq_no,
        crc32,
        blake2s,
    })
}

// ─── CRC32 (header + ciphertext, no decryption required) ─────────────────────

/// Verify the CRC32 of an object header + ciphertext.
///
/// `header_bytes` is the raw serialised header (first `HEADER_SIZE` bytes of
/// the sector).  `ciphertext` is the payload bytes that follow immediately
/// after the header.
///
/// The CRC is computed over:
///   * header bytes [0..HEADER_CRC32_OFFSET]   — fields before the crc32 field
///   * header bytes [HEADER_CRC32_OFFSET+4..]  — fields after  the crc32 field
///   * ciphertext                               — the full encrypted blob
///
/// Returns `Err(StorageError::IntegrityFailure)` on mismatch.
pub fn verify_header_crc32(
    header_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<(), StorageError> {
    if header_bytes.len() < HEADER_SIZE {
        return Err(StorageError::IntegrityFailure);
    }
    let stored_crc = u32::from_le_bytes([
        header_bytes[HEADER_CRC32_OFFSET],
        header_bytes[HEADER_CRC32_OFFSET + 1],
        header_bytes[HEADER_CRC32_OFFSET + 2],
        header_bytes[HEADER_CRC32_OFFSET + 3],
    ]);
    let computed = compute_object_crc32(header_bytes, ciphertext);
    if computed == stored_crc {
        Ok(())
    } else {
        defmt::warn!(
            "integrity: CRC32 mismatch — stored 0x{:08X}, computed 0x{:08X}",
            stored_crc,
            computed,
        );
        Err(StorageError::IntegrityFailure)
    }
}

/// Compute the CRC32 of header + ciphertext for writing.
///
/// The CRC32 covers all header bytes except the 4-byte `crc32` field at
/// offset `HEADER_CRC32_OFFSET`, plus the full ciphertext.
pub fn compute_object_crc32(header_bytes: &[u8], ciphertext: &[u8]) -> u32 {
    let mut h = Crc32Hasher::new();
    // Feed the pre-crc32 header bytes.
    h.update(&header_bytes[..HEADER_CRC32_OFFSET]);
    // Skip the 4-byte crc32 field, then feed the remainder of the header.
    let after_crc32 = HEADER_CRC32_OFFSET + 4;
    if after_crc32 < header_bytes.len() {
        h.update(&header_bytes[after_crc32..]);
    }
    // Feed ciphertext.
    h.update(ciphertext);
    h.finalize()
}

// ─── BLAKE2s (plaintext, after decryption) ────────────────────────────────────

/// Verify the BLAKE2s-256 digest of decrypted plaintext.
///
/// `expected` is the `blake2s` field from the `ObjectHeader`.
/// `plaintext` is the decrypted key material.
///
/// Returns `Err(StorageError::IntegrityFailure)` on mismatch.
pub fn verify_plaintext_blake2s(
    expected: &[u8; 32],
    plaintext: &[u8],
) -> Result<(), StorageError> {
    let computed = compute_plaintext_blake2s(plaintext);
    // Constant-time comparison to avoid timing side-channels.
    use subtle::ConstantTimeEq;
    if computed.ct_eq(expected).into() {
        Ok(())
    } else {
        defmt::warn!("integrity: BLAKE2s plaintext digest mismatch");
        Err(StorageError::IntegrityFailure)
    }
}

/// Compute the BLAKE2s-256 digest of plaintext for writing.
pub fn compute_plaintext_blake2s(plaintext: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(plaintext);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ─── Sequence number rollback detection ──────────────────────────────────────

/// Check the sequence number for rollback detection.
///
/// `stored_seq_no` is the seq_no read from flash.
/// `last_seen_seq_no` is the highest seq_no previously committed for this key
/// slot (stored in the in-RAM directory; 0 = first write ever).
///
/// A write is considered valid when `stored_seq_no ==
/// last_seen_seq_no.wrapping_add(1)`, or when `last_seen_seq_no == 0`
/// (first write, any seq_no is accepted).
///
/// Returns `Err(StorageError::IntegrityFailure)` if the seq_no looks like
/// a rollback.
pub fn check_seq_no(stored_seq_no: u8, last_seen_seq_no: u8) -> Result<(), StorageError> {
    // Wrap-aware comparison: seq_no=0 after seq_no=255 is valid.
    let expected_next = last_seen_seq_no.wrapping_add(1);
    if last_seen_seq_no == 0 || stored_seq_no == expected_next {
        Ok(())
    } else {
        defmt::warn!(
            "integrity: seq_no rollback detected — stored {}, expected {}",
            stored_seq_no,
            expected_next,
        );
        Err(StorageError::IntegrityFailure)
    }
}

// ─── Magic + blank sector helpers ────────────────────────────────────────────

/// Verify magic bytes at start of a sector.
///
/// Returns `true` if the first 4 bytes match `SECTOR_MAGIC` (*b"P2HM").
pub fn verify_magic(sector_data: &[u8]) -> bool {
    sector_data.len() >= 4 && sector_data[0..4] == pico2hsm_core::storage::SECTOR_MAGIC
}

/// Check if a sector is blank (all `0xFF` — erased flash).
pub fn is_blank(sector_data: &[u8]) -> bool {
    sector_data.iter().all(|&b| b == 0xFF)
}

// ─── IntegrityChecker — OOP façade (per architecture spec) ───────────────────

/// Stateless integrity-check helper matching the spec API.
pub struct IntegrityChecker;

impl IntegrityChecker {
    /// Verify CRC32 of header + ciphertext in a full 4096-byte sector buffer.
    ///
    /// The header occupies the first `HEADER_SIZE` bytes; the ciphertext
    /// follows immediately and extends to the end of the sector (minus the
    /// trailing BLAKE2s digest and CRC32 appended by the write path).
    ///
    /// Returns `Ok(())` if CRC matches, `Err(StorageError::IntegrityFailure)`
    /// otherwise.
    pub fn verify_crc32(sector_data: &[u8; 4096]) -> Result<(), StorageError> {
        let header_bytes = &sector_data[..HEADER_SIZE];
        // Read plaintext_len to determine ciphertext extent.
        // plaintext_len is at bytes [10..12] (after magic[4] + key_id[4] + key_type[1] + flags[1]).
        let plaintext_len = u16::from_le_bytes([sector_data[10], sector_data[11]]) as usize;
        // Round up to PAGE_SIZE (256) boundary.
        let ciphertext_len = (plaintext_len + 255) & !255;
        let ciphertext_end = HEADER_SIZE + ciphertext_len;
        let ciphertext = if ciphertext_end <= 4096 {
            &sector_data[HEADER_SIZE..ciphertext_end]
        } else {
            &sector_data[HEADER_SIZE..]
        };
        verify_header_crc32(header_bytes, ciphertext)
    }

    /// Compute CRC32 of header + ciphertext for writing.
    pub fn compute_crc32(header: &ObjectHeader, ciphertext: &[u8]) -> u32 {
        let mut header_bytes = [0u8; HEADER_SIZE];
        write_header(&mut header_bytes, header);
        compute_object_crc32(&header_bytes, ciphertext)
    }

    /// Verify magic bytes at start of sector.
    pub fn verify_magic(sector_data: &[u8; 4096]) -> bool {
        verify_magic(sector_data)
    }

    /// Check if sector is blank (all `0xFF` — erased flash).
    pub fn is_blank(sector_data: &[u8; 4096]) -> bool {
        is_blank(sector_data)
    }

    /// Serialise an `ObjectHeader` to the first `HEADER_SIZE` bytes of a
    /// sector buffer.
    pub fn write_header(buf: &mut [u8; 4096], header: &ObjectHeader) {
        write_header(&mut buf[..], header)
    }

    /// Deserialise `ObjectHeader` from sector data.
    pub fn read_header(sector_data: &[u8; 4096]) -> Result<ObjectHeader, StorageError> {
        read_header(&sector_data[..])
    }
}
