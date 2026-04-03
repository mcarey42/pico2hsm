//! `pico2hsm-core` — Shared no_std types and traits for the pico2hsm HSM firmware.
//!
//! This crate is `no_std` compatible and is used by both the device firmware
//! and host-side tooling. All shared APDU types, error enums, storage traits,
//! and crypto key types live here so that specialist agents can work on
//! firmware and tools independently.
#![no_std]

pub mod apdu;
pub mod error;
pub mod flash;
pub mod key;
pub mod protocol;
pub mod storage;

// Re-export the most commonly used items at crate root.
pub use apdu::{ApduCommand, ApduResponse};
pub use error::{AuthError, CryptoError, HsmError, ProtocolError, StorageError};
pub use flash::{FlashChip, MAX_CHIPS, PAGE_SIZE, SECTOR_SIZE};
pub use key::{KeyId, KeyMaterial, KeyRecord, KeyType, MAX_KEY_BYTES};
pub use protocol::HsmProtocol;
pub use storage::{
    ChipState, DirectoryEntry, MirrorPair, MirrorState, ObjectHeader, DATA_START_SECTOR,
    DIRECTORY_SECTOR, SECTOR_MAGIC, WAL_SECTOR_0, WAL_SECTOR_1,
};
