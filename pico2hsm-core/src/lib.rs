//! `pico2hsm-core` — Shared `no_std` types and traits for the pico2hsm HSM firmware.
//!
//! This crate is `no_std` compatible and is used by both the device firmware
//! and host-side tooling. All shared APDU types, error enums, storage traits,
//! and crypto key types live here so that specialist agents can work on
//! firmware and tools independently.
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap
)]
#![no_std]

pub mod apdu;
pub mod error;
pub mod flash;
pub mod key;
pub mod op;
pub mod protocol;
pub mod storage;

// Re-export the most commonly used items at crate root.
pub use apdu::{ApduCommand, ApduResponse};
pub use error::{AuthError, CryptoError, HsmError, ProtocolError, StorageError};
pub use flash::{FlashChip, MAX_CHIPS, PAGE_SIZE, SECTOR_SIZE};
pub use key::{AppletId, KeyId, KeyMaterial, KeyRecord, KeyType, PinSlot, MAX_KEY_BYTES};
pub use protocol::HsmProtocol;
pub use storage::{
    ChipState, DirectoryEntry, MirrorPair, MirrorState, ObjectHeader, DATA_START_SECTOR,
    DIRECTORY_SECTOR, SECTOR_MAGIC, WAL_SECTOR_0, WAL_SECTOR_1,
};
