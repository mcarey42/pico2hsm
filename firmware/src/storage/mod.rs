//! Persistent storage (docs/STORAGE_V2.md).
//!
//! ```text
//! keystore region (QMI flash or the SD card)   store_v2.rs   journal, snapshots, objects
//!    ↑                                         keystore_v2.rs  KeyStore over it (BoardKeyStore)
//! internal flash, every board:                 binding.rs      the binding block ring
//!                                              retry_counter.rs counter log v2 (retry counters,
//!                                                              device values, the anchor)
//!                                              rsa_pool.rs     the RSA key pool
//! ```
//!
//! `flash_layout.rs` places the internal-flash regions; `flash_chip.rs`
//! and `sdcard.rs` are the drivers.  The 1.x filesystem, RAID-1, WAL and
//! multi-chip layers were removed in 2.0 (STORAGE_V2 §12).

pub mod binding;
pub mod flash_layout;
pub mod keystore;
pub mod keystore_v2;
pub mod retry_counter;
#[cfg(feature = "rsa")]
pub mod rsa_pool;
pub mod store_v2;
#[cfg(test)]
mod store_v2_tests;
pub use keystore::{KeyStore, SoPin, SoPinHome, StoreReport, StoreState};

pub use keystore::NullKeyStore;

// The following sub-modules use embassy-rp / embassy-time / defmt and can
// only compile for ARM bare-metal targets.
#[cfg(target_arch = "arm")]
pub mod board_chips;
#[cfg(target_arch = "arm")]
pub mod flash_chip;
#[cfg(target_arch = "arm")]
pub mod integrity;
#[cfg(target_arch = "arm")]
pub mod sdcard;

#[cfg(target_arch = "arm")]
pub use board_chips::BoardChip;
#[cfg(target_arch = "arm")]
pub use board_chips::{BoardKeyStore, BoardStoreChip};

/// The retry-counter log on internal flash, as every board uses it.
#[cfg(target_arch = "arm")]
pub type BoardCounterLog = retry_counter::CounterLog<flash_chip::QmiCounterFlash>;

/// The RSA key pool region on internal flash, as every board uses it.
#[cfg(all(target_arch = "arm", feature = "rsa"))]
pub type BoardPoolRegion = rsa_pool::PoolRegion<flash_chip::QmiPoolFlash>;
