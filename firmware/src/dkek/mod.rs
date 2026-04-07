//! DKEK module — re-exports from the canonical implementation.
pub use crate::security::dkek::{
    DkekManager, DkekError, DkekImportResult,
    SHARE_BLOB_SIZE, MAX_SHARES,
    encrypt_share_blob,
};
