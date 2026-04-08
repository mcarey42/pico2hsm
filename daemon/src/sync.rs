//! Synchronisation orchestration between two pico2hsm devices.
//!
//! The core operation compares state hashes, then uses WRAP_KEY / UNWRAP_KEY
//! to copy missing or stale keys from primary to secondary.

use tracing::{info, warn};

use crate::apdu;
use crate::device::Device;
use crate::error::{DaemonError, Result};

/// Outcome of a synchronisation attempt.
#[derive(Debug)]
pub struct SyncReport {
    /// True if both devices already had identical root hashes.
    pub already_in_sync: bool,
    /// Number of keys transferred from primary to secondary.
    pub keys_transferred: u32,
}

/// Compare state hashes of two devices and, if they differ, copy every key
/// from primary to secondary via DKEK wrap/unwrap.
///
/// Opens both devices internally so callers do not need to manage `Device`
/// lifetimes across async boundaries.
pub fn sync_device_pair(
    ctx: &pcsc::Context,
    primary_reader: &str,
    secondary_reader: &str,
) -> Result<SyncReport> {
    let _ = ctx; // Context used to prove PC/SC is available; devices open their own.
    let mut primary = Device::open(primary_reader)?;
    let mut secondary = Device::open(secondary_reader)?;

    // Step 1: fetch state hashes from both devices.
    let (primary_hash, _sw1) = primary.transmit(&apdu::build_get_state_hash())?;
    let (secondary_hash, _sw2) = secondary.transmit(&apdu::build_get_state_hash())?;

    // State hash layout: generation(8) + root(32) + sig(64) = 104 bytes.
    if primary_hash.len() < 40 || secondary_hash.len() < 40 {
        return Err(DaemonError::Sync(
            "state hash response too short".to_string(),
        ));
    }

    let primary_root = &primary_hash[8..40];
    let secondary_root = &secondary_hash[8..40];

    if primary_root == secondary_root {
        info!("devices already in sync");
        return Ok(SyncReport {
            already_in_sync: true,
            keys_transferred: 0,
        });
    }

    info!("root hashes differ — starting key transfer");

    // Step 2: get the key manifest from the primary device.
    let (manifest_data, manifest_sw) =
        primary.transmit(&apdu::build_get_key_manifest())?;
    if manifest_sw != 0x9000 {
        return Err(DaemonError::apdu(manifest_sw));
    }

    // The manifest is a sequence of key descriptors. Each descriptor starts
    // with a 1-byte key reference. For now we treat the manifest as a flat
    // list of key_ref bytes (the firmware may refine the format later).
    let key_refs: Vec<u8> = manifest_data.to_vec();

    let mut keys_transferred: u32 = 0;

    for &key_ref in &key_refs {
        // Wrap (export) from primary.
        let (blob, wrap_sw) = primary.transmit(&apdu::build_wrap_key(key_ref))?;
        if wrap_sw != 0x9000 {
            warn!(key_ref, sw = wrap_sw, "WRAP_KEY failed — skipping");
            continue;
        }

        // Unwrap (import) into secondary.
        let (_resp, unwrap_sw) =
            secondary.transmit(&apdu::build_unwrap_key(key_ref, &blob))?;
        if unwrap_sw != 0x9000 {
            warn!(key_ref, sw = unwrap_sw, "UNWRAP_KEY failed — skipping");
            continue;
        }

        keys_transferred += 1;
    }

    // Step 3: verify that the root hashes now match.
    let (new_primary, _) = primary.transmit(&apdu::build_get_state_hash())?;
    let (new_secondary, _) = secondary.transmit(&apdu::build_get_state_hash())?;

    if new_primary.len() >= 40
        && new_secondary.len() >= 40
        && new_primary[8..40] != new_secondary[8..40]
    {
        warn!("root hashes still differ after sync — devices may need re-initialisation");
    }

    Ok(SyncReport {
        already_in_sync: false,
        keys_transferred,
    })
}
