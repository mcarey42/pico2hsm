//! Periodic health-check task.
//!
//! Opens every pico2hsm reader, reads the state hash, and logs whether all
//! devices share the same Merkle root.

use std::sync::Arc;

use tokio::time::{self, Duration};
use tracing::{error, info, warn};

use crate::apdu;
use crate::config::Config;
use crate::device::Device;

/// Runs forever, performing a health check every `config.health_check_interval_secs`.
pub async fn health_check_task(config: Arc<Config>) {
    let interval = Duration::from_secs(config.health_check_interval_secs);

    loop {
        time::sleep(interval).await;

        // PC/SC operations are blocking — run in a blocking thread.
        let result = tokio::task::spawn_blocking(run_health_check).await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!("health check failed: {e}"),
            Err(e) => error!("health check task panicked: {e}"),
        }
    }
}

/// Synchronous health-check logic (runs inside `spawn_blocking`).
fn run_health_check() -> crate::error::Result<()> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
    let readers = Device::list_readers(&ctx)?;

    if readers.is_empty() {
        info!("health: no pico2hsm readers found");
        return Ok(());
    }

    let mut roots: Vec<(String, Vec<u8>)> = Vec::new();

    for reader_name in &readers {
        match Device::open(reader_name) {
            Ok(mut dev) => {
                let apdu = apdu::build_get_state_hash();
                match dev.transmit(&apdu) {
                    Ok((data, sw)) => {
                        if sw != 0x9000 {
                            warn!(reader = %reader_name, sw, "GET_STATE_HASH returned non-9000");
                            continue;
                        }
                        if data.len() >= 40 {
                            let root = data[8..40].to_vec();
                            info!(
                                reader = %reader_name,
                                root = hex::encode(&root),
                                "state hash OK"
                            );
                            roots.push((reader_name.clone(), root));
                        } else {
                            warn!(reader = %reader_name, "state hash too short");
                        }
                    }
                    Err(e) => warn!(reader = %reader_name, "transmit error: {e}"),
                }
            }
            Err(e) => warn!(reader = %reader_name, "open error: {e}"),
        }
    }

    if roots.len() >= 2 {
        let first_root = &roots[0].1;
        let all_match = roots.iter().all(|(_, r)| r == first_root);
        if all_match {
            info!("health: all {} devices in sync", roots.len());
        } else {
            warn!("health: devices OUT OF SYNC");
        }
    }

    Ok(())
}
