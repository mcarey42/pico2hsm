mod apdu;
mod config;
mod device;
mod error;
mod health;
mod sync;
mod tcp;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::device::Device;

/// pico2hsm cluster sync daemon.
#[derive(Parser)]
#[command(name = "pico2hsm-daemon", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the daemon (health checks, TCP listener, USB monitor).
    Start {
        /// Path to the TOML configuration file.
        #[arg(long, default_value = "/etc/pico2hsm/daemon.toml")]
        config: PathBuf,
        /// Path to write the PID file.
        #[arg(long)]
        pid_file: Option<PathBuf>,
    },
    /// Stop a running daemon by sending SIGTERM to the PID in the given file.
    Stop {
        /// Path to the PID file.
        #[arg(long, default_value = "/run/pico2hsm-daemon.pid")]
        pid_file: PathBuf,
    },
    /// Show connected devices and their state hashes.
    Status {
        /// Path to the TOML configuration file.
        #[arg(long, default_value = "/etc/pico2hsm/daemon.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    // Initialise tracing with RUST_LOG env-filter support.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Start { config, pid_file } => {
            cmd_start(config, pid_file).await;
        }
        Command::Stop { pid_file } => {
            cmd_stop(pid_file);
        }
        Command::Status { config } => {
            cmd_status(config).await;
        }
    }
}

/// Start the daemon: load config, write PID file, spawn long-running tasks.
async fn cmd_start(config_path: PathBuf, pid_file: Option<PathBuf>) {
    let config = match Config::load(&config_path) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            // If the config file doesn't exist, fall back to defaults.
            warn!("could not load config from {}: {e} — using defaults", config_path.display());
            Arc::new(Config::default())
        }
    };

    // Write PID file if requested.
    if let Some(ref path) = pid_file {
        let pid = std::process::id();
        if let Err(e) = std::fs::write(path, pid.to_string()) {
            error!("failed to write PID file {}: {e}", path.display());
        }
    }

    info!("starting pico2hsm daemon");

    // Spawn health check task.
    let health_config = Arc::clone(&config);
    tokio::spawn(health::health_check_task(health_config));

    // Spawn TCP listener task.
    let tcp_config = Arc::clone(&config);
    tokio::spawn(tcp::tcp_listener_task(tcp_config));

    // Spawn peer sync task (runs periodically, syncs with configured peers).
    if !config.peers.is_empty() {
        let sync_config = Arc::clone(&config);
        tokio::spawn(peer_sync_task(sync_config));
    }

    // USB device monitor — polls every 5 seconds for new readers.
    let monitor_config = Arc::clone(&config);
    tokio::spawn(usb_monitor_task(monitor_config));

    // Keep the main task alive so spawned tasks continue running.
    // Wait for a shutdown signal (Ctrl-C).
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c");
    info!("received shutdown signal — exiting");
}

/// Background task that polls for new pico2hsm USB devices every 5 seconds
/// and triggers a sync when `config.sync_on_connect` is true and at least two
/// readers are present.
async fn usb_monitor_task(config: Arc<Config>) {
    let mut known_readers: HashSet<String> = HashSet::new();

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        let result =
            tokio::task::spawn_blocking(|| -> error::Result<Vec<String>> {
                let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
                device::list_pico2hsm_reader_names(&ctx)
            })
            .await;

        match result {
            Ok(Ok(current_readers)) => {
                let current_set: HashSet<String> =
                    current_readers.iter().cloned().collect();

                // Detect new readers.
                let new_readers: Vec<String> = current_readers
                    .iter()
                    .filter(|r| !known_readers.contains(r.as_str()))
                    .cloned()
                    .collect();

                for reader in &new_readers {
                    info!("New pico2hsm device detected: {reader}");
                }

                // Detect removals.
                for reader in &known_readers {
                    if !current_set.contains(reader) {
                        info!(reader = %reader, "pico2hsm device removed");
                    }
                }

                // Trigger sync for each new reader if conditions are met.
                if config.sync_on_connect && current_readers.len() >= 2 {
                    for new_reader in &new_readers {
                        // Use readers[0] as primary (skip if the new reader IS readers[0]).
                        let primary = &current_readers[0];
                        if primary == new_reader {
                            // Use the second reader as the other end instead.
                            if current_readers.len() >= 2 {
                                let secondary = new_reader.clone();
                                let primary = current_readers[1].clone();
                                tokio::task::spawn_blocking(move || {
                                    match pcsc::Context::establish(pcsc::Scope::User) {
                                        Ok(ctx) => {
                                            match sync::sync_device_pair(
                                                &ctx, &primary, &secondary,
                                            ) {
                                                Ok(report) => {
                                                    info!(
                                                        keys_transferred = report.keys_transferred,
                                                        already_in_sync = report.already_in_sync,
                                                        "sync complete"
                                                    );
                                                }
                                                Err(e) => {
                                                    warn!("sync failed: {e}");
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("PC/SC context error: {e:?}");
                                        }
                                    }
                                });
                            }
                        } else {
                            let primary = primary.clone();
                            let secondary = new_reader.clone();
                            tokio::task::spawn_blocking(move || {
                                match pcsc::Context::establish(pcsc::Scope::User) {
                                    Ok(ctx) => {
                                        match sync::sync_device_pair(
                                            &ctx, &primary, &secondary,
                                        ) {
                                            Ok(report) => {
                                                info!(
                                                    keys_transferred = report.keys_transferred,
                                                    already_in_sync = report.already_in_sync,
                                                    "sync complete"
                                                );
                                            }
                                            Err(e) => {
                                                warn!("sync failed: {e}");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("PC/SC context error: {e:?}");
                                    }
                                }
                            });
                        }
                    }
                }

                known_readers = current_set;
            }
            Ok(Err(e)) => {
                warn!("USB monitor error: {e}");
            }
            Err(e) => {
                error!("USB monitor task panicked: {e}");
            }
        }
    }
}

/// Periodically connect to each configured peer and perform a state-hash
/// comparison.  If the hashes differ, download wrapped key blobs from the
/// peer.  The blobs are logged for now; a future iteration will unwrap them
/// onto the local device.
async fn peer_sync_task(config: Arc<Config>) {
    let interval = tokio::time::Duration::from_secs(config.health_check_interval_secs);

    loop {
        tokio::time::sleep(interval).await;

        // Get local state root from the first available pico2hsm device.
        let local_root = match tokio::task::spawn_blocking(get_local_state_root).await {
            Ok(Ok(root)) => root,
            Ok(Err(e)) => {
                warn!("peer_sync: could not read local state root: {e}");
                continue;
            }
            Err(e) => {
                error!("peer_sync: spawn_blocking panicked: {e}");
                continue;
            }
        };

        for peer in &config.peers {
            match tcp::initiate_peer_sync(&peer.address, peer.port, local_root).await {
                Ok(result) => {
                    if result.already_in_sync {
                        info!(
                            peer = %peer.name,
                            address = %result.peer_address,
                            "peer already in sync"
                        );
                    } else {
                        info!(
                            peer = %peer.name,
                            address = %result.peer_address,
                            blobs = result.key_blobs.len(),
                            peer_root = hex::encode(result.peer_root),
                            "peer sync fetched key blobs"
                        );
                    }
                }
                Err(e) => {
                    warn!(peer = %peer.name, "peer sync failed: {e}");
                }
            }
        }
    }
}

/// Read the 32-byte state root from the first available local pico2hsm device.
/// This is a blocking function intended to run inside `spawn_blocking`.
fn get_local_state_root() -> error::Result<[u8; 32]> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
    let readers = Device::list_readers(&ctx)?;

    if readers.is_empty() {
        return Err(error::DaemonError::Device(
            "no pico2hsm readers found".to_string(),
        ));
    }

    let mut dev = Device::open(&readers[0])?;
    let (data, sw) = dev.transmit(&apdu::build_get_state_hash())?;

    if sw != 0x9000 {
        return Err(error::DaemonError::apdu(sw));
    }

    if data.len() < 40 {
        return Err(error::DaemonError::Sync(
            "state hash response too short".to_string(),
        ));
    }

    let mut root = [0u8; 32];
    root.copy_from_slice(&data[8..40]);
    Ok(root)
}

/// Send SIGTERM to the PID recorded in the given file.
fn cmd_stop(pid_file: PathBuf) {
    let pid_str = match std::fs::read_to_string(&pid_file) {
        Ok(s) => s.trim().to_string(),
        Err(e) => {
            error!("cannot read PID file {}: {e}", pid_file.display());
            std::process::exit(1);
        }
    };

    let pid: i32 = match pid_str.parse() {
        Ok(p) => p,
        Err(e) => {
            error!("invalid PID in {}: {e}", pid_file.display());
            std::process::exit(1);
        }
    };

    // Send SIGTERM via libc.
    #[cfg(unix)]
    {
        // SAFETY: sending a signal to a process is safe; worst case the PID is
        // stale and we get ESRCH.
        let ret = unsafe { libc::kill(pid, libc::SIGTERM) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            error!("kill({pid}, SIGTERM) failed: {err}");
            std::process::exit(1);
        }
        info!("sent SIGTERM to PID {pid}");
    }

    #[cfg(not(unix))]
    {
        error!("stop command is only supported on Unix");
        std::process::exit(1);
    }
}

/// Print the status of all connected pico2hsm devices.
async fn cmd_status(config_path: PathBuf) {
    let _config = Config::load(&config_path).unwrap_or_else(|_| Config::default());

    let result = tokio::task::spawn_blocking(|| -> error::Result<()> {
        let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
        let readers = Device::list_readers(&ctx)?;

        if readers.is_empty() {
            println!("No pico2hsm devices found.");
            return Ok(());
        }

        for reader_name in &readers {
            print!("{reader_name}: ");
            match Device::open(reader_name) {
                Ok(mut dev) => {
                    let apdu_bytes = apdu::build_get_state_hash();
                    match dev.transmit(&apdu_bytes) {
                        Ok((data, sw)) => {
                            if sw != 0x9000 {
                                println!("SW={sw:04X}");
                                continue;
                            }
                            if data.len() >= 40 {
                                let gen = &data[0..8];
                                let root = &data[8..40];
                                println!(
                                    "gen={} root={}",
                                    hex::encode(gen),
                                    hex::encode(root),
                                );
                            } else {
                                println!("short response ({} bytes)", data.len());
                            }
                        }
                        Err(e) => println!("transmit error: {e}"),
                    }
                }
                Err(e) => println!("open error: {e}"),
            }
        }
        Ok(())
    })
    .await;

    if let Err(e) = result {
        error!("status task panicked: {e}");
    }
}
