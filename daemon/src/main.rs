mod apdu;
mod config;
mod device;
mod error;
mod health;
mod sync;
mod tcp;

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

    // USB device monitor — polls every 5 seconds for new readers.
    let monitor_config = Arc::clone(&config);
    usb_monitor_loop(monitor_config).await;
}

/// Polling loop that watches for new pico2hsm USB devices.
async fn usb_monitor_loop(config: Arc<Config>) {
    let mut known_readers: Vec<String> = Vec::new();

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        let result =
            tokio::task::spawn_blocking(|| -> error::Result<Vec<String>> {
                let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
                Device::list_readers(&ctx)
            })
            .await;

        match result {
            Ok(Ok(current_readers)) => {
                for reader in &current_readers {
                    if !known_readers.contains(reader) {
                        info!(reader = %reader, "new pico2hsm device detected");
                        if config.sync_on_connect {
                            info!("sync_on_connect is enabled — sync would start here");
                        }
                    }
                }
                // Detect removals.
                for reader in &known_readers {
                    if !current_readers.contains(reader) {
                        info!(reader = %reader, "pico2hsm device removed");
                    }
                }
                known_readers = current_readers;
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
