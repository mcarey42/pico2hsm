use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{DaemonError, Result};

/// A remote peer that we may sync with over TCP.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct PeerConfig {
    pub name: String,
    pub address: String,
    pub port: u16,
    /// Role of this peer: "primary", "secondary", or "" (default).
    #[serde(default)]
    pub role: String,
}

/// Top-level daemon configuration, deserialized from TOML.
///
/// Missing fields are filled in with sensible defaults via `#[serde(default)]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
#[allow(dead_code)]
pub struct Config {
    /// Address to bind the TCP listener on.
    pub listen_address: String,
    /// TCP port for the peer protocol.
    pub listen_port: u16,
    /// Directory for persistent state (generation counters, DKEK cache, etc.).
    pub state_dir: PathBuf,
    /// Whether to trigger a full sync when a new device is detected.
    pub sync_on_connect: bool,
    /// Interval in seconds between health-check sweeps.
    pub health_check_interval_secs: u64,
    /// Known remote peers.
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_address: "0.0.0.0".to_string(),
            listen_port: 7777,
            state_dir: PathBuf::from("/var/lib/pico2hsm"),
            sync_on_connect: true,
            health_check_interval_secs: 60,
            peers: Vec::new(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file, filling in defaults for missing fields.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            DaemonError::Config(format!("failed to read {}: {e}", path.display()))
        })?;
        let config: Config = toml::from_str(&contents)
            .map_err(|e| DaemonError::Config(format!("invalid TOML: {e}")))?;
        Ok(config)
    }
}
