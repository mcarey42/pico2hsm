/// All errors produced by the daemon.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("device error: {0}")]
    Device(String),

    #[error("APDU error: SW={sw:#06x}")]
    Apdu { sw: u16 },

    #[error("sync error: {0}")]
    Sync(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PC/SC error: {0}")]
    Pcsc(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, DaemonError>;

// pcsc::Error does not implement std::error::Error in all versions,
// so we convert manually.
impl From<pcsc::Error> for DaemonError {
    fn from(e: pcsc::Error) -> Self {
        DaemonError::Pcsc(format!("{e:?}"))
    }
}

impl DaemonError {
    /// Shorthand for building an APDU status-word error.
    #[allow(dead_code)]
    pub fn apdu(sw: u16) -> Self {
        DaemonError::Apdu { sw }
    }
}

/// Display the SW word in the standard `XXXX` hex form when formatted for
/// user-facing messages (the `Display` impl from thiserror already does this
/// via the `#06x` format specifier, but keep a helper for structured logging).
impl DaemonError {
    #[allow(dead_code)]
    pub fn sw_hex(&self) -> Option<String> {
        match self {
            DaemonError::Apdu { sw } => Some(format!("{sw:04X}")),
            _ => None,
        }
    }
}
