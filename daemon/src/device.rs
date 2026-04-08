//! PC/SC device communication layer.
//!
//! Wraps the `pcsc` crate to provide a convenient interface for sending APDUs
//! to pico2hsm smart-card readers.

use pcsc::{Card, Context, Protocols, Scope, ShareMode};

use crate::error::{DaemonError, Result};

/// Name substring used to identify pico2hsm readers in the PC/SC reader list.
const PICO2HSM_READER_SUBSTRING: &str = "pico2hsm";

/// A handle to an open smart-card connection.
pub struct Device {
    card: Card,
    reader_name: String,
}

impl Device {
    /// Open a connection to the card in the named reader.
    pub fn open(reader_name: &str) -> Result<Self> {
        let ctx = Context::establish(Scope::User)?;
        let card = ctx.connect(
            &std::ffi::CString::new(reader_name)
                .map_err(|e| DaemonError::Device(format!("invalid reader name: {e}")))?,
            ShareMode::Shared,
            Protocols::ANY,
        )?;
        Ok(Self {
            card,
            reader_name: reader_name.to_string(),
        })
    }

    /// List all PC/SC readers whose names contain the pico2hsm identifier.
    pub fn list_readers(ctx: &Context) -> Result<Vec<String>> {
        let mut buf = vec![0u8; 4096];
        let readers = ctx.list_readers(&mut buf)?;
        let names: Vec<String> = readers
            .filter(|name| {
                name.to_str()
                    .map(|s| s.to_lowercase().contains(PICO2HSM_READER_SUBSTRING))
                    .unwrap_or(false)
            })
            .map(|name| name.to_string_lossy().into_owned())
            .collect();
        Ok(names)
    }

    /// Send an APDU and return `(response_data, status_word)`.
    ///
    /// The last two bytes of the card's response are interpreted as the SW1-SW2
    /// status word; everything before that is the response data payload.
    pub fn transmit(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16)> {
        let mut recv_buf = vec![0u8; 4096];
        let response = self.card.transmit(apdu, &mut recv_buf)?;

        if response.len() < 2 {
            return Err(DaemonError::Device(
                "response too short (< 2 bytes)".to_string(),
            ));
        }

        let sw1 = response[response.len() - 2];
        let sw2 = response[response.len() - 1];
        let sw = u16::from(sw1) << 8 | u16::from(sw2);
        let data = response[..response.len() - 2].to_vec();

        Ok((data, sw))
    }

    /// The reader name this device was opened from.
    #[allow(dead_code)]
    pub fn reader_name(&self) -> &str {
        &self.reader_name
    }
}

/// Return owned reader names for all PC/SC readers whose names contain
/// "pico2hsm" (case-insensitive).
pub fn list_pico2hsm_reader_names(ctx: &Context) -> Result<Vec<String>> {
    let mut buf = vec![0u8; 4096];
    let readers = ctx.list_readers(&mut buf)?;
    let names: Vec<String> = readers
        .filter(|name| {
            name.to_str()
                .map(|s| s.to_lowercase().contains(PICO2HSM_READER_SUBSTRING))
                .unwrap_or(false)
        })
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    Ok(names)
}
