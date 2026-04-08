//! TCP peer protocol — framed message listener.
//!
//! Each message on the wire is:
//!   1 byte  — message type
//!   4 bytes — payload length (little-endian u32)
//!   N bytes — payload

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::config::Config;

// ── Message types ──────────────────────────────────────────────────────

/// Request the remote's key manifest.
pub const MSG_MANIFEST_REQ: u8 = 0x01;
/// Response carrying a key manifest.
pub const MSG_MANIFEST_RESP: u8 = 0x02;
/// Request the remote's state hash.
pub const MSG_STATE_HASH_REQ: u8 = 0x03;
/// Response carrying a state hash.
pub const MSG_STATE_HASH_RESP: u8 = 0x04;
/// A DKEK-wrapped key blob for import.
pub const MSG_KEY_BLOB: u8 = 0x05;
/// Indicates that a sync operation has completed.
pub const MSG_SYNC_COMPLETE: u8 = 0x06;
/// Generic acknowledgement.
pub const MSG_ACK: u8 = 0xFF;

/// Maximum payload size we accept (16 MB — far larger than any key blob).
const MAX_PAYLOAD: u32 = 16 * 1024 * 1024;

/// Bind a TCP listener and spawn a handler task for each accepted connection.
pub async fn tcp_listener_task(config: Arc<Config>) {
    let addr = format!("{}:{}", config.listen_address, config.listen_port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            info!("TCP listener bound to {addr}");
            l
        }
        Err(e) => {
            error!("failed to bind TCP listener on {addr}: {e}");
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!(%peer_addr, "accepted TCP connection");
                let cfg = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, cfg).await {
                        warn!(%peer_addr, "connection handler error: {e}");
                    }
                });
            }
            Err(e) => {
                warn!("TCP accept error: {e}");
            }
        }
    }
}

/// Read framed messages from a peer and dispatch them.
async fn handle_connection(
    mut stream: TcpStream,
    _config: Arc<Config>,
) -> std::io::Result<()> {
    loop {
        // Read 5-byte header: type(1) + length(4 LE).
        let mut header = [0u8; 5];
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!("peer disconnected");
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        let msg_type = header[0];
        let payload_len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);

        if payload_len > MAX_PAYLOAD {
            warn!(payload_len, "payload too large — closing connection");
            return Ok(());
        }

        let mut payload = vec![0u8; payload_len as usize];
        if payload_len > 0 {
            stream.read_exact(&mut payload).await?;
        }

        dispatch_message(&mut stream, msg_type, &payload).await?;
    }
}

/// Handle a single framed message. Unrecognised types get an ACK with empty
/// payload (forward-compatible).
async fn dispatch_message(
    stream: &mut TcpStream,
    msg_type: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    match msg_type {
        MSG_MANIFEST_REQ => {
            info!("received MANIFEST_REQ ({} bytes)", payload.len());
            // Respond with an empty manifest for now — the real implementation
            // will query a local device via spawn_blocking.
            send_message(stream, MSG_MANIFEST_RESP, &[]).await?;
        }
        MSG_STATE_HASH_REQ => {
            info!("received STATE_HASH_REQ");
            send_message(stream, MSG_STATE_HASH_RESP, &[]).await?;
        }
        MSG_KEY_BLOB => {
            info!("received KEY_BLOB ({} bytes)", payload.len());
            send_message(stream, MSG_ACK, &[]).await?;
        }
        MSG_SYNC_COMPLETE => {
            info!("received SYNC_COMPLETE");
            send_message(stream, MSG_ACK, &[]).await?;
        }
        _ => {
            warn!(msg_type, "unknown message type — sending ACK");
            send_message(stream, MSG_ACK, &[]).await?;
        }
    }
    Ok(())
}

/// Write a framed message (header + payload) to the stream.
async fn send_message(
    stream: &mut TcpStream,
    msg_type: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = payload.len() as u32;
    let mut header = [0u8; 5];
    header[0] = msg_type;
    header[1..5].copy_from_slice(&len.to_le_bytes());
    stream.write_all(&header).await?;
    if !payload.is_empty() {
        stream.write_all(payload).await?;
    }
    Ok(())
}
