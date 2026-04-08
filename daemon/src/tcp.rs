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
use crate::error::DaemonError;

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

// ── Client-side async helpers ──────────────────────────────────────────

/// Send a framed message (type + LE-u32 length + payload) on `stream`.
async fn send_framed_async(
    stream: &mut TcpStream,
    msg_type: u8,
    payload: &[u8],
) -> Result<(), DaemonError> {
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

/// Read one framed message from `stream`.  Returns `(msg_type, payload)`.
async fn recv_framed_async(
    stream: &mut TcpStream,
) -> Result<(u8, Vec<u8>), DaemonError> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;

    let msg_type = header[0];
    let payload_len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);

    if payload_len > MAX_PAYLOAD {
        return Err(DaemonError::Sync(format!(
            "peer sent oversized payload ({payload_len} bytes)"
        )));
    }

    let mut payload = vec![0u8; payload_len as usize];
    if payload_len > 0 {
        stream.read_exact(&mut payload).await?;
    }

    Ok((msg_type, payload))
}

// ── Client-side peer sync ──────────────────────────────────────────────

/// Outcome of a peer sync attempt over TCP.
#[derive(Debug)]
pub struct PeerSyncResult {
    /// Address of the peer we connected to.
    pub peer_address: String,
    /// True if the peer already had the same state root — no transfer needed.
    pub already_in_sync: bool,
    /// The peer's final state root hash.
    pub peer_root: [u8; 32],
    /// Key blobs fetched from the peer: `(key_ref, wrapped_blob)`.
    pub key_blobs: Vec<(u32, Vec<u8>)>,
}

/// Connect to a remote peer daemon, compare state hashes, and — if they
/// differ — download every key blob from the peer's manifest.
///
/// The caller is responsible for unwrapping the returned key blobs onto the
/// local device.
pub async fn initiate_peer_sync(
    peer_address: &str,
    peer_port: u16,
    local_state_root: [u8; 32],
) -> Result<PeerSyncResult, DaemonError> {
    let addr = format!("{peer_address}:{peer_port}");
    let mut stream = TcpStream::connect(&addr).await.map_err(|e| {
        DaemonError::Sync(format!("failed to connect to {addr}: {e}"))
    })?;

    info!(peer = %addr, "connected to peer for sync");

    // Step 1: request the peer's state hash.
    send_framed_async(&mut stream, MSG_STATE_HASH_REQ, &[]).await?;
    let (resp_type, resp_payload) = recv_framed_async(&mut stream).await?;

    if resp_type != MSG_STATE_HASH_RESP {
        return Err(DaemonError::Sync(format!(
            "expected STATE_HASH_RESP (0x{:02X}), got 0x{:02X}",
            MSG_STATE_HASH_RESP, resp_type,
        )));
    }

    // State hash layout: generation(8) + root(32) + sig(64) = 104 bytes.
    if resp_payload.len() < 40 {
        return Err(DaemonError::Sync(format!(
            "STATE_HASH_RESP too short ({} bytes, need >= 40)",
            resp_payload.len(),
        )));
    }

    let mut peer_root = [0u8; 32];
    peer_root.copy_from_slice(&resp_payload[8..40]);

    // Step 2: if roots match, we are already in sync.
    if peer_root == local_state_root {
        info!(peer = %addr, "already in sync with peer");
        return Ok(PeerSyncResult {
            peer_address: addr,
            already_in_sync: true,
            peer_root,
            key_blobs: Vec::new(),
        });
    }

    info!(peer = %addr, "state roots differ — requesting manifest");

    // Step 3: request the key manifest.
    send_framed_async(&mut stream, MSG_MANIFEST_REQ, &[]).await?;
    let (mtype, manifest_payload) = recv_framed_async(&mut stream).await?;

    if mtype != MSG_MANIFEST_RESP {
        return Err(DaemonError::Sync(format!(
            "expected MANIFEST_RESP (0x{:02X}), got 0x{:02X}",
            MSG_MANIFEST_RESP, mtype,
        )));
    }

    // The manifest is a sequence of 4-byte LE u32 key references.
    if manifest_payload.len() % 4 != 0 {
        return Err(DaemonError::Sync(format!(
            "manifest payload length {} is not a multiple of 4",
            manifest_payload.len(),
        )));
    }

    let key_refs: Vec<u32> = manifest_payload
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();

    info!(peer = %addr, count = key_refs.len(), "received manifest");

    // Step 4: fetch each key blob.
    let mut key_blobs: Vec<(u32, Vec<u8>)> = Vec::new();

    for &key_ref in &key_refs {
        let req_payload = key_ref.to_le_bytes();
        send_framed_async(&mut stream, MSG_KEY_BLOB, &req_payload).await?;

        let (btype, blob_payload) = recv_framed_async(&mut stream).await?;
        if btype == MSG_KEY_BLOB {
            key_blobs.push((key_ref, blob_payload));
        } else {
            warn!(peer = %addr, key_ref, msg_type = btype, "unexpected response for KEY_BLOB request");
        }
    }

    info!(peer = %addr, fetched = key_blobs.len(), "key blobs received");

    // Step 5: send SYNC_COMPLETE with our local state root.
    send_framed_async(&mut stream, MSG_SYNC_COMPLETE, &local_state_root).await?;

    // Step 6: read SYNC_COMPLETE response — extract peer's final root.
    let (ctype, complete_payload) = recv_framed_async(&mut stream).await?;

    let mut final_peer_root = peer_root; // fallback
    if ctype == MSG_SYNC_COMPLETE || ctype == MSG_ACK {
        if complete_payload.len() >= 32 {
            final_peer_root.copy_from_slice(&complete_payload[..32]);
        }
    } else {
        warn!(peer = %addr, msg_type = ctype, "unexpected SYNC_COMPLETE response type");
    }

    info!(peer = %addr, "peer sync complete");

    Ok(PeerSyncResult {
        peer_address: addr,
        already_in_sync: false,
        peer_root: final_peer_root,
        key_blobs,
    })
}
