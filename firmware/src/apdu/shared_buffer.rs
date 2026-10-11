//! Shared response buffer for GET RESPONSE chaining.
//!
//! Centralizes the ISO 7816-4 GET RESPONSE protocol in the Dispatcher,
//! replacing per-protocol `pending_response` / `last_response` buffers.
//! Protocols return full `ApduResponse` data; the Dispatcher truncates to
//! Le and stores the overflow here for subsequent GET RESPONSE calls.

/// What the shared response buffer currently holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedBufState {
    /// Buffer is empty / invalid.
    Empty,
    /// Buffer holds overflow data for GET RESPONSE chaining.
    PendingResponse,
    /// Buffer holds decrypted key material (Phase 3 — added now, used later).
    KeyData(u32),
    /// Buffer holds modified key material (Phase 3 — added now, used later).
    KeyDataDirty(u32),
}

/// Single shared buffer for GET RESPONSE chaining across all protocols.
///
/// Owned by `Dispatcher`. Protocols never touch this directly — the
/// Dispatcher intercepts INS=0xC0, performs Le-truncation after protocol
/// dispatch, and serves chunks from here.
pub struct SharedResponseBuffer {
    /// Raw overflow data.
    pub data: [u8; 4096],
    /// Number of valid bytes in `data`.
    pub len: usize,
    /// Byte offset for the next GET RESPONSE chunk.
    pub offset: usize,
    /// Current buffer state.
    pub state: SharedBufState,
}

impl SharedResponseBuffer {
    /// Create a new empty buffer.
    pub const fn new() -> Self {
        SharedResponseBuffer {
            data: [0u8; 4096],
            len: 0,
            offset: 0,
            state: SharedBufState::Empty,
        }
    }

    /// Clear the buffer to Empty state, wiping the held response bytes —
    /// they can be secrets (decrypted plaintext, ECDH output, key blobs).
    pub fn invalidate(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.data[..self.len]);
        self.state = SharedBufState::Empty;
        self.len = 0;
        self.offset = 0;
    }

    /// Store overflow response data for GET RESPONSE chaining.
    ///
    /// `data` is the overflow portion (bytes beyond the first Le chunk).
    /// Sets state to `PendingResponse` with offset=0.
    pub fn store_response(&mut self, data: &[u8]) {
        let n = data.len().min(4096);
        self.data[..n].copy_from_slice(&data[..n]);
        self.len = n;
        self.offset = 0;
        self.state = SharedBufState::PendingResponse;
    }

    /// Return the next chunk of pending response data.
    ///
    /// `max_len` is the maximum number of bytes to return (from Le).
    /// Returns `Some((slice, more_remaining))` or `None` if nothing is pending.
    pub fn get_response_chunk(&mut self, max_len: usize) -> Option<(&[u8], bool)> {
        if self.state != SharedBufState::PendingResponse {
            return None;
        }
        let remaining = self.len.saturating_sub(self.offset);
        if remaining == 0 {
            self.invalidate();
            return None;
        }
        let chunk_len = remaining.min(max_len);
        let start = self.offset;
        self.offset += chunk_len;
        let new_remaining = self.len.saturating_sub(self.offset);
        let more = new_remaining > 0;
        if !more {
            // All data consumed — will be cleared on next non-C0 command.
        }
        Some((&self.data[start..start + chunk_len], more))
    }

    /// True if the buffer holds pending GET RESPONSE data.
    pub fn has_pending_response(&self) -> bool {
        self.state == SharedBufState::PendingResponse && self.len > self.offset
    }

    /// Clear the buffer if the current command is not GET RESPONSE.
    ///
    /// Called by the Dispatcher before routing non-C0 APDUs.
    pub fn clear_if_not_get_response(&mut self) {
        if self.state == SharedBufState::PendingResponse {
            self.invalidate();
        }
    }
}
