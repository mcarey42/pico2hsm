//! ISO 7816-3 T=1 block protocol framing.
//!
//! T=1 is the byte-oriented asynchronous half-duplex transmission protocol
//! defined in ISO/IEC 7816-3. The CCID layer delivers T=1 frames; this module
//! assembles chained I-blocks into complete APDU buffers and splits long
//! responses back into chained I-blocks.
//!
//! # T=1 block structure
//! ```text
//! [ NAD | PCB | LEN | INF(0..LEN) | EDC ]
//! ```
//! - NAD: Node Address byte (0x00 for single-device)
//! - PCB: Protocol Control Byte (I-block / R-block / S-block)
//! - LEN: Length of information field (0–254)
//! - INF: Information field (APDU fragment)
//! - EDC: Error Detection Code (LRC = XOR of all bytes NAD..INF)

use heapless::Vec;

/// Maximum Information Field Size for the card (IFSC).
/// RP2350 SRAM is not constrained here; 254 is the T=1 maximum.
pub const IFSC: usize = 254;

// ─── PCB block type masks ──────────────────────────────────────────────────

/// I-block: high 2 bits = 0b00, i.e. PCB & 0x80 == 0
const IBLOCK_MASK: u8 = 0x80;
const IBLOCK_TAG: u8 = 0x00;

/// R-block: high 2 bits = 0b10, i.e. PCB & 0xC0 == 0x80
const RBLOCK_MASK: u8 = 0xC0;
const RBLOCK_TAG: u8 = 0x80;

/// S-block: high 2 bits = 0b11, i.e. PCB & 0xC0 == 0xC0
const SBLOCK_MASK: u8 = 0xC0;
const SBLOCK_TAG: u8 = 0xC0;

// ─── S-block subtypes ─────────────────────────────────────────────────────

const SBLOCK_RESYNCH_REQ: u8 = 0xC0;
const SBLOCK_RESYNCH_RESP: u8 = 0xE0;
const SBLOCK_IFS_REQ: u8 = 0xC1;
const SBLOCK_IFS_RESP: u8 = 0xE1;
const SBLOCK_ABORT_REQ: u8 = 0xC2;
const SBLOCK_ABORT_RESP: u8 = 0xE2;
const SBLOCK_WTX_REQ: u8 = 0xC3;
const SBLOCK_WTX_RESP: u8 = 0xE3;

// ─── I-block PCB bits ─────────────────────────────────────────────────────

/// Sequence bit in I-block PCB (bit 6).
const IBLOCK_SEQ_BIT: u8 = 0x40;
/// More-data (chaining) bit in I-block PCB (bit 5).
const IBLOCK_MORE_BIT: u8 = 0x20;

// ─── R-block PCB bits ─────────────────────────────────────────────────────

/// Sequence bit in R-block PCB (bit 4).
const RBLOCK_SEQ_BIT: u8 = 0x10;

// ─── T=1 block types encoded in PCB byte ─────────────────────────────────

/// T=1 block types encoded in PCB byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    /// Information block — carries APDU fragment.
    IBlock { seq: bool, more: bool },
    /// Receive-ready / error block.
    RBlock { seq: bool, error: u8 },
    /// Supervisory block (IFS, ABORT, WTX).
    SBlock { request: bool, code: u8 },
}

/// A single parsed T=1 block.
#[derive(Debug)]
pub struct T1Block<'a> {
    pub nad: u8,
    pub block_type: BlockType,
    /// Information field (may be empty for R/S blocks).
    pub inf: &'a [u8],
}

impl<'a> T1Block<'a> {
    /// Parse one T=1 block from a raw byte slice.
    ///
    /// Format: `[NAD] [PCB] [LEN] [INF(0..LEN)] [LRC]`
    /// Minimum length is 4 bytes (NAD + PCB + LEN + LRC with 0 INF bytes).
    pub fn parse(raw: &'a [u8]) -> Result<Self, T1Error> {
        // Need at least NAD + PCB + LEN + LRC
        if raw.len() < 4 {
            return Err(T1Error::TooShort);
        }

        let nad = raw[0];
        let pcb = raw[1];
        let len = raw[2] as usize;

        // Validate total length: NAD(1) + PCB(1) + LEN(1) + INF(len) + LRC(1)
        let expected_total = 3 + len + 1;
        if raw.len() < expected_total {
            return Err(T1Error::TooShort);
        }

        let inf = &raw[3..3 + len];

        // Verify LRC: XOR of NAD through last INF byte must equal the LRC byte.
        let lrc_byte = raw[3 + len];
        let computed_lrc = Self::compute_lrc(&raw[..3 + len]);
        if computed_lrc != lrc_byte {
            return Err(T1Error::ChecksumFail);
        }

        // Decode PCB
        let block_type = if (pcb & IBLOCK_MASK) == IBLOCK_TAG {
            // I-block: bit6 = seq, bit5 = more
            BlockType::IBlock {
                seq: (pcb & IBLOCK_SEQ_BIT) != 0,
                more: (pcb & IBLOCK_MORE_BIT) != 0,
            }
        } else if (pcb & RBLOCK_MASK) == RBLOCK_TAG {
            // R-block: bit4 = seq, bits 1:0 = error code
            BlockType::RBlock {
                seq: (pcb & RBLOCK_SEQ_BIT) != 0,
                error: pcb & 0x03,
            }
        } else if (pcb & SBLOCK_MASK) == SBLOCK_TAG {
            // S-block: bit5 = response (1) vs request (0)
            BlockType::SBlock {
                request: (pcb & 0x20) == 0,
                code: pcb,
            }
        } else {
            return Err(T1Error::InvalidBlock);
        };

        Ok(T1Block { nad, block_type, inf })
    }

    /// Compute LRC: XOR of all bytes in `data`.
    fn compute_lrc(data: &[u8]) -> u8 {
        data.iter().fold(0u8, |a, &b| a ^ b)
    }
}

/// T=1 framing errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T1Error {
    /// The block is shorter than the minimum 4 bytes.
    TooShort,
    /// EDC checksum mismatch.
    ChecksumFail,
    /// PCB byte encoding is invalid.
    InvalidBlock,
    /// The reassembly buffer would overflow.
    BufferOverflow,
    /// Sequence number mismatch.
    SequenceError,
}

/// Result returned by [`T1State::process_block`].
pub enum T1Result {
    /// More I-blocks needed before the APDU is complete.
    IncompleteApdu,
    /// APDU fully assembled in the `apdu_buf` passed to `process_block`.
    CompleteApdu,
    /// An S-block response that must be sent back to the host before the next I-block.
    SBlockResponse(Vec<u8, 16>),
    /// A protocol error occurred.
    Error(T1Error),
}

/// Stateful T=1 protocol engine.
///
/// Manages sequence numbers, IFSC/IFSD negotiation, and I-block reassembly.
pub struct T1State {
    /// Send-sequence number for I-blocks we originate (0 or 1).
    send_seq: u8,
    /// Expected receive-sequence number for incoming I-blocks.
    recv_seq: u8,
    /// Card Information Field Size — maximum INF bytes per card→host I-block.
    pub ifsc: u8,
    /// Device Information Field Size — maximum INF bytes per host→card I-block.
    pub ifsd: u8,
}

impl T1State {
    /// Create a new T=1 state with default IFSC/IFSD of 254.
    pub fn new() -> Self {
        T1State {
            send_seq: 0,
            recv_seq: 0,
            ifsc: IFSC as u8,
            ifsd: IFSC as u8,
        }
    }

    /// Process a raw T=1 block received from the CCID XfrBlock payload.
    ///
    /// On an I-block, appends the INF field to `apdu_buf`.
    /// Returns `CompleteApdu` when the last block of a (possibly chained) APDU
    /// is received.  Returns `SBlockResponse` for S-block exchanges that must
    /// be completed before the next I-block arrives.
    pub fn process_block(
        &mut self,
        block: &[u8],
        apdu_buf: &mut Vec<u8, 4096>,
    ) -> T1Result {
        let parsed = match T1Block::parse(block) {
            Ok(b) => b,
            Err(e) => return T1Result::Error(e),
        };

        match parsed.block_type {
            BlockType::IBlock { seq, more } => {
                // Sequence number check
                let expected = self.recv_seq & 1;
                if seq != (expected != 0) {
                    // Unexpected sequence — respond with R-block (error)
                    return T1Result::Error(T1Error::SequenceError);
                }

                // Append INF to assembly buffer
                if apdu_buf.extend_from_slice(parsed.inf).is_err() {
                    return T1Result::Error(T1Error::BufferOverflow);
                }

                // Advance expected recv sequence
                self.recv_seq = self.recv_seq.wrapping_add(1) & 1;

                if more {
                    // Chaining: send R(ACK) and wait for next block
                    // The caller will need to respond with an R-block to request
                    // the next chained I-block.  We signal IncompleteApdu; the
                    // CCID layer must build and send the R-block itself since we
                    // don't own the transport here.
                    T1Result::IncompleteApdu
                } else {
                    T1Result::CompleteApdu
                }
            }

            BlockType::RBlock { seq: _, error } => {
                // R-block from the host is an ACK or error-recovery request.
                // For our simple implementation, treat as IncompleteApdu — the
                // upper CCID layer will handle retransmission if needed.
                if error == 0 {
                    T1Result::IncompleteApdu
                } else {
                    T1Result::Error(T1Error::InvalidBlock)
                }
            }

            BlockType::SBlock { request, code } => {
                // Build the appropriate S-block response
                let resp = self.build_sblock_response(code, parsed.inf);
                match resp {
                    Ok(v) => T1Result::SBlockResponse(v),
                    Err(e) => T1Result::Error(e),
                }
            }
        }
    }

    /// Encode an APDU response into one or more T=1 I-blocks.
    ///
    /// For responses that fit within `ifsc` bytes, produces a single I-block.
    /// For larger responses, produces chained I-blocks with the M-bit set on
    /// all but the last.
    pub fn encode_response(
        &mut self,
        apdu_response: &[u8],
        blocks_out: &mut Vec<Vec<u8, 261>, 32>,
    ) -> Result<(), T1Error> {
        let chunk_size = self.ifsc as usize;
        let mut offset = 0;

        if apdu_response.is_empty() {
            // Empty response — send single I-block with 0-byte INF
            let block = self.build_iblock(&[], false)?;
            blocks_out.push(block).map_err(|_| T1Error::BufferOverflow)?;
            self.send_seq = self.send_seq.wrapping_add(1) & 1;
            return Ok(());
        }

        while offset < apdu_response.len() {
            let end = (offset + chunk_size).min(apdu_response.len());
            let chunk = &apdu_response[offset..end];
            let more = end < apdu_response.len();

            let block = self.build_iblock(chunk, more)?;
            blocks_out.push(block).map_err(|_| T1Error::BufferOverflow)?;

            // Advance send sequence number for each I-block sent
            self.send_seq = self.send_seq.wrapping_add(1) & 1;
            offset = end;
        }

        Ok(())
    }

    /// Compute LRC: XOR of all bytes in `data`.
    fn compute_lrc(data: &[u8]) -> u8 {
        data.iter().fold(0u8, |a, &b| a ^ b)
    }

    /// Build a single I-block with given INF payload.
    fn build_iblock(&self, inf: &[u8], more: bool) -> Result<Vec<u8, 261>, T1Error> {
        // Max block size: NAD(1) + PCB(1) + LEN(1) + INF(254) + LRC(1) = 258
        // We allocate 261 to be safe.
        let mut block: Vec<u8, 261> = Vec::new();

        let mut pcb: u8 = 0x00; // I-block base
        if self.send_seq != 0 {
            pcb |= IBLOCK_SEQ_BIT;
        }
        if more {
            pcb |= IBLOCK_MORE_BIT;
        }

        block.push(0x00).map_err(|_| T1Error::BufferOverflow)?; // NAD
        block.push(pcb).map_err(|_| T1Error::BufferOverflow)?; // PCB
        block.push(inf.len() as u8).map_err(|_| T1Error::BufferOverflow)?; // LEN
        block.extend_from_slice(inf).map_err(|_| T1Error::BufferOverflow)?; // INF

        let lrc = Self::compute_lrc(&block);
        block.push(lrc).map_err(|_| T1Error::BufferOverflow)?; // LRC

        Ok(block)
    }

    /// Build an S-block response to a given S-block request PCB code.
    fn build_sblock_response(&mut self, code: u8, inf: &[u8]) -> Result<Vec<u8, 16>, T1Error> {
        let resp_code = match code {
            SBLOCK_RESYNCH_REQ => {
                // Resync: reset sequence numbers
                self.send_seq = 0;
                self.recv_seq = 0;
                SBLOCK_RESYNCH_RESP
            }
            SBLOCK_IFS_REQ => {
                // IFS request: update our IFSD
                if let Some(&new_ifsd) = inf.first() {
                    self.ifsd = new_ifsd;
                }
                SBLOCK_IFS_RESP
            }
            SBLOCK_ABORT_REQ => SBLOCK_ABORT_RESP,
            SBLOCK_WTX_REQ => SBLOCK_WTX_RESP,
            _ => return Err(T1Error::InvalidBlock),
        };

        // Build response block: NAD(1) + PCB(1) + LEN(1) + INF(0..1) + LRC(1)
        let mut block: Vec<u8, 16> = Vec::new();
        let resp_inf: &[u8] = match code {
            SBLOCK_IFS_REQ => inf, // echo back the IFSD value
            SBLOCK_WTX_REQ => inf, // echo back the WT multiplier
            _ => &[],
        };

        block.push(0x00).map_err(|_| T1Error::BufferOverflow)?; // NAD
        block.push(resp_code).map_err(|_| T1Error::BufferOverflow)?; // PCB
        block.push(resp_inf.len() as u8).map_err(|_| T1Error::BufferOverflow)?; // LEN
        if !resp_inf.is_empty() {
            block.extend_from_slice(resp_inf).map_err(|_| T1Error::BufferOverflow)?;
        }
        let lrc = compute_lrc_slice(&block);
        block.push(lrc).map_err(|_| T1Error::BufferOverflow)?;

        Ok(block)
    }
}

impl Default for T1State {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Legacy types kept for compatibility with the existing scaffold ───────────

/// T=1 reassembler — accumulates I-block fragments into a complete APDU.
pub struct T1Reassembler {
    buf: Vec<u8, 4096>,
    expected_seq: bool,
}

impl T1Reassembler {
    /// Create a new reassembler.
    pub fn new() -> Self {
        T1Reassembler { buf: Vec::new(), expected_seq: false }
    }

    /// Feed one I-block fragment. Returns `Some(&[u8])` when the last block
    /// of a chained APDU has been received.
    pub fn feed(&mut self, block: &T1Block<'_>) -> Result<Option<&[u8]>, T1Error> {
        match block.block_type {
            BlockType::IBlock { seq, more } => {
                // Check sequence
                if seq != self.expected_seq {
                    return Err(T1Error::SequenceError);
                }
                // Append INF
                self.buf.extend_from_slice(block.inf).map_err(|_| T1Error::BufferOverflow)?;
                // Advance expected sequence
                self.expected_seq = !self.expected_seq;

                if more {
                    Ok(None)
                } else {
                    Ok(Some(&self.buf))
                }
            }
            _ => {
                // Non-I-blocks are not handled by the reassembler
                Err(T1Error::InvalidBlock)
            }
        }
    }

    /// Reset reassembly state (e.g. after an error or S(ABORT)).
    pub fn reset(&mut self) {
        self.buf.clear();
        self.expected_seq = false;
    }
}

impl Default for T1Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute LRC: XOR of all bytes in `data`.
fn compute_lrc_slice(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |a, &b| a ^ b)
}
