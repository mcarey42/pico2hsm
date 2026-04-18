//! CCID (Chip/Smart Card Interface Device) USB class implementation.
//!
//! Implements the USB CCID class specification v1.1. The device exposes:
//! - One bulk OUT endpoint (host → device commands)
//! - One bulk IN endpoint  (device → host responses)
//! - One interrupt IN endpoint (slot change notifications, 8-byte packets)
//!
//! # CCID message types handled
//! | PC_to_RDR | Description |
//! |-----------|-------------|
//! | 0x62 IccPowerOn | Power on the ICC slot; return ATR |
//! | 0x63 IccPowerOff | Power off the ICC slot |
//! | 0x65 GetSlotStatus | Return current slot status |
//! | 0x6F XfrBlock | Transmit APDU block; return response |
//! | 0x6C GetParameters | Return current T=1 parameters |
//! | 0x6D ResetParameters | Reset T=1 parameters to defaults |
//! | 0x61 SetParameters | Set T=1 parameters |

use embassy_usb::driver::{Driver, Endpoint, EndpointError, EndpointIn, EndpointOut};
use embassy_usb::Builder;
use heapless::Vec;

use crate::transport::{ATR, MAX_APDU_SIZE};

// ─── USB CCID class constants ─────────────────────────────────────────────

/// USB interface class for Smart Card (CCID).
const USB_CLASS_CCID: u8 = 0x0B;
const USB_SUBCLASS_CCID: u8 = 0x00;
const USB_PROTOCOL_CCID: u8 = 0x00;

/// CCID class descriptor type.
const CCID_DESCRIPTOR_TYPE: u8 = 0x21;

/// CCID class descriptor (54 bytes).
///
/// Describes the CCID reader capabilities to the host driver:
/// - dwProtocols: T=1 (0x02)
/// - dwFeatures: auto params + T=1 + extended APDUs (0x000400FE)
/// - dwMaxCCIDMessageLength: 4096 (0x00001000)
const CCID_CLASS_DESCRIPTOR: [u8; 54] = [
    54,   // bLength
    0x21, // bDescriptorType (CCID)
    0x10, 0x01, // bcdCCID (1.10)
    0x00, // bMaxSlotIndex (0 = 1 slot)
    0x03, // bVoltageSupport (5V and 3.3V)
    0x02, 0x00, 0x00, 0x00, // dwProtocols: T=1
    0xA0, 0x0F, 0x00, 0x00, // dwDefaultClock (4000 kHz)
    0xA0, 0x0F, 0x00, 0x00, // dwMaximumClock
    0x00, // bNumClockSupported
    0x00, 0x2A, 0x00, 0x00, // dwDataRate (10752 bps default)
    0x00, 0x2A, 0x00, 0x00, // dwMaxDataRate
    0x00, // bNumDataRatesSupported
    0xFE, 0x00, 0x00, 0x00, // dwMaxIFSD (254)
    0x00, 0x00, 0x00, 0x00, // dwSynchProtocols
    0x00, 0x00, 0x00, 0x00, // dwMechanical
    0xFE, 0x00, 0x04,
    0x00, // dwFeatures: 0x000400FE — auto-params + Short&Extended APDU exchange
    0x00, 0x10, 0x00, 0x00, // dwMaxCCIDMessageLength (4096)
    0xFF, // bClassGetResponse
    0xFF, // bClassEnvelope
    0x00, 0x00, // wLcdLayout (no LCD)
    0x00, // bPINSupport
    0x01, // bMaxCCIDBusySlots
];

// ─── PC_to_RDR message type codes ─────────────────────────────────────────

const PC_TO_RDR_ICCPOWERON: u8 = 0x62;
const PC_TO_RDR_ICCPOWEROFF: u8 = 0x63;
const PC_TO_RDR_GETSLOTSTATUS: u8 = 0x65;
const PC_TO_RDR_XFRBLOCK: u8 = 0x6F;
const PC_TO_RDR_GETPARAMETERS: u8 = 0x6C;
const PC_TO_RDR_RESETPARAMETERS: u8 = 0x6D;
const PC_TO_RDR_SETPARAMETERS: u8 = 0x61;
const PC_TO_RDR_ESCAPE: u8 = 0x6B;
const PC_TO_RDR_ICCCLOCK: u8 = 0x6E;
const PC_TO_RDR_T0APDU: u8 = 0x6A;
const PC_TO_RDR_MECHANICAL: u8 = 0x71;
const PC_TO_RDR_ABORT: u8 = 0x72;
const PC_TO_RDR_SETDATARATE: u8 = 0x73;

// ─── RDR_to_PC message type codes ─────────────────────────────────────────

const RDR_TO_PC_DATABLOCK: u8 = 0x80;
const RDR_TO_PC_SLOTSTATUS: u8 = 0x81;
const RDR_TO_PC_PARAMETERS: u8 = 0x82;
const RDR_TO_PC_ESCAPE: u8 = 0x83;
const RDR_TO_PC_DATARATEANDCLOCK: u8 = 0x84;

// ─── CCID status / error byte values ──────────────────────────────────────

/// bStatus: card active, no error.
const STATUS_OK: u8 = 0x00;
/// bStatus: command not supported.
const STATUS_CMD_NOT_SUPPORTED: u8 = 0x40;
/// bError: slot not present (used when card is absent).
const ERROR_SLOT_NOT_PRESENT: u8 = 0x05;
/// bError: no error.
const ERROR_OK: u8 = 0x00;

// ─── Bulk packet size ─────────────────────────────────────────────────────

/// USB full-speed bulk endpoint max packet size.
const BULK_MAX_PACKET_SIZE: u16 = 64;
/// USB interrupt endpoint max packet size for slot notifications.
const INTR_MAX_PACKET_SIZE: u16 = 8;

// ─── CCID header length ───────────────────────────────────────────────────

const CCID_HEADER_LEN: usize = 10;

// ─── T=1 Parameters (for GetParameters / SetParameters response) ──────────

/// Default T=1 parameters structure as returned by GetParameters / SetParameters.
/// Format matches bProtocolNum = 0x01 (T=1) parameter block.
const T1_PARAMS: [u8; 7] = [
    0x11, // bmFindexDindex
    0x10, // bmTCCKST1
    0x00, // bGuardTimeT1
    0x4D, // bmWaitingIntegersT1 (BWI=4, CWI=13)
    0x00, // bClockStop
    0xFE, // bIFSC = 254
    0x00, // bNadValue
];

// ─── CCID header struct ────────────────────────────────────────────────────

/// Parsed CCID message header (10 bytes).
pub struct CcidHeader {
    pub msg_type: u8,
    pub length: u32,
    pub slot: u8,
    pub seq: u8,
    /// bStatus in responses / specific byte in commands.
    pub status: u8,
    pub error: u8,
    pub specific: u8,
}

impl CcidHeader {
    /// Parse a 10-byte CCID header from a raw slice.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < CCID_HEADER_LEN {
            return None;
        }
        Some(CcidHeader {
            msg_type: b[0],
            length: u32::from_le_bytes([b[1], b[2], b[3], b[4]]),
            slot: b[5],
            seq: b[6],
            status: b[7],
            error: b[8],
            specific: b[9],
        })
    }

    /// Serialize a 10-byte CCID response header.
    pub fn to_bytes(&self) -> [u8; 10] {
        let len = self.length.to_le_bytes();
        [
            self.msg_type,
            len[0],
            len[1],
            len[2],
            len[3],
            self.slot,
            self.seq,
            self.status,
            self.error,
            self.specific,
        ]
    }
}

// ─── CcidError ────────────────────────────────────────────────────────────

/// Errors returned by the CCID transport.
#[derive(Debug)]
pub enum CcidError {
    /// USB endpoint disconnected or disabled.
    UsbDisconnected,
    /// Received CCID message is malformed.
    MalformedMessage,
    /// Buffer capacity exceeded.
    BufferOverflow,
}

impl From<EndpointError> for CcidError {
    fn from(e: EndpointError) -> Self {
        match e {
            EndpointError::Disabled => CcidError::UsbDisconnected,
            EndpointError::BufferOverflow => CcidError::BufferOverflow,
        }
    }
}

// ─── CcidTransport ────────────────────────────────────────────────────────

/// CCID USB transport.
///
/// Owns the three USB endpoints and drives the CCID state machine:
/// - Bulk OUT: receives PC_to_RDR messages
/// - Bulk IN:  sends RDR_to_PC responses
/// - Interrupt IN: sends slot-change notifications (not actively used here)
pub struct CcidTransport<'d, D: Driver<'d>> {
    read_ep: D::EndpointOut,
    write_ep: D::EndpointIn,
    intr_ep: D::EndpointIn,
    /// True after `IccPowerOn`; false initially and after `IccPowerOff`.
    /// Determines `bmICCStatus` in slot-status responses.
    card_powered: bool,
    /// Sequence number from the last XfrBlock; echoed in the DataBlock response.
    pending_seq: u8,
}

impl<'d, D: Driver<'d>> CcidTransport<'d, D> {
    /// Register the CCID interface with the embassy-usb builder and return a
    /// `CcidTransport` that owns the allocated endpoints.
    ///
    /// # Arguments
    /// * `builder` — mutable reference to the USB device builder.
    pub fn new(builder: &mut Builder<'d, D>) -> Self {
        // CCID is a single-interface function (no IAD needed when device is
        // non-composite, but embassy-usb's `function()` call handles the IAD
        // automatically when composite_with_iads is set).
        let mut func = builder.function(USB_CLASS_CCID, USB_SUBCLASS_CCID, USB_PROTOCOL_CCID);
        let mut iface = func.interface();
        let mut alt = iface.alt_setting(USB_CLASS_CCID, USB_SUBCLASS_CCID, USB_PROTOCOL_CCID, None);

        // Write the 54-byte CCID class descriptor after the interface descriptor.
        alt.descriptor(CCID_DESCRIPTOR_TYPE, &CCID_CLASS_DESCRIPTOR[2..]);

        // Allocate endpoints: Bulk OUT, Bulk IN, Interrupt IN.
        let read_ep = alt.endpoint_bulk_out(None, BULK_MAX_PACKET_SIZE);
        let write_ep = alt.endpoint_bulk_in(None, BULK_MAX_PACKET_SIZE);
        let intr_ep = alt.endpoint_interrupt_in(None, INTR_MAX_PACKET_SIZE, 16);

        drop(func);

        CcidTransport {
            read_ep,
            write_ep,
            intr_ep,
            card_powered: false,
            pending_seq: 0,
        }
    }

    /// Wait until the USB device is enumerated, then announce card presence.
    ///
    /// Blocks until the bulk-OUT endpoint is enabled (host has configured the
    /// device). After that, sends `RDR_to_PC_NotifySlotChange` on the interrupt
    /// IN endpoint so that libccid's monitoring thread unblocks and tells pcscd
    /// that a card is present in slot 0.
    ///
    /// # Interrupt notification timeout
    ///
    /// The interrupt write is capped at 250 ms.  If pcscd hasn't started polling
    /// the interrupt endpoint within that window (which happens when pcscd's
    /// internal reader-init sequence is already in progress and hasn't reached
    /// the interrupt-monitor thread yet), the write is abandoned and the firmware
    /// proceeds directly to `recv_apdu()`.  pcscd will still discover the card
    /// via the next `PC_to_RDR_GetSlotStatus` exchange, which returns status 0x01
    /// (ICC present, inactive) — libccid then sends `IccPowerOn` and receives
    /// the ATR normally.
    ///
    /// Without this timeout there is a deadlock:
    ///   * The firmware awaits the interrupt write (waiting for the host to poll
    ///     the IN interrupt endpoint).
    ///   * pcscd is concurrently trying to write a `PC_to_RDR_GetSlotStatus`
    ///     command to the bulk-OUT endpoint.
    ///   * Because the firmware is not in `recv_apdu()`, the bulk-OUT buffer
    ///     fills and pcscd's write receives USB NAKs until it times out (~100 s).
    ///   * pcscd then marks the reader "unavailable" and stops polling the
    ///     interrupt endpoint — so the firmware's write never completes.
    pub async fn wait_connected(&mut self) {
        self.read_ep.wait_enabled().await;
        // Reset ICC state — each new USB session starts with an unpowered card.
        self.card_powered = false;
        // RDR_to_PC_NotifySlotChange: bmSlotICCState byte
        //   bit 0 = slot 0 ICC present (1)
        //   bit 1 = slot 0 ICC state changed (1)
        // → 0x03: card inserted (state transition)
        //
        // Use a timeout so we never block here if pcscd isn't polling yet.
        let _ = embassy_time::with_timeout(
            embassy_time::Duration::from_millis(250),
            self.intr_ep.write(&[0x50, 0x03]),
        )
        .await;
    }

    /// Wait for a complete APDU from the host.
    ///
    /// Reads CCID bulk messages in a loop, handling control messages (power
    /// on/off, slot status, parameters) internally and returning only when a
    /// complete application-layer APDU has been received via XfrBlock.
    ///
    /// With APDU-level exchange (dwFeatures 0x00040000) the host sends raw
    /// APDUs directly; no T=1 framing at the CCID layer.
    ///
    /// The returned `Vec` contains the raw APDU bytes (CLA INS P1 P2 ...).
    pub async fn recv_apdu(&mut self) -> Result<Vec<u8, 4096>, CcidError> {
        // Single receive buffer for multi-packet CCID messages.
        // After extracting the APDU payload from an XfrBlock, the 10-byte
        // CCID header is stripped in-place and the same buffer is returned,
        // avoiding a second 4096-byte stack allocation.
        let mut raw: Vec<u8, 4096> = Vec::new();

        loop {
            // ── Read CCID message from bulk-OUT endpoint ──────────────────
            raw.clear();

            // Read the 10-byte header first (may span multiple 64-byte packets)
            let header = self.read_ccid_message(&mut raw).await?;

            // ── Dispatch on message type ──────────────────────────────────
            match header.msg_type {
                PC_TO_RDR_ICCPOWERON => {
                    self.handle_power_on(header.seq).await?;
                }
                PC_TO_RDR_ICCPOWEROFF => {
                    self.handle_power_off(header.seq).await?;
                }
                PC_TO_RDR_GETSLOTSTATUS => {
                    self.handle_get_slot_status(header.seq).await?;
                }
                PC_TO_RDR_GETPARAMETERS | PC_TO_RDR_RESETPARAMETERS => {
                    self.handle_get_parameters(header.seq).await?;
                }
                PC_TO_RDR_SETPARAMETERS => {
                    self.handle_set_parameters(header.seq).await?;
                }
                PC_TO_RDR_ESCAPE => {
                    // Not supported — return command-not-supported
                    self.send_slot_status(
                        RDR_TO_PC_ESCAPE,
                        header.seq,
                        STATUS_CMD_NOT_SUPPORTED,
                        0x00,
                    )
                    .await?;
                }
                PC_TO_RDR_ICCCLOCK
                | PC_TO_RDR_T0APDU
                | PC_TO_RDR_MECHANICAL
                | PC_TO_RDR_ABORT
                | PC_TO_RDR_SETDATARATE => {
                    // Not supported — return slot status with command-not-supported
                    let resp = self.build_slot_status(header.seq, STATUS_CMD_NOT_SUPPORTED, 0x00);
                    self.write_response(&resp).await?;
                }
                PC_TO_RDR_XFRBLOCK => {
                    // dwFeatures = 0x000400FE includes bit 0x00040000 (Short and
                    // Extended APDU level exchange). The host sends a raw APDU as
                    // the XfrBlock payload — no T=1 framing at the CCID layer.
                    if raw.len() <= CCID_HEADER_LEN {
                        let resp = self.build_slot_status(header.seq, 0x40, 0x00);
                        self.write_response(&resp).await?;
                    } else {
                        self.pending_seq = header.seq;
                        // Strip the 10-byte CCID header in-place: copy payload
                        // bytes down to the start of the buffer, then truncate.
                        let payload_len = raw.len() - CCID_HEADER_LEN;
                        raw.copy_within(CCID_HEADER_LEN.., 0);
                        raw.truncate(payload_len);
                        return Ok(raw);
                    }
                }
                _ => {
                    // Unknown command — return command-not-supported
                    let resp = self.build_slot_status(header.seq, STATUS_CMD_NOT_SUPPORTED, 0x00);
                    self.write_response(&resp).await?;
                }
            }
        }
    }

    /// Send a CCID time extension request to the host.
    ///
    /// Called while core1 is processing a long APDU (P-384/P-521 ECC) to reset
    /// pcscd's XfrBlock timeout.  The host sees a `RDR_to_PC_DataBlock` with
    /// `bStatus = 0x80` (bmCommandStatus = time extension) and resets its timer.
    ///
    /// `bError = 1` requests one additional BWI unit.  With BWI=4 in T1_PARAMS
    /// the host waits roughly 1–2 seconds per extension before retrying.
    /// Call this every ~1.5 s to stay well inside any reasonable host timeout.
    pub async fn send_time_extension(&mut self) -> Result<(), CcidError> {
        let msg = [
            RDR_TO_PC_DATABLOCK,
            0x00,
            0x00,
            0x00,
            0x00, // dwLength = 0 (no APDU data yet)
            0x00, // bSlot
            self.pending_seq,
            0x80, // bStatus: bmCommandStatus = 10 (time extension)
            0x01, // bError: 1 BWI unit extension
            0x00, // bChainParameter
        ];
        self.write_response(&msg).await
    }

    /// Send an APDU response back to the host in a single RDR_to_PC_DataBlock.
    ///
    /// With APDU-level exchange (dwFeatures bit 0x00040000) the response bytes
    /// are sent directly — no T=1 framing at the CCID layer.
    pub async fn send_response(&mut self, apdu_response: &[u8]) -> Result<(), CcidError> {
        let seq = self.pending_seq;
        let hdr = self.build_data_block_header(seq, apdu_response.len() as u32);
        // Header and payload must travel in one USB bulk transfer.  Sending the
        // 10-byte header alone creates a short packet that terminates the transfer
        // before the APDU data arrives, leaving libccid with no response data.
        let mut msg: Vec<u8, 4106> = Vec::new(); // 10 header + up to 4096 payload
        msg.extend_from_slice(&hdr)
            .map_err(|_| CcidError::BufferOverflow)?;
        msg.extend_from_slice(apdu_response)
            .map_err(|_| CcidError::BufferOverflow)?;
        let total = msg.len();
        self.write_response(&msg).await?;
        // Zero-length packet if total is an exact multiple of the bulk packet size.
        if total % BULK_MAX_PACKET_SIZE as usize == 0 {
            self.write_response(&[]).await?;
        }
        Ok(())
    }

    // ─── Internal helpers ─────────────────────────────────────────────────

    /// Read a complete CCID message (header + payload) from the bulk-OUT
    /// endpoint into `buf`.  Returns the parsed header.
    ///
    /// CCID messages may be larger than one 64-byte USB packet, so we continue
    /// reading until we have `header.length` payload bytes after the 10-byte
    /// header.
    async fn read_ccid_message(
        &mut self,
        buf: &mut Vec<u8, 4096>,
    ) -> Result<CcidHeader, CcidError> {
        let mut pkt = [0u8; 64];

        // Read packets until we have at least the 10-byte CCID header.
        while buf.len() < CCID_HEADER_LEN {
            let n = self.read_ep.read(&mut pkt).await?;
            buf.extend_from_slice(&pkt[..n])
                .map_err(|_| CcidError::BufferOverflow)?;
        }

        let header = CcidHeader::from_bytes(buf).ok_or(CcidError::MalformedMessage)?;
        let payload_len = header.length as usize;
        let total = CCID_HEADER_LEN + payload_len;

        // Read remaining packets until we have the full message.
        while buf.len() < total {
            let n = self.read_ep.read(&mut pkt).await?;
            buf.extend_from_slice(&pkt[..n])
                .map_err(|_| CcidError::BufferOverflow)?;
        }

        Ok(header)
    }

    /// Write `data` to the bulk-IN endpoint, chunked into max-packet-size pieces.
    async fn write_response(&mut self, data: &[u8]) -> Result<(), CcidError> {
        if data.is_empty() {
            // Zero-length packet
            self.write_ep.write(&[]).await?;
            return Ok(());
        }

        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + BULK_MAX_PACKET_SIZE as usize).min(data.len());
            self.write_ep.write(&data[offset..end]).await?;
            offset = end;
        }
        Ok(())
    }

    /// Handle `PC_TO_RDR_ICCPOWERON`: respond with ATR in a DataBlock.
    async fn handle_power_on(&mut self, seq: u8) -> Result<(), CcidError> {
        self.card_powered = true;
        let hdr = self.build_data_block_header(seq, ATR.len() as u32);
        // Header and ATR must be in one buffer so they go in a single USB bulk
        // transfer.  A 10-byte header sent alone is a short packet (< 64 bytes)
        // that terminates the transfer; libccid would then treat the header bytes
        // as the ATR instead of reading the payload.
        let mut msg: Vec<u8, 64> = Vec::new(); // 10 header + up to 33 ATR bytes
        msg.extend_from_slice(&hdr).unwrap();
        msg.extend_from_slice(ATR).unwrap();
        // 10 + 24 = 34 bytes — not a multiple of 64, no ZLP needed.
        self.write_response(&msg).await
    }

    /// Handle `PC_TO_RDR_ICCPOWEROFF`: respond with SlotStatus.
    async fn handle_power_off(&mut self, seq: u8) -> Result<(), CcidError> {
        self.card_powered = false;
        // bStatus = 0x01: ICC present but no longer active
        let resp = self.build_slot_status(seq, 0x01, ERROR_OK);
        self.write_response(&resp).await
    }

    /// Handle `PC_TO_RDR_GETSLOTSTATUS`: respond with current slot status.
    ///
    /// `bmICCStatus`:
    /// - 0x00 = ICC present and active (after IccPowerOn)
    /// - 0x01 = ICC present but inactive (before first IccPowerOn, or after IccPowerOff)
    async fn handle_get_slot_status(&mut self, seq: u8) -> Result<(), CcidError> {
        let status = if self.card_powered { 0x00 } else { 0x01 };
        let resp = self.build_slot_status(seq, status, ERROR_OK);
        self.write_response(&resp).await
    }

    /// Handle `PC_TO_RDR_GETPARAMETERS` / `PC_TO_RDR_RESETPARAMETERS`:
    /// respond with RDR_to_PC_Parameters containing T=1 parameter block.
    async fn handle_get_parameters(&mut self, seq: u8) -> Result<(), CcidError> {
        // Header: msg_type=0x82, length=7 (T=1 param block), bProtocolNum=0x01
        let len_le = (T1_PARAMS.len() as u32).to_le_bytes();
        let hdr = [
            RDR_TO_PC_PARAMETERS,
            len_le[0],
            len_le[1],
            len_le[2],
            len_le[3],
            0x00, // bSlot
            seq,
            STATUS_OK,
            ERROR_OK,
            0x01, // bProtocolNum = T=1
        ];
        // Combine header and params in one buffer (same reason as handle_power_on).
        let mut msg: Vec<u8, 18> = Vec::new();
        msg.extend_from_slice(&hdr).unwrap();
        msg.extend_from_slice(&T1_PARAMS).unwrap();
        // 10 + 7 = 17 bytes — not a multiple of 64, no ZLP needed.
        self.write_response(&msg).await
    }

    /// Handle `PC_TO_RDR_SETPARAMETERS`: accept new parameters, echo them back.
    async fn handle_set_parameters(&mut self, seq: u8) -> Result<(), CcidError> {
        // We accept whatever the host sends (for now just respond with current T1_PARAMS)
        self.handle_get_parameters(seq).await
    }

    /// Send an arbitrary 10-byte status message.
    async fn send_slot_status(
        &mut self,
        msg_type: u8,
        seq: u8,
        status: u8,
        error: u8,
    ) -> Result<(), CcidError> {
        let resp = [
            msg_type, 0x00, 0x00, 0x00, 0x00, // dwLength = 0
            0x00, // bSlot
            seq, status, error, 0x00, // bSpecific
        ];
        self.write_response(&resp).await
    }

    /// Build a 10-byte `RDR_to_PC_DataBlock` response header.
    fn build_data_block_header(&self, seq: u8, payload_len: u32) -> [u8; 10] {
        let len = payload_len.to_le_bytes();
        [
            RDR_TO_PC_DATABLOCK,
            len[0],
            len[1],
            len[2],
            len[3],
            0x00, // bSlot
            seq,
            STATUS_OK, // bStatus
            ERROR_OK,  // bError
            0x00,      // bChainParameter (no chaining on our side)
        ]
    }

    /// Build a 10-byte `RDR_to_PC_SlotStatus` response.
    fn build_slot_status(&self, seq: u8, status: u8, error: u8) -> [u8; 10] {
        [
            RDR_TO_PC_SLOTSTATUS,
            0x00,
            0x00,
            0x00,
            0x00, // dwLength = 0
            0x00, // bSlot
            seq,
            status,
            error,
            0x00, // bClockStatus (card clock running)
        ]
    }
}

// ─── Legacy types kept for compatibility with the existing scaffold ───────────

/// CCID message types from host to device (PC_to_RDR).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcToRdrMsgType {
    IccPowerOn = 0x62,
    IccPowerOff = 0x63,
    GetSlotStatus = 0x65,
    XfrBlock = 0x6F,
    GetParameters = 0x61,
}

/// CCID message types from device to host (RDR_to_PC).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdrToPcMsgType {
    DataBlock = 0x80,
    SlotStatus = 0x81,
    Parameters = 0x82,
}

/// A parsed PC_to_RDR_XfrBlock message.
#[derive(Debug)]
pub struct XfrBlock<'a> {
    /// Sequence number (bSeq).
    pub seq: u8,
    /// Block waiting time extension (bBWI).
    pub bwi: u8,
    /// Level parameter (wLevelParameter).
    pub level: u16,
    /// APDU data (may be a T=1 frame or raw APDU depending on level).
    pub data: &'a [u8],
}

/// Simulated ATR (Answer to Reset) for the virtual SC-HSM slot.
///
/// This is re-exported from the transport module constants for backward
/// compatibility.  The canonical ATR is defined in `transport::ATR`.
pub use crate::transport::ATR as ATR_BYTES;

/// CCID transport handler (simple message-based variant without embassy-usb).
///
/// Kept for host-side unit testing and backward compatibility.
pub struct CcidHandler {
    // TODO: implement — embassy-usb handler fields
}

impl CcidHandler {
    /// Create a new `CcidHandler`.
    pub fn new() -> Self {
        CcidHandler {}
    }

    /// Process one incoming CCID bulk message.
    ///
    /// Returns the response bytes to be sent on the bulk IN endpoint.
    pub async fn process_message<'a>(&mut self, _msg: &'a [u8], _out: &mut Vec<u8, 512>) {
        // TODO: implement
    }
}

impl Default for CcidHandler {
    fn default() -> Self {
        Self::new()
    }
}
