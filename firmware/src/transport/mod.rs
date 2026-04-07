//! USB CCID transport layer.
//!
//! This module provides the USB device class implementation for the CCID
//! (Chip/Smart Card Interface Device) standard. The RP2350 presents itself
//! as a USB CCID device; the host PKCS#11 library talks to it using
//! standard CCID bulk-transfer messages.
//!
//! # Sub-modules
//! - `ccid`  — CCID class implementation (USB descriptors + bulk message parsing)
//! - `t1`    — ISO 7816-3 T=1 block protocol framing
//!
//! # Data flow
//! ```text
//! USB host (PKCS#11 library)
//!   → USB bulk OUT endpoint
//!     → ccid::CcidMessage (PC_to_RDR_XfrBlock / PC_to_RDR_IccPowerOn / …)
//!       → t1::T1Frame
//!         → raw APDU bytes
//!           → apdu::Dispatcher::dispatch()
//!             → HsmProtocol::process_apdu()
//!               → ApduResponse
//!           ← serialized response
//!         ← T=1 response frame
//!       ← RDR_to_PC_DataBlock
//!     ← USB bulk IN endpoint
//! ← USB host
//! ```

pub mod ccid;
pub mod cdc_serial;
pub mod t1;

pub use ccid::CcidTransport;

/// Maximum APDU size we will handle (extended length APDUs).
pub const MAX_APDU_SIZE: usize = 4096;

/// ATR (Answer to Reset) — SmartCard-HSM 2 ATR.
///
/// Exact ATR of the SmartCard-HSM 2 (Nitrokey HSM 2) so that OpenSC's
/// `sc-hsm` driver binds automatically and pcscd/pcsc_scan report a known
/// card identity.
///
/// Structure:
///   TS=3B TD(0)=FE K=14 TA1=18 TB1=00 TC1=00
///   TD1=81 (T=1, TD2 present)
///   TD2=31 (T=1, TA3 TB3 present)
///   TA3=FE (IFSC=254)  TB3=45 (BWI=4 CWI=5)
///   14 historical bytes (includes "THsm1" tag)
///   TCK=FA  (XOR of all bytes from T0 to last historical = 0x00)
pub const ATR: &[u8] = &[
    0x3B,                               // TS: direct convention
    0xFE,                               // T0: TA1 TB1 TC1 TD1 present, K=14
    0x18,                               // TA1: Fi=372 Di=12
    0x00,                               // TB1: no programming voltage
    0x00,                               // TC1: guard time = 0
    0x81,                               // TD1: TD2 present, T=1
    0x31,                               // TD2: TA3 TB3 present, T=1
    0xFE,                               // TA3: IFSC = 254
    0x45,                               // TB3: BWI=4 CWI=5
    0x80, 0x31, 0x81,                   // historical: card service / capabilities
    0x54, 0x48, 0x53, 0x4D, 0x31,      // historical: "THsm1" (SmartCard-HSM marker)
    0x73, 0x80, 0x21, 0x40, 0x81, 0x07, // historical
    0xFA,                               // TCK: makes XOR(T0..last_hist) == 0x00
];

/// Card status — used by CCID to report card presence.
#[derive(Clone, Copy, PartialEq)]
pub enum CardStatus {
    Present,
    Absent,
}
