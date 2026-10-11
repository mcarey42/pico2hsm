//! Pluggable HSM protocol trait.
//!
//! The firmware supports multiple card protocols (SC-HSM, PIV, OpenPGP)
//! behind a single USB CCID interface. A protocol implementation receives
//! raw APDU bytes and returns a response buffer including SW1/SW2.
//!
//! The APDU dispatcher in `firmware/src/apdu/dispatcher.rs` holds a slice
//! of `&mut dyn HsmProtocol` and calls `handles_aid` at SELECT time to
//! route subsequent commands to the correct implementation.

use heapless::Vec;

/// A pluggable HSM protocol implementation.
///
/// Implementations must be `no_std` compatible and must never allocate.
/// All buffers are stack-allocated via `heapless`.
pub trait HsmProtocol {
    /// Process a raw APDU command buffer.
    ///
    /// Returns a response buffer containing the response data bytes followed
    /// by SW1 and SW2 (status word). The minimum valid response is 2 bytes
    /// (SW1 + SW2 only, i.e. no data).
    ///
    /// The implementation MUST NOT panic. If an unrecoverable internal error
    /// occurs, return `SW_CONDITIONS_NOT_SATISFIED` (0x6985).
    fn process_apdu(&mut self, apdu: &[u8]) -> Vec<u8, 4098>;

    /// Returns `true` if this protocol implementation handles the given AID.
    ///
    /// Called by the dispatcher when a SELECT (INS=0xA4, P1=0x04) command is
    /// received. The `aid` slice is the raw AID bytes from the command data
    /// field (Lc bytes, no padding).
    fn handles_aid(&self, aid: &[u8]) -> bool;

    /// Short ASCII protocol identifier, used in debug/defmt logging.
    fn protocol_name(&self) -> &'static str;
}
