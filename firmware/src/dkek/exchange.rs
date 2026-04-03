//! Noise_XX DKEK share exchange over USB (local) and TCP (network).
//!
//! Two pico2hsm devices can exchange DKEK shares using the Noise_XX
//! handshake pattern. This provides:
//! - Mutual authentication (both devices present static key pairs)
//! - Forward secrecy (ephemeral keys per session)
//! - Encrypted transport for the DKEK share bytes
//!
//! # Protocol overview
//! ```text
//! Initiator (host)          Responder (device)
//!     → Noise_XX msg1  ────────────────→
//!     ← Noise_XX msg2  ←────────────────
//!     → Noise_XX msg3  ────────────────→
//!     [handshake complete — transport keys established]
//!     → DKEK_SHARE_CMD ────────────────→
//!     ← DKEK_SHARE_ACK ←────────────────
//! ```
//!
//! # USB transport
//! Over USB, the Noise frames are carried inside SC-HSM proprietary APDUs:
//! - INS=0x54 (EXTRAS), P1=0x10: Send Noise frame, receive response frame
//!
//! # TCP transport
//! For HSM-to-HSM backup over a network, the Noise frames are carried
//! directly over a TCP connection. The HSM listens on port 4443 (configurable
//! via OTP user area).
//!
//! # Static key pairs
//! Each HSM has a static Noise key pair stored in the keystore under a
//! reserved key ID. The key pair is generated during INITIALIZE and the
//! public key is included in the EF.DevAut file for peer authentication.
//!
//! # TODO (DKEK specialist agent)
//! - Implement `NoiseSession::new_initiator()` using snow crate
//! - Implement `NoiseSession::new_responder()` using snow crate
//! - Implement `NoiseSession::handshake_step()` — advance Noise state machine
//! - Implement `NoiseSession::send_share()` — encrypt and send DKEK share
//! - Implement `NoiseSession::receive_share()` — receive and decrypt DKEK share

use pico2hsm_core::error::HsmError;

/// A Noise_XX session for DKEK exchange.
pub struct NoiseSession {
    // TODO: implement — snow HandshakeState or TransportState
    state: NoiseState,
}

/// Internal Noise protocol state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoiseState {
    /// Handshake not yet started.
    Idle,
    /// Handshake in progress (step 1 of 3).
    Handshaking { step: u8 },
    /// Handshake complete; transport keys established.
    Transport,
    /// Session terminated or errored.
    Closed,
}

impl NoiseSession {
    /// Create a new Noise_XX session as initiator.
    pub fn new_initiator(_static_keypair: &[u8; 64]) -> Result<Self, HsmError> {
        // TODO: implement using snow crate
        Ok(NoiseSession { state: NoiseState::Idle })
    }

    /// Create a new Noise_XX session as responder.
    pub fn new_responder(_static_keypair: &[u8; 64]) -> Result<Self, HsmError> {
        // TODO: implement using snow crate
        Ok(NoiseSession { state: NoiseState::Idle })
    }

    /// Advance the Noise handshake by one step.
    ///
    /// `input` is the received handshake message (empty for the first initiator step).
    /// Returns the message to send to the peer.
    pub fn handshake_step(
        &mut self,
        _input: &[u8],
        _output: &mut heapless::Vec<u8, 256>,
    ) -> Result<bool, HsmError> {
        // TODO: implement — returns true when handshake is complete
        Err(HsmError::NotSupported)
    }

    /// Send a DKEK share encrypted under the established transport key.
    ///
    /// Only valid after handshake is complete.
    pub fn send_share(
        &mut self,
        _share: &[u8; 32],
        _output: &mut heapless::Vec<u8, 64>,
    ) -> Result<(), HsmError> {
        // TODO: implement
        Err(HsmError::NotSupported)
    }

    /// Receive and decrypt a DKEK share from the peer.
    ///
    /// Only valid after handshake is complete.
    pub fn receive_share(
        &mut self,
        _ciphertext: &[u8],
    ) -> Result<[u8; 32], HsmError> {
        // TODO: implement
        Err(HsmError::NotSupported)
    }

    /// Returns `true` if the Noise handshake is complete.
    pub fn is_transport_ready(&self) -> bool {
        self.state == NoiseState::Transport
    }
}
