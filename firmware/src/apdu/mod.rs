//! APDU dispatcher module.
//!
//! Receives raw APDU byte slices from the T=1 reassembler and routes them to
//! the correct `HsmProtocol` implementation based on the currently selected
//! AID or default protocol.

pub mod dispatcher;

pub use dispatcher::Dispatcher;
