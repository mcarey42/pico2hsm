//! Integration tests for APDU parsing (pico2hsm-core).
//!
//! These tests run on the host (std) and exercise the no_std APDU parser.

use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_OK};

#[test]
fn test_case1_apdu_parse() {
    // Case 1: [CLA INS P1 P2] — no data, no Le
    let raw = [0x00u8, 0xA4, 0x04, 0x00];
    let cmd = ApduCommand::parse(&raw).expect("Case 1 parse failed");
    assert_eq!(cmd.cla, 0x00);
    assert_eq!(cmd.ins, 0xA4);
    assert_eq!(cmd.p1, 0x04);
    assert_eq!(cmd.p2, 0x00);
    assert!(cmd.data.is_empty());
    assert_eq!(cmd.le, None);
}

#[test]
fn test_case2s_apdu_parse() {
    // Case 2S: [CLA INS P1 P2 Le]
    let raw = [0x00u8, 0x84, 0x00, 0x00, 0x08];
    let cmd = ApduCommand::parse(&raw).expect("Case 2S parse failed");
    assert_eq!(cmd.le, Some(8));
}

#[test]
fn test_case2s_le_zero() {
    // Case 2S: Le=0x00 means 256 bytes expected
    let raw = [0x00u8, 0x84, 0x00, 0x00, 0x00];
    let cmd = ApduCommand::parse(&raw).expect("Case 2S Le=0 parse failed");
    assert_eq!(cmd.le, Some(256));
}

#[test]
fn test_case3s_apdu_parse() {
    // Case 3S: [CLA INS P1 P2 Lc data...]
    let raw = [0x00u8, 0x20, 0x00, 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36];
    let cmd = ApduCommand::parse(&raw).expect("Case 3S parse failed");
    assert_eq!(cmd.data, &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36]);
    assert_eq!(cmd.le, None);
}

#[test]
fn test_case4s_apdu_parse() {
    // Case 4S: [CLA INS P1 P2 Lc data... Le]
    let raw = [0x00u8, 0x20, 0x00, 0x81, 0x04, 0x01, 0x02, 0x03, 0x04, 0x10];
    let cmd = ApduCommand::parse(&raw).expect("Case 4S parse failed");
    assert_eq!(cmd.data.len(), 4);
    assert_eq!(cmd.le, Some(0x10));
}

#[test]
fn test_apdu_too_short() {
    use pico2hsm_core::error::ProtocolError;
    let raw = [0x00u8, 0xA4, 0x04];
    let result = ApduCommand::parse(&raw);
    assert_eq!(result, Err(ProtocolError::ApduTooShort));
}

#[test]
fn test_apdu_response_ok() {
    let data = [0xDE, 0xAD, 0xBE, 0xEF];
    let resp = ApduResponse::ok(&data);
    assert_eq!(resp.sw, SW_OK);
    let serialized = resp.serialize();
    assert_eq!(&serialized[..4], &data);
    assert_eq!(serialized[4], 0x90);
    assert_eq!(serialized[5], 0x00);
}

#[test]
fn test_apdu_response_err() {
    let resp = ApduResponse::err(0x6982);
    assert_eq!(resp.sw, 0x6982);
    let serialized = resp.serialize();
    assert_eq!(serialized.len(), 2);
    assert_eq!(serialized[0], 0x69);
    assert_eq!(serialized[1], 0x82);
}
