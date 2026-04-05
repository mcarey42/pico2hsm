//! VERIFY command handler (INS = 0x20) for PIV.
//!
//! Verifies the PIV PIN (P2=0x80). On first use after fresh flash, the
//! default PIN "123456" (padded to 8 bytes with 0xFF) is accepted.
//!
//! PIV PIN format: 6-8 ASCII digits, padded to 8 bytes with 0xFF.
//!
//! Query mode (empty data): returns remaining retries without consuming
//! an attempt.

use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_OK};

use crate::protocol::piv::PivState;
use crate::security::pin::PinVerifyResult;

/// INS byte for VERIFY.
pub const INS_VERIFY: u8 = 0x20;

/// P2 for PIV Global PIN.
const P2_PIV_PIN: u8 = 0x80;

/// Build a retry-count status word: 0x63C0 | remaining.
fn sw_retry(remaining: u8) -> u16 {
    0x63C0 | (remaining as u16 & 0x0F)
}

/// Strip 0xFF padding from the end of a PIV PIN buffer.
///
/// PIV PINs are padded to 8 bytes with 0xFF. This function returns
/// the unpadded PIN bytes.
fn strip_pin_padding(padded: &[u8]) -> &[u8] {
    let mut end = padded.len();
    while end > 0 && padded[end - 1] == 0xFF {
        end -= 1;
    }
    &padded[..end]
}

/// Handle a VERIFY APDU command.
pub fn handle(state: &mut PivState, cmd: &ApduCommand<'_>) -> ApduResponse {
    if cmd.p1 != 0x00 {
        return ApduResponse::err(0x6A86); // incorrect P1/P2
    }

    match cmd.p2 {
        P2_PIV_PIN => {
            // Query mode: empty data returns retry count
            if cmd.data.is_empty() {
                if state.pin_state.pin_blocked {
                    return ApduResponse::err(0x6983); // auth blocked
                }
                // If already authenticated in this session, return 90 00
                if state.pin_state.session_authenticated {
                    return ApduResponse::err(SW_OK);
                }
                return ApduResponse::err(sw_retry(state.pin_state.pin_retries_remaining));
            }

            // PIV PIN must be exactly 8 bytes (padded with 0xFF)
            if cmd.data.len() != 8 {
                return ApduResponse::err(0x6700); // wrong length
            }

            if state.pin_state.pin_blocked {
                return ApduResponse::err(0x6983); // auth blocked
            }

            // Strip 0xFF padding to get the actual PIN
            let pin = strip_pin_padding(cmd.data);

            // Verify against PinState
            match state.pin_state.verify_pin(pin, &state.device_id, None) {
                Ok(PinVerifyResult::Success) => {
                    state.pin_verified = true;
                    ApduResponse::ok(&[])
                }
                Ok(PinVerifyResult::WrongPin { retries_remaining }) => {
                    state.pin_verified = false;
                    ApduResponse::err(sw_retry(retries_remaining))
                }
                Ok(PinVerifyResult::Blocked) => {
                    state.pin_verified = false;
                    ApduResponse::err(0x6983) // auth blocked
                }
                Err(_) => {
                    ApduResponse::err(0x6984) // reference data not usable
                }
            }
        }
        _ => {
            ApduResponse::err(0x6A86) // incorrect P1/P2
        }
    }
}
