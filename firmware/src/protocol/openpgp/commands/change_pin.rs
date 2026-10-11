//! CHANGE REFERENCE DATA command handler (INS = 0x24) for OpenPGP.
//!
//! Changes PW1 (P2=0x81) or PW3 (P2=0x83).
//! Data format: old PIN bytes immediately followed by new PIN bytes.
//! The split point is the stored length of the current password (kept in
//! its `PwHash` record), so each attempt checks exactly one candidate.

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_AUTH_BLOCKED, SW_WRONG_DATA, SW_WRONG_LENGTH,
};

use crate::protocol::openpgp::pw::PwHash;
use crate::protocol::openpgp::OpenPgpState;

/// INS byte for CHANGE REFERENCE DATA.
pub const INS_CHANGE_PIN: u8 = 0x24;

/// Build a retry-count status word.
fn sw_retry(remaining: u8) -> u16 {
    0x63C0 | (remaining as u16 & 0x0F)
}

/// Minimum PW1 / PW3 lengths (OpenPGP Card 3.4).
pub const PW1_MIN_LEN: usize = 6;
pub const PW3_MIN_LEN: usize = 8;

/// Where `old || new` splits: the stored password length, if the request
/// is well formed (so the old password would actually be compared).
pub fn split_at(stored: Option<&PwHash>, data_len: usize, min_len: usize) -> Option<usize> {
    let old_len = stored?.len()?;
    let new_len = data_len.checked_sub(old_len)?;
    (min_len..=127).contains(&new_len).then_some(old_len)
}

/// CHANGE REFERENCE DATA for one password.  `old || new` is split at the
/// stored length — exactly one candidate per attempt (previously every
/// split point was tried, several guesses for one retry).
fn change(
    slot: &mut Option<PwHash>,
    retries: &mut u8,
    max_retries: u8,
    min_len: usize,
    data: &[u8],
) -> ApduResponse {
    if *retries == 0 {
        return ApduResponse::err(SW_AUTH_BLOCKED);
    }
    let Some(stored) = slot.as_ref() else {
        return ApduResponse::err(SW_AUTH_BLOCKED);
    };
    if stored.len().is_none() {
        // Legacy record of unknown length: a VERIFY records it first.
        return ApduResponse::err(pico2hsm_core::apdu::SW_CONDITIONS_NOT_SATISFIED);
    }
    let Some(old_len) = split_at(Some(stored), data.len(), min_len) else {
        return ApduResponse::err(SW_WRONG_LENGTH);
    };
    let (old, new) = data.split_at(old_len);
    if !stored.matches(old) {
        *retries = retries.saturating_sub(1);
        return if *retries == 0 {
            ApduResponse::err(SW_AUTH_BLOCKED)
        } else {
            ApduResponse::err(sw_retry(*retries))
        };
    }
    *slot = Some(PwHash::new(new));
    *retries = max_retries;
    ApduResponse::ok(&[])
}

/// Handle a CHANGE REFERENCE DATA APDU command.
pub fn handle(state: &mut OpenPgpState, cmd: &ApduCommand<'_>) -> ApduResponse {
    if cmd.p1 != 0x00 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    use crate::protocol::openpgp::{PW1_MAX_RETRIES, PW3_MAX_RETRIES};
    match cmd.p2 {
        // Change PW1
        0x81 => change(
            &mut state.pw1_hash,
            &mut state.pw1_retries,
            PW1_MAX_RETRIES,
            PW1_MIN_LEN,
            cmd.data,
        ),
        // Change PW3
        0x83 => change(
            &mut state.pw3_hash,
            &mut state.pw3_retries,
            PW3_MAX_RETRIES,
            PW3_MIN_LEN,
            cmd.data,
        ),
        _ => ApduResponse::err(0x6A86), // Incorrect P2
    }
}
