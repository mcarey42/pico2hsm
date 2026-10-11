//! GET METADATA (INS = 0xF7, Yubico PIV extension; `ykman piv info`,
//! `ykman piv keys info`).
//!
//! `00 F7 00 <ref>`, no data, no authentication.  Response TLVs:
//!
//! | Tag  | Content                                                       |
//! |------|---------------------------------------------------------------|
//! | `01` | algorithm (`FF` PIN/PUK, `03` 3DES, `11` P-256, `14` P-384)    |
//! | `02` | policy: PIN policy, touch policy (effective values)           |
//! | `03` | origin: `01` generated on the device                          |
//! | `04` | public key: `86 L <point>`                                    |
//! | `05` | default value still set: `01` yes, `00` no                    |
//! | `06` | retries: total, remaining (PIN / PUK)                         |
//!
//! An empty key slot answers 6A88.

use pico2hsm_core::apdu::{ApduCommand, ApduResponse, SW_MEMORY_FAILURE};
use subtle::ConstantTimeEq;

use crate::protocol::piv::PivState;
use crate::security::key_policy::{pin_policy, touch_policy};

/// INS byte for GET METADATA.
pub const INS_GET_METADATA: u8 = 0xF7;

fn tlv(out: &mut heapless::Vec<u8, 256>, tag: u8, value: &[u8]) {
    let _ = out.push(tag);
    if value.len() >= 0x80 {
        let _ = out.push(0x81);
    }
    let _ = out.push(value.len() as u8);
    let _ = out.extend_from_slice(value);
}

/// Handle GET METADATA.
pub fn handle_with_store(
    state: &PivState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    if cmd.p1 != 0x00 {
        return ApduResponse::err(0x6A86);
    }
    let mut out: heapless::Vec<u8, 256> = heapless::Vec::new();
    let ps = &state.pin_state;
    match cmd.p2 {
        // PIN / PUK.
        0x80 | 0x81 => {
            let (is_default, total, left): (bool, u8, u8) = if cmd.p2 == 0x80 {
                (
                    ps.pin_hash.ct_eq(&super::super::DEFAULT_PIN_HASH).into(),
                    ps.pin_max_retries,
                    ps.pin_retries_remaining,
                )
            } else {
                (
                    ps.puk_hash.ct_eq(&super::super::DEFAULT_PUK_HASH).into(),
                    crate::security::pin::MAX_PUK_RETRIES,
                    ps.puk_retries_remaining,
                )
            };
            tlv(&mut out, 0x01, &[0xFF]);
            tlv(&mut out, 0x05, &[u8::from(is_default)]);
            tlv(&mut out, 0x06, &[total, left]);
        }
        // Management key: 3DES, no PIN, no touch.
        0x9B => {
            let is_default: bool = state.mgmt_key.ct_eq(&super::super::DEFAULT_MGMT_KEY).into();
            tlv(&mut out, 0x01, &[0x03]);
            tlv(&mut out, 0x02, &[pin_policy::NEVER, touch_policy::NEVER]);
            tlv(&mut out, 0x05, &[u8::from(is_default)]);
        }
        key_ref if super::generate_keypair::is_valid_key_ref(key_ref) => {
            let kid = pico2hsm_core::key::KeyId::piv(key_ref);
            let Some(meta) = state.key_index.iter().find(|m| m.key_id == kid.0) else {
                return ApduResponse::err(0x6A88);
            };
            let pin = super::generate_keypair::effective_pin_policy(key_ref, meta.key_flags & 0x0F);
            let obj = match store.fetch_key(kid) {
                Ok(Some(obj)) => obj,
                Ok(None) => return ApduResponse::err(0x6A88),
                Err(_) => return ApduResponse::err(SW_MEMORY_FAILURE),
            };
            tlv(&mut out, 0x01, &[meta.algo]);
            // No button: touch is never required.
            tlv(&mut out, 0x02, &[pin, touch_policy::NEVER]);
            tlv(&mut out, 0x03, &[0x01]);
            let mut pk: heapless::Vec<u8, 140> = heapless::Vec::new();
            let _ = pk.push(0x86);
            let _ = pk.push(obj.public_key.len() as u8);
            let _ = pk.extend_from_slice(&obj.public_key);
            tlv(&mut out, 0x04, &pk);
        }
        _ => return ApduResponse::err(0x6A88),
    }
    ApduResponse::ok(&out)
}
