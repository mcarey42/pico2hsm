//! GENERATE KEY PAIR command handler (INS = 0x47) for PIV.
//!
//! Generates an asymmetric key pair in a PIV key slot.
//! Requires prior management key authentication.
//!
//! # Command format
//! - CLA=0x00, INS=0x47, P1=0x00, P2=key reference (9A/9C/9D/9E, retired 82–95)
//! - Data: AC <len> 80 01 <alg_id> [AA 01 <pin policy>] [AB 01 <touch policy>]
//!
//! `AA` / `AB` are the Yubico PIN- and touch-policy extension.  PIN policy:
//! 00 slot default, 01 never, 02 once per session, 03 always; it is stored
//! with the key and enforced by GENERAL AUTHENTICATE.  Touch policy: this
//! device has no button, so only 00 (default) and 01 (never) are accepted;
//! anything else is refused with 6A80.
//!
//! # Response format
//! For ECC keys:
//! ```text
//! 7F49 <len>
//!   86 <point_len> <uncompressed_point>  -- 04 || X || Y
//! ```

use pico2hsm_core::{
    apdu::{ApduCommand, ApduResponse},
    key::{KeyId, KeyType as CoreKeyType},
};

use crate::protocol::piv::PivState;
use crate::protocol::sc_hsm::FwRng;

/// INS byte for GENERATE KEY PAIR.
pub const INS_GENERATE_KEYPAIR: u8 = 0x47;

/// PIV algorithm ID for ECC P-256.
const ALG_ECC_P256: u8 = 0x11;
/// PIV algorithm ID for ECC P-384.
const ALG_ECC_P384: u8 = 0x14;

/// Valid PIV asymmetric key references: PIV Authentication (9A), Digital
/// Signature (9C), Key Management (9D), Card Authentication (9E) and the
/// twenty retired Key Management keys (82–95), SP 800-73-4 Part 1 Table 4b.
pub fn is_valid_key_ref(key_ref: u8) -> bool {
    matches!(key_ref, 0x9A | 0x9C | 0x9D | 0x9E | 0x82..=0x95)
}

/// The PIN policy that applies to `key_ref`: the stored Yubico policy, or
/// the SP 800-73-4 slot default when none was given — 9C "PIN always",
/// 9E none (Card Authentication), every other key "PIN once per session".
pub fn effective_pin_policy(key_ref: u8, stored: u8) -> u8 {
    use crate::security::key_policy::pin_policy;
    if stored != pin_policy::DEFAULT {
        return stored;
    }
    match key_ref {
        0x9C => pin_policy::ALWAYS,
        0x9E => pin_policy::NEVER,
        _ => pin_policy::ONCE,
    }
}

/// The policy as kept in `KeyMeta::key_flags` (RAM): PIN policy in the
/// low nibble, touch policy in the high nibble.
pub fn policy_flags(policy: &crate::security::key_policy::KeyPolicy) -> u8 {
    (policy.pin_policy & 0x0F) | (policy.touch_policy << 4)
}

/// Handle a GENERATE KEY PAIR APDU command (non-store path, used by legacy dispatch).
pub fn handle(state: &mut PivState, cmd: &ApduCommand<'_>) -> ApduResponse {
    let mut null_store = crate::storage::NullKeyStore;
    handle_with_store(state, &mut null_store, cmd)
}

/// Handle GENERATE KEY PAIR and persist the result to flash.
pub fn handle_with_store(
    state: &mut PivState,
    store: &mut dyn crate::storage::KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    crate::cdc_log!("PIV GENERATE KEY PAIR start slot=0x{:02x}", cmd.p2);
    let key_ref = cmd.p2;

    // Validate P1
    if cmd.p1 != 0x00 {
        return ApduResponse::err(0x6A86);
    }

    // Validate key reference
    if !is_valid_key_ref(key_ref) {
        return ApduResponse::err(0x6A86); // incorrect P2
    }

    // SP 800-73-4 §3.3.2: GENERATE ASYMMETRIC KEY PAIR requires the PIV
    // card application administrator (management key).  The cardholder PIN
    // alone must not be able to replace a slot's key.
    if !state.mgmt_key_authenticated {
        return ApduResponse::err(0x6982); // security status not satisfied
    }

    // Parse the Cryptographic Algorithm Identifier Template (tag 0xAC)
    let (alg_id, policy) = match parse_keygen_template(cmd.data) {
        Some(a) => a,
        None => return ApduResponse::err(0x6A80), // incorrect data
    };

    // Map PIV algorithm ID to core key type
    let key_type = match alg_id {
        ALG_ECC_P256 => CoreKeyType::EcPrivateP256,
        ALG_ECC_P384 => CoreKeyType::EcPrivateP384,
        _ => return ApduResponse::err(0x6A81), // function not supported
    };

    // Generate the key pair
    let mut rng = FwRng;
    let keypair = match crate::crypto::asymmetric::generate_ec_keypair(key_type, &mut rng) {
        Ok(kp) => kp,
        Err(_) => return ApduResponse::err(0x6985), // conditions not satisfied
    };

    let key_id = KeyId::piv(key_ref);
    let flags = policy_flags(&policy);

    // Persist to flash.
    {
        use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmKeyType};
        use pico2hsm_core::key::AppletId;

        let algorithm = match key_type {
            CoreKeyType::EcPrivateP256 => AlgorithmId::EcdsaP256,
            CoreKeyType::EcPrivateP384 => AlgorithmId::EcdsaP384,
            _ => return ApduResponse::err(0x6985),
        };

        let mut obj = KeyObject::new(KmKeyType::Ec, key_id.0, AppletId::Piv, algorithm);
        obj.policy = policy;
        let _ = obj.private_key.extend_from_slice(&keypair.private_key);
        let _ = obj.public_key.extend_from_slice(&keypair.public_key);
        if store.save_key(&obj).is_err() {
            return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
        }
    }

    // Update key_index metadata (replace any existing entry for this slot).
    state.key_index.retain(|m| m.key_id != key_id.0);
    let meta = crate::protocol::sc_hsm::KeyMeta {
        key_id: key_id.0,
        key_type: key_type as u8,
        algo: alg_id,
        key_flags: flags,
    };
    if state.key_index.push(meta).is_err() {
        // Every valid slot fits (MAX_PIV_KEYS); never report an unindexed key.
        return ApduResponse::err(pico2hsm_core::apdu::SW_CONDITIONS_NOT_SATISFIED);
    }

    // Build response per NIST SP 800-73-4 Part 2 Table 3.3-1:
    //   7C [len]  Dynamic Authentication Template
    //     7F49 [len]  Public Key
    //       86 [len]  EC Point (uncompressed)
    let pub_key_bytes = &keypair.public_key;

    // Build inner 7F49 content: 86 <len> <point>
    let mut inner_7f49 = heapless::Vec::<u8, 128>::new();
    let _ = inner_7f49.push(0x86);
    if pub_key_bytes.len() < 128 {
        let _ = inner_7f49.push(pub_key_bytes.len() as u8);
    } else {
        let _ = inner_7f49.push(0x81);
        let _ = inner_7f49.push(pub_key_bytes.len() as u8);
    }
    let _ = inner_7f49.extend_from_slice(pub_key_bytes);

    // Build 7F49 TLV: 7F 49 <len> <inner>
    let mut tag_7f49 = heapless::Vec::<u8, 160>::new();
    let _ = tag_7f49.push(0x7F);
    let _ = tag_7f49.push(0x49);
    if inner_7f49.len() < 128 {
        let _ = tag_7f49.push(inner_7f49.len() as u8);
    } else {
        let _ = tag_7f49.push(0x81);
        let _ = tag_7f49.push(inner_7f49.len() as u8);
    }
    let _ = tag_7f49.extend_from_slice(&inner_7f49);

    // Wrap in 7C Dynamic Authentication Template
    let mut resp = heapless::Vec::<u8, 256>::new();
    let _ = resp.push(0x7C);
    if tag_7f49.len() < 128 {
        let _ = resp.push(tag_7f49.len() as u8);
    } else {
        let _ = resp.push(0x81);
        let _ = resp.push(tag_7f49.len() as u8);
    }
    let _ = resp.extend_from_slice(&tag_7f49);

    crate::cdc_log!(
        "PIV GENERATE KEY PAIR done key=0x{:08x} algo=0x{:02x}",
        key_id.0,
        alg_id
    );
    ApduResponse::ok(&resp)
}

/// Parse the AC template: the algorithm ID (tag 80) and the Yubico PIN /
/// touch policies (AA / AB).
///
/// Expected format: `AC <len> 80 01 <alg_id> [AA 01 <pin>] [AB 01 <touch>]`.
/// `None` (6A80) for a malformed template, a missing algorithm, or a policy
/// value this device can't honour (touch "always"/"cached": no button).
fn parse_keygen_template(data: &[u8]) -> Option<(u8, crate::security::key_policy::KeyPolicy)> {
    use crate::security::key_policy::{for_each_tlv, KeyPolicy};
    let mut template: Option<&[u8]> = None;
    for_each_tlv(data, |tag, value| {
        if tag == 0xAC && template.is_none() {
            template = Some(value);
        }
        Ok(())
    })
    .ok()?;
    let mut alg = None;
    let mut policy = KeyPolicy::default();
    let mut attrs: heapless::Vec<u8, 8> = heapless::Vec::new();
    for_each_tlv(template?, |tag, value| {
        match tag {
            0x80 => match value {
                [a] if alg.is_none() => alg = Some(*a),
                _ => return Err(0x6A80),
            },
            0xAA | 0xAB => {
                // Each at most once, one byte, a supported value.
                if attrs.contains(&(tag as u8)) || attrs.push(tag as u8).is_err() {
                    return Err(0x6A80);
                }
                let p = KeyPolicy::from_piv_attribute(tag as u8, value)?;
                policy.pin_policy |= p.pin_policy;
                policy.touch_policy |= p.touch_policy;
            }
            _ => {}
        }
        Ok(())
    })
    .ok()?;
    Some((alg?, policy))
}
