//! APDU builder functions for every pico2hsm cluster command.
//!
//! Each function returns an owned `Vec<u8>` containing the exact byte sequence
//! to send over PC/SC.
#![allow(dead_code)]

/// GET_DEVICE_PUBLIC_KEY — returns the device's 65-byte uncompressed P-256 public key.
///
/// APDU: `80 54 30 00`
pub fn build_get_device_public_key() -> Vec<u8> {
    vec![0x80, 0x54, 0x30, 0x00]
}

/// GET_STATE_HASH — returns 104 bytes: generation(8) + root_hash(32) + signature(64).
///
/// APDU: `80 54 31 00`
pub fn build_get_state_hash() -> Vec<u8> {
    vec![0x80, 0x54, 0x31, 0x00]
}

/// NOISE_TARGET_INIT — Noise XX handshake step 1.
///
/// `payload` must be exactly 76 bytes (0x4C).
///
/// APDU: `80 54 33 00 4C <payload>`
pub fn build_noise_target_init(payload: &[u8; 76]) -> Vec<u8> {
    let mut apdu = vec![0x80, 0x54, 0x33, 0x00, 0x4C];
    apdu.extend_from_slice(payload);
    apdu
}

/// GET_KEY_MANIFEST — returns the list of key descriptors present on the device.
///
/// APDU: `80 54 35 00`
pub fn build_get_key_manifest() -> Vec<u8> {
    vec![0x80, 0x54, 0x35, 0x00]
}

/// GET_GENERATION_V2 — returns an 8-byte generation counter.
///
/// APDU: `80 54 37 00 00`
pub fn build_get_generation_v2() -> Vec<u8> {
    vec![0x80, 0x54, 0x37, 0x00, 0x00]
}

/// IMPORT_DKEK_SHARE — imports a raw 32-byte DKEK share.
///
/// Returns 10 bytes: remaining(1) + total(1) + KCV(8).
///
/// APDU: `80 52 00 00 20 <32 bytes>`
pub fn build_import_dkek_share(share: &[u8; 32]) -> Vec<u8> {
    let mut apdu = vec![0x80, 0x52, 0x00, 0x00, 0x20];
    apdu.extend_from_slice(share);
    apdu
}

/// WRAP_KEY — DKEK-encrypted key export for the given key reference.
///
/// APDU: `80 72 <key_ref> 92 00`
pub fn build_wrap_key(key_ref: u8) -> Vec<u8> {
    vec![0x80, 0x72, key_ref, 0x92, 0x00]
}

/// UNWRAP_KEY — DKEK-encrypted key import for the given key reference.
///
/// APDU: `80 74 <key_ref> 93 <Lc> <blob>`
pub fn build_unwrap_key(key_ref: u8, blob: &[u8]) -> Vec<u8> {
    let lc = blob.len();
    let mut apdu = if lc <= 255 {
        vec![0x80, 0x74, key_ref, 0x93, lc as u8]
    } else {
        // Extended length encoding: 3-byte Lc (0x00 + high + low)
        vec![
            0x80,
            0x74,
            key_ref,
            0x93,
            0x00,
            ((lc >> 8) & 0xFF) as u8,
            (lc & 0xFF) as u8,
        ]
    };
    apdu.extend_from_slice(blob);
    apdu
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_device_public_key_bytes() {
        assert_eq!(build_get_device_public_key(), vec![0x80, 0x54, 0x30, 0x00]);
    }

    #[test]
    fn get_state_hash_bytes() {
        assert_eq!(build_get_state_hash(), vec![0x80, 0x54, 0x31, 0x00]);
    }

    #[test]
    fn get_key_manifest_bytes() {
        assert_eq!(build_get_key_manifest(), vec![0x80, 0x54, 0x35, 0x00]);
    }

    #[test]
    fn get_generation_v2_bytes() {
        assert_eq!(
            build_get_generation_v2(),
            vec![0x80, 0x54, 0x37, 0x00, 0x00]
        );
    }

    #[test]
    fn import_dkek_share_bytes() {
        let share = [0xAA; 32];
        let apdu = build_import_dkek_share(&share);
        assert_eq!(&apdu[..5], &[0x80, 0x52, 0x00, 0x00, 0x20]);
        assert_eq!(apdu.len(), 5 + 32);
    }

    #[test]
    fn wrap_key_bytes() {
        assert_eq!(build_wrap_key(0x01), vec![0x80, 0x72, 0x01, 0x92, 0x00]);
    }

    #[test]
    fn unwrap_key_short_blob() {
        let blob = vec![0xBB; 10];
        let apdu = build_unwrap_key(0x02, &blob);
        assert_eq!(&apdu[..5], &[0x80, 0x74, 0x02, 0x93, 0x0A]);
        assert_eq!(apdu.len(), 5 + 10);
    }
}
