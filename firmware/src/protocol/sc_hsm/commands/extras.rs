//! EXTRAS command handler (INS = 0x54).
//!
//! Additional cryptographic primitives dispatched by P1 sub-command:
//! - P1=0x01: HKDF-Extract
//! - P1=0x02: HKDF-Expand
//! - P1=0x03: PBKDF2-SHA256
//! - P1=0x04: X9.63-KDF
//! - P1=0x05: AES-CMAC
//! - P1=0x06: HMAC-SHA256
//! - P1=0x30: GET_DEVICE_PUBLIC_KEY
//! - P1=0x31–0x33: (removed — V1 DKEK exchange, returns SW_INS_NOT_SUPPORTED)
//! - P1=0x34: GET_GENERATION (V1 compat, returns low 4 bytes of generation counter)
//! - P1=0x35: NOISE_TARGET_INIT (V2 mutual-auth DKEK exchange)
//! - P1=0x36: NOISE_SOURCE_RESPOND (V2)
//! - P1=0x37: NOISE_FINALIZE_SEND_V2
//! - P1=0x38: NOISE_FINALIZE_RECV_V2
//! - P1=0x39: GET_KEY_MANIFEST
//! - P1=0x3A: GET_STATE_HASH
//! - P1=0x3B: SIGN_ENROLLMENT
//! - P1=0x3C: GET_GENERATION_V2

use pico2hsm_core::apdu::{
    ApduCommand, ApduResponse, SW_CONDITIONS_NOT_SATISFIED, SW_SECURITY_STATUS, SW_WRONG_DATA,
    SW_WRONG_LENGTH,
};
use pico2hsm_core::key::KeyId;

use rand_core::RngCore;

use crate::protocol::sc_hsm::{FwRng, ScHsmState};
use crate::storage::KeyStore;

/// INS byte for EXTRAS.
pub const INS_EXTRAS: u8 = 0x54;

/// Handle an EXTRAS APDU command.
pub fn handle(state: &mut ScHsmState, store: &mut dyn KeyStore, cmd: &ApduCommand<'_>) -> ApduResponse {
    match cmd.p1 {
        // No-PIN sub-commands.
        0x30 => handle_get_device_public_key(state, store, cmd),
        0x34 => handle_get_generation(state, cmd),
        0x39 => handle_get_key_manifest(state, store, cmd),
        0x3A => handle_get_state_hash(state, store, cmd),
        0x3C => handle_get_generation_v2(state, cmd),

        // SO-PIN required.
        0x3B => {
            if !state.so_pin_verified {
                return ApduResponse::err(SW_SECURITY_STATUS);
            }
            handle_sign_enrollment(state, store, cmd)
        }

        // All remaining sub-commands require PIN authentication.
        _ => {
            if !state.pin_verified {
                return ApduResponse::err(SW_SECURITY_STATUS);
            }
            match cmd.p1 {
                0x01 => hkdf_extract(cmd.data),
                0x02 => hkdf_expand(cmd.data),
                0x03 => pbkdf2(cmd.data),
                0x04 => x963_kdf(cmd.data),
                0x05 => aes_cmac(cmd.data),
                0x06 => hmac_sha256(cmd.data),
                // V1 DKEK exchange (P1=0x31–0x33) removed — use V2 (P1=0x35–0x38).
                0x31 | 0x32 | 0x33 => ApduResponse::err(pico2hsm_core::apdu::SW_INS_NOT_SUPPORTED),
                // V2 mutual-auth DKEK exchange.
                0x35 => handle_noise_target_init(state, store, cmd),
                0x36 => handle_noise_source_respond(state, store, cmd),
                0x37 => handle_noise_finalize_send_v2(state, store, cmd),
                0x38 => handle_noise_finalize_recv_v2(state, store, cmd),
                _ => ApduResponse::err(SW_WRONG_DATA),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// P1=0x30  GET_DEVICE_PUBLIC_KEY
// ---------------------------------------------------------------------------

fn handle_get_device_public_key(state: &mut ScHsmState, store: &mut dyn KeyStore, _cmd: &ApduCommand<'_>) -> ApduResponse {
    let dev_key_id = KeyId::sc_hsm(0, 0xFE);

    // Try in-memory key store first.
    if let Some(key) = state.keys.iter().find(|k| k.key_id == dev_key_id.0) {
        if !key.public_key.is_empty() {
            return ApduResponse::ok(&key.public_key);
        }
    }

    // Try EF 0x2F02 (public key stored during INITIALIZE).
    if let Some(ef) = state.ef_files.iter().find(|ef| ef.file_id == 0x2F02) {
        if !ef.data.is_empty() {
            return ApduResponse::ok(&ef.data);
        }
    }

    // Try persistent store.
    if let Ok(Some(key_obj)) = store.fetch_key(dev_key_id) {
        if !key_obj.public_key.is_empty() {
            return ApduResponse::ok(&key_obj.public_key);
        }
    }

    // Device not initialized or no identity key.
    ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED)
}

// ---------------------------------------------------------------------------
// P1=0x34  GET_GENERATION
// ---------------------------------------------------------------------------

fn handle_get_generation(state: &mut ScHsmState, _cmd: &ApduCommand<'_>) -> ApduResponse {
    // Return the low 4 bytes of the generation counter (V1 compat).
    ApduResponse::ok(&(state.generation as u32).to_be_bytes())
}

// ---------------------------------------------------------------------------
// P1=0x35  NOISE_TARGET_INIT (V2 mutual-auth)
// ---------------------------------------------------------------------------

fn handle_noise_target_init(state: &mut ScHsmState, store: &mut dyn KeyStore, cmd: &ApduCommand<'_>) -> ApduResponse {
    use crate::crypto::asymmetric::generate_ec_keypair;
    use pico2hsm_core::key::KeyType as CoreKeyType;
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    // Input: source_static_pub(65)
    if cmd.data.len() != 65 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Generate ephemeral P-256 keypair.
    let mut rng = FwRng;
    let pair = match generate_ec_keypair(CoreKeyType::EcPrivateP256, &mut rng) {
        Ok(p) => p,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    if pair.private_key.len() != 32 || pair.public_key.len() != 65 {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    let mut priv_bytes = Zeroizing::new([0u8; 32]);
    priv_bytes.copy_from_slice(&pair.private_key);

    let mut ephem_pub = [0u8; 65];
    ephem_pub.copy_from_slice(&pair.public_key);

    // Generate challenge[32].
    let mut challenge = [0u8; 32];
    rng.fill_bytes(&mut challenge);

    // Compute msg = SHA-256(ephem_T_pub(65) || challenge(32))
    let mut hasher = Sha256::new();
    hasher.update(&ephem_pub);
    hasher.update(&challenge);
    let msg_hash: [u8; 32] = hasher.finalize().into();

    // Sign with device static private key.
    let sig_bytes = match sign_with_device_key(state, store, &msg_hash) {
        Ok(s) => s,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Store ephemeral state.
    state.exchange_ephem_priv = Some(priv_bytes);
    state.exchange_ephem_pub = Some(ephem_pub);
    state.exchange_challenge = Some(challenge);

    // Return ephem_T_pub(65) || challenge(32) || Sig_T(64) = 161 bytes
    let mut resp_buf = [0u8; 161];
    resp_buf[..65].copy_from_slice(&ephem_pub);
    resp_buf[65..97].copy_from_slice(&challenge);
    resp_buf[97..161].copy_from_slice(&sig_bytes);

    ApduResponse::ok(&resp_buf)
}

// ---------------------------------------------------------------------------
// P1=0x36  NOISE_SOURCE_RESPOND (V2 mutual-auth)
// ---------------------------------------------------------------------------

fn handle_noise_source_respond(state: &mut ScHsmState, store: &mut dyn KeyStore, cmd: &ApduCommand<'_>) -> ApduResponse {
    use sha2::{Digest, Sha256};

    // Input: ephem_T_pub(65) || challenge(32) || Sig_T(64) = 161 bytes
    if cmd.data.len() != 161 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    let ephem_t_pub: &[u8; 65] = cmd.data[..65].try_into().unwrap();
    let challenge: &[u8; 32] = cmd.data[65..97].try_into().unwrap();
    let sig_t: &[u8; 64] = cmd.data[97..161].try_into().unwrap();

    // Verify Sig_T: TARGET signed SHA-256(ephem_T_pub || challenge) with its static key.
    if let Some(ref peer_pubkey) = state.noise_enrolled_peer_pubkey {
        use ecdsa::signature::hazmat::PrehashVerifier;
        use p256::ecdsa::VerifyingKey;

        let vk = match VerifyingKey::from_sec1_bytes(peer_pubkey) {
            Ok(v) => v,
            Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
        };
        // Reconstruct the message hash that TARGET signed.
        let mut hasher = Sha256::new();
        hasher.update(ephem_t_pub);
        hasher.update(challenge);
        let msg_hash: [u8; 32] = hasher.finalize().into();

        let sig = match ecdsa::Signature::<p256::NistP256>::from_bytes(sig_t.into()) {
            Ok(s) => s,
            Err(_) => return ApduResponse::err(SW_WRONG_DATA),
        };
        if vk.verify_prehash(&msg_hash, &sig).is_err() {
            return ApduResponse::err(SW_SECURITY_STATUS);
        }
    } else {
        // No peer pubkey enrolled — unauthenticated mode.
        // Continue without signature verification (allows bootstrapping before enrollment).
    }

    // Source must already have an ephemeral keypair from a prior NOISE_INITIATE (P1=0x31).
    let ephem_s_pub = match &state.exchange_ephem_pub {
        Some(p) => *p,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Store challenge and target ephem pub for channel binding.
    state.exchange_challenge = Some(*challenge);
    let mut peer_ephem = [0u8; 65];
    peer_ephem.copy_from_slice(ephem_t_pub);
    state.exchange_peer_ephem_pub = Some(peer_ephem);

    // Compute msg_S = SHA-256(ephem_S_pub(65) || challenge(32))
    let mut hasher = Sha256::new();
    hasher.update(&ephem_s_pub);
    hasher.update(challenge);
    let msg_hash: [u8; 32] = hasher.finalize().into();

    // Sign with device static private key.
    let sig_bytes = match sign_with_device_key(state, store, &msg_hash) {
        Ok(s) => s,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Return ephem_S_pub(65) || Sig_S(64) = 129 bytes
    let mut resp_buf = [0u8; 129];
    resp_buf[..65].copy_from_slice(&ephem_s_pub);
    resp_buf[65..129].copy_from_slice(&sig_bytes);

    ApduResponse::ok(&resp_buf)
}

// ---------------------------------------------------------------------------
// P1=0x37  NOISE_FINALIZE_SEND_V2
// ---------------------------------------------------------------------------

fn handle_noise_finalize_send_v2(state: &mut ScHsmState, _store: &mut dyn KeyStore, cmd: &ApduCommand<'_>) -> ApduResponse {
    use crate::security::dkek::{derive_session_key_v2, p256_ecdh};
    use aes_gcm::{aead::{AeadInPlace, KeyInit}, Aes256Gcm, Nonce as GcmNonce};
    use zeroize::Zeroizing;

    // Require DKEK ready.
    if !state.dkek.is_ready() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Input: target_ephem_pub(65) || target_static_pub(65) || challenge(32) = 162 bytes
    if cmd.data.len() != 162 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    let target_ephem_pub: &[u8; 65] = cmd.data[..65].try_into().unwrap();
    let target_static_pub: &[u8; 65] = cmd.data[65..130].try_into().unwrap();
    let challenge: &[u8; 32] = cmd.data[130..162].try_into().unwrap();

    // Require ephemeral private key from a prior NOISE_INITIATE.
    let ephem_priv = match &state.exchange_ephem_priv {
        Some(p) => **p,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };
    let ephem_pub = match &state.exchange_ephem_pub {
        Some(p) => *p,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Validate: input challenge matches exchange_challenge — ABORT if mismatch.
    match &state.exchange_challenge {
        Some(stored) => {
            if stored != challenge {
                // Clear ephemeral state on mismatch.
                state.exchange_ephem_priv = None;
                state.exchange_ephem_pub = None;
                state.exchange_challenge = None;
                state.exchange_peer_ephem_pub = None;
                return ApduResponse::err(SW_WRONG_DATA);
            }
        }
        None => {
            state.exchange_ephem_priv = None;
            state.exchange_ephem_pub = None;
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    // Compute ECDH shared secret.
    let shared_secret = match p256_ecdh(&ephem_priv, target_ephem_pub) {
        Ok(s) => s,
        Err(_) => {
            state.exchange_ephem_priv = None;
            state.exchange_ephem_pub = None;
            state.exchange_challenge = None;
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
    };

    // Derive session key with channel binding.
    // info = b"pico2hsm-dkek-v2" || source_ephem_pub || target_ephem_pub || challenge
    let session_key = match derive_session_key_v2(&shared_secret, &ephem_pub, target_ephem_pub, challenge) {
        Ok(k) => k,
        Err(_) => {
            state.exchange_ephem_priv = None;
            state.exchange_ephem_pub = None;
            state.exchange_challenge = None;
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
    };

    // Encrypt DKEK with AES-256-GCM.
    let dkek = match state.dkek.get_dkek() {
        Some(d) => *d,
        None => {
            state.exchange_ephem_priv = None;
            state.exchange_ephem_pub = None;
            state.exchange_challenge = None;
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
    };

    let mut rng = FwRng;
    let mut nonce_buf = [0u8; 12];
    rng.fill_bytes(&mut nonce_buf);

    // AAD = target_static_pub(65)
    let cipher = match Aes256Gcm::new_from_slice(&*session_key) {
        Ok(c) => c,
        Err(_) => {
            state.exchange_ephem_priv = None;
            state.exchange_ephem_pub = None;
            state.exchange_challenge = None;
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
    };
    let nonce = GcmNonce::from_slice(&nonce_buf);
    let mut ct = dkek;
    let tag = match cipher.encrypt_in_place_detached(nonce, target_static_pub, &mut ct) {
        Ok(t) => t,
        Err(_) => {
            state.exchange_ephem_priv = None;
            state.exchange_ephem_pub = None;
            state.exchange_challenge = None;
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
    };

    // Clear ephemeral state.
    state.exchange_ephem_priv = None;
    state.exchange_ephem_pub = None;
    state.exchange_challenge = None;
    state.exchange_peer_ephem_pub = None;

    // Return nonce(12) || ciphertext(32) || tag(16) = 60 bytes
    let mut out = [0u8; 60];
    out[..12].copy_from_slice(&nonce_buf);
    out[12..44].copy_from_slice(&ct);
    out[44..60].copy_from_slice(tag.as_slice());

    // Zeroize ct copy.
    ct.iter_mut().for_each(|b| *b = 0);

    ApduResponse::ok(&out)
}

// ---------------------------------------------------------------------------
// P1=0x38  NOISE_FINALIZE_RECV_V2
// ---------------------------------------------------------------------------

fn handle_noise_finalize_recv_v2(state: &mut ScHsmState, store: &mut dyn KeyStore, cmd: &ApduCommand<'_>) -> ApduResponse {
    use crate::security::dkek::{derive_session_key_v2, p256_ecdh};
    use aes_gcm::{aead::{AeadInPlace, KeyInit}, Aes256Gcm, Nonce as GcmNonce, Tag as GcmTag};
    use zeroize::Zeroizing;

    // Input: source_ephem_pub(65) || Sig_S(64) || encrypted_dkek(60) = 189 bytes
    if cmd.data.len() != 189 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    let source_ephem_pub: &[u8; 65] = cmd.data[..65].try_into().unwrap();
    let sig_s: &[u8; 64] = cmd.data[65..129].try_into().unwrap();
    let encrypted_dkek: &[u8; 60] = cmd.data[129..189].try_into().unwrap();

    // Require ephemeral state from NOISE_TARGET_INIT.
    let ephem_priv = match &state.exchange_ephem_priv {
        Some(p) => **p,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };
    let ephem_pub = match &state.exchange_ephem_pub {
        Some(p) => *p,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };
    let challenge = match &state.exchange_challenge {
        Some(c) => *c,
        None => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Check challenge replay cache.
    if !check_and_add_challenge(state, &challenge) {
        state.exchange_ephem_priv = None;
        state.exchange_ephem_pub = None;
        state.exchange_challenge = None;
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Verify Sig_S: SOURCE signed SHA-256(source_ephem_pub || challenge) with its static key.
    if let Some(ref peer_pubkey) = state.noise_enrolled_peer_pubkey {
        use ecdsa::signature::hazmat::PrehashVerifier;
        use p256::ecdsa::VerifyingKey;
        use sha2::{Digest, Sha256};

        let vk = match VerifyingKey::from_sec1_bytes(peer_pubkey) {
            Ok(v) => v,
            Err(_) => {
                state.exchange_ephem_priv = None;
                state.exchange_ephem_pub = None;
                state.exchange_challenge = None;
                return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
            }
        };
        // Reconstruct the message hash that SOURCE signed.
        let mut hasher = Sha256::new();
        hasher.update(source_ephem_pub.as_slice());
        hasher.update(&challenge);
        let msg_hash: [u8; 32] = hasher.finalize().into();

        let sig = match ecdsa::Signature::<p256::NistP256>::from_bytes(sig_s.into()) {
            Ok(s) => s,
            Err(_) => {
                state.exchange_ephem_priv = None;
                state.exchange_ephem_pub = None;
                state.exchange_challenge = None;
                return ApduResponse::err(SW_WRONG_DATA);
            }
        };
        if vk.verify_prehash(&msg_hash, &sig).is_err() {
            state.exchange_ephem_priv = None;
            state.exchange_ephem_pub = None;
            state.exchange_challenge = None;
            return ApduResponse::err(SW_SECURITY_STATUS);
        }
    } else {
        // No peer pubkey enrolled — unauthenticated mode.
        // Continue without signature verification (allows bootstrapping before enrollment).
    }

    // Compute ECDH shared secret.
    let shared_secret = match p256_ecdh(&ephem_priv, source_ephem_pub) {
        Ok(s) => s,
        Err(_) => {
            state.exchange_ephem_priv = None;
            state.exchange_ephem_pub = None;
            state.exchange_challenge = None;
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
    };

    // Derive session key with channel binding.
    // info = b"pico2hsm-dkek-v2" || source_ephem_pub || our_ephem_pub || challenge
    let session_key = match derive_session_key_v2(&shared_secret, source_ephem_pub, &ephem_pub, &challenge) {
        Ok(k) => k,
        Err(_) => {
            state.exchange_ephem_priv = None;
            state.exchange_ephem_pub = None;
            state.exchange_challenge = None;
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
    };

    // AAD = own_static_pub(65) — device's own static pubkey.
    let own_static_pub = match get_device_static_pub(state, store) {
        Some(p) => p,
        None => {
            state.exchange_ephem_priv = None;
            state.exchange_ephem_pub = None;
            state.exchange_challenge = None;
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
    };

    // Decrypt DKEK: encrypted_dkek = nonce(12) || ct(32) || tag(16)
    let nonce_bytes: &[u8; 12] = encrypted_dkek[..12].try_into().unwrap();
    let ct_bytes = &encrypted_dkek[12..44];
    let tag_bytes: &[u8; 16] = encrypted_dkek[44..60].try_into().unwrap();

    let cipher = match Aes256Gcm::new_from_slice(&*session_key) {
        Ok(c) => c,
        Err(_) => {
            state.exchange_ephem_priv = None;
            state.exchange_ephem_pub = None;
            state.exchange_challenge = None;
            return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
        }
    };
    let nonce = GcmNonce::from_slice(nonce_bytes);
    let tag = GcmTag::clone_from_slice(tag_bytes);

    let mut dkek_buf = Zeroizing::new([0u8; 32]);
    dkek_buf.copy_from_slice(ct_bytes);

    if cipher.decrypt_in_place_detached(nonce, &own_static_pub, dkek_buf.as_mut(), &tag).is_err() {
        state.exchange_ephem_priv = None;
        state.exchange_ephem_pub = None;
        state.exchange_challenge = None;
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }

    // Store DKEK via DkekManager — put it directly into Ready state.
    state.dkek.set_dkek_direct(*dkek_buf);
    state.dkek_shares_imported = state.dkek.shares_total();

    // Clear ephemeral state.
    state.exchange_ephem_priv = None;
    state.exchange_ephem_pub = None;
    state.exchange_challenge = None;
    state.exchange_peer_ephem_pub = None;

    ApduResponse::ok(&[])
}

// ---------------------------------------------------------------------------
// P1=0x39  GET_KEY_MANIFEST
// ---------------------------------------------------------------------------

fn handle_get_key_manifest(state: &mut ScHsmState, store: &mut dyn KeyStore, _cmd: &ApduCommand<'_>) -> ApduResponse {
    use sha2::{Digest, Sha256};

    // Each entry: key_ref(1) || algo(1) || key_flags(1) || deleted(1) || timestamp_ms_BE(8) || pubkey_hash(32) = 44 bytes
    // Max: 256 entries * 44 = 11264 — but realistically we have at most ~16 in-memory + flash keys.
    // Use a heapless Vec with reasonable max.
    let mut manifest: heapless::Vec<u8, 2816> = heapless::Vec::new(); // 64 entries * 44

    // Iterate in-memory EC keys.
    for key in state.keys.iter() {
        let key_ref = (key.key_id & 0xFF) as u8;
        // Exclude device-internal keys: 0x00 (device cluster signing key) and
        // 0xFE (device auth cert key).  Only user keys 0x01–0xFD are synced.
        if key_ref == 0x00 || key_ref >= 0xFE {
            continue;
        }
        let algo = key.algo;
        let key_flags = 0u8; // No flags defined yet.
        let deleted = 0u8;
        let timestamp_ms = 0u64; // In-memory keys don't have timestamps.
        let pubkey_hash = if !key.public_key.is_empty() {
            let h: [u8; 32] = Sha256::digest(&key.public_key).into();
            h
        } else {
            [0u8; 32]
        };

        let _ = manifest.push(key_ref);
        let _ = manifest.push(algo);
        let _ = manifest.push(key_flags);
        let _ = manifest.push(deleted);
        let _ = manifest.extend_from_slice(&timestamp_ms.to_be_bytes());
        let _ = manifest.extend_from_slice(&pubkey_hash);
    }

    // Iterate flash keys via store.enumerate_keys().
    let flash_keys = store.enumerate_keys();
    for kid in flash_keys.iter() {
        let key_ref = (kid.0 & 0xFF) as u8;
        // Exclude device-internal keys (same filter as in-memory above).
        if key_ref == 0x00 || key_ref >= 0xFE {
            continue;
        }
        // Skip if already seen in in-memory keys.
        if state.keys.iter().any(|k| (k.key_id & 0xFF) as u8 == key_ref) {
            continue;
        }
        if let Ok(Some(key_obj)) = store.fetch_key(*kid) {
            let algo = key_obj.algorithm as u8;
            let key_flags = 0u8;
            let deleted = 0u8;
            let timestamp_ms = key_obj.timestamp_ms;
            let pubkey_hash = if !key_obj.public_key.is_empty() {
                let h: [u8; 32] = Sha256::digest(&key_obj.public_key).into();
                h
            } else {
                [0u8; 32]
            };

            let _ = manifest.push(key_ref);
            let _ = manifest.push(algo);
            let _ = manifest.push(key_flags);
            let _ = manifest.push(deleted);
            let _ = manifest.extend_from_slice(&timestamp_ms.to_be_bytes());
            let _ = manifest.extend_from_slice(&pubkey_hash);
        }
    }

    ApduResponse::ok(&manifest)
}

// ---------------------------------------------------------------------------
// P1=0x3A  GET_STATE_HASH
// ---------------------------------------------------------------------------

fn handle_get_state_hash(state: &mut ScHsmState, store: &mut dyn KeyStore, _cmd: &ApduCommand<'_>) -> ApduResponse {
    use sha2::{Digest, Sha256};

    // Build a map of key_ref -> key info from in-memory and flash.
    // For each slot 0..=253, compute a leaf hash.
    let mut root_hasher = Sha256::new();

    for slot in 0u8..=253u8 {
        let mut leaf_hasher = Sha256::new();

        // Try to find key in memory first, then flash.
        let key_info = find_key_info_for_slot(state, store, slot);

        match key_info {
            Some((algo, key_flags, timestamp_ms, pubkey_hash)) => {
                // Alive key: SHA-256(0x01 || key_ref || algo || key_flags || timestamp_ms_BE || pubkey_hash)
                leaf_hasher.update(&[0x01, slot, algo, key_flags]);
                leaf_hasher.update(&timestamp_ms.to_be_bytes());
                leaf_hasher.update(&pubkey_hash);
            }
            None => {
                // Empty slot: SHA-256(0x00 || key_ref || [0;43])
                leaf_hasher.update(&[0x00, slot]);
                leaf_hasher.update(&[0u8; 43]);
            }
        }

        let leaf: [u8; 32] = leaf_hasher.finalize().into();
        root_hasher.update(&leaf);
    }

    let state_root: [u8; 32] = root_hasher.finalize().into();
    let generation = state.generation;

    // Sign: Sig = P256_RFC6979_ECDSA_sign(device_static_priv, SHA-256(generation_BE(8) || state_root(32)))
    let mut sig_hasher = Sha256::new();
    sig_hasher.update(&generation.to_be_bytes());
    sig_hasher.update(&state_root);
    let sig_msg: [u8; 32] = sig_hasher.finalize().into();

    let sig_bytes = match sign_with_device_key(state, store, &sig_msg) {
        Ok(s) => s,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    // Return generation(8) || state_root(32) || Sig(64) = 104 bytes
    let mut resp = [0u8; 104];
    resp[..8].copy_from_slice(&generation.to_be_bytes());
    resp[8..40].copy_from_slice(&state_root);
    resp[40..104].copy_from_slice(&sig_bytes);

    ApduResponse::ok(&resp)
}

// ---------------------------------------------------------------------------
// P1=0x3B  SIGN_ENROLLMENT
// ---------------------------------------------------------------------------

fn handle_sign_enrollment(state: &mut ScHsmState, store: &mut dyn KeyStore, cmd: &ApduCommand<'_>) -> ApduResponse {
    use sha2::{Digest, Sha256};

    // Input: tls_cert_fingerprint(32) || cluster_id(16) = 48 bytes
    if cmd.data.len() != 48 {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Compute msg = SHA-256(fingerprint(32) || cluster_id(16))
    let msg_hash: [u8; 32] = Sha256::digest(cmd.data).into();

    // Sign with device static private key.
    let sig_bytes = match sign_with_device_key(state, store, &msg_hash) {
        Ok(s) => s,
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    };

    ApduResponse::ok(&sig_bytes)
}

// ---------------------------------------------------------------------------
// P1=0x3C  GET_GENERATION_V2
// ---------------------------------------------------------------------------

fn handle_get_generation_v2(state: &mut ScHsmState, _cmd: &ApduCommand<'_>) -> ApduResponse {
    ApduResponse::ok(&state.generation.to_be_bytes())
}

// ---------------------------------------------------------------------------
// Helper: sign with device static key (P-256 ECDSA RFC 6979)
// ---------------------------------------------------------------------------

/// Load device static private key and sign a pre-hashed message.
/// Returns fixed 64-byte r||s signature.
fn sign_with_device_key(state: &ScHsmState, store: &mut dyn KeyStore, msg_hash: &[u8; 32]) -> Result<[u8; 64], ()> {
    use ecdsa::signature::hazmat::PrehashSigner;
    use p256::SecretKey;
    use ecdsa::SigningKey;
    use zeroize::Zeroizing;

    let dev_key_id = KeyId::sc_hsm(0, 0xFE);

    // Try to find device private key: in-memory first, then flash.
    let priv_bytes: Zeroizing<[u8; 32]> = if let Some(key) = state.keys.iter().find(|k| k.key_id == dev_key_id.0) {
        if key.private_key.len() == 32 {
            let mut b = Zeroizing::new([0u8; 32]);
            b.copy_from_slice(&key.private_key);
            b
        } else {
            return Err(());
        }
    } else if let Ok(Some(key_obj)) = store.fetch_key(dev_key_id) {
        if key_obj.private_key.len() == 32 {
            let mut b = Zeroizing::new([0u8; 32]);
            b.copy_from_slice(&key_obj.private_key);
            b
        } else {
            return Err(());
        }
    } else {
        return Err(());
    };

    let secret = SecretKey::from_slice(&*priv_bytes).map_err(|_| ())?;
    let signing_key = SigningKey::from(&secret);

    // sign_prehash is RFC 6979 deterministic.
    let signature: ecdsa::Signature<p256::NistP256> = signing_key.sign_prehash(msg_hash).map_err(|_| ())?;
    let sig = signature.to_bytes();

    let mut out = [0u8; 64];
    out.copy_from_slice(&sig);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Helper: get device static public key
// ---------------------------------------------------------------------------

fn get_device_static_pub(state: &ScHsmState, store: &mut dyn KeyStore) -> Option<[u8; 65]> {
    let dev_key_id = KeyId::sc_hsm(0, 0xFE);

    if let Some(key) = state.keys.iter().find(|k| k.key_id == dev_key_id.0) {
        if key.public_key.len() == 65 {
            let mut out = [0u8; 65];
            out.copy_from_slice(&key.public_key);
            return Some(out);
        }
    }

    if let Some(ef) = state.ef_files.iter().find(|ef| ef.file_id == 0x2F02) {
        if ef.data.len() == 65 {
            let mut out = [0u8; 65];
            out.copy_from_slice(&ef.data);
            return Some(out);
        }
    }

    if let Ok(Some(key_obj)) = store.fetch_key(dev_key_id) {
        if key_obj.public_key.len() == 65 {
            let mut out = [0u8; 65];
            out.copy_from_slice(&key_obj.public_key);
            return Some(out);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Helper: check and add challenge to replay cache
// ---------------------------------------------------------------------------

fn check_and_add_challenge(state: &mut ScHsmState, challenge: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;

    // Check if challenge already seen.
    for i in 0..state.exchange_challenge_cache_count as usize {
        if bool::from(state.exchange_challenge_cache[i].ct_eq(challenge)) {
            return false; // Replay detected.
        }
    }
    // Add to cache with ring-buffer eviction.
    let idx = (state.exchange_challenge_cache_count as usize) % 16;
    state.exchange_challenge_cache[idx] = *challenge;
    if (state.exchange_challenge_cache_count as usize) < 16 {
        state.exchange_challenge_cache_count += 1;
    }
    true
}

// ---------------------------------------------------------------------------
// Helper: find key info for a given slot (used by GET_STATE_HASH)
// ---------------------------------------------------------------------------

/// Returns (algo, key_flags, timestamp_ms, pubkey_hash) if a key exists at this slot.
fn find_key_info_for_slot(
    state: &ScHsmState,
    store: &mut dyn KeyStore,
    slot: u8,
) -> Option<(u8, u8, u64, [u8; 32])> {
    use sha2::{Digest, Sha256};

    let key_id = KeyId::sc_hsm(0, slot);

    // Check in-memory keys.
    if let Some(key) = state.keys.iter().find(|k| k.key_id == key_id.0) {
        let pubkey_hash = if !key.public_key.is_empty() {
            Sha256::digest(&key.public_key).into()
        } else {
            [0u8; 32]
        };
        return Some((key.algo, 0, 0, pubkey_hash));
    }

    // Check in-memory sym keys.
    if state.sym_keys.iter().any(|k| k.key_id == key_id.0) {
        return Some((0, 0, 0, [0u8; 32]));
    }

    // Check flash.
    if let Ok(Some(key_obj)) = store.fetch_key(key_id) {
        let pubkey_hash = if !key_obj.public_key.is_empty() {
            Sha256::digest(&key_obj.public_key).into()
        } else {
            [0u8; 32]
        };
        return Some((key_obj.algorithm as u8, 0, key_obj.timestamp_ms, pubkey_hash));
    }

    None
}

// ---------------------------------------------------------------------------
// P1=0x01  HKDF-Extract
// ---------------------------------------------------------------------------
// data[0]           = salt_len (0 = no salt)
// data[1..1+sl]     = salt bytes
// data[1+sl..]      = IKM bytes
// Response: 32-byte PRK

fn hkdf_extract(data: &[u8]) -> ApduResponse {
    if data.is_empty() {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let salt_len = data[0] as usize;
    if data.len() < 1 + salt_len {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let salt = &data[1..1 + salt_len];
    let ikm = &data[1 + salt_len..];

    let prk = crate::crypto::kdf::hkdf_extract(salt, ikm);
    ApduResponse::ok(&prk)
}

// ---------------------------------------------------------------------------
// P1=0x02  HKDF-Expand
// ---------------------------------------------------------------------------
// data[0..32]  = PRK (32 bytes)
// data[32]     = output_length (1–255)
// data[33..]   = info bytes (may be empty)
// Response: output_length bytes of OKM

fn hkdf_expand(data: &[u8]) -> ApduResponse {
    if data.len() < 33 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let prk_arr: [u8; 32] = match data[..32].try_into() {
        Ok(a) => a,
        Err(_) => return ApduResponse::err(SW_WRONG_LENGTH),
    };
    let output_length = data[32] as usize;
    if output_length == 0 || output_length > 255 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let info = &data[33..];

    let mut out: heapless::Vec<u8, 256> = heapless::Vec::new();
    match crate::crypto::kdf::hkdf_expand(&prk_arr, info, output_length, &mut out) {
        Ok(()) => {}
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }

    ApduResponse::ok(&out[..output_length])
}

// ---------------------------------------------------------------------------
// P1=0x03  PBKDF2-SHA256
// ---------------------------------------------------------------------------
// data[0]                          = password_len
// data[1..1+pw_len]                = password
// data[1+pw_len]                   = salt_len
// data[2+pw_len..2+pw_len+sl]      = salt
// data[2+pw_len+sl..6+pw_len+sl]   = iterations (4-byte big-endian)
// data[6+pw_len+sl]                = dklen (1–64)
// Response: dklen derived key bytes

fn pbkdf2(data: &[u8]) -> ApduResponse {
    if data.is_empty() {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let pw_len = data[0] as usize;
    let needed = 1 + pw_len + 1;
    if data.len() < needed {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let password = &data[1..1 + pw_len];
    let salt_len = data[1 + pw_len] as usize;
    let needed = 2 + pw_len + salt_len + 4 + 1;
    if data.len() < needed {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let salt = &data[2 + pw_len..2 + pw_len + salt_len];
    let iter_start = 2 + pw_len + salt_len;
    let iterations = u32::from_be_bytes([
        data[iter_start],
        data[iter_start + 1],
        data[iter_start + 2],
        data[iter_start + 3],
    ]);
    let dklen = data[iter_start + 4] as usize;
    if dklen == 0 || dklen > 64 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }

    let mut buf = [0u8; 64];
    match crate::crypto::kdf::pbkdf2_hmac_sha256(password, salt, iterations, &mut buf[..dklen]) {
        Ok(()) => {}
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }

    ApduResponse::ok(&buf[..dklen])
}

// ---------------------------------------------------------------------------
// P1=0x04  X9.63-KDF
// ---------------------------------------------------------------------------
// data[0]              = Z_len
// data[1..1+Z_len]     = Z (shared secret)
// data[1+Z_len]        = key_len (1–64)
// data[2+Z_len..]      = SharedInfo (may be empty)
// Response: key_len derived key bytes

fn x963_kdf(data: &[u8]) -> ApduResponse {
    if data.is_empty() {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let z_len = data[0] as usize;
    if data.len() < 1 + z_len + 1 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let z = &data[1..1 + z_len];
    let key_len = data[1 + z_len] as usize;
    if key_len == 0 || key_len > 64 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let shared_info = &data[2 + z_len..];

    let mut out: heapless::Vec<u8, 64> = heapless::Vec::new();
    match crate::crypto::kdf::x963_kdf(z, shared_info, key_len, &mut out) {
        Ok(()) => {}
        Err(_) => return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }

    ApduResponse::ok(&out)
}

// ---------------------------------------------------------------------------
// P1=0x05  AES-CMAC
// ---------------------------------------------------------------------------
// data[0]               = key_len (16, 24, or 32)
// data[1..1+key_len]    = AES key bytes
// data[1+key_len..]     = message
// Response: 16-byte CMAC tag

fn aes_cmac(data: &[u8]) -> ApduResponse {
    use pico2hsm_core::key::{KeyId as CoreKeyId, KeyMaterial, KeyType};

    if data.is_empty() {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let key_len = data[0] as usize;
    if data.len() < 1 + key_len {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let key_bytes = &data[1..1 + key_len];
    let message = &data[1 + key_len..];

    let key_type = match key_len {
        16 => KeyType::Aes128,
        24 => KeyType::Aes192,
        32 => KeyType::Aes256,
        _ => return ApduResponse::err(SW_WRONG_DATA),
    };

    let mut raw: heapless::Vec<u8, { pico2hsm_core::key::MAX_KEY_BYTES }> = heapless::Vec::new();
    if raw.extend_from_slice(key_bytes).is_err() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }
    let km = KeyMaterial {
        key_type,
        key_id: CoreKeyId(0x0100),
        raw,
    };

    match crate::crypto::symmetric::aes_cmac(&km, message) {
        Ok(tag) => ApduResponse::ok(&tag),
        Err(_) => ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED),
    }
}

// ---------------------------------------------------------------------------
// P1=0x06  HMAC-SHA256
// ---------------------------------------------------------------------------
// data[0]               = key_len
// data[1..1+key_len]    = HMAC key
// data[1+key_len..]     = message
// Response: 32-byte HMAC tag

fn hmac_sha256(data: &[u8]) -> ApduResponse {
    if data.is_empty() {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let key_len = data[0] as usize;
    if data.len() < 1 + key_len {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }
    let key = &data[1..1 + key_len];
    let message = &data[1 + key_len..];

    let tag = crate::crypto::kdf::hmac_sha256(key, message);
    ApduResponse::ok(&tag)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build an APDU-style data buffer from parts
    fn make_data(parts: &[&[u8]]) -> heapless::Vec<u8, 512> {
        let mut v: heapless::Vec<u8, 512> = heapless::Vec::new();
        for p in parts {
            v.extend_from_slice(p).unwrap();
        }
        v
    }

    // -----------------------------------------------------------------------
    // HKDF-Extract — RFC 5869 Test Case A.1
    // salt = 0x000102...0x0c (13 bytes)
    // IKM  = 0x0b0b...0b (22 bytes)
    // Expected PRK = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
    // -----------------------------------------------------------------------
    #[test]
    fn test_hkdf_extract_rfc5869_a1() {
        let salt: [u8; 13] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let ikm: [u8; 22] = [0x0b; 22];

        let data = make_data(&[&[salt.len() as u8], &salt, &ikm]);
        let resp = hkdf_extract(&data);

        let expected = hex_to_32(
            b"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        );
        assert_eq!(resp.sw, 0x9000, "expected SW_OK");
        assert_eq!(&resp.data[..], &expected[..]);
    }

    // -----------------------------------------------------------------------
    // HKDF-Expand — use A.1 PRK, expand 42 bytes, verify non-zero
    // -----------------------------------------------------------------------
    #[test]
    fn test_hkdf_expand_produces_output() {
        // PRK from A.1
        let prk = hex_to_32(
            b"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        );
        let info: &[u8] = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let output_len: u8 = 42;

        let data = make_data(&[&prk, &[output_len], info]);
        let resp = hkdf_expand(&data);

        assert_eq!(resp.sw, 0x9000, "expected SW_OK");
        assert_eq!(resp.data.len(), 42);
        assert!(resp.data.iter().any(|&b| b != 0), "output should be non-zero");
    }

    // -----------------------------------------------------------------------
    // PBKDF2-SHA256 — known inputs, check length
    // -----------------------------------------------------------------------
    #[test]
    fn test_pbkdf2_correct_length() {
        let password = b"password";
        let salt = b"salt";
        let iterations: u32 = 1;
        let dklen: u8 = 32;

        let mut data: heapless::Vec<u8, 64> = heapless::Vec::new();
        data.push(password.len() as u8).unwrap();
        data.extend_from_slice(password).unwrap();
        data.push(salt.len() as u8).unwrap();
        data.extend_from_slice(salt).unwrap();
        data.extend_from_slice(&iterations.to_be_bytes()).unwrap();
        data.push(dklen).unwrap();

        let resp = pbkdf2(&data);
        assert_eq!(resp.sw, 0x9000, "expected SW_OK");
        assert_eq!(resp.data.len(), 32);
    }

    // -----------------------------------------------------------------------
    // X9.63-KDF — check output length
    // -----------------------------------------------------------------------
    #[test]
    fn test_x963_kdf_correct_length() {
        let z: [u8; 32] = [0xca; 32];
        let key_len: u8 = 32;
        let shared_info: &[u8] = b"test";

        let data = make_data(&[&[z.len() as u8], &z, &[key_len], shared_info]);
        let resp = x963_kdf(&data);

        assert_eq!(resp.sw, 0x9000, "expected SW_OK");
        assert_eq!(resp.data.len(), 32);
    }

    // -----------------------------------------------------------------------
    // AES-CMAC — key [0x01;16] + message [0x00;16] → 16-byte tag
    // -----------------------------------------------------------------------
    #[test]
    fn test_aes_cmac_returns_16_bytes() {
        let key = [0x01u8; 16];
        let message = [0x00u8; 16];

        let data = make_data(&[&[key.len() as u8], &key, &message]);
        let resp = aes_cmac(&data);

        assert_eq!(resp.sw, 0x9000, "expected SW_OK");
        assert_eq!(resp.data.len(), 16);
    }

    // -----------------------------------------------------------------------
    // HMAC-SHA256 — RFC 2202 test vector 1
    // key = 0x0b×20, message = "Hi There"
    // expected = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    // -----------------------------------------------------------------------
    #[test]
    fn test_hmac_sha256_rfc2202_vector1() {
        let key = [0x0bu8; 20];
        let message = b"Hi There";

        let data = make_data(&[&[key.len() as u8], &key, message]);
        let resp = hmac_sha256(&data);

        let expected = hex_to_32(
            b"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        );
        assert_eq!(resp.sw, 0x9000, "expected SW_OK");
        assert_eq!(&resp.data[..], &expected[..]);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Decode a 64-hex-char lowercase string into a [u8; 32].
    fn hex_to_32(hex: &[u8]) -> [u8; 32] {
        assert_eq!(hex.len(), 64);
        let mut out = [0u8; 32];
        for i in 0..32 {
            let hi = nibble(hex[2 * i]);
            let lo = nibble(hex[2 * i + 1]);
            out[i] = (hi << 4) | lo;
        }
        out
    }

    fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid hex nibble"),
        }
    }

    // -----------------------------------------------------------------------
    // V2 DKEK Exchange Tests
    // -----------------------------------------------------------------------

    use crate::protocol::sc_hsm::{ScHsmState, InMemoryKey};
    use crate::storage::KeyStore;
    use pico2hsm_core::key::{AppletId, KeyId, KeyType as CoreKeyType};

    /// Null key store for tests.
    struct NullStore;
    impl KeyStore for NullStore {
        fn save_key(&mut self, _: &crate::security::key_management::KeyObject) -> Result<(), pico2hsm_core::error::HsmError> { Ok(()) }
        fn fetch_key(&mut self, _: KeyId) -> Result<Option<crate::security::key_management::KeyObject>, pico2hsm_core::error::HsmError> { Ok(None) }
        fn erase_key(&mut self, _: KeyId) -> Result<(), pico2hsm_core::error::HsmError> { Ok(()) }
        fn wipe_all(&mut self) -> Result<(), pico2hsm_core::error::HsmError> { Ok(()) }
        fn wipe_by_owner(&mut self, _: AppletId) -> Result<(), pico2hsm_core::error::HsmError> { Ok(()) }
        fn enumerate_keys(&self) -> heapless::Vec<KeyId, 512> { heapless::Vec::new() }
    }

    /// Create a ScHsmState with a device static key (key_ref=0xFE) and PIN verified.
    fn state_with_device_key() -> ScHsmState {
        use crate::crypto::asymmetric::generate_ec_keypair;
        use rand_core::RngCore;

        let mut state = ScHsmState::new();
        state.pin_verified = true;
        state.so_pin_verified = true;
        state.initialized = true;

        // Generate a real P-256 keypair for the device identity key.
        let mut rng = crate::protocol::sc_hsm::FwRng;
        let pair = generate_ec_keypair(CoreKeyType::EcPrivateP256, &mut rng).unwrap();

        let dev_key_id = KeyId::sc_hsm(0, 0xFE).0;
        let mut entry = InMemoryKey {
            key_id: dev_key_id,
            key_type: CoreKeyType::EcPrivateP256,
            algo: 0x13,
            private_key: heapless::Vec::new(),
            public_key: heapless::Vec::new(),
        };
        entry.private_key.extend_from_slice(&pair.private_key).unwrap();
        entry.public_key.extend_from_slice(&pair.public_key).unwrap();
        state.keys.push(entry).unwrap();

        state
    }

    #[test]
    fn test_noise_target_init_returns_correct_length() {
        let mut state = state_with_device_key();
        let mut store = NullStore;

        // Source static pubkey (dummy 65 bytes, starts with 0x04).
        let mut source_pub = [0u8; 65];
        source_pub[0] = 0x04;
        source_pub[1] = 0x01;

        let cmd = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x35,
            p2: 0x00,
            data: &source_pub,
            le: None,
        };

        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, 0x9000, "expected SW_OK, got {:04X}", resp.sw);
        assert_eq!(resp.data.len(), 161, "expected 161 bytes: ephem_pub(65) + challenge(32) + sig(64)");

        // Verify ephemeral state was stored.
        assert!(state.exchange_ephem_priv.is_some());
        assert!(state.exchange_ephem_pub.is_some());
        assert!(state.exchange_challenge.is_some());
    }

    #[test]
    fn test_noise_source_respond_returns_correct_length() {
        use crate::crypto::asymmetric::generate_ec_keypair;

        let mut state = state_with_device_key();
        let mut store = NullStore;

        // Source needs an existing ephemeral keypair (from NOISE_INITIATE).
        let mut rng = crate::protocol::sc_hsm::FwRng;
        let pair = generate_ec_keypair(CoreKeyType::EcPrivateP256, &mut rng).unwrap();
        let mut priv_bytes = zeroize::Zeroizing::new([0u8; 32]);
        priv_bytes.copy_from_slice(&pair.private_key);
        state.exchange_ephem_priv = Some(priv_bytes);
        let mut pub_bytes = [0u8; 65];
        pub_bytes.copy_from_slice(&pair.public_key);
        state.exchange_ephem_pub = Some(pub_bytes);

        // Build input: ephem_T_pub(65) || challenge(32) || Sig_T(64) = 161 bytes
        let mut input = [0u8; 161];
        // Fill with a valid-looking ephem pub (we won't verify sig in V1).
        input[0] = 0x04;
        input[1] = 0x42;
        // challenge at [65..97] — random.
        input[65] = 0xAA;
        // sig at [97..161] — dummy 64 bytes (V1 doesn't verify).

        let cmd = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x36,
            p2: 0x00,
            data: &input,
            le: None,
        };

        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, 0x9000, "expected SW_OK, got {:04X}", resp.sw);
        assert_eq!(resp.data.len(), 129, "expected 129 bytes: ephem_S_pub(65) + Sig_S(64)");

        // Verify challenge was stored.
        assert!(state.exchange_challenge.is_some());
        assert!(state.exchange_peer_ephem_pub.is_some());
    }

    #[test]
    fn test_challenge_replay_rejected() {
        let mut state = ScHsmState::new();
        let challenge = [0xBBu8; 32];

        // First add should succeed.
        assert!(check_and_add_challenge(&mut state, &challenge));
        // Second add with same challenge should fail (replay).
        assert!(!check_and_add_challenge(&mut state, &challenge));
        // Different challenge should succeed.
        let challenge2 = [0xCCu8; 32];
        assert!(check_and_add_challenge(&mut state, &challenge2));
    }

    #[test]
    fn test_get_state_hash_returns_104_bytes() {
        let mut state = state_with_device_key();
        let mut store = NullStore;

        let cmd = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x3A,
            p2: 0x00,
            data: &[],
            le: None,
        };

        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, 0x9000, "expected SW_OK, got {:04X}", resp.sw);
        assert_eq!(resp.data.len(), 104, "expected 104 bytes: generation(8) + state_root(32) + sig(64)");
    }

    #[test]
    fn test_get_state_hash_changes_after_key_add() {
        let mut state = state_with_device_key();
        let mut store = NullStore;

        let cmd = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x3A,
            p2: 0x00,
            data: &[],
            le: None,
        };

        // Get state hash before adding a key.
        let resp1 = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp1.sw, 0x9000);
        let hash1 = resp1.data.clone();

        // Add a fake key to a new slot.
        let key_id2 = KeyId::sc_hsm(0, 0x01).0;
        let mut entry = InMemoryKey {
            key_id: key_id2,
            key_type: CoreKeyType::EcPrivateP256,
            algo: 0x13,
            private_key: heapless::Vec::new(),
            public_key: heapless::Vec::new(),
        };
        entry.private_key.extend_from_slice(&[0x42u8; 32]).unwrap();
        let mut pub_key = [0u8; 65];
        pub_key[0] = 0x04;
        entry.public_key.extend_from_slice(&pub_key).unwrap();
        state.keys.push(entry).unwrap();

        // Get state hash after adding a key.
        let resp2 = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp2.sw, 0x9000);

        // The state_root portion (bytes 8..40) should differ.
        assert_ne!(&hash1[8..40], &resp2.data[8..40], "state_root should change after adding a key");
    }

    #[test]
    fn test_get_generation_v2_returns_8_bytes() {
        let mut state = ScHsmState::new();
        let mut store = NullStore;

        let cmd = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x3C,
            p2: 0x00,
            data: &[],
            le: None,
        };

        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, 0x9000);
        assert_eq!(resp.data.len(), 8);
        assert_eq!(&resp.data[..], &[0u8; 8]);

        // Increment and check again.
        state.generation = 42;
        let resp2 = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp2.sw, 0x9000);
        assert_eq!(&resp2.data[..], &42u64.to_be_bytes());
    }

    #[test]
    fn test_sign_enrollment_returns_64_bytes() {
        let mut state = state_with_device_key();
        let mut store = NullStore;

        // Input: tls_cert_fingerprint(32) || cluster_id(16) = 48 bytes
        let input = [0x55u8; 48];

        let cmd = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x3B,
            p2: 0x00,
            data: &input,
            le: None,
        };

        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, 0x9000, "expected SW_OK, got {:04X}", resp.sw);
        assert_eq!(resp.data.len(), 64, "expected 64-byte signature");
    }

    #[test]
    fn test_sign_enrollment_requires_so_pin() {
        let mut state = state_with_device_key();
        state.so_pin_verified = false; // Override
        let mut store = NullStore;

        let input = [0x55u8; 48];
        let cmd = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x3B,
            p2: 0x00,
            data: &input,
            le: None,
        };

        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_SECURITY_STATUS, "should require SO-PIN");
    }

    #[test]
    fn test_get_key_manifest_empty_state() {
        let mut state = state_with_device_key();
        let mut store = NullStore;

        let cmd = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x39,
            p2: 0x00,
            data: &[],
            le: None,
        };

        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, 0x9000);
        // State has only the device static key at 0xFE, which is filtered out
        // from the manifest (only user keys 0x01–0xFD are exported).
        assert_eq!(resp.data.len(), 0, "device key (0xFE) must be excluded from manifest");
    }

    #[test]
    fn test_v2_channel_binding_different_ephem_different_session_key() {
        use crate::security::dkek::derive_session_key_v2;

        let shared_secret = [0xAAu8; 32];
        let ephem1 = {
            let mut e = [0u8; 65];
            e[0] = 0x04;
            e[1] = 0x01;
            e
        };
        let ephem2 = {
            let mut e = [0u8; 65];
            e[0] = 0x04;
            e[1] = 0x02;
            e
        };
        let ephem3 = {
            let mut e = [0u8; 65];
            e[0] = 0x04;
            e[1] = 0x03;
            e
        };
        let challenge = [0xBBu8; 32];

        let key1 = derive_session_key_v2(&shared_secret, &ephem1, &ephem2, &challenge).unwrap();
        let key2 = derive_session_key_v2(&shared_secret, &ephem1, &ephem3, &challenge).unwrap();

        assert_ne!(*key1, *key2, "different ephem pubkeys should produce different session keys");
    }
}
