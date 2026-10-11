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
//! - P1=0x35: NOISE_TARGET_INIT (V2 mutual-auth DKEK exchange, SO-PIN)
//! - P1=0x36: NOISE_SOURCE_RESPOND (V2, SO-PIN)
//! - P1=0x37: NOISE_FINALIZE_SEND_V2 (SO-PIN)
//! - P1=0x38: NOISE_FINALIZE_RECV_V2 (SO-PIN)
//! - P1=0x39: GET_KEY_MANIFEST (user PIN)
//! - P1=0x3A: GET_STATE_HASH
//! - P1=0x3B: SIGN_ENROLLMENT
//! - P1=0x3C: GET_GENERATION_V2
//! - P1=0x3D: ENROLL_PEER_PUBKEY (SO-PIN required)

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
pub fn handle(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    match cmd.p1 {
        // No-PIN sub-commands.
        0x30 => handle_get_device_public_key(state, store, cmd),
        0x34 => handle_get_generation(state, cmd),
        0x3A => handle_get_state_hash(state, store, cmd),
        0x3C => handle_get_generation_v2(state, cmd),

        // SO-PIN required.
        0x3B => {
            if !state.so_pin_verified {
                return ApduResponse::err(SW_SECURITY_STATUS);
            }
            handle_sign_enrollment(state, store, cmd)
        }
        0x3D => {
            if !state.so_pin_verified {
                return ApduResponse::err(SW_SECURITY_STATUS);
            }
            handle_enroll_peer_pubkey(state, store, cmd)
        }
        // V2 DKEK exchange: moves the master wrapping key, so SO-PIN only.
        0x35..=0x38 => {
            if !state.so_pin_verified {
                return ApduResponse::err(SW_SECURITY_STATUS);
            }
            match cmd.p1 {
                0x35 => handle_noise_target_init(state, store, cmd),
                0x36 => handle_noise_source_respond(state, store, cmd),
                0x37 => handle_noise_finalize_send_v2(state, store, cmd),
                _ => handle_noise_finalize_recv_v2(state, store, cmd),
            }
        }

        // All remaining sub-commands require PIN authentication.
        _ => {
            if !state.pin_verified {
                return ApduResponse::err(SW_SECURITY_STATUS);
            }
            match cmd.p1 {
                // Lists every key (ids, algorithms, flags, public-key hashes).
                0x39 => handle_get_key_manifest(state, store, cmd),
                0x01 => hkdf_extract(cmd.data),
                0x02 => hkdf_expand(cmd.data),
                0x03 => pbkdf2(cmd.data),
                0x04 => x963_kdf(cmd.data),
                0x05 => aes_cmac(cmd.data),
                0x06 => hmac_sha256(cmd.data),
                // V1 DKEK exchange (P1=0x31–0x33) removed — use V2 (P1=0x35–0x38).
                0x31..=0x33 => ApduResponse::err(pico2hsm_core::apdu::SW_INS_NOT_SUPPORTED),
                _ => ApduResponse::err(SW_WRONG_DATA),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// P1=0x30  GET_DEVICE_PUBLIC_KEY
// ---------------------------------------------------------------------------

fn handle_get_device_public_key(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    _cmd: &ApduCommand<'_>,
) -> ApduResponse {
    let dev_key_id = KeyId::sc_hsm(0, 0xFE);

    // Try persistent store (key object has public_key field).
    if let Ok(Some(key_obj)) = store.fetch_key(dev_key_id) {
        if !key_obj.public_key.is_empty() {
            return ApduResponse::ok(&key_obj.public_key);
        }
    }

    // Try EF 0x2F02 (public key stored during INITIALIZE) from ef_cache,
    // then fall back to flash via cross-core fetch_key RPC.
    let ef_key_id = KeyId::sc_hsm_ef(0, 0x2F, 0x02);
    if let Some(data) = state.ef_cache_get(ef_key_id.0) {
        if !data.is_empty() {
            return ApduResponse::ok(data);
        }
    }
    if let Ok(Some(obj)) = store.fetch_key(ef_key_id) {
        let data = &obj.private_key;
        if !data.is_empty() {
            state.ef_cache_put(ef_key_id.0, data);
            return ApduResponse::ok(data);
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
// V2 DKEK exchange (P1=0x35–0x38)
// ---------------------------------------------------------------------------
//
// SOURCE (holds the DKEK) sends it to TARGET (has none).  Both devices must
// have the other's static P-256 key enrolled via ENROLL_PEER_PUBKEY (0x3D);
// there is no unauthenticated mode.  All four steps require the SO-PIN.
//
//   1. TARGET 0x35 (source_static_pub)        → ephem_T || chal || Sig_T
//   2. SOURCE 0x36 (ephem_T || chal || Sig_T) → ephem_S || Sig_S
//      SOURCE verifies Sig_T with its enrolled peer key, then generates its
//      own ephemeral key.  Only now is SOURCE armed to send (see 0x37).
//   3. SOURCE 0x37 (ephem_T || target_static || chal) → enc_DKEK
//      Every field must match what step 2 verified; the DKEK is encrypted
//      only to that ephemeral key, bound to the enrolled peer's static key.
//   4. TARGET 0x38 (ephem_S || Sig_S || enc_DKEK)
//      TARGET verifies Sig_S, decrypts, and installs the DKEK.  An existing
//      DKEK is never overwritten.
//
// `exchange_peer_ephem_pub` is set only by a successful step 2, so it marks
// "SOURCE, peer verified"; TARGET state has it `None`.  Every step that
// fails, and every final step, clears all exchange state (one-shot).

/// Drop all in-progress exchange state (ephemeral key is zeroized on drop).
fn clear_exchange(state: &mut ScHsmState) {
    state.exchange_ephem_priv = None;
    state.exchange_ephem_pub = None;
    state.exchange_challenge = None;
    state.exchange_peer_ephem_pub = None;
}

/// Clear exchange state and return `sw`.
fn abort_exchange(state: &mut ScHsmState, sw: u16) -> ApduResponse {
    clear_exchange(state);
    ApduResponse::err(sw)
}

/// Verify `sig` as the enrolled peer's ECDSA signature over
/// SHA-256(ephem_pub || challenge).
fn peer_signed(peer: &[u8; 65], ephem_pub: &[u8], challenge: &[u8; 32], sig: &[u8; 64]) -> bool {
    use ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::VerifyingKey;
    use sha2::{Digest, Sha256};

    let Ok(vk) = VerifyingKey::from_sec1_bytes(peer) else {
        return false;
    };
    let Ok(sig) = ecdsa::Signature::<p256::NistP256>::from_bytes(sig.into()) else {
        return false;
    };
    let mut hasher = Sha256::new();
    hasher.update(ephem_pub);
    hasher.update(challenge);
    let msg_hash: [u8; 32] = hasher.finalize().into();
    vk.verify_prehash(&msg_hash, &sig).is_ok()
}

/// Generate an ephemeral P-256 key pair: (private scalar, uncompressed public).
fn new_ephemeral() -> Option<(zeroize::Zeroizing<[u8; 32]>, [u8; 65])> {
    use crate::crypto::asymmetric::generate_ec_keypair;
    use pico2hsm_core::key::KeyType as CoreKeyType;

    let pair = generate_ec_keypair(CoreKeyType::EcPrivateP256, &mut FwRng).ok()?;
    if pair.private_key.len() != 32 || pair.public_key.len() != 65 {
        return None;
    }
    let mut private = zeroize::Zeroizing::new([0u8; 32]);
    private.copy_from_slice(&pair.private_key);
    let mut public = [0u8; 65];
    public.copy_from_slice(&pair.public_key);
    Some((private, public))
}

/// Sign SHA-256(ephem_pub || challenge) with the device static key.
fn sign_ephemeral(
    state: &ScHsmState,
    store: &mut dyn KeyStore,
    ephem_pub: &[u8; 65],
    challenge: &[u8; 32],
) -> Result<[u8; 64], ()> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(ephem_pub);
    hasher.update(challenge);
    let msg_hash: [u8; 32] = hasher.finalize().into();
    sign_with_device_key(state, store, &msg_hash)
}

// P1=0x35  NOISE_TARGET_INIT — TARGET, step 1.
fn handle_noise_target_init(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    // Input: source_static_pub(65)
    if cmd.data.len() != 65 {
        return abort_exchange(state, SW_WRONG_DATA);
    }
    let Some(peer) = state.noise_enrolled_peer_pubkey else {
        return abort_exchange(state, SW_CONDITIONS_NOT_SATISFIED);
    };
    if cmd.data != peer.as_slice() {
        return abort_exchange(state, SW_SECURITY_STATUS);
    }
    // A DKEK is never overwritten, so refuse up front rather than at step 4.
    if state.dkek.is_ready() {
        return abort_exchange(state, SW_CONDITIONS_NOT_SATISFIED);
    }

    let Some((ephem_priv, ephem_pub)) = new_ephemeral() else {
        return abort_exchange(state, SW_CONDITIONS_NOT_SATISFIED);
    };
    let mut challenge = [0u8; 32];
    FwRng.fill_bytes(&mut challenge);
    let Ok(sig) = sign_ephemeral(state, store, &ephem_pub, &challenge) else {
        return abort_exchange(state, SW_CONDITIONS_NOT_SATISFIED);
    };

    clear_exchange(state);
    state.exchange_ephem_priv = Some(ephem_priv);
    state.exchange_ephem_pub = Some(ephem_pub);
    state.exchange_challenge = Some(challenge);

    // ephem_T_pub(65) || challenge(32) || Sig_T(64) = 161 bytes
    let mut out = [0u8; 161];
    out[..65].copy_from_slice(&ephem_pub);
    out[65..97].copy_from_slice(&challenge);
    out[97..].copy_from_slice(&sig);
    ApduResponse::ok(&out)
}

// P1=0x36  NOISE_SOURCE_RESPOND — SOURCE, step 2.
fn handle_noise_source_respond(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    // Input: ephem_T_pub(65) || challenge(32) || Sig_T(64) = 161 bytes
    if cmd.data.len() != 161 {
        return abort_exchange(state, SW_WRONG_DATA);
    }
    let ephem_t_pub: &[u8; 65] = cmd.data[..65].try_into().unwrap();
    let challenge: &[u8; 32] = cmd.data[65..97].try_into().unwrap();
    let sig_t: &[u8; 64] = cmd.data[97..161].try_into().unwrap();

    if !state.dkek.is_ready() {
        return abort_exchange(state, SW_CONDITIONS_NOT_SATISFIED);
    }
    let Some(peer) = state.noise_enrolled_peer_pubkey else {
        return abort_exchange(state, SW_CONDITIONS_NOT_SATISFIED);
    };
    if !peer_signed(&peer, ephem_t_pub, challenge, sig_t) {
        return abort_exchange(state, SW_SECURITY_STATUS);
    }

    let Some((ephem_priv, ephem_pub)) = new_ephemeral() else {
        return abort_exchange(state, SW_CONDITIONS_NOT_SATISFIED);
    };
    let Ok(sig) = sign_ephemeral(state, store, &ephem_pub, challenge) else {
        return abort_exchange(state, SW_CONDITIONS_NOT_SATISFIED);
    };

    clear_exchange(state);
    state.exchange_ephem_priv = Some(ephem_priv);
    state.exchange_ephem_pub = Some(ephem_pub);
    state.exchange_challenge = Some(*challenge);
    state.exchange_peer_ephem_pub = Some(*ephem_t_pub);

    // ephem_S_pub(65) || Sig_S(64) = 129 bytes
    let mut out = [0u8; 129];
    out[..65].copy_from_slice(&ephem_pub);
    out[65..].copy_from_slice(&sig);
    ApduResponse::ok(&out)
}

// P1=0x37  NOISE_FINALIZE_SEND_V2 — SOURCE, step 3.
fn handle_noise_finalize_send_v2(
    state: &mut ScHsmState,
    _store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    use crate::security::dkek::{derive_session_key_v2, p256_ecdh};
    use aes_gcm::{
        aead::{AeadInPlace, KeyInit},
        Aes256Gcm, Nonce as GcmNonce,
    };
    use zeroize::Zeroizing;

    // Input: target_ephem_pub(65) || target_static_pub(65) || challenge(32) = 162 bytes
    if cmd.data.len() != 162 {
        return abort_exchange(state, SW_WRONG_DATA);
    }
    let target_ephem_pub: &[u8; 65] = cmd.data[..65].try_into().unwrap();
    let target_static_pub: &[u8; 65] = cmd.data[65..130].try_into().unwrap();
    let challenge: &[u8; 32] = cmd.data[130..162].try_into().unwrap();

    // Armed only by a successful step 2, and only for what it verified.
    let (Some(peer), Some(peer_ephem), Some(stored_challenge), Some(ephem_priv), Some(ephem_pub)) = (
        state.noise_enrolled_peer_pubkey,
        state.exchange_peer_ephem_pub,
        state.exchange_challenge,
        state.exchange_ephem_priv.take(),
        state.exchange_ephem_pub,
    ) else {
        return abort_exchange(state, SW_CONDITIONS_NOT_SATISFIED);
    };
    if target_ephem_pub != &peer_ephem
        || target_static_pub != &peer
        || challenge != &stored_challenge
    {
        return abort_exchange(state, SW_SECURITY_STATUS);
    }
    let Some(dkek) = state.dkek.get_dkek().map(|d| Zeroizing::new(*d)) else {
        return abort_exchange(state, SW_CONDITIONS_NOT_SATISFIED);
    };
    clear_exchange(state);

    let Ok(shared_secret) = p256_ecdh(&ephem_priv, &peer_ephem) else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };
    // info = b"pico2hsm-dkek-v2" || source_ephem_pub || target_ephem_pub || challenge
    let Ok(session_key) =
        derive_session_key_v2(&shared_secret, &ephem_pub, &peer_ephem, &stored_challenge)
    else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };
    let Ok(cipher) = Aes256Gcm::new_from_slice(&*session_key) else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };

    let mut nonce_buf = [0u8; 12];
    FwRng.fill_bytes(&mut nonce_buf);
    let mut ct = dkek;
    // AAD = the enrolled peer's static key: only that device can open it.
    let Ok(tag) =
        cipher.encrypt_in_place_detached(GcmNonce::from_slice(&nonce_buf), &peer, ct.as_mut())
    else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };

    // nonce(12) || ciphertext(32) || tag(16) = 60 bytes
    let mut out = [0u8; 60];
    out[..12].copy_from_slice(&nonce_buf);
    out[12..44].copy_from_slice(ct.as_ref());
    out[44..].copy_from_slice(tag.as_slice());
    ApduResponse::ok(&out)
}

// P1=0x38  NOISE_FINALIZE_RECV_V2 — TARGET, step 4.
fn handle_noise_finalize_recv_v2(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    use crate::security::dkek::{derive_session_key_v2, p256_ecdh};
    use aes_gcm::{
        aead::{AeadInPlace, KeyInit},
        Aes256Gcm, Nonce as GcmNonce, Tag as GcmTag,
    };
    use zeroize::Zeroizing;

    // Input: source_ephem_pub(65) || Sig_S(64) || encrypted_dkek(60) = 189 bytes
    if cmd.data.len() != 189 {
        return abort_exchange(state, SW_WRONG_DATA);
    }
    let source_ephem_pub: &[u8; 65] = cmd.data[..65].try_into().unwrap();
    let sig_s: &[u8; 64] = cmd.data[65..129].try_into().unwrap();
    let encrypted_dkek: &[u8; 60] = cmd.data[129..189].try_into().unwrap();

    // TARGET state from step 1 (a SOURCE-armed state has a peer ephemeral).
    let (Some(peer), Some(ephem_priv), Some(ephem_pub), Some(challenge), None) = (
        state.noise_enrolled_peer_pubkey,
        state.exchange_ephem_priv.take(),
        state.exchange_ephem_pub,
        state.exchange_challenge,
        state.exchange_peer_ephem_pub,
    ) else {
        return abort_exchange(state, SW_CONDITIONS_NOT_SATISFIED);
    };
    clear_exchange(state);

    if state.dkek.is_ready() {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    }
    if !check_and_add_challenge(state, &challenge) {
        return ApduResponse::err(SW_WRONG_DATA);
    }
    if !peer_signed(&peer, source_ephem_pub, &challenge, sig_s) {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    let Ok(shared_secret) = p256_ecdh(&ephem_priv, source_ephem_pub) else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };
    // info = b"pico2hsm-dkek-v2" || source_ephem_pub || target_ephem_pub || challenge
    let Ok(session_key) =
        derive_session_key_v2(&shared_secret, source_ephem_pub, &ephem_pub, &challenge)
    else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };
    // AAD = own static public key (SOURCE bound the ciphertext to it).
    let Some(own_static_pub) = get_device_static_pub(state, store) else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };
    let Ok(cipher) = Aes256Gcm::new_from_slice(&*session_key) else {
        return ApduResponse::err(SW_CONDITIONS_NOT_SATISFIED);
    };

    // encrypted_dkek = nonce(12) || ct(32) || tag(16)
    let nonce = GcmNonce::from_slice(&encrypted_dkek[..12]);
    let tag = GcmTag::clone_from_slice(&encrypted_dkek[44..60]);
    let mut dkek_buf = Zeroizing::new([0u8; 32]);
    dkek_buf.copy_from_slice(&encrypted_dkek[12..44]);
    if cipher
        .decrypt_in_place_detached(nonce, &own_static_pub, dkek_buf.as_mut(), &tag)
        .is_err()
    {
        return ApduResponse::err(SW_SECURITY_STATUS);
    }

    state.dkek.set_dkek_direct(&dkek_buf);
    state.dkek_shares_imported = state.dkek.shares_total();
    ApduResponse::ok(&[])
}

// ---------------------------------------------------------------------------
// P1=0x39  GET_KEY_MANIFEST
// ---------------------------------------------------------------------------

fn handle_get_key_manifest(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    _cmd: &ApduCommand<'_>,
) -> ApduResponse {
    use sha2::{Digest, Sha256};

    // Each entry: key_ref(1) || algo(1) || key_flags(1) || deleted(1) || timestamp_ms_BE(8) || pubkey_hash(32) = 44 bytes
    // Max: 256 entries * 44 = 11264 — but realistically we have at most ~16 in-memory + flash keys.
    // Use a heapless Vec with reasonable max.
    let mut manifest: heapless::Vec<u8, 1408> = heapless::Vec::new(); // 32 entries * 44

    // Iterate key_index for crypto keys (not EfFile entries).
    for meta in state.key_index.iter() {
        // Skip EfFile entries.
        if meta.key_type == 16 {
            continue;
        }
        let key_ref = (meta.key_id & 0xFF) as u8;
        // Exclude device-internal keys: 0x00 (device cluster signing key) and
        // 0xFE (device auth cert key).  Only user keys 0x01–0xFD are synced.
        if key_ref == 0x00 || key_ref >= 0xFE {
            continue;
        }
        let algo = meta.algo;
        let key_flags = meta.key_flags;
        let deleted = 0u8;

        // Fetch from flash to get timestamp and pubkey hash.
        let kid = KeyId(meta.key_id);
        let (timestamp_ms, pubkey_hash) = if let Ok(Some(key_obj)) = store.fetch_key(kid) {
            let h = if !key_obj.public_key.is_empty() {
                Sha256::digest(&key_obj.public_key).into()
            } else {
                [0u8; 32]
            };
            (key_obj.timestamp_ms, h)
        } else {
            (0u64, [0u8; 32])
        };

        let _ = manifest.push(key_ref);
        let _ = manifest.push(algo);
        let _ = manifest.push(key_flags);
        let _ = manifest.push(deleted);
        let _ = manifest.extend_from_slice(&timestamp_ms.to_be_bytes());
        let _ = manifest.extend_from_slice(&pubkey_hash);
    }

    ApduResponse::ok(&manifest)
}

// ---------------------------------------------------------------------------
// P1=0x3A  GET_STATE_HASH
// ---------------------------------------------------------------------------

fn handle_get_state_hash(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    _cmd: &ApduCommand<'_>,
) -> ApduResponse {
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
                leaf_hasher.update([0x01, slot, algo, key_flags]);
                leaf_hasher.update(timestamp_ms.to_be_bytes());
                leaf_hasher.update(pubkey_hash);
            }
            None => {
                // Empty slot: SHA-256(0x00 || key_ref || [0;43])
                leaf_hasher.update([0x00, slot]);
                leaf_hasher.update([0u8; 43]);
            }
        }

        let leaf: [u8; 32] = leaf_hasher.finalize().into();
        root_hasher.update(leaf);
    }

    let state_root: [u8; 32] = root_hasher.finalize().into();
    let generation = state.generation;

    // Sign: Sig = P256_RFC6979_ECDSA_sign(device_static_priv, SHA-256(generation_BE(8) || state_root(32)))
    let mut sig_hasher = Sha256::new();
    sig_hasher.update(generation.to_be_bytes());
    sig_hasher.update(state_root);
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

fn handle_sign_enrollment(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
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
// P1=0x3D  ENROLL_PEER_PUBKEY (SO-PIN required)
// ---------------------------------------------------------------------------

/// Enroll (or re-enroll) a peer device's static P-256 public key for V2
/// Noise mutual authentication.  Once enrolled, unauthenticated DKEK
/// exchanges are permanently locked out.
///
/// Input: 65-byte uncompressed P-256 public key (0x04 || x || y).
/// Returns: SW 9000 on success.
///
/// SO-PIN VERIFY is required before calling this command (checked in the
/// dispatch match above).  Re-enrollment (overwriting an existing peer)
/// is allowed with SO-PIN to support HSM replacement scenarios.
fn handle_enroll_peer_pubkey(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    // Validate input length: must be exactly 65 bytes (uncompressed P-256).
    if cmd.data.len() != 65 {
        return ApduResponse::err(SW_WRONG_LENGTH);
    }

    // Validate that the pubkey is a valid point on P-256.
    if p256::ecdsa::VerifyingKey::from_sec1_bytes(cmd.data).is_err() {
        return ApduResponse::err(SW_WRONG_DATA);
    }

    // Store the peer pubkey in volatile state.
    let mut pubkey = [0u8; 65];
    pubkey.copy_from_slice(cmd.data);
    state.noise_enrolled_peer_pubkey = Some(pubkey);

    // Persist to flash so the enrollment survives power cycles.
    if crate::protocol::sc_hsm::ScHsm::save_peer_pubkey_to_store(state, store).is_err() {
        state.noise_enrolled_peer_pubkey = None;
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    }

    ApduResponse::ok(&[])
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
fn sign_with_device_key(
    state: &ScHsmState,
    store: &mut dyn KeyStore,
    msg_hash: &[u8; 32],
) -> Result<[u8; 64], ()> {
    use ecdsa::signature::hazmat::PrehashSigner;
    use ecdsa::SigningKey;
    use p256::SecretKey;
    use zeroize::Zeroizing;

    let dev_key_id = KeyId::sc_hsm(0, 0xFE);

    // Try flash first, then deprecated in-memory fallback.
    let priv_bytes: Zeroizing<[u8; 32]> = if let Ok(Some(key_obj)) = store.fetch_key(dev_key_id) {
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
    let signature: ecdsa::Signature<p256::NistP256> =
        signing_key.sign_prehash(msg_hash).map_err(|_| ())?;
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

    // Try flash key object first.
    if let Ok(Some(key_obj)) = store.fetch_key(dev_key_id) {
        if key_obj.public_key.len() == 65 {
            let mut out = [0u8; 65];
            out.copy_from_slice(&key_obj.public_key);
            return Some(out);
        }
    }

    // Try EF 0x2F02 from ef_cache.
    let ef_key_id = KeyId::sc_hsm_ef(0, 0x2F, 0x02);
    if let Some(data) = state.ef_cache_get(ef_key_id.0) {
        if data.len() == 65 {
            let mut out = [0u8; 65];
            out.copy_from_slice(data);
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
    let cap = crate::protocol::sc_hsm::MAX_EXCHANGE_CHALLENGE_CACHE as u8;
    let idx = (state.exchange_challenge_cache_write_idx % cap) as usize;
    state.exchange_challenge_cache[idx] = *challenge;
    state.exchange_challenge_cache_write_idx =
        state.exchange_challenge_cache_write_idx.wrapping_add(1);
    if state.exchange_challenge_cache_count < cap {
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

    // Check key_index for metadata.
    if let Some(meta) = state
        .key_index
        .iter()
        .find(|m| m.key_id == key_id.0 && m.key_type != 16)
    {
        // Fetch from flash for pubkey hash and timestamp.
        if let Ok(Some(key_obj)) = store.fetch_key(key_id) {
            let pubkey_hash = if !key_obj.public_key.is_empty() {
                Sha256::digest(&key_obj.public_key).into()
            } else {
                [0u8; 32]
            };
            return Some((meta.algo, meta.key_flags, key_obj.timestamp_ms, pubkey_hash));
        }
        // Key is in index but not in flash (e.g. volatile sentinel); use metadata only.
        return Some((meta.algo, meta.key_flags, 0, [0u8; 32]));
    }

    // Fallback: check flash directly (for keys not yet in key_index).
    if let Ok(Some(key_obj)) = store.fetch_key(key_id) {
        let pubkey_hash = if !key_obj.public_key.is_empty() {
            Sha256::digest(&key_obj.public_key).into()
        } else {
            [0u8; 32]
        };
        return Some((
            key_obj.algorithm as u8,
            key_obj.key_flags,
            key_obj.timestamp_ms,
            pubkey_hash,
        ));
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
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let ikm: [u8; 22] = [0x0b; 22];

        let data = make_data(&[&[salt.len() as u8], &salt, &ikm]);
        let resp = hkdf_extract(&data);

        let expected =
            hex_to_32(b"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        assert_eq!(resp.sw, 0x9000, "expected SW_OK");
        assert_eq!(&resp.data[..], &expected[..]);
    }

    // -----------------------------------------------------------------------
    // HKDF-Expand — use A.1 PRK, expand 42 bytes, verify non-zero
    // -----------------------------------------------------------------------
    #[test]
    fn test_hkdf_expand_produces_output() {
        // PRK from A.1
        let prk = hex_to_32(b"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let info: &[u8] = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let output_len: u8 = 42;

        let data = make_data(&[&prk, &[output_len], info]);
        let resp = hkdf_expand(&data);

        assert_eq!(resp.sw, 0x9000, "expected SW_OK");
        assert_eq!(resp.data.len(), 42);
        assert!(
            resp.data.iter().any(|&b| b != 0),
            "output should be non-zero"
        );
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

        let expected =
            hex_to_32(b"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
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

    use crate::protocol::sc_hsm::{KeyMeta, ScHsmState};
    use crate::storage::KeyStore;
    use pico2hsm_core::key::{AppletId, KeyId, KeyType as CoreKeyType};

    use crate::security::key_management::{AlgorithmId, KeyObject, KeyType as KmType};

    /// Copy a KeyObject (KeyObject doesn't impl Clone).
    fn copy_key_object(obj: &KeyObject) -> KeyObject {
        let mut copy = KeyObject::new(obj.key_type, obj.key_id, obj.owner, obj.algorithm);
        copy.key_flags = obj.key_flags;
        let _ = copy.private_key.extend_from_slice(&obj.private_key);
        let _ = copy.public_key.extend_from_slice(&obj.public_key);
        copy
    }

    /// Test key store that holds a device identity key and optionally an EF 0x2F02.
    struct DevKeyStore {
        dev_key: Option<KeyObject>,
        ef_key: Option<KeyObject>,
    }
    impl DevKeyStore {
        fn new() -> Self {
            DevKeyStore {
                dev_key: None,
                ef_key: None,
            }
        }
    }
    impl KeyStore for DevKeyStore {
        fn save_key(&mut self, obj: &KeyObject) -> Result<(), pico2hsm_core::error::HsmError> {
            let dev_key_id = KeyId::sc_hsm(0, 0xFE).0;
            let ef_key_id = KeyId::sc_hsm_ef(0, 0x2F, 0x02).0;
            if obj.key_id == dev_key_id {
                self.dev_key = Some(copy_key_object(obj));
            } else if obj.key_id == ef_key_id {
                self.ef_key = Some(copy_key_object(obj));
            }
            Ok(())
        }
        fn fetch_key(
            &mut self,
            kid: KeyId,
        ) -> Result<Option<KeyObject>, pico2hsm_core::error::HsmError> {
            let dev_key_id = KeyId::sc_hsm(0, 0xFE).0;
            let ef_key_id = KeyId::sc_hsm_ef(0, 0x2F, 0x02).0;
            if kid.0 == dev_key_id {
                return Ok(self.dev_key.as_ref().map(copy_key_object));
            }
            if kid.0 == ef_key_id {
                return Ok(self.ef_key.as_ref().map(copy_key_object));
            }
            Ok(None)
        }
        fn erase_key(&mut self, _: KeyId) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn wipe_all(&mut self) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn wipe_by_owner(&mut self, _: AppletId) -> Result<(), pico2hsm_core::error::HsmError> {
            Ok(())
        }
        fn enumerate_keys(&self) -> heapless::Vec<KeyId, 64> {
            heapless::Vec::new()
        }
        fn for_each_key(&self, _f: &mut dyn FnMut(KeyId)) {}
    }

    /// Create a ScHsmState with a device static key (key_ref=0xFE) and PIN verified,
    /// along with a DevKeyStore that holds the key material.
    fn state_with_device_key() -> (ScHsmState, DevKeyStore) {
        use crate::crypto::asymmetric::generate_ec_keypair;

        let mut state = ScHsmState::new();
        state.pin_verified = true;
        state.so_pin_verified = true;
        state.initialized = true;

        // Generate a real P-256 keypair for the device identity key.
        let mut rng = crate::protocol::sc_hsm::FwRng;
        let pair = generate_ec_keypair(CoreKeyType::EcPrivateP256, &mut rng).unwrap();

        let dev_key_id = KeyId::sc_hsm(0, 0xFE).0;
        let meta = KeyMeta {
            key_id: dev_key_id,
            key_type: CoreKeyType::EcPrivateP256 as u8,
            algo: 0x13,
            key_flags: 0,
        };
        state.key_index.push(meta).unwrap();

        // Store key material in the test store.
        let mut store = DevKeyStore::new();
        let mut key_obj = crate::security::key_management::KeyObject::new(
            crate::security::key_management::KeyType::Ec,
            dev_key_id,
            AppletId::ScHsm,
            crate::security::key_management::AlgorithmId::EcdsaP256,
        );
        let _ = key_obj.private_key.extend_from_slice(&pair.private_key);
        let _ = key_obj.public_key.extend_from_slice(&pair.public_key);
        store.dev_key = Some(key_obj);

        // Also store public key as EF 0x2F02.
        let ef_key_id = KeyId::sc_hsm_ef(0, 0x2F, 0x02);
        let mut ef_obj = crate::security::key_management::KeyObject::new(
            crate::security::key_management::KeyType::Generic,
            ef_key_id.0,
            AppletId::ScHsm,
            crate::security::key_management::AlgorithmId::EcdsaP256,
        );
        let _ = ef_obj.private_key.extend_from_slice(&pair.public_key);
        store.ef_key = Some(ef_obj);

        // Add EF metadata to key_index.
        let ef_meta = KeyMeta {
            key_id: ef_key_id.0,
            key_type: 16, // EfFile
            algo: 0x2F,   // high byte of file_id 0x2F02
            key_flags: 0,
        };
        state.key_index.push(ef_meta).unwrap();

        (state, store)
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
    fn test_challenge_cache_full_rotation() {
        let mut state = ScHsmState::new();

        // Fill cache with 8 unique challenges (slots 0..7).
        for i in 0u8..8 {
            let mut c = [0u8; 32];
            c[0] = i;
            assert!(
                check_and_add_challenge(&mut state, &c),
                "challenge {} should succeed",
                i
            );
        }
        assert_eq!(state.exchange_challenge_cache_count, 8);

        // Add a 9th challenge — this should evict slot 0 (challenge with c[0]=0).
        let mut c9 = [0u8; 32];
        c9[0] = 0x08; // 8
        assert!(
            check_and_add_challenge(&mut state, &c9),
            "9th challenge should succeed"
        );

        // The 9th challenge should be found (it was just inserted in slot 0).
        assert!(
            !check_and_add_challenge(&mut state, &c9),
            "9th challenge should be detected as replay"
        );

        // Challenge 0 (c[0]=0) was evicted from slot 0 and should NOT be detected.
        let c0 = [0u8; 32];
        assert!(
            check_and_add_challenge(&mut state, &c0),
            "evicted challenge 0 should be accepted as new"
        );
        // c0 was written to slot 1 (write_idx=10, 10%8=2 — wait, 9%8=1), evicting challenge 1.

        // Challenges 2..7 should still be in the cache (slots 2..7 untouched).
        for i in 2u8..8 {
            let mut c = [0u8; 32];
            c[0] = i;
            assert!(
                !check_and_add_challenge(&mut state, &c),
                "challenge {} should still be in cache",
                i
            );
        }

        // Challenge 1 was evicted by c0's insert and should be accepted as new.
        let mut c1 = [0u8; 32];
        c1[0] = 1;
        assert!(
            check_and_add_challenge(&mut state, &c1),
            "evicted challenge 1 should be accepted as new"
        );

        // Verify write pointer advances correctly: after 11 inserts (8+3),
        // write_idx should be 11.
        assert_eq!(state.exchange_challenge_cache_write_idx, 11);
        assert_eq!(state.exchange_challenge_cache_count, 8);
    }

    #[test]
    fn test_challenge_cache_deduplication_works() {
        let mut state = ScHsmState::new();
        let challenge_a = [0xAAu8; 32];

        // First insert succeeds.
        assert!(check_and_add_challenge(&mut state, &challenge_a));
        // Duplicate is rejected.
        assert!(!check_and_add_challenge(&mut state, &challenge_a));

        // Fill remaining slots with distinct challenges (cache is MAX_EXCHANGE_CHALLENGE_CACHE).
        for i in 1u8..(crate::protocol::sc_hsm::MAX_EXCHANGE_CHALLENGE_CACHE as u8) {
            let mut c = [0u8; 32];
            c[0] = i;
            assert!(check_and_add_challenge(&mut state, &c));
        }

        // challenge_a should still be detected (it's in slot 0, not yet evicted).
        assert!(!check_and_add_challenge(&mut state, &challenge_a));

        // One more insert evicts slot 0 (where challenge_a lives).
        let new_c = [0xFFu8; 32];
        assert!(check_and_add_challenge(&mut state, &new_c));

        // Now challenge_a has been evicted — it should be accepted as new.
        assert!(check_and_add_challenge(&mut state, &challenge_a));
    }

    #[test]
    fn test_get_state_hash_returns_104_bytes() {
        let (mut state, mut store) = state_with_device_key();

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
        assert_eq!(
            resp.data.len(),
            104,
            "expected 104 bytes: generation(8) + state_root(32) + sig(64)"
        );
    }

    #[test]
    fn test_get_state_hash_changes_after_key_add() {
        let (mut state, mut store) = state_with_device_key();

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

        // Add a fake key to a new slot (both key_index and deprecated keys).
        let key_id2 = KeyId::sc_hsm(0, 0x01).0;
        let meta = crate::protocol::sc_hsm::KeyMeta {
            key_id: key_id2,
            key_type: CoreKeyType::EcPrivateP256 as u8,
            algo: 0x13,
            key_flags: 0,
        };
        state.key_index.push(meta).unwrap();

        // Get state hash after adding a key.
        let resp2 = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp2.sw, 0x9000);

        // The state_root portion (bytes 8..40) should differ.
        assert_ne!(
            &hash1[8..40],
            &resp2.data[8..40],
            "state_root should change after adding a key"
        );
    }

    #[test]
    fn test_get_generation_v2_returns_8_bytes() {
        let mut state = ScHsmState::new();
        let mut store = DevKeyStore::new();

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
        let (mut state, mut store) = state_with_device_key();

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
        let (mut state, mut store) = state_with_device_key();
        state.so_pin_verified = false; // Override

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
        let (mut state, mut store) = state_with_device_key();

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
        assert_eq!(
            resp.data.len(),
            0,
            "device key (0xFE) must be excluded from manifest"
        );
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

        assert_ne!(
            *key1, *key2,
            "different ephem pubkeys should produce different session keys"
        );
    }

    // -----------------------------------------------------------------------
    // ENROLL_PEER_PUBKEY tests (P1=0x3D)
    // -----------------------------------------------------------------------

    /// Generate a valid P-256 public key for enrollment tests.
    fn generate_test_p256_pubkey() -> [u8; 65] {
        use crate::crypto::asymmetric::generate_ec_keypair;
        let mut rng = crate::protocol::sc_hsm::FwRng;
        let pair = generate_ec_keypair(CoreKeyType::EcPrivateP256, &mut rng).unwrap();
        let mut pubkey = [0u8; 65];
        pubkey.copy_from_slice(&pair.public_key);
        pubkey
    }

    #[test]
    fn test_enroll_peer_pubkey_requires_sopin() {
        let (mut state, mut store) = state_with_device_key();
        state.so_pin_verified = false;

        let pubkey = generate_test_p256_pubkey();
        let cmd = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x3D,
            p2: 0x00,
            data: &pubkey,
            le: None,
        };

        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_SECURITY_STATUS, "should require SO-PIN");
    }

    #[test]
    fn test_enroll_peer_pubkey_validates_key_wrong_length() {
        let (mut state, mut store) = state_with_device_key();

        // Too short (32 bytes instead of 65).
        let short_data = [0x04u8; 32];
        let cmd = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x3D,
            p2: 0x00,
            data: &short_data,
            le: None,
        };

        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_WRONG_LENGTH, "wrong length should be rejected");
    }

    #[test]
    fn test_enroll_peer_pubkey_validates_key_not_on_curve() {
        let (mut state, mut store) = state_with_device_key();

        // 65 bytes starting with 0x04 but invalid point.
        let mut bad_key = [0u8; 65];
        bad_key[0] = 0x04;
        bad_key[1] = 0xFF; // Not a valid P-256 point.
        let cmd = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x3D,
            p2: 0x00,
            data: &bad_key,
            le: None,
        };

        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, SW_WRONG_DATA, "invalid point should be rejected");
    }

    #[test]
    fn test_enroll_peer_pubkey_stores_key() {
        let (mut state, mut store) = state_with_device_key();

        let pubkey = generate_test_p256_pubkey();
        let cmd = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x3D,
            p2: 0x00,
            data: &pubkey,
            le: None,
        };

        assert!(state.noise_enrolled_peer_pubkey.is_none());
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, 0x9000, "enrollment should succeed");
        assert_eq!(state.noise_enrolled_peer_pubkey.unwrap(), pubkey);
    }

    #[test]
    fn test_enroll_peer_pubkey_re_enrollment() {
        let (mut state, mut store) = state_with_device_key();

        let pubkey1 = generate_test_p256_pubkey();
        let pubkey2 = generate_test_p256_pubkey();

        // Enroll first key.
        let cmd1 = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x3D,
            p2: 0x00,
            data: &pubkey1,
            le: None,
        };
        let resp1 = handle(&mut state, &mut store, &cmd1);
        assert_eq!(resp1.sw, 0x9000);
        assert_eq!(state.noise_enrolled_peer_pubkey.unwrap(), pubkey1);

        // Re-enroll with second key (SO-PIN still verified).
        let cmd2 = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x3D,
            p2: 0x00,
            data: &pubkey2,
            le: None,
        };
        let resp2 = handle(&mut state, &mut store, &cmd2);
        assert_eq!(resp2.sw, 0x9000);
        assert_eq!(
            state.noise_enrolled_peer_pubkey.unwrap(),
            pubkey2,
            "re-enrollment should overwrite"
        );
    }

    // -----------------------------------------------------------------------
    // V2 DKEK exchange — two simulated devices
    // -----------------------------------------------------------------------

    fn extras(
        state: &mut ScHsmState,
        store: &mut DevKeyStore,
        p1: u8,
        data: &[u8],
    ) -> ApduResponse {
        let cmd = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1,
            p2: 0x00,
            data,
            le: None,
        };
        handle(state, store, &cmd)
    }

    fn static_pub(store: &DevKeyStore) -> [u8; 65] {
        store.dev_key.as_ref().unwrap().public_key[..]
            .try_into()
            .unwrap()
    }

    /// SOURCE (holds DKEK) and TARGET, each enrolled to the other.
    fn enrolled_pair() -> ((ScHsmState, DevKeyStore), (ScHsmState, DevKeyStore)) {
        let (mut src, mut src_store) = state_with_device_key();
        let (mut tgt, mut tgt_store) = state_with_device_key();
        let (src_pub, tgt_pub) = (static_pub(&src_store), static_pub(&tgt_store));
        assert_eq!(extras(&mut src, &mut src_store, 0x3D, &tgt_pub).sw, 0x9000);
        assert_eq!(extras(&mut tgt, &mut tgt_store, 0x3D, &src_pub).sw, 0x9000);
        src.dkek.set_dkek_direct(&[0x5Cu8; 32]);
        ((src, src_store), (tgt, tgt_store))
    }

    #[test]
    fn exchange_transfers_dkek_between_enrolled_peers() {
        let ((mut src, mut ss), (mut tgt, mut ts)) = enrolled_pair();
        let (src_pub, tgt_pub) = (static_pub(&ss), static_pub(&ts));

        let init = extras(&mut tgt, &mut ts, 0x35, &src_pub);
        assert_eq!(init.sw, 0x9000);
        let respond = extras(&mut src, &mut ss, 0x36, &init.data);
        assert_eq!(respond.sw, 0x9000);
        let send = extras(
            &mut src,
            &mut ss,
            0x37,
            &make_data(&[&init.data[..65], &tgt_pub, &init.data[65..97]]),
        );
        assert_eq!(send.sw, 0x9000);
        let recv = extras(
            &mut tgt,
            &mut ts,
            0x38,
            &make_data(&[&respond.data, &send.data]),
        );
        assert_eq!(recv.sw, 0x9000);
        assert_eq!(tgt.dkek.get_dkek(), Some(&[0x5Cu8; 32]));
        // One-shot: both sides are disarmed.
        assert!(src.exchange_ephem_priv.is_none() && tgt.exchange_ephem_priv.is_none());
    }

    #[test]
    fn send_without_verified_respond_is_refused() {
        // The S-02 attack: arm SOURCE with 0x35 (its own challenge), then ask
        // it to send the DKEK to an attacker-chosen ephemeral key.
        let ((mut src, mut ss), (_tgt, ts)) = enrolled_pair();
        let tgt_pub = static_pub(&ts);
        let init = extras(&mut src, &mut ss, 0x35, &tgt_pub);
        // SOURCE holds a DKEK, so it refuses to act as TARGET at all.
        assert_ne!(init.sw, 0x9000);
        let attacker_ephem = static_pub(&ts); // any valid point
        let send = extras(
            &mut src,
            &mut ss,
            0x37,
            &make_data(&[&attacker_ephem, &tgt_pub, &[0u8; 32]]),
        );
        assert_eq!(send.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn send_to_substituted_ephemeral_is_refused() {
        let ((mut src, mut ss), (mut tgt, mut ts)) = enrolled_pair();
        let (src_pub, tgt_pub) = (static_pub(&ss), static_pub(&ts));
        let init = extras(&mut tgt, &mut ts, 0x35, &src_pub);
        assert_eq!(extras(&mut src, &mut ss, 0x36, &init.data).sw, 0x9000);
        let attacker_ephem = src_pub; // valid point, but not the verified one
        let send = extras(
            &mut src,
            &mut ss,
            0x37,
            &make_data(&[&attacker_ephem, &tgt_pub, &init.data[65..97]]),
        );
        assert_eq!(send.sw, SW_SECURITY_STATUS);
        assert!(
            src.exchange_peer_ephem_pub.is_none(),
            "aborted exchange is disarmed"
        );
    }

    #[test]
    fn respond_rejects_forged_target_signature() {
        let ((mut src, mut ss), (mut tgt, mut ts)) = enrolled_pair();
        let init = extras(&mut tgt, &mut ts, 0x35, &static_pub(&ss));
        let mut forged = make_data(&[&init.data]);
        forged[100] ^= 0x01;
        assert_eq!(
            extras(&mut src, &mut ss, 0x36, &forged).sw,
            SW_SECURITY_STATUS
        );
    }

    #[test]
    fn exchange_requires_enrolled_peer() {
        let (mut tgt, mut ts) = state_with_device_key();
        let (_src, ss) = state_with_device_key();
        let resp = extras(&mut tgt, &mut ts, 0x35, &static_pub(&ss));
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn exchange_requires_so_pin() {
        let ((_src, ss), (mut tgt, mut ts)) = enrolled_pair();
        tgt.so_pin_verified = false;
        let resp = extras(&mut tgt, &mut ts, 0x35, &static_pub(&ss));
        assert_eq!(resp.sw, SW_SECURITY_STATUS);
    }

    #[test]
    fn target_with_dkek_is_never_overwritten() {
        let ((_src, ss), (mut tgt, mut ts)) = enrolled_pair();
        tgt.dkek.set_dkek_direct(&[0x11u8; 32]);
        let resp = extras(&mut tgt, &mut ts, 0x35, &static_pub(&ss));
        assert_eq!(resp.sw, SW_CONDITIONS_NOT_SATISFIED);
        assert_eq!(tgt.dkek.get_dkek(), Some(&[0x11u8; 32]));
    }
}
