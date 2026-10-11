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
//! - P1=0x34: GET_GENERATION (V1 compat, low 4 bytes of the Lamport counter)
//! - P1=0x35: NOISE_TARGET_INIT (V2 mutual-auth DKEK exchange, SO-PIN)
//! - P1=0x36: NOISE_SOURCE_RESPOND (V2, SO-PIN)
//! - P1=0x37: NOISE_FINALIZE_SEND_V2 (SO-PIN)
//! - P1=0x38: NOISE_FINALIZE_RECV_V2 (SO-PIN)
//! - P1=0x39: GET_KEY_MANIFEST (user PIN; paged, P2 = first key ref)
//! - P1=0x3A: GET_STATE_HASH
//! - P1=0x3B: SIGN_ENROLLMENT
//! - P1=0x3C: GET_GENERATION_V2 (the persisted Lamport counter, u64)
//! - P1=0x3D: ENROLL_PEER_PUBKEY (SO-PIN; pins the peer for one exchange)
//! - P1=0x40: DOMAIN_STATUS (no auth)
//! - P1=0x47: GET_MEMBERS (no auth; paged, P2 = first slot)

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
        0x34 => handle_get_generation(store),
        0x3A => handle_get_state_hash(state, store, cmd),
        0x3C => handle_get_generation_v2(store),
        0x40 => handle_domain_status(state, store),
        0x47 => handle_get_members(store, cmd),

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

fn handle_get_generation(store: &mut dyn KeyStore) -> ApduResponse {
    // The low 4 bytes of the Lamport counter (V1 compat).
    match crate::storage::retry_counter::lamport(store) {
        Ok(v) => ApduResponse::ok(&(v as u32).to_be_bytes()),
        Err(_) => ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE),
    }
}

// ---------------------------------------------------------------------------
// V2 DKEK exchange (P1=0x35–0x38)
// ---------------------------------------------------------------------------
//
// SOURCE (holds the DKEK) sends it to TARGET (has none).  Both devices must
// have the other's static P-256 key pinned via ENROLL_PEER_PUBKEY (0x3D);
// there is no unauthenticated mode.  All four steps require the SO-PIN.
// The pin is single-use (cluster plan V3 §5.2 step 3): SOURCE spends it
// before releasing the encrypted DKEK (step 3), TARGET before installing
// it (step 4).  Steps that fail keep it, so an aborted exchange can be
// run again.
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
    let Some(peer) = state.pinned_peer else {
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
    let Some(peer) = state.pinned_peer else {
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
        state.pinned_peer,
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

    // Single use: the pin is spent before the DKEK leaves the device.
    if crate::protocol::sc_hsm::ScHsm::consume_pinned_peer(state, _store).is_err() {
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    }

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
        state.pinned_peer,
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

    // Single use: the pin is spent before the DKEK is installed.
    if crate::protocol::sc_hsm::ScHsm::consume_pinned_peer(state, store).is_err() {
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    }
    state.dkek.set_dkek_direct(&dkek_buf);
    state.dkek_shares_imported = state.dkek.shares_total();
    ApduResponse::ok(&[])
}

// ---------------------------------------------------------------------------
// P1=0x39  GET_KEY_MANIFEST
// ---------------------------------------------------------------------------

/// Manifest entry formats: 1 = legacy 44-byte entries, 2 = with object ID.
const MANIFEST_V1_ENTRY: usize = 44;
const MANIFEST_V2_ENTRY: usize = 64;

/// One page of the key manifest.
///
/// P2 = the first key reference to list; data = absent or `01` for the
/// legacy format, `02` for the format with global object IDs.  Keys are
/// listed in ascending key-reference order, as many as fit in one
/// response (`MAX_RESPONSE_DATA`, sent with GET RESPONSE chaining); the
/// host asks again with P2 = last listed reference + 1 until a page comes
/// back empty.  Built straight into the response buffer, so nothing large
/// sits on the core1 stack.
///
/// ```text
/// v1 entry: key_ref(1) algo(1) key_flags(1) 00(1) timestamp_ms(8 BE)
///           SHA-256(public key)(32)                                  44 bytes
/// v2 entry: key_ref(1) algo(1) key_flags(1) id_len(1) timestamp_ms(8 BE)
///           SHA-256(public key)(32) object_id(20, zero-padded)       64 bytes
/// ```
///
/// In v2 a key without an ID yet (a symmetric key from before this
/// firmware) gets its random ID now (§6.2, lazy assignment); a write
/// failure fails the page (6581).
#[inline(never)]
fn handle_get_key_manifest(
    state: &mut ScHsmState,
    store: &mut dyn KeyStore,
    cmd: &ApduCommand<'_>,
) -> ApduResponse {
    use crate::apdu::dispatcher::MAX_RESPONSE_DATA;

    let v2 = match cmd.data {
        [] | [0x01] => false,
        [0x02] => true,
        _ => return ApduResponse::err(SW_WRONG_DATA),
    };
    let entry_len = if v2 {
        MANIFEST_V2_ENTRY
    } else {
        MANIFEST_V1_ENTRY
    };
    let mut resp = ApduResponse::ok(&[]);
    // User keys only: 0x00 is the device sentinel, 0xFC.. are records.
    let first = cmd.p2.max(0x01);
    for key_ref in first..crate::protocol::sc_hsm::RESERVED_KEY_REF_MIN {
        let kid = KeyId::sc_hsm(0, key_ref);
        let Some(meta) = state
            .key_index
            .iter()
            .find(|m| m.key_id == kid.0 && m.key_type != 16)
            .copied()
        else {
            continue;
        };
        if resp.data.len() + entry_len > MAX_RESPONSE_DATA {
            break;
        }
        let (timestamp_ms, pubkey_hash, intrinsic, found) = key_summary(store, kid);
        let id = if !v2 || !found {
            None
        } else if intrinsic.is_some() {
            intrinsic
        } else {
            // No intrinsic ID: the sidecar's, assigned now if missing.
            match sidecar_id(store, kid) {
                Ok(id) => Some(id),
                Err(_) => return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE),
            }
        };
        let mut e = [0u8; MANIFEST_V2_ENTRY];
        e[0] = key_ref;
        e[1] = meta.algo;
        e[2] = meta.key_flags;
        e[3] = if v2 { id.map_or(0, |i| i.len) } else { 0 };
        e[4..12].copy_from_slice(&timestamp_ms.to_be_bytes());
        e[12..44].copy_from_slice(&pubkey_hash);
        if let Some(id) = id {
            e[44..64].copy_from_slice(&id.bytes);
        }
        if resp.data.extend_from_slice(&e[..entry_len]).is_err() {
            break;
        }
    }
    resp
}

/// `(timestamp_ms, SHA-256(public key), intrinsic ID, found)` of the key
/// at `kid`.  Its own frame: the fetched `KeyObject` is gone before the
/// caller touches the store again (core1 stack).
#[inline(never)]
fn key_summary(
    store: &mut dyn KeyStore,
    kid: KeyId,
) -> (
    u64,
    [u8; 32],
    Option<crate::domain::object_id::ObjectId>,
    bool,
) {
    use sha2::{Digest, Sha256};
    match store.fetch_key(kid) {
        Ok(Some(obj)) => {
            let h: [u8; 32] = if obj.public_key.is_empty() {
                [0u8; 32]
            } else {
                Sha256::digest(&obj.public_key).into()
            };
            (
                obj.timestamp_ms,
                h,
                crate::domain::object_id::intrinsic(&obj),
                true,
            )
        }
        _ => (0, [0u8; 32], None, false),
    }
}

/// The sidecar ID of `kid`, assigned (random, kind key) if it has none.
#[inline(never)]
fn sidecar_id(
    store: &mut dyn KeyStore,
    kid: KeyId,
) -> Result<crate::domain::object_id::ObjectId, pico2hsm_core::error::HsmError> {
    use crate::domain::object_id;
    match object_id::load_sidecar(store, kid)? {
        Some(sc) => Ok(sc.id),
        None => object_id::assign_random(store, kid, object_id::KIND_KEY),
    }
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
    let Ok(generation) = crate::storage::retry_counter::lamport(store) else {
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    };

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

/// Pin a peer device's static P-256 public key for the next V2 DKEK
/// exchange (cluster plan V3 §5.2 step 3).  The exchange that completes
/// with it spends it; pinning again replaces it.  The operator checks the
/// key out of band (short authentication string) before pinning.
///
/// Input: 65-byte uncompressed P-256 public key (0x04 || x || y).
/// Returns: SW 9000 on success.
///
/// SO-PIN VERIFY is required before calling this command (checked in the
/// dispatch match above).
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

    let mut pubkey = [0u8; 65];
    pubkey.copy_from_slice(cmd.data);
    let before = state.pinned_peer.replace(pubkey);

    // Persist so the pin survives a reset between pinning and the exchange.
    if crate::protocol::sc_hsm::ScHsm::save_pinned_peer(state, store).is_err() {
        state.pinned_peer = before;
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    }

    ApduResponse::ok(&[])
}

// ---------------------------------------------------------------------------
// P1=0x3C  GET_GENERATION_V2
// ---------------------------------------------------------------------------

fn handle_get_generation_v2(store: &mut dyn KeyStore) -> ApduResponse {
    match crate::storage::retry_counter::lamport(store) {
        Ok(v) => ApduResponse::ok(&v.to_be_bytes()),
        Err(_) => ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE),
    }
}

// ---------------------------------------------------------------------------
// P1=0x40  DOMAIN_STATUS
// ---------------------------------------------------------------------------

/// DOMAIN_STATUS response format version.
pub const DOMAIN_STATUS_VERSION: u8 = 1;
/// DOMAIN_STATUS response length.
pub const DOMAIN_STATUS_LEN: usize = 117;
/// DOMAIN_STATUS flags: the device holds a DKEK (and so a domain key).
pub const DS_DKEK: u8 = 0x01;
/// DOMAIN_STATUS flags: OTP production mode (else development mode).
pub const DS_PRODUCTION: u8 = 0x02;
/// DOMAIN_STATUS flags: the member list holds this device's certificate.
pub const DS_SELF_MEMBER: u8 = 0x04;
/// DOMAIN_STATUS flags: a peer is pinned for the next DKEK exchange.
pub const DS_PINNED_PEER: u8 = 0x08;

/// Public domain state; no authentication (cluster plan V3 §7.4, §8).
///
/// ```text
/// [0]        version 1
/// [1]        flags (DS_*)
/// [2..18]    domain_id         zeros without a DKEK
/// [18..26]   KCV               SHA-256(DKEK)[0..8], zeros without a DKEK
/// [26..91]   Q_domain          uncompressed P-256, zeros without a DKEK
/// [91..107]  own member ID     SHA-256(device key)[0..16], zeros if none
/// [107..115] Lamport counter   u64 BE
/// [115]      member-list entries
/// [116]      member-list capacity (32)
/// ```
#[inline(never)]
fn handle_domain_status(state: &mut ScHsmState, store: &mut dyn KeyStore) -> ApduResponse {
    use crate::domain::member;

    let Ok(lamport) = crate::storage::retry_counter::lamport(store) else {
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    };
    let Ok(members) = member::count(store) else {
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    };
    let own =
        crate::protocol::sc_hsm::ScHsm::device_member_pub(store).map(|p| member::member_id(&p));

    let mut out = [0u8; DOMAIN_STATUS_LEN];
    out[0] = DOMAIN_STATUS_VERSION;
    let mut flags = 0u8;
    if let Some(domain) = state.domain.as_ref() {
        flags |= DS_DKEK;
        out[2..18].copy_from_slice(&domain.id);
        if let Ok(kcv) = state.dkek.compute_kcv() {
            out[18..26].copy_from_slice(&kcv);
        }
        out[26..91].copy_from_slice(&domain.q);
    }
    if crate::protocol::sc_hsm::commands::provisioning::production_mode() {
        flags |= DS_PRODUCTION;
    }
    if let Some(id) = own {
        out[91..107].copy_from_slice(&id);
        for slot in 0..members {
            match member::load(store, slot) {
                Ok(Some(e)) if e.cert.member_id == id => {
                    flags |= DS_SELF_MEMBER;
                    break;
                }
                Ok(_) => {}
                Err(_) => return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE),
            }
        }
    }
    if state.pinned_peer.is_some() {
        flags |= DS_PINNED_PEER;
    }
    out[1] = flags;
    out[107..115].copy_from_slice(&lamport.to_be_bytes());
    out[115] = members;
    out[116] = member::MAX_MEMBERS;
    ApduResponse::ok(&out)
}

// ---------------------------------------------------------------------------
// P1=0x47  GET_MEMBERS
// ---------------------------------------------------------------------------

/// Member-list entries per GET_MEMBERS page.
pub const MEMBERS_PER_PAGE: u8 = 16;

/// The member list, a page at a time; no authentication (certificates are
/// public and signed).  P2 = first slot.
///
/// ```text
/// [0]  total entries      [1]  first slot (= P2)     [2]  n entries here
/// n × 197-byte entries (`domain::member`: version, status,
///      revoked_lamport, certificate)
/// ```
/// The host asks again with P2 = first + n while first + n < total.
#[inline(never)]
fn handle_get_members(store: &mut dyn KeyStore, cmd: &ApduCommand<'_>) -> ApduResponse {
    use crate::domain::member;

    let Ok(total) = member::count(store) else {
        return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
    };
    let first = cmd.p2;
    if first > total {
        return ApduResponse::err(pico2hsm_core::apdu::SW_INCORRECT_P1P2);
    }
    let n = (total - first).min(MEMBERS_PER_PAGE);
    let mut resp = ApduResponse::ok(&[total, first, n]);
    for slot in first..first + n {
        let entry = match member::load(store, slot) {
            Ok(Some(e)) => e,
            _ => return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE),
        };
        if resp.data.extend_from_slice(&entry.encode()).is_err() {
            return ApduResponse::err(pico2hsm_core::apdu::SW_MEMORY_FAILURE);
        }
    }
    resp
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

    extern crate std;

    /// Test key store that holds a device identity key, optionally an EF
    /// 0x2F02, any other object, and the counter log (Lamport counter).
    struct DevKeyStore {
        dev_key: Option<KeyObject>,
        ef_key: Option<KeyObject>,
        others: std::vec::Vec<KeyObject>,
        counters: crate::storage::retry_counter::MemCounters,
        fail_saves: bool,
    }
    impl DevKeyStore {
        fn new() -> Self {
            DevKeyStore {
                dev_key: None,
                ef_key: None,
                others: std::vec::Vec::new(),
                counters: Default::default(),
                fail_saves: false,
            }
        }
        fn has(&self, kid: KeyId) -> bool {
            self.others.iter().any(|o| o.key_id == kid.0)
        }
    }
    impl KeyStore for DevKeyStore {
        fn save_key(&mut self, obj: &KeyObject) -> Result<(), pico2hsm_core::error::HsmError> {
            let dev_key_id = KeyId::sc_hsm(0, 0xFE).0;
            let ef_key_id = KeyId::sc_hsm_ef(0, 0x2F, 0x02).0;
            if self.fail_saves {
                return Err(pico2hsm_core::error::HsmError::Storage(
                    pico2hsm_core::error::StorageError::WriteError,
                ));
            }
            if obj.key_id == dev_key_id {
                self.dev_key = Some(copy_key_object(obj));
            } else if obj.key_id == ef_key_id {
                self.ef_key = Some(copy_key_object(obj));
            } else {
                self.others.retain(|o| o.key_id != obj.key_id);
                self.others.push(copy_key_object(obj));
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
            Ok(self
                .others
                .iter()
                .find(|o| o.key_id == kid.0)
                .map(copy_key_object))
        }
        fn erase_key(&mut self, kid: KeyId) -> Result<(), pico2hsm_core::error::HsmError> {
            if self.fail_saves {
                return Err(pico2hsm_core::error::HsmError::Storage(
                    pico2hsm_core::error::StorageError::WriteError,
                ));
            }
            self.others.retain(|o| o.key_id != kid.0);
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
        fn retry_counters(
            &mut self,
        ) -> Option<&mut dyn crate::storage::retry_counter::RetryCounterBackend> {
            Some(&mut self.counters)
        }
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

        // The persisted counter, not RAM.
        store.counters.lamport = 42;
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

        assert!(state.pinned_peer.is_none());
        let resp = handle(&mut state, &mut store, &cmd);
        assert_eq!(resp.sw, 0x9000, "enrollment should succeed");
        assert_eq!(state.pinned_peer.unwrap(), pubkey);
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
        assert_eq!(state.pinned_peer.unwrap(), pubkey1);

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
            state.pinned_peer.unwrap(),
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
        // Single-use pins (§5.2 step 3): spent on both sides, in RAM and
        // on flash, so a second exchange needs a new pin.
        assert!(src.pinned_peer.is_none() && tgt.pinned_peer.is_none());
        assert!(!ss.has(crate::domain::records::PINNED_PEER));
        assert!(!ts.has(crate::domain::records::PINNED_PEER));
        assert_eq!(
            extras(&mut src, &mut ss, 0x36, &init.data).sw,
            SW_CONDITIONS_NOT_SATISFIED
        );
    }

    #[test]
    fn pin_that_cannot_be_spent_keeps_the_dkek_home() {
        let ((mut src, mut ss), (mut tgt, mut ts)) = enrolled_pair();
        let (src_pub, tgt_pub) = (static_pub(&ss), static_pub(&ts));
        let init = extras(&mut tgt, &mut ts, 0x35, &src_pub);
        assert_eq!(extras(&mut src, &mut ss, 0x36, &init.data).sw, 0x9000);
        ss.fail_saves = true; // the pin's erase fails
        let send = extras(
            &mut src,
            &mut ss,
            0x37,
            &make_data(&[&init.data[..65], &tgt_pub, &init.data[65..97]]),
        );
        assert_eq!(send.sw, pico2hsm_core::apdu::SW_MEMORY_FAILURE);
        assert!(send.data.is_empty(), "no ciphertext released");
        assert!(src.pinned_peer.is_some());
    }

    #[test]
    fn pin_is_persisted_and_replaced() {
        let (mut st, mut store) = state_with_device_key();
        let a = generate_test_p256_pubkey();
        let b = generate_test_p256_pubkey();
        assert_eq!(extras(&mut st, &mut store, 0x3D, &a).sw, 0x9000);
        assert_eq!(extras(&mut st, &mut store, 0x3D, &b).sw, 0x9000);
        let mut fresh = ScHsmState::new();
        crate::protocol::sc_hsm::ScHsm::load_pinned_peer(&mut fresh, &mut store);
        assert_eq!(fresh.pinned_peer, Some(b));
    }

    #[test]
    fn legacy_peer_slot_becomes_the_pin() {
        let (_, mut store) = state_with_device_key();
        let peer = generate_test_p256_pubkey();
        let legacy = crate::protocol::sc_hsm::ScHsm::sc_hsm_peer_pubkey_key_id();
        let mut obj = KeyObject::new(
            KmType::Generic,
            legacy.0,
            AppletId::ScHsm,
            AlgorithmId::AesGcm,
        );
        obj.private_key.extend_from_slice(&peer).unwrap();
        obj.private_key.push(0).unwrap();
        store.save_key(&obj).unwrap();

        let mut st = ScHsmState::new();
        crate::protocol::sc_hsm::ScHsm::load_pinned_peer(&mut st, &mut store);
        assert_eq!(st.pinned_peer, Some(peer), "read before the move");
        assert!(!store.has(crate::domain::records::PINNED_PEER));
        crate::protocol::sc_hsm::ScHsm::migrate_domain(&st, &mut store);
        assert!(store.has(crate::domain::records::PINNED_PEER), "moved");
        assert!(!store.has(legacy), "legacy slot erased");
        let mut again = ScHsmState::new();
        crate::protocol::sc_hsm::ScHsm::load_pinned_peer(&mut again, &mut store);
        assert_eq!(again.pinned_peer, Some(peer));
    }

    #[test]
    fn spending_an_unmoved_legacy_pin_erases_it() {
        let (mut st, mut store) = state_with_device_key();
        let peer = generate_test_p256_pubkey();
        let legacy = crate::protocol::sc_hsm::ScHsm::sc_hsm_peer_pubkey_key_id();
        let mut obj = KeyObject::new(
            KmType::Generic,
            legacy.0,
            AppletId::ScHsm,
            AlgorithmId::AesGcm,
        );
        obj.private_key.extend_from_slice(&peer).unwrap();
        store.save_key(&obj).unwrap();
        crate::protocol::sc_hsm::ScHsm::load_pinned_peer(&mut st, &mut store);
        crate::protocol::sc_hsm::ScHsm::consume_pinned_peer(&mut st, &mut store).unwrap();
        assert!(!store.has(legacy));
        crate::protocol::sc_hsm::ScHsm::load_pinned_peer(&mut st, &mut store);
        assert_eq!(st.pinned_peer, None, "single use, even unmoved");
    }

    // -----------------------------------------------------------------------
    // DOMAIN_STATUS (P1=0x40) and GET_MEMBERS (P1=0x47)
    // -----------------------------------------------------------------------

    #[test]
    fn domain_status_before_and_after_the_dkek() {
        let (mut st, mut store) = state_with_device_key();
        st.pin_verified = false;
        st.so_pin_verified = false; // no authentication needed
        let own = crate::domain::member::member_id(&static_pub(&store));

        let r = extras(&mut st, &mut store, 0x40, &[]);
        assert_eq!(r.sw, 0x9000);
        assert_eq!(r.data.len(), DOMAIN_STATUS_LEN);
        assert_eq!(r.data[0], 1);
        assert_eq!(r.data[1] & DS_DKEK, 0);
        assert_eq!(&r.data[2..91], &[0u8; 89][..], "no domain yet");
        assert_eq!(&r.data[91..107], &own);
        assert_eq!(r.data[115], 0);
        assert_eq!(r.data[116], 32);

        // DKEK arrives (as persist_dkek_change does it).
        st.dkek.set_dkek_direct(&[0x5C; 32]);
        crate::protocol::sc_hsm::ScHsm::derive_domain(&mut st);
        assert!(crate::protocol::sc_hsm::ScHsm::ensure_self_member(&st, &mut store).unwrap());
        assert!(
            !crate::protocol::sc_hsm::ScHsm::ensure_self_member(&st, &mut store).unwrap(),
            "only while no list exists"
        );

        let r = extras(&mut st, &mut store, 0x40, &[]);
        assert_eq!(r.sw, 0x9000);
        let domain = crate::domain::key::DomainKey::derive(&[0x5C; 32]).unwrap();
        assert_eq!(
            r.data[1] & (DS_DKEK | DS_SELF_MEMBER),
            DS_DKEK | DS_SELF_MEMBER
        );
        assert_eq!(&r.data[2..18], &domain.id);
        assert_eq!(&r.data[18..26], &st.dkek.compute_kcv().unwrap());
        assert_eq!(&r.data[26..91], &domain.q[..]);
        assert_eq!(u64::from_be_bytes(r.data[107..115].try_into().unwrap()), 1);
        assert_eq!(r.data[115], 1);

        // The list holds a self-issued certificate that verifies.
        let m = extras(&mut st, &mut store, 0x47, &[]);
        assert_eq!(m.sw, 0x9000);
        assert_eq!(&m.data[..3], &[1, 0, 1]);
        let e = crate::domain::member::MemberEntry::decode(&m.data[3..]).unwrap();
        assert_eq!(e.status, crate::domain::member::STATUS_ACTIVE);
        assert_eq!(e.cert.member_id, own);
        assert_eq!(e.cert.sponsor_id, own);
        assert_eq!(e.cert.issued_lamport, 1);
        assert_eq!(e.cert.verify(&domain.q), Ok(()));
        assert_eq!(
            extras(&mut st, &mut store, 0x47, &[]).data.len(),
            3 + crate::domain::member::ENTRY_LEN
        );
    }

    #[test]
    fn get_members_pages() {
        let (mut st, mut store) = state_with_device_key();
        st.dkek.set_dkek_direct(&[0x33; 32]);
        crate::protocol::sc_hsm::ScHsm::derive_domain(&mut st);
        let domain = crate::domain::key::DomainKey::derive(&[0x33; 32]).unwrap();
        for i in 0..20u8 {
            let p = generate_test_p256_pubkey();
            let id = crate::domain::member::member_id(&p);
            let c = crate::domain::member::MemberCert::issue(&domain, &p, &id, u64::from(i), 1)
                .unwrap();
            crate::domain::member::upsert(
                &mut store,
                &crate::domain::member::MemberEntry::active(c),
            )
            .unwrap();
        }
        let first = ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x47,
            p2: 0,
            data: &[],
            le: None,
        };
        let r = handle(&mut st, &mut store, &first);
        assert_eq!(r.sw, 0x9000);
        assert_eq!(&r.data[..3], &[20, 0, MEMBERS_PER_PAGE]);
        assert!(r.data.len() <= crate::apdu::dispatcher::MAX_RESPONSE_DATA);
        let next = ApduCommand { p2: 16, ..first };
        let r = handle(&mut st, &mut store, &next);
        assert_eq!(&r.data[..3], &[20, 16, 4]);
        let past = ApduCommand { p2: 21, ..first };
        assert_eq!(handle(&mut st, &mut store, &past).sw, 0x6A86);
    }

    #[test]
    fn manifest_pages_past_32_keys_with_object_ids() {
        let (mut st, mut store) = state_with_device_key();
        let mut rng = crate::protocol::sc_hsm::FwRng;
        for r in 1..=100u8 {
            let pair = crate::crypto::asymmetric::generate_ec_keypair(
                CoreKeyType::EcPrivateP256,
                &mut rng,
            )
            .unwrap();
            let kid = KeyId::sc_hsm(0, r);
            let mut obj =
                KeyObject::new(KmType::Ec, kid.0, AppletId::ScHsm, AlgorithmId::EcdsaP256);
            obj.public_key.extend_from_slice(&pair.public_key).unwrap();
            store.save_key(&obj).unwrap();
            st.key_index
                .push(KeyMeta {
                    key_id: kid.0,
                    key_type: CoreKeyType::EcPrivateP256 as u8,
                    algo: 0x13,
                    key_flags: 0,
                })
                .unwrap();
        }
        let cmd = |p2: u8, data: &'static [u8]| ApduCommand {
            cla: 0x80,
            ins: INS_EXTRAS,
            p1: 0x39,
            p2,
            data,
            le: None,
        };
        let mut seen = 0usize;
        let mut p2 = 0u8;
        loop {
            let r = handle(&mut st, &mut store, &cmd(p2, &[0x02]));
            assert_eq!(r.sw, 0x9000);
            assert!(r.data.len() <= crate::apdu::dispatcher::MAX_RESPONSE_DATA);
            assert_eq!(r.data.len() % MANIFEST_V2_ENTRY, 0);
            if r.data.is_empty() {
                break;
            }
            for e in r.data.chunks(MANIFEST_V2_ENTRY) {
                seen += 1;
                assert_eq!(e[0] as usize, seen, "ascending key refs");
                assert_eq!(e[3], 20, "intrinsic ID");
                let obj = store.fetch_key(KeyId::sc_hsm(0, e[0])).unwrap().unwrap();
                assert_eq!(
                    &e[44..64],
                    &crate::crypto::symmetric::sha1(&obj.public_key[1..33])
                );
            }
            p2 = r.data[r.data.len() - MANIFEST_V2_ENTRY] + 1;
        }
        assert_eq!(seen, 100, "no 32-entry cap");
        // Legacy format: 44-byte entries, first page as large as fits.
        let r = handle(&mut st, &mut store, &cmd(0, &[]));
        assert_eq!(r.data.len(), 92 * MANIFEST_V1_ENTRY);
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
