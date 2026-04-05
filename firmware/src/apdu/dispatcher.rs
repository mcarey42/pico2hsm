//! APDU dispatcher — routes commands to the active `HsmProtocol` implementation.
//!
//! The dispatcher holds references to all registered protocol implementations.
//! On receiving a SELECT AID command (INS=0xA4, P1=0x04), it iterates the
//! registered protocols and activates the first one that returns `true` from
//! `handles_aid()`. Subsequent commands are forwarded to the active protocol
//! until the next SELECT AID.
//!
//! # Protocol priority
//! 1. SC-HSM (primary — always registered)
//! 2. PIV (stub)
//! 3. OpenPGP (stub)
//!
//! # AID routing
//! - SC-HSM AID `E8 2B 06 01 04 01 81 C3 1F 02 01` → ScHsm, returns FCI
//! - PIV AID     `A0 00 00 03 08 00 00 10 00 01 00` → Piv stub
//! - OpenPGP AID `D2 76 00 01 24 01 ...`            → OpenPgp stub
//! - Any other AID                                   → SW_FILE_NOT_FOUND

use heapless::Vec;
use pico2hsm_core::{
    apdu::{
        ApduCommand, ApduResponse, SW_CLASS_NOT_SUPPORTED, SW_FILE_NOT_FOUND,
        SW_INS_NOT_SUPPORTED, SW_OK,
    },
    protocol::HsmProtocol,
};

use crate::protocol::{
    openpgp::{OpenPgp, OPENPGP_AID_PREFIX},
    piv::{Piv, PIV_AID},
    sc_hsm::{ScHsm, SC_HSM_AID},
};

/// INS byte for SELECT (ISO 7816-4).
const INS_SELECT: u8 = 0xA4;
/// P1 value for SELECT by AID.
const P1_SELECT_BY_AID: u8 = 0x04;

/// Active protocol discriminant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ActiveProtocol {
    /// No protocol selected (pre-SELECT state).
    None,
    /// SC-HSM is the active protocol.
    ScHsm,
    /// PIV stub is the active protocol.
    Piv,
    /// OpenPGP stub is the active protocol.
    OpenPgp,
}

/// APDU dispatcher.
///
/// Holds one instance of each registered protocol and routes APDUs to
/// the currently active one. The active protocol starts as `None` until
/// a SELECT AID command is received.
pub struct Dispatcher {
    active: ActiveProtocol,
    sc_hsm: ScHsm,
    piv: Piv,
    openpgp: OpenPgp,
}

impl Dispatcher {
    /// Create a new dispatcher with all protocols initialised.
    pub fn new() -> Self {
        Dispatcher {
            active: ActiveProtocol::None,
            sc_hsm: ScHsm::new(),
            piv: Piv::new(),
            openpgp: OpenPgp::new(),
        }
    }

    /// Load all persisted keys from flash into the in-memory key cache.
    ///
    /// Called at session start and on USB reconnect (new Dispatcher).
    pub fn load_keys_from_store(&mut self, store: &mut dyn crate::storage::KeyStore) {
        let ids = store.enumerate_keys();
        let mut loaded = 0usize;
        for kid in ids.iter() {
            match store.fetch_key(*kid) {
                Ok(Some(obj)) => {
                    push_key_object_to_state(&mut self.sc_hsm.state, obj);
                    loaded += 1;
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }
        let _ = loaded;
    }

    /// Dispatch a raw APDU byte slice with access to persistent storage.
    ///
    /// For key-mutating commands (INITIALIZE, GENERATE KEY PAIR, DELETE FILE)
    /// routes through the storage-aware path.  All other commands (and all
    /// non-ScHsm APDUs) fall through to the stateless `dispatch()`.
    pub fn dispatch_with_store(
        &mut self,
        raw_apdu: &[u8],
        store: &mut dyn crate::storage::KeyStore,
    ) -> Vec<u8, 4098> {
        // Parse the APDU
        let cmd = match pico2hsm_core::apdu::ApduCommand::parse(raw_apdu) {
            Ok(c) => c,
            Err(_) => {
                return pico2hsm_core::apdu::ApduResponse::err(
                    pico2hsm_core::apdu::SW_INS_NOT_SUPPORTED,
                )
                .serialize()
            }
        };

        // Intercept SELECT by AID before forwarding.
        if cmd.ins == INS_SELECT && cmd.p1 == P1_SELECT_BY_AID {
            let resp = self.select_aid(cmd.data);
            return resp.serialize();
        }

        // For the active ScHsm protocol use the storage-aware path.
        // All other protocols (Piv, OpenPgp) are stateless and use the
        // existing path.
        let raw_resp: Vec<u8, 4096> = match self.active {
            ActiveProtocol::ScHsm => self.sc_hsm.process_apdu_with_store(raw_apdu, store),
            ActiveProtocol::Piv => self.piv.process_apdu(raw_apdu),
            ActiveProtocol::OpenPgp => self.openpgp.process_apdu(raw_apdu),
            ActiveProtocol::None => {
                return pico2hsm_core::apdu::ApduResponse::err(
                    pico2hsm_core::apdu::SW_INS_NOT_SUPPORTED,
                )
                .serialize()
            }
        };

        let mut out: Vec<u8, 4098> = Vec::new();
        let _ = out.extend_from_slice(&raw_resp);
        out
    }

    /// Dispatch a raw APDU byte slice.
    ///
    /// Handles SELECT AID (INS=0xA4, P1=0x04) by switching the active
    /// protocol. All other commands are forwarded to the active protocol.
    ///
    /// Returns the serialized response bytes (data + SW1 + SW2).
    pub fn dispatch(&mut self, raw_apdu: &[u8]) -> Vec<u8, 4098> {
        // Parse the APDU
        let cmd = match ApduCommand::parse(raw_apdu) {
            Ok(c) => c,
            Err(_) => return ApduResponse::err(SW_INS_NOT_SUPPORTED).serialize(),
        };

        // Intercept SELECT by AID before forwarding to the active protocol.
        if cmd.ins == INS_SELECT && cmd.p1 == P1_SELECT_BY_AID {
            let resp = self.select_aid(cmd.data);
            return resp.serialize();
        }

        // Forward to the active protocol.
        let raw_resp: Vec<u8, 4096> = match self.active {
            ActiveProtocol::ScHsm => self.sc_hsm.process_apdu(raw_apdu),
            ActiveProtocol::Piv => self.piv.process_apdu(raw_apdu),
            ActiveProtocol::OpenPgp => self.openpgp.process_apdu(raw_apdu),
            ActiveProtocol::None => {
                // No AID selected yet — return INS not supported
                return ApduResponse::err(SW_INS_NOT_SUPPORTED).serialize();
            }
        };

        // Convert 4096-byte Vec to 4098-byte Vec (add room for SW if needed).
        let mut out: Vec<u8, 4098> = Vec::new();
        let _ = out.extend_from_slice(&raw_resp);
        out
    }

    /// Route a SELECT-by-AID command and return the appropriate FCI response.
    fn select_aid(&mut self, aid: &[u8]) -> ApduResponse {
        // SC-HSM AID
        if aid == SC_HSM_AID {
            self.active = ActiveProtocol::ScHsm;
            return build_sc_hsm_fci();
        }

        // PIV AID
        if aid == PIV_AID {
            self.active = ActiveProtocol::Piv;
            return ApduResponse::ok(&[]);
        }

        // OpenPGP AID (prefix match)
        if aid.len() >= OPENPGP_AID_PREFIX.len()
            && &aid[..OPENPGP_AID_PREFIX.len()] == OPENPGP_AID_PREFIX
        {
            self.active = ActiveProtocol::OpenPgp;
            return ApduResponse::ok(&[]);
        }

        // Unknown AID
        ApduResponse::err(SW_FILE_NOT_FOUND)
    }
}

// ─── Key loader helpers ───────────────────────────────────────────────────────

/// Map a `security::key_management::AlgorithmId` to the `pico2hsm_core` `CoreKeyType`
/// used by `InMemoryKey.key_type`.
fn km_algo_to_core_key_type(
    algo: crate::security::key_management::AlgorithmId,
) -> pico2hsm_core::key::KeyType {
    use crate::security::key_management::AlgorithmId;
    use pico2hsm_core::key::KeyType as CoreKeyType;
    match algo {
        AlgorithmId::EcdsaP256 | AlgorithmId::EcdhP256 => CoreKeyType::EcPrivateP256,
        AlgorithmId::EcdsaP384 | AlgorithmId::EcdhP384 => CoreKeyType::EcPrivateP384,
        AlgorithmId::EcdsaP521 | AlgorithmId::EcdhP521 => CoreKeyType::EcPrivateP521,
        AlgorithmId::EcdsaK256 => CoreKeyType::EcPrivateK256,
        AlgorithmId::EcdsaBrainpool256 => CoreKeyType::EcPrivateBrainpoolP256,
        AlgorithmId::EcdsaBrainpool384 => CoreKeyType::EcPrivateBrainpoolP384,
        AlgorithmId::EcdsaBrainpool512 => CoreKeyType::EcPrivateBrainpoolP512,
        AlgorithmId::RsaPkcs1Sha256
        | AlgorithmId::RsaPkcs1Sha384
        | AlgorithmId::RsaPkcs1Sha512
        | AlgorithmId::RsaPss
        | AlgorithmId::RsaDecrypt => CoreKeyType::RsaPrivate2048,
        AlgorithmId::AesEcb
        | AlgorithmId::AesCbc
        | AlgorithmId::AesCtr
        | AlgorithmId::AesGcm => CoreKeyType::Aes256,
    }
}

/// Convert a `KeyObject` (security layer) to an `InMemoryKey` (protocol layer)
/// and push it into `ScHsmState`, honouring the slot limits.
///
/// RSA keys are partially reconstructed: the PKCS#1 DER is placed back in
/// `RsaInMemoryKey.private_key_der`, and the modulus / exponent are extracted
/// from the stored `public_key` blob (layout: `[2 BE mod_len] || modulus || exponent`).
fn push_key_object_to_state(
    state: &mut crate::protocol::sc_hsm::ScHsmState,
    obj: crate::security::key_management::KeyObject,
) {
    use crate::security::key_management::KeyType as KmKeyType;
    use crate::protocol::sc_hsm::{InMemoryKey, MAX_IN_MEMORY_KEYS};

    let is_rsa = matches!(obj.key_type, KmKeyType::Rsa);

    #[cfg(feature = "rsa")]
    if is_rsa {
        use crate::protocol::sc_hsm::{RsaInMemoryKey, MAX_RSA_IN_MEMORY_KEYS};
        if state.rsa_keys.len() >= MAX_RSA_IN_MEMORY_KEYS {
            #[cfg(target_arch = "arm")]
            defmt::warn!("MAX_RSA_IN_MEMORY_KEYS reached, key {} not loaded", obj.key_id);
            return;
        }

        // Reconstruct modulus and exponent from the stored public_key blob.
        // Layout written by generate_keypair: [2-byte mod_len BE] || modulus || exponent
        let (modulus_bytes, exponent_bytes) = if obj.public_key.len() >= 2 {
            let mod_len = ((obj.public_key[0] as usize) << 8) | (obj.public_key[1] as usize);
            let rest = &obj.public_key[2..];
            if rest.len() >= mod_len {
                (&rest[..mod_len], &rest[mod_len..])
            } else {
                #[cfg(target_arch = "arm")]
                defmt::warn!("RSA key {} public_key blob malformed, skipping", obj.key_id);
                return;
            }
        } else {
            #[cfg(target_arch = "arm")]
            defmt::warn!("RSA key {} missing public_key blob, skipping", obj.key_id);
            return;
        };

        let core_key_type = km_algo_to_core_key_type(obj.algorithm);
        let algo = obj.algorithm as u8;

        let mut entry = RsaInMemoryKey {
            key_id: obj.key_id,
            key_type: core_key_type,
            algo,
            private_key_der: heapless::Vec::new(),
            modulus: heapless::Vec::new(),
            exponent: heapless::Vec::new(),
        };
        let _ = entry.private_key_der.extend_from_slice(&obj.private_key);
        let _ = entry.modulus.extend_from_slice(modulus_bytes);
        let _ = entry.exponent.extend_from_slice(exponent_bytes);
        let _ = state.rsa_keys.push(entry);
        return;
    }

    // For non-rsa feature flag builds, suppress the unused variable warning.
    #[cfg(not(feature = "rsa"))]
    let _ = is_rsa;

    // EC / symmetric key
    if state.keys.len() >= MAX_IN_MEMORY_KEYS {
        #[cfg(target_arch = "arm")]
        defmt::warn!("MAX_IN_MEMORY_KEYS reached, key {} not loaded", obj.key_id);
        return;
    }

    let algo = obj.algorithm as u8;
    let core_key_type = km_algo_to_core_key_type(obj.algorithm);

    let mut entry = InMemoryKey {
        key_id: obj.key_id,
        key_type: core_key_type,
        algo,
        private_key: heapless::Vec::new(),
        public_key: heapless::Vec::new(),
    };
    let _ = entry.private_key.extend_from_slice(&obj.private_key);
    let _ = entry.public_key.extend_from_slice(&obj.public_key);
    let _ = state.keys.push(entry);
}

/// Build the FCI (File Control Information) template returned on SELECT SC-HSM AID.
///
/// Structure matches a real SmartCard-HSM 2 SELECT response so that OpenSC's
/// `iso7816_select_file` accepts it (it requires the outer tag to be 0x6F):
///
/// ```text
/// 6F 16          FCI template (ISO 7816-4 §7.1.1)
///   84 0B [AID]  DF name (tag 0x84 = DF name in FCI context)
///   A5 07        Proprietary information
///     9F 6E 04 [4 bytes]  COS/HW version (SmartCard-HSM convention)
/// ```
fn build_sc_hsm_fci() -> ApduResponse {
    let aid: &[u8] = SC_HSM_AID; // 11 bytes
    // 4 version bytes: [cwa_major, cwa_minor, hw_major, hw_minor]
    let version: &[u8] = &[0x20, 0x00, 0x00, 0x00];

    // A5 inner: 9F 6E 04 + 4 bytes = 7 bytes
    let a5_inner_len: u8 = 2 + 1 + version.len() as u8; // tag(2) + len(1) + data(4) = 7
    // 6F inner: 84 TLV (13 bytes) + A5 TLV (2+7 = 9 bytes) = 22 bytes
    let outer_len: u8 = (2 + aid.len() as u8) + (2 + a5_inner_len);

    let mut fci: Vec<u8, 32> = Vec::new();
    let _ = fci.push(0x6F);
    let _ = fci.push(outer_len);

    // 84: DF name (AID)
    let _ = fci.push(0x84);
    let _ = fci.push(aid.len() as u8);
    let _ = fci.extend_from_slice(aid);

    // A5: proprietary — contains 9F6E version TLV
    let _ = fci.push(0xA5);
    let _ = fci.push(a5_inner_len);
    let _ = fci.push(0x9F);
    let _ = fci.push(0x6E);
    let _ = fci.push(version.len() as u8);
    let _ = fci.extend_from_slice(version);

    ApduResponse::ok(&fci)
}
