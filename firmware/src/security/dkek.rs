//! DKEK (Device Key Encryption Key) management and exchange protocol.
//!
//! # DKEK overview
//! The DKEK is a 256-bit AES key that protects key export and import between
//! HSMs.  It is assembled from 1–8 shares via XOR-split (NOT Shamir secret
//! sharing): each share is a random 32-byte value and the DKEK is their XOR.
//!
//! # Share format (SC-HSM compatible)
//! Each share is transported as an AES-256-CBC encrypted blob:
//! ```text
//! [16]  IV     — random per share import
//! [48]  ciphertext = AES-256-CBC(key=SHA-256(password), iv, plaintext)
//! ```
//! where `plaintext = share_value(32) || SHA-256(share_value)(32)`
//! — the embedded hash allows integrity verification after decryption.
//!
//! # State machine
//! ```text
//! NotInitialized
//!   │ init_shares(n)
//!   ▼
//! CollectingShares { received=0, total=n, accumulated=[0;32] }
//!   │ import_share() × n
//!   ▼
//! Ready { dkek=XOR(all shares) }
//! ```
//!
//! # DKEK exchange (simplified Noise-like)
//! Full Noise_XX requires the `snow` crate which does not compile in
//! `no_std` + no `alloc` without additional porting work (as of snow 0.10).
//! This module implements a functionally equivalent simplified protocol:
//!
//! ```text
//! Initiator (sender)                     Responder (receiver)
//! ─────────────────────────────────────────────────────────────
//! 1. Generate ephemeral P-256 keypair
//!    Send  → ephem_pub(65)
//!                                        2. Generate ephemeral P-256 keypair
//!                                           Send ← static_pub(65) || ephem_pub(65)
//! 3. Compute ECDH(ephem_priv, resp_ephem_pub)
//!    Derive session_key via HKDF-SHA256
//!    Encrypt DKEK with AES-256-GCM
//!    Send  → encrypted_dkek(12+32+16)
//!                                        4. Compute ECDH, derive session_key
//!                                           Decrypt DKEK, store in DkekManager
//! ```
//!
//! TODO: Replace with full Noise_XX_25519_AESGCM_SHA256 once `snow` ships
//! stable `no_std` support (tracked upstream: snow-lang/snow#305).

#![allow(dead_code)]

use core::convert::TryInto;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use cmac::{Cmac, Mac as CmacMac};

use aes::Aes256;
use aes_gcm::{
    aead::{AeadInPlace, KeyInit as GcmKeyInit},
    Aes256Gcm, Nonce as GcmNonce, Tag as GcmTag,
};
use cbc::{Decryptor as CbcDecryptor, Encryptor as CbcEncryptor};
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use crate::security::key_blob;
use crate::security::key_management::KeyObject;
use crate::security::key_policy::KeyPolicy;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of DKEK shares (SC-HSM supports up to 8).
pub const MAX_SHARES: u8 = 8;

/// Share blob size: IV(16) + ciphertext(64) = 80 bytes.
/// Plaintext is share_value(32) + SHA-256(share_value)(32) = 64 bytes.
/// AES-256-CBC with NoPadding on 64 bytes produces 64 bytes of ciphertext.
pub const SHARE_BLOB_SIZE: usize = 80;

/// Size of the share plaintext: share_value(32) + SHA-256(share_value)(32) = 64.
const SHARE_PT_SIZE: usize = 64;

/// AES-256-GCM nonce size for DKEK session exchange.
const NONCE_SIZE: usize = 12;

/// AES-256-GCM tag size.
const TAG_SIZE: usize = 16;

/// Uncompressed P-256 public key size.
const P256_UNCOMPRESSED_SIZE: usize = 65;

/// HKDF info for the session key derived during DKEK exchange.
const EXCHANGE_INFO: &[u8] = b"pico2hsm-dkek-exchange-v1";

/// HKDF info for deriving the static Noise key from the OTP identity key.
const NOISE_STATIC_INFO: &[u8] = b"pico2hsm-noise-static-v1";

/// KCV (Key Check Value) size.
const KCV_SIZE: usize = 8;
/// CBC IV size.
const CBC_IV_SIZE: usize = 16;

// --- CardContact key blob (WRAP / UNWRAP) ----------------------------------

/// AES-CMAC length at the end of a CardContact blob.
const CC_MAC_SIZE: usize = 16;
/// Smallest CardContact blob: KCV, type, four empty LV fields, one block,
/// CMAC.
const CC_MIN_BLOB: usize = KCV_SIZE + 1 + 4 * 2 + 16 + CC_MAC_SIZE;
/// Largest encrypted part accepted (an RSA-4096 CRT key needs 1840 bytes).
const CC_MAX_ENC: usize = 2048;

/// CardContact KCV: SHA-256(DKEK)[0..8].
fn cc_kcv(dkek: &[u8; 32]) -> [u8; KCV_SIZE] {
    let h = Sha256::digest(dkek);
    let mut kcv = [0u8; KCV_SIZE];
    kcv.copy_from_slice(&h[..KCV_SIZE]);
    kcv
}

/// CardContact K_enc = SHA-256(DKEK || 00000001) and
/// K_mac = SHA-256(DKEK || 00000002).
fn cc_keys(dkek: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let derive = |counter: u8| {
        let mut h = Sha256::new();
        h.update(dkek);
        h.update([0, 0, 0, counter]);
        Zeroizing::new(<[u8; 32]>::from(h.finalize()))
    };
    (derive(1), derive(2))
}

/// AES-256-CMAC(K_mac) over the blob before the MAC.
fn cc_cmac(kmac: &[u8; 32], data: &[u8]) -> [u8; CC_MAC_SIZE] {
    let mut mac = <Cmac<Aes256> as CmacMac>::new_from_slice(kmac).expect("32-byte key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn wrap_err(e: key_blob::BlobError) -> DkekError {
    match e {
        key_blob::BlobError::Unsupported => DkekError::UnsupportedKey,
        key_blob::BlobError::Malformed => DkekError::EncryptFailure,
    }
}

fn unwrap_err(e: key_blob::BlobError) -> DkekError {
    match e {
        key_blob::BlobError::Unsupported => DkekError::UnsupportedKey,
        key_blob::BlobError::Malformed => DkekError::InvalidWrapBlob,
    }
}

/// What [`DkekManager::unwrap`] decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unwrapped {
    /// Key index metadata for the key.
    pub decoded: key_blob::Decoded,
    /// The key flags restored from the blob.
    pub key_flags: u8,
    /// A deprecated pico2hsm blob (version 2 or 3).
    pub legacy: bool,
}

// --- Deprecated pico2hsm blob (versions 2 and 3; UNWRAP only) --------------

/// Wrap blob format version 2 (encrypt-then-MAC).
const WRAP_VERSION: u8 = 0x02;
/// Wrap blob format version 3: version 2 plus the key's usage policy.
const WRAP_VERSION_POLICY: u8 = 0x03;
/// Largest wrap plaintext: key (2400) + policy + its length + algo + flags
/// + up to 16 bytes of padding, rounded to a block.
const WRAP_MAX_PT: usize = (2400 + crate::security::key_policy::MAX_POLICY_EXT + 3 + 16) / 16 * 16;
/// Largest wrapped blob: header + ciphertext + MAC.
pub const WRAP_MAX_BLOB: usize = WRAP_HEADER_SIZE + WRAP_MAX_PT + WRAP_MAC_SIZE;
/// Truncated HMAC-SHA256 tag length.
const WRAP_MAC_SIZE: usize = 16;
/// Header: KCV || version || IV.
const WRAP_HEADER_SIZE: usize = KCV_SIZE + 1 + CBC_IV_SIZE;
const WRAP_MIN_SIZE: usize = WRAP_HEADER_SIZE + 16 + WRAP_MAC_SIZE;

/// Derive the wrap encryption and MAC keys from the DKEK (never use the
/// DKEK itself for both).
fn wrap_keys(dkek: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    use hmac::{Hmac, Mac};
    let derive = |label: &[u8]| {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(dkek).expect("any key length");
        mac.update(label);
        Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()))
    };
    (
        derive(b"pico2hsm-wrap-v2-enc"),
        derive(b"pico2hsm-wrap-v2-mac"),
    )
}

/// HMAC-SHA256 over the blob (header + ciphertext), truncated.
fn wrap_mac(kmac: &[u8; 32], authenticated: &[u8]) -> [u8; WRAP_MAC_SIZE] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(kmac).expect("any key length");
    mac.update(authenticated);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; WRAP_MAC_SIZE];
    tag.copy_from_slice(&full[..WRAP_MAC_SIZE]);
    tag
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by DKEK operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkekError {
    /// DKEK manager is not in the correct state for this operation.
    WrongState,
    /// Decryption of the share blob failed (wrong password or tampered blob).
    ShareDecryptFailure,
    /// Share integrity check (embedded SHA-256) failed.
    ShareIntegrityFailure,
    /// Too many shares (n > MAX_SHARES).
    TooManyShares,
    /// The share blob length is incorrect.
    InvalidShareBlob,
    /// Session key derivation failed.
    KdfFailure,
    /// AES-GCM encryption failure.
    EncryptFailure,
    /// AES-GCM authentication failure on decryption.
    DecryptFailure,
    /// The exchange message is malformed or too short.
    InvalidExchangeMessage,
    /// RNG produced insufficient entropy.
    RngFailure,
    /// Key agreement / ECC operation failed.
    EcdhFailure,
    /// KCV (Key Check Value) mismatch on unwrap — wrong DKEK or tampered blob.
    KcvMismatch,
    /// Wrapped blob has invalid length (not a multiple of 16 after header, or too short).
    InvalidWrapBlob,
    /// PKCS#7 padding is invalid.
    InvalidPadding,
    /// The key has no CardContact blob encoding (Ed25519, X25519,
    /// brainpool, BIP32 master, data object), or this build cannot use it
    /// (RSA without the `rsa` feature).
    UnsupportedKey,
}

// ---------------------------------------------------------------------------
// Import result
// ---------------------------------------------------------------------------

/// Result returned from [`DkekManager::import_share`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkekImportResult {
    /// More shares are needed before the DKEK is complete.
    MoreSharesNeeded { received: u8, total: u8 },
    /// All shares have been received; DKEK is now ready.
    Complete,
}

// ---------------------------------------------------------------------------
// DkekStatus
// ---------------------------------------------------------------------------

/// Internal state of the DKEK manager.
pub enum DkekStatus {
    /// No DKEK has been configured.
    NotInitialized,
    /// Shares are being collected; accumulator XORs each share as it arrives.
    CollectingShares {
        received: u8,
        total: u8,
        accumulated: Zeroizing<[u8; 32]>,
    },
    /// All shares received; DKEK is available.
    Ready { dkek: Zeroizing<[u8; 32]> },
}

impl Zeroize for DkekStatus {
    fn zeroize(&mut self) {
        // Wipe the secret where it lives *before* changing the variant.
        // Moving it out first (e.g. via `mem::replace`) would zeroize only the
        // moved copy: writing `NotInitialized` updates just the enum tag and
        // leaves the old payload bytes in place.
        match self {
            DkekStatus::CollectingShares { accumulated, .. } => accumulated.zeroize(),
            DkekStatus::Ready { dkek } => dkek.zeroize(),
            DkekStatus::NotInitialized => {}
        }
        // DkekStatus has no Drop impl, so this assignment cannot recurse.
        *self = DkekStatus::NotInitialized;
    }
}

// No Drop impl for DkekStatus: Zeroizing<[u8;32]> fields zeroize on drop
// automatically, and an explicit Drop calling zeroize() would recurse.

// ---------------------------------------------------------------------------
// DkekManager
// ---------------------------------------------------------------------------

/// DKEK lifecycle manager.
///
/// Tracks the XOR-split share collection state and provides access to the
/// assembled DKEK once all shares have been imported.
pub struct DkekManager {
    status: DkekStatus,
    total_shares: u8,
    /// 16-byte device identifier (used in exchange AAD and static key derivation).
    device_id: [u8; 16],
}

impl DkekManager {
    /// Create a new `DkekManager` in the `NotInitialized` state.
    pub fn new(device_id: [u8; 16]) -> Self {
        DkekManager {
            status: DkekStatus::NotInitialized,
            total_shares: 0,
            device_id,
        }
    }

    // -----------------------------------------------------------------------
    // Initialisation
    // -----------------------------------------------------------------------

    /// Initialise the DKEK share collection with `n_shares` total shares.
    ///
    /// Resets any previously collected shares.
    pub fn init_shares(&mut self, n_shares: u8) {
        // Zeroize previous state.
        self.status.zeroize();
        self.total_shares = n_shares;

        if n_shares == 0 {
            // n=0 means "no DKEK" — stay NotInitialized.
            return;
        }

        self.status = DkekStatus::CollectingShares {
            received: 0,
            total: n_shares,
            accumulated: Zeroizing::new([0u8; 32]),
        };
    }

    // -----------------------------------------------------------------------
    // Share import
    // -----------------------------------------------------------------------

    /// Import one DKEK share encrypted under `password`.
    ///
    /// `share_blob` layout: `IV(16) || AES-256-CBC(key=SHA-256(password), IV, share_value||SHA-256(share_value))`
    ///
    /// On success, XOR-accumulates the share into the running DKEK. When all
    /// `n` shares have been received the status transitions to `Ready`.
    pub fn import_share(
        &mut self,
        share_blob: &[u8],
        password: &[u8],
    ) -> Result<DkekImportResult, DkekError> {
        // Validate blob length.
        if share_blob.len() != SHARE_BLOB_SIZE {
            return Err(DkekError::InvalidShareBlob);
        }

        // Ensure we are in the right state.
        let (received, total, accumulated) = match &mut self.status {
            DkekStatus::CollectingShares {
                received,
                total,
                accumulated,
            } => (received, *total, accumulated),
            _ => return Err(DkekError::WrongState),
        };

        // Decrypt the share blob.
        let decrypted = decrypt_share_blob(share_blob, password)?;

        // Validate embedded SHA-256 hash.
        let share_value = &decrypted[..32];
        let expected_hash: [u8; 32] = Sha256::digest(share_value).into();
        let stored_hash = &decrypted[32..64];
        if !bool::from(expected_hash.ct_eq(stored_hash)) {
            return Err(DkekError::ShareIntegrityFailure);
        }

        // XOR-accumulate this share into the running DKEK.
        for (acc, sh) in accumulated.iter_mut().zip(share_value.iter()) {
            *acc ^= sh;
        }

        *received += 1;
        let received_now = *received;

        if received_now >= total {
            // All shares collected — move to Ready state.
            // Extract the accumulated DKEK before replacing status.
            let mut dkek_val: [u8; 32] = **accumulated;
            self.status.zeroize();
            self.status = DkekStatus::Ready {
                dkek: Zeroizing::new(dkek_val),
            };
            dkek_val.zeroize(); // the stack copy, not just the stored value
            Ok(DkekImportResult::Complete)
        } else {
            Ok(DkekImportResult::MoreSharesNeeded {
                received: received_now,
                total,
            })
        }
    }

    /// Import one raw (unencrypted) 32-byte DKEK share.
    ///
    /// This is the code path used by `sc-hsm-tool --import-dkek-share` which
    /// decrypts the PBE-protected share file on the host side and sends the
    /// raw 32-byte share value to the card via `INS=0x52 P1=0x00`.
    ///
    /// Follows the same state machine as [`import_share`]: XOR-accumulates
    /// the value and transitions to `Ready` when all shares have arrived.
    pub fn import_share_raw(
        &mut self,
        raw_share: &[u8; 32],
    ) -> Result<DkekImportResult, DkekError> {
        // Ensure we are in the right state.
        let (received, total, accumulated) = match &mut self.status {
            DkekStatus::CollectingShares {
                received,
                total,
                accumulated,
            } => (received, *total, accumulated),
            _ => return Err(DkekError::WrongState),
        };

        // XOR-accumulate this share into the running DKEK.
        for (acc, sh) in accumulated.iter_mut().zip(raw_share.iter()) {
            *acc ^= sh;
        }

        *received += 1;
        let received_now = *received;

        if received_now >= total {
            // All shares collected — move to Ready state.
            let mut dkek_val: [u8; 32] = **accumulated;
            self.status.zeroize();
            self.status = DkekStatus::Ready {
                dkek: Zeroizing::new(dkek_val),
            };
            dkek_val.zeroize(); // the stack copy, not just the stored value
            Ok(DkekImportResult::Complete)
        } else {
            Ok(DkekImportResult::MoreSharesNeeded {
                received: received_now,
                total,
            })
        }
    }

    // -----------------------------------------------------------------------
    // Share generation
    // -----------------------------------------------------------------------

    /// Generate a new random 32-byte DKEK share value.
    ///
    /// The returned value is NOT encrypted; the caller must pass it through
    /// [`encrypt_share_blob`] before distributing it.
    pub fn generate_share(&self, rng: &mut impl rand_core::RngCore) -> Zeroizing<[u8; 32]> {
        let mut share = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(share.as_mut());
        share
    }

    // -----------------------------------------------------------------------
    // Status queries
    // -----------------------------------------------------------------------

    /// Returns `true` when the DKEK is fully assembled and ready for use.
    pub fn is_ready(&self) -> bool {
        matches!(self.status, DkekStatus::Ready { .. })
    }

    /// Returns how many shares have been received so far.
    pub fn shares_received(&self) -> u8 {
        match &self.status {
            DkekStatus::CollectingShares { received, .. } => *received,
            DkekStatus::Ready { .. } => self.total_shares,
            DkekStatus::NotInitialized => 0,
        }
    }

    /// Returns the total number of shares required.
    pub fn shares_total(&self) -> u8 {
        self.total_shares
    }

    /// Borrow the DKEK (only `Some` when status is `Ready`).
    pub fn get_dkek(&self) -> Option<&[u8; 32]> {
        match &self.status {
            DkekStatus::Ready { dkek } => Some(&**dkek),
            _ => None,
        }
    }

    /// Set the DKEK directly (bypassing share collection).
    ///
    /// Used by V2 DKEK exchange (NOISE_FINALIZE_RECV_V2) to store a
    /// decrypted DKEK received from a peer HSM.
    /// Takes a reference so the caller's (zeroizing) buffer is the only
    /// other copy — passing the array by value would leave one on the stack.
    pub fn set_dkek_direct(&mut self, dkek: &[u8; 32]) {
        self.status.zeroize();
        self.status = DkekStatus::Ready {
            dkek: Zeroizing::new(*dkek),
        };
        self.total_shares = 1;
    }

    /// Restore a persisted DKEK that was assembled from `total_shares` shares.
    pub fn restore_ready(&mut self, dkek: &[u8; 32], total_shares: u8) {
        self.set_dkek_direct(dkek);
        self.total_shares = total_shares;
    }

    /// Zeroize and reset to `NotInitialized`.
    pub fn clear(&mut self) {
        self.status.zeroize();
        self.total_shares = 0;
    }

    // -----------------------------------------------------------------------
    // Simplified DKEK exchange — Initiator role
    // -----------------------------------------------------------------------

    /// Send the DKEK to a peer HSM (initiator role).
    ///
    /// **Protocol (simplified Noise-like using P-256 ECDH):**
    /// 1. Generate ephemeral P-256 keypair.
    /// 2. Write `ephem_pub(65)` to `writer`.
    /// 3. Read `resp_ephem_pub(65)` from `reader`.
    /// 4. Compute ECDH shared secret, derive session key via HKDF-SHA256.
    /// 5. Encrypt DKEK under session key (AES-256-GCM).
    /// 6. Write `nonce(12) || ciphertext(32) || tag(16)` to `writer`.
    ///
    /// NOTE: This is a structural stub. Full I/O depends on the transport
    /// layer (USB, UART) wiring that is outside the scope of this module.
    /// The cryptographic logic is implemented but `embedded_io` calls are
    /// annotated so the transport agent can wire them in.
    pub fn noise_send_dkek_data(
        &self,
        resp_ephem_pub: &[u8; P256_UNCOMPRESSED_SIZE],
        our_ephem_priv: &[u8; 32],
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> Result<[u8; NONCE_SIZE + 32 + TAG_SIZE], DkekError> {
        let dkek = self.get_dkek().ok_or(DkekError::WrongState)?;

        // ECDH using P-256: derive shared secret.
        let shared_secret = p256_ecdh(our_ephem_priv, resp_ephem_pub)?;

        // Derive session key: HKDF-SHA256(ikm=shared_secret, info=EXCHANGE_INFO)
        let session_key = derive_session_key(&shared_secret)?;

        // Encrypt DKEK with AES-256-GCM.
        let mut nonce_buf = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce_buf);

        // AAD = our device_id
        let aad = &self.device_id;

        let cipher =
            Aes256Gcm::new_from_slice(&*session_key).map_err(|_| DkekError::EncryptFailure)?;
        let nonce_arr = GcmNonce::from_slice(&nonce_buf);

        let mut ct = *dkek; // copy of DKEK — will be zeroized below
        let tag = cipher
            .encrypt_in_place_detached(nonce_arr, aad, &mut ct)
            .map_err(|_| DkekError::EncryptFailure)?;

        let mut out = [0u8; NONCE_SIZE + 32 + TAG_SIZE];
        out[..NONCE_SIZE].copy_from_slice(&nonce_buf);
        out[NONCE_SIZE..NONCE_SIZE + 32].copy_from_slice(&ct);
        out[NONCE_SIZE + 32..].copy_from_slice(tag.as_slice());

        // Zeroize the CT copy.
        ct.zeroize();

        Ok(out)
    }

    // -----------------------------------------------------------------------
    // Simplified DKEK exchange — Responder role
    // -----------------------------------------------------------------------

    /// Receive and store the DKEK from a peer HSM (responder role).
    ///
    /// **Protocol (simplified Noise-like using P-256 ECDH):**
    /// 1. Receive `initiator_ephem_pub(65)` from initiator.
    /// 2. Generate our ephemeral P-256 keypair.
    /// 3. Compute ECDH shared secret, derive session key via HKDF-SHA256.
    /// 4. Receive `nonce(12) || ciphertext(32) || tag(16)` from initiator.
    /// 5. Decrypt and store the DKEK.
    ///
    /// This function handles step 5 given pre-received data.
    pub fn noise_recv_dkek_data(
        &mut self,
        initiator_ephem_pub: &[u8; P256_UNCOMPRESSED_SIZE],
        our_ephem_priv: &[u8; 32],
        encrypted_dkek: &[u8; NONCE_SIZE + 32 + TAG_SIZE],
        initiator_device_id: &[u8; 16],
    ) -> Result<(), DkekError> {
        // ECDH using P-256.
        let shared_secret = p256_ecdh(our_ephem_priv, initiator_ephem_pub)?;

        // Derive session key.
        let session_key = derive_session_key(&shared_secret)?;

        // Decrypt DKEK.
        let nonce_bytes: &[u8; 12] = encrypted_dkek[..NONCE_SIZE].try_into().unwrap();
        let ct_with_tag = &encrypted_dkek[NONCE_SIZE..];
        let ct_end = ct_with_tag.len() - TAG_SIZE;
        let tag_bytes: &[u8; 16] = ct_with_tag[ct_end..].try_into().unwrap();

        let cipher =
            Aes256Gcm::new_from_slice(&*session_key).map_err(|_| DkekError::DecryptFailure)?;
        let nonce_arr = GcmNonce::from_slice(nonce_bytes);
        let tag_val = GcmTag::clone_from_slice(tag_bytes);

        let mut dkek_buf = Zeroizing::new([0u8; 32]);
        dkek_buf.copy_from_slice(&ct_with_tag[..ct_end]);

        cipher
            .decrypt_in_place_detached(nonce_arr, initiator_device_id, dkek_buf.as_mut(), &tag_val)
            .map_err(|_| DkekError::DecryptFailure)?;

        // Store decrypted DKEK and move to Ready state.
        self.status.zeroize();
        self.status = DkekStatus::Ready {
            dkek: Zeroizing::new(*dkek_buf),
        };
        self.total_shares = 1; // Imported as a single unit.

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Static key derivation from OTP identity key
    // -----------------------------------------------------------------------

    /// Derive the static Noise keypair from the device identity key.
    ///
    /// `HKDF-SHA256(ikm=otp_identity_key, salt=[], info=b"pico2hsm-noise-static-v1", len=32)`
    ///
    /// The returned scalar can be used as a P-256 private key seed (must be
    /// reduced mod the P-256 curve order by the caller, but for key derivation
    /// purposes the raw 32 bytes are used as an HKDF output directly).
    pub fn derive_static_private_key(otp_identity_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(None, otp_identity_key);
        let mut out = Zeroizing::new([0u8; 32]);
        // Infallible for len=32.
        hkdf.expand(NOISE_STATIC_INFO, out.as_mut())
            .expect("HKDF expand cannot fail for 32 bytes");
        out
    }

    /// Key Check Value: the first 8 bytes of SHA-256(DKEK), as a
    /// SmartCard-HSM computes it (KEY DOMAIN status, share import, and the
    /// first 8 bytes of every key blob).  `sc-hsm-tool` prints it.
    pub fn compute_kcv(&self) -> Result<[u8; KCV_SIZE], DkekError> {
        let dkek = self.get_dkek().ok_or(DkekError::WrongState)?;
        Ok(cc_kcv(dkek))
    }

    /// The KCV of the deprecated pico2hsm wrap format (versions 2 and 3):
    /// the first 8 bytes of AES-256-CMAC(DKEK, 0^16).
    fn legacy_kcv(&self) -> Result<[u8; KCV_SIZE], DkekError> {
        let dkek = self.get_dkek().ok_or(DkekError::WrongState)?;
        let mut mac = <Cmac<Aes256> as CmacMac>::new_from_slice(dkek)
            .map_err(|_| DkekError::EncryptFailure)?;
        mac.update(&[0u8; 16]);
        let result = mac.finalize().into_bytes();
        let mut kcv = [0u8; KCV_SIZE];
        kcv.copy_from_slice(&result[..KCV_SIZE]);
        Ok(kcv)
    }

    /// WRAP KEY: `key` as a SmartCard-HSM (CardContact) key blob.
    ///
    /// ```text
    /// KCV(8) | type(1) | LV(OID) | LV(algorithms) | LV(access) | LV(key OID)
    ///        | AES-256-CBC(K_enc, IV=0, rand(8) | size(2) | key | 80 00..)
    ///        | AES-CMAC(K_mac, all of the above)(16)
    /// ```
    /// Layout of the fields: [`crate::security::key_blob`] and
    /// `docs/SC_HSM_APDU_REFERENCE.md`.  The algorithm list comes from
    /// `key.policy`, the access conditions from `key_flags`.  The caller
    /// enforces export permission (NO_EXPORT, algorithm 92, use counter).
    pub fn wrap(
        &self,
        key: &KeyObject,
        key_flags: u8,
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> Result<heapless::Vec<u8, WRAP_MAX_BLOB>, DkekError> {
        let dkek = self.get_dkek().ok_or(DkekError::WrongState)?;
        let (key_type, oid) = key_blob::classify(key).map_err(wrap_err)?;

        // Built in place; wiped on drop, so an early return leaves no
        // plaintext behind.
        let mut out: Zeroizing<heapless::Vec<u8, WRAP_MAX_BLOB>> =
            Zeroizing::new(heapless::Vec::new());
        let fail = |_| DkekError::EncryptFailure;
        out.extend_from_slice(&cc_kcv(dkek)).map_err(fail)?;
        out.push(key_type).map_err(|_| DkekError::EncryptFailure)?;
        key_blob::put_lv(&mut *out, oid).map_err(wrap_err)?;
        key_blob::write_policy_fields(&key.policy, key_flags, &mut *out).map_err(wrap_err)?;
        key_blob::put_lv(&mut *out, &[]).map_err(wrap_err)?; // key OID: unused
        let enc_start = out.len();
        let mut randomize = [0u8; 8];
        rng.fill_bytes(&mut randomize);
        out.extend_from_slice(&randomize).map_err(fail)?;
        key_blob::encode_key(key, &mut *out).map_err(wrap_err)?;
        // ISO/IEC 9797-1 padding method 2.
        out.push(0x80).map_err(|_| DkekError::EncryptFailure)?;
        while (out.len() - enc_start) % 16 != 0 {
            out.push(0x00).map_err(|_| DkekError::EncryptFailure)?;
        }
        let enc_len = out.len() - enc_start;
        let (kenc, kmac) = cc_keys(dkek);
        let enc = <CbcEncryptor<Aes256> as KeyIvInit>::new_from_slices(kenc.as_ref(), &[0u8; 16])
            .map_err(|_| DkekError::EncryptFailure)?;
        enc.encrypt_padded_mut::<NoPadding>(&mut out[enc_start..], enc_len)
            .map_err(|_| DkekError::EncryptFailure)?;
        let tag = cc_cmac(&kmac, &out);
        out.extend_from_slice(&tag).map_err(fail)?;
        // Ciphertext only from here on: hand it out without the wipe.
        Ok(core::mem::take(&mut *out))
    }

    /// UNWRAP KEY: decode a key blob into `out` (`key_type`, `algorithm`,
    /// `private_key`, `public_key`, `key_flags`, `policy`).
    ///
    /// Accepts the CardContact format, and — deprecated, for one release —
    /// the pico2hsm formats version 2 and 3 (byte 8 = 0x02 / 0x03, never a
    /// CardContact key type).
    ///
    /// The blob is authenticated (KCV, then CMAC or HMAC, compared in
    /// constant time) before anything is decrypted or parsed; every failure
    /// up to and including authentication is `InvalidWrapBlob`.
    pub fn unwrap(&self, blob: &[u8], out: &mut KeyObject) -> Result<Unwrapped, DkekError> {
        let dkek = self.get_dkek().ok_or(DkekError::WrongState)?;
        if matches!(
            blob.get(KCV_SIZE),
            Some(&(WRAP_VERSION | WRAP_VERSION_POLICY))
        ) {
            return self.unwrap_legacy_into(blob, out);
        }
        if blob.len() < CC_MIN_BLOB || blob.len() > WRAP_MAX_BLOB {
            return Err(DkekError::InvalidWrapBlob);
        }
        let (authenticated, tag) = blob.split_at(blob.len() - CC_MAC_SIZE);
        let kcv_ok = cc_kcv(dkek).ct_eq(&blob[..KCV_SIZE]);
        let (kenc, kmac) = cc_keys(dkek);
        let mac_ok = cc_cmac(&kmac, authenticated).ct_eq(tag);
        if !bool::from(kcv_ok & mac_ok) {
            return Err(DkekError::InvalidWrapBlob);
        }

        // Authenticated from here on.
        let bad = DkekError::InvalidWrapBlob;
        let key_type = authenticated[KCV_SIZE];
        let rest = &authenticated[KCV_SIZE + 1..];
        let (oid, rest) = key_blob::split_lv(rest).ok_or(bad)?;
        let (algorithms, rest) = key_blob::split_lv(rest).ok_or(bad)?;
        let (access, rest) = key_blob::split_lv(rest).ok_or(bad)?;
        let (key_oid, enc) = key_blob::split_lv(rest).ok_or(bad)?;
        if oid.len() > key_blob::MAX_OID
            || key_oid.len() > key_blob::MAX_OID
            || access.len() > key_blob::MAX_ACCESS
            || enc.len() < 16
            || enc.len() % 16 != 0
            || enc.len() > CC_MAX_ENC
        {
            return Err(bad);
        }
        let (mut policy, key_flags) =
            key_blob::read_policy_fields(algorithms, access).map_err(unwrap_err)?;
        // The key joins the key domain whose DKEK opened it (as on a
        // SmartCard-HSM); this device has one, domain 0.
        policy.domain = Some(0);

        let mut pt_buf = Zeroizing::new([0u8; CC_MAX_ENC]);
        let pt = &mut pt_buf[..enc.len()];
        pt.copy_from_slice(enc);
        let dec = <CbcDecryptor<Aes256> as KeyIvInit>::new_from_slices(kenc.as_ref(), &[0u8; 16])
            .map_err(|_| DkekError::DecryptFailure)?;
        dec.decrypt_padded_mut::<NoPadding>(pt)
            .map_err(|_| DkekError::DecryptFailure)?;
        // randomize(8) | key size(2) | material | padding (lengths are
        // explicit; the padding is covered by the CMAC and not checked).
        let decoded = key_blob::decode_key(key_type, &pt[8..], out).map_err(unwrap_err)?;
        out.policy = policy;
        out.key_flags = key_flags;
        Ok(Unwrapped {
            decoded,
            key_flags,
            legacy: false,
        })
    }

    /// A deprecated pico2hsm blob (version 2 or 3) into `out`.
    fn unwrap_legacy_into(&self, blob: &[u8], out: &mut KeyObject) -> Result<Unwrapped, DkekError> {
        let (key, algo, key_flags, policy) = self.unwrap_legacy(blob)?;
        let key = crate::security::zeroize::WipeOnDrop(key);
        let decoded = key_blob::decode_legacy(&key, algo, out).map_err(unwrap_err)?;
        out.policy = policy;
        out.key_flags = key_flags;
        Ok(Unwrapped {
            decoded,
            key_flags,
            legacy: true,
        })
    }

    /// Wrap in the deprecated pico2hsm format (version 2, or 3 with a
    /// policy).  Tests only: WRAP KEY writes the CardContact format.
    #[cfg(test)]
    pub(crate) fn wrap_legacy(
        &self,
        key_material: &[u8],
        algo_id: u8,
        key_flags: u8,
        policy: &KeyPolicy,
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> Result<heapless::Vec<u8, WRAP_MAX_BLOB>, DkekError> {
        let dkek = self.get_dkek().ok_or(DkekError::WrongState)?;
        let kcv = self.legacy_kcv()?;

        let mut ext: heapless::Vec<u8, { crate::security::key_policy::MAX_POLICY_EXT }> =
            heapless::Vec::new();
        policy
            .encode(&mut ext)
            .map_err(|_| DkekError::EncryptFailure)?;
        let version = if ext.is_empty() {
            WRAP_VERSION
        } else {
            WRAP_VERSION_POLICY
        };

        // Assemble KCV(8) || version || IV(16) || plaintext (layout above,
        // PKCS#7-padded), then encrypt the plaintext in place and append
        // MAC(16).  Wiped on drop, so an early return leaves no plaintext.
        let mut out: Zeroizing<heapless::Vec<u8, WRAP_MAX_BLOB>> =
            Zeroizing::new(heapless::Vec::new());
        let mut iv = [0u8; CBC_IV_SIZE];
        rng.fill_bytes(&mut iv);
        let fail = |_| DkekError::EncryptFailure;
        out.extend_from_slice(&kcv).map_err(fail)?;
        out.push(version).map_err(|_| DkekError::EncryptFailure)?;
        out.extend_from_slice(&iv).map_err(fail)?;
        out.extend_from_slice(key_material).map_err(fail)?;
        if !ext.is_empty() {
            out.extend_from_slice(&ext).map_err(fail)?;
            out.push(ext.len() as u8)
                .map_err(|_| DkekError::EncryptFailure)?;
        }
        out.push(algo_id).map_err(|_| DkekError::EncryptFailure)?;
        out.push(key_flags).map_err(|_| DkekError::EncryptFailure)?;
        let pad_len = 16 - ((out.len() - WRAP_HEADER_SIZE) % 16);
        for _ in 0..pad_len {
            out.push(pad_len as u8)
                .map_err(|_| DkekError::EncryptFailure)?;
        }
        let padded_len = out.len() - WRAP_HEADER_SIZE;
        if padded_len > WRAP_MAX_PT {
            return Err(DkekError::EncryptFailure);
        }

        let (kenc, kmac) = wrap_keys(dkek);
        let enc = <CbcEncryptor<Aes256> as KeyIvInit>::new_from_slices(kenc.as_ref(), &iv)
            .map_err(|_| DkekError::EncryptFailure)?;
        enc.encrypt_padded_mut::<NoPadding>(&mut out[WRAP_HEADER_SIZE..], padded_len)
            .map_err(|_| DkekError::EncryptFailure)?;
        let tag = wrap_mac(&kmac, &out);
        out.extend_from_slice(&tag).map_err(fail)?;
        // Ciphertext only from here on: hand it out without the wipe.
        Ok(core::mem::take(&mut *out))
    }

    /// Decode a deprecated pico2hsm blob (versions 2 and 3).
    ///
    /// Verifies KCV and MAC, decrypts AES-256-CBC, removes PKCS#7 padding.
    /// Returns `(key_material, algo_id, key_flags, policy)`.
    #[allow(clippy::type_complexity)]
    fn unwrap_legacy(
        &self,
        blob: &[u8],
    ) -> Result<(heapless::Vec<u8, 2400>, u8, u8, KeyPolicy), DkekError> {
        let dkek = self.get_dkek().ok_or(DkekError::WrongState)?;

        // Validate minimum length and alignment.
        if blob.len() < WRAP_MIN_SIZE {
            return Err(DkekError::InvalidWrapBlob);
        }
        // Layout: KCV(8) || version(1) || IV(16) || ct || MAC(16).
        // Version-1 blobs (no MAC) are refused: decrypting unauthenticated
        // CBC is what made IMPORT KEY a padding oracle.
        let ct_len = blob.len() - WRAP_HEADER_SIZE - WRAP_MAC_SIZE;
        let version = blob[KCV_SIZE];
        if ct_len % 16 != 0 || (version != WRAP_VERSION && version != WRAP_VERSION_POLICY) {
            return Err(DkekError::InvalidWrapBlob);
        }
        let kcv_received: &[u8; KCV_SIZE] = blob[..KCV_SIZE].try_into().unwrap();
        let iv: &[u8; CBC_IV_SIZE] = blob[KCV_SIZE + 1..WRAP_HEADER_SIZE].try_into().unwrap();
        let (authenticated, tag) = blob.split_at(blob.len() - WRAP_MAC_SIZE);
        let ct = &authenticated[WRAP_HEADER_SIZE..];
        // Verify KCV.
        let kcv_expected = self.legacy_kcv()?;
        if !bool::from(kcv_expected.ct_eq(kcv_received)) {
            return Err(DkekError::InvalidWrapBlob);
        }
        // Verify the MAC (it covers the version byte) before touching the
        // ciphertext.
        let (kenc, kmac) = wrap_keys(dkek);
        if !bool::from(wrap_mac(&kmac, authenticated).ct_eq(tag)) {
            return Err(DkekError::InvalidWrapBlob);
        }
        // AES-256-CBC decrypt.
        // Self-wiping: also covers the early error returns below.
        let mut pt_buf = Zeroizing::new([0u8; WRAP_MAX_PT]);
        if ct_len > pt_buf.len() {
            return Err(DkekError::InvalidWrapBlob);
        }
        let pt_slice = &mut pt_buf[..ct_len];
        pt_slice.copy_from_slice(ct);

        let dec = <CbcDecryptor<Aes256> as KeyIvInit>::new_from_slices(kenc.as_ref(), iv)
            .map_err(|_| DkekError::DecryptFailure)?;
        dec.decrypt_padded_mut::<NoPadding>(pt_slice)
            .map_err(|_| DkekError::DecryptFailure)?;

        // Remove PKCS#7 padding — constant-time validation to avoid leaking
        // information about the decrypted plaintext structure via timing.
        let pad_len = *pt_slice.last().ok_or(DkekError::InvalidPadding)? as usize;

        // Constant-time bounds check: pad_len must be 1..=16 and <= ct_len.
        let pad_invalid = Choice::from((pad_len == 0 || pad_len > 16 || pad_len > ct_len) as u8);

        // Constant-time padding byte check — accumulate without early exit.
        // Iterate over all 16 potential padding positions with a fixed loop count
        // to avoid length-dependent timing.
        let mut bad = Choice::from(0u8);
        for i in 0..16usize {
            let in_range = Choice::from((i < pad_len && ct_len >= pad_len && i < ct_len) as u8);
            let idx = ct_len
                .saturating_sub(pad_len)
                .saturating_add(i)
                .min(ct_len.saturating_sub(1));
            let byte_ok = pt_slice[idx].ct_eq(&(pad_len as u8));
            // Only count mismatch if we're in the padding range.
            bad |= in_range & !byte_ok;
        }
        bad |= pad_invalid;

        if bool::from(bad) {
            return Err(DkekError::InvalidPadding);
        }
        let unpadded_len = ct_len - pad_len;

        // Trailer: [policy || policy_len] (version 3) || algo_id || key_flags.
        if unpadded_len < 2 {
            return Err(DkekError::InvalidWrapBlob);
        }
        let algo_id = pt_slice[unpadded_len - 2];
        let key_flags = pt_slice[unpadded_len - 1];
        let mut key_material_len = unpadded_len - 2;
        let mut policy = KeyPolicy::default();
        if version == WRAP_VERSION_POLICY {
            let len_at = key_material_len
                .checked_sub(1)
                .ok_or(DkekError::InvalidWrapBlob)?;
            let ext_start = len_at
                .checked_sub(pt_slice[len_at] as usize)
                .ok_or(DkekError::InvalidWrapBlob)?;
            policy = KeyPolicy::decode(&pt_slice[ext_start..len_at])
                .map_err(|_| DkekError::InvalidWrapBlob)?;
            if policy.is_unrestricted() {
                return Err(DkekError::InvalidWrapBlob);
            }
            key_material_len = ext_start;
        }

        let mut key_material: heapless::Vec<u8, 2400> = heapless::Vec::new();
        key_material
            .extend_from_slice(&pt_slice[..key_material_len])
            .map_err(|_| DkekError::InvalidWrapBlob)?;

        // Zeroize pt_buf.
        pt_buf.zeroize();

        Ok((key_material, algo_id, key_flags, policy))
    }
}

impl Drop for DkekManager {
    fn drop(&mut self) {
        self.status.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Share blob encrypt / decrypt helpers
// ---------------------------------------------------------------------------

/// Encrypt a 32-byte share value into a 64-byte share blob.
///
/// Format: `IV(16) || AES-256-CBC(key=SHA-256(password), IV, share||SHA-256(share))`
pub fn encrypt_share_blob(
    share: &[u8; 32],
    password: &[u8],
    iv: &[u8; 16],
) -> Result<[u8; SHARE_BLOB_SIZE], DkekError> {
    // Derive CBC key from password.
    let key: [u8; 32] = Sha256::digest(password).into();

    // Build plaintext: share(32) || SHA-256(share)(32)
    let mut pt = [0u8; SHARE_PT_SIZE];
    pt[..32].copy_from_slice(share);
    let hash: [u8; 32] = Sha256::digest(share).into();
    pt[32..].copy_from_slice(&hash);

    // AES-256-CBC encrypt (no padding — plaintext is already block-aligned).
    let enc = <CbcEncryptor<Aes256> as KeyIvInit>::new_from_slices(&key, iv)
        .map_err(|_| DkekError::EncryptFailure)?;
    enc.encrypt_padded_mut::<NoPadding>(&mut pt, SHARE_PT_SIZE)
        .map_err(|_| DkekError::EncryptFailure)?;

    // Assemble blob.
    let mut blob = [0u8; SHARE_BLOB_SIZE];
    blob[..16].copy_from_slice(iv);
    blob[16..].copy_from_slice(&pt);

    // Zeroize intermediate key material.
    let mut key_z = key;
    key_z.zeroize();
    pt.zeroize();

    Ok(blob)
}

/// Decrypt a share blob into the 64-byte plaintext (share_value || hash).
///
/// Returns `Err(ShareDecryptFailure)` if decryption fails.
fn decrypt_share_blob(blob: &[u8], password: &[u8]) -> Result<[u8; SHARE_PT_SIZE], DkekError> {
    if blob.len() != SHARE_BLOB_SIZE {
        return Err(DkekError::InvalidShareBlob);
    }

    let iv: &[u8; 16] = blob[..16].try_into().unwrap();
    let ct = &blob[16..]; // 48 bytes

    // Derive CBC key from password.
    let key: [u8; 32] = Sha256::digest(password).into();

    let mut pt = [0u8; SHARE_PT_SIZE];
    pt.copy_from_slice(ct);

    let dec = <CbcDecryptor<Aes256> as KeyIvInit>::new_from_slices(&key, iv)
        .map_err(|_| DkekError::ShareDecryptFailure)?;
    dec.decrypt_padded_mut::<NoPadding>(&mut pt)
        .map_err(|_| DkekError::ShareDecryptFailure)?;

    // Zeroize intermediate key material.
    let mut key_z = key;
    key_z.zeroize();

    Ok(pt)
}

// ---------------------------------------------------------------------------
// P-256 ECDH helper (simplified, using existing p256 crate)
// ---------------------------------------------------------------------------

/// Compute a P-256 ECDH shared secret.
///
/// `priv_key` is the 32-byte scalar (big-endian).
/// `peer_pub` is the 65-byte uncompressed public key (0x04 || X || Y).
///
/// Returns the 32-byte X-coordinate of the shared point.
pub fn p256_ecdh(
    priv_key: &[u8; 32],
    peer_pub: &[u8; P256_UNCOMPRESSED_SIZE],
) -> Result<Zeroizing<[u8; 32]>, DkekError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::elliptic_curve::ScalarPrimitive;
    use p256::{
        elliptic_curve::sec1::FromEncodedPoint, EncodedPoint, NistP256, NonZeroScalar,
        ProjectivePoint, PublicKey,
    };

    // Parse peer public key.
    let encoded =
        EncodedPoint::from_bytes(peer_pub.as_slice()).map_err(|_| DkekError::EcdhFailure)?;
    let peer_pk = PublicKey::from_encoded_point(&encoded)
        .into_option()
        .ok_or(DkekError::EcdhFailure)?;

    // Construct NonZeroScalar from the raw 32-byte private key.
    let scalar_primitive =
        ScalarPrimitive::<NistP256>::from_slice(priv_key).map_err(|_| DkekError::EcdhFailure)?;
    let scalar: p256::Scalar = scalar_primitive.into();
    let nz_scalar = NonZeroScalar::new(scalar)
        .into_option()
        .ok_or(DkekError::EcdhFailure)?;

    // Multiply peer point by our scalar.
    let peer_point: ProjectivePoint = peer_pk.into();
    let shared_point = (peer_point * *nz_scalar).to_affine();

    // Extract X-coordinate (the ECDH shared secret).
    let shared_encoded = shared_point.to_encoded_point(false);
    let x = shared_encoded.x().ok_or(DkekError::EcdhFailure)?;

    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(x.as_slice());

    Ok(out)
}

/// Derive an AES-256 session key for V2 DKEK exchange with channel binding.
///
/// `info = b"pico2hsm-dkek-v2" || ephem_pub_1(65) || ephem_pub_2(65) || challenge(32)`
/// `session_key = HKDF-SHA256(ikm=shared_secret, salt=[], info=info, len=32)`
pub fn derive_session_key_v2(
    shared_secret: &[u8; 32],
    ephem_pub_1: &[u8; 65],
    ephem_pub_2: &[u8; 65],
    challenge: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, DkekError> {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_ref());
    // info = b"pico2hsm-dkek-v2"(16) || ephem_pub_1(65) || ephem_pub_2(65) || challenge(32) = 178 bytes
    let mut info_buf = [0u8; 178];
    info_buf[..16].copy_from_slice(b"pico2hsm-dkek-v2");
    info_buf[16..81].copy_from_slice(ephem_pub_1);
    info_buf[81..146].copy_from_slice(ephem_pub_2);
    info_buf[146..].copy_from_slice(challenge);
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info_buf, out.as_mut())
        .map_err(|_| DkekError::KdfFailure)?;
    Ok(out)
}

/// Derive an AES-256 session key from the ECDH shared secret.
///
/// `HKDF-SHA256(ikm=shared_secret, salt=[], info=EXCHANGE_INFO, len=32)`
fn derive_session_key(shared_secret: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, DkekError> {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_ref());
    let mut session_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(EXCHANGE_INFO, session_key.as_mut())
        .map_err(|_| DkekError::KdfFailure)?;
    Ok(session_key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_device_id() -> [u8; 16] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]
    }

    fn contains(mgr: &DkekManager, pattern: &[u8; 32]) -> bool {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (mgr as *const DkekManager).cast::<u8>(),
                core::mem::size_of::<DkekManager>(),
            )
        };
        bytes.windows(32).any(|w| w == pattern)
    }

    #[test]
    fn clear_wipes_dkek_in_place() {
        let pattern = [0xA5u8; 32];
        let mut mgr = DkekManager::new(test_device_id());
        mgr.set_dkek_direct(&pattern);
        assert!(contains(&mgr, &pattern));
        mgr.clear();
        assert!(!mgr.is_ready());
        assert!(!contains(&mgr, &pattern));
    }

    #[test]
    fn set_dkek_direct_wipes_previous_dkek() {
        let old = [0xA5u8; 32];
        let mut mgr = DkekManager::new(test_device_id());
        mgr.set_dkek_direct(&old);
        mgr.set_dkek_direct(&[0x5Au8; 32]);
        assert!(!contains(&mgr, &old));
    }

    /// Deterministic RNG for tests (no OsRng in no_std firmware builds).
    struct DeterministicRng {
        state: u64,
    }

    impl DeterministicRng {
        fn seeded(seed: u64) -> Self {
            DeterministicRng { state: seed | 1 }
        }
    }

    impl rand_core::RngCore for DeterministicRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                let n = chunk.len();
                chunk.copy_from_slice(&v[..n]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for DeterministicRng {}

    #[test]
    fn test_init_shares_transitions_state() {
        let mut mgr = DkekManager::new(test_device_id());
        assert!(!mgr.is_ready());
        assert_eq!(mgr.shares_received(), 0);
        mgr.init_shares(3);
        assert!(!mgr.is_ready());
        assert_eq!(mgr.shares_total(), 3);
    }

    #[test]
    fn test_share_blob_encrypt_decrypt_roundtrip() {
        let share: [u8; 32] = [0xABu8; 32];
        let password = b"correct-horse-battery-staple";
        let iv: [u8; 16] = [0x11u8; 16];

        let blob = encrypt_share_blob(&share, password, &iv).unwrap();
        assert_eq!(blob.len(), SHARE_BLOB_SIZE);

        let pt = decrypt_share_blob(&blob, password).unwrap();
        assert_eq!(&pt[..32], &share[..]);

        // Verify embedded hash.
        let expected_hash: [u8; 32] = Sha256::digest(&share).into();
        assert_eq!(&pt[32..], &expected_hash[..]);
    }

    #[test]
    fn test_share_blob_wrong_password_fails_integrity() {
        let share: [u8; 32] = [0x55u8; 32];
        let iv: [u8; 16] = [0x22u8; 16];

        let blob = encrypt_share_blob(&share, b"password", &iv).unwrap();
        // Decryption with a wrong password yields garbage — integrity check must catch it.
        let pt = decrypt_share_blob(&blob, b"wrongpassword").unwrap();
        // The hash check would catch this in import_share; verify it fails here.
        let expected_hash: [u8; 32] = Sha256::digest(&share).into();
        // Hash stored in pt[32..] will not match because decryption used wrong key.
        let stored_hash = &pt[32..];
        // This should NOT match.
        assert!(!bool::from(expected_hash.ct_eq(stored_hash)));
    }

    #[test]
    fn test_single_share_xor_dkek() {
        let mut mgr = DkekManager::new(test_device_id());
        mgr.init_shares(1);

        // Create a share and its blob.
        let share: [u8; 32] = [0xDEu8; 32];
        let iv: [u8; 16] = [0x33u8; 16];
        let password = b"test-password";
        let blob = encrypt_share_blob(&share, password, &iv).unwrap();

        let result = mgr.import_share(&blob, password).unwrap();
        assert_eq!(result, DkekImportResult::Complete);
        assert!(mgr.is_ready());

        // DKEK should be exactly the single share (XOR of one value).
        let dkek = mgr.get_dkek().unwrap();
        assert_eq!(dkek, &share);
    }

    #[test]
    fn test_multi_share_xor_accumulation() {
        let mut mgr = DkekManager::new(test_device_id());
        mgr.init_shares(3);

        let shares: [[u8; 32]; 3] = [[0x01u8; 32], [0x02u8; 32], [0x04u8; 32]];
        let password = b"test-pw";
        let iv: [u8; 16] = [0x44u8; 16];

        // Expected DKEK = XOR of all three shares.
        let mut expected = [0u8; 32];
        for s in &shares {
            for (e, b) in expected.iter_mut().zip(s.iter()) {
                *e ^= b;
            }
        }

        for (i, share) in shares.iter().enumerate() {
            // Use different IVs to simulate real distribution.
            let mut iv_i = iv;
            iv_i[0] = i as u8;
            let blob = encrypt_share_blob(share, password, &iv_i).unwrap();

            let result = mgr.import_share(&blob, password).unwrap();
            if i < 2 {
                assert_eq!(
                    result,
                    DkekImportResult::MoreSharesNeeded {
                        received: (i + 1) as u8,
                        total: 3,
                    }
                );
                assert!(!mgr.is_ready());
            } else {
                assert_eq!(result, DkekImportResult::Complete);
                assert!(mgr.is_ready());
            }
        }

        let dkek = mgr.get_dkek().unwrap();
        assert_eq!(dkek, &expected);
    }

    #[test]
    fn test_import_wrong_state_fails() {
        let mut mgr = DkekManager::new(test_device_id());
        // Not initialized — import should fail.
        let dummy_blob = [0u8; SHARE_BLOB_SIZE];
        let result = mgr.import_share(&dummy_blob, b"pw");
        assert_eq!(result, Err(DkekError::WrongState));
    }

    #[test]
    fn test_static_key_derivation_deterministic() {
        let otp_key = [0xABu8; 32];
        let key1 = DkekManager::derive_static_private_key(&otp_key);
        let key2 = DkekManager::derive_static_private_key(&otp_key);
        assert_eq!(*key1, *key2);
    }

    #[test]
    fn test_clear_resets_state() {
        let mut mgr = DkekManager::new(test_device_id());
        mgr.init_shares(1);

        let share = [0xFFu8; 32];
        let iv = [0u8; 16];
        let blob = encrypt_share_blob(&share, b"pw", &iv).unwrap();
        mgr.import_share(&blob, b"pw").unwrap();
        assert!(mgr.is_ready());

        mgr.clear();
        assert!(!mgr.is_ready());
        assert_eq!(mgr.shares_total(), 0);
    }

    // --- CardContact key blob -----------------------------------------------

    use crate::security::key_management::{AlgorithmId, KeyType as KmType};
    use pico2hsm_core::key::AppletId;

    fn ready(dkek: [u8; 32]) -> DkekManager {
        let mut mgr = DkekManager::new(test_device_id());
        mgr.set_dkek_direct(&dkek);
        mgr
    }

    fn ec_key(algo: AlgorithmId, d: &[u8]) -> KeyObject {
        let mut k = KeyObject::new(KmType::Ec, 1, AppletId::ScHsm, algo);
        k.private_key.extend_from_slice(d).unwrap();
        k
    }

    fn blank() -> KeyObject {
        KeyObject::new(KmType::Generic, 1, AppletId::ScHsm, AlgorithmId::AesGcm)
    }

    fn hex(s: &str) -> heapless::Vec<u8, 256> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn kcv_is_sha256_prefix() {
        let mgr = ready([0x5A; 32]);
        let h = Sha256::digest([0x5Au8; 32]);
        assert_eq!(&mgr.compute_kcv().unwrap()[..], &h[..8]);
    }

    #[test]
    fn cc_round_trip_ec_and_aes() {
        let mgr = ready([0x33; 32]);
        let mut rng = DeterministicRng::seeded(7);
        let key = ec_key(AlgorithmId::EcdsaP384, &[0x44; 48]);
        let blob = mgr.wrap(&key, 0, &mut rng).unwrap();
        assert_eq!(&blob[..8], &mgr.compute_kcv().unwrap());
        assert_eq!(blob[8], key_blob::KEY_TYPE_EC);
        let mut out = blank();
        let u = mgr.unwrap(&blob, &mut out).unwrap();
        assert!(!u.legacy);
        assert_eq!(&out.private_key[..], &[0x44; 48]);
        assert_eq!(out.algorithm, AlgorithmId::EcdsaP384);
        assert_eq!(out.public_key.len(), 97);

        let mut aes = KeyObject::new(KmType::Aes, 2, AppletId::ScHsm, AlgorithmId::AesGcm);
        aes.private_key.extend_from_slice(&[0x77; 24]).unwrap();
        let blob = mgr.wrap(&aes, 0, &mut rng).unwrap();
        assert_eq!(blob[8], key_blob::KEY_TYPE_AES);
        let mut out = blank();
        let u = mgr.unwrap(&blob, &mut out).unwrap();
        assert_eq!(&out.private_key[..], &[0x77; 24]);
        assert_eq!(u.decoded.core_type, pico2hsm_core::key::KeyType::Aes192);
    }

    #[test]
    fn cc_policy_and_flags_survive() {
        let mgr = ready([0x21; 32]);
        let mut rng = DeterministicRng::seeded(3);
        let mut key = ec_key(AlgorithmId::EcdsaP256, &[0x11; 32]);
        key.policy
            .algorithms
            .extend_from_slice(&[0x73, 0x92])
            .unwrap();
        let blob = mgr.wrap(&key, 0x03, &mut rng).unwrap();
        let mut out = blank();
        let u = mgr.unwrap(&blob, &mut out).unwrap();
        assert_eq!(&out.policy.algorithms[..], &[0x73, 0x92]);
        assert_eq!((u.key_flags, out.key_flags), (0x03, 0x03));
        assert_eq!(out.policy.use_counter, None);
        assert_eq!(out.policy.domain, Some(0));
    }

    #[test]
    fn cc_every_bit_flip_is_one_uniform_error() {
        let mgr = ready([0x33; 32]);
        let mut rng = DeterministicRng::seeded(9);
        let mut key = ec_key(AlgorithmId::EcdsaP256, &[0x44; 32]);
        key.policy.algorithms.push(0x73).unwrap();
        let blob = mgr.wrap(&key, 0x01, &mut rng).unwrap();
        let mut out = blank();
        assert!(mgr.unwrap(&blob, &mut out).is_ok());
        // KCV, type, OID, algorithm list, access conditions, key OID,
        // ciphertext and CMAC: every bit is covered by the CMAC (or the
        // KCV), and every failure looks the same.
        for i in 0..blob.len() {
            for bit in 0..8 {
                let mut t = blob.clone();
                t[i] ^= 1 << bit;
                let mut out = blank();
                assert_eq!(
                    mgr.unwrap(&t, &mut out),
                    Err(DkekError::InvalidWrapBlob),
                    "byte {i} bit {bit}"
                );
                assert!(out.private_key.is_empty(), "nothing decoded");
            }
        }
        // Truncated and extended.
        let mut out = blank();
        assert_eq!(
            mgr.unwrap(&blob[..blob.len() - 1], &mut out),
            Err(DkekError::InvalidWrapBlob)
        );
        let mut longer = blob.clone();
        longer.push(0).unwrap();
        assert_eq!(
            mgr.unwrap(&longer, &mut out),
            Err(DkekError::InvalidWrapBlob)
        );
        // Another DKEK.
        assert_eq!(
            ready([0x34; 32]).unwrap(&blob, &mut out),
            Err(DkekError::InvalidWrapBlob)
        );
    }

    #[test]
    fn cc_refuses_keys_without_an_encoding() {
        let mgr = ready([0x33; 32]);
        let mut rng = DeterministicRng::seeded(1);
        for algo in [
            AlgorithmId::Ed25519,
            AlgorithmId::X25519,
            AlgorithmId::EcdsaBrainpool256,
        ] {
            let key = ec_key(algo, &[0x01; 32]);
            assert_eq!(mgr.wrap(&key, 0, &mut rng), Err(DkekError::UnsupportedKey));
        }
    }

    #[test]
    fn cc_requires_a_dkek() {
        let mgr = DkekManager::new(test_device_id());
        let mut rng = DeterministicRng::seeded(1);
        let key = ec_key(AlgorithmId::EcdsaP256, &[0x01; 32]);
        assert_eq!(mgr.wrap(&key, 0, &mut rng), Err(DkekError::WrongState));
        assert_eq!(
            mgr.unwrap(&[0u8; 64], &mut blank()),
            Err(DkekError::WrongState)
        );
    }

    /// Blobs written by the previous release (wrap format version 2),
    /// captured from `fix/reset-deadlock-and-zeroize` 77a50a5 with
    /// DKEK = 5A..5A: a P-256 key 42..42 and an AES-128 key 24..24.
    #[test]
    fn legacy_v2_blobs_from_the_previous_release_import() {
        let mgr = ready([0x5A; 32]);
        let p256 = hex(
            "0409ba14596d2b4102787c4a7fb979379e8df894fe72f36e3ca6b3493fc933cb8d5e53b2a4\
             6561b5e13056d9a73e59ddefd4a6643c53678195b2eca406f07ac3e919643b2878c14acda3\
             a9807289b0a4bcd5378b7cf471407f",
        );
        let mut out = blank();
        let u = mgr.unwrap(&p256, &mut out).unwrap();
        assert!(u.legacy);
        assert_eq!(&out.private_key[..], &[0x42; 32]);
        assert_eq!(out.algorithm, AlgorithmId::EcdsaP256);
        assert_eq!(out.public_key.len(), 65, "public key filled in");
        assert_eq!(u.decoded.meta_algo, 0x13);

        let aes = hex(
            "0409ba14596d2b4102a274df7d2c6da6dab7f029fde5e6dd78b050230e58799c3b6480fbc9\
             a6b4836d915c473494ea0c278f5b8e388b122caa030d48aa04075679a3779b458725ae2b",
        );
        let mut out = blank();
        let u = mgr.unwrap(&aes, &mut out).unwrap();
        assert!(u.legacy);
        assert_eq!(&out.private_key[..], &[0x24; 16]);
        assert_eq!(out.key_type, KmType::Aes);

        // Tampering with a legacy blob: the same uniform error.
        for i in 0..p256.len() {
            let mut t = p256.clone();
            t[i] ^= 0x01;
            let r = mgr.unwrap(&t, &mut blank());
            assert_eq!(r, Err(DkekError::InvalidWrapBlob), "byte {i}");
        }
    }

    #[test]
    fn legacy_v3_keeps_its_policy() {
        let mgr = ready([0x21; 32]);
        let mut rng = DeterministicRng::seeded(3);
        let mut policy = KeyPolicy::default();
        policy.algorithms.extend_from_slice(&[0x73, 0x92]).unwrap();
        let blob = mgr
            .wrap_legacy(&[0x6B; 32], 0x13, 0x00, &policy, &mut rng)
            .unwrap();
        assert_eq!(blob[KCV_SIZE], WRAP_VERSION_POLICY);
        let mut out = blank();
        let u = mgr.unwrap(&blob, &mut out).unwrap();
        assert!(u.legacy);
        assert_eq!(out.policy, policy);
        // The version byte is authenticated.
        let mut t = blob.clone();
        t[KCV_SIZE] = WRAP_VERSION;
        assert_eq!(
            mgr.unwrap(&t, &mut blank()),
            Err(DkekError::InvalidWrapBlob)
        );
    }

    #[test]
    fn version_1_blobs_are_refused() {
        let mgr = ready([0x33; 32]);
        // v1 layout: legacy KCV(8) || IV(16) || CBC ciphertext — no version, no MAC.
        let mut v1: heapless::Vec<u8, 64> = heapless::Vec::new();
        v1.extend_from_slice(&mgr.legacy_kcv().unwrap()).unwrap();
        v1.extend_from_slice(&[0u8; 16 + 32]).unwrap();
        assert_eq!(
            mgr.unwrap(&v1, &mut blank()),
            Err(DkekError::InvalidWrapBlob)
        );
    }

    /// Build an authentic CardContact blob around `body`
    /// (`size(2) || material`), as another DKEK holder could.
    fn craft(dkek: &[u8; 32], key_type: u8, body: &[u8]) -> heapless::Vec<u8, 512> {
        let mut b: heapless::Vec<u8, 512> = heapless::Vec::new();
        b.extend_from_slice(&cc_kcv(dkek)).unwrap();
        b.push(key_type).unwrap();
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let start = b.len();
        b.extend_from_slice(&[0xA5; 8]).unwrap();
        b.extend_from_slice(body).unwrap();
        b.push(0x80).unwrap();
        while (b.len() - start) % 16 != 0 {
            b.push(0).unwrap();
        }
        let (kenc, kmac) = cc_keys(dkek);
        let len = b.len() - start;
        <CbcEncryptor<Aes256> as KeyIvInit>::new_from_slices(kenc.as_ref(), &[0u8; 16])
            .unwrap()
            .encrypt_padded_mut::<NoPadding>(&mut b[start..], len)
            .unwrap();
        let tag = cc_cmac(&kmac, &b);
        b.extend_from_slice(&tag).unwrap();
        b
    }

    #[test]
    fn authentic_blobs_of_unsupported_keys_are_refused_as_such() {
        let dkek = [0x42u8; 32];
        let mgr = ready(dkek);
        // EC on brainpoolP256r1: no curve arithmetic in this firmware.
        let bp_p = hex("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377");
        let mut body: heapless::Vec<u8, 256> = heapless::Vec::new();
        body.extend_from_slice(&[0x01, 0x00]).unwrap();
        for f in [&[][..], &[], &bp_p[..], &[], &[], &[1u8; 32], &[]] {
            body.extend_from_slice(&(f.len() as u16).to_be_bytes())
                .unwrap();
            body.extend_from_slice(f).unwrap();
        }
        let blob = craft(&dkek, key_blob::KEY_TYPE_EC, &body);
        assert_eq!(
            mgr.unwrap(&blob, &mut blank()),
            Err(DkekError::UnsupportedKey)
        );
        // An unknown key type code, and AES-512 (pico-hsm only).
        let blob = craft(&dkek, 7, &[0, 16]);
        assert_eq!(
            mgr.unwrap(&blob, &mut blank()),
            Err(DkekError::UnsupportedKey)
        );
        let mut aes512 = [0x11u8; 66];
        aes512[..2].copy_from_slice(&[0, 64]);
        let blob = craft(&dkek, key_blob::KEY_TYPE_AES, &aes512);
        assert_eq!(
            mgr.unwrap(&blob, &mut blank()),
            Err(DkekError::UnsupportedKey)
        );
        // Authentic but inconsistent: Q that is not d·G.
        let mut key = ec_key(AlgorithmId::EcdsaP256, &[0x05; 32]);
        key.public_key
            .extend_from_slice(ec_key_pub(&[0x06; 32]).as_slice())
            .unwrap();
        let blob = mgr.wrap(&key, 0, &mut DeterministicRng::seeded(5)).unwrap();
        assert_eq!(
            mgr.unwrap(&blob, &mut blank()),
            Err(DkekError::InvalidWrapBlob)
        );
    }

    fn ec_key_pub(d: &[u8; 32]) -> heapless::Vec<u8, 65> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let sk = p256::SecretKey::from_slice(d).unwrap();
        let mut v = heapless::Vec::new();
        v.extend_from_slice(sk.public_key().to_encoded_point(false).as_bytes())
            .unwrap();
        v
    }
}
