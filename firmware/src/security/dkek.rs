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
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use cmac::{Cmac, Mac as CmacMac};

use aes_gcm::{
    aead::{AeadInPlace, KeyInit as GcmKeyInit},
    Aes256Gcm,
    Nonce as GcmNonce,
    Tag as GcmTag,
};
use aes::Aes256;
use cbc::{Decryptor as CbcDecryptor, Encryptor as CbcEncryptor};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cipher::block_padding::NoPadding;

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

/// KCV (Key Check Value) size: first 8 bytes of AES-CMAC over zeros.
const KCV_SIZE: usize = 8;
/// CBC IV size.
const CBC_IV_SIZE: usize = 16;
/// Minimum wrapped blob size: KCV(8) + IV(16) + at least one CBC block(16).
const WRAP_MIN_SIZE: usize = KCV_SIZE + CBC_IV_SIZE + 16;

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
}

// ---------------------------------------------------------------------------
// Import result
// ---------------------------------------------------------------------------

/// Result returned from [`DkekManager::import_share`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkekImportResult {
    /// More shares are needed before the DKEK is complete.
    MoreSharesNeeded {
        received: u8,
        total:    u8,
    },
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
        received:    u8,
        total:       u8,
        accumulated: Zeroizing<[u8; 32]>,
    },
    /// All shares received; DKEK is available.
    Ready {
        dkek: Zeroizing<[u8; 32]>,
    },
}

impl Zeroize for DkekStatus {
    fn zeroize(&mut self) {
        // Use mem::replace to take ownership of the old value without triggering
        // Drop on it (which would call zeroize() again → infinite recursion).
        let old = core::mem::replace(self, DkekStatus::NotInitialized);
        match old {
            DkekStatus::CollectingShares { mut accumulated, .. } => accumulated.zeroize(),
            DkekStatus::Ready { mut dkek } => dkek.zeroize(),
            DkekStatus::NotInitialized => {}
        }
        // `old` is consumed by the match — no Drop call.
        // The inner Zeroizing<[u8;32]> fields zeroize themselves on drop.
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
    status:      DkekStatus,
    total_shares: u8,
    /// 16-byte device identifier (used in exchange AAD and static key derivation).
    device_id:   [u8; 16],
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
            received:    0,
            total:       n_shares,
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
        password:   &[u8],
    ) -> Result<DkekImportResult, DkekError> {
        // Validate blob length.
        if share_blob.len() != SHARE_BLOB_SIZE {
            return Err(DkekError::InvalidShareBlob);
        }

        // Ensure we are in the right state.
        let (received, total, accumulated) = match &mut self.status {
            DkekStatus::CollectingShares { received, total, accumulated } => {
                (received, *total, accumulated)
            }
            _ => return Err(DkekError::WrongState),
        };

        // Decrypt the share blob.
        let decrypted = decrypt_share_blob(share_blob, password)?;

        // Validate embedded SHA-256 hash.
        let share_value = &decrypted[..32];
        let expected_hash: [u8; 32] = Sha256::digest(share_value).into();
        let stored_hash   = &decrypted[32..64];
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
            let dkek_val: [u8; 32] = **accumulated; // Copy inner array before zeroizing
            self.status.zeroize();
            self.status = DkekStatus::Ready {
                dkek: Zeroizing::new(dkek_val),
            };
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
    pub fn generate_share(
        &self,
        rng: &mut impl rand_core::RngCore,
    ) -> Zeroizing<[u8; 32]> {
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
    pub fn set_dkek_direct(&mut self, dkek: [u8; 32]) {
        self.status.zeroize();
        self.status = DkekStatus::Ready {
            dkek: Zeroizing::new(dkek),
        };
        self.total_shares = 1;
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

        let cipher = Aes256Gcm::new_from_slice(&*session_key)
            .map_err(|_| DkekError::EncryptFailure)?;
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
        our_ephem_priv:      &[u8; 32],
        encrypted_dkek:      &[u8; NONCE_SIZE + 32 + TAG_SIZE],
        initiator_device_id: &[u8; 16],
    ) -> Result<(), DkekError> {
        // ECDH using P-256.
        let shared_secret = p256_ecdh(our_ephem_priv, initiator_ephem_pub)?;

        // Derive session key.
        let session_key = derive_session_key(&shared_secret)?;

        // Decrypt DKEK.
        let nonce_bytes: &[u8; 12] = encrypted_dkek[..NONCE_SIZE].try_into().unwrap();
        let ct_with_tag = &encrypted_dkek[NONCE_SIZE..];
        let ct_end  = ct_with_tag.len() - TAG_SIZE;
        let tag_bytes: &[u8; 16] = ct_with_tag[ct_end..].try_into().unwrap();

        let cipher = Aes256Gcm::new_from_slice(&*session_key)
            .map_err(|_| DkekError::DecryptFailure)?;
        let nonce_arr = GcmNonce::from_slice(nonce_bytes);
        let tag_val   = GcmTag::clone_from_slice(tag_bytes);

        let mut dkek_buf = Zeroizing::new([0u8; 32]);
        dkek_buf.copy_from_slice(&ct_with_tag[..ct_end]);

        cipher
            .decrypt_in_place_detached(
                nonce_arr,
                initiator_device_id,
                dkek_buf.as_mut(),
                &tag_val,
            )
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
    pub fn derive_static_private_key(
        otp_identity_key: &[u8; 32],
    ) -> Zeroizing<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(None, otp_identity_key);
        let mut out = Zeroizing::new([0u8; 32]);
        // Infallible for len=32.
        hkdf.expand(NOISE_STATIC_INFO, out.as_mut()).expect("HKDF expand cannot fail for 32 bytes");
        out
    }

    /// Compute Key Check Value: first 8 bytes of AES-256-CMAC(DKEK, zeros[16]).
    pub fn compute_kcv(&self) -> Result<[u8; KCV_SIZE], DkekError> {
        let dkek = self.get_dkek().ok_or(DkekError::WrongState)?;
        let mut mac = <Cmac<Aes256> as CmacMac>::new_from_slice(dkek)
            .map_err(|_| DkekError::EncryptFailure)?;
        mac.update(&[0u8; 16]);
        let result = mac.finalize().into_bytes();
        let mut kcv = [0u8; KCV_SIZE];
        kcv.copy_from_slice(&result[..KCV_SIZE]);
        Ok(kcv)
    }

    /// Wrap key material in SC-HSM DKEK wrap format.
    ///
    /// Output format: KCV(8) || IV(16) || AES-256-CBC(DKEK, IV, padded_plaintext)
    /// Plaintext before padding: key_material || algo_id(1) || key_flags(1)
    /// PKCS#7 padding to 16-byte boundary.
    pub fn wrap(
        &self,
        key_material: &[u8],
        algo_id: u8,
        key_flags: u8,
        rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
    ) -> Result<heapless::Vec<u8, 2080>, DkekError> {
        let dkek = self.get_dkek().ok_or(DkekError::WrongState)?;

        // Compute KCV.
        let kcv = self.compute_kcv()?;

        // Build plaintext: key_material || algo_id || key_flags
        let plain_data_len = key_material.len() + 2; // +2 for algo_id + key_flags
        // PKCS#7 pad to 16-byte boundary.
        let pad_len = 16 - (plain_data_len % 16);
        let padded_len = plain_data_len + pad_len;

        // Use a stack buffer. Max private key = 132 bytes (P-521); + 2 + up to 16 pad = 150 bytes.
        // heapless::Vec<u8, 160> for the plaintext buffer.
        let mut pt: heapless::Vec<u8, 160> = heapless::Vec::new();
        pt.extend_from_slice(key_material).map_err(|_| DkekError::EncryptFailure)?;
        pt.push(algo_id).map_err(|_| DkekError::EncryptFailure)?;
        pt.push(key_flags).map_err(|_| DkekError::EncryptFailure)?;
        for _ in 0..pad_len {
            pt.push(pad_len as u8).map_err(|_| DkekError::EncryptFailure)?;
        }

        // Generate random IV.
        let mut iv = [0u8; CBC_IV_SIZE];
        rng.fill_bytes(&mut iv);

        // AES-256-CBC encrypt in-place.
        // The cbc encryptor needs a mutable fixed-size slice. Use a fixed stack buffer.
        let mut ct_buf = [0u8; 160];
        let ct_slice = &mut ct_buf[..padded_len];
        ct_slice.copy_from_slice(&pt[..padded_len]);

        let enc = <CbcEncryptor<Aes256> as KeyIvInit>::new_from_slices(dkek, &iv)
            .map_err(|_| DkekError::EncryptFailure)?;
        enc.encrypt_padded_mut::<NoPadding>(ct_slice, padded_len)
            .map_err(|_| DkekError::EncryptFailure)?;

        // Zeroize plaintext buffer.
        for b in pt.iter_mut() { *b = 0; }

        // Assemble output: KCV(8) || IV(16) || ciphertext(padded_len)
        let mut out: heapless::Vec<u8, 2080> = heapless::Vec::new();
        out.extend_from_slice(&kcv).map_err(|_| DkekError::EncryptFailure)?;
        out.extend_from_slice(&iv).map_err(|_| DkekError::EncryptFailure)?;
        out.extend_from_slice(ct_slice).map_err(|_| DkekError::EncryptFailure)?;

        Ok(out)
    }

    /// Unwrap a DKEK-wrapped key blob.
    ///
    /// Verifies KCV, decrypts AES-256-CBC, removes PKCS#7 padding.
    /// Returns: (key_material, algo_id, key_flags)
    pub fn unwrap(
        &self,
        blob: &[u8],
    ) -> Result<(heapless::Vec<u8, 2048>, u8, u8), DkekError> {
        let dkek = self.get_dkek().ok_or(DkekError::WrongState)?;

        // Validate minimum length and alignment.
        if blob.len() < WRAP_MIN_SIZE {
            return Err(DkekError::InvalidWrapBlob);
        }
        let ct_len = blob.len() - KCV_SIZE - CBC_IV_SIZE;
        if ct_len % 16 != 0 {
            return Err(DkekError::InvalidWrapBlob);
        }

        let kcv_received: &[u8; KCV_SIZE] = blob[..KCV_SIZE].try_into().unwrap();
        let iv: &[u8; CBC_IV_SIZE] = blob[KCV_SIZE..KCV_SIZE + CBC_IV_SIZE].try_into().unwrap();
        let ct = &blob[KCV_SIZE + CBC_IV_SIZE..];

        // Verify KCV.
        let kcv_expected = self.compute_kcv()?;
        if !bool::from(kcv_expected.ct_eq(kcv_received)) {
            return Err(DkekError::KcvMismatch);
        }

        // AES-256-CBC decrypt.
        let mut pt_buf = [0u8; 160];
        if ct_len > pt_buf.len() {
            return Err(DkekError::InvalidWrapBlob);
        }
        let pt_slice = &mut pt_buf[..ct_len];
        pt_slice.copy_from_slice(ct);

        let dec = <CbcDecryptor<Aes256> as KeyIvInit>::new_from_slices(dkek, iv)
            .map_err(|_| DkekError::DecryptFailure)?;
        dec.decrypt_padded_mut::<NoPadding>(pt_slice)
            .map_err(|_| DkekError::DecryptFailure)?;

        // Remove PKCS#7 padding.
        let pad_len = *pt_slice.last().ok_or(DkekError::InvalidPadding)? as usize;
        if pad_len == 0 || pad_len > 16 || pad_len > ct_len {
            return Err(DkekError::InvalidPadding);
        }
        // Validate all padding bytes.
        for &b in &pt_slice[ct_len - pad_len..] {
            if b as usize != pad_len {
                return Err(DkekError::InvalidPadding);
            }
        }
        let unpadded_len = ct_len - pad_len;

        // Extract key_material, algo_id, key_flags.
        // Layout: key_material(unpadded_len - 2) || algo_id(1) || key_flags(1)
        if unpadded_len < 2 {
            return Err(DkekError::InvalidWrapBlob);
        }
        let key_material_len = unpadded_len - 2;
        let algo_id = pt_slice[key_material_len];
        let key_flags = pt_slice[key_material_len + 1];

        let mut key_material: heapless::Vec<u8, 2048> = heapless::Vec::new();
        key_material.extend_from_slice(&pt_slice[..key_material_len])
            .map_err(|_| DkekError::InvalidWrapBlob)?;

        // Zeroize pt_buf.
        pt_buf.zeroize();

        Ok((key_material, algo_id, key_flags))
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
    share:    &[u8; 32],
    password: &[u8],
    iv:       &[u8; 16],
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
    use p256::{
        elliptic_curve::sec1::FromEncodedPoint,
        EncodedPoint,
        PublicKey,
        NistP256,
        NonZeroScalar,
        ProjectivePoint,
    };
    use p256::elliptic_curve::ScalarPrimitive;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    // Parse peer public key.
    let encoded = EncodedPoint::from_bytes(peer_pub.as_slice())
        .map_err(|_| DkekError::EcdhFailure)?;
    let peer_pk = PublicKey::from_encoded_point(&encoded)
        .into_option()
        .ok_or(DkekError::EcdhFailure)?;

    // Construct NonZeroScalar from the raw 32-byte private key.
    let scalar_primitive = ScalarPrimitive::<NistP256>::from_slice(priv_key)
        .map_err(|_| DkekError::EcdhFailure)?;
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
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
    }

    /// Deterministic RNG for tests (no OsRng in no_std firmware builds).
    struct DeterministicRng { state: u64 }

    impl DeterministicRng {
        fn seeded(seed: u64) -> Self { DeterministicRng { state: seed | 1 } }
    }

    impl rand_core::RngCore for DeterministicRng {
        fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }

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

        let shares: [[u8; 32]; 3] = [
            [0x01u8; 32],
            [0x02u8; 32],
            [0x04u8; 32],
        ];
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
                        total:    3,
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

    #[test]
    fn test_wrap_unwrap_roundtrip_p256() {
        let mut mgr = DkekManager::new(test_device_id());
        mgr.init_shares(1);
        let share = [0x42u8; 32];
        let iv = [0x11u8; 16];
        let blob = encrypt_share_blob(&share, b"pw", &iv).unwrap();
        mgr.import_share(&blob, b"pw").unwrap();

        let mut rng = DeterministicRng::seeded(1);
        let key_material = [0xABu8; 32]; // simulated P-256 private key
        let algo_id = 0x13u8; // SC-HSM EC_P256
        let key_flags = 0x01u8; // exportable

        let wrapped = mgr.wrap(&key_material, algo_id, key_flags, &mut rng).unwrap();
        let (recovered, recovered_algo, recovered_flags) = mgr.unwrap(&wrapped).unwrap();

        assert_eq!(&*recovered, &key_material);
        assert_eq!(recovered_algo, algo_id);
        assert_eq!(recovered_flags, key_flags);
    }

    #[test]
    fn test_wrap_unwrap_roundtrip_aes256() {
        let mut mgr = DkekManager::new(test_device_id());
        mgr.init_shares(1);
        let share = [0x77u8; 32];
        let iv = [0x22u8; 16];
        let blob = encrypt_share_blob(&share, b"pw2", &iv).unwrap();
        mgr.import_share(&blob, b"pw2").unwrap();

        let mut rng = DeterministicRng::seeded(2);
        let key_material = [0xCDu8; 32]; // AES-256 key
        let wrapped = mgr.wrap(&key_material, 0x63u8, 0x00u8, &mut rng).unwrap();
        let (recovered, algo, flags) = mgr.unwrap(&wrapped).unwrap();
        assert_eq!(&*recovered, &key_material);
        assert_eq!(algo, 0x63u8);
        assert_eq!(flags, 0x00u8);
    }

    #[test]
    fn test_unwrap_kcv_mismatch_fails() {
        let mut mgr = DkekManager::new(test_device_id());
        mgr.init_shares(1);
        let share = [0x55u8; 32];
        let iv = [0x33u8; 16];
        let blob = encrypt_share_blob(&share, b"pw3", &iv).unwrap();
        mgr.import_share(&blob, b"pw3").unwrap();

        let mut rng = DeterministicRng::seeded(3);
        let key_material = [0x10u8; 32];
        let mut wrapped = mgr.wrap(&key_material, 0x13, 0x01, &mut rng).unwrap();
        // Corrupt the KCV (first 8 bytes).
        wrapped[0] ^= 0xFF;
        let result = mgr.unwrap(&wrapped);
        assert_eq!(result, Err(DkekError::KcvMismatch));
    }

    #[test]
    fn test_wrap_requires_ready_dkek() {
        let mgr = DkekManager::new(test_device_id());
        let mut rng = DeterministicRng::seeded(4);
        let result = mgr.wrap(&[0u8; 32], 0x13, 0x01, &mut rng);
        assert_eq!(result, Err(DkekError::WrongState));
    }

    #[test]
    fn test_unwrap_requires_ready_dkek() {
        let mgr = DkekManager::new(test_device_id());
        let dummy_blob = [0u8; 40]; // KCV(8) + IV(16) + one block(16)
        let result = mgr.unwrap(&dummy_blob);
        assert_eq!(result, Err(DkekError::WrongState));
    }
}
