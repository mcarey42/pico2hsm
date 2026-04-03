//! Error types for the pico2hsm HSM firmware.
//!
//! All errors in the system are represented as variants of `HsmError`, which
//! wraps domain-specific sub-error enums. This allows callers to match at
//! whatever granularity they need.

/// Top-level error type returned by all HSM operations.
#[derive(Debug, Clone, PartialEq)]
pub enum HsmError {
    /// A storage (flash/SDCard) error occurred.
    Storage(StorageError),
    /// A cryptographic operation failed.
    Crypto(CryptoError),
    /// An APDU protocol violation was detected.
    Protocol(ProtocolError),
    /// An authentication or authorization failure occurred.
    Auth(AuthError),
    /// A parameter or input value was invalid.
    InvalidInput,
    /// The requested object was not found.
    NotFound,
    /// The requested operation is not supported by this build.
    NotSupported,
    /// The HSM is temporarily unable to service the request.
    Busy,
}

/// Storage layer errors.
#[derive(Debug, Clone, PartialEq)]
pub enum StorageError {
    /// A flash read operation failed.
    ReadError,
    /// A flash write/program operation failed.
    WriteError,
    /// A sector erase operation failed.
    EraseError,
    /// The chip has exceeded its rated erase cycle count.
    ChipDegraded,
    /// BLAKE2s / CRC32 integrity check failed on a stored object.
    IntegrityFailure,
    /// The keystore has no free sectors for a new key.
    KeystoreFull,
    /// The keystore has never been formatted (SECTOR_MAGIC missing).
    NotFormatted,
    /// A specific sector on a specific chip has permanently failed.
    BadBlock { chip: u8, sector: u32 },
}

/// Cryptographic operation errors.
#[derive(Debug, Clone, PartialEq)]
pub enum CryptoError {
    /// The RNG failed to produce entropy.
    RngFailure,
    /// A key derivation operation failed (bad input length, etc.).
    KdfFailure,
    /// An ECDSA or RSA signature operation failed.
    SignFailure,
    /// A signature verification failed.
    VerifyFailure,
    /// An ECDH key agreement failed.
    EcdhFailure,
    /// An AES-GCM or ChaCha20-Poly1305 encryption failure (e.g. bad nonce).
    EncryptFailure,
    /// An authenticated decryption tag mismatch.
    DecryptFailure,
    /// The requested curve or algorithm is not supported.
    UnsupportedAlgorithm,
    /// Key material was the wrong length for the operation.
    WrongKeyLength,
    /// The input plaintext or ciphertext exceeded internal buffer limits.
    BufferTooSmall,
}

/// APDU protocol errors.
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolError {
    /// The APDU was shorter than the minimum 4 bytes.
    ApduTooShort,
    /// The Lc field claimed more data than the buffer contains.
    LcMismatch,
    /// The Le field value is out of range.
    InvalidLe,
    /// The CLA byte is not supported by any loaded protocol.
    UnsupportedClass,
    /// The INS byte is not implemented by the selected protocol.
    UnsupportedInstruction,
    /// A required TLV tag was absent from the command data.
    MissingTag,
    /// A TLV structure was malformed (bad length encoding, truncated, etc.).
    MalformedTlv,
    /// The state machine is in the wrong state for this command.
    WrongState,
}

/// Authentication and authorization errors.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthError {
    /// The presented PIN was incorrect.
    WrongPin,
    /// The PIN retry counter has reached zero; the PIN is locked.
    PinLocked,
    /// The presented SO-PIN was incorrect.
    WrongSoPIN,
    /// The requested operation requires authentication that has not been performed.
    NotAuthenticated,
}

impl From<StorageError> for HsmError {
    fn from(e: StorageError) -> Self {
        HsmError::Storage(e)
    }
}

impl From<CryptoError> for HsmError {
    fn from(e: CryptoError) -> Self {
        HsmError::Crypto(e)
    }
}

impl From<ProtocolError> for HsmError {
    fn from(e: ProtocolError) -> Self {
        HsmError::Protocol(e)
    }
}

impl From<AuthError> for HsmError {
    fn from(e: AuthError) -> Self {
        HsmError::Auth(e)
    }
}
