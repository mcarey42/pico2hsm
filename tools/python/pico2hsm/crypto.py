"""Host-side cryptographic helpers for pico2hsm.

Provides key wrapping/unwrapping, certificate generation and
manipulation using the `cryptography` library.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import struct
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------------------
# Key wrapping (AES-256-CBC + HMAC-SHA256 envelope)
# ---------------------------------------------------------------------------

# KWP version tag stored in wrap blob header
KWP_VERSION = 0x01
# AES key size used for wrapping
WRAP_KEY_BITS = 256
WRAP_KEY_BYTES = WRAP_KEY_BITS // 8


class WrappedKey:
    """Represents a DKEK-wrapped key blob.

    Format (big-endian)::

        [1B version] [4B flags] [16B IV] [Nc B ciphertext] [32B HMAC-SHA256]

    The HMAC covers version + flags + IV + ciphertext.
    """

    HEADER_SIZE = 1 + 4 + 16  # version + flags + IV
    MAC_SIZE = 32

    def __init__(self, blob: bytes):
        if len(blob) < self.HEADER_SIZE + self.MAC_SIZE + 1:
            raise ValueError("Wrapped key blob too short")
        self._blob = blob

    @property
    def version(self) -> int:
        return self._blob[0]

    @property
    def flags(self) -> int:
        return struct.unpack(">I", self._blob[1:5])[0]

    @property
    def iv(self) -> bytes:
        return self._blob[5:21]

    @property
    def ciphertext(self) -> bytes:
        return self._blob[21 : -self.MAC_SIZE]

    @property
    def mac(self) -> bytes:
        return self._blob[-self.MAC_SIZE :]

    @property
    def raw(self) -> bytes:
        return self._blob

    def __len__(self) -> int:
        return len(self._blob)


def wrap_key(
    plaintext_key: bytes,
    dkek: bytes,
    flags: int = 0,
) -> WrappedKey:
    """Wrap a plaintext key under the DKEK using AES-256-CBC + HMAC-SHA256.

    Args:
        plaintext_key: Raw key material to protect.
        dkek: 32-byte Device Key Encryption Key.
        flags: Optional 4-byte flags field (key usage / type metadata).

    Returns:
        WrappedKey blob.
    """
    if len(dkek) != WRAP_KEY_BYTES:
        raise ValueError(f"DKEK must be {WRAP_KEY_BYTES} bytes, got {len(dkek)}")

    # Derive separate encryption and MAC keys from DKEK
    enc_key = _kdf(dkek, b"wrap-enc", WRAP_KEY_BYTES)
    mac_key = _kdf(dkek, b"wrap-mac", WRAP_KEY_BYTES)

    iv = os.urandom(16)
    # Pad plaintext to AES block boundary
    padded = _pkcs7_pad(plaintext_key, 16)
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    flags_b = struct.pack(">I", flags)
    header = bytes([KWP_VERSION]) + flags_b + iv
    mac_input = header + ciphertext
    mac = hmac.new(mac_key, mac_input, hashlib.sha256).digest()

    return WrappedKey(header + ciphertext + mac)


def unwrap_key(wrapped: WrappedKey, dkek: bytes) -> bytes:
    """Unwrap a key blob using the DKEK.

    Args:
        wrapped: WrappedKey instance.
        dkek: 32-byte Device Key Encryption Key.

    Returns:
        Plaintext key material.

    Raises:
        ValueError: On version mismatch or MAC failure.
    """
    if len(dkek) != WRAP_KEY_BYTES:
        raise ValueError(f"DKEK must be {WRAP_KEY_BYTES} bytes")
    if wrapped.version != KWP_VERSION:
        raise ValueError(f"Unsupported wrapped key version: {wrapped.version}")

    enc_key = _kdf(dkek, b"wrap-enc", WRAP_KEY_BYTES)
    mac_key = _kdf(dkek, b"wrap-mac", WRAP_KEY_BYTES)

    header = wrapped.raw[: WrappedKey.HEADER_SIZE]
    ciphertext = wrapped.ciphertext
    expected_mac = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()

    if not hmac.compare_digest(expected_mac, wrapped.mac):
        raise ValueError("Wrapped key MAC verification failed")

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(wrapped.iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    return _pkcs7_unpad(padded)


# ---------------------------------------------------------------------------
# DKEK share derivation from a passphrase (PBKDF2)
# ---------------------------------------------------------------------------

DKEK_SALT_SIZE = 16
DKEK_ITERATIONS = 600_000


def derive_dkek_share(passphrase: str, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
    """Derive a DKEK share from a passphrase using PBKDF2-HMAC-SHA256.

    Args:
        passphrase: User-supplied passphrase.
        salt: 16-byte salt; generated randomly if not provided.

    Returns:
        Tuple of (dkek_share_bytes, salt).
    """
    if salt is None:
        salt = os.urandom(DKEK_SALT_SIZE)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=WRAP_KEY_BYTES,
        salt=salt,
        iterations=DKEK_ITERATIONS,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    return key, salt


def xor_dkek_shares(*shares: bytes) -> bytes:
    """XOR multiple DKEK shares together to reconstruct the DKEK."""
    if not shares:
        raise ValueError("No shares provided")
    result = bytearray(shares[0])
    for share in shares[1:]:
        if len(share) != len(result):
            raise ValueError("All DKEK shares must be the same length")
        for i, b in enumerate(share):
            result[i] ^= b
    return bytes(result)


# ---------------------------------------------------------------------------
# Certificate helpers
# ---------------------------------------------------------------------------


def generate_self_signed_cert(
    private_key,
    subject_name: str = "pico2hsm",
    validity_days: int = 3650,
) -> bytes:
    """Generate a self-signed X.509 certificate for a given private key.

    Args:
        private_key: cryptography private key object (RSA or EC).
        subject_name: Common name for the certificate subject/issuer.
        validity_days: Certificate validity period in days.

    Returns:
        DER-encoded certificate bytes.
    """
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, subject_name)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def load_certificate(cert_data: bytes) -> x509.Certificate:
    """Load a DER or PEM certificate.

    Args:
        cert_data: Certificate bytes (DER or PEM).

    Returns:
        cryptography Certificate object.
    """
    if cert_data.startswith(b"-----"):
        return x509.load_pem_x509_certificate(cert_data)
    return x509.load_der_x509_certificate(cert_data)


def cert_to_pem(cert: x509.Certificate) -> bytes:
    """Convert a certificate to PEM format."""
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_to_der(cert: x509.Certificate) -> bytes:
    """Convert a certificate to DER format."""
    return cert.public_bytes(serialization.Encoding.DER)


def generate_ec_keypair(curve: str = "P-256") -> tuple[bytes, bytes]:
    """Generate an EC key pair on the host.

    Args:
        curve: Named curve ('P-256', 'P-384', 'P-521', 'secp256k1').

    Returns:
        Tuple of (private_key_pem, public_key_pem).
    """
    curve_map = {
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
        "secp256k1": ec.SECP256K1(),
    }
    if curve not in curve_map:
        raise ValueError(f"Unsupported curve: {curve}. Choose from {list(curve_map)}")
    private_key = ec.generate_private_key(curve_map[curve])
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def generate_rsa_keypair(key_size: int = 2048) -> tuple[bytes, bytes]:
    """Generate an RSA key pair on the host.

    Returns:
        Tuple of (private_key_pem, public_key_pem).
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def encrypt_aes_gcm(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt data with AES-GCM.

    Returns:
        nonce (12B) + ciphertext + tag (16B) concatenated.
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad if aad else None)
    return nonce + ct


def decrypt_aes_gcm(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Decrypt AES-GCM blob produced by :func:`encrypt_aes_gcm`."""
    nonce = blob[:12]
    ct = blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, aad if aad else None)


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------


def _kdf(key: bytes, label: bytes, length: int) -> bytes:
    """Simple HKDF-style key derivation using HMAC-SHA256."""
    return hmac.new(key, label + b"\x00", hashlib.sha256).digest()[:length]


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError(f"Invalid PKCS7 padding byte: {pad_len}")
    return data[:-pad_len]
