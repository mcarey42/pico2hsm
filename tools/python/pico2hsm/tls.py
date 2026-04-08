"""Daemon TLS identity management for pico2hsm cluster."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import ssl
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Files stored in config_dir
DAEMON_CERT_FILE = "daemon.crt"
DAEMON_KEY_FILE = "daemon.key"
KNOWN_PEERS_FILE = "known_peers.json"


def ensure_daemon_identity(config_dir: Path) -> tuple[Path, Path]:
    """Ensure daemon has a persistent TLS identity. Generate on first run.

    Creates RSA-2048 self-signed X.509 certificate if not present.
    Sets file permissions to 0o600 for key, 0o644 for cert.

    Returns (cert_path, key_path).
    """
    config_dir = Path(config_dir)
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    cert_path = config_dir / DAEMON_CERT_FILE
    key_path = config_dir / DAEMON_KEY_FILE

    if not cert_path.exists() or not key_path.exists():
        _generate_identity(cert_path, key_path)
        logger.info("Generated new daemon TLS identity: %s", cert_path)
    else:
        # Verify key file permissions
        _check_key_permissions(key_path)

    return cert_path, key_path


def get_cert_fingerprint(cert_path: Path) -> bytes:
    """Return SHA-256 fingerprint of a PEM certificate (32 bytes)."""
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography import x509

    cert_pem = cert_path.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_pem)
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).digest()


def create_mtls_server_context(
    cert_path: Path,
    key_path: Path,
    peer_certs: list[Path],
) -> ssl.SSLContext:
    """Create mTLS server context requiring client cert verification.

    peer_certs: list of trusted peer certificate files.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    if peer_certs:
        ctx.verify_mode = ssl.CERT_REQUIRED
        for peer_cert in peer_certs:
            ctx.load_verify_locations(str(peer_cert))
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def create_mtls_client_context(
    cert_path: Path,
    key_path: Path,
    server_cert: Optional[Path] = None,
) -> ssl.SSLContext:
    """Create mTLS client context.

    server_cert: if provided, verify server against this specific cert.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    ctx.check_hostname = False
    if server_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(str(server_cert))
    else:
        ctx.verify_mode = ssl.CERT_NONE  # fallback for development
    return ctx


def load_known_peers(config_dir: Path) -> dict[str, str]:
    """Load peer fingerprint -> cert_path mapping from known_peers.json."""
    peers_file = Path(config_dir) / KNOWN_PEERS_FILE
    if not peers_file.exists():
        return {}
    try:
        with open(peers_file) as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Failed to load known peers: %s", e)
        return {}


def enroll_peer(config_dir: Path, peer_name: str, peer_cert_pem: bytes) -> None:
    """Save a peer's certificate and update known_peers.json."""
    config_dir = Path(config_dir)
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    # Save the peer cert
    peer_cert_path = config_dir / f"peer_{peer_name}.crt"
    peer_cert_path.write_bytes(peer_cert_pem)
    peer_cert_path.chmod(0o644)

    # Compute fingerprint
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(peer_cert_pem)
    from cryptography.hazmat.primitives.serialization import Encoding
    fingerprint = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()

    # Update known_peers.json
    peers = load_known_peers(config_dir)
    peers[fingerprint] = str(peer_cert_path)

    peers_file = config_dir / KNOWN_PEERS_FILE
    with open(peers_file, "w") as f:
        json.dump(peers, f, indent=2)
    peers_file.chmod(0o600)

    logger.info("Enrolled peer %s (fingerprint %s...)", peer_name, fingerprint[:16])


def _generate_identity(cert_path: Path, key_path: Path) -> None:
    """Generate RSA-2048 key + self-signed cert. Write with strict permissions."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Write key with mode 0o600
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key_pem)

    # Build self-signed cert
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pico2hsm-daemon")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=3650)
        )
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cert_path.chmod(0o644)


def _check_key_permissions(key_path: Path) -> None:
    """Warn if key file has overly permissive permissions."""
    mode = oct(key_path.stat().st_mode & 0o777)
    if key_path.stat().st_mode & 0o077:
        logger.warning(
            "Key file %s has unsafe permissions: %s (should be 0o600)",
            key_path,
            mode,
        )
