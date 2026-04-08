"""Daemon TLS identity management for pico2hsm cluster.

Supports two modes:
  - Anonymous (default): TLS encryption only, no peer certificate verification.
  - CA-authenticated: peer certificates must be issued by a configured CA.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
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

# Default warning threshold for certificate expiry
DEFAULT_CERT_WARN_DAYS = 90


def ensure_daemon_identity(config_dir: Path) -> tuple[Path, Path]:
    """Ensure daemon has a persistent TLS identity. Generate on first run.

    Creates P-256 ECDSA self-signed X.509 certificate if not present.
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


def create_server_context(
    cert_path: str,
    key_path: str,
    ca_cert: Optional[str] = None,
    peer_cn: Optional[str] = None,
    warn_days: int = DEFAULT_CERT_WARN_DAYS,
) -> ssl.SSLContext:
    """Create TLS server context.

    If ca_cert is None: anonymous mode (encryption only, CERT_NONE).
    If ca_cert is set: CA-authenticated mode (CERT_REQUIRED, CA bundle loaded).

    Args:
        cert_path: Path to this daemon's certificate PEM.
        key_path: Path to this daemon's private key PEM.
        ca_cert: Path to CA bundle PEM for authenticated mode. None = anonymous.
        peer_cn: Expected peer CN/SAN (used with CA mode for subject check).
        warn_days: Days before expiry to log a warning for own cert.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)

    # Check own cert expiry at context creation time
    check_cert_expiry_file(cert_path, "own daemon", warn_days)

    if ca_cert is not None:
        # CA-authenticated mode
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=ca_cert)
        # Server contexts cannot use check_hostname (it requires server_hostname
        # which is only available on the client side). Manual CN/SAN checks
        # must be done after the handshake via check_peer_identity().
    else:
        # Anonymous mode: encryption only
        ctx.verify_mode = ssl.CERT_NONE

    # Use modern cipher suites
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    return ctx


def create_client_context(
    cert_path: str,
    key_path: str,
    ca_cert: Optional[str] = None,
    peer_name: Optional[str] = None,
    warn_days: int = DEFAULT_CERT_WARN_DAYS,
) -> ssl.SSLContext:
    """Create TLS client context.

    If ca_cert is None: anonymous mode (encryption only, CERT_NONE).
    If ca_cert is set: CA-authenticated mode (CERT_REQUIRED, CA bundle,
        hostname verification if peer_name is a hostname).

    Args:
        cert_path: Path to this daemon's certificate PEM.
        key_path: Path to this daemon's private key PEM.
        ca_cert: Path to CA bundle PEM for authenticated mode. None = anonymous.
        peer_name: Expected peer hostname or IP for subject verification.
        warn_days: Days before expiry to log a warning for own cert.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(cert_path, key_path)

    # Check own cert expiry at context creation time
    check_cert_expiry_file(cert_path, "own daemon", warn_days)

    if ca_cert is not None:
        # CA-authenticated mode
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=ca_cert)

        # Enable hostname checking only for actual hostnames, not raw IPs
        if peer_name and not _is_ip_address(peer_name):
            ctx.check_hostname = True
        else:
            ctx.check_hostname = False
    else:
        # Anonymous mode
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    return ctx


def check_cert_expiry(
    cert_pem: bytes,
    name: str,
    warn_days: int = DEFAULT_CERT_WARN_DAYS,
) -> Optional[int]:
    """Check certificate expiry and log a warning if it expires within warn_days.

    Args:
        cert_pem: PEM-encoded certificate bytes.
        name: Human-readable name for log messages (e.g., peer name).
        warn_days: Days before expiry to start warning.

    Returns:
        Days until expiry if within the warning window, None otherwise.
    """
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(cert_pem)
    not_after = cert.not_valid_after_utc
    now = datetime.datetime.now(datetime.timezone.utc)
    remaining = (not_after - now).days

    if remaining <= warn_days:
        expiry_date = not_after.strftime("%Y-%m-%d")
        logger.warning(
            "Peer '%s' certificate expires in %d days (%s). "
            "Renew before expiry to avoid connection failures.",
            name, remaining, expiry_date,
        )
        return remaining
    return None


def check_cert_expiry_file(
    cert_path: str,
    name: str,
    warn_days: int = DEFAULT_CERT_WARN_DAYS,
) -> Optional[int]:
    """Check certificate expiry from a file path. Convenience wrapper."""
    try:
        cert_pem = Path(cert_path).read_bytes()
        return check_cert_expiry(cert_pem, name, warn_days)
    except Exception as e:
        logger.debug("Could not check cert expiry for %s: %s", name, e)
        return None


def check_peer_cert_expiry(
    ssl_sock: ssl.SSLSocket,
    peer_name: str,
    warn_days: int = DEFAULT_CERT_WARN_DAYS,
) -> Optional[int]:
    """Check the peer certificate expiry after a successful TLS handshake.

    Args:
        ssl_sock: Connected SSLSocket after handshake.
        peer_name: Human-readable name for log messages.
        warn_days: Days before expiry to start warning.

    Returns:
        Days until expiry if within the warning window, None otherwise.
    """
    der_cert = ssl_sock.getpeercert(binary_form=True)
    if der_cert is None:
        return None

    from cryptography import x509
    cert = x509.load_der_x509_certificate(der_cert)
    not_after = cert.not_valid_after_utc
    now = datetime.datetime.now(datetime.timezone.utc)
    remaining = (not_after - now).days

    if remaining <= warn_days:
        expiry_date = not_after.strftime("%Y-%m-%d")
        logger.warning(
            "Peer '%s' certificate expires in %d days (%s). "
            "Renew before expiry to avoid connection failures.",
            peer_name, remaining, expiry_date,
        )
        return remaining
    return None


def check_peer_identity(
    ssl_sock: ssl.SSLSocket,
    expected_name: str,
) -> bool:
    """Verify peer certificate CN or SAN matches expected_name.

    Used in CA-authenticated mode for server-side checks (where
    ssl.check_hostname is not available).

    Args:
        ssl_sock: Connected SSLSocket after handshake.
        expected_name: Expected CN or SAN (hostname or IP).

    Returns:
        True if the peer identity matches.
    """
    der_cert = ssl_sock.getpeercert(binary_form=True)
    if der_cert is None:
        logger.warning("No peer certificate available for identity check")
        return False

    from cryptography import x509

    cert = x509.load_der_x509_certificate(der_cert)

    # Check Subject Alternative Names first
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        ip_addrs = [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
        if expected_name in dns_names or expected_name in ip_addrs:
            return True
    except x509.ExtensionNotFound:
        pass

    # Fall back to Common Name
    cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    for attr in cn_attrs:
        if attr.value == expected_name:
            return True

    logger.warning(
        "Peer certificate CN/SAN does not match expected name '%s'",
        expected_name,
    )
    return False


# ---------------------------------------------------------------------------
# Legacy compatibility aliases
# ---------------------------------------------------------------------------

def create_mtls_server_context(
    cert_path: Path,
    key_path: Path,
    peer_certs: list[Path],
) -> ssl.SSLContext:
    """Legacy wrapper. Use create_server_context() for new code."""
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
    """Legacy wrapper. Use create_client_context() for new code."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    ctx.check_hostname = False
    if server_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(str(server_cert))
    else:
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ---------------------------------------------------------------------------
# Peer enrollment helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _generate_identity(cert_path: Path, key_path: Path) -> None:
    """Generate P-256 ECDSA key + self-signed cert. Write with strict permissions."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())

    # Write key with mode 0o600
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key_pem)

    # Build self-signed cert with ECDSA-SHA256
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


def _is_ip_address(value: str) -> bool:
    """Return True if value is an IP address (v4 or v6)."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
