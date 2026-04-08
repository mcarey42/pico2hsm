"""Tests for pico2hsm TLS identity management, dual-mode TLS, and security hardening."""

from __future__ import annotations

import datetime
import logging
import socket
import ssl
import struct
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Make sure the package is importable from the test directory
sys.path.insert(0, str(Path(__file__).parent.parent))

from pico2hsm.tls import (
    ensure_daemon_identity,
    get_cert_fingerprint,
    create_server_context,
    create_client_context,
    check_cert_expiry,
    check_cert_expiry_file,
)
from pico2hsm.state import SyncState, DeviceState, StatePersistence
from pico2hsm.dkek import _recv_framed, MAGIC, MAX_FRAME_SIZE
from pico2hsm.errors import DKEKError


# ---------------------------------------------------------------------------
# Helper: generate a CA + signed cert for testing
# ---------------------------------------------------------------------------

def _generate_ca(tmp_path: Path) -> tuple[Path, "cryptography.x509.Certificate", "ec.EllipticCurvePrivateKey"]:
    """Generate a self-signed CA cert+key. Returns (ca_cert_path, ca_cert, ca_key)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=3650)
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = tmp_path / "ca.crt"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return ca_path, ca_cert, ca_key


def _generate_signed_cert(
    tmp_path: Path,
    ca_cert,
    ca_key,
    cn: str,
    prefix: str = "node",
    days_valid: int = 365,
) -> tuple[Path, Path]:
    """Generate a cert signed by the given CA. Returns (cert_path, key_path)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import os

    key = ec.generate_private_key(ec.SECP256R1())
    key_path = tmp_path / f"{prefix}.key"
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=days_valid)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_path = tmp_path / f"{prefix}.crt"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cert_path.chmod(0o644)
    return cert_path, key_path


def _generate_expiring_cert(
    tmp_path: Path,
    prefix: str = "expiring",
    days_remaining: int = 30,
) -> tuple[Path, Path]:
    """Generate a self-signed cert that expires in days_remaining days."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import os

    key = ec.generate_private_key(ec.SECP256R1())
    key_path = tmp_path / f"{prefix}.key"
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pico2hsm-daemon")])
    # Set not_valid_before to some time in the past so the cert is currently valid
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=30)
        )
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=days_remaining)
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / f"{prefix}.crt"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    cert_path.chmod(0o644)
    return cert_path, key_path


# ---------------------------------------------------------------------------
# TLS identity tests
# ---------------------------------------------------------------------------

def test_ensure_daemon_identity_creates_files(tmp_path):
    """ensure_daemon_identity creates cert and key files."""
    cert_path, key_path = ensure_daemon_identity(tmp_path)
    assert cert_path.exists()
    assert key_path.exists()
    assert cert_path.name == "daemon.crt"
    assert key_path.name == "daemon.key"


def test_ensure_daemon_identity_idempotent(tmp_path):
    """Calling ensure_daemon_identity twice does not regenerate the cert."""
    cert_path, key_path = ensure_daemon_identity(tmp_path)
    cert_content = cert_path.read_bytes()
    key_content = key_path.read_bytes()

    cert_path2, key_path2 = ensure_daemon_identity(tmp_path)
    assert cert_path2.read_bytes() == cert_content
    assert key_path2.read_bytes() == key_content


def test_key_file_permissions(tmp_path):
    """Key file must have mode 0o600."""
    _cert_path, key_path = ensure_daemon_identity(tmp_path)
    mode = key_path.stat().st_mode & 0o777
    assert mode == 0o600, f"Key file permissions are {oct(mode)}, expected 0o600"


def test_cert_file_permissions(tmp_path):
    """Cert file must have mode 0o644."""
    cert_path, _key_path = ensure_daemon_identity(tmp_path)
    mode = cert_path.stat().st_mode & 0o777
    assert mode == 0o644, f"Cert file permissions are {oct(mode)}, expected 0o644"


def test_get_cert_fingerprint_returns_32_bytes(tmp_path):
    """SHA-256 fingerprint must be exactly 32 bytes."""
    cert_path, _key_path = ensure_daemon_identity(tmp_path)
    fp = get_cert_fingerprint(cert_path)
    assert isinstance(fp, bytes)
    assert len(fp) == 32


def test_get_cert_fingerprint_deterministic(tmp_path):
    """Same cert must produce the same fingerprint."""
    cert_path, _key_path = ensure_daemon_identity(tmp_path)
    fp1 = get_cert_fingerprint(cert_path)
    fp2 = get_cert_fingerprint(cert_path)
    assert fp1 == fp2


# ---------------------------------------------------------------------------
# P-256 identity test
# ---------------------------------------------------------------------------

def test_p256_identity_generated(tmp_path):
    """Generated cert uses EC P-256 key, not RSA."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec

    cert_path, _key_path = ensure_daemon_identity(tmp_path)
    cert_pem = cert_path.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_pem)
    pub = cert.public_key()
    assert isinstance(pub, ec.EllipticCurvePublicKey), (
        f"Expected EC public key, got {type(pub).__name__}"
    )
    assert isinstance(pub.curve, ec.SECP256R1), (
        f"Expected SECP256R1, got {type(pub.curve).__name__}"
    )


# ---------------------------------------------------------------------------
# Anonymous mode TLS connection test
# ---------------------------------------------------------------------------

def test_anonymous_mode_connects(tmp_path):
    """Two endpoints with no CA connect successfully in anonymous mode."""
    # Generate identities for server and client
    server_dir = tmp_path / "server"
    client_dir = tmp_path / "client"
    srv_cert, srv_key = ensure_daemon_identity(server_dir)
    cli_cert, cli_key = ensure_daemon_identity(client_dir)

    server_ctx = create_server_context(
        cert_path=str(srv_cert),
        key_path=str(srv_key),
        ca_cert=None,  # anonymous mode
    )
    client_ctx = create_client_context(
        cert_path=str(cli_cert),
        key_path=str(cli_key),
        ca_cert=None,  # anonymous mode
    )

    # Create a socketpair and wrap both sides
    s_sock, c_sock = socket.socketpair()
    connected = threading.Event()
    server_result = {}

    def server_thread():
        try:
            ssl_s = server_ctx.wrap_socket(s_sock, server_side=True)
            ssl_s.sendall(b"hello")
            server_result["ok"] = True
            ssl_s.close()
        except Exception as e:
            server_result["error"] = str(e)

    t = threading.Thread(target=server_thread)
    t.start()

    ssl_c = client_ctx.wrap_socket(c_sock, server_side=False)
    data = ssl_c.recv(5)
    ssl_c.close()
    t.join(timeout=5)

    assert data == b"hello"
    assert server_result.get("ok") is True


# ---------------------------------------------------------------------------
# CA mode rejects wrong CA
# ---------------------------------------------------------------------------

def test_ca_mode_rejects_wrong_ca(tmp_path):
    """Peer cert signed by a different CA is rejected in CA-authenticated mode."""
    # CA 1 -- used by server
    ca1_path, ca1_cert, ca1_key = _generate_ca(tmp_path / "ca1")
    srv_cert, srv_key = _generate_signed_cert(
        tmp_path / "ca1", ca1_cert, ca1_key, "server", "server"
    )

    # CA 2 -- used by client (different CA)
    ca2_path, ca2_cert, ca2_key = _generate_ca(tmp_path / "ca2")
    cli_cert, cli_key = _generate_signed_cert(
        tmp_path / "ca2", ca2_cert, ca2_key, "client", "client"
    )

    # Server trusts CA1, client trusts CA2
    # Client connects to server: server has cert from CA1, client verifies against CA2 -> fail
    server_ctx = create_server_context(
        cert_path=str(srv_cert),
        key_path=str(srv_key),
        ca_cert=str(ca2_path),  # server expects client certs from CA2
    )
    client_ctx = create_client_context(
        cert_path=str(cli_cert),
        key_path=str(cli_key),
        ca_cert=str(ca2_path),  # client trusts only CA2
        peer_name="server",
    )

    s_sock, c_sock = socket.socketpair()
    server_error = {}

    def server_thread():
        try:
            ssl_s = server_ctx.wrap_socket(s_sock, server_side=True)
            ssl_s.close()
        except ssl.SSLError as e:
            server_error["ssl"] = str(e)
        except Exception as e:
            server_error["other"] = str(e)

    t = threading.Thread(target=server_thread)
    t.start()

    # The client should fail because the server cert (CA1) is not trusted by CA2
    with pytest.raises(ssl.SSLError):
        client_ctx.wrap_socket(c_sock, server_side=False, server_hostname="server")

    t.join(timeout=5)


# ---------------------------------------------------------------------------
# Certificate expiry warning test
# ---------------------------------------------------------------------------

def test_cert_expiry_warning_logged(tmp_path, caplog):
    """Cert with notAfter in 30 days triggers a warning."""
    cert_path, _key_path = _generate_expiring_cert(tmp_path, "expiring", days_remaining=30)
    cert_pem = cert_path.read_bytes()

    with caplog.at_level(logging.WARNING, logger="pico2hsm.tls"):
        result = check_cert_expiry(cert_pem, "test-peer", warn_days=90)

    assert result is not None
    assert result <= 30
    assert "test-peer" in caplog.text
    assert "expires in" in caplog.text


def test_cert_expiry_no_warning_for_long_lived(tmp_path, caplog):
    """Cert with 10 years left does not trigger a warning."""
    cert_path, _key_path = ensure_daemon_identity(tmp_path)
    cert_pem = cert_path.read_bytes()

    with caplog.at_level(logging.WARNING, logger="pico2hsm.tls"):
        result = check_cert_expiry(cert_pem, "test-peer", warn_days=90)

    assert result is None
    assert "expires in" not in caplog.text


# ---------------------------------------------------------------------------
# Own cert expiry at startup
# ---------------------------------------------------------------------------

def test_own_cert_expiry_checked_at_startup(tmp_path, caplog):
    """Creating a server context with a near-expiry cert logs a warning."""
    cert_path, key_path = _generate_expiring_cert(
        tmp_path, "daemon", days_remaining=30,
    )

    with caplog.at_level(logging.WARNING, logger="pico2hsm.tls"):
        ctx = create_server_context(
            cert_path=str(cert_path),
            key_path=str(key_path),
            ca_cert=None,
            warn_days=90,
        )

    assert "own daemon" in caplog.text
    assert "expires in" in caplog.text


# ---------------------------------------------------------------------------
# State schema validation tests
# ---------------------------------------------------------------------------

def test_state_schema_validation_rejects_unknown_fields():
    """State.json with extra fields loads without crashing (fields ignored)."""
    data = {
        "version": 1,
        "devices": {
            "abc123": {
                "fingerprint": "abc123",
                "name": "test-hsm",
                "last_generation": 1,
                "last_seen": "2026-01-01T00:00:00",
                "last_sync_result": "success",
                "evil_extra_field": "malicious",
            }
        },
    }
    state = SyncState.from_dict(data)
    assert "abc123" in state.devices
    device = state.devices["abc123"]
    assert device.name == "test-hsm"
    assert not hasattr(device, "evil_extra_field")


def test_state_schema_validation_rejects_wrong_type():
    """Int where string expected causes device to be skipped."""
    data = {
        "version": 1,
        "devices": {
            "abc123": {
                "fingerprint": "abc123",
                "name": 12345,  # should be str
                "last_generation": 1,
                "last_seen": "2026-01-01T00:00:00",
                "last_sync_result": "success",
            }
        },
    }
    state = SyncState.from_dict(data)
    assert "abc123" not in state.devices


# ---------------------------------------------------------------------------
# Frame size enforcement tests
# ---------------------------------------------------------------------------

def _make_mock_conn(msg_type: int, payload: bytes):
    """Build a mock socket that returns a framed message."""
    data = MAGIC + bytes([msg_type]) + struct.pack(">I", len(payload)) + payload
    chunks = [data]
    conn = MagicMock()

    def recv(n):
        if not chunks[0]:
            return b""
        chunk = chunks[0][:n]
        chunks[0] = chunks[0][n:]
        return chunk

    conn.recv.side_effect = recv
    return conn


def _make_mock_conn_raw(raw_header: bytes):
    """Build a mock socket that returns raw header bytes (no payload follows)."""
    chunks = [raw_header]
    conn = MagicMock()

    def recv(n):
        if not chunks[0]:
            return b""
        chunk = chunks[0][:n]
        chunks[0] = chunks[0][n:]
        return chunk

    conn.recv.side_effect = recv
    return conn


def test_recv_framed_rejects_oversized():
    """Frame with length > MAX_FRAME_SIZE must raise DKEKError."""
    oversized_length = MAX_FRAME_SIZE + 1
    raw = MAGIC + bytes([0x01]) + struct.pack(">I", oversized_length)
    conn = _make_mock_conn_raw(raw)
    with pytest.raises(DKEKError, match="Frame payload too large"):
        _recv_framed(conn)


def test_recv_framed_accepts_max_size():
    """Frame with exactly MAX_FRAME_SIZE payload is accepted."""
    payload = b"\x00" * MAX_FRAME_SIZE
    conn = _make_mock_conn(0x01, payload)
    msg_type, received = _recv_framed(conn)
    assert msg_type == 0x01
    assert len(received) == MAX_FRAME_SIZE


# ---------------------------------------------------------------------------
# StatePersistence file permissions test
# ---------------------------------------------------------------------------

def test_state_save_file_permissions(tmp_path):
    """State file written by save() must have mode 0o600."""
    sp = StatePersistence(state_dir=str(tmp_path / "state"))
    sp.load()
    sp.state.update_device("fp1", "test", 1, "success")
    sp.save()

    state_file = tmp_path / "state" / "state.json"
    assert state_file.exists()
    mode = state_file.stat().st_mode & 0o777
    assert mode == 0o600, f"State file permissions are {oct(mode)}, expected 0o600"
