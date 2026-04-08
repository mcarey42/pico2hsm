"""Tests for pico2hsm TLS identity management and security hardening."""

from __future__ import annotations

import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Make sure the package is importable from the test directory
sys.path.insert(0, str(Path(__file__).parent.parent))

from pico2hsm.tls import ensure_daemon_identity, get_cert_fingerprint
from pico2hsm.state import SyncState, DeviceState, StatePersistence
from pico2hsm.dkek import _recv_framed, MAGIC, MAX_FRAME_SIZE
from pico2hsm.errors import DKEKError


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
