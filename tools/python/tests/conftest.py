"""Shared pytest fixtures for pico2hsm tests.

All tests in this suite run without hardware — the HSM device is never
contacted.  We use lightweight stubs/mocks where needed.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Make sure the package is importable from the test directory
sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Common test data
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_so_pin() -> str:
    return "12345678"


@pytest.fixture()
def sample_pin() -> str:
    return "123456"


@pytest.fixture()
def sample_label() -> str:
    return "test-hsm"


@pytest.fixture()
def sample_dkek() -> bytes:
    """A fixed 32-byte DKEK for deterministic test cases."""
    return bytes(range(32))


@pytest.fixture()
def sample_aes_key() -> bytes:
    """A fixed 32-byte AES-256 key."""
    return bytes([0xAA] * 32)


@pytest.fixture()
def sample_ec_private_key():
    """An in-memory EC P-256 private key."""
    from cryptography.hazmat.primitives.asymmetric import ec
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture()
def sample_rsa_private_key():
    """A small RSA key for fast tests (1024-bit — not for production)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


# ---------------------------------------------------------------------------
# Mock Pico2HSM (no hardware)
# ---------------------------------------------------------------------------

class MockPico2HSM:
    """Minimal mock of Pico2HSM that records transmitted APDUs."""

    def __init__(self):
        self.transmitted: list[bytes] = []
        self._responses: list[tuple[bytes, int]] = []
        self._connected = True

    def queue_response(self, data: bytes = b"", sw: int = 0x9000) -> None:
        self._responses.append((data, sw))

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        self.transmitted.append(apdu)
        if self._responses:
            return self._responses.pop(0)
        return b"", 0x9000

    def select_applet(self) -> None:
        pass

    def connect(self) -> None:
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.disconnect()


@pytest.fixture()
def mock_hsm() -> MockPico2HSM:
    return MockPico2HSM()
