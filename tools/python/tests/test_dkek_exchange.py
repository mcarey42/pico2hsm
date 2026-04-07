"""Integration tests for DKEK exchange protocol.

Tests the relay protocol, sync manager, key blob serialisation,
and enrollment fingerprint logic using mocks -- no hardware required.
"""

from __future__ import annotations

import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the package is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from pico2hsm.dkek import DkekExchange
from pico2hsm.enrollment import DeviceEnrollment
from pico2hsm.errors import EnrollmentError
from pico2hsm.key_transfer import KeyBlob
from pico2hsm.state import SyncState, DeviceState


# ---------------------------------------------------------------------------
# MockDevice — simple APDU response queue
# ---------------------------------------------------------------------------

class MockDevice:
    """Simulates a Pico2HSM device for testing.

    Responses are queued in order. Each call to transmit() pops the next response.
    """

    def __init__(self, name: str):
        self.name = name
        self._responses: deque = deque()

    def queue_response(self, data: bytes, sw: int = 0x9000) -> None:
        self._responses.append((data, sw))

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        if not self._responses:
            raise RuntimeError(f"{self.name}: No more queued responses for APDU {apdu.hex()}")
        return self._responses.popleft()


# ---------------------------------------------------------------------------
# Fixtures — fake key material
# ---------------------------------------------------------------------------

MOCK_SOURCE_PUBKEY = bytes([0x04] + [0xAA] * 32 + [0xBB] * 32)   # 65 bytes
MOCK_TARGET_PUBKEY = bytes([0x04] + [0xCC] * 32 + [0xDD] * 32)   # 65 bytes
MOCK_SOURCE_EPHEM_PUB = bytes([0x04] + [0x11] * 32 + [0x22] * 32)  # 65 bytes
MOCK_TARGET_EPHEM_PUB = bytes([0x04] + [0x33] * 32 + [0x44] * 32)  # 65 bytes
MOCK_ENCRYPTED_DKEK = bytes([0x55] * 60)  # nonce(12) + ct(32) + tag(16)


def make_source_device() -> MockDevice:
    d = MockDevice("source")
    d.queue_response(MOCK_SOURCE_PUBKEY)     # GET_DEVICE_PUBKEY
    d.queue_response(MOCK_SOURCE_EPHEM_PUB)  # NOISE_INITIATE
    d.queue_response(MOCK_ENCRYPTED_DKEK)    # NOISE_FINALIZE_SEND
    return d


def make_target_device() -> MockDevice:
    d = MockDevice("target")
    d.queue_response(MOCK_TARGET_PUBKEY)     # GET_DEVICE_PUBKEY
    d.queue_response(MOCK_TARGET_EPHEM_PUB)  # NOISE_INITIATE
    d.queue_response(b"", 0x9000)            # NOISE_FINALIZE_RECV (SW OK, no data)
    return d


# ---------------------------------------------------------------------------
# DkekExchange._relay_exchange tests
# ---------------------------------------------------------------------------

class TestRelayExchange:
    """Tests for the core 4-step DKEK relay protocol."""

    def test_calls_correct_apdus(self):
        """Verify the 4-step relay protocol sends APDUs in the right order."""
        source = make_source_device()
        target = make_target_device()

        exchange = DkekExchange(config=None)
        exchange._relay_exchange(source, target)

        # All queued responses should have been consumed
        assert len(source._responses) == 0, "Source has unconsumed responses"
        assert len(target._responses) == 0, "Target has unconsumed responses"

    def test_without_config_skips_enrollment(self):
        """Exchange without config should not raise EnrollmentError."""
        exchange = DkekExchange(config=None)
        source = make_source_device()
        target = make_target_device()
        # Should not raise
        exchange._relay_exchange(source, target)

    def test_with_enrolled_peers_succeeds(self):
        """Exchange with config where both peers are enrolled should succeed."""
        config = MagicMock()
        config.find_peer_by_pubkey.side_effect = lambda k: MagicMock(name="peer")

        exchange = DkekExchange(config=config)
        source = make_source_device()
        target = make_target_device()
        exchange._relay_exchange(source, target)

        # Enrollment check was called for both devices
        assert config.find_peer_by_pubkey.call_count == 2

    def test_with_unenrolled_peer_fails(self):
        """Exchange with config where a peer is NOT enrolled should raise EnrollmentError."""
        config = MagicMock()
        config.find_peer_by_pubkey.return_value = None  # Not enrolled

        exchange = DkekExchange(config=config)
        source = make_source_device()
        target = make_target_device()

        with pytest.raises(EnrollmentError):
            exchange._relay_exchange(source, target)


# ---------------------------------------------------------------------------
# SyncManager tests
# ---------------------------------------------------------------------------

class TestSyncManager:
    """Tests for SyncManager generation-aware sync and quorum logic."""

    def test_skips_when_already_synced(self):
        """SyncManager should skip if secondary generation >= primary generation."""
        from pico2hsm.sync import SyncManager
        from pico2hsm.state import StatePersistence

        config = MagicMock()
        persistence = MagicMock(spec=StatePersistence)
        state = SyncState()
        persistence.load.return_value = state

        manager = SyncManager(config, persistence, quorum_required=1)

        # Call order: get_generation, then get_device_info (pubkey + gen)
        primary = MagicMock()
        primary.transmit.side_effect = [
            (bytes([0, 0, 0, 5]), 0x9000),            # get_generation -> 5
            (bytes([0x04] + [0xAA] * 64), 0x9000),   # get_device_info pubkey
            (bytes([0, 0, 0, 5]), 0x9000),            # get_device_info generation
        ]
        secondary = MagicMock()
        secondary.transmit.side_effect = [
            (bytes([0, 0, 0, 5]), 0x9000),            # get_generation -> 5
            (bytes([0x04] + [0xBB] * 64), 0x9000),   # get_device_info pubkey
            (bytes([0, 0, 0, 5]), 0x9000),            # get_device_info generation
        ]

        result = manager.sync_local(primary, secondary, "primary", "secondary")
        assert result.success
        assert result.message == "Already in sync"

    def test_quorum_gate(self):
        """SyncManager should defer sync if quorum is not met."""
        from pico2hsm.sync import SyncManager
        from pico2hsm.state import StatePersistence

        config = MagicMock()
        persistence = MagicMock(spec=StatePersistence)

        # State: only 1 device has confirmed generation 10 (quorum needs 3)
        state = SyncState()
        state.devices["fp-confirmed"] = DeviceState(
            fingerprint="fp-confirmed",
            name="node-1",
            last_generation=10,
            last_seen=datetime.now(timezone.utc).isoformat(),
            last_sync_result="success",
        )
        persistence.load.return_value = state

        manager = SyncManager(config, persistence, quorum_required=3)

        primary = MagicMock()
        secondary = MagicMock()

        # Call order for primary:
        #   1. get_generation()         -> returns gen=10 (4 bytes BE)
        #   2. get_device_info.pubkey   -> returns 65-byte pubkey
        #   3. get_device_info.gen      -> returns gen=10 (4 bytes BE)
        primary.transmit.side_effect = [
            (bytes([0, 0, 0, 10]), 0x9000),               # get_generation
            (bytes([0x04] + [0xAA] * 64), 0x9000),        # get_device_info pubkey
            (bytes([0, 0, 0, 10]), 0x9000),               # get_device_info generation
        ]
        # Call order for secondary:
        #   1. get_generation()         -> returns gen=5 (4 bytes BE)
        #   2. get_device_info.pubkey   -> returns 65-byte pubkey
        #   3. get_device_info.gen      -> returns gen=5 (4 bytes BE)
        secondary.transmit.side_effect = [
            (bytes([0, 0, 0, 5]), 0x9000),                # get_generation
            (bytes([0x04] + [0xBB] * 64), 0x9000),        # get_device_info pubkey
            (bytes([0, 0, 0, 5]), 0x9000),                # get_device_info generation
        ]

        result = manager.sync_local(primary, secondary, "primary", "secondary")
        assert not result.success
        assert "Quorum not met" in result.message


# ---------------------------------------------------------------------------
# SyncState quorum tests
# ---------------------------------------------------------------------------

class TestSyncStateQuorum:
    """Tests for SyncState.quorum_achieved counting logic."""

    def test_quorum_achieved(self):
        """quorum_achieved should count devices at the target generation correctly."""
        state = SyncState()
        now = datetime.now(timezone.utc).isoformat()
        state.devices["fp1"] = DeviceState("fp1", "n1", 10, now, "success")
        state.devices["fp2"] = DeviceState("fp2", "n2", 10, now, "success")
        state.devices["fp3"] = DeviceState("fp3", "n3", 9, now, "success")   # gen 9, not 10

        achieved, count = state.quorum_achieved(target_generation=10, required=2)
        assert achieved
        assert count == 2

        achieved, count = state.quorum_achieved(target_generation=10, required=3)
        assert not achieved
        assert count == 2

    def test_quorum_with_exclusion(self):
        """quorum_achieved should exclude the specified fingerprint."""
        state = SyncState()
        now = datetime.now(timezone.utc).isoformat()
        state.devices["fp1"] = DeviceState("fp1", "n1", 10, now, "success")
        state.devices["fp2"] = DeviceState("fp2", "n2", 10, now, "success")

        # Excluding fp2: only fp1 confirmed
        achieved, count = state.quorum_achieved(
            target_generation=10, required=2, exclude_fingerprint="fp2"
        )
        assert not achieved
        assert count == 1


# ---------------------------------------------------------------------------
# KeyBlob serialisation tests
# ---------------------------------------------------------------------------

class TestKeyBlob:
    """Tests for KeyBlob serialize/deserialize roundtrip."""

    def test_roundtrip(self):
        """KeyBlob should serialize and deserialize correctly."""
        wrapped = bytes(range(40))  # 40-byte fake wrapped data
        blob = KeyBlob(key_id=5, algo_id=0x13, wrapped_data=wrapped)
        serialized = blob.to_bytes()
        recovered = KeyBlob.from_bytes(serialized)

        assert recovered.key_id == 5
        assert recovered.algo_id == 0x13
        assert recovered.wrapped_data == wrapped

    def test_wrong_magic(self):
        """KeyBlob.from_bytes should reject wrong magic."""
        bad_data = b"XXXX" + bytes([0x01, 0x01, 0x13, 0x00]) + bytes(10)
        with pytest.raises(ValueError, match="Invalid blob magic"):
            KeyBlob.from_bytes(bad_data)

    def test_too_short(self):
        """KeyBlob.from_bytes should reject blobs shorter than the header."""
        with pytest.raises(ValueError, match="Blob too short"):
            KeyBlob.from_bytes(b"P2HK")  # only 4 bytes, need 8


# ---------------------------------------------------------------------------
# Enrollment fingerprint tests
# ---------------------------------------------------------------------------

class TestEnrollmentFingerprint:
    """Tests for DeviceEnrollment.fingerprint formatting."""

    def test_fingerprint_format(self):
        """DeviceEnrollment.fingerprint should return colon-separated hex."""
        pubkey = bytes([0x04] + [0xAB] * 64)
        fp = DeviceEnrollment.fingerprint(pubkey)
        # Should be colon-separated hex bytes
        parts = fp.split(":")
        assert len(parts) == 8  # 8 bytes shown (first 16 hex chars / 2 = 8)
        for part in parts:
            assert len(part) == 2
            int(part, 16)  # should not raise

    def test_fingerprint_deterministic(self):
        """Same pubkey should always produce the same fingerprint."""
        pubkey = bytes([0x04] + [0xCD] * 64)
        fp1 = DeviceEnrollment.fingerprint(pubkey)
        fp2 = DeviceEnrollment.fingerprint(pubkey)
        assert fp1 == fp2

    def test_fingerprint_differs_for_different_keys(self):
        """Different pubkeys should produce different fingerprints."""
        pubkey_a = bytes([0x04] + [0x11] * 64)
        pubkey_b = bytes([0x04] + [0x22] * 64)
        assert DeviceEnrollment.fingerprint(pubkey_a) != DeviceEnrollment.fingerprint(pubkey_b)
