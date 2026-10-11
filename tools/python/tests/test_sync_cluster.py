"""Tests for cluster sync methods on SyncManager.

Tests full_sync() and verify_sync() using MockPico2HSM -- no hardware required.
Because manifest.py and cluster.py may not exist in this worktree, we mock
the cluster/manifest imports and inject the needed types directly.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from conftest import MockPico2HSM


# ---------------------------------------------------------------------------
# Stub types that mirror the manifest.py / cluster.py spec
# ---------------------------------------------------------------------------

@dataclass
class KeyManifestEntry:
    key_ref: int
    algo: int
    key_flags: int
    deleted: bool
    timestamp_ms: int
    pubkey_hash: bytes


@dataclass
class SyncPlan:
    missing_on_secondary: list
    conflicts: list
    tombstone_on_secondary: list
    orphans: list


@dataclass
class SyncResult:
    success: bool
    keys_transferred: int
    keys_deleted: int
    conflicts_resolved: int
    error: Optional[str] = None


def diff_manifests(primary, secondary):
    """Stub diff_manifests: computes missing keys based on key_ref sets."""
    primary_refs = {e.key_ref for e in primary if not e.deleted}
    secondary_refs = {e.key_ref for e in secondary if not e.deleted}
    missing = sorted(primary_refs - secondary_refs)
    orphans = sorted(secondary_refs - primary_refs)
    return SyncPlan(
        missing_on_secondary=missing,
        conflicts=[],
        tombstone_on_secondary=[],
        orphans=orphans,
    )


def compute_state_root(entries):
    """Stub: hash of sorted key_refs."""
    import hashlib
    refs = sorted(e.key_ref for e in entries)
    return hashlib.sha256(b"".join(r.to_bytes(2, "big") for r in refs)).digest()


# Valid 40-byte wrapped blob
VALID_BLOB_40 = bytes(range(8)) + bytes([12]) + bytes(range(9, 40))  # byte 8: CardContact EC


# ---------------------------------------------------------------------------
# Helpers to build a SyncManager with mocked cluster imports
# ---------------------------------------------------------------------------

def _make_sync_manager():
    """Create a SyncManager with mocked persistence and config."""
    from pico2hsm.state import SyncState

    config = MagicMock()
    persistence = MagicMock()
    persistence.load.return_value = SyncState()

    # Import SyncManager after patching
    from pico2hsm.sync import SyncManager
    mgr = SyncManager(config, persistence, quorum_required=1)
    return mgr, persistence


class _patch_cluster_available:
    """Context manager that patches _CLUSTER_AVAILABLE and injects stub types into sync module."""

    def __enter__(self):
        import pico2hsm.sync as sync_mod
        self._mod = sync_mod
        self._originals = {}
        patches = {
            "_CLUSTER_AVAILABLE": True,
            "diff_manifests": diff_manifests,
            "ClusterSyncResult": SyncResult,
            "KeyManifestEntry": KeyManifestEntry,
            "compute_state_root": compute_state_root,
        }
        for attr, value in patches.items():
            self._originals[attr] = getattr(sync_mod, attr, _SENTINEL)
            setattr(sync_mod, attr, value)
        return self

    def __exit__(self, *args):
        for attr, orig in self._originals.items():
            if orig is _SENTINEL:
                delattr(self._mod, attr)
            else:
                setattr(self._mod, attr, orig)


_SENTINEL = object()


# ---------------------------------------------------------------------------
# full_sync tests
# ---------------------------------------------------------------------------

class TestFullSync:

    def test_full_sync_already_in_sync(self):
        """Same manifests on both devices -> SyncResult with 0 transferred."""
        mgr, _ = _make_sync_manager()

        primary = MockPico2HSM()
        secondary = MockPico2HSM()

        entry = KeyManifestEntry(key_ref=1, algo=0x13, key_flags=0, deleted=False,
                                 timestamp_ms=1000, pubkey_hash=bytes(32))
        manifest = [entry]
        state_hash = (1, bytes(32), bytes(64))

        # Mock get_manifest and get_state_hash on the manager
        # Also mock get_generation for ensure_dkek check
        primary.get_key_manifest = MagicMock(return_value=manifest)
        secondary.get_key_manifest = MagicMock(return_value=list(manifest))
        primary.get_state_hash = MagicMock(return_value=state_hash)
        secondary.get_state_hash = MagicMock(return_value=state_hash)

        # Queue generation responses (ensure_dkek=True)
        # get_generation sends EXTRAS APDU, returns 4 bytes BE
        primary.queue_response(bytes([0, 0, 0, 5]), sw=0x9000)  # primary gen
        secondary.queue_response(bytes([0, 0, 0, 5]), sw=0x9000)  # secondary gen (equal)

        with _patch_cluster_available():
            result = mgr.full_sync(primary, secondary)

        assert result.success
        assert result.keys_transferred == 0
        assert result.keys_deleted == 0

    def test_full_sync_transfers_missing_key(self):
        """Primary has key 1, secondary doesn't -> transferred=1."""
        mgr, _ = _make_sync_manager()

        primary = MockPico2HSM()
        secondary = MockPico2HSM()

        primary_manifest = [
            KeyManifestEntry(key_ref=1, algo=0x13, key_flags=0, deleted=False,
                             timestamp_ms=1000, pubkey_hash=bytes(32)),
        ]
        secondary_manifest = []
        state_hash = (1, bytes(32), bytes(64))

        primary.get_key_manifest = MagicMock(return_value=primary_manifest)
        secondary.get_key_manifest = MagicMock(return_value=secondary_manifest)
        primary.get_state_hash = MagicMock(return_value=state_hash)
        secondary.get_state_hash = MagicMock(return_value=state_hash)

        # Generation: same (skip DKEK relay)
        primary.queue_response(bytes([0, 0, 0, 5]), sw=0x9000)
        secondary.queue_response(bytes([0, 0, 0, 5]), sw=0x9000)

        # transfer_keys will call: export from primary, import to secondary
        primary.queue_response(VALID_BLOB_40, sw=0x9000)  # export key 1
        secondary.queue_response(b"", sw=0x9000)           # import key 1

        with _patch_cluster_available():
            result = mgr.full_sync(primary, secondary)

        assert result.success
        assert result.keys_transferred == 1


# ---------------------------------------------------------------------------
# verify_sync tests
# ---------------------------------------------------------------------------

class TestVerifySync:

    def test_verify_sync_all_match(self):
        """All devices return same state root -> all values equal."""
        mgr, _ = _make_sync_manager()

        root = bytes([0xAA] * 32)
        sig = bytes(64)

        dev_a = MockPico2HSM()
        dev_b = MockPico2HSM()
        dev_c = MockPico2HSM()

        dev_a.get_state_hash = MagicMock(return_value=(1, root, sig))
        dev_b.get_state_hash = MagicMock(return_value=(1, root, sig))
        dev_c.get_state_hash = MagicMock(return_value=(1, root, sig))

        # Patch get_state_hash on the manager to use device method
        mgr.get_state_hash = lambda dev: dev.get_state_hash()

        result = mgr.verify_sync([("a", dev_a), ("b", dev_b), ("c", dev_c)])

        assert result["a"] == root
        assert result["b"] == root
        assert result["c"] == root
        assert result["a"] == result["b"] == result["c"]

    def test_verify_sync_diverged(self):
        """One device has different root -> detected in return dict."""
        mgr, _ = _make_sync_manager()

        root_a = bytes([0xAA] * 32)
        root_b = bytes([0xBB] * 32)
        sig = bytes(64)

        dev_a = MockPico2HSM()
        dev_b = MockPico2HSM()

        dev_a.get_state_hash = MagicMock(return_value=(1, root_a, sig))
        dev_b.get_state_hash = MagicMock(return_value=(1, root_b, sig))

        mgr.get_state_hash = lambda dev: dev.get_state_hash()

        result = mgr.verify_sync([("a", dev_a), ("b", dev_b)])

        assert result["a"] == root_a
        assert result["b"] == root_b
        assert result["a"] != result["b"]

    def test_verify_sync_device_failure(self):
        """Failed device returns None in result dict."""
        mgr, _ = _make_sync_manager()

        root = bytes([0xAA] * 32)
        sig = bytes(64)

        dev_a = MockPico2HSM()
        dev_b = MockPico2HSM()

        dev_a.get_state_hash = MagicMock(return_value=(1, root, sig))
        dev_b.get_state_hash = MagicMock(side_effect=Exception("device offline"))

        # Let the manager's get_state_hash handle the exception
        result = mgr.verify_sync([("a", dev_a), ("b", dev_b)])

        assert result["a"] == root
        assert result["b"] is None
