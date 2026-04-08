"""Tests for pico2hsm.cluster — cluster state comparison and sync planning."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from pico2hsm.cluster import (
    ClusterState,
    SyncPlan,
    cluster_in_sync,
    diff_manifests,
)
from pico2hsm.manifest import KeyManifestEntry, compute_state_root


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry(
    key_ref: int = 1,
    algo: int = 0x13,
    key_flags: int = 0x01,
    deleted: bool = False,
    timestamp_ms: int = 1000,
    pubkey_hash: bytes | None = None,
) -> KeyManifestEntry:
    if pubkey_hash is None:
        pubkey_hash = bytes([key_ref]) * 32
    return KeyManifestEntry(
        key_ref=key_ref,
        algo=algo,
        key_flags=key_flags,
        deleted=deleted,
        timestamp_ms=timestamp_ms,
        pubkey_hash=pubkey_hash,
    )


def _state(device_id: str, entries: list[KeyManifestEntry], generation: int = 1) -> ClusterState:
    return ClusterState(
        device_id=device_id,
        state_root=compute_state_root(entries),
        manifest=entries,
        generation=generation,
        attestation_sig=None,
    )


# ---------------------------------------------------------------------------
# diff_manifests tests
# ---------------------------------------------------------------------------

class TestDiffManifests:

    def test_diff_empty_manifests(self):
        """Both empty manifests produce an empty SyncPlan."""
        plan = diff_manifests([], [])
        assert plan.missing_on_secondary == []
        assert plan.conflicts == []
        assert plan.tombstone_on_secondary == []
        assert plan.orphans == []

    def test_diff_missing_on_secondary(self):
        """Primary has key_ref=1, secondary doesn't -> missing=[1]."""
        primary = [_entry(key_ref=1)]
        secondary: list[KeyManifestEntry] = []
        plan = diff_manifests(primary, secondary)
        assert plan.missing_on_secondary == [1]
        assert plan.conflicts == []
        assert plan.tombstone_on_secondary == []
        assert plan.orphans == []

    def test_diff_conflict(self):
        """Both have key_ref=1 but different pubkey_hash -> conflicts=[1]."""
        primary = [_entry(key_ref=1, pubkey_hash=b"\xAA" * 32)]
        secondary = [_entry(key_ref=1, pubkey_hash=b"\xBB" * 32)]
        plan = diff_manifests(primary, secondary)
        assert plan.conflicts == [1]
        assert plan.missing_on_secondary == []

    def test_diff_tombstone_propagation(self):
        """Primary tombstones key_ref=1, secondary has it alive -> tombstone_on_secondary=[1]."""
        primary = [_entry(key_ref=1, deleted=True)]
        secondary = [_entry(key_ref=1, deleted=False)]
        plan = diff_manifests(primary, secondary)
        assert plan.tombstone_on_secondary == [1]
        assert plan.conflicts == []

    def test_diff_orphan_detection(self):
        """Secondary has key_ref=5, primary doesn't -> orphans=[5]."""
        primary: list[KeyManifestEntry] = []
        secondary = [_entry(key_ref=5)]
        plan = diff_manifests(primary, secondary)
        assert plan.orphans == [5]
        assert plan.missing_on_secondary == []

    def test_diff_primary_wins_conflict(self):
        """Conflict key is in conflicts list, not missing."""
        primary = [_entry(key_ref=1, pubkey_hash=b"\xAA" * 32)]
        secondary = [_entry(key_ref=1, pubkey_hash=b"\xBB" * 32)]
        plan = diff_manifests(primary, secondary)
        assert 1 in plan.conflicts
        assert 1 not in plan.missing_on_secondary

    def test_diff_tombstoned_primary_not_missing(self):
        """A tombstoned primary key absent from secondary is not listed as missing."""
        primary = [_entry(key_ref=3, deleted=True)]
        secondary: list[KeyManifestEntry] = []
        plan = diff_manifests(primary, secondary)
        assert plan.missing_on_secondary == []

    def test_diff_matching_keys_no_action(self):
        """Keys with identical pubkey_hash and alive status need no action."""
        e = _entry(key_ref=1, pubkey_hash=b"\xCC" * 32)
        plan = diff_manifests([e], [e])
        assert plan.missing_on_secondary == []
        assert plan.conflicts == []
        assert plan.tombstone_on_secondary == []
        assert plan.orphans == []


# ---------------------------------------------------------------------------
# cluster_in_sync tests
# ---------------------------------------------------------------------------

class TestClusterInSync:

    def test_cluster_in_sync_true(self):
        """All same root -> True."""
        entries = [_entry(key_ref=1)]
        s1 = _state("dev-1", entries)
        s2 = _state("dev-2", entries)
        assert cluster_in_sync([s1, s2]) is True

    def test_cluster_in_sync_false(self):
        """Different roots -> False."""
        s1 = _state("dev-1", [_entry(key_ref=1)])
        s2 = _state("dev-2", [_entry(key_ref=2)])
        assert cluster_in_sync([s1, s2]) is False

    def test_cluster_in_sync_empty(self):
        """No states -> True."""
        assert cluster_in_sync([]) is True

    def test_cluster_in_sync_single(self):
        """Single state -> True."""
        s = _state("dev-1", [])
        assert cluster_in_sync([s]) is True
