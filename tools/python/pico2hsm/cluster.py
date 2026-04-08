"""Cluster state comparison and sync planning."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from .manifest import KeyManifestEntry, compute_state_root


@dataclass
class ClusterState:
    """Snapshot of one HSM device's key state."""

    device_id: str                        # fingerprint
    state_root: bytes                     # 32-byte hash
    manifest: list[KeyManifestEntry]
    generation: int                       # u64 device generation
    attestation_sig: Optional[bytes]      # 64-byte device signature over (generation || state_root), or None
    captured_at: float = field(default_factory=time.time)


@dataclass
class SyncPlan:
    """What needs to happen to bring secondary in sync with primary."""

    missing_on_secondary: list[int]       # key_refs to export from primary + import to secondary
    conflicts: list[int]                  # key_refs present on both but with different pubkey_hash
    tombstone_on_secondary: list[int]     # key_refs alive on secondary but tombstoned on primary
    orphans: list[int]                    # key_refs on secondary but absent from primary


@dataclass
class SyncResult:
    """Outcome of a sync operation."""

    success: bool
    keys_transferred: int
    keys_deleted: int
    conflicts_resolved: int
    error: Optional[str] = None


def diff_manifests(
    primary: list[KeyManifestEntry],
    secondary: list[KeyManifestEntry],
) -> SyncPlan:
    """Compute what changes secondary needs to match primary.

    Matching is by key_ref. A key present on both but with different
    pubkey_hash is a conflict (primary wins). A live secondary key that
    is tombstoned on primary goes into tombstone_on_secondary.
    A secondary key with no corresponding primary entry is an orphan.
    """
    primary_map: dict[int, KeyManifestEntry] = {e.key_ref: e for e in primary}
    secondary_map: dict[int, KeyManifestEntry] = {e.key_ref: e for e in secondary}

    missing: list[int] = []
    conflicts: list[int] = []
    tombstones: list[int] = []
    orphans: list[int] = []

    # Check all primary keys against secondary
    for key_ref, p_entry in primary_map.items():
        if key_ref not in secondary_map:
            if not p_entry.deleted:
                missing.append(key_ref)
        else:
            s_entry = secondary_map[key_ref]
            if p_entry.pubkey_hash != s_entry.pubkey_hash:
                conflicts.append(key_ref)
            elif p_entry.deleted and not s_entry.deleted:
                tombstones.append(key_ref)

    # Check for orphans: secondary keys not in primary
    for key_ref in secondary_map:
        if key_ref not in primary_map:
            orphans.append(key_ref)

    return SyncPlan(
        missing_on_secondary=sorted(missing),
        conflicts=sorted(conflicts),
        tombstone_on_secondary=sorted(tombstones),
        orphans=sorted(orphans),
    )


def cluster_in_sync(states: list[ClusterState]) -> bool:
    """Return True if all states have identical state_root."""
    if not states:
        return True
    return all(s.state_root == states[0].state_root for s in states)
