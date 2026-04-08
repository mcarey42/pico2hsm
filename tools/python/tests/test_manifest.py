"""Tests for pico2hsm.manifest — key manifest parsing and state root computation."""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from pico2hsm.manifest import (
    MANIFEST_ENTRY_SIZE,
    MAX_KEY_SLOTS,
    KeyManifestEntry,
    compute_empty_slot_hash,
    compute_entry_hash,
    compute_state_root,
    parse_key_manifest,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_raw_entry(
    key_ref: int = 1,
    algo: int = 0x13,
    key_flags: int = 0x01,
    deleted: int = 0,
    timestamp_ms: int = 1000,
    pubkey_hash: bytes | None = None,
) -> bytes:
    """Build a raw 44-byte manifest entry."""
    if pubkey_hash is None:
        pubkey_hash = bytes([key_ref]) * 32
    return (
        bytes([key_ref, algo, key_flags, deleted])
        + struct.pack(">Q", timestamp_ms)
        + pubkey_hash
    )


def _make_entry(
    key_ref: int = 1,
    algo: int = 0x13,
    key_flags: int = 0x01,
    deleted: bool = False,
    timestamp_ms: int = 1000,
    pubkey_hash: bytes | None = None,
) -> KeyManifestEntry:
    """Build a KeyManifestEntry for testing."""
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


# ---------------------------------------------------------------------------
# parse_key_manifest tests
# ---------------------------------------------------------------------------

class TestParseKeyManifest:

    def test_parse_empty_manifest(self):
        """Empty bytes produces an empty list."""
        assert parse_key_manifest(b"") == []

    def test_parse_single_entry(self):
        """44 bytes produces one KeyManifestEntry with correct fields."""
        raw = _make_raw_entry(key_ref=5, algo=0x70, key_flags=0x03, deleted=0, timestamp_ms=42)
        entries = parse_key_manifest(raw)
        assert len(entries) == 1
        e = entries[0]
        assert e.key_ref == 5
        assert e.algo == 0x70
        assert e.key_flags == 0x03
        assert e.deleted is False
        assert e.timestamp_ms == 42
        assert e.pubkey_hash == bytes([5]) * 32

    def test_parse_wrong_length_raises(self):
        """43 bytes raises ValueError."""
        with pytest.raises(ValueError, match="not a multiple"):
            parse_key_manifest(b"\x00" * 43)

    def test_parse_tombstone_entry(self):
        """deleted=1 byte produces entry.deleted == True."""
        raw = _make_raw_entry(deleted=1)
        entries = parse_key_manifest(raw)
        assert len(entries) == 1
        assert entries[0].deleted is True

    def test_parse_multiple_entries(self):
        """Multiple concatenated entries are parsed correctly."""
        raw = _make_raw_entry(key_ref=1) + _make_raw_entry(key_ref=2) + _make_raw_entry(key_ref=3)
        entries = parse_key_manifest(raw)
        assert len(entries) == 3
        assert [e.key_ref for e in entries] == [1, 2, 3]


# ---------------------------------------------------------------------------
# compute_entry_hash tests
# ---------------------------------------------------------------------------

class TestComputeEntryHash:

    def test_compute_entry_hash_alive_key(self):
        """Alive key hash is deterministic and uses 0x01 prefix."""
        entry = _make_entry(key_ref=1, algo=0x13, key_flags=0x01, deleted=False, timestamp_ms=1000)
        h = compute_entry_hash(entry)
        assert len(h) == 32

        # Verify by recomputing manually
        ts = struct.pack(">Q", 1000)
        msg = b"\x01" + bytes([1, 0x13, 0x01]) + ts + entry.pubkey_hash
        expected = hashlib.sha256(msg).digest()
        assert h == expected

    def test_compute_entry_hash_tombstone(self):
        """Tombstone hash differs from alive hash for the same fields."""
        alive = _make_entry(deleted=False)
        tombstone = _make_entry(deleted=True)
        h_alive = compute_entry_hash(alive)
        h_tomb = compute_entry_hash(tombstone)
        assert h_alive != h_tomb

    def test_compute_empty_slot_hash(self):
        """Empty slot hash is deterministic and differs per key_ref."""
        h1 = compute_empty_slot_hash(1)
        h2 = compute_empty_slot_hash(2)
        assert len(h1) == 32
        assert len(h2) == 32
        assert h1 != h2

    def test_compute_empty_slot_hash_deterministic(self):
        """Same key_ref always produces the same hash."""
        assert compute_empty_slot_hash(42) == compute_empty_slot_hash(42)


# ---------------------------------------------------------------------------
# compute_state_root tests
# ---------------------------------------------------------------------------

class TestComputeStateRoot:

    def test_compute_state_root_empty_manifest(self):
        """No entries means all 254 slots are empty; root is deterministic."""
        root = compute_state_root([])
        assert len(root) == 32
        # Recompute manually
        leaves = b""
        for slot in range(1, MAX_KEY_SLOTS + 1):
            leaves += compute_empty_slot_hash(slot)
        expected = hashlib.sha256(leaves).digest()
        assert root == expected

    def test_compute_state_root_single_key(self):
        """One entry at key_ref=1, rest empty."""
        entry = _make_entry(key_ref=1)
        root = compute_state_root([entry])
        assert len(root) == 32

        # Manually verify
        leaves = compute_entry_hash(entry)
        for slot in range(2, MAX_KEY_SLOTS + 1):
            leaves += compute_empty_slot_hash(slot)
        expected = hashlib.sha256(leaves).digest()
        assert root == expected

    def test_compute_state_root_is_deterministic(self):
        """Same entries produce the same root."""
        entries = [_make_entry(key_ref=1), _make_entry(key_ref=10)]
        root1 = compute_state_root(entries)
        root2 = compute_state_root(entries)
        assert root1 == root2

    def test_compute_state_root_changes_on_add(self):
        """Adding an entry changes the root."""
        root_empty = compute_state_root([])
        root_with_key = compute_state_root([_make_entry(key_ref=1)])
        assert root_empty != root_with_key

    def test_compute_state_root_changes_on_delete(self):
        """Tombstoning an entry changes the root."""
        alive = _make_entry(key_ref=1, deleted=False)
        tombstone = _make_entry(key_ref=1, deleted=True)
        root_alive = compute_state_root([alive])
        root_tomb = compute_state_root([tombstone])
        assert root_alive != root_tomb
