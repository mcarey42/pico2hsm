"""Key manifest types and cluster state root computation."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

MANIFEST_ENTRY_SIZE = 44  # bytes per entry in GET_KEY_MANIFEST response
MAX_KEY_SLOTS = 254       # SC-HSM supports key refs 1-254


@dataclass
class KeyManifestEntry:
    key_ref: int          # u8, 1-254
    algo: int             # u8, SC-HSM algorithm identifier
    key_flags: int        # u8
    deleted: bool         # True = tombstone
    timestamp_ms: int     # u64, daemon-assigned HLC
    pubkey_hash: bytes    # 32 bytes, SHA-256 of public key


def parse_key_manifest(apdu_response: bytes) -> list[KeyManifestEntry]:
    """Parse the raw response from GET_KEY_MANIFEST into a list of entries.

    Raises ValueError if response length is not a multiple of MANIFEST_ENTRY_SIZE.
    """
    if len(apdu_response) % MANIFEST_ENTRY_SIZE != 0:
        raise ValueError(
            f"Response length {len(apdu_response)} is not a multiple of "
            f"{MANIFEST_ENTRY_SIZE}"
        )
    entries: list[KeyManifestEntry] = []
    for i in range(0, len(apdu_response), MANIFEST_ENTRY_SIZE):
        chunk = apdu_response[i : i + MANIFEST_ENTRY_SIZE]
        key_ref = chunk[0]
        algo = chunk[1]
        key_flags = chunk[2]
        deleted = chunk[3] != 0
        timestamp_ms = struct.unpack(">Q", chunk[4:12])[0]
        pubkey_hash = chunk[12:44]
        entries.append(
            KeyManifestEntry(
                key_ref=key_ref,
                algo=algo,
                key_flags=key_flags,
                deleted=deleted,
                timestamp_ms=timestamp_ms,
                pubkey_hash=pubkey_hash,
            )
        )
    return entries


def compute_entry_hash(entry: KeyManifestEntry) -> bytes:
    """Compute the Merkle leaf hash for one key entry.

    Alive key:   SHA-256(0x01 || key_ref || algo || key_flags || timestamp_ms_BE(8) || pubkey_hash(32))
    Tombstone:   SHA-256(0x02 || key_ref || algo || key_flags || timestamp_ms_BE(8) || pubkey_hash(32))
    """
    prefix = b"\x02" if entry.deleted else b"\x01"
    ts_bytes = struct.pack(">Q", entry.timestamp_ms)
    msg = (
        prefix
        + bytes([entry.key_ref, entry.algo, entry.key_flags])
        + ts_bytes
        + entry.pubkey_hash
    )
    return hashlib.sha256(msg).digest()


def compute_empty_slot_hash(key_ref: int) -> bytes:
    """SHA-256(0x00 || key_ref || [0;43])"""
    msg = b"\x00" + bytes([key_ref]) + b"\x00" * 43
    return hashlib.sha256(msg).digest()


def compute_state_root(entries: list[KeyManifestEntry]) -> bytes:
    """Compute the cluster state root over all 254 key slots.

    Build a map key_ref -> entry from the entries list.
    For each slot 1-254 in order:
      - If slot has an entry: compute_entry_hash(entry)
      - If slot is empty: compute_empty_slot_hash(slot)
    Concatenate all 254 leaf hashes, then SHA-256 the result.
    """
    entry_map: dict[int, KeyManifestEntry] = {}
    for e in entries:
        entry_map[e.key_ref] = e

    leaves = bytearray()
    for slot in range(1, MAX_KEY_SLOTS + 1):
        if slot in entry_map:
            leaves.extend(compute_entry_hash(entry_map[slot]))
        else:
            leaves.extend(compute_empty_slot_hash(slot))

    return hashlib.sha256(bytes(leaves)).digest()
