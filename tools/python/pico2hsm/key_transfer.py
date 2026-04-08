"""Key export/import blob file I/O for pico2hsm DKEK-wrapped keys."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from .device import Pico2HSM
from .errors import Pico2HSMError
from .protocol import build_export_key, build_import_key, build_delete_key

try:
    from .cluster import SyncPlan, SyncResult, diff_manifests
except ImportError:
    # Provide minimal fallback types when cluster.py is not available.
    # These are duck-type compatible with the real cluster types.
    @dataclass
    class SyncResult:  # type: ignore[no-redef]
        """Fallback SyncResult when cluster.py is not available."""
        success: bool
        keys_transferred: int
        keys_deleted: int
        conflicts_resolved: int
        error: Optional[str] = None

logger = logging.getLogger(__name__)

# Blob file format: P2HK(4) + version(1) + key_id(1) + algo_id(1) + reserved(1) + wrapped_data
BLOB_MAGIC = b"P2HK"
BLOB_VERSION = 0x01
BLOB_HEADER_SIZE = 8


@dataclass
class KeyBlob:
    """A DKEK-wrapped key blob for offline storage / HSM transfer."""
    key_id: int
    algo_id: int
    wrapped_data: bytes

    def to_bytes(self) -> bytes:
        header = BLOB_MAGIC + bytes([BLOB_VERSION, self.key_id, self.algo_id, 0x00])
        return header + self.wrapped_data

    @classmethod
    def from_bytes(cls, data: bytes) -> "KeyBlob":
        if len(data) < BLOB_HEADER_SIZE:
            raise ValueError("Blob too short")
        if data[:4] != BLOB_MAGIC:
            raise ValueError(f"Invalid blob magic: {data[:4].hex()}")
        version = data[4]
        if version != BLOB_VERSION:
            raise ValueError(f"Unsupported blob version: {version}")
        key_id = data[5]
        algo_id = data[6]
        wrapped_data = data[BLOB_HEADER_SIZE:]
        return cls(key_id=key_id, algo_id=algo_id, wrapped_data=wrapped_data)

    def save(self, path: str) -> None:
        with open(path, "wb") as f:
            f.write(self.to_bytes())
        logger.info("Key blob saved to %s (%d bytes)", path, BLOB_HEADER_SIZE + len(self.wrapped_data))

    @classmethod
    def load(cls, path: str) -> "KeyBlob":
        with open(path, "rb") as f:
            return cls.from_bytes(f.read())


def export_key(device: Pico2HSM, key_id: int, output_path: str) -> None:
    """Export a DKEK-wrapped key from the device and save to a file.

    The device must have an active DKEK and the user must be authenticated.

    Args:
        device: Connected HSM.
        key_id: Key reference (1-254).
        output_path: Path to save the .p2hk blob file.
    """
    if not 1 <= key_id <= 254:
        raise ValueError(f"key_id must be 1-254, got {key_id}")

    apdu = build_export_key(key_id)
    wrapped_data, sw = device.transmit(apdu)
    if not wrapped_data:
        raise Pico2HSMError(f"EXPORT KEY returned no data (SW={sw:04X})")

    # We don't know algo_id until we parse the blob -- store 0x00 as placeholder.
    # The algo_id is embedded in the wrapped_data by the firmware.
    blob = KeyBlob(key_id=key_id, algo_id=0x00, wrapped_data=wrapped_data)
    blob.save(output_path)
    logger.info("Exported key %d to %s", key_id, output_path)


def import_key(device: Pico2HSM, key_id: int, input_path: str) -> None:
    """Import a DKEK-wrapped key blob into the device.

    Args:
        device: Connected HSM.
        key_id: Key reference to store the imported key under (1-254).
        input_path: Path to the .p2hk blob file.
    """
    blob = KeyBlob.load(input_path)
    if not 1 <= key_id <= 254:
        raise ValueError(f"key_id must be 1-254, got {key_id}")

    apdu = build_import_key(key_id, blob.wrapped_data)
    _resp, sw = device.transmit(apdu)
    logger.info("Imported key to slot %d (SW=%04X)", key_id, sw)


# ---------------------------------------------------------------------------
# Device-to-device transfer functions (cluster sync)
# ---------------------------------------------------------------------------

# Minimum wrapped blob size: KCV(8) + IV(16) + one CBC block(16) = 40
_MIN_BLOB_SIZE = 40
_MAX_BLOB_SIZE = 4096
_KCV_IV_SIZE = 24  # KCV(8) + IV(16)


def export_key_from_device(device: Pico2HSM, key_ref: int) -> bytes:
    """Export a DKEK-wrapped key blob from the device.

    Returns the raw wrapped blob bytes (not a KeyBlob container).
    Raises ValueError for invalid key_ref, Pico2HSMError on APDU error.
    """
    if not 1 <= key_ref <= 254:
        raise ValueError(f"key_ref must be 1-254, got {key_ref}")

    apdu = build_export_key(key_ref)
    data, sw = device.transmit(apdu)
    if sw != 0x9000:
        raise Pico2HSMError(f"EXPORT KEY ref={key_ref} failed (SW={sw:04X})")
    if len(data) < _MIN_BLOB_SIZE:
        raise Pico2HSMError(
            f"EXPORT KEY ref={key_ref} returned too few bytes: {len(data)} (need >= {_MIN_BLOB_SIZE})"
        )
    logger.info("Exported key ref=%d (%d bytes)", key_ref, len(data))
    return data


def import_key_to_device(
    device: Pico2HSM,
    key_ref: int,
    wrapped_blob: bytes,
    timestamp_ms: int = 0,
) -> None:
    """Import a DKEK-wrapped key blob into the device at key_ref.

    Validates wrapped_blob before sending:
    - Must be at least 40 bytes (KCV + IV + one CBC block)
    - Must be at most 4096 bytes
    - Length after KCV+IV must be multiple of 16 (CBC block alignment)
    Raises ValueError on validation failure, Pico2HSMError on APDU error.
    """
    if not 1 <= key_ref <= 254:
        raise ValueError(f"key_ref must be 1-254, got {key_ref}")
    if len(wrapped_blob) < _MIN_BLOB_SIZE:
        raise ValueError(
            f"Wrapped blob too short: {len(wrapped_blob)} bytes (need >= {_MIN_BLOB_SIZE})"
        )
    if len(wrapped_blob) > _MAX_BLOB_SIZE:
        raise ValueError(
            f"Wrapped blob too large: {len(wrapped_blob)} bytes (max {_MAX_BLOB_SIZE})"
        )
    payload_len = len(wrapped_blob) - _KCV_IV_SIZE
    if payload_len % 16 != 0:
        raise ValueError(
            f"Wrapped blob payload length {payload_len} is not a multiple of 16 (CBC block alignment)"
        )

    apdu = build_import_key(key_ref, wrapped_blob)
    _resp, sw = device.transmit(apdu)
    if sw != 0x9000:
        raise Pico2HSMError(f"IMPORT KEY ref={key_ref} failed (SW={sw:04X})")
    logger.info("Imported key ref=%d (%d bytes, SW=%04X)", key_ref, len(wrapped_blob), sw)


def delete_key_from_device(device: Pico2HSM, key_ref: int) -> None:
    """Delete a key from the device (propagate tombstone).

    Raises ValueError for invalid key_ref, Pico2HSMError on APDU error.
    """
    if not 1 <= key_ref <= 254:
        raise ValueError(f"key_ref must be 1-254, got {key_ref}")

    apdu = build_delete_key(key_ref)
    _resp, sw = device.transmit(apdu)
    if sw != 0x9000:
        raise Pico2HSMError(f"DELETE KEY ref={key_ref} failed (SW={sw:04X})")
    logger.info("Deleted key ref=%d (SW=%04X)", key_ref, sw)


def transfer_keys(
    primary: Pico2HSM,
    secondary: Pico2HSM,
    plan: "SyncPlan",
    conflict_backup_dir: Optional[str] = None,
) -> "SyncResult":
    """Transfer keys from primary to secondary according to plan.

    Precondition: both devices share the same DKEK.

    For each key_ref in plan.missing_on_secondary:
        export from primary, import to secondary.

    For each key_ref in plan.conflicts:
        optionally back up secondary's version, then overwrite from primary.

    For each key_ref in plan.tombstone_on_secondary:
        delete from secondary.

    plan.orphans: logged as warning, NOT auto-deleted (operator decision).

    Returns SyncResult with counts. Handles individual APDU errors gracefully.
    """
    keys_transferred = 0
    keys_deleted = 0
    conflicts_resolved = 0
    had_error = False
    error_messages: list[str] = []

    # Transfer missing keys
    for key_ref in plan.missing_on_secondary:
        try:
            blob = export_key_from_device(primary, key_ref)
            import_key_to_device(secondary, key_ref, blob)
            keys_transferred += 1
            logger.info("Transferred key ref=%d (missing on secondary)", key_ref)
        except Exception as e:
            had_error = True
            msg = f"Failed to transfer key ref={key_ref}: {e}"
            error_messages.append(msg)
            logger.error(msg)

    # Resolve conflicts (primary wins)
    for key_ref in plan.conflicts:
        try:
            if conflict_backup_dir:
                try:
                    backup_blob = export_key_from_device(secondary, key_ref)
                    backup_path = os.path.join(
                        conflict_backup_dir, f"conflict_backup_key_{key_ref}.bin"
                    )
                    with open(backup_path, "wb") as f:
                        f.write(backup_blob)
                    logger.info("Backed up conflicting key ref=%d to %s", key_ref, backup_path)
                except Exception as e:
                    logger.warning("Could not back up conflicting key ref=%d: %s", key_ref, e)

            blob = export_key_from_device(primary, key_ref)
            import_key_to_device(secondary, key_ref, blob)
            conflicts_resolved += 1
            logger.info("Resolved conflict for key ref=%d (primary wins)", key_ref)
        except Exception as e:
            had_error = True
            msg = f"Failed to resolve conflict for key ref={key_ref}: {e}"
            error_messages.append(msg)
            logger.error(msg)

    # Propagate tombstones
    for key_ref in plan.tombstone_on_secondary:
        try:
            delete_key_from_device(secondary, key_ref)
            keys_deleted += 1
            logger.info("Deleted tombstoned key ref=%d from secondary", key_ref)
        except Exception as e:
            had_error = True
            msg = f"Failed to delete key ref={key_ref}: {e}"
            error_messages.append(msg)
            logger.error(msg)

    # Log orphans — do NOT auto-delete
    for key_ref in plan.orphans:
        logger.warning(
            "Orphan key ref=%d exists only on secondary — manual review required", key_ref
        )

    return SyncResult(
        success=not had_error,
        keys_transferred=keys_transferred,
        keys_deleted=keys_deleted,
        conflicts_resolved=conflicts_resolved,
        error="; ".join(error_messages) if error_messages else None,
    )
