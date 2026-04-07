"""Key export/import blob file I/O for pico2hsm DKEK-wrapped keys."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .device import Pico2HSM
from .errors import Pico2HSMError
from .protocol import build_export_key, build_import_key

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
