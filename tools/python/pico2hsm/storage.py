"""Storage status and RAID resync commands for pico2hsm.

The pico2hsm firmware manages a multi-chip storage backend with mirrored
RAID pairs for redundancy.  This module provides host-side access to storage
health information and resync operations.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import Optional

from .device import Pico2HSM
from .errors import StorageError
from .protocol import build_extras

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# EXTRAS sub-commands for storage operations
# ---------------------------------------------------------------------------
EXTRAS_STORAGE_STATUS = 0x20
EXTRAS_STORAGE_RESYNC = 0x21
EXTRAS_STORAGE_FORMAT = 0x22
EXTRAS_STORAGE_INFO = 0x23

# Chip status flags
CHIP_FLAG_PRESENT = 0x01
CHIP_FLAG_HEALTHY = 0x02
CHIP_FLAG_SYNCED = 0x04
CHIP_FLAG_DEGRADED = 0x08
CHIP_FLAG_FAILED = 0x10

# Mirror pair states
PAIR_STATE_SYNCED = 0x00
PAIR_STATE_DEGRADED = 0x01
PAIR_STATE_REBUILDING = 0x02
PAIR_STATE_FAILED = 0x03


@dataclass
class ChipStatus:
    """Status of a single storage chip."""

    index: int
    present: bool
    healthy: bool
    synced: bool
    degraded: bool
    failed: bool
    capacity_bytes: int = 0
    used_bytes: int = 0
    bad_sectors: int = 0

    @classmethod
    def from_bytes(cls, index: int, data: bytes) -> "ChipStatus":
        """Parse a ChipStatus from a 12-byte status record."""
        if len(data) < 12:
            raise StorageError(f"Chip status record too short: {len(data)} bytes")
        flags = data[0]
        capacity = struct.unpack(">I", data[1:5])[0]
        used = struct.unpack(">I", data[5:9])[0]
        bad = struct.unpack(">H", data[9:11])[0]
        return cls(
            index=index,
            present=bool(flags & CHIP_FLAG_PRESENT),
            healthy=bool(flags & CHIP_FLAG_HEALTHY),
            synced=bool(flags & CHIP_FLAG_SYNCED),
            degraded=bool(flags & CHIP_FLAG_DEGRADED),
            failed=bool(flags & CHIP_FLAG_FAILED),
            capacity_bytes=capacity,
            used_bytes=used,
            bad_sectors=bad,
        )

    def status_str(self) -> str:
        """Return a human-readable one-liner status string."""
        parts = []
        if self.failed:
            parts.append("FAILED")
        elif self.degraded:
            parts.append("DEGRADED")
        elif self.synced and self.healthy:
            parts.append("OK")
        elif not self.present:
            parts.append("ABSENT")
        else:
            parts.append("UNKNOWN")
        if self.bad_sectors:
            parts.append(f"{self.bad_sectors} bad sectors")
        return ", ".join(parts)


@dataclass
class MirrorPairStatus:
    """Status of a RAID-1 mirror pair."""

    pair_index: int
    primary_chip: int
    secondary_chip: int
    state: int  # PAIR_STATE_*
    rebuild_progress_pct: int = 0

    @classmethod
    def from_bytes(cls, pair_index: int, data: bytes) -> "MirrorPairStatus":
        """Parse a MirrorPairStatus from a 4-byte record."""
        if len(data) < 4:
            raise StorageError(f"Mirror pair record too short: {len(data)} bytes")
        primary = data[0]
        secondary = data[1]
        state = data[2]
        progress = data[3]
        return cls(
            pair_index=pair_index,
            primary_chip=primary,
            secondary_chip=secondary,
            state=state,
            rebuild_progress_pct=progress,
        )

    def state_str(self) -> str:
        """Return a human-readable state string."""
        state_map = {
            PAIR_STATE_SYNCED: "SYNCED",
            PAIR_STATE_DEGRADED: "DEGRADED",
            PAIR_STATE_REBUILDING: f"REBUILDING ({self.rebuild_progress_pct}%)",
            PAIR_STATE_FAILED: "FAILED",
        }
        return state_map.get(self.state, f"UNKNOWN({self.state:02X})")


@dataclass
class StorageStatus:
    """Overall storage system status."""

    chips: list[ChipStatus] = field(default_factory=list)
    mirror_pairs: list[MirrorPairStatus] = field(default_factory=list)
    total_keys: int = 0
    total_capacity_bytes: int = 0
    used_bytes: int = 0

    @property
    def free_bytes(self) -> int:
        return max(0, self.total_capacity_bytes - self.used_bytes)

    @property
    def used_pct(self) -> float:
        if self.total_capacity_bytes == 0:
            return 0.0
        return 100.0 * self.used_bytes / self.total_capacity_bytes

    @property
    def healthy(self) -> bool:
        """True if all mirror pairs are SYNCED and no chips have failed."""
        return (
            all(p.state == PAIR_STATE_SYNCED for p in self.mirror_pairs)
            and all(not c.failed for c in self.chips)
        )


def get_storage_status(device: Pico2HSM) -> StorageStatus:
    """Query storage health from the HSM.

    Sends EXTRAS(STORAGE_STATUS) and parses the TLV response.

    Args:
        device: Connected Pico2HSM instance.

    Returns:
        StorageStatus instance.

    Raises:
        StorageError: On protocol / parsing failures.
    """
    apdu = build_extras(EXTRAS_STORAGE_STATUS)
    try:
        response, _ = device.transmit(apdu)
    except Exception as exc:
        raise StorageError(f"Failed to get storage status: {exc}") from exc

    return _parse_storage_status(response)


def trigger_resync(device: Pico2HSM, chip_index: int) -> None:
    """Trigger a RAID resync for a specific chip.

    This should be called after a chip has been replaced or repaired.
    The firmware will rebuild the mirror from the healthy counterpart.

    Args:
        device: Connected Pico2HSM instance.
        chip_index: Index of the chip to resync (0-based).

    Raises:
        StorageError: On command failure.
    """
    apdu = build_extras(EXTRAS_STORAGE_RESYNC, bytes([chip_index]))
    try:
        device.transmit(apdu)
        logger.info("RAID resync triggered for chip %d", chip_index)
    except Exception as exc:
        raise StorageError(f"Failed to trigger resync for chip {chip_index}: {exc}") from exc


def format_chip(device: Pico2HSM, chip_index: int) -> None:
    """Format (erase) a specific storage chip.

    WARNING: This destroys all data on the chip.  Use only when replacing
    a failed chip that has been physically swapped.

    Args:
        device: Connected Pico2HSM instance.
        chip_index: Index of the chip to format (0-based).

    Raises:
        StorageError: On command failure.
    """
    apdu = build_extras(EXTRAS_STORAGE_FORMAT, bytes([chip_index]))
    try:
        device.transmit(apdu)
        logger.info("Chip %d formatted", chip_index)
    except Exception as exc:
        raise StorageError(f"Failed to format chip {chip_index}: {exc}") from exc


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

_CHIP_RECORD_SIZE = 12
_PAIR_RECORD_SIZE = 4


def _parse_storage_status(data: bytes) -> StorageStatus:
    """Parse EXTRAS STORAGE_STATUS response.

    Expected TLV layout::

        81 01 <num_chips>
        82 01 <num_pairs>
        83 02 <total_keys BE16>
        84 04 <total_capacity BE32>
        85 04 <used_bytes BE32>
        86 <n*12> <chip records>
        87 <m*4>  <pair records>
    """
    status = StorageStatus()
    num_chips = 0
    num_pairs = 0
    offset = 0

    while offset < len(data):
        if offset + 2 > len(data):
            break
        tag = data[offset]
        offset += 1
        length = data[offset]
        offset += 1
        if length == 0x81:
            if offset >= len(data):
                break
            length = data[offset]
            offset += 1
        value = data[offset : offset + length]
        offset += length

        if tag == 0x81 and length == 1:
            num_chips = value[0]
        elif tag == 0x82 and length == 1:
            num_pairs = value[0]
        elif tag == 0x83 and length == 2:
            status.total_keys = struct.unpack(">H", value)[0]
        elif tag == 0x84 and length == 4:
            status.total_capacity_bytes = struct.unpack(">I", value)[0]
        elif tag == 0x85 and length == 4:
            status.used_bytes = struct.unpack(">I", value)[0]
        elif tag == 0x86:
            # Chip status records
            for i in range(num_chips):
                start = i * _CHIP_RECORD_SIZE
                end = start + _CHIP_RECORD_SIZE
                if end <= len(value):
                    try:
                        chip = ChipStatus.from_bytes(i, value[start:end])
                        status.chips.append(chip)
                    except StorageError:
                        pass
        elif tag == 0x87:
            # Mirror pair records
            for i in range(num_pairs):
                start = i * _PAIR_RECORD_SIZE
                end = start + _PAIR_RECORD_SIZE
                if end <= len(value):
                    try:
                        pair = MirrorPairStatus.from_bytes(i, value[start:end])
                        status.mirror_pairs.append(pair)
                    except StorageError:
                        pass

    # If the device returns nothing (e.g. mock), provide defaults
    if not status.chips and num_chips > 0:
        for i in range(num_chips):
            status.chips.append(
                ChipStatus(
                    index=i,
                    present=False,
                    healthy=False,
                    synced=False,
                    degraded=False,
                    failed=False,
                )
            )

    return status
