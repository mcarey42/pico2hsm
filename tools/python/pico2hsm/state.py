"""Sync state persistence for pico2hsm DKEK daemon."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DeviceState:
    """Known state for one enrolled HSM device."""
    fingerprint: str             # Hex fingerprint from DeviceEnrollment.fingerprint()
    name: str                    # From config
    last_generation: int         # Last known DKEK generation counter
    last_seen: str               # ISO 8601 timestamp of last successful contact
    last_sync_result: str        # "success" | "failed" | "skipped" | "unknown"


@dataclass
class SyncState:
    """Persisted sync state for the daemon."""
    version: int = 1
    devices: dict[str, DeviceState] = field(default_factory=dict)  # keyed by fingerprint

    def get_device(self, fingerprint: str) -> Optional[DeviceState]:
        return self.devices.get(fingerprint)

    def update_device(
        self,
        fingerprint: str,
        name: str,
        generation: int,
        result: str,
    ) -> None:
        self.devices[fingerprint] = DeviceState(
            fingerprint=fingerprint,
            name=name,
            last_generation=generation,
            last_seen=datetime.now(timezone.utc).isoformat(),
            last_sync_result=result,
        )

    def quorum_achieved(
        self,
        target_generation: int,
        required: int,
        exclude_fingerprint: Optional[str] = None,
    ) -> tuple[bool, int]:
        """Check if N devices have the target generation.

        Args:
            target_generation: The DKEK generation that must be confirmed.
            required: Number of devices (N) that must confirm.
            exclude_fingerprint: Fingerprint to exclude (e.g., the device being synced).

        Returns:
            (achieved: bool, confirmed_count: int)
        """
        confirmed = sum(
            1
            for d in self.devices.values()
            if d.last_generation >= target_generation
            and d.fingerprint != exclude_fingerprint
        )
        return confirmed >= required, confirmed

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "devices": {k: asdict(v) for k, v in self.devices.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SyncState":
        devices = {}
        for fp, d in data.get("devices", {}).items():
            devices[fp] = DeviceState(**d)
        return cls(version=data.get("version", 1), devices=devices)


class StatePersistence:
    """Load and save SyncState to disk."""

    def __init__(self, state_dir: str = "~/.pico2hsm"):
        self._state_dir = os.path.expanduser(state_dir)
        self._state_file = os.path.join(self._state_dir, "state.json")
        self._state: SyncState = SyncState()

    def load(self) -> SyncState:
        """Load state from disk or return empty state."""
        os.makedirs(self._state_dir, exist_ok=True)
        if not os.path.exists(self._state_file):
            logger.debug("No state file at %s; starting fresh", self._state_file)
            self._state = SyncState()
            return self._state
        try:
            with open(self._state_file) as f:
                data = json.load(f)
            self._state = SyncState.from_dict(data)
            logger.debug("Loaded state: %d devices", len(self._state.devices))
        except Exception as e:
            logger.warning("Failed to load state file: %s; starting fresh", e)
            self._state = SyncState()
        return self._state

    def save(self, state: Optional[SyncState] = None) -> None:
        """Persist state to disk."""
        if state is not None:
            self._state = state
        os.makedirs(self._state_dir, exist_ok=True)
        tmp = self._state_file + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(self._state.to_dict(), f, indent=2)
            os.replace(tmp, self._state_file)
        except Exception as e:
            logger.error("Failed to save state: %s", e)

    @property
    def state(self) -> SyncState:
        return self._state
