"""Primary/secondary sync and quorum management for pico2hsm DKEK."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from .config import PeerConfig, PeerEntry
from .device import Pico2HSM
from .dkek import DkekExchange
from .enrollment import DeviceEnrollment
from .errors import SyncError
from .protocol import build_get_generation
from .state import StatePersistence, SyncState

logger = logging.getLogger(__name__)


@dataclass
class SyncResult:
    """Result of a single sync operation."""
    success: bool
    source_name: str
    target_name: str
    source_generation: int
    target_generation: int
    message: str


class SyncManager:
    """Orchestrate DKEK synchronisation between HSM devices.

    Uses generation counters to determine sync direction and quorum
    to guard offline-node catchup.
    """

    def __init__(
        self,
        config: Optional[PeerConfig],
        persistence: StatePersistence,
        quorum_required: int = 1,
    ):
        """
        Args:
            config: Peer configuration (may be None for config-less operation).
            persistence: State persistence handler.
            quorum_required: Number of confirmed HSMs before syncing an offline node.
                             1 = sync immediately (no quorum gate).
                             N > 1 = require N confirmed before syncing a lagging node.
        """
        self._config = config
        self._persistence = persistence
        self._quorum_required = quorum_required
        self._exchange = DkekExchange()

    def get_generation(self, device: Pico2HSM) -> int:
        """Query the generation counter from a device. Returns 0 on failure."""
        try:
            apdu = build_get_generation()
            data, _sw = device.transmit(apdu)
            return int.from_bytes(data[:4], "big") if len(data) >= 4 else 0
        except Exception as e:
            logger.warning("Failed to get generation: %s", e)
            return 0

    def sync_local(
        self,
        primary: Pico2HSM,
        secondary: Pico2HSM,
        primary_name: str = "primary",
        secondary_name: str = "secondary",
    ) -> SyncResult:
        """Sync DKEK from primary to secondary over local USB.

        Skips sync if secondary is already at or ahead of primary's generation.
        Gates sync on quorum if quorum_required > 1.

        Returns a SyncResult describing what happened.
        """
        state = self._persistence.load()

        primary_gen = self.get_generation(primary)
        secondary_gen = self.get_generation(secondary)
        logger.info(
            "Sync %s (gen=%d) -> %s (gen=%d)",
            primary_name, primary_gen, secondary_name, secondary_gen,
        )

        # Get device fingerprints for state tracking
        try:
            primary_info = DeviceEnrollment.get_device_info(primary)
            secondary_info = DeviceEnrollment.get_device_info(secondary)
            primary_fp = primary_info.fingerprint
            secondary_fp = secondary_info.fingerprint
        except Exception as e:
            logger.warning("Could not read device info: %s", e)
            primary_fp = primary_name
            secondary_fp = secondary_name

        # Update state with current primary status
        state.update_device(primary_fp, primary_name, primary_gen, "success")

        # Already in sync?
        if secondary_gen >= primary_gen:
            logger.info("%s is already at gen %d (primary is %d) -- skipping",
                        secondary_name, secondary_gen, primary_gen)
            state.update_device(secondary_fp, secondary_name, secondary_gen, "skipped")
            self._persistence.save(state)
            return SyncResult(
                success=True,
                source_name=primary_name,
                target_name=secondary_name,
                source_generation=primary_gen,
                target_generation=secondary_gen,
                message="Already in sync",
            )

        # Quorum check: before syncing this lagging device, verify N others are confirmed
        if self._quorum_required > 1:
            achieved, confirmed = state.quorum_achieved(
                target_generation=primary_gen,
                required=self._quorum_required,
                exclude_fingerprint=secondary_fp,
            )
            if not achieved:
                msg = (
                    f"Quorum not met: {confirmed}/{self._quorum_required} devices confirmed "
                    f"generation {primary_gen} (excluding {secondary_name}). "
                    "Sync deferred until quorum is reached."
                )
                logger.warning(msg)
                return SyncResult(
                    success=False,
                    source_name=primary_name,
                    target_name=secondary_name,
                    source_generation=primary_gen,
                    target_generation=secondary_gen,
                    message=msg,
                )

        # Perform the DKEK exchange
        try:
            self._exchange.exchange_local_usb(primary, secondary)
            new_gen = self.get_generation(secondary)
            state.update_device(secondary_fp, secondary_name, new_gen, "success")
            self._persistence.save(state)
            logger.info("Sync complete: %s now at gen %d", secondary_name, new_gen)
            return SyncResult(
                success=True,
                source_name=primary_name,
                target_name=secondary_name,
                source_generation=primary_gen,
                target_generation=new_gen,
                message="Sync successful",
            )
        except Exception as e:
            state.update_device(secondary_fp, secondary_name, secondary_gen, "failed")
            self._persistence.save(state)
            raise SyncError(f"Sync failed: {e}") from e

    def sync_tcp_to_peer(
        self,
        source: Pico2HSM,
        peer_name: str,
        tls: bool = True,
    ) -> None:
        """Initiate TCP sync to a named peer from config.

        Args:
            source: Local HSM that holds the DKEK.
            peer_name: Name of the target peer in config.
            tls: Use anonymous TLS.
        """
        if self._config is None:
            raise SyncError("No config provided; cannot resolve peer by name")

        peer = self._config.find_peer_by_name(peer_name)
        if peer is None:
            raise SyncError(f"Peer '{peer_name}' not found in config")
        if peer.address is None:
            raise SyncError(f"Peer '{peer_name}' has no TCP address configured")

        host, _, port_str = peer.address.rpartition(":")
        port = int(port_str) if port_str else 7890

        self._exchange.exchange_tcp_server(source, port=port)
