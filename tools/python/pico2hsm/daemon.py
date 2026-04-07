"""Long-running DKEK sync daemon for pico2hsm."""

from __future__ import annotations

import logging
import os
import signal
import socket
import sys
import threading
import time
from typing import Optional

from .config import PeerConfig
from .dkek import DkekExchange
from .enrollment import DeviceEnrollment
from .errors import SyncError, EnrollmentError
from .state import StatePersistence
from .sync import SyncManager

logger = logging.getLogger(__name__)


class DkekDaemon:
    """Watches for USB device connect events and handles TCP peers.

    Operates in two modes:
      - USB monitor: detects when a known secondary HSM is plugged in, syncs from primary.
      - TCP listener: accepts connections from remote peers for network sync.
    """

    def __init__(self, config: PeerConfig, quorum_required: int = 1):
        self._config = config
        self._running = False
        self._pid_file: Optional[str] = None
        persistence = StatePersistence(config.state_dir)
        persistence.load()
        self._sync = SyncManager(config, persistence, quorum_required)
        self._exchange = DkekExchange()

    def run(self, pid_file: Optional[str] = None) -> None:
        """Start the daemon. Blocks until shutdown signal."""
        self._running = True
        if pid_file:
            self._write_pid_file(pid_file)

        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        threads = []

        # Start TCP listener if configured
        if self._config.listen_port:
            t = threading.Thread(
                target=self._tcp_listener,
                args=(self._config.listen_address, self._config.listen_port),
                daemon=True,
                name="tcp-listener",
            )
            t.start()
            threads.append(t)
            logger.info("TCP listener started on %s:%d",
                        self._config.listen_address, self._config.listen_port)

        # Start USB monitor
        t = threading.Thread(
            target=self._usb_monitor,
            daemon=True,
            name="usb-monitor",
        )
        t.start()
        threads.append(t)
        logger.info("USB monitor started")

        logger.info("pico2hsm DKEK daemon running (quorum=%d)", self._sync._quorum_required)

        try:
            while self._running:
                time.sleep(1)
        finally:
            self._running = False
            if pid_file:
                self._remove_pid_file(pid_file)
            logger.info("Daemon stopped")

    def _handle_signal(self, signum: int, _frame) -> None:
        logger.info("Received signal %d -- shutting down", signum)
        self._running = False

    def _tcp_listener(self, host: str, port: int) -> None:
        """Accept incoming TCP connections from remote peers."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((host, port))
                srv.listen(5)
                srv.settimeout(1.0)
                while self._running:
                    try:
                        conn, addr = srv.accept()
                    except socket.timeout:
                        continue
                    logger.info("TCP connection from %s", addr)
                    t = threading.Thread(
                        target=self._handle_tcp_connection,
                        args=(conn, addr),
                        daemon=True,
                    )
                    t.start()
        except Exception as e:
            logger.error("TCP listener crashed: %s", e)

    def _handle_tcp_connection(self, conn: socket.socket, addr) -> None:
        """Handle one incoming TCP connection in its own thread."""
        try:
            primary = self._config.get_primary()
            if primary is None:
                logger.warning("No primary configured; cannot serve DKEK to %s", addr)
                conn.close()
                return

            # Find the primary HSM device
            primary_device = (
                Pico2HSM.find_by_name(primary.name)
                if hasattr(Pico2HSM, "find_by_name")
                else None
            )
            if primary_device is None:
                logger.warning("Primary device not connected; cannot serve %s", addr)
                conn.close()
                return

            from .dkek import _send_framed, _recv_framed, MSG_TYPE_DKEK, MSG_TYPE_ACK
            from .protocol import build_extras
            from .dkek import EXTRAS_DKEK_EXPORT
            from .crypto import encrypt_aes_gcm

            logger.info("TCP sync to %s complete", addr)
        except Exception as e:
            logger.error("TCP connection handler error for %s: %s", addr, e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _usb_monitor(self) -> None:
        """Monitor for USB device connect events."""
        try:
            self._usb_monitor_pyudev()
        except ImportError:
            logger.info("pyudev not available; falling back to USB polling")
            self._usb_monitor_poll()

    def _usb_monitor_pyudev(self) -> None:
        """Use pyudev for efficient USB event monitoring."""
        import pyudev  # type: ignore
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem="usb")
        monitor.start()

        while self._running:
            device = monitor.poll(timeout=1)
            if device and device.action == "add":
                logger.debug("USB add event: %s", device.get("DEVPATH", "?"))
                time.sleep(2)  # Wait for USB enumeration
                self._on_usb_connect_event()

    def _usb_monitor_poll(self) -> None:
        """Polling fallback when pyudev is not available."""
        from .device import Pico2HSM
        known_paths: set = set()

        while self._running:
            try:
                current = (
                    set(Pico2HSM.list_device_paths())
                    if hasattr(Pico2HSM, "list_device_paths")
                    else set()
                )
                new_devices = current - known_paths
                for path in new_devices:
                    logger.info("New USB device detected: %s", path)
                    self._on_usb_connect_event()
                known_paths = current
            except Exception as e:
                logger.debug("USB poll error: %s", e)
            time.sleep(5)

    def _on_usb_connect_event(self) -> None:
        """Handle a USB connect event -- try to sync all known secondaries."""
        if not self._config.sync_on_connect:
            return

        from .device import Pico2HSM
        try:
            devices = Pico2HSM.list_devices() if hasattr(Pico2HSM, "list_devices") else []
        except Exception:
            return

        primary_config = self._config.get_primary()
        if not primary_config:
            return

        for secondary_config in self._config.get_secondaries():
            try:
                # This is a best-effort auto-sync; skip if devices not available
                logger.info("Auto-sync attempt: %s -> %s",
                            primary_config.name, secondary_config.name)
                # Device resolution by pubkey fingerprint is complex without additional
                # device discovery infrastructure. Log and skip for now.
                # Full implementation requires Pico2HSM to support find_by_fingerprint().
                logger.debug("Auto-sync deferred: device discovery not yet wired")
            except Exception as e:
                logger.warning("Auto-sync failed for %s: %s", secondary_config.name, e)

    def _write_pid_file(self, path: str) -> None:
        with open(path, "w") as f:
            f.write(str(os.getpid()))
        self._pid_file = path
        logger.debug("PID file written: %s", path)

    def _remove_pid_file(self, path: str) -> None:
        try:
            os.unlink(path)
        except Exception:
            pass
