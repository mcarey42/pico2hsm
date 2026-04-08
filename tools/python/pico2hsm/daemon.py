"""Long-running DKEK sync daemon for pico2hsm."""

from __future__ import annotations

import logging
import os
import signal
import socket
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
        self._persistence = StatePersistence(config.state_dir)
        self._persistence.load()
        self._sync = SyncManager(config, self._persistence, quorum_required)
        self._exchange = DkekExchange()

    def run(self, pid_file: Optional[str] = None) -> None:
        """Start the daemon. Blocks until shutdown signal."""
        self._running = True
        if pid_file:
            self._write_pid_file(pid_file)

        if threading.current_thread() is threading.main_thread():
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

        # Start periodic health check
        t = threading.Thread(
            target=self._periodic_health_check,
            daemon=True,
            name="health-check",
        )
        t.start()
        threads.append(t)
        logger.info("Health check started")

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
        """Handle incoming TCP connection from a remote peer daemon.

        Protocol: peer initiates sync. We serve as the source (primary).
        Uses the updated cluster sync protocol with new message types.
        """
        try:
            # Set idle timeout
            conn.settimeout(30.0)

            from .dkek import (
                _send_framed, _recv_framed,
                MSG_TYPE_ACK,
                MSG_TYPE_MANIFEST_REQ, MSG_TYPE_MANIFEST_RESP,
                MSG_TYPE_KEY_BLOB,
                MSG_TYPE_SYNC_COMPLETE,
                MSG_TYPE_STATE_HASH_REQ, MSG_TYPE_STATE_HASH_RESP,
            )

            primary_config = self._config.get_primary()
            if primary_config is None:
                logger.warning("No primary; cannot serve %s", addr)
                conn.close()
                return

            # Main handler loop -- process messages from peer
            while True:
                try:
                    msg_type, payload = _recv_framed(conn)
                except Exception:
                    break

                if msg_type == MSG_TYPE_MANIFEST_REQ:
                    # Peer wants our key manifest
                    manifest_bytes = self._get_local_manifest_bytes()
                    _send_framed(conn, MSG_TYPE_MANIFEST_RESP, manifest_bytes)

                elif msg_type == MSG_TYPE_STATE_HASH_REQ:
                    hash_bytes = self._get_local_state_hash_bytes()
                    _send_framed(conn, MSG_TYPE_STATE_HASH_RESP, hash_bytes)

                elif msg_type == MSG_TYPE_KEY_BLOB:
                    # Peer wants a specific key: payload = key_ref(1) [or key_ref(4)]
                    key_ref = payload[0] if payload else 0
                    blob = self._export_key_blob(key_ref)
                    _send_framed(conn, MSG_TYPE_KEY_BLOB, bytes([key_ref]) + blob)

                elif msg_type == MSG_TYPE_SYNC_COMPLETE:
                    their_root = payload[:32] if len(payload) >= 32 else b""
                    our_root = self._get_local_state_root()
                    match = (their_root == our_root) if our_root else False
                    logger.info("TCP sync complete from %s: roots_match=%s", addr, match)
                    _send_framed(conn, MSG_TYPE_SYNC_COMPLETE, our_root or b"\x00" * 32)
                    break

                elif msg_type == MSG_TYPE_ACK:
                    break

                else:
                    logger.warning("Unknown message type 0x%02X from %s", msg_type, addr)
                    break

        except Exception as e:
            logger.error("TCP connection handler error for %s: %s", addr, e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _get_local_manifest_bytes(self) -> bytes:
        """Try to get manifest bytes from connected primary HSM. Returns empty on failure."""
        try:
            from .device import Pico2HSM
            devices = Pico2HSM.list_devices() if hasattr(Pico2HSM, 'list_devices') else []
            if not devices:
                return b""
            from .protocol import build_extras
            # Use EXTRAS command with a manifest sub-command (0x39)
            apdu = build_extras(0x39)
            data, sw = devices[0].transmit(apdu)
            return data if sw == 0x9000 else b""
        except Exception as e:
            logger.debug("Could not get manifest: %s", e)
            return b""

    def _get_local_state_hash_bytes(self) -> bytes:
        """Get state hash bytes from primary HSM."""
        try:
            from .device import Pico2HSM
            devices = Pico2HSM.list_devices() if hasattr(Pico2HSM, 'list_devices') else []
            if not devices:
                return b"\x00" * 104
            from .protocol import build_extras
            # Use EXTRAS command with a state hash sub-command (0x3A)
            apdu = build_extras(0x3A)
            data, sw = devices[0].transmit(apdu)
            return data if sw == 0x9000 else b"\x00" * 104
        except Exception as e:
            logger.debug("Could not get state hash: %s", e)
            return b"\x00" * 104

    def _export_key_blob(self, key_ref: int) -> bytes:
        """Export a DKEK-wrapped key from the primary HSM."""
        try:
            from .device import Pico2HSM
            from .protocol import build_export_key
            devices = Pico2HSM.list_devices() if hasattr(Pico2HSM, 'list_devices') else []
            if not devices:
                return b""
            apdu = build_export_key(key_ref)
            data, sw = devices[0].transmit(apdu)
            return data if sw == 0x9000 else b""
        except Exception as e:
            logger.debug("Could not export key %d: %s", key_ref, e)
            return b""

    def _get_local_state_root(self) -> bytes:
        """Get 32-byte state root from primary HSM."""
        data = self._get_local_state_hash_bytes()
        return data[8:40] if len(data) >= 40 else b"\x00" * 32

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
        """Handle a USB connect event -- sync any newly connected secondary devices."""
        if not self._config.sync_on_connect:
            return

        try:
            from .device import Pico2HSM
            devices = Pico2HSM.list_devices() if hasattr(Pico2HSM, 'list_devices') else []
        except Exception as e:
            logger.debug("USB event: could not list devices: %s", e)
            return

        primary_config = self._config.get_primary()
        if not primary_config:
            logger.debug("No primary configured; skipping auto-sync")
            return

        # Find primary device among connected devices
        # Match by enrolled pubkey fingerprint if possible, else by order
        for secondary_config in self._config.get_secondaries():
            try:
                # Attempt to find primary and secondary devices
                # This requires Pico2HSM to support device discovery -- use best-effort
                logger.info("Auto-sync: attempting %s -> %s",
                            primary_config.name, secondary_config.name)
                # If devices list has at least 2, try syncing first two
                if len(devices) >= 2:
                    result = self._sync.sync_local(
                        devices[0], devices[1],
                        primary_config.name, secondary_config.name
                    )
                    if result.success:
                        logger.info("Auto-sync complete: %s", result.message)
                    else:
                        logger.warning("Auto-sync failed: %s", result.message)
            except Exception as e:
                logger.warning("Auto-sync error for %s: %s", secondary_config.name, e)

    def _periodic_health_check(self) -> None:
        """Every 60s: fetch state hashes from all connected devices, log sync status."""
        while self._running:
            try:
                from .device import Pico2HSM
                devices = Pico2HSM.list_devices() if hasattr(Pico2HSM, 'list_devices') else []
                if len(devices) >= 2:
                    roots = {}
                    for i, dev in enumerate(devices):
                        try:
                            from .protocol import build_extras
                            apdu = build_extras(0x3A)
                            data, sw = dev.transmit(apdu)
                            if sw == 0x9000 and len(data) >= 40:
                                root = data[8:40].hex()
                                roots[f"device-{i}"] = root
                        except Exception:
                            pass
                    if roots:
                        all_same = len(set(roots.values())) == 1
                        if all_same:
                            logger.info("Health check: cluster IN SYNC (%s)",
                                        list(roots.values())[0][:8])
                        else:
                            logger.warning("Health check: cluster OUT OF SYNC: %s", roots)
            except Exception as e:
                logger.debug("Health check error: %s", e)

            for _ in range(60):  # sleep 60s in 1s chunks to allow clean shutdown
                if not self._running:
                    break
                time.sleep(1)

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
