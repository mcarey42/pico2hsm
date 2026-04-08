"""Tests for DkekDaemon cluster extensions and CLI."""

from __future__ import annotations

import json
import socket
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from pico2hsm.config import PeerConfig
from pico2hsm.dkek import (
    MAGIC,
    MSG_TYPE_ACK,
    MSG_TYPE_MANIFEST_REQ,
    MSG_TYPE_MANIFEST_RESP,
    MSG_TYPE_STATE_HASH_REQ,
    MSG_TYPE_STATE_HASH_RESP,
    MSG_TYPE_SYNC_COMPLETE,
    _send_framed,
    _recv_framed,
)
from pico2hsm.daemon import DkekDaemon


def _make_config(**kwargs):
    """Build a mock PeerConfig for testing."""
    config = MagicMock(spec=PeerConfig)
    config.listen_port = kwargs.get("listen_port", None)
    config.listen_address = "127.0.0.1"
    config.sync_on_connect = kwargs.get("sync_on_connect", True)
    config.state_dir = "/tmp/test_pico2hsm"
    config.get_primary.return_value = None
    config.get_secondaries.return_value = []
    return config


def _find_free_port() -> int:
    """Return a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestDaemonStartStop:
    """Test that the daemon starts and stops cleanly."""

    def test_daemon_starts_and_stops(self):
        config = _make_config()
        daemon = DkekDaemon(config, quorum_required=1)
        assert not daemon._running

        # Start in background thread
        t = threading.Thread(target=daemon.run, daemon=True)
        t.start()

        # Give it a moment to start
        time.sleep(0.2)
        assert daemon._running

        # Stop it
        daemon._running = False
        t.join(timeout=3)
        assert not t.is_alive()

    def test_daemon_with_tcp_listener(self):
        port = _find_free_port()
        config = _make_config(listen_port=port)
        daemon = DkekDaemon(config, quorum_required=1)

        t = threading.Thread(target=daemon.run, daemon=True)
        t.start()
        time.sleep(0.5)

        # Verify we can connect to the listener
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=2)
            sock.close()
            connected = True
        except Exception:
            connected = False

        daemon._running = False
        t.join(timeout=3)
        assert connected


class TestTcpConnectionHandler:
    """Test _handle_tcp_connection message handling."""

    def _start_daemon_with_listener(self):
        """Start a daemon with a TCP listener and return (daemon, port)."""
        port = _find_free_port()
        config = _make_config(listen_port=port)
        # Set up a primary so the handler does not bail out early
        primary = MagicMock()
        primary.name = "test-primary"
        config.get_primary.return_value = primary

        daemon = DkekDaemon(config, quorum_required=1)

        t = threading.Thread(target=daemon.run, daemon=True)
        t.start()
        time.sleep(0.5)
        return daemon, port, t

    def test_tcp_listener_handles_connection(self):
        daemon, port, t = self._start_daemon_with_listener()
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=2)
            # Send ACK -- daemon should handle and close
            _send_framed(sock, MSG_TYPE_ACK, b"")
            time.sleep(0.2)
            sock.close()
        finally:
            daemon._running = False
            t.join(timeout=3)

    def test_handle_manifest_req(self):
        daemon, port, t = self._start_daemon_with_listener()
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=2)
            sock.settimeout(3.0)

            # Send MANIFEST_REQ
            _send_framed(sock, MSG_TYPE_MANIFEST_REQ, b"")

            # Should get MANIFEST_RESP back
            msg_type, payload = _recv_framed(sock)
            assert msg_type == MSG_TYPE_MANIFEST_RESP
            # Payload may be empty (no real device), but response must arrive

            # Clean up with ACK
            _send_framed(sock, MSG_TYPE_ACK, b"")
            time.sleep(0.1)
            sock.close()
        finally:
            daemon._running = False
            t.join(timeout=3)

    def test_handle_state_hash_req(self):
        daemon, port, t = self._start_daemon_with_listener()
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=2)
            sock.settimeout(3.0)

            _send_framed(sock, MSG_TYPE_STATE_HASH_REQ, b"")

            msg_type, payload = _recv_framed(sock)
            assert msg_type == MSG_TYPE_STATE_HASH_RESP
            # Default response is 104 zero bytes when no device is connected
            assert len(payload) == 104

            _send_framed(sock, MSG_TYPE_ACK, b"")
            time.sleep(0.1)
            sock.close()
        finally:
            daemon._running = False
            t.join(timeout=3)

    def test_handle_tcp_connection_unknown_msg_closes(self):
        daemon, port, t = self._start_daemon_with_listener()
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=2)
            sock.settimeout(3.0)

            # Send an unknown message type (0xFE)
            _send_framed(sock, 0xFE, b"test")

            # Connection should be closed by daemon (recv should fail or return empty)
            time.sleep(0.3)
            # Try to receive -- should fail because daemon closed its side
            try:
                data = sock.recv(1024)
                # Empty data means connection closed
                assert data == b""
            except (ConnectionError, OSError):
                pass  # Expected -- connection was closed
            sock.close()
        finally:
            daemon._running = False
            t.join(timeout=3)

    def test_handle_sync_complete(self):
        daemon, port, t = self._start_daemon_with_listener()
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=2)
            sock.settimeout(3.0)

            fake_root = b"\xaa" * 32
            _send_framed(sock, MSG_TYPE_SYNC_COMPLETE, fake_root)

            msg_type, payload = _recv_framed(sock)
            assert msg_type == MSG_TYPE_SYNC_COMPLETE
            assert len(payload) == 32

            sock.close()
        finally:
            daemon._running = False
            t.join(timeout=3)


class TestPeriodicHealthCheck:
    """Test that the health check thread starts."""

    def test_periodic_health_check_runs(self):
        config = _make_config()
        daemon = DkekDaemon(config, quorum_required=1)

        t = threading.Thread(target=daemon.run, daemon=True)
        t.start()
        time.sleep(0.5)

        # Verify health-check thread exists
        thread_names = [th.name for th in threading.enumerate()]
        assert "health-check" in thread_names

        daemon._running = False
        t.join(timeout=3)


class TestUsbConnectEvent:
    """Test _on_usb_connect_event logic."""

    def test_skips_when_sync_on_connect_disabled(self):
        config = _make_config(sync_on_connect=False)
        daemon = DkekDaemon(config, quorum_required=1)
        # Should return immediately without error
        daemon._on_usb_connect_event()

    def test_skips_when_no_primary(self):
        config = _make_config()
        config.get_primary.return_value = None
        daemon = DkekDaemon(config, quorum_required=1)
        # Patch device listing to return something
        with patch("pico2hsm.device.Pico2HSM") as mock_cls:
            mock_cls.list_devices.return_value = [MagicMock(), MagicMock()]
            daemon._on_usb_connect_event()
        # No crash, no sync attempted


class TestCliExportState:
    """Test the CLI export-state command."""

    def test_export_state_outputs_json(self, tmp_path):
        from pico2hsm.state import StatePersistence, SyncState

        state_dir = str(tmp_path / "state")
        persistence = StatePersistence(state_dir)
        state = SyncState()
        state.update_device("abc123", "test-hsm", 42, "success")
        persistence.save(state)

        # Now use cmd_export_state with a mock config
        import hsm_daemon

        args = MagicMock()
        args.config = None

        with patch.object(hsm_daemon, '_load_config') as mock_load:
            mock_config = MagicMock()
            mock_config.state_dir = state_dir
            mock_load.return_value = mock_config

            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = hsm_daemon.cmd_export_state(args)

        assert rc == 0
        output = json.loads(buf.getvalue())
        assert output["version"] == 1
        assert "abc123" in output["devices"]
        assert output["devices"]["abc123"]["name"] == "test-hsm"
        assert output["devices"]["abc123"]["last_generation"] == 42
