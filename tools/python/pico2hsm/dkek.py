"""DKEK exchange for pico2hsm — P-256 ECDH relay protocol.

The host acts as a relay between two HSMs. DKEK material never passes through
the host in plaintext. The exchange uses on-device P-256 ephemeral keypairs
with HKDF-SHA256 session key derivation.

Exchange protocol (host-mediated relay):

    Host                 Source HSM              Target HSM
    ----                 ----------              ----------
    GET_DEVICE_PUBKEY →  ← source_static_pub
    GET_DEVICE_PUBKEY →                          ← target_static_pub
    [verify both are enrolled]
    NOISE_INITIATE →     ← source_ephem_pub
    NOISE_INITIATE(source_ephem_pub) →           ← target_ephem_pub
    NOISE_FINALIZE_SEND(target_ephem_pub) →      ← encrypted_dkek(60B)
    NOISE_FINALIZE_RECV(source_ephem_pub + encrypted_dkek + device_id) →
                                                 [DKEK stored on target]
"""

from __future__ import annotations

import logging
import ssl
import socket
import struct
from typing import Optional

from .config import PeerConfig, PeerEntry
from .device import Pico2HSM
from .enrollment import DeviceEnrollment
from .errors import DKEKError, EnrollmentError
from .protocol import (
    build_get_device_pubkey,
    build_noise_initiate,
    build_noise_finalize_send,
    build_noise_finalize_recv,
    build_get_generation,
    EXTRAS_GET_DEVICE_PUBKEY,
)

logger = logging.getLogger(__name__)

# Wire framing constants
MAGIC = b"P2H1"
MSG_TYPE_NOISE      = 0x01
MSG_TYPE_ACK        = 0xFF
MSG_TYPE_DEV_PUBKEY = 0x05
MSG_TYPE_EPHEM_PUB  = 0x06
MSG_TYPE_ENC_DKEK   = 0x07

# Cluster sync message types
MSG_TYPE_MANIFEST_REQ    = 0x10
MSG_TYPE_MANIFEST_RESP   = 0x11
MSG_TYPE_KEY_BLOB        = 0x12
MSG_TYPE_SYNC_COMPLETE   = 0x13
MSG_TYPE_STATE_HASH_REQ  = 0x14
MSG_TYPE_STATE_HASH_RESP = 0x15
MSG_TYPE_TOMBSTONE       = 0x20
MSG_TYPE_PROMOTE_PRIMARY = 0x21

# Default TCP port
DEFAULT_PORT = 7890

# Sizes
PUBKEY_SIZE = 65      # uncompressed P-256
ENCRYPTED_DKEK_SIZE = 60  # nonce(12) + ct(32) + tag(16)
DEVICE_ID_SIZE = 16
MAX_FRAME_SIZE = 65536  # 64 KB max payload

# TCP listener DoS protection is implemented in daemon.py:
# - conn.settimeout(30.0) after accept
# - rate limiting: max 3 concurrent connections per IP
# - max 100 messages per minute per connection


class DkekExchange:
    """Orchestrate DKEK exchange between two HSMs.

    The host is a relay — no plaintext DKEK material passes through it.
    """

    def __init__(self, config: Optional[PeerConfig] = None):
        self._config = config

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def exchange_local_usb(
        self,
        source: Pico2HSM,
        target: Pico2HSM,
    ) -> None:
        """Exchange DKEK between two locally connected HSMs.

        Args:
            source: HSM that holds the DKEK to copy.
            target: HSM that will receive the DKEK.
        """
        logger.info("Starting local USB DKEK exchange")
        try:
            self._relay_exchange(source, target)
            logger.info("Local USB DKEK exchange complete")
        except Exception as exc:
            raise DKEKError(f"Local USB exchange failed: {exc}") from exc

    def exchange_tcp_server(
        self,
        source: Pico2HSM,
        port: int = DEFAULT_PORT,
        tls: bool = True,
    ) -> None:
        """Server mode: source HSM sends DKEK to a remote peer.

        Listens on the given port. The remote peer (exchange_tcp_client) connects.

        Args:
            source: Local HSM that holds the DKEK.
            port: TCP port to listen on.
            tls: Use anonymous TLS for transport encryption.
        """
        logger.info("Listening for DKEK exchange on port %d (tls=%s)", port, tls)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(1)
            conn, addr = srv.accept()
            logger.info("Connection from %s", addr)
            if tls:
                conn = _wrap_tls_server(conn)
            with conn:
                try:
                    self._tcp_server_relay(conn, source)
                except Exception as exc:
                    raise DKEKError(f"TCP server exchange failed: {exc}") from exc

    def exchange_tcp_client(
        self,
        target: Pico2HSM,
        server_host: str,
        server_port: int = DEFAULT_PORT,
        tls: bool = True,
    ) -> None:
        """Client mode: target HSM receives DKEK from a remote server.

        Args:
            target: Local HSM that will receive the DKEK.
            server_host: Hostname/IP of the server running exchange_tcp_server.
            server_port: TCP port of the server.
            tls: Use anonymous TLS for transport encryption.
        """
        logger.info("Connecting to DKEK server %s:%d (tls=%s)", server_host, server_port, tls)
        raw_conn = socket.create_connection((server_host, server_port), timeout=30)
        if tls:
            raw_conn = _wrap_tls_client(raw_conn, server_host)
        with raw_conn:
            try:
                self._tcp_client_relay(raw_conn, target)
            except Exception as exc:
                raise DKEKError(f"TCP client exchange failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Internal relay implementation
    # ------------------------------------------------------------------

    def _get_device_pubkey(self, device: Pico2HSM) -> bytes:
        """Get the 65-byte static P-256 identity key from a device."""
        apdu = build_get_device_pubkey()
        data, _sw = device.transmit(apdu)
        if len(data) != PUBKEY_SIZE:
            raise DKEKError(f"Unexpected pubkey length: {len(data)}")
        return data

    def _verify_enrolled(self, pubkey: bytes) -> Optional[PeerEntry]:
        """Check that pubkey is enrolled in config. Raises EnrollmentError if not enrolled."""
        if self._config is None:
            return None  # No config — skip enrollment check
        peer = self._config.find_peer_by_pubkey(pubkey)
        if peer is None:
            raise EnrollmentError(
                f"Device with pubkey {pubkey[:4].hex()}... is not enrolled. "
                "Run 'hsm-tool.py enroll' and add the key to your config."
            )
        logger.info("Verified enrolled peer: %s (%s)", peer.name, peer.role)
        return peer

    def _relay_exchange(self, source: Pico2HSM, target: Pico2HSM) -> None:
        """Core 4-step DKEK relay protocol between two locally connected HSMs."""

        # Step 0: Get static pubkeys and verify enrollment
        source_static = self._get_device_pubkey(source)
        target_static = self._get_device_pubkey(target)
        source_peer = self._verify_enrolled(source_static)
        target_peer = self._verify_enrolled(target_static)
        logger.debug(
            "Source: %s, Target: %s",
            source_peer.name if source_peer else "unknown",
            target_peer.name if target_peer else "unknown",
        )

        # Step 1: NOISE_INITIATE on source (no peer pubkey yet)
        # Source generates ephemeral keypair, returns source_ephem_pub
        apdu = build_noise_initiate(b"")
        source_ephem_pub, _sw = source.transmit(apdu)
        if len(source_ephem_pub) != PUBKEY_SIZE:
            raise DKEKError(f"Source returned unexpected ephem_pub length: {len(source_ephem_pub)}")
        logger.debug("Source ephemeral pubkey: %s...", source_ephem_pub[:4].hex())

        # Step 2: NOISE_INITIATE on target with source's ephemeral pubkey
        apdu = build_noise_initiate(source_ephem_pub)
        target_ephem_pub, _sw = target.transmit(apdu)
        if len(target_ephem_pub) != PUBKEY_SIZE:
            raise DKEKError(f"Target returned unexpected ephem_pub length: {len(target_ephem_pub)}")
        logger.debug("Target ephemeral pubkey: %s...", target_ephem_pub[:4].hex())

        # Step 3: NOISE_FINALIZE_SEND on source with target's ephemeral pubkey
        # Source computes ECDH, derives session key, encrypts DKEK, returns encrypted blob
        apdu = build_noise_finalize_send(target_ephem_pub)
        encrypted_dkek, _sw = source.transmit(apdu)
        if len(encrypted_dkek) != ENCRYPTED_DKEK_SIZE:
            raise DKEKError(f"Source returned unexpected encrypted_dkek length: {len(encrypted_dkek)}")
        logger.debug("Received encrypted DKEK (%d bytes)", len(encrypted_dkek))

        # Step 4: NOISE_FINALIZE_RECV on target
        # Target computes ECDH, decrypts DKEK, stores it
        # device_id is source's static pubkey first 16 bytes (used as AAD in firmware)
        device_id = source_static[:DEVICE_ID_SIZE]
        apdu = build_noise_finalize_recv(source_ephem_pub, encrypted_dkek, device_id)
        _data, _sw = target.transmit(apdu)
        logger.debug("Target confirmed DKEK receipt")

    def _tcp_server_relay(self, conn: socket.socket, source: Pico2HSM) -> None:
        """TCP server side of relay: drives source HSM, relays messages with remote target."""
        conn.settimeout(30.0)

        # Exchange static pubkeys for enrollment verification
        source_static = self._get_device_pubkey(source)
        _send_framed(conn, MSG_TYPE_DEV_PUBKEY, source_static)
        msg_type, target_static = _recv_framed(conn)
        if msg_type != MSG_TYPE_DEV_PUBKEY:
            raise DKEKError(f"Expected DEV_PUBKEY message, got {msg_type:02X}")

        self._verify_enrolled(source_static)
        self._verify_enrolled(target_static)

        # Step 1: Get source ephemeral pubkey
        apdu = build_noise_initiate(b"")
        source_ephem_pub, _ = source.transmit(apdu)
        _send_framed(conn, MSG_TYPE_EPHEM_PUB, source_ephem_pub)

        # Step 2: Receive target ephemeral pubkey
        msg_type, target_ephem_pub = _recv_framed(conn)
        if msg_type != MSG_TYPE_EPHEM_PUB:
            raise DKEKError(f"Expected EPHEM_PUB, got {msg_type:02X}")

        # Step 3: Source encrypts DKEK
        apdu = build_noise_finalize_send(target_ephem_pub)
        encrypted_dkek, _ = source.transmit(apdu)
        _send_framed(conn, MSG_TYPE_ENC_DKEK, encrypted_dkek)

        # Wait for ACK
        msg_type, _ = _recv_framed(conn)
        if msg_type != MSG_TYPE_ACK:
            raise DKEKError(f"Expected ACK, got {msg_type:02X}")
        logger.info("TCP DKEK server: exchange complete")

    def _tcp_client_relay(self, conn: socket.socket, target: Pico2HSM) -> None:
        """TCP client side of relay: drives target HSM, relays messages with remote server."""
        conn.settimeout(30.0)

        target_static = self._get_device_pubkey(target)

        # Exchange static pubkeys
        msg_type, source_static = _recv_framed(conn)
        if msg_type != MSG_TYPE_DEV_PUBKEY:
            raise DKEKError(f"Expected DEV_PUBKEY, got {msg_type:02X}")
        _send_framed(conn, MSG_TYPE_DEV_PUBKEY, target_static)

        self._verify_enrolled(source_static)
        self._verify_enrolled(target_static)

        # Step 2: Receive source ephemeral pubkey, get target's
        msg_type, source_ephem_pub = _recv_framed(conn)
        if msg_type != MSG_TYPE_EPHEM_PUB:
            raise DKEKError(f"Expected EPHEM_PUB, got {msg_type:02X}")
        apdu = build_noise_initiate(source_ephem_pub)
        target_ephem_pub, _ = target.transmit(apdu)
        _send_framed(conn, MSG_TYPE_EPHEM_PUB, target_ephem_pub)

        # Step 4: Receive encrypted DKEK and import into target
        msg_type, encrypted_dkek = _recv_framed(conn)
        if msg_type != MSG_TYPE_ENC_DKEK:
            raise DKEKError(f"Expected ENC_DKEK, got {msg_type:02X}")

        device_id = source_static[:DEVICE_ID_SIZE]
        apdu = build_noise_finalize_recv(source_ephem_pub, encrypted_dkek, device_id)
        target.transmit(apdu)

        _send_framed(conn, MSG_TYPE_ACK, b"")
        logger.info("TCP DKEK client: exchange complete")


# ---------------------------------------------------------------------------
# Wire framing helpers
# ---------------------------------------------------------------------------

def _send_framed(conn: socket.socket, msg_type: int, payload: bytes) -> None:
    """Send a length-prefixed framed message.
    Frame: [4B magic][1B type][4B BE length][payload]
    """
    frame = MAGIC + bytes([msg_type]) + struct.pack(">I", len(payload)) + payload
    conn.sendall(frame)


def _recv_framed(conn: socket.socket) -> tuple[int, bytes]:
    """Receive a framed message; return (msg_type, payload)."""
    header = _recv_exactly(conn, 9)
    if header[:4] != MAGIC:
        raise DKEKError(f"Bad protocol magic: {header[:4].hex()}")
    msg_type = header[4]
    length = struct.unpack(">I", header[5:9])[0]
    if length > MAX_FRAME_SIZE:
        raise DKEKError(f"Frame payload too large: {length} bytes (max {MAX_FRAME_SIZE})")
    payload = _recv_exactly(conn, length) if length else b""
    return msg_type, payload


def _recv_exactly(conn: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes."""
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise DKEKError("Connection closed unexpectedly")
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Anonymous TLS helpers (used by standalone exchange_tcp_server/client)
# ---------------------------------------------------------------------------

def _wrap_tls_server(
    conn: socket.socket,
    cert_path: Optional[str] = None,
    key_path: Optional[str] = None,
    ca_cert: Optional[str] = None,
) -> socket.socket:
    """Wrap server socket with TLS. Uses daemon identity cert if provided."""
    from .tls import ensure_daemon_identity, create_server_context
    import tempfile
    from pathlib import Path

    if cert_path is None or key_path is None:
        tmp_dir = Path(tempfile.mkdtemp())
        cert_path_p, key_path_p = ensure_daemon_identity(tmp_dir)
        cert_path = str(cert_path_p)
        key_path = str(key_path_p)

    ctx = create_server_context(
        cert_path=cert_path,
        key_path=key_path,
        ca_cert=ca_cert,
    )
    return ctx.wrap_socket(conn, server_side=True)


def _wrap_tls_client(
    conn: socket.socket,
    hostname: str,
    cert_path: Optional[str] = None,
    key_path: Optional[str] = None,
    ca_cert: Optional[str] = None,
) -> socket.socket:
    """Wrap a client socket with TLS. Uses daemon identity cert if provided."""
    from .tls import create_client_context

    if not cert_path or not key_path:
        # Auto-generate daemon identity if none provided
        from pathlib import Path as _Path
        from .tls import ensure_daemon_identity
        _config_dir = _Path.home() / ".pico2hsm"
        cert_path, key_path = ensure_daemon_identity(_config_dir)
        cert_path, key_path = str(cert_path), str(key_path)

    ctx = create_client_context(
        cert_path=cert_path,
        key_path=key_path,
        ca_cert=ca_cert,
        peer_name=hostname,
    )

    server_hostname = hostname if ca_cert else None
    return ctx.wrap_socket(conn, server_hostname=server_hostname)
