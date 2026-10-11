"""DKEK exchange for pico2hsm — V2 mutual-auth relay protocol.

The host relays messages between two HSMs; the DKEK never passes through it
in plaintext.  Each HSM must have the other's static P-256 key enrolled
(EXTRAS P1=0x3D) and the SO-PIN verified on both before starting — the
firmware refuses every step otherwise.

    Host                         Source HSM (has DKEK)     Target HSM
    ----                         ---------------------     ----------
    GET_DEVICE_PUBKEY        →   ← source_static
    GET_DEVICE_PUBKEY        →                             ← target_static
    [verify both are enrolled in the host config]
    TARGET_INIT(source_static)                          →  ← ephem_T, chal, Sig_T
    SOURCE_RESPOND(ephem_T, chal, Sig_T) →  ← ephem_S, Sig_S   (verifies Sig_T)
    FINALIZE_SEND(ephem_T, target_static, chal) → ← enc_DKEK
    FINALIZE_RECV(ephem_S, Sig_S, enc_DKEK)             →  [verifies Sig_S, stores DKEK]
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
    build_noise_target_init,
    build_noise_source_respond,
    build_noise_finalize_send_v2,
    build_noise_finalize_recv_v2,
    build_get_generation,
    EXTRAS_GET_DEVICE_PUBKEY,
)

logger = logging.getLogger(__name__)

# Wire framing constants.  "P2H2" = V2 exchange; V1 peers fail at the first frame.
MAGIC = b"P2H2"
MSG_TYPE_NOISE      = 0x01
MSG_TYPE_ACK        = 0xFF
MSG_TYPE_DEV_PUBKEY = 0x05
MSG_TYPE_ENC_DKEK   = 0x07
MSG_TYPE_TARGET_INIT    = 0x08  # ephem_T(65) || challenge(32) || Sig_T(64)
MSG_TYPE_SOURCE_RESPOND = 0x09  # ephem_S(65) || Sig_S(64)

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
TARGET_INIT_SIZE = 161    # ephem_T(65) + challenge(32) + Sig_T(64)
SOURCE_RESPOND_SIZE = 129  # ephem_S(65) + Sig_S(64)
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

    @staticmethod
    def _step(device: Pico2HSM, apdu: bytes, name: str, size: int) -> bytes:
        """Send one exchange step; require SW 9000 and exactly `size` data bytes."""
        data, sw = device.transmit(apdu)
        if sw != 0x9000:
            raise DKEKError(f"{name} failed: SW={sw:04X}")
        if len(data) != size:
            raise DKEKError(f"{name}: expected {size} bytes, got {len(data)}")
        return data

    def _target_init(self, target: Pico2HSM, source_static: bytes) -> bytes:
        return self._step(
            target, build_noise_target_init(source_static), "NOISE_TARGET_INIT", TARGET_INIT_SIZE
        )

    def _source_respond_and_send(
        self, source: Pico2HSM, target_init: bytes, target_static: bytes
    ) -> tuple[bytes, bytes]:
        """Steps 2–3 on SOURCE: returns (source_respond, encrypted_dkek)."""
        ephem_t, challenge, sig_t = target_init[:65], target_init[65:97], target_init[97:]
        respond = self._step(
            source,
            build_noise_source_respond(ephem_t, challenge, sig_t),
            "NOISE_SOURCE_RESPOND",
            SOURCE_RESPOND_SIZE,
        )
        encrypted_dkek = self._step(
            source,
            build_noise_finalize_send_v2(ephem_t, target_static, challenge),
            "NOISE_FINALIZE_SEND_V2",
            ENCRYPTED_DKEK_SIZE,
        )
        return respond, encrypted_dkek

    def _target_receive(self, target: Pico2HSM, respond: bytes, encrypted_dkek: bytes) -> None:
        self._step(
            target,
            build_noise_finalize_recv_v2(respond[:65], respond[65:], encrypted_dkek),
            "NOISE_FINALIZE_RECV_V2",
            0,
        )

    def _relay_exchange(self, source: Pico2HSM, target: Pico2HSM) -> None:
        """V2 DKEK relay between two locally connected HSMs."""
        source_static = self._get_device_pubkey(source)
        target_static = self._get_device_pubkey(target)
        source_peer = self._verify_enrolled(source_static)
        target_peer = self._verify_enrolled(target_static)
        logger.debug(
            "Source: %s, Target: %s",
            source_peer.name if source_peer else "unknown",
            target_peer.name if target_peer else "unknown",
        )

        target_init = self._target_init(target, source_static)
        respond, encrypted_dkek = self._source_respond_and_send(source, target_init, target_static)
        self._target_receive(target, respond, encrypted_dkek)
        logger.debug("Target confirmed DKEK receipt")

    def _tcp_server_relay(self, conn: socket.socket, source: Pico2HSM) -> None:
        """TCP server side: drives the SOURCE HSM."""
        conn.settimeout(30.0)

        source_static = self._get_device_pubkey(source)
        _send_framed(conn, MSG_TYPE_DEV_PUBKEY, source_static)
        msg_type, target_static = _recv_framed(conn)
        if msg_type != MSG_TYPE_DEV_PUBKEY:
            raise DKEKError(f"Expected DEV_PUBKEY message, got {msg_type:02X}")

        self._verify_enrolled(source_static)
        self._verify_enrolled(target_static)

        msg_type, target_init = _recv_framed(conn)
        if msg_type != MSG_TYPE_TARGET_INIT or len(target_init) != TARGET_INIT_SIZE:
            raise DKEKError(f"Expected TARGET_INIT, got {msg_type:02X}")

        respond, encrypted_dkek = self._source_respond_and_send(source, target_init, target_static)
        _send_framed(conn, MSG_TYPE_SOURCE_RESPOND, respond)
        _send_framed(conn, MSG_TYPE_ENC_DKEK, encrypted_dkek)

        msg_type, _ = _recv_framed(conn)
        if msg_type != MSG_TYPE_ACK:
            raise DKEKError(f"Expected ACK, got {msg_type:02X}")
        logger.info("TCP DKEK server: exchange complete")

    def _tcp_client_relay(self, conn: socket.socket, target: Pico2HSM) -> None:
        """TCP client side: drives the TARGET HSM."""
        conn.settimeout(30.0)

        target_static = self._get_device_pubkey(target)
        msg_type, source_static = _recv_framed(conn)
        if msg_type != MSG_TYPE_DEV_PUBKEY:
            raise DKEKError(f"Expected DEV_PUBKEY, got {msg_type:02X}")
        _send_framed(conn, MSG_TYPE_DEV_PUBKEY, target_static)

        self._verify_enrolled(source_static)
        self._verify_enrolled(target_static)

        _send_framed(conn, MSG_TYPE_TARGET_INIT, self._target_init(target, source_static))

        msg_type, respond = _recv_framed(conn)
        if msg_type != MSG_TYPE_SOURCE_RESPOND or len(respond) != SOURCE_RESPOND_SIZE:
            raise DKEKError(f"Expected SOURCE_RESPOND, got {msg_type:02X}")
        msg_type, encrypted_dkek = _recv_framed(conn)
        if msg_type != MSG_TYPE_ENC_DKEK:
            raise DKEKError(f"Expected ENC_DKEK, got {msg_type:02X}")

        self._target_receive(target, respond, encrypted_dkek)
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
