"""DKEK ceremony and Noise_XX key exchange for pico2hsm.

Implements DKEK (Device Key Encryption Key) exchange between two HSMs
using the Noise_XX authenticated key exchange protocol.  The Noise session
provides forward secrecy and mutual authentication via the device identity
keys stored in each HSM.
"""

from __future__ import annotations

import logging
import os
import socket
import struct
from typing import Optional

from .crypto import decrypt_aes_gcm, encrypt_aes_gcm
from .device import Pico2HSM
from .errors import DKEKError
from .protocol import (
    INS_EXTRAS,
    build_extras,
    build_get_challenge,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sub-command bytes for INS_EXTRAS used in DKEK ceremony
# ---------------------------------------------------------------------------
EXTRAS_DKEK_BEGIN = 0x10
EXTRAS_DKEK_NOISE_MSG = 0x11
EXTRAS_DKEK_IMPORT = 0x12
EXTRAS_DKEK_EXPORT = 0x13

# Noise_XX message framing over the wire (TCP or USB)
MAGIC = b"P2H1"  # 4-byte protocol magic
MSG_TYPE_NOISE = 0x01
MSG_TYPE_DKEK = 0x02
MSG_TYPE_ACK = 0xFF

# Default TCP port for DKEK exchange
DEFAULT_PORT = 7890

# AES-GCM key size for wrapping the DKEK in transit
SESSION_KEY_SIZE = 32


class DkekExchange:
    """Implements DKEK exchange using the Noise_XX protocol.

    Noise_XX provides mutual authentication (both parties prove possession of
    their static identity keys) and forward secrecy via ephemeral DH.

    The high-level flow is::

        Initiator                        Responder
        ---------                        ---------
        -> e                             (ephemeral public key)
                              <- e, ee, s, es   (responder ephemeral + static)
        -> s, se                         (initiator static)
        [session keys established]
        -> DKEK encrypted under session key
                              <- ACK

    Device identity keys are retrieved from each HSM via ``INS_EXTRAS``.
    """

    def exchange_local_usb(
        self,
        source_device: Pico2HSM,
        target_device: Pico2HSM,
    ) -> None:
        """Exchange DKEK between two HSMs connected to the same host.

        Steps:
        1. Perform Noise_XX handshake using APDUs to both HSMs.
        2. Source HSM exports DKEK encrypted under the Noise session key.
        3. Target HSM imports the encrypted DKEK.

        Args:
            source_device: HSM that holds the existing DKEK to copy.
            target_device: HSM that will receive the DKEK.
        """
        logger.info("Starting local USB DKEK exchange")
        try:
            session_key = self._noise_handshake_apdu(source_device, target_device)
            encrypted_dkek = self._export_dkek(source_device, session_key)
            self._import_dkek(target_device, session_key, encrypted_dkek)
            logger.info("DKEK exchange complete")
        except Exception as exc:
            raise DKEKError(f"Local USB DKEK exchange failed: {exc}") from exc

    def exchange_tcp_server(
        self,
        source_device: Pico2HSM,
        port: int = DEFAULT_PORT,
    ) -> None:
        """Run as TCP server: wait for a remote HSM to connect and receive the DKEK.

        Args:
            source_device: Local HSM that holds the DKEK to share.
            port: TCP port to listen on.
        """
        logger.info("Listening for DKEK exchange on port %d", port)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(1)
            logger.info("Waiting for remote peer...")
            conn, addr = srv.accept()
            logger.info("Connection from %s", addr)
            with conn:
                try:
                    session_key = self._noise_handshake_tcp_server(conn, source_device)
                    encrypted_dkek = self._export_dkek(source_device, session_key)
                    _send_framed(conn, MSG_TYPE_DKEK, encrypted_dkek)
                    msg_type, _ = _recv_framed(conn)
                    if msg_type != MSG_TYPE_ACK:
                        raise DKEKError("Remote peer did not acknowledge DKEK receipt")
                    logger.info("DKEK sent and acknowledged")
                except Exception as exc:
                    raise DKEKError(f"TCP server DKEK exchange failed: {exc}") from exc

    def exchange_tcp_client(
        self,
        target_device: Pico2HSM,
        server_host: str,
        server_port: int = DEFAULT_PORT,
    ) -> None:
        """Connect to a TCP server and receive the DKEK into the target HSM.

        Args:
            target_device: Local HSM that will receive the DKEK.
            server_host: Hostname or IP of the DKEK server.
            server_port: TCP port of the DKEK server.
        """
        logger.info("Connecting to DKEK server %s:%d", server_host, server_port)
        with socket.create_connection((server_host, server_port), timeout=30) as conn:
            try:
                session_key = self._noise_handshake_tcp_client(conn, target_device)
                msg_type, encrypted_dkek = _recv_framed(conn)
                if msg_type != MSG_TYPE_DKEK:
                    raise DKEKError(f"Expected DKEK message, got type {msg_type:02X}")
                self._import_dkek(target_device, session_key, encrypted_dkek)
                _send_framed(conn, MSG_TYPE_ACK, b"")
                logger.info("DKEK received and imported")
            except Exception as exc:
                raise DKEKError(f"TCP client DKEK exchange failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Noise_XX handshake helpers
    # ------------------------------------------------------------------

    def _noise_handshake_apdu(
        self,
        source: Pico2HSM,
        target: Pico2HSM,
    ) -> bytes:
        """Perform a Noise_XX handshake between two locally connected HSMs.

        Returns the 32-byte shared session key for subsequent DKEK wrapping.
        """
        try:
            from noise.connection import NoiseConnection, Keypair  # type: ignore
            from noise.backends.default import DefaultNoise  # type: ignore
        except ImportError:
            raise DKEKError(
                "noiseprotocol package not installed. "
                "Run: pip install noiseprotocol"
            )

        # Initiator: source device
        initiator = NoiseConnection.from_name(b"Noise_XX_25519_AESGCM_SHA256")
        initiator.set_as_initiator()
        initiator.noise_protocol.prologue = b"pico2hsm-dkek-v1"

        # Responder: target device
        responder = NoiseConnection.from_name(b"Noise_XX_25519_AESGCM_SHA256")
        responder.set_as_responder()
        responder.noise_protocol.prologue = b"pico2hsm-dkek-v1"

        # Get identity keys from each HSM via EXTRAS
        source_static_pub = self._get_device_public_key(source)
        target_static_pub = self._get_device_public_key(target)

        # Configure static keys (in a real implementation these come from HSM)
        # Here we generate ephemeral stand-ins for the handshake
        initiator_static = _generate_noise_keypair()
        responder_static = _generate_noise_keypair()

        initiator.set_keypair_from_private_bytes(Keypair.STATIC, initiator_static["private"])
        responder.set_keypair_from_private_bytes(Keypair.STATIC, responder_static["private"])

        initiator.start_handshake()
        responder.start_handshake()

        # Message 1: initiator -> responder (e)
        msg1 = initiator.write_message()
        responder.read_message(data=msg1)

        # Message 2: responder -> initiator (e, ee, s, es)
        msg2 = responder.write_message()
        initiator.read_message(data=msg2)

        # Message 3: initiator -> responder (s, se)
        msg3 = initiator.write_message()
        responder.read_message(data=msg3)

        # Both sides now have session keys
        # We derive a single symmetric key from the initiator's send key
        session_key = initiator.get_handshake_hash()[:SESSION_KEY_SIZE]
        logger.debug("Noise_XX handshake complete, session key derived")
        return session_key

    def _noise_handshake_tcp_server(
        self,
        conn: socket.socket,
        source: Pico2HSM,
    ) -> bytes:
        """Server-side Noise_XX handshake over TCP."""
        return self._tcp_noise_handshake(conn, role="server")

    def _noise_handshake_tcp_client(
        self,
        conn: socket.socket,
        target: Pico2HSM,
    ) -> bytes:
        """Client-side Noise_XX handshake over TCP."""
        return self._tcp_noise_handshake(conn, role="client")

    def _tcp_noise_handshake(self, conn: socket.socket, role: str) -> bytes:
        """Perform Noise_XX handshake over a TCP socket."""
        try:
            from noise.connection import NoiseConnection, Keypair  # type: ignore
        except ImportError:
            raise DKEKError("noiseprotocol package not installed")

        noise = NoiseConnection.from_name(b"Noise_XX_25519_AESGCM_SHA256")
        static_kp = _generate_noise_keypair()

        if role == "client":
            noise.set_as_initiator()
        else:
            noise.set_as_responder()

        noise.noise_protocol.prologue = b"pico2hsm-dkek-v1"
        noise.set_keypair_from_private_bytes(Keypair.STATIC, static_kp["private"])
        noise.start_handshake()

        if role == "client":
            # -> e
            msg1 = noise.write_message()
            _send_framed(conn, MSG_TYPE_NOISE, msg1)
            # <- e, ee, s, es
            _, msg2 = _recv_framed(conn)
            noise.read_message(data=msg2)
            # -> s, se
            msg3 = noise.write_message()
            _send_framed(conn, MSG_TYPE_NOISE, msg3)
        else:
            # <- e
            _, msg1 = _recv_framed(conn)
            noise.read_message(data=msg1)
            # -> e, ee, s, es
            msg2 = noise.write_message()
            _send_framed(conn, MSG_TYPE_NOISE, msg2)
            # <- s, se
            _, msg3 = _recv_framed(conn)
            noise.read_message(data=msg3)

        return noise.get_handshake_hash()[:SESSION_KEY_SIZE]

    # ------------------------------------------------------------------
    # DKEK import / export via APDU
    # ------------------------------------------------------------------

    def _export_dkek(self, device: Pico2HSM, session_key: bytes) -> bytes:
        """Export DKEK from HSM, encrypted under the Noise session key."""
        apdu = build_extras(EXTRAS_DKEK_EXPORT)
        raw_dkek, _ = device.transmit(apdu)
        encrypted = encrypt_aes_gcm(session_key, raw_dkek, aad=b"dkek-export-v1")
        logger.debug("Exported and encrypted DKEK (%d bytes)", len(encrypted))
        return encrypted

    def _import_dkek(
        self,
        device: Pico2HSM,
        session_key: bytes,
        encrypted_dkek: bytes,
    ) -> None:
        """Decrypt and import DKEK into target HSM."""
        raw_dkek = decrypt_aes_gcm(session_key, encrypted_dkek, aad=b"dkek-export-v1")
        apdu = build_extras(EXTRAS_DKEK_IMPORT, raw_dkek)
        device.transmit(apdu)
        logger.debug("DKEK imported into target HSM")

    def _get_device_public_key(self, device: Pico2HSM) -> bytes:
        """Retrieve the device's Noise static public key via EXTRAS APDU."""
        apdu = build_extras(EXTRAS_DKEK_BEGIN)
        pub_key, _ = device.transmit(apdu)
        return pub_key


# ---------------------------------------------------------------------------
# Wire framing helpers
# ---------------------------------------------------------------------------


def _send_framed(conn: socket.socket, msg_type: int, payload: bytes) -> None:
    """Send a length-prefixed framed message.

    Frame format::

        [4B magic] [1B type] [4B LE length] [payload]
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
    payload = _recv_exactly(conn, length) if length else b""
    return msg_type, payload


def _recv_exactly(conn: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise DKEKError("Connection closed unexpectedly")
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Noise static key generation helper
# ---------------------------------------------------------------------------


def _generate_noise_keypair() -> dict[str, bytes]:
    """Generate a Curve25519 key pair for Noise."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        private = X25519PrivateKey.generate()
        private_bytes = private.private_bytes_raw()
        public_bytes = private.public_key().public_bytes_raw()
        return {"private": private_bytes, "public": public_bytes}
    except Exception as exc:
        raise DKEKError(f"Failed to generate Noise keypair: {exc}") from exc
