"""Device enrollment — read device public key, save PEM, compute fingerprint."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    SECP256R1,
)
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)
from cryptography.hazmat.backends import default_backend

from .device import Pico2HSM
from .errors import EnrollmentError
from .protocol import build_get_device_pubkey, build_get_generation

logger = logging.getLogger(__name__)


@dataclass
class DeviceInfo:
    """Information retrieved from a connected HSM during enrollment."""
    pubkey: bytes            # 65-byte uncompressed P-256 public key
    fingerprint: str         # SHA-256 fingerprint (colon-separated hex, 16 bytes shown)
    generation: int          # Current key generation counter


class DeviceEnrollment:
    """Read and save the device identity public key."""

    @staticmethod
    def get_device_info(device: Pico2HSM) -> DeviceInfo:
        """Retrieve device public key and generation counter."""
        apdu = build_get_device_pubkey()
        try:
            pubkey_bytes, sw = device.transmit(apdu)
        except Exception as e:
            raise EnrollmentError(f"Failed to read device public key: {e}") from e

        if len(pubkey_bytes) != 65 or pubkey_bytes[0] != 0x04:
            raise EnrollmentError(
                f"Unexpected public key length/format: {len(pubkey_bytes)} bytes"
            )

        # Get generation counter
        try:
            gen_apdu = build_get_generation()
            gen_bytes, _ = device.transmit(gen_apdu)
            generation = int.from_bytes(gen_bytes[:4], "big") if len(gen_bytes) >= 4 else 0
        except Exception:
            generation = 0
            logger.debug("Could not retrieve generation counter; defaulting to 0")

        fingerprint = DeviceEnrollment.fingerprint(pubkey_bytes)
        logger.info("Device public key fingerprint: %s", fingerprint)
        return DeviceInfo(pubkey=pubkey_bytes, fingerprint=fingerprint, generation=generation)

    @staticmethod
    def save_pubkey_pem(pubkey_bytes: bytes, output_path: str) -> None:
        """Save a 65-byte uncompressed P-256 public key as PEM SubjectPublicKeyInfo."""
        from cryptography.hazmat.primitives.asymmetric.ec import (
            EllipticCurvePublicNumbers,
        )
        from cryptography.hazmat.primitives.asymmetric import ec

        if len(pubkey_bytes) != 65 or pubkey_bytes[0] != 0x04:
            raise EnrollmentError("Expected 65-byte uncompressed P-256 public key")

        x = int.from_bytes(pubkey_bytes[1:33], "big")
        y = int.from_bytes(pubkey_bytes[33:65], "big")
        pub_numbers = EllipticCurvePublicNumbers(x=x, y=y, curve=ec.SECP256R1())
        pub_key = pub_numbers.public_key(default_backend())
        pem = pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

        with open(output_path, "wb") as f:
            f.write(pem)
        logger.info("Public key saved to %s", output_path)

    @staticmethod
    def load_pubkey_pem(path: str) -> bytes:
        """Load a PEM file and return the 65-byte uncompressed P-256 public key."""
        try:
            with open(path, "rb") as f:
                pem_data = f.read()
            pub = load_pem_public_key(pem_data, backend=default_backend())
            return pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        except Exception as e:
            raise EnrollmentError(f"Failed to load PEM from {path}: {e}") from e

    @staticmethod
    def fingerprint(pubkey_bytes: bytes) -> str:
        """Compute a human-readable fingerprint (first 8 bytes of SHA-256, colon-separated)."""
        digest = hashlib.sha256(pubkey_bytes).hexdigest()
        return ":".join(digest[i:i+2] for i in range(0, 16, 2))
