"""USB/PCSC device connection and APDU transport for pico2hsm."""

from __future__ import annotations

import logging
import struct
from typing import Optional

from .errors import (
    APDUError,
    DeviceConnectionError,
    DeviceNotFoundError,
    PINError,
)

logger = logging.getLogger(__name__)

# SC-HSM AID: E8 2B 06 01 04 01 81 C3 1F 02 01
SC_HSM_AID = bytes([0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01])

# pico2hsm USB identifiers
PICO2HSM_VID = 0x2E8A  # Raspberry Pi
PICO2HSM_PID = 0x000A  # pico2hsm HID device (placeholder)

# CCID USB class
CCID_CLASS = 0x0B

SW_SUCCESS = 0x9000
SW_MORE_DATA_MASK = 0x6100


class Pico2HSM:
    """Connection to a pico2hsm device via USB CCID (PCSC) or direct USB HID.

    Tries PCSC first (pyscard), falls back to direct USB HID (hidapi).
    Use as a context manager for automatic disconnect::

        with Pico2HSM() as hsm:
            hsm.select_applet()
            data, sw = hsm.transmit(apdu)
    """

    SC_HSM_AID = SC_HSM_AID

    def __init__(self, reader_index: int = 0, debug: bool = False):
        """Connect to HSM.

        Args:
            reader_index: Index of the PCSC reader to use (default 0).
            debug: If True, log raw APDUs at DEBUG level.
        """
        self.reader_index = reader_index
        self.debug = debug
        self._connection = None
        self._transport: str = "none"
        self._hid_device = None
        self._connected = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Connect to the HSM.  Tries PCSC first, then direct USB HID."""
        try:
            self._connect_pcsc()
            self._transport = "pcsc"
        except Exception as pcsc_err:
            logger.debug("PCSC connection failed (%s), trying USB HID", pcsc_err)
            try:
                self._connect_hid()
                self._transport = "hid"
            except Exception as hid_err:
                raise DeviceNotFoundError(
                    f"Could not connect to pico2hsm via PCSC ({pcsc_err}) "
                    f"or USB HID ({hid_err}). "
                    "Is the device plugged in and do you have permission to access it?"
                ) from hid_err
        self._connected = True
        logger.debug("Connected via %s (reader index %d)", self._transport, self.reader_index)

    def disconnect(self) -> None:
        """Disconnect from the HSM."""
        if not self._connected:
            return
        try:
            if self._transport == "pcsc" and self._connection is not None:
                self._connection.disconnect()
            elif self._transport == "hid" and self._hid_device is not None:
                self._hid_device.close()
        except Exception as exc:
            logger.debug("Error during disconnect: %s", exc)
        finally:
            self._connection = None
            self._hid_device = None
            self._connected = False

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        """Send an APDU and return ``(response_data, sw)``.

        Args:
            apdu: Raw APDU bytes to send.

        Returns:
            Tuple of (response data bytes, 2-byte status word as int).

        Raises:
            APDUError: If the status word is not 0x9000 (or 0x61xx).
            DeviceConnectionError: If no connection is active.
        """
        if not self._connected:
            raise DeviceConnectionError("Not connected. Call connect() first.")

        if self.debug:
            logger.debug("APDU >  %s", apdu.hex().upper())

        if self._transport == "pcsc":
            data, sw = self._transmit_pcsc(apdu)
        else:
            data, sw = self._transmit_hid(apdu)

        if self.debug:
            logger.debug("APDU <  %s SW=%04X", data.hex().upper(), sw)

        # Handle GET RESPONSE chaining (SW 61xx)
        while (sw >> 8) == 0x61:
            remaining = sw & 0xFF
            le = remaining if remaining != 0 else 0x00
            get_resp = bytes([0x00, 0xC0, 0x00, 0x00, le])
            more_data, sw = self._raw_transmit(get_resp)
            data += more_data

        if sw == SW_SUCCESS:
            return data, sw

        # Map PIN blocked / wrong PIN to PINError
        if sw == 0x6983:
            raise PINError(retries_remaining=0)
        if (sw >> 8) == 0x63 and (sw & 0xF0) == 0xC0:
            retries = sw & 0x0F
            raise PINError(retries_remaining=retries)

        raise APDUError(sw)

    def select_applet(self) -> None:
        """Send SELECT command to activate the SC-HSM applet."""
        aid = self.SC_HSM_AID
        # CLA=00 INS=A4 P1=04 P2=00 Lc=len(AID) AID Le=00
        apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid + bytes([0x00])
        self.transmit(apdu)
        logger.debug("SC-HSM applet selected")

    def get_key_manifest(self) -> list:
        """Fetch the key manifest from the device.

        Returns a list of KeyManifestEntry objects.
        """
        from .manifest import parse_key_manifest
        from .protocol import build_get_key_manifest

        apdu = build_get_key_manifest()
        data, sw = self.transmit(apdu)
        return parse_key_manifest(data)

    def get_state_hash(self) -> tuple:
        """Fetch the state hash from the device.

        Returns (generation: int, state_root: bytes[32], sig: bytes[64]).
        """
        from .protocol import build_get_state_hash

        apdu = build_get_state_hash()
        data, sw = self.transmit(apdu)
        if len(data) != 104:
            raise DeviceConnectionError(
                f"GET_STATE_HASH: expected 104 bytes, got {len(data)}"
            )
        generation = struct.unpack(">Q", data[0:8])[0]
        state_root = data[8:40]
        sig = data[40:104]
        return generation, state_root, sig

    def get_generation_v2(self) -> int:
        """Returns u64 generation counter."""
        from .protocol import build_get_generation_v2

        apdu = build_get_generation_v2()
        data, sw = self.transmit(apdu)
        if len(data) != 8:
            raise DeviceConnectionError(
                f"GET_GENERATION_V2: expected 8 bytes, got {len(data)}"
            )
        return struct.unpack(">Q", data)[0]

    @classmethod
    def list_devices(cls) -> list[str]:
        """Return a list of available HSM reader/device names."""
        devices: list[str] = []

        # Try PCSC
        try:
            from smartcard.System import readers as pcsc_readers  # type: ignore

            for r in pcsc_readers():
                devices.append(f"PCSC: {r}")
        except Exception:
            pass

        # Try HID
        try:
            import hid  # type: ignore

            for dev in hid.enumerate(PICO2HSM_VID, 0):
                devices.append(
                    f"HID: {dev.get('manufacturer_string', '')} "
                    f"{dev.get('product_string', '')} "
                    f"(VID={dev['vendor_id']:04X} PID={dev['product_id']:04X})"
                )
        except Exception:
            pass

        return devices

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "Pico2HSM":
        self.connect()
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()

    # ------------------------------------------------------------------
    # PCSC transport
    # ------------------------------------------------------------------

    def _connect_pcsc(self) -> None:
        from smartcard.System import readers as pcsc_readers  # type: ignore
        from smartcard.util import toBytes  # type: ignore  # noqa: F401

        reader_list = pcsc_readers()
        if not reader_list:
            raise DeviceNotFoundError("No PCSC readers found")
        if self.reader_index >= len(reader_list):
            raise DeviceNotFoundError(
                f"Reader index {self.reader_index} out of range "
                f"({len(reader_list)} readers available)"
            )
        reader = reader_list[self.reader_index]
        self._connection = reader.createConnection()
        self._connection.connect()

    def _transmit_pcsc(self, apdu: bytes) -> tuple[bytes, int]:
        from smartcard.util import toBytes, toHexString  # type: ignore  # noqa: F401

        apdu_list = list(apdu)
        data, sw1, sw2 = self._connection.transmit(apdu_list)
        sw = (sw1 << 8) | sw2
        return bytes(data), sw

    # ------------------------------------------------------------------
    # USB HID transport (fallback)
    # ------------------------------------------------------------------

    def _connect_hid(self) -> None:
        import hid  # type: ignore

        # Find a pico2hsm device
        for dev_info in hid.enumerate(PICO2HSM_VID, 0):
            try:
                device = hid.device()
                device.open_path(dev_info["path"])
                self._hid_device = device
                return
            except Exception:
                continue

        raise DeviceNotFoundError(
            f"No pico2hsm USB HID device found (VID={PICO2HSM_VID:04X})"
        )

    def _transmit_hid(self, apdu: bytes) -> tuple[bytes, int]:
        """Send APDU over raw HID using a simple length-prefixed framing."""
        if self._hid_device is None:
            raise DeviceConnectionError("HID device not open")

        # Frame: [report_id=0x00] [2-byte LE length] [apdu]
        length = len(apdu)
        frame = bytes([0x00]) + struct.pack(">H", length) + apdu
        self._hid_device.write(list(frame))

        # Read response: [2-byte LE length] [data] [sw1] [sw2]
        response = bytes(self._hid_device.read(4096))
        if len(response) < 4:
            raise DeviceConnectionError("Short HID response")

        resp_len = struct.unpack(">H", response[:2])[0]
        payload = response[2 : 2 + resp_len]
        if len(payload) < 2:
            raise DeviceConnectionError("HID response too short for status word")

        sw = (payload[-2] << 8) | payload[-1]
        data = payload[:-2]
        return data, sw

    def _raw_transmit(self, apdu: bytes) -> tuple[bytes, int]:
        """Internal raw transmit without chaining logic."""
        if self._transport == "pcsc":
            return self._transmit_pcsc(apdu)
        return self._transmit_hid(apdu)
