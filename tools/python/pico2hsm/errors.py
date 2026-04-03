"""Exception classes for pico2hsm."""

from __future__ import annotations


class Pico2HSMError(Exception):
    """Base exception for all pico2hsm errors."""


class DeviceNotFoundError(Pico2HSMError):
    """Raised when no HSM device is found."""


class DeviceConnectionError(Pico2HSMError):
    """Raised when connection to HSM fails."""


class APDUError(Pico2HSMError):
    """Raised when an APDU returns a non-9000 status word."""

    def __init__(self, sw: int, message: str = ""):
        self.sw = sw
        self.sw1 = (sw >> 8) & 0xFF
        self.sw2 = sw & 0xFF
        msg = f"APDU error SW={sw:04X}"
        if message:
            msg = f"{msg}: {message}"
        super().__init__(msg)

    @property
    def description(self) -> str:
        """Human-readable description of the status word."""
        return _SW_DESCRIPTIONS.get(self.sw, f"Unknown status {self.sw:04X}")


class ProtocolError(Pico2HSMError):
    """Raised when an unexpected protocol response is received."""


class PINError(Pico2HSMError):
    """Raised on PIN verification failure."""

    def __init__(self, retries_remaining: int | None = None):
        self.retries_remaining = retries_remaining
        if retries_remaining is not None:
            msg = f"PIN verification failed. Retries remaining: {retries_remaining}"
        else:
            msg = "PIN verification failed."
        super().__init__(msg)


class DKEKError(Pico2HSMError):
    """Raised on DKEK ceremony errors."""


class StorageError(Pico2HSMError):
    """Raised on storage / RAID errors."""


class KeyError(Pico2HSMError):
    """Raised on key management errors."""


# Common status word descriptions
_SW_DESCRIPTIONS: dict[int, str] = {
    0x9000: "Success",
    0x6100: "Response bytes still available",
    0x6283: "File deactivated",
    0x6300: "Verification failed",
    0x6400: "Execution error (no precise diagnosis)",
    0x6500: "Memory failure",
    0x6700: "Wrong length",
    0x6881: "Logical channel not supported",
    0x6882: "Secure messaging not supported",
    0x6900: "Command not allowed",
    0x6981: "Command incompatible with file structure",
    0x6982: "Security status not satisfied",
    0x6983: "Authentication method blocked",
    0x6984: "Referenced data invalidated",
    0x6985: "Conditions of use not satisfied",
    0x6986: "Command not allowed (no EF selected)",
    0x6988: "Incorrect secure messaging data objects",
    0x6A00: "Wrong parameters P1-P2",
    0x6A80: "Incorrect parameters in the data field",
    0x6A81: "Function not supported",
    0x6A82: "File not found",
    0x6A83: "Record not found",
    0x6A84: "Not enough memory space",
    0x6A86: "Incorrect parameters P1-P2",
    0x6A88: "Referenced data not found",
    0x6B00: "Wrong parameters (offset outside EF)",
    0x6C00: "Wrong Le field",
    0x6D00: "Instruction code not supported or invalid",
    0x6E00: "Class not supported",
    0x6F00: "No precise diagnosis",
}
