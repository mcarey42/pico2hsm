"""pico2hsm — Host-side Python library for the pico2hsm HSM device.

This package provides:
- device.py    : USB/PCSC connection and APDU transport
- protocol.py  : SC-HSM APDU command builders and parsers
- crypto.py    : Host-side cryptographic helpers
- dkek.py      : DKEK ceremony and Noise_XX exchange
- storage.py   : Storage status and RAID resync
- errors.py    : Exception hierarchy
"""

from .device import Pico2HSM
from .errors import (
    APDUError,
    DKEKError,
    DeviceConnectionError,
    DeviceNotFoundError,
    KeyError,
    PINError,
    Pico2HSMError,
    ProtocolError,
    StorageError,
)

__version__ = "0.1.0"
__all__ = [
    "Pico2HSM",
    "Pico2HSMError",
    "APDUError",
    "DeviceNotFoundError",
    "DeviceConnectionError",
    "PINError",
    "DKEKError",
    "StorageError",
    "KeyError",
    "ProtocolError",
]
