"""pico2hsm — Host-side Python library for the pico2hsm HSM device.

This package provides:
- device.py      : USB/PCSC connection and APDU transport
- protocol.py    : SC-HSM APDU command builders and parsers
- crypto.py      : Host-side cryptographic helpers
- dkek.py        : DKEK exchange via P-256 ECDH relay protocol
- config.py      : Peer configuration for DKEK sync daemon
- enrollment.py  : Device enrollment and identity key management
- storage.py     : Storage status and RAID resync
- errors.py      : Exception hierarchy
"""

from .device import Pico2HSM
from .errors import (
    APDUError,
    ConfigError,
    DKEKError,
    DeviceConnectionError,
    DeviceNotFoundError,
    EnrollmentError,
    KeyError,
    PINError,
    Pico2HSMError,
    ProtocolError,
    StorageError,
    SyncError,
)
from .config import PeerConfig, PeerEntry
from .enrollment import DeviceEnrollment, DeviceInfo
from .dkek import DkekExchange

__version__ = "0.1.0"
__all__ = [
    "Pico2HSM",
    "Pico2HSMError",
    "APDUError",
    "ConfigError",
    "DeviceNotFoundError",
    "DeviceConnectionError",
    "EnrollmentError",
    "PINError",
    "DKEKError",
    "StorageError",
    "KeyError",
    "ProtocolError",
    "SyncError",
    "PeerConfig",
    "PeerEntry",
    "DeviceEnrollment",
    "DeviceInfo",
    "DkekExchange",
]
