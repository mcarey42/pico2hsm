"""Peer configuration for pico2hsm DKEK sync daemon."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

try:
    import yaml
except ImportError:
    raise ImportError("pyyaml is required: pip install pyyaml")

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    Encoding,
    PublicFormat,
)

from .errors import ConfigError


@dataclass
class PeerEntry:
    name: str
    role: str                        # "primary" | "secondary" | "quorum-member"
    public_key: bytes                # 65-byte uncompressed P-256 (internal representation)
    fingerprint: str                 # SHA-256 hex of public_key
    address: Optional[str] = None   # "host:port" for TCP sync, None for USB-only


@dataclass
class PeerConfig:
    peers: list[PeerEntry]
    listen_address: str = "0.0.0.0"
    listen_port: int = 7890
    state_dir: str = "~/.pico2hsm"
    log_level: str = "INFO"
    sync_on_connect: bool = True
    tls_enabled: bool = True         # Use anonymous TLS for TCP transport

    @classmethod
    def load(cls, path: str) -> "PeerConfig":
        """Load and validate YAML config file."""
        try:
            with open(path) as f:
                raw = yaml.safe_load(f)
        except Exception as e:
            raise ConfigError(f"Failed to read config {path}: {e}") from e

        if not isinstance(raw, dict):
            raise ConfigError("Config must be a YAML mapping")

        peers_raw = raw.get("peers", [])
        if not isinstance(peers_raw, list):
            raise ConfigError("'peers' must be a list")

        peers = []
        for entry in peers_raw:
            peer = cls._load_peer(entry)
            peers.append(peer)

        # Validate: exactly one primary
        primaries = [p for p in peers if p.role == "primary"]
        if len(primaries) > 1:
            raise ConfigError(f"Config has {len(primaries)} primary peers; exactly one is required")

        # Validate: no duplicate names or pubkeys
        names = [p.name for p in peers]
        if len(names) != len(set(names)):
            raise ConfigError("Duplicate peer names in config")

        return cls(
            peers=peers,
            listen_address=raw.get("listen_address", "0.0.0.0"),
            listen_port=int(raw.get("listen_port", 7890)),
            state_dir=raw.get("state_dir", "~/.pico2hsm"),
            log_level=raw.get("log_level", "INFO"),
            sync_on_connect=bool(raw.get("sync_on_connect", True)),
            tls_enabled=bool(raw.get("tls_enabled", True)),
        )

    @classmethod
    def _load_peer(cls, entry: dict) -> PeerEntry:
        import hashlib
        name = entry.get("name")
        if not name:
            raise ConfigError("Peer entry missing 'name'")
        role = entry.get("role", "secondary")
        if role not in ("primary", "secondary", "quorum-member"):
            raise ConfigError(f"Peer '{name}' has invalid role '{role}'")

        # Load public key from file or inline
        pubkey_bytes: Optional[bytes] = None
        if "public_key_file" in entry:
            path = os.path.expanduser(entry["public_key_file"])
            try:
                with open(path, "rb") as f:
                    pem_data = f.read()
                pub = load_pem_public_key(pem_data)
                pubkey_bytes = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            except Exception as e:
                raise ConfigError(f"Failed to load public key for peer '{name}': {e}") from e
        elif "public_key" in entry:
            import base64
            try:
                der_bytes = base64.b64decode(entry["public_key"])
                from cryptography.hazmat.primitives.serialization import load_der_public_key
                pub = load_der_public_key(der_bytes)
                pubkey_bytes = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            except Exception as e:
                raise ConfigError(f"Failed to parse inline public key for peer '{name}': {e}") from e
        else:
            raise ConfigError(f"Peer '{name}' has no public key (public_key_file or public_key required)")

        if len(pubkey_bytes) != 65:
            raise ConfigError(f"Peer '{name}' public key is not 65 bytes (expected uncompressed P-256)")

        fingerprint = ":".join(
            hashlib.sha256(pubkey_bytes).hexdigest()[i:i+2]
            for i in range(0, 16, 2)  # First 8 bytes for display
        )

        return PeerEntry(
            name=name,
            role=role,
            public_key=pubkey_bytes,
            fingerprint=fingerprint,
            address=entry.get("address"),
        )

    def find_peer_by_pubkey(self, pubkey: bytes) -> Optional[PeerEntry]:
        for p in self.peers:
            if p.public_key == pubkey:
                return p
        return None

    def find_peer_by_name(self, name: str) -> Optional[PeerEntry]:
        for p in self.peers:
            if p.name == name:
                return p
        return None

    def get_primary(self) -> Optional[PeerEntry]:
        for p in self.peers:
            if p.role == "primary":
                return p
        return None

    def get_secondaries(self) -> list[PeerEntry]:
        return [p for p in self.peers if p.role == "secondary"]
