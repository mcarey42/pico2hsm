"""ECDSA sign + verify for MD5, SHA-1, RIPEMD-160, and GOSTR3411 digests.

PKCS#11 mechanism selection strategy
-------------------------------------
SHA-1 has a dedicated CKM_ECDSA_SHA1 mechanism (OpenSC algo 0x71); the card
computes the hash.  MD5, RIPEMD-160, and GOSTR3411 have no combined
ECDSA+hash PKCS#11 mechanisms, so for those we:
  1. Hash the message on the host.
  2. Pass the raw digest bytes to pkcs11-tool --mechanism ECDSA (CKM_ECDSA,
     algo 0x70 = ALGO_EC_RAW), which forwards the bytes verbatim to the card.
  3. Verify the resulting signature on the host using
     cryptography.hazmat.primitives.asymmetric.ec.ECDSA(Prehashed()).

Hash libraries used
-------------------
  SHA-1       : Python cryptography + hashlib (standard)
  MD5         : hashlib (standard)
  RIPEMD-160  : hashlib (OpenSSL-backed; available on this system)
  GOSTR3411   : gostcrypto.gosthash streebog256
                (GOST R 34.11-2012 / Streebog-256, the modern GOST hash standard;
                 GOST R 34.11-94 is unavailable without the older pygost package)
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Callable

import pytest

from conftest import KEY_SLOTS
from helpers import trace, crypto
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

TEST_MESSAGE = b"pico2hsm extra-hash sign test message"

# ---------------------------------------------------------------------------
# Hash method descriptors
# ---------------------------------------------------------------------------
# Each entry describes one hash algorithm to test.
#
# For SHA-1 the card hashes (mechanism = ECDSA-SHA1, input_is_prehash=False):
#   pkcs11-tool receives the raw message; it sends algo 0x71 and the card
#   computes SHA-1 internally.
# For the rest the host pre-hashes (mechanism = ECDSA, input_is_prehash=True):
#   pkcs11-tool receives the digest bytes and forwards them as-is (algo 0x70).

def _ripemd160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", data).digest()


def _streebog256(data: bytes) -> bytes:
    """GOST R 34.11-2012 (Streebog-256) via gostcrypto."""
    gostcrypto = pytest.importorskip(
        "gostcrypto", reason="gostcrypto not installed; skipping GOSTR3411 test"
    )
    h = gostcrypto.gosthash.new("streebog256", data=data)
    return h.digest()


HASH_METHODS: list[dict] = [
    {
        "name":            "sha1",
        "display":         "SHA-1",
        "mechanism":       "ECDSA-SHA1",
        "input_is_prehash": False,      # card hashes; send the raw message
        "host_hash_fn":    None,        # not needed: card does the hashing
        "verify_mode":     "named",     # use verify_ecdsa_signature(..., 'sha1')
        "verify_hash":     "sha1",
    },
    {
        "name":            "md5",
        "display":         "MD5",
        "mechanism":       "ECDSA",
        "input_is_prehash": True,       # host hashes; send digest to card
        "host_hash_fn":    lambda d: hashlib.md5(d).digest(),
        "verify_mode":     "prehash",
        "verify_hash":     None,
    },
    {
        "name":            "ripemd160",
        "display":         "RIPEMD-160",
        "mechanism":       "ECDSA",
        "input_is_prehash": True,
        "host_hash_fn":    _ripemd160,
        "verify_mode":     "prehash",
        "verify_hash":     None,
    },
    {
        "name":            "gostr34112012",
        "display":         "GOSTR3411 (Streebog-256)",
        "mechanism":       "ECDSA",
        "input_is_prehash": True,
        "host_hash_fn":    _streebog256,
        "verify_mode":     "prehash",
        "verify_hash":     None,
    },
]

# 4 slots × 4 hash methods = 16 combinations
_PARAMS = [
    pytest.param(slot, hm, id=f"{slot['name']}-{hm['name']}")
    for slot in KEY_SLOTS
    for hm in HASH_METHODS
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _prepare_input(
    hm: dict,
    message: bytes,
    tmp_path: Path,
) -> Path:
    """Return the path to the file that pkcs11-tool should sign.

    For pre-hash methods this is the digest; for card-hash methods it is the
    raw message.
    """
    if hm["input_is_prehash"]:
        digest = hm["host_hash_fn"](message)
        p = tmp_path / f"input_{hm['name']}.bin"
        p.write_bytes(digest)
        return p
    else:
        p = tmp_path / "message.bin"
        p.write_bytes(message)
        return p


def _run_sign(
    slot: dict,
    hm: dict,
    runner: CLIRunner,
    config: dict,
    input_file: Path,
    sig_file: Path,
    save_as: str | None,
) -> object:
    return runner.pkcs11_tool(
        "--login",
        "--pin",         config["pin"],
        "--sign",
        "--mechanism",   hm["mechanism"],
        "--id",          slot["key_id"],
        "--input-file",  str(input_file),
        "--output-file", str(sig_file),
        save_as=save_as,
    )


def _verify(
    hm: dict,
    pub_pem: str,
    message: bytes,
    sig_bytes: bytes,
) -> bool:
    if hm["verify_mode"] == "named":
        return crypto.verify_ecdsa_signature(pub_pem, message, sig_bytes, hm["verify_hash"])
    else:
        digest = hm["host_hash_fn"](message)
        return crypto.verify_ecdsa_prehash_signature(pub_pem, digest, sig_bytes)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("slot,hm", _PARAMS)
def test_extra_hash_sign_returns_data(
    slot: dict,
    hm: dict,
    provisioned_keys: dict,
    runner: CLIRunner,
    config: dict,
    run_dir: Path,
    tmp_path: Path,
) -> None:
    """Signing must succeed and produce a non-empty signature for every (curve, hash)."""
    entry = provisioned_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['curve_display']} was not generated.")

    # Eagerly skip GOSTR3411 if gostcrypto is not available
    if hm["name"] == "gostr34112012":
        pytest.importorskip("gostcrypto", reason="gostcrypto not installed")

    input_file = _prepare_input(hm, TEST_MESSAGE, tmp_path)
    sig_file = tmp_path / f"sig_{slot['name']}_{hm['name']}.bin"

    save_key = f"05_sign_{slot['name']}_{hm['name']}"
    result = _run_sign(slot, hm, runner, config, input_file, sig_file, save_key)

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / f"{save_key}.json",
        save_key,
        result,
        exchanges,
    )

    assert result.returncode == 0, (
        f"pkcs11-tool --sign failed for {slot['curve_display']} / "
        f"{hm['display']} (rc={result.returncode}):\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert sig_file.exists(), f"Signature output file not created: {sig_file}"
    sig_bytes = sig_file.read_bytes()
    assert len(sig_bytes) > 0, "Signature file is empty."
    log.info(
        "%s / %s: %d-byte signature  APDUs: %d",
        slot["curve_display"], hm["display"], len(sig_bytes), len(exchanges),
    )


@pytest.mark.parametrize("slot,hm", _PARAMS)
def test_extra_hash_signature_valid(
    slot: dict,
    hm: dict,
    provisioned_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """The signature must verify against the device public key using the same hash."""
    entry = provisioned_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['curve_display']} was not generated.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key not available for {slot['curve_display']}.")

    if hm["name"] == "gostr34112012":
        pytest.importorskip("gostcrypto", reason="gostcrypto not installed")

    input_file = _prepare_input(hm, TEST_MESSAGE, tmp_path)
    sig_file = tmp_path / "sig.bin"

    result = _run_sign(slot, hm, runner, config, input_file, sig_file, save_as=None)
    assert result.returncode == 0, (
        f"Signing failed for {slot['curve_display']} / {hm['display']} "
        f"(rc={result.returncode}):\n{result.stderr}"
    )

    sig_bytes = sig_file.read_bytes()
    assert len(sig_bytes) > 0, "Signature is empty."

    is_valid = _verify(hm, pub_pem, TEST_MESSAGE, sig_bytes)
    assert is_valid, (
        f"Signature did NOT verify for {slot['curve_display']} / {hm['display']}. "
        "The device may have used the wrong hash or produced a malformed signature."
    )
    log.info("%s / %s: signature verified OK", slot["curve_display"], hm["display"])
