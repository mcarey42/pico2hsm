"""Cross-hash ECDSA sign + verify tests.

Tests all combinations of the three firmware-supported hash algorithms
(SHA-256, SHA-384, SHA-512) × all four key slots (P-256, P-384, P-521, K-256).

The firmware's sign.rs handles:
  algo 0x71/0x73 → SHA-256  (card hashes the raw message)
  algo 0x75      → SHA-384
  algo 0x77      → SHA-512
  algo 0x13/0x15/0x17/0x19/0x70 → pass-through (host pre-hashed)

pkcs11-tool selects the algo code via --mechanism ECDSA-SHAxxx, so all
hash/curve combinations are exercised end-to-end through the PKCS#11 layer.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from conftest import KEY_SLOTS
from helpers import trace, crypto
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

TEST_MESSAGE = b"pico2hsm cross-hash sign test message"

# All three hash algorithms the firmware supports for ECDSA.
HASH_MECHANISMS = [
    {"hash": "sha256", "mechanism": "ECDSA-SHA256"},
    {"hash": "sha384", "mechanism": "ECDSA-SHA384"},
    {"hash": "sha512", "mechanism": "ECDSA-SHA512"},
]

# Full cross-product: 4 slots × 3 hashes = 12 test cases.
_CROSS_PARAMS = [
    pytest.param(slot, mech, id=f"{slot['name']}-{mech['hash']}")
    for slot in KEY_SLOTS
    for mech in HASH_MECHANISMS
]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("slot,hash_mech", _CROSS_PARAMS)
def test_cross_hash_sign_returns_data(
    slot: dict,
    hash_mech: dict,
    provisioned_keys: dict,
    runner: CLIRunner,
    config: dict,
    run_dir: Path,
    tmp_path: Path,
) -> None:
    """Signing must succeed for every (curve, hash) combination."""
    entry = provisioned_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['curve_display']} was not generated.")

    msg_file = tmp_path / "message.bin"
    sig_file = tmp_path / f"sig_{slot['name']}_{hash_mech['hash']}.bin"
    msg_file.write_bytes(TEST_MESSAGE)

    save_key = f"04_sign_{slot['name']}_{hash_mech['hash']}"
    result = runner.pkcs11_tool(
        "--login",
        "--pin",         config["pin"],
        "--sign",
        "--mechanism",   hash_mech["mechanism"],
        "--id",          slot["key_id"],
        "--input-file",  str(msg_file),
        "--output-file", str(sig_file),
        save_as=save_key,
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / f"{save_key}.json",
        save_key,
        result,
        exchanges,
    )

    assert result.returncode == 0, (
        f"pkcs11-tool --sign failed for {slot['curve_display']} / {hash_mech['mechanism']} "
        f"(rc={result.returncode}):\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert sig_file.exists(), f"Signature output file not created: {sig_file}"
    sig_bytes = sig_file.read_bytes()
    assert len(sig_bytes) > 0, "Signature file is empty."
    log.info(
        "%s / %s: %d-byte signature  APDUs: %d",
        slot["curve_display"], hash_mech["mechanism"], len(sig_bytes), len(exchanges),
    )


@pytest.mark.parametrize("slot,hash_mech", _CROSS_PARAMS)
def test_cross_hash_signature_valid(
    slot: dict,
    hash_mech: dict,
    provisioned_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """The signature produced with each (curve, hash) must verify against the device public key."""
    entry = provisioned_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['curve_display']} was not generated.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key not available for {slot['curve_display']}.")

    msg_file = tmp_path / "message.bin"
    sig_file = tmp_path / "sig.bin"
    msg_file.write_bytes(TEST_MESSAGE)

    result = runner.pkcs11_tool(
        "--login",
        "--pin",         config["pin"],
        "--sign",
        "--mechanism",   hash_mech["mechanism"],
        "--id",          slot["key_id"],
        "--input-file",  str(msg_file),
        "--output-file", str(sig_file),
        save_as=None,
    )
    assert result.returncode == 0, (
        f"Signing failed for {slot['curve_display']} / {hash_mech['mechanism']} "
        f"(rc={result.returncode}):\n{result.stderr}"
    )

    sig_bytes = sig_file.read_bytes()
    assert len(sig_bytes) > 0, "Signature is empty."

    is_valid = crypto.verify_ecdsa_signature(
        pub_pem, TEST_MESSAGE, sig_bytes, hash_mech["hash"],
    )
    assert is_valid, (
        f"Signature did NOT verify for {slot['curve_display']} / {hash_mech['mechanism']}. "
        "The device may have used the wrong hash or produced a malformed signature."
    )
    log.info(
        "%s / %s: signature verified OK",
        slot["curve_display"], hash_mech["mechanism"],
    )
