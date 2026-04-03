"""RSA signing tests — PKCS#1 v1.5 and PSS.

Covers:
- PKCS#1 v1.5 sign + verify (SHA-256)
- PSS sign + verify (SHA-256)
- Signature length matches RSA modulus size
- APDU trace captured for both mechanisms
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from conftest import RSA_KEY_SLOTS
from helpers import trace
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

TEST_MESSAGE = b"pico2hsm RSA hardware test message - sign and verify"

_SLOT_PARAMS = pytest.mark.parametrize(
    "slot",
    RSA_KEY_SLOTS,
    ids=[s["name"] for s in RSA_KEY_SLOTS],
)


def _load_rsa_pub(pub_pem: str) -> RSAPublicKey:
    return serialization.load_pem_public_key(  # type: ignore[return-value]
        pub_pem.encode(), backend=default_backend()
    )


def _sign_pkcs(
    slot: dict,
    runner: CLIRunner,
    config: dict,
    msg_path: Path,
    sig_path: Path,
    save_as: str | None,
):
    """Sign with PKCS#1 v1.5 (pkcs11-tool --sign --mechanism SHA256-RSA-PKCS)."""
    return runner.pkcs11_tool(
        "--login",
        "--pin",          config["pin"],
        "--sign",
        "--mechanism",    slot["mechanism_pkcs"],
        "--id",           slot["key_id"],
        "--input-file",   str(msg_path),
        "--output-file",  str(sig_path),
        save_as=save_as,
    )


def _sign_pss(
    slot: dict,
    runner: CLIRunner,
    config: dict,
    msg_path: Path,
    sig_path: Path,
    save_as: str | None,
):
    """Sign with RSA-PSS (pkcs11-tool --sign --mechanism SHA256-RSA-PKCS-PSS)."""
    return runner.pkcs11_tool(
        "--login",
        "--pin",          config["pin"],
        "--sign",
        "--mechanism",    slot["mechanism_pss"],
        "--id",           slot["key_id"],
        "--input-file",   str(msg_path),
        "--output-file",  str(sig_path),
        save_as=save_as,
    )


# ---------------------------------------------------------------------------
# PKCS#1 v1.5 tests
# ---------------------------------------------------------------------------

@_SLOT_PARAMS
def test_rsa_pkcs_sign_succeeds(
    slot: dict,
    provisioned_rsa_keys: dict,
    runner: CLIRunner,
    config: dict,
    run_dir: Path,
    tmp_path: Path,
) -> None:
    """PKCS#1 v1.5 sign must succeed and produce a non-empty signature."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"RSA key for {slot['name']} was not generated.")

    msg_file = tmp_path / "message.bin"
    sig_file = tmp_path / f"sig_pkcs_{slot['name']}.bin"
    msg_file.write_bytes(TEST_MESSAGE)

    result = _sign_pkcs(
        slot, runner, config, msg_file, sig_file,
        save_as=f"07_rsa_pkcs_sign_{slot['name']}",
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / f"07_rsa_pkcs_sign_{slot['name']}.json",
        f"rsa_pkcs_sign_{slot['name']}",
        result,
        exchanges,
    )

    assert result.returncode == 0, (
        f"PKCS#1 v1.5 sign failed for {slot['name']} (rc={result.returncode}):\n"
        f"{result.stderr}"
    )
    assert sig_file.exists(), "Signature file not created."
    sig_bytes = sig_file.read_bytes()
    assert len(sig_bytes) > 0, "Signature file is empty."
    log.info(
        "%s PKCS#1v1.5 signature: %d bytes  APDUs: %d",
        slot["name"], len(sig_bytes), len(exchanges),
    )


@_SLOT_PARAMS
def test_rsa_pkcs_sign_length(
    slot: dict,
    provisioned_rsa_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """PKCS#1 v1.5 signature must be exactly sig_len bytes (= key_size // 8)."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"RSA key for {slot['name']} was not generated.")

    msg_file = tmp_path / "message.bin"
    sig_file = tmp_path / "sig.bin"
    msg_file.write_bytes(TEST_MESSAGE)

    result = _sign_pkcs(slot, runner, config, msg_file, sig_file, save_as=None)
    assert result.returncode == 0, f"Signing failed: {result.stderr}"

    sig_bytes = sig_file.read_bytes()
    assert len(sig_bytes) == slot["sig_len"], (
        f"Expected {slot['sig_len']}-byte signature, got {len(sig_bytes)} bytes."
    )


@_SLOT_PARAMS
def test_rsa_pkcs_sign_verifies(
    slot: dict,
    provisioned_rsa_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """PKCS#1 v1.5 signature must verify against the device's RSA public key."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"RSA key for {slot['name']} was not generated.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key not available for {slot['name']}.")

    msg_file = tmp_path / "message.bin"
    sig_file = tmp_path / "sig.bin"
    msg_file.write_bytes(TEST_MESSAGE)

    result = _sign_pkcs(slot, runner, config, msg_file, sig_file, save_as=None)
    assert result.returncode == 0, f"Signing failed: {result.stderr}"

    sig_bytes = sig_file.read_bytes()
    pub_key = _load_rsa_pub(pub_pem)

    # pkcs11-tool SHA256-RSA-PKCS hashes the message internally; verify likewise
    pub_key.verify(
        sig_bytes,
        TEST_MESSAGE,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    log.info("%s PKCS#1v1.5 signature verified OK", slot["name"])


@_SLOT_PARAMS
def test_rsa_pkcs_sign_two_independent_sigs_valid(
    slot: dict,
    provisioned_rsa_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """Two independent PKCS#1 v1.5 signatures must both verify (deterministic = OK)."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"RSA key for {slot['name']} was not generated.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key not available for {slot['name']}.")

    msg_file = tmp_path / "message.bin"
    msg_file.write_bytes(TEST_MESSAGE)
    pub_key = _load_rsa_pub(pub_pem)

    for i in range(2):
        sig_file = tmp_path / f"sig_{i}.bin"
        result = _sign_pkcs(slot, runner, config, msg_file, sig_file, save_as=None)
        assert result.returncode == 0, f"Sign attempt {i+1} failed: {result.stderr}"
        sig_bytes = sig_file.read_bytes()
        pub_key.verify(sig_bytes, TEST_MESSAGE, padding.PKCS1v15(), hashes.SHA256())
        log.info("%s sig %d/2 verified OK", slot["name"], i + 1)


# ---------------------------------------------------------------------------
# PSS tests
# ---------------------------------------------------------------------------

@_SLOT_PARAMS
def test_rsa_pss_sign_succeeds(
    slot: dict,
    provisioned_rsa_keys: dict,
    runner: CLIRunner,
    config: dict,
    run_dir: Path,
    tmp_path: Path,
) -> None:
    """PSS sign must succeed and produce a non-empty signature."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"RSA key for {slot['name']} was not generated.")

    msg_file = tmp_path / "message.bin"
    sig_file = tmp_path / f"sig_pss_{slot['name']}.bin"
    msg_file.write_bytes(TEST_MESSAGE)

    result = _sign_pss(
        slot, runner, config, msg_file, sig_file,
        save_as=f"07_rsa_pss_sign_{slot['name']}",
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / f"07_rsa_pss_sign_{slot['name']}.json",
        f"rsa_pss_sign_{slot['name']}",
        result,
        exchanges,
    )

    assert result.returncode == 0, (
        f"PSS sign failed for {slot['name']} (rc={result.returncode}):\n{result.stderr}"
    )
    assert sig_file.exists(), "Signature file not created."
    sig_bytes = sig_file.read_bytes()
    assert len(sig_bytes) > 0, "Signature file is empty."
    log.info(
        "%s PSS signature: %d bytes  APDUs: %d",
        slot["name"], len(sig_bytes), len(exchanges),
    )


@_SLOT_PARAMS
def test_rsa_pss_sign_length(
    slot: dict,
    provisioned_rsa_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """PSS signature must be exactly sig_len bytes (= key_size // 8)."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"RSA key for {slot['name']} was not generated.")

    msg_file = tmp_path / "message.bin"
    sig_file = tmp_path / "sig.bin"
    msg_file.write_bytes(TEST_MESSAGE)

    result = _sign_pss(slot, runner, config, msg_file, sig_file, save_as=None)
    assert result.returncode == 0, f"Signing failed: {result.stderr}"

    sig_bytes = sig_file.read_bytes()
    assert len(sig_bytes) == slot["sig_len"], (
        f"Expected {slot['sig_len']}-byte PSS signature, got {len(sig_bytes)} bytes."
    )


@_SLOT_PARAMS
def test_rsa_pss_sign_verifies(
    slot: dict,
    provisioned_rsa_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """PSS signature must verify against the device's RSA public key (salt=32)."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"RSA key for {slot['name']} was not generated.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key not available for {slot['name']}.")

    msg_file = tmp_path / "message.bin"
    sig_file = tmp_path / "sig.bin"
    msg_file.write_bytes(TEST_MESSAGE)

    result = _sign_pss(slot, runner, config, msg_file, sig_file, save_as=None)
    assert result.returncode == 0, f"Signing failed: {result.stderr}"

    sig_bytes = sig_file.read_bytes()
    pub_key = _load_rsa_pub(pub_pem)

    # Firmware uses salt_len=32 (digest length for SHA-256)
    pub_key.verify(
        sig_bytes,
        TEST_MESSAGE,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32,
        ),
        hashes.SHA256(),
    )
    log.info("%s PSS signature verified OK", slot["name"])


@_SLOT_PARAMS
def test_rsa_pss_sign_trace_has_apdus(
    slot: dict,
    provisioned_rsa_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """PSS sign trace must contain parseable APDU exchanges."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"RSA key for {slot['name']} was not generated.")

    msg_file = tmp_path / "message.bin"
    sig_file = tmp_path / "sig.bin"
    msg_file.write_bytes(TEST_MESSAGE)

    result = _sign_pss(slot, runner, config, msg_file, sig_file, save_as=None)
    assert result.returncode == 0, f"Signing failed: {result.stderr}"

    exchanges = trace.parse_apdu_trace(result.stderr)
    assert len(exchanges) > 0, (
        f"No APDU exchanges in PSS sign trace.\nStderr: {result.stderr[:400]}"
    )
    log.info("%s PSS sign APDU count: %d", slot["name"], len(exchanges))
