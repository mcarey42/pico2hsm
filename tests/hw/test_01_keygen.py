"""Parametrized key generation tests for all supported EC curves."""

from __future__ import annotations

import logging

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives import serialization

from conftest import KEY_SLOTS
from helpers import trace
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# Parametrize by slot name so pytest IDs are human-readable (p256, p384, …)
_SLOT_PARAMS = pytest.mark.parametrize(
    "slot",
    KEY_SLOTS,
    ids=[s["name"] for s in KEY_SLOTS],
)

# Map OpenSSL curve names to cryptography library curve class names
_CURVE_CLASS_NAME: dict[str, str] = {
    "prime256v1": "SECP256R1",
    "secp384r1":  "SECP384R1",
    "secp521r1":  "SECP521R1",
    "secp256k1":  "SECP256K1",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@_SLOT_PARAMS
def test_keygen_succeeds(slot: dict, provisioned_keys: dict) -> None:
    """Key generation must succeed for each supported curve."""
    entry = provisioned_keys.get(slot["name"])
    if entry is None:
        pytest.skip(f"No provisioning result recorded for slot '{slot['name']}'")
    if not entry["generated"]:
        pytest.skip(
            f"Key generation was skipped/failed for {slot['curve_display']}. "
            f"The host OpenSC build may not support {slot['curve_openssl']}."
        )
    assert entry["generated"] is True


@_SLOT_PARAMS
def test_keygen_public_key_exported(slot: dict, provisioned_keys: dict) -> None:
    """After keygen, the public key must be exportable as a PEM string."""
    entry = provisioned_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['curve_display']} was not generated.")

    pub_pem = entry.get("pub_pem")
    assert pub_pem is not None, (
        f"Public key PEM is None for {slot['curve_display']} (id={slot['key_id']}). "
        "Check that pkcs11-tool --read-object succeeded."
    )
    assert pub_pem.strip().startswith("-----BEGIN PUBLIC KEY-----"), (
        f"Expected PEM header, got: {pub_pem[:80]!r}"
    )


@_SLOT_PARAMS
def test_keygen_public_key_is_correct_curve(slot: dict, provisioned_keys: dict) -> None:
    """The exported public key must be an EC key on the expected curve."""
    entry = provisioned_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['curve_display']} was not generated.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key PEM not available for {slot['curve_display']}.")

    pub_key = serialization.load_pem_public_key(
        pub_pem.encode(), backend=default_backend()
    )

    assert isinstance(pub_key, EllipticCurvePublicKey), (
        f"Expected EllipticCurvePublicKey, got {type(pub_key).__name__}"
    )

    expected_curve = _CURVE_CLASS_NAME.get(slot["curve_openssl"], "").upper()
    actual_curve   = type(pub_key.curve).__name__.upper()
    assert actual_curve == expected_curve, (
        f"Curve mismatch for {slot['curve_display']}: "
        f"expected {expected_curve}, got {actual_curve}"
    )


@_SLOT_PARAMS
def test_keygen_trace_has_apdus(
    slot: dict,
    provisioned_keys: dict,
    run_dir,
) -> None:
    """The keygen trace file must exist and contain parseable APDU exchanges."""
    entry = provisioned_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['curve_display']} was not generated.")

    trace_file = run_dir / f"01_keygen_{slot['name']}.txt"
    assert trace_file.exists(), (
        f"Trace file not found: {trace_file}"
    )

    keygen_result = entry["keygen_trace"]
    exchanges = trace.parse_apdu_trace(keygen_result.stderr)
    log.info(
        "%s keygen APDU count: %d",
        slot["curve_display"],
        len(exchanges),
    )
    assert len(exchanges) > 0, (
        f"No APDU exchanges found in keygen trace for {slot['curve_display']}.\n"
        f"Stderr snippet:\n{keygen_result.stderr[:400]}"
    )


def test_list_objects_shows_keys(
    runner: CLIRunner,
    config: dict,
    provisioned_keys: dict,
) -> None:
    """pkcs11-tool --list-objects must list the labels of all generated keys."""
    result = runner.pkcs11_tool(
        "--login",
        "--pin",          config["pin"],
        "--list-objects",
        save_as="01_list_objects_post_keygen",
    )
    assert result.returncode == 0, (
        f"pkcs11-tool --list-objects failed (rc={result.returncode}):\n{result.stderr}"
    )

    output = result.stdout + result.stderr  # some versions write to stderr
    log.info("Object listing:\n%s", result.stdout.strip())

    missing_labels: list[str] = []
    for slot in KEY_SLOTS:
        if provisioned_keys.get(slot["name"], {}).get("generated"):
            if slot["name"] not in output:
                missing_labels.append(slot["name"])

    assert not missing_labels, (
        f"The following generated key labels were not found in --list-objects output: "
        f"{missing_labels}\nOutput:\n{result.stdout}"
    )
