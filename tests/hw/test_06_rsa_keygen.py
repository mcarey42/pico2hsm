"""RSA key generation tests.

Generates an RSA-2048 key pair on the device and verifies:
- The keygen command succeeds.
- The public key can be exported and parses as a valid RSA public key.
- The public key has the expected modulus size.
- The key appears in --list-objects output.
"""

from __future__ import annotations

import logging

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from conftest import RSA_KEY_SLOTS
from helpers import trace
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

_SLOT_PARAMS = pytest.mark.parametrize(
    "slot",
    RSA_KEY_SLOTS,
    ids=[s["name"] for s in RSA_KEY_SLOTS],
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@_SLOT_PARAMS
def test_rsa_keygen_succeeds(slot: dict, provisioned_rsa_keys: dict) -> None:
    """RSA key generation must succeed."""
    entry = provisioned_rsa_keys.get(slot["name"])
    if entry is None:
        pytest.skip(f"No provisioning result for slot '{slot['name']}'")
    if not entry["generated"]:
        pytest.fail(
            f"RSA key generation failed for {slot['name']} "
            f"(key_size={slot['key_size']}).\n"
            f"Stderr: {entry['keygen_trace'].stderr[:400]}"
        )


@_SLOT_PARAMS
def test_rsa_public_key_exported(slot: dict, provisioned_rsa_keys: dict) -> None:
    """After keygen the public key must be exportable as PEM."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['name']} was not generated.")

    pub_pem = entry.get("pub_pem")
    assert pub_pem is not None, (
        f"Public key PEM is None for {slot['name']} (id={slot['key_id']}). "
        "Check that pkcs11-tool --read-object succeeded."
    )
    assert pub_pem.strip().startswith("-----BEGIN PUBLIC KEY-----"), (
        f"Expected PEM header, got: {pub_pem[:80]!r}"
    )


@_SLOT_PARAMS
def test_rsa_public_key_is_correct_type(slot: dict, provisioned_rsa_keys: dict) -> None:
    """The exported public key must be an RSA key with the correct modulus size."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['name']} was not generated.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key PEM not available for {slot['name']}.")

    pub_key = serialization.load_pem_public_key(
        pub_pem.encode(), backend=default_backend()
    )
    assert isinstance(pub_key, RSAPublicKey), (
        f"Expected RSAPublicKey, got {type(pub_key).__name__}"
    )
    assert pub_key.key_size == slot["key_size"], (
        f"Expected {slot['key_size']}-bit key, got {pub_key.key_size}-bit"
    )


@_SLOT_PARAMS
def test_rsa_keygen_trace_has_apdus(
    slot: dict,
    provisioned_rsa_keys: dict,
    run_dir,
) -> None:
    """The keygen trace file must exist and contain parseable APDU exchanges."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['name']} was not generated.")

    keygen_result = entry["keygen_trace"]
    exchanges = trace.parse_apdu_trace(keygen_result.stderr)
    log.info("RSA keygen APDU count: %d", len(exchanges))
    assert len(exchanges) > 0, (
        f"No APDU exchanges in keygen trace.\n"
        f"Stderr snippet:\n{keygen_result.stderr[:400]}"
    )


def test_rsa_list_objects_shows_keys(
    runner: CLIRunner,
    config: dict,
    provisioned_rsa_keys: dict,
) -> None:
    """pkcs11-tool --list-objects must list the labels of generated RSA keys."""
    result = runner.pkcs11_tool(
        "--login",
        "--pin",          config["pin"],
        "--list-objects",
        save_as="06_rsa_list_objects",
    )
    assert result.returncode == 0, (
        f"pkcs11-tool --list-objects failed (rc={result.returncode}):\n{result.stderr}"
    )

    output = result.stdout + result.stderr
    missing_labels: list[str] = []
    for slot in RSA_KEY_SLOTS:
        if provisioned_rsa_keys.get(slot["name"], {}).get("generated"):
            if slot["name"] not in output:
                missing_labels.append(slot["name"])

    assert not missing_labels, (
        f"RSA key labels not found in --list-objects: {missing_labels}\n"
        f"Output:\n{result.stdout}"
    )
