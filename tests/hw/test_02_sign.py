"""ECDSA sign + verify tests, parametrized over all supported key slots."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from conftest import KEY_SLOTS
from helpers import trace, crypto
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

TEST_MESSAGE = b"pico2hsm hardware test message - sign and verify"

_SLOT_PARAMS = pytest.mark.parametrize(
    "slot",
    KEY_SLOTS,
    ids=[s["name"] for s in KEY_SLOTS],
)


def _sign(
    slot: dict,
    runner: CLIRunner,
    config: dict,
    msg_path: Path,
    sig_path: Path,
    save_as: str,
):
    """Run pkcs11-tool --sign and return the CLIResult."""
    return runner.pkcs11_tool(
        "--login",
        "--pin",          config["pin"],
        "--sign",
        "--mechanism",    slot["mechanism"],
        "--id",           slot["key_id"],
        "--input-file",   str(msg_path),
        "--output-file",  str(sig_path),
        save_as=save_as,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@_SLOT_PARAMS
def test_sign_returns_data(
    slot: dict,
    provisioned_keys: dict,
    runner: CLIRunner,
    config: dict,
    run_dir,
    tmp_path: Path,
) -> None:
    """Signing must succeed and produce a non-empty signature file."""
    entry = provisioned_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['curve_display']} was not generated.")

    msg_file = tmp_path / "message.bin"
    sig_file = tmp_path / f"sig_{slot['name']}.bin"
    msg_file.write_bytes(TEST_MESSAGE)

    result = _sign(
        slot, runner, config, msg_file, sig_file,
        save_as=f"02_sign_{slot['name']}",
    )

    # Save JSON APDU trace
    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / f"02_sign_{slot['name']}.json",
        f"sign_{slot['name']}",
        result,
        exchanges,
    )

    assert result.returncode == 0, (
        f"pkcs11-tool --sign failed for {slot['curve_display']} (rc={result.returncode}):\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert sig_file.exists(), f"Signature output file not created: {sig_file}"
    sig_bytes = sig_file.read_bytes()
    assert len(sig_bytes) > 0, "Signature file is empty."
    log.info(
        "%s signature: %d bytes  APDUs: %d",
        slot["curve_display"], len(sig_bytes), len(exchanges),
    )


@_SLOT_PARAMS
def test_sign_signature_valid(
    slot: dict,
    provisioned_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """The ECDSA signature must verify against the device's public key."""
    entry = provisioned_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['curve_display']} was not generated.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key not available for {slot['curve_display']}.")

    msg_file = tmp_path / "message.bin"
    sig_file = tmp_path / "sig.bin"
    msg_file.write_bytes(TEST_MESSAGE)

    result = _sign(slot, runner, config, msg_file, sig_file, save_as=None)
    assert result.returncode == 0, (
        f"Signing failed (rc={result.returncode}):\n{result.stderr}"
    )

    sig_bytes = sig_file.read_bytes()
    assert len(sig_bytes) > 0, "Signature is empty."

    is_valid = crypto.verify_ecdsa_signature(
        pub_pem, TEST_MESSAGE, sig_bytes, slot["hash"]
    )
    assert is_valid, (
        f"Signature did NOT verify for {slot['curve_display']}. "
        "The device may have signed with the wrong key or produced a malformed signature."
    )
    log.info("%s signature verified OK", slot["curve_display"])


@_SLOT_PARAMS
def test_sign_wrong_key_fails_verify(
    slot: dict,
    provisioned_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """A signature from one key must not verify under a different key's public key."""
    # We need at least 2 generated slots on the SAME curve family for this to be
    # meaningful; we compare the current slot's sig against the *next* generated slot.
    generated_slots = [
        s for s in KEY_SLOTS if provisioned_keys.get(s["name"], {}).get("generated")
    ]
    if len(generated_slots) < 2:
        pytest.skip("Need at least 2 generated keys to cross-verify.")

    entry = provisioned_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['curve_display']} was not generated.")

    # Pick a different slot that has a public key and is NOT this slot
    other_entry = None
    for s in generated_slots:
        if s["name"] != slot["name"] and provisioned_keys[s["name"]].get("pub_pem"):
            other_entry = provisioned_keys[s["name"]]
            other_slot_name = s["name"]
            other_hash = s["hash"]
            break
    if other_entry is None:
        pytest.skip("No other slot with a public key available for cross-check.")

    msg_file = tmp_path / "message.bin"
    sig_file = tmp_path / "sig.bin"
    msg_file.write_bytes(TEST_MESSAGE)

    result = _sign(slot, runner, config, msg_file, sig_file, save_as=None)
    assert result.returncode == 0, (
        f"Signing with {slot['curve_display']} failed (rc={result.returncode})"
    )

    sig_bytes = sig_file.read_bytes()
    wrong_pub_pem = other_entry["pub_pem"]

    # Verification must raise InvalidSignature (or similar) OR return False
    raised = False
    verified = False
    try:
        verified = crypto.verify_ecdsa_signature(
            wrong_pub_pem, TEST_MESSAGE, sig_bytes, other_hash
        )
    except Exception as exc:
        raised = True
        log.info(
            "Cross-key verify correctly raised %s: %s",
            type(exc).__name__, exc,
        )

    assert raised or not verified, (
        f"Signature from {slot['curve_display']} (id={slot['key_id']}) "
        f"unexpectedly verified against public key from slot '{other_slot_name}'. "
        "This indicates a serious key isolation failure."
    )


@_SLOT_PARAMS
def test_sign_determinism_not_required_but_non_null(
    slot: dict,
    provisioned_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """Both of two independent signatures must be individually valid (ECDSA is non-deterministic)."""
    entry = provisioned_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['curve_display']} was not generated.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key not available for {slot['curve_display']}.")

    msg_file = tmp_path / "message.bin"
    msg_file.write_bytes(TEST_MESSAGE)

    results = []
    for i in range(2):
        sig_file = tmp_path / f"sig_{i}.bin"
        r = _sign(slot, runner, config, msg_file, sig_file, save_as=None)
        assert r.returncode == 0, (
            f"Signing attempt {i+1} failed (rc={r.returncode}):\n{r.stderr}"
        )
        sig_bytes = sig_file.read_bytes()
        assert len(sig_bytes) > 0, f"Signature {i+1} is empty."
        results.append(sig_bytes)

    for i, sig_bytes in enumerate(results):
        valid = crypto.verify_ecdsa_signature(
            pub_pem, TEST_MESSAGE, sig_bytes, slot["hash"]
        )
        assert valid, (
            f"Signature {i+1} of 2 did not verify for {slot['curve_display']}."
        )

    log.info(
        "%s: both signatures valid (same=%s)",
        slot["curve_display"],
        results[0] == results[1],
    )
