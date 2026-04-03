"""ECDH key agreement tests for P-256, P-384, and P-521 slots.

K-256 (secp256k1) is excluded because ECDH1-COFACTOR-DERIVE is not supported
for that curve in the SC-HSM firmware.

The cross-check test (test_ecdh_cross_check) is a real cryptographic correctness
test: both the device and the host independently compute the ECDH shared secret,
and the test asserts the raw byte values are identical.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from conftest import KEY_SLOTS
from helpers import trace, crypto
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# Only slots where ECDH is defined in the firmware
_ECDH_SLOTS = [s for s in KEY_SLOTS if s["ecdh"]]

_SLOT_PARAMS = pytest.mark.parametrize(
    "slot",
    _ECDH_SLOTS,
    ids=[s["name"] for s in _ECDH_SLOTS],
)

# Expected shared-secret byte lengths per curve
_SECRET_LEN: dict[str, int] = {
    "prime256v1": 32,
    "secp384r1":  48,
    "secp521r1":  66,
}


def _derive(
    slot: dict,
    runner: CLIRunner,
    config: dict,
    peer_point_file: Path,
    secret_file: Path,
    save_as: str | None,
):
    """Invoke pkcs11-tool --derive and return the CLIResult."""
    return runner.pkcs11_tool(
        "--login",
        "--pin",          config["pin"],
        "--derive",
        "--mechanism",    "ECDH1-COFACTOR-DERIVE",
        "--id",           slot["key_id"],
        "--input-file",   str(peer_point_file),
        "--output-file",  str(secret_file),
        save_as=save_as,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@_SLOT_PARAMS
def test_ecdh_returns_correct_length(
    slot: dict,
    provisioned_keys: dict,
    runner: CLIRunner,
    config: dict,
    run_dir,
    tmp_path: Path,
) -> None:
    """ECDH derive must succeed and return a secret of the correct byte length."""
    entry = provisioned_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['curve_display']} was not generated.")
    if not slot.get("ecdh"):
        pytest.skip(f"ECDH not supported for {slot['curve_display']}.")

    _priv_pem, raw_point = crypto.generate_ec_peer_key(slot["curve_openssl"])

    peer_point_file = tmp_path / f"peer_point_{slot['name']}.bin"
    secret_file     = tmp_path / f"secret_{slot['name']}.bin"
    peer_point_file.write_bytes(raw_point)

    result = _derive(
        slot, runner, config, peer_point_file, secret_file,
        save_as=f"03_ecdh_{slot['name']}",
    )

    # Save JSON APDU trace
    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / f"03_ecdh_{slot['name']}.json",
        f"ecdh_{slot['name']}",
        result,
        exchanges,
    )

    assert result.returncode == 0, (
        f"pkcs11-tool --derive failed for {slot['curve_display']} (rc={result.returncode}):\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert secret_file.exists(), f"Secret output file not created: {secret_file}"

    secret_bytes = secret_file.read_bytes()
    expected_len = _SECRET_LEN[slot["curve_openssl"]]
    assert len(secret_bytes) == expected_len, (
        f"ECDH shared secret for {slot['curve_display']} has wrong length: "
        f"got {len(secret_bytes)}, expected {expected_len}"
    )
    log.info(
        "%s ECDH: %d-byte secret OK  APDUs: %d",
        slot["curve_display"], len(secret_bytes), len(exchanges),
    )


@_SLOT_PARAMS
def test_ecdh_cross_check(
    slot: dict,
    provisioned_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """Cryptographic correctness: device and host must agree on the shared secret.

    The test generates an ephemeral key pair on the host, sends the raw EC point
    to the device via pkcs11-tool --derive, then computes the same ECDH on the
    host using the device's public key.  The two resulting X-coordinates must be
    byte-for-byte identical.
    """
    entry = provisioned_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['curve_display']} was not generated.")
    if not slot.get("ecdh"):
        pytest.skip(f"ECDH not supported for {slot['curve_display']}.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key not available for {slot['curve_display']}.")

    # Generate ephemeral peer key on the host
    peer_priv_pem, raw_point = crypto.generate_ec_peer_key(slot["curve_openssl"])

    peer_point_file = tmp_path / f"peer_point_{slot['name']}.bin"
    secret_file     = tmp_path / f"secret_{slot['name']}.bin"
    peer_point_file.write_bytes(raw_point)

    # Device side: ECDH1-COFACTOR-DERIVE
    result = _derive(slot, runner, config, peer_point_file, secret_file, save_as=None)
    assert result.returncode == 0, (
        f"Device ECDH failed for {slot['curve_display']} (rc={result.returncode}):\n"
        f"{result.stderr}"
    )
    device_secret = secret_file.read_bytes()
    assert len(device_secret) > 0, "Device returned empty ECDH secret."

    # Host side: standard ECDH using peer private key + device public key
    host_secret = crypto.ecdh_host_side(peer_priv_pem, pub_pem)

    log.info(
        "%s ECDH cross-check:\n  device: %s\n  host:   %s",
        slot["curve_display"],
        device_secret.hex(),
        host_secret.hex(),
    )

    assert device_secret == host_secret, (
        f"ECDH shared secret MISMATCH for {slot['curve_display']}!\n"
        f"  Device secret ({len(device_secret)} bytes): {device_secret.hex()}\n"
        f"  Host secret   ({len(host_secret)} bytes): {host_secret.hex()}\n"
        "This is a cryptographic correctness failure in the ECDH implementation."
    )
    log.info("%s ECDH cross-check PASSED", slot["curve_display"])


@_SLOT_PARAMS
def test_ecdh_different_peers_give_different_secrets(
    slot: dict,
    provisioned_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """Two different ephemeral peer keys must yield different shared secrets."""
    entry = provisioned_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"Key for {slot['curve_display']} was not generated.")
    if not slot.get("ecdh"):
        pytest.skip(f"ECDH not supported for {slot['curve_display']}.")

    secrets: list[bytes] = []
    for i in range(2):
        _priv_pem, raw_point = crypto.generate_ec_peer_key(slot["curve_openssl"])
        peer_file   = tmp_path / f"peer_{i}.bin"
        secret_file = tmp_path / f"secret_{i}.bin"
        peer_file.write_bytes(raw_point)

        result = _derive(slot, runner, config, peer_file, secret_file, save_as=None)
        assert result.returncode == 0, (
            f"ECDH derive {i+1} failed for {slot['curve_display']} (rc={result.returncode}):\n"
            f"{result.stderr}"
        )
        s = secret_file.read_bytes()
        assert len(s) > 0, f"Empty secret on attempt {i+1}."
        secrets.append(s)

    assert secrets[0] != secrets[1], (
        f"Two different peer keys produced the SAME shared secret for "
        f"{slot['curve_display']} ({secrets[0].hex()}). "
        "This strongly suggests a broken RNG or ECDH implementation."
    )
    log.info(
        "%s: different peer keys → different secrets OK",
        slot["curve_display"],
    )
