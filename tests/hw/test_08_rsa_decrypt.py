"""RSA decryption tests — PKCS#1 v1.5 and OAEP.

The host encrypts a known plaintext using the device's RSA public key,
then asks the device to decrypt it. The recovered plaintext is compared
against the original.

Covers:
- PKCS#1 v1.5 encrypt (host) + decrypt (device)
- OAEP-SHA256 encrypt (host) + decrypt (device)
- Decrypted plaintext matches original
- APDU trace captured for both mechanisms
"""

from __future__ import annotations

import logging
import os
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

TEST_PLAINTEXT = b"pico2hsm RSA decrypt test - secret payload 12345"


def _load_rsa_pub(pub_pem: str) -> RSAPublicKey:
    return serialization.load_pem_public_key(  # type: ignore[return-value]
        pub_pem.encode(), backend=default_backend()
    )


def _encrypt_pkcs1v15(pub_key: RSAPublicKey, plaintext: bytes) -> bytes:
    return pub_key.encrypt(plaintext, padding.PKCS1v15())


def _encrypt_oaep(pub_key: RSAPublicKey, plaintext: bytes) -> bytes:
    return pub_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _decrypt_on_device(
    slot: dict,
    runner: CLIRunner,
    config: dict,
    ciphertext_path: Path,
    plaintext_path: Path,
    mechanism: str,
    save_as: str | None,
):
    """Run pkcs11-tool --decrypt and return the CLIResult."""
    return runner.pkcs11_tool(
        "--login",
        "--pin",          config["pin"],
        "--decrypt",
        "--mechanism",    mechanism,
        "--id",           slot["key_id"],
        "--input-file",   str(ciphertext_path),
        "--output-file",  str(plaintext_path),
        save_as=save_as,
    )


_SLOT_PARAMS = pytest.mark.parametrize(
    "slot",
    RSA_KEY_SLOTS,
    ids=[s["name"] for s in RSA_KEY_SLOTS],
)


# ---------------------------------------------------------------------------
# PKCS#1 v1.5 decryption tests
# ---------------------------------------------------------------------------

@_SLOT_PARAMS
def test_rsa_pkcs_decrypt_succeeds(
    slot: dict,
    provisioned_rsa_keys: dict,
    runner: CLIRunner,
    config: dict,
    run_dir: Path,
    tmp_path: Path,
) -> None:
    """PKCS#1 v1.5 decrypt must succeed and recover the original plaintext."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"RSA key for {slot['name']} was not generated.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key not available for {slot['name']}.")

    pub_key = _load_rsa_pub(pub_pem)
    ciphertext = _encrypt_pkcs1v15(pub_key, TEST_PLAINTEXT)

    ct_file  = tmp_path / "ciphertext_pkcs.bin"
    pt_file  = tmp_path / "plaintext_pkcs.bin"
    ct_file.write_bytes(ciphertext)

    result = _decrypt_on_device(
        slot, runner, config, ct_file, pt_file,
        mechanism=slot["mechanism_enc"],
        save_as=f"08_rsa_pkcs_decrypt_{slot['name']}",
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / f"08_rsa_pkcs_decrypt_{slot['name']}.json",
        f"rsa_pkcs_decrypt_{slot['name']}",
        result,
        exchanges,
    )

    assert result.returncode == 0, (
        f"PKCS#1 v1.5 decrypt failed for {slot['name']} (rc={result.returncode}):\n"
        f"{result.stderr}"
    )
    assert pt_file.exists(), "Decrypted output file not created."
    recovered = pt_file.read_bytes()
    assert recovered == TEST_PLAINTEXT, (
        f"Decrypted plaintext does not match original.\n"
        f"Expected: {TEST_PLAINTEXT!r}\n"
        f"Got:      {recovered!r}"
    )
    log.info(
        "%s PKCS#1v1.5 decrypt OK  APDUs: %d", slot["name"], len(exchanges)
    )


@_SLOT_PARAMS
def test_rsa_pkcs_decrypt_wrong_ciphertext_fails(
    slot: dict,
    provisioned_rsa_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """Decrypting random bytes must fail (non-zero return code or garbage output)."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"RSA key for {slot['name']} was not generated.")

    # Feed random bytes of the correct ciphertext length
    key_bytes = slot["key_size"] // 8
    garbage = os.urandom(key_bytes)

    ct_file = tmp_path / "garbage.bin"
    pt_file = tmp_path / "plaintext_bad.bin"
    ct_file.write_bytes(garbage)

    result = _decrypt_on_device(
        slot, runner, config, ct_file, pt_file,
        mechanism=slot["mechanism_enc"],
        save_as=None,
    )

    # Either the device returns an error status (non-zero rc) OR the recovered
    # bytes differ from our known plaintext.  Both outcomes are acceptable;
    # the critical failure would be if it returned our known plaintext exactly.
    if result.returncode == 0 and pt_file.exists():
        recovered = pt_file.read_bytes()
        assert recovered != TEST_PLAINTEXT, (
            "Random ciphertext was 'successfully' decrypted to the known plaintext — "
            "this indicates a serious decryption vulnerability."
        )
    # Otherwise: non-zero rc is the expected (good) outcome
    log.info(
        "%s PKCS#1v1.5 random-garbage decrypt rc=%d (expected non-zero or wrong plaintext)",
        slot["name"], result.returncode,
    )


@_SLOT_PARAMS
def test_rsa_pkcs_decrypt_trace_has_apdus(
    slot: dict,
    provisioned_rsa_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """PKCS#1 v1.5 decrypt trace must contain parseable APDU exchanges."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"RSA key for {slot['name']} was not generated.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key not available for {slot['name']}.")

    pub_key = _load_rsa_pub(pub_pem)
    ciphertext = _encrypt_pkcs1v15(pub_key, TEST_PLAINTEXT)

    ct_file = tmp_path / "ciphertext.bin"
    pt_file = tmp_path / "plaintext.bin"
    ct_file.write_bytes(ciphertext)

    result = _decrypt_on_device(
        slot, runner, config, ct_file, pt_file,
        mechanism=slot["mechanism_enc"],
        save_as=None,
    )
    assert result.returncode == 0, f"Decrypt failed: {result.stderr}"

    exchanges = trace.parse_apdu_trace(result.stderr)
    assert len(exchanges) > 0, (
        f"No APDU exchanges in decrypt trace.\nStderr: {result.stderr[:400]}"
    )
    log.info("%s PKCS#1v1.5 decrypt APDU count: %d", slot["name"], len(exchanges))


# ---------------------------------------------------------------------------
# OAEP decryption tests
# ---------------------------------------------------------------------------

@_SLOT_PARAMS
def test_rsa_oaep_decrypt_succeeds(
    slot: dict,
    provisioned_rsa_keys: dict,
    runner: CLIRunner,
    config: dict,
    run_dir: Path,
    tmp_path: Path,
) -> None:
    """OAEP-SHA256 decrypt must succeed and recover the original plaintext."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"RSA key for {slot['name']} was not generated.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key not available for {slot['name']}.")

    pub_key = _load_rsa_pub(pub_pem)
    ciphertext = _encrypt_oaep(pub_key, TEST_PLAINTEXT)

    ct_file = tmp_path / "ciphertext_oaep.bin"
    pt_file = tmp_path / "plaintext_oaep.bin"
    ct_file.write_bytes(ciphertext)

    # OAEP uses algorithm ID 0x22; mechanism name for pkcs11-tool is RSA-PKCS-OAEP
    result = _decrypt_on_device(
        slot, runner, config, ct_file, pt_file,
        mechanism="RSA-PKCS-OAEP",
        save_as=f"08_rsa_oaep_decrypt_{slot['name']}",
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / f"08_rsa_oaep_decrypt_{slot['name']}.json",
        f"rsa_oaep_decrypt_{slot['name']}",
        result,
        exchanges,
    )

    assert result.returncode == 0, (
        f"OAEP decrypt failed for {slot['name']} (rc={result.returncode}):\n"
        f"{result.stderr}"
    )
    assert pt_file.exists(), "Decrypted output file not created."
    recovered = pt_file.read_bytes()
    assert recovered == TEST_PLAINTEXT, (
        f"OAEP decrypted plaintext does not match original.\n"
        f"Expected: {TEST_PLAINTEXT!r}\n"
        f"Got:      {recovered!r}"
    )
    log.info(
        "%s OAEP decrypt OK  APDUs: %d", slot["name"], len(exchanges)
    )


@_SLOT_PARAMS
def test_rsa_oaep_decrypt_trace_has_apdus(
    slot: dict,
    provisioned_rsa_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """OAEP decrypt trace must contain parseable APDU exchanges."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"RSA key for {slot['name']} was not generated.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key not available for {slot['name']}.")

    pub_key = _load_rsa_pub(pub_pem)
    ciphertext = _encrypt_oaep(pub_key, TEST_PLAINTEXT)

    ct_file = tmp_path / "ciphertext.bin"
    pt_file = tmp_path / "plaintext.bin"
    ct_file.write_bytes(ciphertext)

    result = _decrypt_on_device(
        slot, runner, config, ct_file, pt_file,
        mechanism="RSA-PKCS-OAEP",
        save_as=None,
    )
    assert result.returncode == 0, f"OAEP decrypt failed: {result.stderr}"

    exchanges = trace.parse_apdu_trace(result.stderr)
    assert len(exchanges) > 0, (
        f"No APDU exchanges in OAEP decrypt trace.\nStderr: {result.stderr[:400]}"
    )
    log.info("%s OAEP decrypt APDU count: %d", slot["name"], len(exchanges))


@_SLOT_PARAMS
def test_rsa_oaep_decrypt_unique_ciphertexts(
    slot: dict,
    provisioned_rsa_keys: dict,
    runner: CLIRunner,
    config: dict,
    tmp_path: Path,
) -> None:
    """OAEP is randomized; two encryptions of the same plaintext must differ
    but both must decrypt to the original plaintext."""
    entry = provisioned_rsa_keys.get(slot["name"], {})
    if not entry.get("generated"):
        pytest.skip(f"RSA key for {slot['name']} was not generated.")
    pub_pem = entry.get("pub_pem")
    if pub_pem is None:
        pytest.skip(f"Public key not available for {slot['name']}.")

    pub_key = _load_rsa_pub(pub_pem)
    ct1 = _encrypt_oaep(pub_key, TEST_PLAINTEXT)
    ct2 = _encrypt_oaep(pub_key, TEST_PLAINTEXT)

    assert ct1 != ct2, (
        "OAEP produced identical ciphertexts for the same plaintext — "
        "randomization is broken."
    )

    for i, ct in enumerate([ct1, ct2], 1):
        ct_file = tmp_path / f"ct_oaep_{i}.bin"
        pt_file = tmp_path / f"pt_oaep_{i}.bin"
        ct_file.write_bytes(ct)

        result = _decrypt_on_device(
            slot, runner, config, ct_file, pt_file,
            mechanism="RSA-PKCS-OAEP",
            save_as=None,
        )
        assert result.returncode == 0, (
            f"OAEP decrypt {i}/2 failed (rc={result.returncode}): {result.stderr}"
        )
        recovered = pt_file.read_bytes()
        assert recovered == TEST_PLAINTEXT, (
            f"OAEP decrypt {i}/2: recovered plaintext does not match.\n"
            f"Expected: {TEST_PLAINTEXT!r}\nGot: {recovered!r}"
        )
        log.info("%s OAEP decrypt %d/2 OK", slot["name"], i)
