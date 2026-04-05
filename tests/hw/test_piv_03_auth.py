"""Tests for PIV GENERAL AUTHENTICATE asymmetric signing with slot 9A (P-256).

Verifies:
- GENERAL AUTHENTICATE (INS=0x87) with key reference 9A produces a valid ECDSA
  signature over a challenge hash.
- The signature verifies with the P-256 public key returned during GENKEY.
- The signature is in DER/ASN.1 format (as returned by PIV GENERAL AUTHENTICATE).

PIV GENERAL AUTHENTICATE sign flow:
    1. SELECT PIV AID
    2. VERIFY PIN (P2=0x80) with default "123456"
    3. GENERAL AUTHENTICATE (P1=algo, P2=key_ref):
         CLA=00 INS=87 P1=11 P2=9A Lc=xx
         7C [len]
           82 00               -- Response = empty (request for sig)
           81 [len] <hash>     -- Challenge = 32-byte SHA-256 digest

    Response:
         7C [len]
           82 [len] <DER sig>  -- Signature

All tests depend on slot 9A having a P-256 key; they skip if no key is present.
All tests are marked xfail because the PIV applet is not yet implemented.
Remove the xfail mark as each feature is completed.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicNumbers,
    SECP256R1,
)
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from helpers import trace, sw_from_output, last_response_hex
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# PIV AID
PIV_AID = "A000000308000010000100"
_SELECT_PIV = "00A404000B" + PIV_AID + "00"

# Default PIN
_DEFAULT_PIN = "313233343536FFFF"
_VERIFY_PIN = "0020008008" + _DEFAULT_PIN

# GENERATE KEY PAIR slot 9A P-256
_GENKEY_9A_P256 = "0047009A05AC0380011100"

# Test message and its SHA-256 hash
_TEST_MESSAGE = b"pico2hsm PIV GENERAL AUTHENTICATE test message"
_TEST_HASH = hashlib.sha256(_TEST_MESSAGE).digest()  # 32 bytes

_XFAIL = pytest.mark.xfail(reason="PIV not yet implemented", strict=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _send_apdus(runner: CLIRunner, *apdus: str, save_as: str | None = None, timeout: int = 60):
    args = ["opensc-tool"]
    for apdu in apdus:
        args.extend(["--send-apdu", apdu.replace(" ", "")])
    return runner.run(args, save_as=save_as, timeout=timeout)


def _sw_from_output(output: str) -> str | None:
    return sw_from_output(output)


def _decode_length(data: bytes, idx: int) -> tuple[int, int]:
    if idx >= len(data):
        return 0, 1
    first = data[idx]
    if first < 0x80:
        return first, 1
    elif first == 0x81:
        return data[idx + 1], 2
    elif first == 0x82:
        return int.from_bytes(data[idx + 1:idx + 3], "big"), 3
    return 0, 1


def _build_general_authenticate_apdu(hash_bytes: bytes) -> str:
    """Build a PIV GENERAL AUTHENTICATE APDU for P-256 signing of hash_bytes.

    Structure:
        7C [len]
          82 00          -- empty Response slot (card fills this)
          81 [len] <hash>  -- Challenge (hash to sign)

    APDU: 00 87 11 9A Lc <data> 00
    where P1=0x11 (ECDSA P-256), P2=0x9A (key slot 9A).
    """
    challenge_value = bytes([0x81, len(hash_bytes)]) + hash_bytes
    response_slot = bytes([0x82, 0x00])
    inner = response_slot + challenge_value
    data_object = bytes([0x7C, len(inner)]) + inner
    lc = len(data_object)
    apdu = bytes([0x00, 0x87, 0x11, 0x9A, lc]) + data_object + bytes([0x00])
    return apdu.hex().upper()


def _extract_signature_from_ga_response(resp_hex: str) -> bytes | None:
    """Extract the DER signature from a GENERAL AUTHENTICATE response.

    Expected structure:
        7C [len]
          82 [len] <DER signature>
    """
    data = bytes.fromhex(resp_hex.replace(" ", ""))
    if not data or data[0] != 0x7C:
        return None

    idx = 1
    outer_len, consumed = _decode_length(data, idx)
    idx += consumed
    payload = data[idx:idx + outer_len]

    i = 0
    while i < len(payload):
        tag = payload[i]
        sig_len, consumed = _decode_length(payload, i + 1)
        if tag == 0x82:
            return payload[i + 1 + consumed:i + 1 + consumed + sig_len]
        i += 1 + consumed + sig_len
    return None


def _extract_ec_point_from_genkey_response(resp_hex: str) -> bytes | None:
    """Parse GENERATE KEY PAIR response: 7C→7F49→86 → uncompressed EC point."""
    data = bytes.fromhex(resp_hex.replace(" ", ""))
    if not data or data[0] != 0x7C:
        return None
    idx = 1
    outer_len, consumed = _decode_length(data, idx)
    idx += consumed
    payload = data[idx:idx + outer_len]
    i = 0
    while i < len(payload) - 1:
        if payload[i] == 0x7F and payload[i + 1] == 0x49:
            i += 2
            inner_len, consumed = _decode_length(payload, i)
            i += consumed
            inner = payload[i:i + inner_len]
            j = 0
            while j < len(inner):
                tag = inner[j]
                point_len, pconsumed = _decode_length(inner, j + 1)
                if tag == 0x86:
                    return inner[j + 1 + pconsumed:j + 1 + pconsumed + point_len]
                j += 1 + pconsumed + point_len
        i += 1
    return None


def _get_or_generate_p256_pubkey(runner: CLIRunner) -> ec.EllipticCurvePublicKey | None:
    """Generate a P-256 key in slot 9A and return the public key object.

    Returns None if key generation fails.
    """
    result = _send_apdus(runner, _SELECT_PIV, _VERIFY_PIN, _GENKEY_9A_P256, timeout=120)
    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    if sw != "9000":
        return None

    resp_hex = last_response_hex(result.stdout)
    ec_point = _extract_ec_point_from_genkey_response(resp_hex)
    if ec_point is None or len(ec_point) != 65 or ec_point[0] != 0x04:
        return None

    x = int.from_bytes(ec_point[1:33], "big")
    y = int.from_bytes(ec_point[33:65], "big")
    pub_numbers = EllipticCurvePublicNumbers(x=x, y=y, curve=SECP256R1())
    try:
        return pub_numbers.public_key(backend=default_backend())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@_XFAIL
def test_piv_general_authenticate_sign_returns_data(
    runner: CLIRunner, run_dir: Path,
) -> None:
    """GENERAL AUTHENTICATE must return a non-empty signature in the 7C→82 TLV."""
    pub_key = _get_or_generate_p256_pubkey(runner)
    if pub_key is None:
        pytest.skip("Could not obtain P-256 public key from slot 9A.")

    ga_apdu = _build_general_authenticate_apdu(_TEST_HASH)
    result = _send_apdus(
        runner,
        _SELECT_PIV,
        _VERIFY_PIN,
        ga_apdu,
        save_as="piv_03_auth_sign",
        timeout=60,
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / "piv_03_auth_sign.json",
        "piv_general_authenticate_sign",
        result,
        exchanges,
    )
    log.info(
        "PIV GENERAL AUTHENTICATE: rc=%d  elapsed=%.0f ms  APDUs=%d",
        result.returncode, result.elapsed_ms, len(exchanges),
    )

    assert result.returncode == 0, (
        f"opensc-tool failed (rc={result.returncode}):\n{result.stderr}"
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("GENERAL AUTHENTICATE SW: %s", sw)
    assert sw == "9000", (
        f"Expected SW=9000 from GENERAL AUTHENTICATE; got SW={sw!r}."
    )

    resp_hex = last_response_hex(result.stdout)
    sig = _extract_signature_from_ga_response(resp_hex)
    assert sig is not None and len(sig) > 0, (
        f"Could not extract signature from GENERAL AUTHENTICATE response.\n"
        f"Expected 7C→82 TLV.\nRaw: {resp_hex[:80]}"
    )
    log.info("Signature extracted: %d bytes", len(sig))


@_XFAIL
def test_piv_general_authenticate_signature_is_valid_ecdsa(
    runner: CLIRunner, run_dir: Path,
) -> None:
    """The ECDSA signature from GENERAL AUTHENTICATE must verify with the device public key.

    The signature is in DER/ASN.1 format (as per NIST SP 800-73-4 Appendix A).
    """
    pub_key = _get_or_generate_p256_pubkey(runner)
    if pub_key is None:
        pytest.skip("Could not obtain P-256 public key from slot 9A.")

    ga_apdu = _build_general_authenticate_apdu(_TEST_HASH)
    result = _send_apdus(
        runner,
        _SELECT_PIV,
        _VERIFY_PIN,
        ga_apdu,
        save_as="piv_03_auth_verify",
        timeout=60,
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    if sw != "9000":
        pytest.skip(f"GENERAL AUTHENTICATE returned SW={sw!r}; cannot verify signature.")

    resp_hex = last_response_hex(result.stdout)
    sig = _extract_signature_from_ga_response(resp_hex)
    if sig is None:
        pytest.skip("Could not extract signature from response.")

    log.info("Verifying signature: %d bytes", len(sig))
    log.info("Signature (hex): %s", sig.hex())

    try:
        pub_key.verify(
            sig,
            _TEST_HASH,
            ec.ECDSA(hashes.Prehashed(hashes.SHA256())),
        )
        log.info("Signature verified OK.")
    except InvalidSignature:
        pytest.fail(
            f"ECDSA signature did NOT verify.\n"
            f"Message hash: {_TEST_HASH.hex()}\n"
            f"Signature: {sig.hex()}"
        )


@_XFAIL
def test_piv_general_authenticate_without_pin_fails(runner: CLIRunner) -> None:
    """GENERAL AUTHENTICATE without prior VERIFY must fail with SW=6982 or 6984.

    SW=6982: Security status not satisfied.
    SW=6984: Reference data not usable (some implementations).
    """
    pub_key = _get_or_generate_p256_pubkey(runner)
    if pub_key is None:
        pytest.skip("Could not obtain P-256 public key from slot 9A.")

    ga_apdu = _build_general_authenticate_apdu(_TEST_HASH)
    # SELECT but do NOT verify the PIN
    result = _send_apdus(runner, _SELECT_PIV, ga_apdu, timeout=30)

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("GENERAL AUTHENTICATE without PIN SW: %s", sw)

    assert sw in ("6982", "6984", "6300", "6983"), (
        f"Expected security failure SW (6982/6984) without PIN; got SW={sw!r}."
    )
    log.info("Correctly rejected GENERAL AUTHENTICATE without PIN (SW=%s)", sw)


@_XFAIL
def test_piv_general_authenticate_two_signatures_both_valid(
    runner: CLIRunner,
) -> None:
    """Two independent GENERAL AUTHENTICATE calls must both produce valid signatures.

    ECDSA is non-deterministic; this test confirms both outputs independently
    verify rather than testing for determinism.
    """
    pub_key = _get_or_generate_p256_pubkey(runner)
    if pub_key is None:
        pytest.skip("Could not obtain P-256 public key from slot 9A.")

    ga_apdu = _build_general_authenticate_apdu(_TEST_HASH)

    signatures = []
    for attempt in range(1, 3):
        result = _send_apdus(runner, _SELECT_PIV, _VERIFY_PIN, ga_apdu, timeout=60)
        combined = result.stdout + result.stderr
        sw = _sw_from_output(combined)
        if sw != "9000":
            pytest.skip(f"GENERAL AUTHENTICATE attempt {attempt} returned SW={sw!r}.")

        resp_hex = last_response_hex(result.stdout)
        sig = _extract_signature_from_ga_response(resp_hex)
        if sig is None:
            pytest.skip(f"Could not extract signature on attempt {attempt}.")
        signatures.append(sig)

    for i, sig in enumerate(signatures):
        try:
            pub_key.verify(
                sig,
                _TEST_HASH,
                ec.ECDSA(hashes.Prehashed(hashes.SHA256())),
            )
        except InvalidSignature:
            pytest.fail(
                f"Signature {i + 1} of 2 did NOT verify.\n"
                f"Signature: {sig.hex()}"
            )

    log.info(
        "Both signatures valid (same=%s)",
        signatures[0] == signatures[1],
    )
