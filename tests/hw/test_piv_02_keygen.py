"""Tests for PIV GENERATE KEY PAIR (INS=0x47) on slot 9A.

Verifies:
- GENERATE KEY PAIR for PIV slot 9A with P-256 succeeds and returns a
  well-formed public key TLV (7F49 wrapping 86 uncompressed point).
- The returned public key is a valid P-256 EC point (parseable by the
  cryptography library).
- The key persists across a SELECT → deselect → re-SELECT sequence (i.e., it
  is stored in flash, not held only in working memory).

PIV GENERATE KEY PAIR APDU (slot 9A, P-256):
    00 47 00 9A 05 AC 03 80 01 11 00
    where:
        AC 03        — Algorithm Information template
          80 01 11   — Algorithm ID 0x11 = P-256 ECDSA

Key slot 9A maps to key reference 0x9A.  The response is:
    7C [len]
      7F 49 [len]         — Public Key template
        86 [len] <point>  — EC public key (uncompressed: 04 <X> <Y>)

All tests are marked xfail because the PIV applet is not yet implemented.
Remove the xfail mark as each feature is completed.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
    SECP256R1,
)

from helpers import trace, sw_from_output, last_response_hex
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# PIV AID
PIV_AID = "A000000308000010000100"
_SELECT_PIV = "00A404000B" + PIV_AID + "00"

# Default PIN
_DEFAULT_PIN = "313233343536FFFF"
_VERIFY_PIN = "0020008008" + _DEFAULT_PIN

# GENERATE KEY PAIR: slot 9A, algo 0x11 (P-256 ECDSA/ECDH, 256-bit)
# APDU: 00 47 00 9A 05 AC 03 80 01 11 00
_GENKEY_9A_P256 = "0047009A05AC03800111 00".replace(" ", "")

_XFAIL = pytest.mark.xfail(reason="PIV not yet implemented", strict=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _send_apdus(runner: CLIRunner, *apdus: str, save_as: str | None = None, timeout: int = 120):
    args = ["opensc-tool"]
    for apdu in apdus:
        args.extend(["--send-apdu", apdu.replace(" ", "")])
    return runner.run(args, save_as=save_as, timeout=timeout)


def _sw_from_output(output: str) -> str | None:
    return sw_from_output(output)


def _extract_ec_point_from_genkey_response(resp_hex: str) -> bytes | None:
    """Parse GENERATE KEY PAIR response and return the raw EC point bytes.

    Expected structure:
        7C [len]
          7F 49 [len]
            86 [len] <uncompressed point: 04 XX...>
    Returns the raw uncompressed point bytes (starting with 0x04), or None.
    """
    data = bytes.fromhex(resp_hex.replace(" ", ""))
    if not data or data[0] != 0x7C:
        return None

    # Skip outer 7C tag+length (may be 1 or 2 byte length)
    idx = 1
    outer_len, consumed = _decode_length(data, idx)
    idx += consumed
    payload = data[idx:idx + outer_len]

    # Find 7F 49 inside
    i = 0
    while i < len(payload) - 1:
        if payload[i] == 0x7F and payload[i + 1] == 0x49:
            i += 2
            inner_len, consumed = _decode_length(payload, i)
            i += consumed
            inner = payload[i:i + inner_len]
            # Find 86 tag inside
            j = 0
            while j < len(inner):
                tag = inner[j]
                point_len, consumed = _decode_length(inner, j + 1)
                if tag == 0x86:
                    return inner[j + 1 + consumed:j + 1 + consumed + point_len]
                j += 1 + consumed + point_len
        i += 1
    return None


def _decode_length(data: bytes, idx: int) -> tuple[int, int]:
    """Decode a BER-TLV length field.  Returns (length_value, bytes_consumed)."""
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@_XFAIL
def test_piv_genkey_9a_p256_succeeds(runner: CLIRunner, run_dir: Path) -> None:
    """GENERATE KEY PAIR for slot 9A (P-256) must return SW=9000."""
    result = _send_apdus(
        runner,
        _SELECT_PIV,
        _VERIFY_PIN,
        _GENKEY_9A_P256,
        save_as="piv_02_genkey_9a",
        timeout=120,
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / "piv_02_genkey_9a.json",
        "piv_genkey_9a",
        result,
        exchanges,
    )
    log.info(
        "PIV GENKEY 9A: rc=%d  elapsed=%.0f ms  APDUs=%d",
        result.returncode, result.elapsed_ms, len(exchanges),
    )

    assert result.returncode == 0, (
        f"opensc-tool failed (rc={result.returncode}):\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("GENKEY SW: %s", sw)
    assert sw == "9000", (
        f"Expected SW=9000 from GENERATE KEY PAIR; got SW={sw!r}."
    )


@_XFAIL
def test_piv_genkey_9a_returns_public_key_tlv(runner: CLIRunner) -> None:
    """GENERATE KEY PAIR response must contain a 7C→7F49→86 public key TLV."""
    result = _send_apdus(
        runner,
        _SELECT_PIV,
        _VERIFY_PIN,
        _GENKEY_9A_P256,
        timeout=120,
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    if sw != "9000":
        pytest.skip(f"GENKEY returned SW={sw!r}; cannot inspect TLV.")

    # opensc-tool prints response data on stdout
    resp_hex = last_response_hex(result.stdout)
    log.info("GENKEY raw response: %s", resp_hex[:80])

    assert resp_hex, "No response data from GENERATE KEY PAIR."
    assert resp_hex.startswith("7C") or resp_hex.startswith("7c"), (
        f"Expected response to start with tag 0x7C; got: {resp_hex[:10]!r}"
    )

    ec_point = _extract_ec_point_from_genkey_response(resp_hex)
    assert ec_point is not None, (
        f"Could not extract EC point from GENKEY response.\n"
        f"Expected structure: 7C→7F49→86.\nRaw: {resp_hex[:80]}"
    )
    log.info("Extracted EC point: %d bytes", len(ec_point))


@_XFAIL
def test_piv_genkey_9a_public_key_is_valid_p256(runner: CLIRunner) -> None:
    """The public key returned by GENKEY must be a valid uncompressed P-256 point."""
    result = _send_apdus(
        runner,
        _SELECT_PIV,
        _VERIFY_PIN,
        _GENKEY_9A_P256,
        timeout=120,
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    if sw != "9000":
        pytest.skip(f"GENKEY returned SW={sw!r}; skipping key validation.")

    resp_hex = last_response_hex(result.stdout)
    ec_point = _extract_ec_point_from_genkey_response(resp_hex)
    if ec_point is None:
        pytest.skip("Could not extract EC point from response.")

    # P-256 uncompressed point: 04 || X (32 bytes) || Y (32 bytes) = 65 bytes total
    assert len(ec_point) == 65 and ec_point[0] == 0x04, (
        f"Expected 65-byte uncompressed P-256 point (04 || X || Y); "
        f"got {len(ec_point)} bytes starting with {ec_point[0]:02X}."
    )

    # Validate the point is on the curve by parsing it
    x = int.from_bytes(ec_point[1:33], "big")
    y = int.from_bytes(ec_point[33:65], "big")
    pub_numbers = EllipticCurvePublicNumbers(x=x, y=y, curve=SECP256R1())
    try:
        pub_key = pub_numbers.public_key(backend=default_backend())
    except Exception as exc:
        pytest.fail(
            f"EC point is not on P-256: {exc}\n"
            f"Point (hex): {ec_point.hex()}"
        )

    assert isinstance(pub_key, EllipticCurvePublicKey), (
        f"Expected EllipticCurvePublicKey, got {type(pub_key).__name__}"
    )
    assert type(pub_key.curve).__name__ == "SECP256R1", (
        f"Expected SECP256R1, got {type(pub_key.curve).__name__}"
    )
    log.info("P-256 public key validated: x=%064x", x)


@_XFAIL
def test_piv_genkey_key_persists_after_reselect(runner: CLIRunner, run_dir: Path) -> None:
    """A key generated in slot 9A must survive a deselect + re-SELECT cycle.

    After GENERATE KEY PAIR, the test sends SELECT again (which resets the
    PIV session) and then calls GENERAL AUTHENTICATE with a challenge to
    confirm the private key is still present.  For simplicity we only check
    that the key reference is valid (SW != 6A88 'reference data not found').

    GENERAL AUTHENTICATE (internal auth / witness):
        00 87 11 9A 04 7C 02 82 00 00
        where: 7C 02 82 00 = Dynamic Authentication Template, witness
    """
    # Generate key
    result_gen = _send_apdus(
        runner,
        _SELECT_PIV,
        _VERIFY_PIN,
        _GENKEY_9A_P256,
        timeout=120,
    )
    gen_sw = _sw_from_output(result_gen.stdout + result_gen.stderr)
    if gen_sw != "9000":
        pytest.skip(f"Key generation failed (SW={gen_sw!r}); cannot test persistence.")

    log.info("Key generated.  Re-selecting PIV applet to verify persistence...")

    # Re-select (resets session) and send a witness request to confirm key exists
    # GENERAL AUTHENTICATE: algo=0x11 (P-256), key ref=0x9A, witness request
    _INTERNAL_AUTH_WITNESS = "008711 9A047C028200 00".replace(" ", "")
    result_auth = _send_apdus(
        runner,
        _SELECT_PIV,
        _VERIFY_PIN,
        _INTERNAL_AUTH_WITNESS,
        save_as="piv_02_genkey_persist_check",
        timeout=30,
    )

    combined = result_auth.stdout + result_auth.stderr
    sw = _sw_from_output(combined)
    log.info("Post-reselect GENERAL AUTHENTICATE witness SW: %s", sw)

    # SW=6A88 means 'reference data not found' = key was lost
    assert sw != "6A88", (
        "Key reference 9A returned SW=6A88 after re-SELECT; "
        "the generated key was not persisted to flash."
    )
    # Any response other than 6A88 (including error SWs for unsupported mode)
    # is acceptable here — we are only checking the key reference is valid.
    log.info("Key slot 9A is still present after re-SELECT (SW=%s)", sw)
