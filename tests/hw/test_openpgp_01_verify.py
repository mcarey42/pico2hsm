"""Tests for OpenPGP Card VERIFY (INS=0x20), retry counter, and CHANGE REFERENCE DATA.

OpenPGP uses three PIN objects:
  PW1 (P2=0x81): User PIN for signing (PSO:CDS)
  PW1 (P2=0x82): User PIN for other operations (PSO:DECIPHER, INTERNAL AUTH)
  PW3 (P2=0x83): Admin PIN (card administration)

Default values:
  PW1: "123456"   (6 bytes UTF-8)
  PW3: "12345678" (8 bytes UTF-8)

VERIFY APDU:
    00 20 00 <P2> Lc <PIN bytes>

Query form (no Lc, no data):
    00 20 00 <P2>   → returns 63Cx (X retries) or 9000 (already verified)

CHANGE REFERENCE DATA APDU:
    00 24 00 <P2> Lc <old PIN> <new PIN>
    (concatenated without padding; lengths determined by Lc)

All tests are marked xfail because the OpenPGP applet is not yet implemented.
Remove the xfail mark as each feature is completed.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from helpers import trace, sw_from_output
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# OpenPGP AID prefix
OPENPGP_AID_PREFIX = "D27600012401"
_SELECT_OPENPGP = "00A40400 06" + OPENPGP_AID_PREFIX + "00"
_SELECT_OPENPGP_CLEAN = "00A404000 6" + OPENPGP_AID_PREFIX + "00"

# Default PINs as UTF-8 hex (no padding — OpenPGP does not use 0xFF padding)
_PW1_DEFAULT = "313233343536"           # "123456" = 6 bytes
_PW3_DEFAULT = "3132333435363738"       # "12345678" = 8 bytes
_PW1_ALT     = "363534333231"           # "654321" = 6 bytes

# VERIFY APDUs
_VERIFY_PW1_81 = f"002000810 6{_PW1_DEFAULT}".replace(" ", "")
_VERIFY_PW1_82 = f"002000820 6{_PW1_DEFAULT}".replace(" ", "")
_VERIFY_PW3    = f"002000830 8{_PW3_DEFAULT}".replace(" ", "")

# Wrong PIN (8 bytes, unlikely to match any real PIN)
_WRONG_PIN_HEX = "4445414442454546"  # "DEADBEEF"

# VERIFY query (no Lc)
_VERIFY_QUERY_PW1_81 = "00200081"
_VERIFY_QUERY_PW3    = "00200083"

_XFAIL = pytest.mark.xfail(reason="OpenPGP not yet implemented", strict=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _send_apdus(runner: CLIRunner, *apdus: str, save_as: str | None = None, timeout: int = 30):
    args = ["opensc-tool"]
    for apdu in apdus:
        args.extend(["--send-apdu", apdu.replace(" ", "")])
    return runner.run(args, save_as=save_as, timeout=timeout)


def _sw_from_output(output: str) -> str | None:
    return sw_from_output(output)


def _build_verify(p2: int, pin_hex: str) -> str:
    """Build a VERIFY APDU: 00 20 00 <P2> Lc <PIN>."""
    pin_bytes = bytes.fromhex(pin_hex)
    lc = len(pin_bytes)
    apdu = bytes([0x00, 0x20, 0x00, p2, lc]) + pin_bytes
    return apdu.hex().upper()


def _build_change_pin(p2: int, old_hex: str, new_hex: str) -> str:
    """Build a CHANGE REFERENCE DATA APDU: 00 24 00 <P2> Lc <old><new>."""
    payload = bytes.fromhex(old_hex) + bytes.fromhex(new_hex)
    lc = len(payload)
    apdu = bytes([0x00, 0x24, 0x00, p2, lc]) + payload
    return apdu.hex().upper()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@_XFAIL
def test_openpgp_verify_pw1_81_accepted(runner: CLIRunner, run_dir: Path) -> None:
    """VERIFY PW1 (P2=0x81) with default '123456' must return SW=9000."""
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN.replace(" ", ""),
        _VERIFY_PW1_81,
        save_as="openpgp_01_verify_pw1_81",
        timeout=30,
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / "openpgp_01_verify_pw1_81.json",
        "openpgp_verify_pw1_81",
        result,
        exchanges,
    )
    log.info(
        "OpenPGP VERIFY PW1(81): rc=%d  elapsed=%.0f ms  APDUs=%d",
        result.returncode, result.elapsed_ms, len(exchanges),
    )

    assert result.returncode == 0, (
        f"opensc-tool failed (rc={result.returncode}):\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("VERIFY PW1(81) SW: %s", sw)
    assert sw == "9000", (
        f"Expected SW=9000 for correct PW1; got SW={sw!r}."
    )


@_XFAIL
def test_openpgp_verify_pw1_82_accepted(runner: CLIRunner, run_dir: Path) -> None:
    """VERIFY PW1 (P2=0x82) with default '123456' must return SW=9000."""
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN.replace(" ", ""),
        _VERIFY_PW1_82,
        save_as="openpgp_01_verify_pw1_82",
        timeout=30,
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("VERIFY PW1(82) SW: %s", sw)
    assert sw == "9000", (
        f"Expected SW=9000 for PW1 mode 82; got SW={sw!r}."
    )


@_XFAIL
def test_openpgp_verify_pw3_accepted(runner: CLIRunner, run_dir: Path) -> None:
    """VERIFY PW3 (P2=0x83) with default '12345678' must return SW=9000."""
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN.replace(" ", ""),
        _VERIFY_PW3,
        save_as="openpgp_01_verify_pw3",
        timeout=30,
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / "openpgp_01_verify_pw3.json",
        "openpgp_verify_pw3",
        result,
        exchanges,
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("VERIFY PW3 SW: %s", sw)
    assert sw == "9000", (
        f"Expected SW=9000 for correct PW3; got SW={sw!r}."
    )


@_XFAIL
def test_openpgp_verify_wrong_pin_returns_63cx(runner: CLIRunner) -> None:
    """VERIFY with a wrong PIN must return SW=63Cx with a plausible retry count."""
    wrong_verify = _build_verify(0x81, _WRONG_PIN_HEX)
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN.replace(" ", ""),
        wrong_verify,
        timeout=30,
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("VERIFY wrong PW1 SW: %s", sw)

    assert sw is not None, f"Could not extract SW from output:\n{combined}"
    assert sw.upper().startswith("63C") or sw.upper() == "6983", (
        f"Expected SW=63Cx (wrong PIN) or 6983 (blocked); got SW={sw!r}."
    )

    if sw.upper().startswith("63C"):
        retries = int(sw[3], 16)
        log.info("Retries remaining after wrong PW1: %d", retries)
        assert 0 <= retries <= 15, f"Implausible retry counter: {retries}"


@_XFAIL
def test_openpgp_verify_query_returns_retry_count(runner: CLIRunner) -> None:
    """VERIFY query (no data) must return 63Cx or 9000 (already verified)."""
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN.replace(" ", ""),
        _VERIFY_QUERY_PW1_81,
        timeout=30,
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("VERIFY query PW1(81) SW: %s", sw)

    assert sw is not None, f"No SW in output:\n{combined}"
    assert sw.upper().startswith("63C") or sw.upper() == "9000", (
        f"Expected 63Cx (retry count) or 9000 (already verified); got {sw!r}."
    )


@_XFAIL
def test_openpgp_change_pw1_succeeds(runner: CLIRunner, run_dir: Path) -> None:
    """CHANGE REFERENCE DATA for PW1 must update the PIN and accept the new value.

    Changes PW1 from '123456' to '654321', verifies the new PIN works, then
    restores the default so subsequent tests are unaffected.
    """
    change_fwd = _build_change_pin(0x81, _PW1_DEFAULT, _PW1_ALT)
    result_fwd = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN.replace(" ", ""),
        change_fwd,
        save_as="openpgp_01_change_pw1_forward",
        timeout=30,
    )
    combined_fwd = result_fwd.stdout + result_fwd.stderr
    sw_fwd = _sw_from_output(combined_fwd)
    log.info("CHANGE PW1 (forward) SW: %s", sw_fwd)

    assert sw_fwd == "9000", (
        f"CHANGE REFERENCE DATA failed (SW={sw_fwd!r}).\n"
        f"Output:\n{combined_fwd}"
    )

    # Verify new PIN
    verify_new = _build_verify(0x81, _PW1_ALT)
    result_verify = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN.replace(" ", ""),
        verify_new,
        timeout=30,
    )
    sw_verify = _sw_from_output(result_verify.stdout + result_verify.stderr)
    log.info("VERIFY new PW1 SW: %s", sw_verify)
    assert sw_verify == "9000", (
        f"New PW1 does not verify (SW={sw_verify!r})."
    )

    # Restore default
    change_back = _build_change_pin(0x81, _PW1_ALT, _PW1_DEFAULT)
    result_back = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN.replace(" ", ""),
        change_back,
        save_as="openpgp_01_change_pw1_back",
        timeout=30,
    )
    sw_back = _sw_from_output(result_back.stdout + result_back.stderr)
    log.info("CHANGE PW1 (back) SW: %s", sw_back)
    assert sw_back == "9000", (
        f"Could not restore PW1 to default (SW={sw_back!r}).\n"
        "Subsequent OpenPGP tests may fail."
    )

    log.info("PW1 change round-trip completed successfully.")


@_XFAIL
def test_openpgp_verify_pw3_wrong_returns_63cx(runner: CLIRunner) -> None:
    """VERIFY PW3 with a wrong value must return SW=63Cx."""
    wrong_verify_pw3 = _build_verify(0x83, _WRONG_PIN_HEX)
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN.replace(" ", ""),
        wrong_verify_pw3,
        timeout=30,
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("VERIFY wrong PW3 SW: %s", sw)

    assert sw is not None, f"No SW in output:\n{combined}"
    assert sw.upper().startswith("63C") or sw.upper() == "6983", (
        f"Expected SW=63Cx or 6983 for wrong PW3; got SW={sw!r}."
    )

    if sw.upper().startswith("63C"):
        retries = int(sw[3], 16)
        log.info("PW3 retries remaining: %d", retries)
        assert 0 <= retries <= 15, f"Implausible PW3 retry counter: {retries}"

    # Immediately restore PW3 by verifying with the correct value
    result_restore = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN.replace(" ", ""),
        _VERIFY_PW3,
        timeout=30,
    )
    sw_restore = _sw_from_output(result_restore.stdout + result_restore.stderr)
    log.info("PW3 restore verify SW: %s", sw_restore)
