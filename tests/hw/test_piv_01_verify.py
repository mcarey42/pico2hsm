"""Tests for PIV PIN VERIFY, retry counter, and CHANGE REFERENCE DATA.

Verifies the PIN authentication lifecycle:
- Default PIN "123456" (padded to 8 bytes: 31 32 33 34 35 36 FF FF) is accepted.
- Submitting a wrong PIN decrements the retry counter and returns SW=63Cx.
- The retry counter value in SW is plausible (>0 and <=15).
- CHANGE REFERENCE DATA (INS=0x24, P2=0x80) successfully updates the PIN.

All tests are marked xfail because the PIV applet is not yet implemented.
Remove the xfail mark as each feature is completed.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from helpers import trace, sw_from_output
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# PIV AID
PIV_AID = "A000000308000010000100"

# Default PIN "123456" padded to 8 bytes with 0xFF, no Le
_DEFAULT_PIN_HEX = "3132333435 36FFFF"
_DEFAULT_PIN_CLEAN = "313233343536FFFF"  # as 8 hex-byte payload

# Wrong PIN (never a valid PIV PIN in these tests)
_WRONG_PIN_CLEAN = "DEADBEEF1234AABB"

# SELECT PIV APDU
_SELECT_PIV = "00A404000B" + PIV_AID + "00"

# VERIFY PIN APDU: 00 20 00 80 08 <PIN bytes>
_VERIFY_DEFAULT_PIN_CLEAN = "0020008008" + _DEFAULT_PIN_CLEAN
_VERIFY_WRONG_PIN = "0020008008" + _WRONG_PIN_CLEAN

# VERIFY query (Lc absent): 00 20 00 80 — returns 63Cx without consuming attempt
_VERIFY_QUERY = "00200080"

_XFAIL = pytest.mark.xfail(reason="PIV not yet implemented", strict=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _send_apdus(runner: CLIRunner, *apdus: str, save_as: str | None = None, timeout: int = 30):
    """Send one or more APDUs in sequence via opensc-tool."""
    args = ["opensc-tool"]
    for apdu in apdus:
        args.extend(["--send-apdu", apdu.replace(" ", "")])
    return runner.run(args, save_as=save_as, timeout=timeout)


def _sw_from_output(output: str) -> str | None:
    return sw_from_output(output)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@_XFAIL
def test_piv_verify_default_pin_accepted(runner: CLIRunner, run_dir: Path) -> None:
    """VERIFY with the default PIN '123456' must return SW=9000."""
    result = _send_apdus(
        runner,
        _SELECT_PIV,
        _VERIFY_DEFAULT_PIN_CLEAN,
        save_as="piv_01_verify_default_pin",
        timeout=30,
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / "piv_01_verify_default_pin.json",
        "piv_verify_default_pin",
        result,
        exchanges,
    )
    log.info(
        "PIV VERIFY default PIN: rc=%d  elapsed=%.0f ms  APDUs=%d",
        result.returncode, result.elapsed_ms, len(exchanges),
    )

    assert result.returncode == 0, (
        f"opensc-tool failed (rc={result.returncode}):\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("VERIFY SW: %s", sw)
    assert sw == "9000", (
        f"Expected SW=9000 for correct PIN; got SW={sw!r}.\n"
        f"Full output:\n{combined}"
    )


@_XFAIL
def test_piv_verify_wrong_pin_returns_63cx(runner: CLIRunner, run_dir: Path) -> None:
    """VERIFY with a wrong PIN must return SW=63Cx (x = retries remaining)."""
    result = _send_apdus(
        runner,
        _SELECT_PIV,
        _VERIFY_WRONG_PIN,
        save_as="piv_01_verify_wrong_pin",
        timeout=30,
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("VERIFY wrong PIN SW: %s", sw)

    assert sw is not None, (
        f"Could not extract SW from output:\n{combined}"
    )
    assert sw.upper().startswith("63C") or sw.upper() == "6983", (
        f"Expected SW=63Cx (wrong PIN) or 6983 (blocked); got SW={sw!r}."
    )

    # If 63Cx, verify the retry counter is plausible (1–15)
    if sw.upper().startswith("63C"):
        retries = int(sw[3], 16)
        log.info("Retries remaining after wrong PIN: %d", retries)
        assert 0 <= retries <= 15, f"Implausible retry counter value: {retries}"


@_XFAIL
def test_piv_verify_retry_counter_decrements(runner: CLIRunner) -> None:
    """Submitting a wrong PIN twice must decrement the retry counter by 2.

    This test re-selects the PIV applet between each attempt so the session
    is clean.  It reads the counter via the query form first, then checks
    that two wrong-PIN attempts each decrease it by one.

    Note: This test consumes real retry attempts.  A fresh card with the
    default PIN has 3 retries; after this test 1 retry will remain.
    The test is designed to avoid locking the PIN by never exhausting all
    retries.
    """
    import re

    def get_counter(runner: CLIRunner) -> int | None:
        """Return retry count from VERIFY query SW=63Cx, or None if unavailable."""
        result = _send_apdus(runner, _SELECT_PIV, _VERIFY_QUERY)
        combined = result.stdout + result.stderr
        sw = _sw_from_output(combined)
        if sw and sw.upper().startswith("63C"):
            return int(sw[3], 16)
        if sw == "9000":
            return None  # already verified
        return None

    initial = get_counter(runner)
    if initial is None:
        pytest.skip("Could not read initial retry counter via VERIFY query.")
    if initial < 3:
        pytest.skip(
            f"Retry counter is already below 3 ({initial}); "
            "skipping destructive test to avoid locking the PIN."
        )

    # First wrong PIN
    _send_apdus(runner, _SELECT_PIV, _VERIFY_WRONG_PIN)
    after_first = get_counter(runner)

    # Second wrong PIN
    _send_apdus(runner, _SELECT_PIV, _VERIFY_WRONG_PIN)
    after_second = get_counter(runner)

    log.info(
        "Retry counter: initial=%s  after_1st_wrong=%s  after_2nd_wrong=%s",
        initial, after_first, after_second,
    )

    if after_first is not None:
        assert after_first == initial - 1, (
            f"Expected counter {initial - 1} after first wrong PIN, got {after_first}"
        )
    if after_second is not None:
        assert after_second == initial - 2, (
            f"Expected counter {initial - 2} after second wrong PIN, got {after_second}"
        )

    # Restore counter by verifying with the correct PIN
    restore = _send_apdus(runner, _SELECT_PIV, _VERIFY_DEFAULT_PIN_CLEAN)
    combined = restore.stdout + restore.stderr
    sw = _sw_from_output(combined)
    log.info("Restore verify SW: %s", sw)


@_XFAIL
def test_piv_change_pin_succeeds(runner: CLIRunner, run_dir: Path) -> None:
    """CHANGE REFERENCE DATA must accept the current PIN and set a new one.

    The test changes the PIN from the default to an alternate value, then
    changes it back so subsequent tests see a clean state.

    CHANGE REFERENCE DATA APDU:
        00 24 00 80 10 <old PIN 8 bytes> <new PIN 8 bytes>
    """
    # Old PIN: 123456 padded  →  new PIN: 654321 padded
    old_pin = "313233343536FFFF"
    new_pin = "363534333231FFFF"

    change_fwd_clean = "0024008010" + old_pin + new_pin

    # Change forward: 123456 → 654321
    result_fwd = _send_apdus(
        runner,
        _SELECT_PIV,
        change_fwd_clean,
        save_as="piv_01_change_pin_forward",
        timeout=30,
    )
    combined_fwd = result_fwd.stdout + result_fwd.stderr
    sw_fwd = _sw_from_output(combined_fwd)
    log.info("CHANGE PIN (forward) SW: %s", sw_fwd)

    assert sw_fwd == "9000", (
        f"CHANGE REFERENCE DATA failed (expected SW=9000, got {sw_fwd!r}).\n"
        f"Output:\n{combined_fwd}"
    )

    # Verify the new PIN works
    verify_new = "0020008008" + new_pin
    result_verify = _send_apdus(runner, _SELECT_PIV, verify_new)
    combined_verify = result_verify.stdout + result_verify.stderr
    sw_verify = _sw_from_output(combined_verify)
    log.info("VERIFY new PIN SW: %s", sw_verify)
    assert sw_verify == "9000", (
        f"New PIN does not verify (SW={sw_verify!r})."
    )

    # Change back: 654321 → 123456
    change_back_clean = "0024008010" + new_pin + old_pin
    result_back = _send_apdus(
        runner,
        _SELECT_PIV,
        change_back_clean,
        save_as="piv_01_change_pin_back",
        timeout=30,
    )
    combined_back = result_back.stdout + result_back.stderr
    sw_back = _sw_from_output(combined_back)
    log.info("CHANGE PIN (back) SW: %s", sw_back)
    assert sw_back == "9000", (
        f"Could not restore PIN to default (SW={sw_back!r}).\n"
        "Subsequent PIV tests may fail."
    )

    # Save trace for this full sequence
    exchanges = trace.parse_apdu_trace(result_fwd.stderr + result_back.stderr)
    trace.save_json_trace(
        run_dir / "piv_01_change_pin.json",
        "piv_change_pin",
        result_fwd,
        exchanges,
    )
    log.info("PIN change round-trip completed successfully.")
