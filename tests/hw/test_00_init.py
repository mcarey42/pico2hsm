"""Tests for HSM device initialization."""

from __future__ import annotations

import logging

import pytest

from helpers import trace
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Initialization tests
# ---------------------------------------------------------------------------

def test_init_succeeds(initialized_device) -> None:
    """sc-hsm-tool --initialize must exit with returncode 0."""
    assert initialized_device.returncode == 0, (
        f"Initialization returned rc={initialized_device.returncode}\n"
        f"STDOUT:\n{initialized_device.stdout}\n"
        f"STDERR:\n{initialized_device.stderr}"
    )


def test_init_apdu_trace_captured(initialized_device, run_dir) -> None:
    """The trace file for initialization must exist and contain data."""
    trace_file = run_dir / "00_initialize.txt"
    assert trace_file.exists(), (
        f"Trace file not found: {trace_file}\n"
        "Check that CLIRunner.sc_hsm_tool was called with save_as='00_initialize'."
    )
    content = trace_file.read_text(encoding="utf-8")
    assert len(content) > 0, "Trace file is empty."


def test_init_apdu_count(initialized_device, runner: CLIRunner) -> None:
    """Initialization must produce at least 3 APDU exchanges.

    Expected minimum: SELECT AID + INITIALIZE + WRITE DATA (EF.C.DevAut stub).
    """
    exchanges = trace.parse_apdu_trace(initialized_device.stderr)
    log.info("APDU exchanges captured: %d", len(exchanges))
    if exchanges:
        log.info("\n%s", trace.format_trace_summary(exchanges))
    assert len(exchanges) >= 3, (
        f"Expected at least 3 APDU exchanges (SELECT + INITIALIZE + WRITE DATA), "
        f"got {len(exchanges)}.\n"
        f"Raw stderr snippet:\n{initialized_device.stderr[:500]}"
    )


def test_reinit_requires_correct_sopin(runner: CLIRunner, config: dict) -> None:
    """Attempting re-initialization with a wrong SO-PIN must fail.

    Note: sc-hsm-tool exits with code 0 even when the card rejects the
    INITIALIZE command with SW=6982 (Security status not satisfied).  We
    therefore check the stderr output for the rejection message rather than
    relying on the process exit code.
    """
    wrong_so_pin = "DEADBEEF12345678"  # deliberately wrong
    result = runner.sc_hsm_tool(
        "--initialize",
        "--label",  config["label"],
        "--so-pin", wrong_so_pin,
        "--pin",    config["pin"],
        save_as="00_reinit_wrong_sopin",
    )
    # Skip if the card is not reachable — this test requires a live device.
    card_absent = (
        "Card not present" in result.stderr
        or "Failed to connect to card" in result.stderr
        or "No card" in result.stderr
    )
    if card_absent:
        pytest.skip(
            "Card not present — cannot verify SO-PIN rejection. "
            "Ensure the device is connected and pcscd recognises it."
        )

    # The firmware returns SW=6982; OpenSC logs this as "Security status not satisfied".
    rejected = (
        "Security status not satisfied" in result.stderr
        or "security status" in result.stderr.lower()
        or "6982" in result.stderr
        or result.returncode != 0
    )
    assert rejected, (
        "Re-initialization with a wrong SO-PIN unexpectedly succeeded "
        f"(rc={result.returncode}). "
        "Expected SW=6982 (Security status not satisfied) in stderr.\n"
        f"STDERR:\n{result.stderr[-1000:]}"
    )
    log.info("Correctly rejected wrong SO-PIN (rc=%d)", result.returncode)


def test_pin_verify_after_init(
    runner: CLIRunner,
    config: dict,
    initialized_device,  # noqa: ARG001 – ensures init ran first
) -> None:
    """pkcs11-tool --list-objects with correct PIN must succeed after initialization."""
    result = runner.pkcs11_tool(
        "--login",
        "--pin",         config["pin"],
        "--list-objects",
        save_as="00_list_objects_after_init",
    )
    assert result.returncode == 0, (
        f"pkcs11-tool --list-objects failed (rc={result.returncode}) after initialization.\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    log.info("PIN verify OK; object list:\n%s", result.stdout.strip())
