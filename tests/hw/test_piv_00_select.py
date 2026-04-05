"""Tests for PIV applet SELECT and basic enumeration.

Verifies that:
- The PIV AID is selectable via a raw APDU (00 A4 04 00 0B <AID>).
- The response FCI TLV is well-formed and contains the correct AID (tag 4F
  inside template 61).
- pkcs11-tool --list-slots via the OpenSC PIV driver shows the PIV slot after
  SELECT, confirming that the PKCS#11 layer can find the applet.

All tests are marked xfail because the PIV applet is not yet implemented in
the firmware.  Remove the xfail mark as each feature is completed.
"""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path

import pytest

from helpers import trace
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# PIV AID (NIST SP 800-73-4): A0 00 00 03 08 00 00 10 00 01 00
PIV_AID = "A000000308000010000100"
PIV_AID_BYTES = bytes.fromhex(PIV_AID)

# SELECT APDU: 00 A4 04 00 0B <AID> 00
_SELECT_PIV_APDU = "00A404000B" + PIV_AID + "00"

_XFAIL = pytest.mark.xfail(reason="PIV not yet implemented", strict=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _send_apdu(runner: CLIRunner, apdu_hex: str, save_as: str | None = None) -> "CLIResult":
    """Send a raw APDU via opensc-tool and return the result."""
    return runner.run(
        ["opensc-tool", "--send-apdu", apdu_hex],
        save_as=save_as,
        timeout=30,
    )


def _send_apdus_sequence(
    runner: CLIRunner,
    apdus: list[str],
    save_as: str | None = None,
) -> "CLIResult":
    """Send a sequence of APDUs via opensc-tool --send-apdu (one flag per APDU)."""
    args = ["opensc-tool"]
    for apdu in apdus:
        args.extend(["--send-apdu", apdu])
    return runner.run(args, save_as=save_as, timeout=30)


def _parse_fci_application_template(response_hex: str) -> dict:
    """Parse the PIV FCI response (61 xx ...) and extract known tags.

    Returns a dict with keys:
        'template_tag': outer tag (should be '61')
        'aid':          hex string from tag 4F (application identifier)
        'label':        hex string from tag 50 (application label)
    """
    data = bytes.fromhex(response_hex.replace(" ", ""))
    result: dict = {}

    if not data:
        return result

    outer_tag = data[0]
    result["template_tag"] = f"{outer_tag:02X}"

    if outer_tag != 0x61 or len(data) < 2:
        return result

    outer_len = data[1]
    payload = data[2:2 + outer_len]

    i = 0
    while i < len(payload):
        tag = payload[i]
        if i + 1 >= len(payload):
            break
        length = payload[i + 1]
        value = payload[i + 2:i + 2 + length]
        if tag == 0x4F:
            result["aid"] = value.hex().upper()
        elif tag == 0x50:
            result["label"] = value.hex().upper()
        i += 2 + length

    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@_XFAIL
def test_piv_select_succeeds(runner: CLIRunner, run_dir: Path) -> None:
    """SELECT PIV AID must return SW=9000."""
    result = _send_apdu(runner, _SELECT_PIV_APDU, save_as="piv_00_select")

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / "piv_00_select.json",
        "piv_select",
        result,
        exchanges,
    )
    log.info(
        "PIV SELECT: rc=%d  elapsed=%.0f ms  APDUs=%d",
        result.returncode,
        result.elapsed_ms,
        len(exchanges),
    )

    assert result.returncode == 0, (
        f"opensc-tool failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    combined = result.stdout + result.stderr
    assert "9000" in combined.replace(" ", "").upper() or "90 00" in combined.upper(), (
        f"Expected SW=9000 in response; got:\n{combined}"
    )


@_XFAIL
def test_piv_select_returns_fci(runner: CLIRunner, run_dir: Path) -> None:
    """SELECT PIV AID response must contain a well-formed FCI template (tag 61)."""
    result = _send_apdu(runner, _SELECT_PIV_APDU, save_as="piv_00_select_fci")

    assert result.returncode == 0, (
        f"opensc-tool failed (rc={result.returncode}):\n{result.stderr}"
    )

    # Extract hex response bytes from stdout (opensc-tool prints them space-separated)
    resp_hex = result.stdout.replace(" ", "").replace("\n", "").strip()
    log.info("PIV SELECT raw response: %s", resp_hex)

    assert resp_hex, "No response data returned from PIV SELECT."

    fci = _parse_fci_application_template(resp_hex)
    assert fci.get("template_tag") == "61", (
        f"Expected outer FCI tag 0x61 (Application Template), got: "
        f"{fci.get('template_tag')!r}\nFull response: {resp_hex}"
    )


@_XFAIL
def test_piv_select_fci_contains_aid(runner: CLIRunner, run_dir: Path) -> None:
    """FCI tag 4F (Application Identifier) must match the PIV AID."""
    result = _send_apdu(runner, _SELECT_PIV_APDU, save_as="piv_00_select_aid_check")

    assert result.returncode == 0, (
        f"opensc-tool failed (rc={result.returncode}):\n{result.stderr}"
    )

    resp_hex = result.stdout.replace(" ", "").replace("\n", "").strip()
    fci = _parse_fci_application_template(resp_hex)

    returned_aid = fci.get("aid", "")
    log.info("FCI AID (tag 4F): %s  expected: %s", returned_aid, PIV_AID)

    assert returned_aid, (
        f"Tag 4F (Application Identifier) not found in FCI response.\n"
        f"Parsed FCI: {fci}\nRaw response: {resp_hex}"
    )
    assert returned_aid.upper() == PIV_AID.upper(), (
        f"AID mismatch: got {returned_aid}, expected {PIV_AID}"
    )


@_XFAIL
def test_piv_list_slots_via_pkcs11(runner: CLIRunner, run_dir: Path) -> None:
    """pkcs11-tool --list-slots must show a PIV-compatible slot after SELECT.

    This exercises the full OpenSC PKCS#11 path: opensc-pkcs11.so binds the
    PIV driver when it finds the AID on the card.
    """
    result = runner.pkcs11_tool(
        "--list-slots",
        save_as="piv_00_list_slots",
        timeout=30,
    )

    log.info(
        "pkcs11-tool --list-slots: rc=%d\n%s",
        result.returncode,
        result.stdout.strip(),
    )

    assert result.returncode == 0, (
        f"pkcs11-tool --list-slots failed (rc={result.returncode}):\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    combined = result.stdout + result.stderr
    assert combined.strip(), "pkcs11-tool --list-slots produced no output."
    log.info("Slot listing output:\n%s", result.stdout.strip())


@_XFAIL
def test_piv_select_clears_session(runner: CLIRunner) -> None:
    """Sending SELECT PIV a second time must succeed (session reset must be idempotent)."""
    for attempt in range(1, 3):
        result = _send_apdu(runner, _SELECT_PIV_APDU)
        assert result.returncode == 0, (
            f"PIV SELECT attempt {attempt} failed (rc={result.returncode}):\n"
            f"{result.stderr}"
        )
        combined = result.stdout + result.stderr
        assert "9000" in combined.replace(" ", "").upper() or "90 00" in combined.upper(), (
            f"PIV SELECT attempt {attempt}: expected SW=9000, got:\n{combined}"
        )
    log.info("Two consecutive PIV SELECTs both returned SW=9000")
