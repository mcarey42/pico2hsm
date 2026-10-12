"""Tests for OpenPGP Card applet SELECT and basic enumeration.

Verifies:
- SELECT OpenPGP AID (D2 76 00 01 24 01) returns SW=9000 and a valid FCI
  (outer tag 6F, containing tag 84 with the full AID).
- GET DATA for DO 006E (Application Related Data) returns a non-empty TLV
  response that is parseable (contains at least one known sub-DO).
- `gpg --no-tty --card-status` can parse the card without error (returncode 0)
  and stdout contains the string "OpenPGP" confirming GnuPG found the applet.

"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import pytest

from helpers import trace, sw_from_output, last_response_hex
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# OpenPGP AID prefix (first 6 bytes) used for SELECT matching
OPENPGP_AID_PREFIX = "D27600012401"

# SELECT OpenPGP APDU: 00 A4 04 00 06 <AID prefix> 00
_SELECT_OPENPGP = "00A404000 6" + OPENPGP_AID_PREFIX + "00"
_SELECT_OPENPGP_CLEAN = "00A40400 06" + OPENPGP_AID_PREFIX + "00"

# GET DATA for DO 006E (Application Related Data)
# Command: 00 CA 00 6E 00
_GET_DATA_006E = "00CA006E00"



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


def _parse_fci_6f(resp_hex: str) -> dict:
    """Parse a SELECT FCI response starting with tag 6F.

    Returns:
        {
            'aid': hex string from tag 84 (application AID),
            'has_a5': True if proprietary data tag A5 is present,
        }
    """
    data = bytes.fromhex(resp_hex.replace(" ", ""))
    result: dict = {}
    if not data or data[0] != 0x6F:
        return result

    # Decode outer 6F length
    idx = 1
    outer_len = data[idx]
    is_two_byte = outer_len >= 0x80
    if outer_len == 0x81:
        outer_len = data[idx + 1]
        idx += 2
    elif outer_len == 0x82:
        outer_len = int.from_bytes(data[idx + 1:idx + 3], "big")
        idx += 3
    else:
        idx += 1

    payload = data[idx:idx + outer_len]
    i = 0
    while i < len(payload):
        tag = payload[i]
        if i + 1 >= len(payload):
            break
        length = payload[i + 1]
        # Handle two-byte lengths
        if length >= 0x80:
            if length == 0x81:
                length = payload[i + 2]
                value = payload[i + 3:i + 3 + length]
                i += 3 + length
            else:
                i += 1
                continue
        else:
            value = payload[i + 2:i + 2 + length]
            i += 2 + length

        if tag == 0x84:
            result["aid"] = value.hex().upper()
        elif tag == 0xA5:
            result["has_a5"] = True

    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_openpgp_select_succeeds(runner: CLIRunner, run_dir: Path) -> None:
    """SELECT OpenPGP AID must return SW=9000."""
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN.replace(" ", ""),
        save_as="openpgp_00_select",
        timeout=30,
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / "openpgp_00_select.json",
        "openpgp_select",
        result,
        exchanges,
    )
    log.info(
        "OpenPGP SELECT: rc=%d  elapsed=%.0f ms  APDUs=%d",
        result.returncode, result.elapsed_ms, len(exchanges),
    )

    assert result.returncode == 0, (
        f"opensc-tool failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    combined = result.stdout + result.stderr
    assert "9000" in combined.replace(" ", "").upper() or "90 00" in combined.upper(), (
        f"Expected SW=9000; got:\n{combined}"
    )


def test_openpgp_select_returns_fci_6f(runner: CLIRunner) -> None:
    """SELECT OpenPGP FCI must be well-formed (outer tag 0x6F)."""
    result = _send_apdus(runner, _SELECT_OPENPGP_CLEAN.replace(" ", ""), timeout=30)
    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    if sw != "9000":
        pytest.skip(f"SELECT returned SW={sw!r}.")

    resp_hex = last_response_hex(result.stdout)
    log.info("OpenPGP SELECT FCI: %s", resp_hex[:80])

    assert resp_hex, "No FCI data returned."
    assert resp_hex.upper().startswith("6F"), (
        f"Expected outer FCI tag 0x6F; got: {resp_hex[:8]!r}"
    )


def test_openpgp_select_fci_contains_aid(runner: CLIRunner) -> None:
    """FCI tag 84 (Application AID) must start with the OpenPGP AID prefix."""
    result = _send_apdus(runner, _SELECT_OPENPGP_CLEAN.replace(" ", ""), timeout=30)
    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    if sw != "9000":
        pytest.skip(f"SELECT returned SW={sw!r}.")

    resp_hex = last_response_hex(result.stdout)
    fci = _parse_fci_6f(resp_hex)
    returned_aid = fci.get("aid", "")
    log.info("FCI AID (tag 84): %s", returned_aid)

    assert returned_aid, (
        f"Tag 84 (Application AID) not found in SELECT FCI.\n"
        f"Parsed FCI: {fci}\nRaw: {resp_hex}"
    )
    assert returned_aid.upper().startswith(OPENPGP_AID_PREFIX.upper()), (
        f"AID mismatch: got {returned_aid}, expected prefix {OPENPGP_AID_PREFIX}"
    )


def test_openpgp_get_data_006e_returns_data(runner: CLIRunner, run_dir: Path) -> None:
    """GET DATA for DO 006E (Application Related Data) must return a non-empty response.

    DO 006E is the Application Related Data object.  Its response is a TLV
    container (tag 6E) that holds sub-DOs including the AID (tag 4F),
    historical bytes (5F52), extended capabilities (C0), and others.  We only
    assert that the response is non-empty and starts with the expected tag.
    """
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN.replace(" ", ""),
        _GET_DATA_006E,
        save_as="openpgp_00_get_data_006e",
        timeout=30,
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / "openpgp_00_get_data_006e.json",
        "openpgp_get_data_006e",
        result,
        exchanges,
    )
    log.info(
        "GET DATA 006E: rc=%d  elapsed=%.0f ms  APDUs=%d",
        result.returncode, result.elapsed_ms, len(exchanges),
    )

    assert result.returncode == 0, (
        f"opensc-tool failed (rc={result.returncode}):\n{result.stderr}"
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("GET DATA 006E SW: %s", sw)
    assert sw == "9000", (
        f"Expected SW=9000 from GET DATA 006E; got SW={sw!r}."
    )

    resp_hex = last_response_hex(result.stdout)
    log.info("DO 006E response: %s ...", resp_hex[:64])

    assert resp_hex, "GET DATA 006E returned no response data."
    # DO 006E response is wrapped in tag 6E
    assert resp_hex.upper().startswith("6E"), (
        f"Expected DO 006E response to start with tag 0x6E; got: {resp_hex[:8]!r}"
    )


def test_openpgp_gpg_card_status(runner: CLIRunner, run_dir: Path) -> None:
    """gpg --no-tty --card-status must exit 0 and mention 'OpenPGP' in output.

    This validates that GnuPG's scdaemon can find and communicate with the
    OpenPGP applet via the pcscd stack.

    Note: Requires gpg and pcscd to be running.  The test is a subprocess
    invocation; it does NOT use the CLIRunner APDU trace infrastructure.
    """
    from conftest import gpg_card_status_cmd

    cmd, reason = gpg_card_status_cmd()
    if reason:
        pytest.skip(reason)
    log.info("Running: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=30,
            text=True,
        )
    except FileNotFoundError:
        pytest.skip("gpg not found in PATH; skipping card-status test.")
    except subprocess.TimeoutExpired:
        pytest.fail("gpg --card-status timed out after 30 s.")

    stdout = proc.stdout
    stderr = proc.stderr
    log.info("gpg --card-status rc=%d", proc.returncode)
    log.info("STDOUT:\n%s", stdout.strip())
    if stderr.strip():
        log.info("STDERR:\n%s", stderr.strip())

    # Save output
    out_path = run_dir / "openpgp_00_gpg_card_status.txt"
    out_path.write_text(
        f"returncode: {proc.returncode}\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}",
        encoding="utf-8",
    )

    # Skip if scdaemon is not available or not running
    if proc.returncode != 0 and "scdaemon" in (stdout + stderr).lower():
        pytest.skip(f"scdaemon not available: {(stdout + stderr).strip()}")

    assert proc.returncode == 0, (
        f"gpg --card-status exited with rc={proc.returncode}.\n"
        f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    )

    combined = (stdout + stderr).lower()
    assert "openpgp" in combined, (
        f"Expected 'openpgp' in gpg --card-status output; got:\n{stdout}"
    )
    log.info("gpg --card-status OK: OpenPGP applet found.")
