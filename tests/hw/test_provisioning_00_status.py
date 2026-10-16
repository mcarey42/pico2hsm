"""Provisioning status (INS=0xF0) integration tests.

Verifies that the GET PROVISIONING STATUS command returns a well-formed
TLV response with the device's current security state.

WARNING: Provisioning tests require deliberate opt-in: run with -m provisioning.
The GET STATUS test itself is non-destructive, but other provisioning tests
(production mode, CRIT1) involve IRREVERSIBLE OTP operations.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from helpers import trace, sw_from_output, last_response_hex
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip(
        reason=(
            "Provisioning tests require deliberate opt-in: run with -m provisioning. "
            "WARNING: production mode and CRIT1 tests are IRREVERSIBLE."
        )
    ),
    pytest.mark.provisioning,
]

# SC-HSM AID
SC_HSM_AID = "E82B0601040181C31F0201"
_SELECT_SC_HSM_APDU = "00A404000B" + SC_HSM_AID + "00"

# GET PROVISIONING STATUS: CLA=00 INS=F0 P1=00 P2=00 Le=00
_GET_STATUS_APDU = "00F0000000"


def _send_apdu(runner: CLIRunner, apdu_hex: str, save_as: str | None = None):
    """Send a raw APDU via opensc-tool and return the result."""
    return runner.run(
        ["opensc-tool", "--send-apdu", apdu_hex],
        save_as=save_as,
        timeout=30,
    )


def _send_apdus_sequence(runner: CLIRunner, apdus: list[str], save_as: str | None = None):
    """Send a sequence of APDUs via opensc-tool --send-apdu (one flag per APDU)."""
    args = ["opensc-tool"]
    for apdu in apdus:
        args.extend(["--send-apdu", apdu])
    return runner.run(args, save_as=save_as, timeout=30)


def test_get_security_status(runner: CLIRunner, run_dir: Path) -> None:
    """GET PROVISIONING STATUS (INS=0xF0) must return SW=9000 with valid TLV.

    Sends SELECT SC-HSM followed by INS=0xF0 and validates:
    1. The response SW is 9000.
    2. The response data starts with tag 0x6F (constructed TLV).
    3. The inner TLV contains tags 80, 81, 82, 83, 84 (1 byte each) and
       85 (the image version, 4 bytes).
    """
    result = _send_apdus_sequence(
        runner,
        [_SELECT_SC_HSM_APDU, _GET_STATUS_APDU],
        save_as="prov_00_get_status",
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / "prov_00_get_status.json",
        "provisioning_get_status",
        result,
        exchanges,
    )

    assert result.returncode == 0, (
        f"opensc-tool failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    combined = result.stdout + result.stderr
    sw = sw_from_output(result.stdout, result.stderr)
    assert sw == "9000", f"Expected SW=9000, got SW={sw}\n{combined}"

    # Validate TLV structure of response data.
    resp_hex = last_response_hex(result.stdout)
    assert resp_hex, "No response data returned from GET STATUS."

    data = bytes.fromhex(resp_hex.replace(" ", ""))
    assert len(data) >= 2, f"Response too short: {resp_hex}"
    assert data[0] == 0x6F, f"Expected outer tag 0x6F, got 0x{data[0]:02X}"

    outer_len = data[1]
    payload = data[2:2 + outer_len]

    # Parse inner TLV tags and verify expected tags are present.
    expected_tags = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85}
    found_tags = set()
    i = 0
    while i < len(payload):
        if i + 1 >= len(payload):
            break
        tag = payload[i]
        length = payload[i + 1]
        found_tags.add(tag)
        want = 4 if tag == 0x85 else 1
        assert length == want, f"Tag 0x{tag:02X} has length {length}, expected {want}"
        i += 2 + length

    missing = expected_tags - found_tags
    assert not missing, (
        f"Missing TLV tags in GET STATUS response: "
        f"{', '.join(f'0x{t:02X}' for t in sorted(missing))}\n"
        f"Found: {', '.join(f'0x{t:02X}' for t in sorted(found_tags))}\n"
        f"Raw response: {resp_hex}"
    )
