"""Provisioning production mode (INS=0xF1) integration tests.

WARNING: These tests involve IRREVERSIBLE OTP operations.
test_set_production_mode_commit() (not yet implemented) permanently modifies
the device. Never run on a device you need to keep in development mode.
Requires -m provisioning to execute.

Currently only contains a non-destructive test that verifies the SO-PIN
guard: sending SET PRODUCTION MODE without prior SO-PIN VERIFY must return
SW 6982 (security status not satisfied).
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from helpers import trace, sw_from_output
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.skip(
        reason=(
            "Provisioning tests require deliberate opt-in: run with -m provisioning. "
            "WARNING: production mode and CRIT0 tests are IRREVERSIBLE."
        )
    ),
    pytest.mark.provisioning,
]

# SC-HSM AID
SC_HSM_AID = "E82B0601040181C31F0201"
_SELECT_SC_HSM_APDU = "00A404000B" + SC_HSM_AID + "00"

# SET PRODUCTION MODE: CLA=00 INS=F1 P1=00 P2=00
_SET_PRODUCTION_APDU = "00F1000000"


def _send_apdus_sequence(runner: CLIRunner, apdus: list[str], save_as: str | None = None):
    """Send a sequence of APDUs via opensc-tool --send-apdu (one flag per APDU)."""
    args = ["opensc-tool"]
    for apdu in apdus:
        args.extend(["--send-apdu", apdu])
    return runner.run(args, save_as=save_as, timeout=30)


def test_set_production_mode_requires_so_pin(runner: CLIRunner, run_dir: Path) -> None:
    """SET PRODUCTION MODE (INS=0xF1) without SO-PIN VERIFY must return SW 6982.

    SELECT SC-HSM resets security state (clearing any prior SO-PIN auth),
    so sending INS=0xF1 immediately after SELECT must fail with
    SW_SECURITY_STATUS (0x6982).
    """
    result = _send_apdus_sequence(
        runner,
        [_SELECT_SC_HSM_APDU, _SET_PRODUCTION_APDU],
        save_as="prov_01_production_no_auth",
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / "prov_01_production_no_auth.json",
        "provisioning_set_production_no_auth",
        result,
        exchanges,
    )

    assert result.returncode == 0, (
        f"opensc-tool failed (rc={result.returncode}).\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    sw = sw_from_output(result.stdout, result.stderr)
    assert sw == "6982", (
        f"Expected SW=6982 (security status not satisfied), got SW={sw}\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
