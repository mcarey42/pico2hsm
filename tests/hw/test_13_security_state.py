"""Hardware integration tests for SELECT AID security-state isolation.

Tests verify that re-selecting the SC-HSM applet (or switching applets)
clears the authenticated session, requiring a fresh VERIFY before any
PIN-protected operation succeeds.

Per SC_HSM_APDU_REFERENCE.md section 3.10:
  CHANGE REFERENCE DATA returns SW=9000 with the note
  "session closed; re-VERIFY required".
The dispatcher also clears pin_verified on every SELECT AID.
"""

from __future__ import annotations

import logging
import re

import pytest

from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# APDU constants
# ---------------------------------------------------------------------------
SELECT_SC_HSM = "00A404000BE82B0601040181C31F020100"
SELECT_PIV    = "00A4040009A00000030800001000"

# LIST KEYS: CLA=0x80 INS=0x58 P1=0x00 P2=0xFF Le=0x00
# Requires PIN-verified session; returns 6982 or 6985 if not authenticated.
LIST_KEYS = "805800FF00"


# ---------------------------------------------------------------------------
# Helpers (module-local)
# ---------------------------------------------------------------------------

def _parse_sw(opensc_output: str) -> list[int]:
    """Return list of status words from all Received lines."""
    sws = []
    for line in opensc_output.splitlines():
        m = re.search(r'Received.*SW1=0x([0-9A-Fa-f]+).*SW2=0x([0-9A-Fa-f]+)', line)
        if m:
            sws.append((int(m.group(1), 16) << 8) | int(m.group(2), 16))
    return sws


def _last_sw(opensc_output: str) -> int:
    """Return the last status word from the output, or 0 if none found."""
    sws = _parse_sw(opensc_output)
    return sws[-1] if sws else 0


def _verify_pin_apdu(pin: str) -> str:
    """Build a VERIFY User PIN APDU from an ASCII PIN string."""
    pin_bytes = pin.encode()
    return f"00200081{len(pin_bytes):02X}{pin_bytes.hex()}"


# ---------------------------------------------------------------------------
# Tests: SELECT clears security state
# ---------------------------------------------------------------------------

class TestSelectClearsAuth:
    """Re-SELECT SC-HSM AID must clear pin_verified."""

    def test_select_clears_pin_verified(
        self, runner: CLIRunner, config: dict, initialized_device
    ) -> None:
        """Re-SELECT SC-HSM AID must clear pin_verified; LIST KEYS must then fail."""
        verify_apdu = _verify_pin_apdu(config["pin"])

        # Step 1: SELECT + VERIFY + LIST KEYS — must succeed
        r = runner.send_apdu(
            SELECT_SC_HSM, verify_apdu, LIST_KEYS,
            reader=0, save_as="13_select_verify_list",
        )
        sws = _parse_sw(r.stdout)
        log.info("Step 1 SWs: %s", [f"{sw:04X}" for sw in sws])
        # Last SW should be 9000 (LIST KEYS success)
        assert _last_sw(r.stdout) == 0x9000, (
            f"LIST KEYS after VERIFY should succeed, got SW={_last_sw(r.stdout):04X}"
        )

        # Step 2: re-SELECT + LIST KEYS without re-verifying — must fail
        r2 = runner.send_apdu(
            SELECT_SC_HSM, LIST_KEYS,
            reader=0, save_as="13_reselect_list_no_verify",
        )
        sw = _last_sw(r2.stdout)
        log.info("Step 2 LIST KEYS after re-SELECT: SW=%04X", sw)
        assert sw == 0x6982 or sw == 0x6985, (
            f"Expected SW=6982 or 6985 after re-SELECT, got {sw:04X}"
        )

    def test_double_select_still_requires_verify(
        self, runner: CLIRunner, config: dict, initialized_device
    ) -> None:
        """Two consecutive SELECTs must still require VERIFY before LIST KEYS."""
        # SELECT twice, then LIST KEYS — should fail
        r = runner.send_apdu(
            SELECT_SC_HSM, SELECT_SC_HSM, LIST_KEYS,
            reader=0, save_as="13_double_select",
        )
        sw = _last_sw(r.stdout)
        assert sw == 0x6982 or sw == 0x6985, (
            f"Double SELECT did not clear auth: SW={sw:04X}"
        )


class TestAppletSwitchClearsAuth:
    """Switching between applets must clear security state."""

    def test_piv_select_then_schsm_requires_reauth(
        self, runner: CLIRunner, config: dict, initialized_device
    ) -> None:
        """Selecting PIV then re-selecting SC-HSM must require fresh PIN."""
        verify_apdu = _verify_pin_apdu(config["pin"])

        # Step 1: Verify on SC-HSM
        r = runner.send_apdu(
            SELECT_SC_HSM, verify_apdu,
            reader=0, save_as="13_verify_before_piv",
        )
        if _last_sw(r.stdout) != 0x9000:
            pytest.skip("Could not verify PIN")

        # Step 2: Switch to PIV applet
        piv_result = runner.send_apdu(
            SELECT_PIV,
            reader=0, save_as="13_select_piv",
        )
        if _last_sw(piv_result.stdout) != 0x9000:
            pytest.skip("PIV applet not present in this build")

        # Step 3: Switch back to SC-HSM — should clear pin_verified
        # Step 4: LIST KEYS without re-verifying — must fail
        r2 = runner.send_apdu(
            SELECT_SC_HSM, LIST_KEYS,
            reader=0, save_as="13_schsm_after_piv",
        )
        sw = _last_sw(r2.stdout)
        log.info("LIST KEYS after PIV→SC-HSM switch: SW=%04X", sw)
        assert sw == 0x6982 or sw == 0x6985, (
            f"Applet switch did not clear security state: SW={sw:04X}"
        )

    def test_openpgp_select_then_schsm_requires_reauth(
        self, runner: CLIRunner, config: dict, initialized_device
    ) -> None:
        """Selecting OpenPGP then re-selecting SC-HSM must require fresh PIN."""
        # OpenPGP AID (D2 76 00 01 24 01)
        SELECT_OPENPGP = "00A4040006D27600012401"
        verify_apdu = _verify_pin_apdu(config["pin"])

        # Step 1: Verify on SC-HSM
        r = runner.send_apdu(
            SELECT_SC_HSM, verify_apdu,
            reader=0, save_as="13_verify_before_openpgp",
        )
        if _last_sw(r.stdout) != 0x9000:
            pytest.skip("Could not verify PIN")

        # Step 2: Switch to OpenPGP applet
        openpgp_result = runner.send_apdu(
            SELECT_OPENPGP,
            reader=0, save_as="13_select_openpgp",
        )
        if _last_sw(openpgp_result.stdout) != 0x9000:
            pytest.skip("OpenPGP applet not present in this build")

        # Step 3: Switch back to SC-HSM + LIST KEYS — must fail
        r2 = runner.send_apdu(
            SELECT_SC_HSM, LIST_KEYS,
            reader=0, save_as="13_schsm_after_openpgp",
        )
        sw = _last_sw(r2.stdout)
        log.info("LIST KEYS after OpenPGP→SC-HSM switch: SW=%04X", sw)
        assert sw == 0x6982 or sw == 0x6985, (
            f"Applet switch did not clear security state: SW={sw:04X}"
        )
