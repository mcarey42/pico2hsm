"""Hardware integration tests for ENROLL_PEER_PUBKEY (INS=0x54, P1=0x3D).

Tests verify:
  - Enrollment with a valid P-256 pubkey succeeds (SW 9000) after SO-PIN VERIFY
  - Enrollment without SO-PIN returns SW 6982 (SECURITY_STATUS)
  - Invalid pubkey (wrong length) returns SW 6700 (WRONG_LENGTH)
  - Invalid pubkey (not on curve) returns SW 6A80 (WRONG_DATA)

The APDU format is:
  CLA=0x80, INS=0x54, P1=0x3D, P2=0x00, Data=65-byte uncompressed P-256 pubkey
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time

import pytest

from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# APDU constants
# ---------------------------------------------------------------------------
SELECT_SC_HSM = "00A404000BE82B0601040181C31F020100"
# VERIFY SO-PIN (3537363231383830 -> 8 bytes)
VERIFY_SO_PIN = "00200088083537363231383830"

# A valid P-256 generator point (uncompressed, 65 bytes) for testing.
# This is the NIST P-256 base point G.
P256_GENERATOR = (
    "04"
    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"
)

# Invalid point: correct length (65 bytes) but not on the P-256 curve.
INVALID_POINT = "04" + "FF" * 64


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


def _build_enroll_apdu(pubkey_hex: str) -> str:
    """Build the ENROLL_PEER_PUBKEY APDU as a hex string.

    CLA=0x80, INS=0x54, P1=0x3D, P2=0x00, Lc=len, Data=pubkey
    """
    data_bytes = bytes.fromhex(pubkey_hex)
    lc = len(data_bytes)
    # Extended APDU: 80 54 3D 00 00 <lc_hi> <lc_lo> <data> 00 00
    # But for 65 bytes, short APDU is fine: 80 54 3D 00 <lc> <data> 00
    apdu = f"80543D00{lc:02X}{pubkey_hex}00"
    return apdu


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _wait_for_device(timeout: float = 25.0) -> bool:
    """Poll until pcscd reports a card present."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = subprocess.run(
                ["opensc-tool", "--list-readers"],
                capture_output=True, timeout=5,
            )
            if r.returncode == 0 and b"Yes" in r.stdout:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        time.sleep(0.5)
    return False


@pytest.fixture(scope="module", autouse=True)
def _reinitialize_device(config: dict) -> None:
    """Re-initialize the device before test_15 runs.

    test_14 performs a probe-rs reset which reboots the device and
    invalidates the session-scoped ``initialized_device`` fixture state.
    This module-scoped fixture ensures the device is freshly initialized
    with known PINs before the enrollment tests run.
    """
    log.info("Re-initializing device for enrollment tests...")
    if not _wait_for_device(timeout=15.0):
        pytest.skip("Device not present — cannot re-initialize for enrollment tests")
    result = subprocess.run(
        [
            "sc-hsm-tool",
            "--initialize",
            "--label", config.get("label", "pico2hsm"),
            "--so-pin", config["so_pin"],
            "--pin", config["pin"],
        ],
        capture_output=True, timeout=60,
    )
    if result.returncode != 0:
        pytest.fail(
            f"Re-INITIALIZE for enrollment tests failed: rc={result.returncode}\n"
            f"{result.stderr.decode(errors='replace')}"
        )
    # Wait for USB re-enumeration after INITIALIZE.
    time.sleep(5)
    if not _wait_for_device(timeout=25.0):
        pytest.fail("Device did not re-enumerate after re-INITIALIZE")
    log.info("Device re-initialized for enrollment tests")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEnrollPeerPubkey:
    """ENROLL_PEER_PUBKEY (P1=0x3D) command tests."""

    def test_enroll_succeeds_with_sopin(
        self, initialized_device, runner: CLIRunner, config: dict,
    ) -> None:
        """Enrollment with valid P-256 pubkey after SO-PIN VERIFY returns SW 9000."""
        result = runner.send_apdu(
            SELECT_SC_HSM,
            VERIFY_SO_PIN,
            _build_enroll_apdu(P256_GENERATOR),
            save_as="15_enroll_success",
        )
        sws = _parse_sw(result.stdout)
        log.info("SWs: %s", [f"0x{sw:04X}" for sw in sws])
        # SELECT should succeed, VERIFY should succeed, ENROLL should succeed.
        assert len(sws) >= 3, f"Expected at least 3 responses, got {len(sws)}"
        assert sws[-1] == 0x9000, f"ENROLL should return 9000, got 0x{sws[-1]:04X}"

    def test_enroll_without_sopin_rejected(
        self, initialized_device, runner: CLIRunner,
    ) -> None:
        """Enrollment without SO-PIN VERIFY returns SW 6982 (SECURITY_STATUS)."""
        result = runner.send_apdu(
            SELECT_SC_HSM,
            # No VERIFY SO-PIN here.
            _build_enroll_apdu(P256_GENERATOR),
            save_as="15_enroll_no_sopin",
        )
        sws = _parse_sw(result.stdout)
        log.info("SWs: %s", [f"0x{sw:04X}" for sw in sws])
        assert len(sws) >= 2, f"Expected at least 2 responses, got {len(sws)}"
        assert sws[-1] == 0x6982, f"Should reject without SO-PIN, got 0x{sws[-1]:04X}"

    def test_enroll_wrong_length_rejected(
        self, initialized_device, runner: CLIRunner, config: dict,
    ) -> None:
        """Enrollment with wrong-length data returns SW 6700 (WRONG_LENGTH)."""
        # Send only 32 bytes instead of 65.
        short_data = "AA" * 32
        result = runner.send_apdu(
            SELECT_SC_HSM,
            VERIFY_SO_PIN,
            _build_enroll_apdu(short_data),
            save_as="15_enroll_wrong_length",
        )
        sws = _parse_sw(result.stdout)
        log.info("SWs: %s", [f"0x{sw:04X}" for sw in sws])
        assert len(sws) >= 3
        assert sws[-1] == 0x6700, f"Should reject wrong length, got 0x{sws[-1]:04X}"

    def test_enroll_invalid_point_rejected(
        self, initialized_device, runner: CLIRunner, config: dict,
    ) -> None:
        """Enrollment with invalid P-256 point returns SW 6A80 (WRONG_DATA)."""
        result = runner.send_apdu(
            SELECT_SC_HSM,
            VERIFY_SO_PIN,
            _build_enroll_apdu(INVALID_POINT),
            save_as="15_enroll_invalid_point",
        )
        sws = _parse_sw(result.stdout)
        log.info("SWs: %s", [f"0x{sw:04X}" for sw in sws])
        assert len(sws) >= 3
        assert sws[-1] == 0x6A80, f"Should reject invalid point, got 0x{sws[-1]:04X}"
