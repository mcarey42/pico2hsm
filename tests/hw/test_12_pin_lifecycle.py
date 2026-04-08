"""Hardware integration tests for PIN lifecycle: change, lockout, reset, and GET CHALLENGE.

Tests cover:
  - CHANGE REFERENCE DATA (INS=0x24) — change User PIN via TLV (P1=0x01)
  - PIN lockout after exhausting retry counter
  - RESET RETRY COUNTER (INS=0x2C) — SO-PIN authenticated reset
  - GET CHALLENGE (INS=0x84) — TRNG random bytes

APDU formats are taken from docs/SC_HSM_APDU_REFERENCE.md.
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


# ---------------------------------------------------------------------------
# Helpers (module-local, same pattern as test_09/test_10)
# ---------------------------------------------------------------------------

def _parse_received_blocks(opensc_output: str) -> list[bytes]:
    """Return one bytes object per Received block in opensc-tool output."""
    blocks: list[bytes] = []
    current: bytearray | None = None
    for line in opensc_output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Received"):
            current = bytearray()
            continue
        if stripped.startswith("Sending"):
            if current is not None:
                blocks.append(bytes(current))
            current = None
            continue
        if current is not None:
            tokens = [t for t in stripped.split()
                      if len(t) == 2 and all(c in '0123456789abcdefABCDEF' for c in t)]
            for tok in tokens[:16]:
                current.append(int(tok, 16))
    if current is not None:
        blocks.append(bytes(current))
    return blocks


def _parse_received_bytes(opensc_output: str) -> bytes:
    """Return data bytes from the LAST Received block."""
    blocks = _parse_received_blocks(opensc_output)
    return blocks[-1] if blocks else b""


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


def _verify_sopin_apdu(so_pin: str) -> str:
    """Build a VERIFY SO-PIN APDU from an ASCII SO-PIN string."""
    so_bytes = so_pin.encode()
    return f"00200088{len(so_bytes):02X}{so_bytes.hex()}"


def _change_pin_tlv_apdu(old_pin: str, new_pin: str, p2: int = 0x81) -> str:
    """Build CHANGE REFERENCE DATA with P1=0x01 (TLV format).

    Per SC_HSM_APDU_REFERENCE.md section 3.10:
      P1=0x01 → TLV encoded: 80 <len> <old_pin> 81 <len> <new_pin>
      P2=0x81 → User PIN
      P2=0x88 → SO-PIN

    Using TLV (P1=0x01) avoids the midpoint-split ambiguity of P1=0x00,
    which requires old and new PINs to be exactly the same length.
    """
    old_bytes = old_pin.encode()
    new_bytes = new_pin.encode()
    # TLV: tag 0x80 = old PIN, tag 0x81 = new PIN
    tlv = bytes([0x80, len(old_bytes)]) + old_bytes + bytes([0x81, len(new_bytes)]) + new_bytes
    lc = len(tlv)
    return f"002401{p2:02X}{lc:02X}{tlv.hex()}"


# ---------------------------------------------------------------------------
# Test class: CHANGE REFERENCE DATA (INS=0x24)
# ---------------------------------------------------------------------------

class TestChangePIN:
    """Tests for CHANGE REFERENCE DATA (INS=0x24)."""

    def test_change_pin_and_use_new_pin(
        self, runner: CLIRunner, config: dict, initialized_device
    ) -> None:
        """CHANGE REFERENCE DATA must accept old+new PIN and activate new PIN."""
        old_pin = config["pin"]
        new_pin = "112233"

        # Change PIN: P1=0x01 (TLV), P2=0x81 (User PIN)
        change_apdu = _change_pin_tlv_apdu(old_pin, new_pin)
        result = runner.send_apdu(
            SELECT_SC_HSM, change_apdu,
            reader=0, save_as="12_change_pin",
        )
        assert _last_sw(result.stdout) == 0x9000, (
            f"CHANGE REFERENCE DATA failed: SW={_last_sw(result.stdout):04X}"
        )

        # Verify new PIN works
        verify_new = _verify_pin_apdu(new_pin)
        r = runner.send_apdu(SELECT_SC_HSM, verify_new, reader=0)
        assert _last_sw(r.stdout) == 0x9000, "New PIN not accepted after change"

        # Restore original PIN so other tests are unaffected
        restore_apdu = _change_pin_tlv_apdu(new_pin, old_pin)
        r2 = runner.send_apdu(SELECT_SC_HSM, restore_apdu, reader=0)
        assert _last_sw(r2.stdout) == 0x9000, (
            f"Failed to restore original PIN: SW={_last_sw(r2.stdout):04X}"
        )

    def test_change_pin_wrong_old_pin_rejected(
        self, runner: CLIRunner, config: dict, initialized_device
    ) -> None:
        """CHANGE REFERENCE DATA with wrong old PIN must be rejected (63Cx or 6983)."""
        wrong_old = "999999"
        new_pin = "112233"

        change_apdu = _change_pin_tlv_apdu(wrong_old, new_pin)
        result = runner.send_apdu(
            SELECT_SC_HSM, change_apdu,
            reader=0, save_as="12_change_pin_wrong_old",
        )
        sw = _last_sw(result.stdout)
        assert sw != 0x9000, "Wrong old PIN was accepted"
        assert (sw & 0xFFF0) == 0x63C0 or sw == 0x6983, (
            f"Unexpected SW={sw:04X} (expected 63Cx or 6983)"
        )

        # Re-verify correct PIN to reset retry counter
        verify = _verify_pin_apdu(config["pin"])
        runner.send_apdu(SELECT_SC_HSM, verify, reader=0)

    def test_change_pin_new_pin_too_short_rejected(
        self, runner: CLIRunner, config: dict, initialized_device
    ) -> None:
        """CHANGE REFERENCE DATA with new PIN below min length (4) must be rejected."""
        old_pin = config["pin"]
        short_pin = "12"  # 2 bytes — below 4-byte minimum

        change_apdu = _change_pin_tlv_apdu(old_pin, short_pin)
        result = runner.send_apdu(
            SELECT_SC_HSM, change_apdu,
            reader=0, save_as="12_change_pin_too_short",
        )
        sw = _last_sw(result.stdout)
        assert sw != 0x9000, f"Short new PIN was accepted: SW={sw:04X}"
        # Expect 6700 (wrong length) per reference
        assert sw == 0x6700 or (sw & 0xFFF0) == 0x63C0, (
            f"Unexpected SW={sw:04X} (expected 6700 or 63Cx)"
        )


# ---------------------------------------------------------------------------
# Test class: PIN lockout and retry counter
# ---------------------------------------------------------------------------

class TestPINLockout:
    """Tests for PIN retry counter decrement and lockout."""

    def test_pin_retry_counter_decrements(
        self, runner: CLIRunner, config: dict, initialized_device
    ) -> None:
        """Each wrong PIN attempt must decrement the retry counter (SW=63Cx)."""
        wrong_pin = "000000"
        apdu = _verify_pin_apdu(wrong_pin)

        result = runner.send_apdu(SELECT_SC_HSM, apdu, reader=0)
        sw = _last_sw(result.stdout)
        assert (sw & 0xFFF0) == 0x63C0, f"Expected 63Cx, got {sw:04X}"
        counter = sw & 0x0F
        assert counter > 0, "Counter already at zero before test"
        log.info("Retry counter after one wrong PIN: %d", counter)

        # Reset by verifying correct PIN
        verify = _verify_pin_apdu(config["pin"])
        r = runner.send_apdu(SELECT_SC_HSM, verify, reader=0)
        assert _last_sw(r.stdout) == 0x9000, "Could not restore PIN after decrement test"

    def test_pin_blocked_after_exhaustion(
        self, runner: CLIRunner, config: dict, initialized_device
    ) -> None:
        """After max wrong PINs, device must return SW=6983 (blocked)."""
        wrong_pin = "000000"
        apdu = _verify_pin_apdu(wrong_pin)

        blocked = False
        for i in range(10):  # default retries = 3, so 10 is more than enough
            result = runner.send_apdu(SELECT_SC_HSM, apdu, reader=0)
            sw = _last_sw(result.stdout)
            log.info("Attempt %d: SW=%04X", i + 1, sw)
            if sw == 0x6983:
                blocked = True
                break

        assert blocked, "PIN was never blocked after repeated failures"

        # Confirm PIN is blocked — even correct PIN must be rejected
        verify_correct = _verify_pin_apdu(config["pin"])
        r = runner.send_apdu(SELECT_SC_HSM, verify_correct, reader=0)
        assert _last_sw(r.stdout) == 0x6983, (
            f"Correct PIN accepted on blocked device: SW={_last_sw(r.stdout):04X}"
        )

        # Restore via SO-PIN reset:
        # Per SC_HSM_APDU_REFERENCE.md section 3.11:
        #   RESET RETRY COUNTER requires so_pin_verified session.
        #   Step 1: VERIFY SO-PIN (INS=0x20 P2=0x88)
        #   Step 2: INS=0x2C P1=0x02 P2=0x81 data=new_pin
        verify_sopin = _verify_sopin_apdu(config["so_pin"])
        new_pin_bytes = config["pin"].encode()
        reset_apdu = f"002C0281{len(new_pin_bytes):02X}{new_pin_bytes.hex()}"

        r = runner.send_apdu(
            SELECT_SC_HSM, verify_sopin, reset_apdu,
            reader=0, save_as="12_unblock_after_exhaust",
        )
        assert _last_sw(r.stdout) == 0x9000, (
            f"RESET RETRY COUNTER failed: SW={_last_sw(r.stdout):04X}"
        )

        # Verify PIN works again
        r = runner.send_apdu(SELECT_SC_HSM, verify_correct, reader=0)
        assert _last_sw(r.stdout) == 0x9000, "PIN still blocked after reset"

    def test_pin_reset_via_sopin(
        self, runner: CLIRunner, config: dict, initialized_device
    ) -> None:
        """RESET RETRY COUNTER with correct SO-PIN session must unblock a locked PIN."""
        wrong_pin = "000000"
        wrong_apdu = _verify_pin_apdu(wrong_pin)

        # Lock the PIN
        for _ in range(10):
            r = runner.send_apdu(SELECT_SC_HSM, wrong_apdu, reader=0)
            if _last_sw(r.stdout) == 0x6983:
                break

        # Confirm locked
        r = runner.send_apdu(SELECT_SC_HSM, wrong_apdu, reader=0)
        assert _last_sw(r.stdout) == 0x6983, "PIN not locked"

        # Reset: VERIFY SO-PIN then RESET RETRY COUNTER P1=0x02 P2=0x81
        verify_sopin = _verify_sopin_apdu(config["so_pin"])
        new_pin_bytes = config["pin"].encode()
        reset_apdu = f"002C0281{len(new_pin_bytes):02X}{new_pin_bytes.hex()}"

        r = runner.send_apdu(
            SELECT_SC_HSM, verify_sopin, reset_apdu,
            reader=0, save_as="12_reset_via_sopin",
        )
        assert _last_sw(r.stdout) == 0x9000, (
            f"RESET RETRY COUNTER failed: SW={_last_sw(r.stdout):04X}"
        )

        # Verify PIN works again
        verify = _verify_pin_apdu(config["pin"])
        r = runner.send_apdu(SELECT_SC_HSM, verify, reader=0)
        assert _last_sw(r.stdout) == 0x9000, "PIN still not accepted after reset"


# ---------------------------------------------------------------------------
# Test class: GET CHALLENGE (INS=0x84)
# ---------------------------------------------------------------------------

class TestGetChallenge:
    """Tests for GET CHALLENGE (INS=0x84) — TRNG random bytes."""

    def test_get_challenge_returns_requested_length(
        self, runner: CLIRunner, initialized_device
    ) -> None:
        """GET CHALLENGE must return exactly Le bytes.

        Per SC_HSM_APDU_REFERENCE.md section 3.16:
          CLA=00 INS=84 P1=00 P2=00 Le=<n>
        Le=0x20 requests 32 bytes.
        """
        apdu = "0084000020"
        result = runner.send_apdu(
            SELECT_SC_HSM, apdu,
            reader=0, save_as="12_get_challenge_32",
        )
        assert _last_sw(result.stdout) == 0x9000
        data = _parse_received_bytes(result.stdout)
        assert len(data) == 32, f"Expected 32 bytes, got {len(data)}"

    def test_get_challenge_8_bytes(
        self, runner: CLIRunner, initialized_device
    ) -> None:
        """GET CHALLENGE with Le=8 must return exactly 8 bytes."""
        apdu = "0084000008"
        result = runner.send_apdu(SELECT_SC_HSM, apdu, reader=0)
        assert _last_sw(result.stdout) == 0x9000
        data = _parse_received_bytes(result.stdout)
        assert len(data) == 8, f"Expected 8 bytes, got {len(data)}"

    def test_get_challenge_not_all_zeros(
        self, runner: CLIRunner, initialized_device
    ) -> None:
        """GET CHALLENGE must not return all zeros (basic entropy sanity check)."""
        apdu = "0084000020"
        result = runner.send_apdu(SELECT_SC_HSM, apdu, reader=0)
        assert _last_sw(result.stdout) == 0x9000
        data = _parse_received_bytes(result.stdout)
        assert data != bytes(32), "GET CHALLENGE returned all zeros — TRNG failure"
        assert data != bytes([0xFF] * 32), "GET CHALLENGE returned all 0xFF"

    def test_get_challenge_differs_on_consecutive_calls(
        self, runner: CLIRunner, initialized_device
    ) -> None:
        """Consecutive GET CHALLENGE calls must return different bytes."""
        apdu = "0084000020"
        r1 = runner.send_apdu(SELECT_SC_HSM, apdu, reader=0)
        r2 = runner.send_apdu(SELECT_SC_HSM, apdu, reader=0)
        d1 = _parse_received_bytes(r1.stdout)
        d2 = _parse_received_bytes(r2.stdout)
        assert _last_sw(r1.stdout) == 0x9000
        assert _last_sw(r2.stdout) == 0x9000
        assert d1 != d2, "GET CHALLENGE returned identical bytes on consecutive calls"
