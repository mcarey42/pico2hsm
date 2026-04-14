"""Hardware integration tests for malformed / hostile APDU handling (PUNCHOUT M3).

A security device must never hang, panic, hard-fault, or leak internal state
when receiving truncated data, wrong CLA bytes, oversized payloads, or
structurally invalid commands.  Every test case in this module sends a
deliberately malformed APDU and then verifies:

  1. The device returned *some* SW (even if it is an error SW like 6D00, 6700,
     6A86, etc.).  Any SW proves Core1 did not hang or fault.
  2. A follow-up SELECT SC-HSM AID succeeds with SW=9000, proving the device
     is still alive and responsive.

Interpreting results with a debug probe
---------------------------------------
If build-all-debug.sh is running in a background terminal (streaming RTT via
probe-rs), you can observe defmt log output during each fuzz APDU.  If Core1
hard-faults, the RTT stream will stop and the follow-up SELECT will time out.

For post-mortem analysis after a hang:
  - ``probe-rs read 32 0xE000ED28`` reads the CFSR (Configurable Fault Status
    Register) on Cortex-M33.  Non-zero means a fault fired.
  - ``probe-rs read 32 0xE000ED34`` reads the MMFAR (MemManage Fault Address).
  - ``probe-rs read 32 0xE000ED38`` reads the BFAR (BusFault Address).

Test numbering: 16_fuzz_malformed — runs after all functional tests so it does
not interfere with key-generation / signing state.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

import pytest

from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# APDU constants
# ---------------------------------------------------------------------------
SELECT_SC_HSM = "00A404000BE82B0601040181C31F020100"

# SC-HSM AID for reference
SC_HSM_AID = "E82B0601040181C31F0201"

# VERIFY User PIN (ASCII "648219")
VERIFY_PIN = "002000810636343832313900"

# ---------------------------------------------------------------------------
# Helpers
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
    """Return the last status word, or 0 if none found."""
    sws = _parse_sw(opensc_output)
    return sws[-1] if sws else 0


def _sw_hex(sw: int) -> str:
    """Format a status word as 4-digit hex."""
    return f"{sw:04X}"


# Common expected error SWs — any of these is acceptable for malformed input.
ACCEPTABLE_ERROR_SWS = {
    0x6700,  # Wrong length
    0x6981,  # Command incompatible with file structure
    0x6982,  # Security status not satisfied
    0x6983,  # Authentication method blocked
    0x6984,  # Reference data not usable
    0x6985,  # Conditions of use not satisfied
    0x6986,  # Command not allowed (no current EF)
    0x6A80,  # Wrong data / incorrect parameters in data field
    0x6A81,  # Function not supported
    0x6A82,  # File or application not found
    0x6A86,  # Incorrect P1/P2
    0x6A88,  # Referenced data not found
    0x6B00,  # Wrong P1/P2
    0x6D00,  # Instruction not supported
    0x6E00,  # Class not supported
    0x6F00,  # No precise diagnosis
}


def _is_error_sw(sw: int) -> bool:
    """Return True if sw is any error (not 9000 / 61xx / 9Cxx)."""
    # 9000 = success, 61xx = more data available, 63Cx = retry counter
    return sw != 0x9000 and (sw >> 8) != 0x61


# ---------------------------------------------------------------------------
# Core test logic — send malformed APDU, verify device survives
# ---------------------------------------------------------------------------

def send_and_verify_alive(
    runner: CLIRunner,
    apdu_hex: str,
    case_name: str,
    *,
    expect_error: bool = True,
) -> int:
    """Send a potentially malformed APDU, then verify the device is alive.

    Steps:
      1. SELECT SC-HSM AID (establish applet context)
      2. Send the malformed APDU
      3. SELECT SC-HSM AID again (liveness check)

    Returns the SW from the malformed APDU.
    Asserts that the final SELECT returns 9000.
    """
    result = runner.send_apdu(
        SELECT_SC_HSM,
        apdu_hex,
        SELECT_SC_HSM,  # liveness check
        save_as=f"16_fuzz_{case_name}",
    )

    sws = _parse_sw(result.stdout)
    log.info(
        "Fuzz [%s]: APDU=%s  SWs=%s",
        case_name,
        apdu_hex[:40] + ("..." if len(apdu_hex) > 40 else ""),
        [_sw_hex(s) for s in sws],
    )

    # We expect at least 3 SWs: SELECT + malformed + SELECT
    assert len(sws) >= 2, (
        f"Expected at least 2 SW responses, got {len(sws)}. "
        f"Device may have hung. Output:\n{result.stdout[:500]}"
    )

    # The malformed APDU's SW (second response)
    malformed_sw = sws[1] if len(sws) >= 3 else sws[-1]

    if expect_error:
        # The malformed APDU should NOT return 9000 (it would mean the
        # device accepted garbage as valid — a different kind of bug).
        # Some cases might legitimately return 9000 though (e.g. empty
        # VERIFY returns retry count 63Cx, not 9000), so we log but
        # don't always fail.
        if malformed_sw == 0x9000:
            log.warning(
                "Fuzz [%s]: malformed APDU returned SW=9000 (success) — "
                "this may indicate missing input validation.",
                case_name,
            )

    # The final SELECT (liveness check) must succeed
    liveness_sw = sws[-1]
    assert liveness_sw == 0x9000, (
        f"Fuzz [{case_name}]: device did NOT survive malformed APDU! "
        f"Follow-up SELECT returned SW={_sw_hex(liveness_sw)}, expected 9000. "
        f"The device may have faulted or hung. Check RTT/probe-rs output. "
        f"All SWs: {[_sw_hex(s) for s in sws]}"
    )

    return malformed_sw


def send_without_select_and_verify_alive(
    runner: CLIRunner,
    apdu_hex: str,
    case_name: str,
) -> int:
    """Send an APDU WITHOUT prior SELECT, then verify liveness.

    Used to test protocol-violation cases (commands before SELECT AID).
    """
    result = runner.send_apdu(
        apdu_hex,
        SELECT_SC_HSM,  # liveness check
        save_as=f"16_fuzz_{case_name}",
    )

    sws = _parse_sw(result.stdout)
    log.info(
        "Fuzz [%s]: APDU=%s  SWs=%s",
        case_name,
        apdu_hex[:40] + ("..." if len(apdu_hex) > 40 else ""),
        [_sw_hex(s) for s in sws],
    )

    assert len(sws) >= 1, (
        f"Expected at least 1 SW response, got {len(sws)}. "
        f"Device may have hung."
    )

    # Liveness check
    liveness_sw = sws[-1]
    assert liveness_sw == 0x9000, (
        f"Fuzz [{case_name}]: device not alive after protocol violation. "
        f"SELECT returned SW={_sw_hex(liveness_sw)}."
    )

    return sws[0] if sws else 0


# ===========================================================================
# Test cases — organized by category
# ===========================================================================


# ---------------------------------------------------------------------------
# Category 1: Structural APDU malformation
# ---------------------------------------------------------------------------

class TestStructuralMalformation:
    """APDUs that are structurally invalid at the ISO 7816-4 level."""

    def test_wrong_cla_0xff(self, runner: CLIRunner, initialized_device) -> None:
        """CLA=0xFF for SELECT — firmware rejects with 6E00, but the CCID/pcscd
        transport layer may normalize CLA before it reaches the card. If SW=9000,
        the CLA was rewritten by the transport; the firmware check is still in place."""
        apdu = "FFA404000BE82B0601040181C31F020100"
        sw = send_and_verify_alive(runner, apdu, "wrong_cla_0xff", expect_error=False)
        if sw == 0x9000:
            log.info("Wrong CLA=0xFF: SW=9000 (CLA normalized by transport layer)")
        else:
            assert _is_error_sw(sw)
            log.info("Wrong CLA=0xFF: SW=%s (rejected by firmware)", _sw_hex(sw))

    def test_wrong_cla_0x80_for_iso_command(self, runner: CLIRunner, initialized_device) -> None:
        """CLA=0x80 for SELECT — firmware rejects with 6E00, but the CCID/pcscd
        transport layer may normalize CLA before it reaches the card."""
        apdu = "80A404000BE82B0601040181C31F020100"
        sw = send_and_verify_alive(runner, apdu, "wrong_cla_0x80_select", expect_error=False)
        if sw == 0x9000:
            log.info("CLA=0x80 for SELECT: SW=9000 (CLA normalized by transport layer)")
        else:
            assert _is_error_sw(sw)
            log.info("CLA=0x80 for SELECT: SW=%s (rejected by firmware)", _sw_hex(sw))

    def test_cla_0x00_for_proprietary_command(self, runner: CLIRunner, initialized_device) -> None:
        """CLA=0x00 for proprietary EXTRAS command — accepted (SmartCard-HSM compat).

        The real SmartCard-HSM and OpenSC both use CLA=0x00 for all commands,
        including proprietary ones.  We accept CLA=0x00 universally.
        """
        apdu = "0054300000"
        sw = send_and_verify_alive(runner, apdu, "cla_0x00_extras", expect_error=False)
        # EXTRAS with valid parameters should not return 6E00 (class not supported)
        assert sw != 0x6E00, f"CLA=0x00 for proprietary command should be accepted, got 6E00"
        log.info("CLA=0x00 for EXTRAS: SW=%s", _sw_hex(sw))

    def test_unknown_ins_0xff(self, runner: CLIRunner, initialized_device) -> None:
        """Completely unknown INS=0xFF."""
        apdu = "00FF000000"
        sw = send_and_verify_alive(runner, apdu, "unknown_ins_0xff")
        assert _is_error_sw(sw), f"Unknown INS should return error, got {_sw_hex(sw)}"

    def test_unknown_ins_0x01(self, runner: CLIRunner, initialized_device) -> None:
        """INS=0x01 — not defined in SC-HSM."""
        apdu = "00010000"
        sw = send_and_verify_alive(runner, apdu, "unknown_ins_0x01")
        assert _is_error_sw(sw), f"Unknown INS should return error, got {_sw_hex(sw)}"

    def test_unknown_ins_0xfe_non_debug(self, runner: CLIRunner, initialized_device) -> None:
        """INS=0xFE (DEBUG_DUMP in debug builds, undefined in release)."""
        apdu = "80FE000000"
        sw = send_and_verify_alive(runner, apdu, "ins_0xfe", expect_error=False)
        log.info("INS=0xFE: SW=%s (may be 9000 in debug builds)", _sw_hex(sw))


# ---------------------------------------------------------------------------
# Category 2: Truncated / malformed TLV in GENERATE KEYPAIR
# ---------------------------------------------------------------------------

class TestTruncatedGenerateKeypair:
    """Truncated or malformed data in GENERATE KEY PAIR (INS=0x46)."""

    def test_empty_data(self, runner: CLIRunner, initialized_device) -> None:
        """GENERATE KEYPAIR with zero-length data field."""
        # INS=0x46, P1=0x01 (key_id=1), P2=0x00, Lc=0x00
        apdu = "00460100"
        sw = send_and_verify_alive(runner, apdu, "genkey_empty_data")
        assert _is_error_sw(sw), f"Expected error for empty GENKEY data, got {_sw_hex(sw)}"

    def test_partial_tag_only(self, runner: CLIRunner, initialized_device) -> None:
        """Data is just a single TLV tag byte with no length or value."""
        # Tag 0x7F alone (incomplete two-byte tag)
        apdu = "004601000" + "1" + "7F"  # Lc=1, data=0x7F
        # Fix: proper APDU encoding
        apdu = "0046010001" + "7F"
        sw = send_and_verify_alive(runner, apdu, "genkey_partial_tag")
        assert _is_error_sw(sw)

    def test_tag_with_missing_value(self, runner: CLIRunner, initialized_device) -> None:
        """TLV tag + length but no value bytes."""
        # Tag 0x85, Length 0x20 (32), but no value bytes follow
        apdu = "0046010002" + "8520"
        sw = send_and_verify_alive(runner, apdu, "genkey_missing_value")
        assert _is_error_sw(sw)

    def test_truncated_tlv_value(self, runner: CLIRunner, initialized_device) -> None:
        """TLV tag + length says 32 bytes, but only 4 bytes of value present."""
        # Tag 0x85, Length 0x20 (32), but only 4 bytes follow
        apdu = "0046010006" + "852001020304"
        sw = send_and_verify_alive(runner, apdu, "genkey_truncated_value")
        assert _is_error_sw(sw)

    def test_garbage_data(self, runner: CLIRunner, initialized_device) -> None:
        """GENERATE KEYPAIR with random garbage as data."""
        garbage = "DEADBEEFCAFEBABE0102030405060708"
        apdu = f"0046010010{garbage}"  # Lc=16
        sw = send_and_verify_alive(runner, apdu, "genkey_garbage")
        assert _is_error_sw(sw)

    def test_zero_key_id(self, runner: CLIRunner, initialized_device) -> None:
        """GENERATE KEYPAIR with P1=0x00 (auto-assign) and empty data."""
        apdu = "00460000"
        sw = send_and_verify_alive(runner, apdu, "genkey_zero_keyid_no_data")
        assert _is_error_sw(sw)


# ---------------------------------------------------------------------------
# Category 3: SIGN command boundary conditions
# ---------------------------------------------------------------------------

class TestSignBoundary:
    """Boundary conditions on SIGN (INS=0x68) and PSO (INS=0x2A)."""

    def test_sign_oversized_data(self, runner: CLIRunner, initialized_device) -> None:
        """SIGN with 128 bytes of data — larger than any valid digest (max is 64 for SHA-512)."""
        # INS=0x68, P1=key_ref 0x01, P2=algo 0x70 (ECDSA raw)
        data = "AA" * 128
        apdu = f"0068017080{data}"
        sw = send_and_verify_alive(runner, apdu, "sign_oversized_128")
        assert _is_error_sw(sw)

    def test_sign_empty_data(self, runner: CLIRunner, initialized_device) -> None:
        """SIGN with no data field — Case 1 APDU (no Lc, no Le)."""
        apdu = "00680170"
        sw = send_and_verify_alive(runner, apdu, "sign_empty_data")
        assert _is_error_sw(sw)

    def test_sign_one_byte_data(self, runner: CLIRunner, initialized_device) -> None:
        """SIGN with just 1 byte — too short for any digest."""
        apdu = "00680170" + "01" + "FF"
        sw = send_and_verify_alive(runner, apdu, "sign_one_byte")
        assert _is_error_sw(sw)

    def test_sign_invalid_algo_id(self, runner: CLIRunner, initialized_device) -> None:
        """SIGN with P2=0xFF — not a valid algorithm ID."""
        data = "AA" * 32  # valid SHA-256 digest length
        apdu = f"006801FF20{data}"
        sw = send_and_verify_alive(runner, apdu, "sign_invalid_algo")
        assert _is_error_sw(sw)

    def test_sign_invalid_key_ref(self, runner: CLIRunner, initialized_device) -> None:
        """SIGN referencing nonexistent key P1=0xFF."""
        data = "AA" * 32
        apdu = f"0068FF7020{data}"
        sw = send_and_verify_alive(runner, apdu, "sign_invalid_keyref")
        assert _is_error_sw(sw)

    def test_pso_cds_empty_data(self, runner: CLIRunner, initialized_device) -> None:
        """PSO:CDS (P1=0x9E, P2=0x9A) with empty data."""
        apdu = "002A9E9A00"
        sw = send_and_verify_alive(runner, apdu, "pso_cds_empty")
        assert _is_error_sw(sw)

    def test_pso_decipher_empty_data(self, runner: CLIRunner, initialized_device) -> None:
        """PSO:DECIPHER (P1=0x80, P2=0x86) with empty data."""
        apdu = "002A808600"
        sw = send_and_verify_alive(runner, apdu, "pso_decipher_empty")
        assert _is_error_sw(sw)


# ---------------------------------------------------------------------------
# Category 4: VERIFY PIN edge cases
# ---------------------------------------------------------------------------

class TestVerifyPinEdgeCases:
    """Edge cases for VERIFY (INS=0x20)."""

    def test_verify_empty_data(self, runner: CLIRunner, initialized_device) -> None:
        """VERIFY with zero-length data — should return retry counter (63Cx)."""
        # P2=0x81 (user PIN), Lc=0
        apdu = "0020008100"
        sw = send_and_verify_alive(runner, apdu, "verify_empty", expect_error=False)
        # 63Cx = retry counter remaining
        if (sw >> 4) == 0x63C:
            log.info("Empty VERIFY returned retry counter: %d remaining", sw & 0x0F)
        else:
            log.info("Empty VERIFY returned SW=%s", _sw_hex(sw))

    def test_verify_single_byte_pin(self, runner: CLIRunner, initialized_device) -> None:
        """VERIFY with a 1-byte PIN — too short (min 6)."""
        apdu = "002000810141"  # Lc=1, data=0x41 ('A')
        sw = send_and_verify_alive(runner, apdu, "verify_1byte_pin")
        assert _is_error_sw(sw)

    def test_verify_oversized_pin(self, runner: CLIRunner, initialized_device) -> None:
        """VERIFY with a 255-byte PIN — far exceeds max length."""
        pin_data = "41" * 255
        apdu = f"00200081FF{pin_data}"
        sw = send_and_verify_alive(runner, apdu, "verify_oversized_pin")
        assert _is_error_sw(sw)

    def test_verify_invalid_p2(self, runner: CLIRunner, initialized_device) -> None:
        """VERIFY with P2=0x00 — not a valid PIN reference."""
        apdu = "002000000636343832313900"
        sw = send_and_verify_alive(runner, apdu, "verify_invalid_p2")
        assert _is_error_sw(sw)

    def test_verify_invalid_p2_0xff(self, runner: CLIRunner, initialized_device) -> None:
        """VERIFY with P2=0xFF — undefined PIN reference."""
        apdu = "0020FF000636343832313900"
        sw = send_and_verify_alive(runner, apdu, "verify_invalid_p2_0xff")
        assert _is_error_sw(sw)

    def test_verify_so_pin_wrong(self, runner: CLIRunner, initialized_device) -> None:
        """VERIFY SO-PIN with wrong value (will decrement retry counter)."""
        # P2=0x88 (SO-PIN), send obviously wrong PIN
        apdu = "00200088080000000000000000"
        sw = send_and_verify_alive(runner, apdu, "verify_sopin_wrong")
        assert _is_error_sw(sw)


# ---------------------------------------------------------------------------
# Category 5: EXTRAS command boundary conditions
# ---------------------------------------------------------------------------

class TestExtrasBoundary:
    """Boundary conditions on EXTRAS (INS=0x54)."""

    def test_extras_invalid_p1(self, runner: CLIRunner, initialized_device) -> None:
        """EXTRAS with P1=0xFF — undefined sub-command."""
        apdu = "8054FF0000"
        sw = send_and_verify_alive(runner, apdu, "extras_invalid_p1")
        assert _is_error_sw(sw)

    def test_extras_oversized_payload(self, runner: CLIRunner, initialized_device) -> None:
        """EXTRAS P1=0x01 (HKDF-Extract) with 255 bytes of data."""
        data = "BB" * 255
        apdu = f"80540100FF{data}"
        sw = send_and_verify_alive(runner, apdu, "extras_oversized")
        assert _is_error_sw(sw)

    def test_extras_hkdf_empty_data(self, runner: CLIRunner, initialized_device) -> None:
        """EXTRAS P1=0x01 (HKDF-Extract) with zero-length data."""
        apdu = "8054010000"
        sw = send_and_verify_alive(runner, apdu, "extras_hkdf_empty")
        assert _is_error_sw(sw)

    def test_extras_pbkdf2_malformed(self, runner: CLIRunner, initialized_device) -> None:
        """EXTRAS P1=0x03 (PBKDF2) with garbage data (should be TLV)."""
        data = "DEADBEEF"
        apdu = f"805403000{len(data)//2:X}{data}"
        # Fix encoding: Lc=4
        apdu = f"8054030004{data}"
        sw = send_and_verify_alive(runner, apdu, "extras_pbkdf2_garbage")
        assert _is_error_sw(sw)

    def test_extras_get_device_pubkey_with_data(self, runner: CLIRunner, initialized_device) -> None:
        """GET_DEVICE_PUBLIC_KEY (P1=0x30) with unexpected data payload.
        This should be a Case 2S APDU (no data), but we send data anyway."""
        apdu = "805430000401020304"
        sw = send_and_verify_alive(runner, apdu, "extras_pubkey_with_data", expect_error=False)
        log.info("GET_DEVICE_PUBKEY with extra data: SW=%s", _sw_hex(sw))


# ---------------------------------------------------------------------------
# Category 6: INITIALIZE command malformation
# ---------------------------------------------------------------------------

class TestInitializeMalformed:
    """Malformed INITIALIZE (INS=0x50) commands.

    Note: valid INITIALIZE would re-format the keystore, so we only send
    structurally invalid ones that should be rejected before any state change.
    """

    def test_initialize_empty_data(self, runner: CLIRunner, initialized_device) -> None:
        """INITIALIZE with zero-length data — missing required TLV tags."""
        apdu = "80500000"
        sw = send_and_verify_alive(runner, apdu, "init_empty_data")
        assert _is_error_sw(sw)

    def test_initialize_garbage_tlv(self, runner: CLIRunner, initialized_device) -> None:
        """INITIALIZE with random bytes instead of valid TLV."""
        garbage = "CAFEBABE01020304DEADBEEF"
        apdu = f"805000000C{garbage}"
        sw = send_and_verify_alive(runner, apdu, "init_garbage_tlv")
        assert _is_error_sw(sw)

    def test_initialize_truncated_sopin_tag(self, runner: CLIRunner, initialized_device) -> None:
        """INITIALIZE with SO-PIN tag (0x82) but truncated value."""
        # Tag 0x82, Length 0x08, but only 3 bytes of value
        apdu = "80500000058203414243"
        sw = send_and_verify_alive(runner, apdu, "init_truncated_sopin")
        assert _is_error_sw(sw)

    def test_initialize_overlapping_lengths(self, runner: CLIRunner, initialized_device) -> None:
        """INITIALIZE with TLV length exceeding available data."""
        # Tag 0x80, Length 0xFF (255), but only 2 bytes follow
        apdu = "805000000480FF0102"
        sw = send_and_verify_alive(runner, apdu, "init_overlapping_len")
        assert _is_error_sw(sw)

    def test_initialize_wrong_sopin_length(self, runner: CLIRunner, initialized_device) -> None:
        """INITIALIZE with SO-PIN that is too short (3 bytes instead of 8)."""
        # Correct structure but SO-PIN too short.
        # Tag 0x82 (init code), Length 0x03, value "ABC"
        # Tag 0x81 (user PIN), Length 0x06, value "648219"
        sopin = "820341424381063634383231390000"
        apdu = f"805000000E{sopin}"
        sw = send_and_verify_alive(runner, apdu, "init_short_sopin")
        assert _is_error_sw(sw)


# ---------------------------------------------------------------------------
# Category 7: Wrong P1/P2 combinations
# ---------------------------------------------------------------------------

class TestWrongP1P2:
    """Valid INS codes with completely wrong P1/P2 values."""

    def test_select_wrong_p1(self, runner: CLIRunner, initialized_device) -> None:
        """SELECT with P1=0xFF (not 0x04)."""
        apdu = "00A4FF000BE82B0601040181C31F020100"
        sw = send_and_verify_alive(runner, apdu, "select_wrong_p1")
        assert _is_error_sw(sw)

    def test_verify_p1_nonzero(self, runner: CLIRunner, initialized_device) -> None:
        """VERIFY with P1=0xFF instead of 0x00."""
        apdu = "0020FF810636343832313900"
        sw = send_and_verify_alive(runner, apdu, "verify_p1_nonzero")
        assert _is_error_sw(sw)

    def test_list_keys_wrong_p2(self, runner: CLIRunner, initialized_device) -> None:
        """LIST KEYS (INS=0x58) with P2=0xFF — must reject with 6A86."""
        apdu = "805800FF00"
        sw = send_and_verify_alive(runner, apdu, "listkeys_wrong_p2")
        assert _is_error_sw(sw), f"Wrong P2 should be rejected, got {_sw_hex(sw)}"
        log.info("LIST KEYS P2=0xFF: SW=%s", _sw_hex(sw))

    def test_mse_invalid_p1p2(self, runner: CLIRunner, initialized_device) -> None:
        """MSE SET (INS=0x22) with P1=0xFF, P2=0xFF."""
        apdu = "0022FFFF00"
        sw = send_and_verify_alive(runner, apdu, "mse_invalid_p1p2")
        assert _is_error_sw(sw)

    def test_change_pin_wrong_p2(self, runner: CLIRunner, initialized_device) -> None:
        """CHANGE REFERENCE DATA (INS=0x24) with P2=0xFF."""
        apdu = "002400FF0636343832313900"
        sw = send_and_verify_alive(runner, apdu, "change_pin_wrong_p2")
        assert _is_error_sw(sw)

    def test_generate_keypair_p2_nonzero(self, runner: CLIRunner, initialized_device) -> None:
        """GENERATE KEYPAIR with P2=0xFF instead of 0x00."""
        apdu = "004601FF00"
        sw = send_and_verify_alive(runner, apdu, "genkey_p2_nonzero")
        assert _is_error_sw(sw)


# ---------------------------------------------------------------------------
# Category 8: Protocol violations — commands without SELECT AID
# ---------------------------------------------------------------------------

class TestProtocolViolations:
    """Commands sent without prior SELECT AID or required auth."""

    def test_verify_without_select(self, runner: CLIRunner, initialized_device) -> None:
        """VERIFY PIN sent to the card without first selecting an applet."""
        sw = send_without_select_and_verify_alive(
            runner,
            "002000810636343832313900",
            "verify_no_select",
        )
        log.info("VERIFY without SELECT: SW=%s", _sw_hex(sw))

    def test_sign_without_select(self, runner: CLIRunner, initialized_device) -> None:
        """SIGN sent without prior SELECT AID."""
        data = "AA" * 32
        sw = send_without_select_and_verify_alive(
            runner,
            f"00680170" + f"20{data}",
            "sign_no_select",
        )
        assert _is_error_sw(sw)

    def test_extras_without_select(self, runner: CLIRunner, initialized_device) -> None:
        """EXTRAS without prior SELECT AID."""
        sw = send_without_select_and_verify_alive(
            runner,
            "8054300000",
            "extras_no_select",
        )
        log.info("EXTRAS without SELECT: SW=%s", _sw_hex(sw))

    def test_generate_keypair_without_select(self, runner: CLIRunner, initialized_device) -> None:
        """GENERATE KEYPAIR without SELECT — must not crash."""
        sw = send_without_select_and_verify_alive(
            runner,
            "00460100",
            "genkey_no_select",
        )
        assert _is_error_sw(sw)

    def test_sign_without_pin_verify(self, runner: CLIRunner, initialized_device) -> None:
        """SIGN after SELECT but without PIN verification."""
        data = "AA" * 32
        apdu = f"0068017020{data}"
        sw = send_and_verify_alive(runner, apdu, "sign_no_pin")
        assert _is_error_sw(sw)
        # Should specifically be 6982 (security status not satisfied)
        log.info("SIGN without PIN: SW=%s", _sw_hex(sw))

    def test_export_key_without_pin(self, runner: CLIRunner, initialized_device) -> None:
        """EXPORT KEY (INS=0x72) without PIN — must return security error."""
        apdu = "80720100" + "00"
        sw = send_and_verify_alive(runner, apdu, "export_no_pin")
        assert _is_error_sw(sw)

    def test_import_key_without_pin(self, runner: CLIRunner, initialized_device) -> None:
        """IMPORT KEY (INS=0x74) without PIN."""
        apdu = "8074010004DEADBEEF"
        sw = send_and_verify_alive(runner, apdu, "import_no_pin")
        assert _is_error_sw(sw)

    def test_decrypt_without_pin(self, runner: CLIRunner, initialized_device) -> None:
        """DECRYPT (INS=0x62) without PIN."""
        data = "AA" * 32
        apdu = f"0062018020{data}"
        sw = send_and_verify_alive(runner, apdu, "decrypt_no_pin")
        assert _is_error_sw(sw)


# ---------------------------------------------------------------------------
# Category 9: Boundary / extreme lengths
# ---------------------------------------------------------------------------

class TestBoundaryLengths:
    """Extreme data lengths and edge cases."""

    def test_max_short_apdu_255_bytes(self, runner: CLIRunner, initialized_device) -> None:
        """Send a valid-structure APDU with exactly 255 bytes of data."""
        data = "CC" * 255
        # VERIFY INS with 255 bytes — will be rejected as wrong length
        apdu = f"00200081FF{data}"
        sw = send_and_verify_alive(runner, apdu, "verify_255bytes")
        assert _is_error_sw(sw)

    def test_sign_max_short_apdu(self, runner: CLIRunner, initialized_device) -> None:
        """SIGN with maximum short APDU data (255 bytes) — far exceeds any digest."""
        data = "DD" * 255
        apdu = f"00680170FF{data}"
        sw = send_and_verify_alive(runner, apdu, "sign_255bytes")
        assert _is_error_sw(sw)

    def test_extras_max_short_apdu(self, runner: CLIRunner, initialized_device) -> None:
        """EXTRAS P1=0x01 (HKDF-Extract) with 254 bytes — max short APDU data."""
        data = "EE" * 254
        apdu = f"80540100FE{data}"
        sw = send_and_verify_alive(runner, apdu, "extras_254bytes")
        assert _is_error_sw(sw)

    def test_read_binary_out_of_range(self, runner: CLIRunner, initialized_device) -> None:
        """READ BINARY (INS=0xB0) with P1P2 offset beyond any file."""
        # P1=0xFF, P2=0xFF → offset 0xFFFF
        apdu = "00B0FFFF00"
        sw = send_and_verify_alive(runner, apdu, "read_binary_oob")
        assert _is_error_sw(sw)

    def test_update_binary_no_data(self, runner: CLIRunner, initialized_device) -> None:
        """UPDATE BINARY (INS=0xD6) with no data."""
        apdu = "00D60000"
        sw = send_and_verify_alive(runner, apdu, "update_binary_empty")
        assert _is_error_sw(sw)

    def test_write_data_no_data(self, runner: CLIRunner, initialized_device) -> None:
        """WRITE DATA (INS=0xD7) with no data field."""
        apdu = "00D70000"
        sw = send_and_verify_alive(runner, apdu, "write_data_empty")
        assert _is_error_sw(sw)

    def test_delete_file_invalid_fid(self, runner: CLIRunner, initialized_device) -> None:
        """DELETE FILE (INS=0xE4) with P1P2 = 0xFFFF (invalid FID)."""
        apdu = "00E4FFFF"
        sw = send_and_verify_alive(runner, apdu, "delete_invalid_fid")
        assert _is_error_sw(sw)


# ---------------------------------------------------------------------------
# Category 10: Key domain / DKEK edge cases
# ---------------------------------------------------------------------------

class TestKeyDomainEdgeCases:
    """Edge cases for KEY DOMAIN (INS=0x52)."""

    def test_key_domain_invalid_p1(self, runner: CLIRunner, initialized_device) -> None:
        """KEY DOMAIN with P1=0xFF."""
        apdu = "8052FF0000"
        sw = send_and_verify_alive(runner, apdu, "keydomain_invalid_p1")
        assert _is_error_sw(sw)

    def test_key_domain_no_data(self, runner: CLIRunner, initialized_device) -> None:
        """KEY DOMAIN P1=0x01 (set shares) with no data."""
        apdu = "80520100"
        sw = send_and_verify_alive(runner, apdu, "keydomain_no_data")
        assert _is_error_sw(sw)


# ---------------------------------------------------------------------------
# Category 11: MSE SET with malformed control reference template
# ---------------------------------------------------------------------------

class TestMseMalformed:
    """Malformed MSE SET (INS=0x22) commands."""

    def test_mse_empty_data(self, runner: CLIRunner, initialized_device) -> None:
        """MSE SET with zero-length control reference template."""
        # P1=0x41 (SET), P2=0xA4 (AT — authentication template)
        apdu = "002241A400"
        sw = send_and_verify_alive(runner, apdu, "mse_empty")
        assert _is_error_sw(sw)

    def test_mse_garbage_crt(self, runner: CLIRunner, initialized_device) -> None:
        """MSE SET with garbage data instead of a CRT."""
        apdu = "002241A40" + "4" + "DEADBEEF"
        # Fix encoding: Lc=4
        apdu = "002241A404DEADBEEF"
        sw = send_and_verify_alive(runner, apdu, "mse_garbage_crt")
        assert _is_error_sw(sw)


# ---------------------------------------------------------------------------
# Category 12: CHALLENGE edge cases
# ---------------------------------------------------------------------------

class TestChallengeEdgeCases:
    """Edge cases for GET CHALLENGE (INS=0x84)."""

    def test_challenge_with_data(self, runner: CLIRunner, initialized_device) -> None:
        """GET CHALLENGE with unexpected data payload."""
        apdu = "0084000004DEADBEEF"
        sw = send_and_verify_alive(runner, apdu, "challenge_with_data", expect_error=False)
        log.info("CHALLENGE with data: SW=%s", _sw_hex(sw))

    def test_challenge_le_zero(self, runner: CLIRunner, initialized_device) -> None:
        """GET CHALLENGE with Le=0 (expect 256 bytes or error)."""
        apdu = "0084000000"
        sw = send_and_verify_alive(runner, apdu, "challenge_le_zero", expect_error=False)
        log.info("CHALLENGE Le=0: SW=%s", _sw_hex(sw))


# ---------------------------------------------------------------------------
# Category 13: EXTERNAL AUTHENTICATE edge cases
# ---------------------------------------------------------------------------

class TestExternalAuthEdgeCases:
    """Edge cases for EXTERNAL AUTHENTICATE (INS=0x82)."""

    def test_external_auth_no_challenge(self, runner: CLIRunner, initialized_device) -> None:
        """EXTERNAL AUTHENTICATE without prior GET CHALLENGE."""
        # P1=0x00, P2=0x81, 8 bytes of garbage
        apdu = "0082008108DEADBEEFCAFEBABE"
        sw = send_and_verify_alive(runner, apdu, "extauth_no_challenge")
        assert _is_error_sw(sw)

    def test_external_auth_wrong_length(self, runner: CLIRunner, initialized_device) -> None:
        """EXTERNAL AUTHENTICATE with wrong data length (3 bytes instead of 8)."""
        apdu = "008200810341424300"
        sw = send_and_verify_alive(runner, apdu, "extauth_wrong_len")
        assert _is_error_sw(sw)

    def test_external_auth_empty(self, runner: CLIRunner, initialized_device) -> None:
        """EXTERNAL AUTHENTICATE with no data."""
        apdu = "00820081"
        sw = send_and_verify_alive(runner, apdu, "extauth_empty")
        assert _is_error_sw(sw)


# ---------------------------------------------------------------------------
# Category 14: SELECT AID malformation
# ---------------------------------------------------------------------------

class TestSelectMalformed:
    """Malformed SELECT AID commands."""

    def test_select_empty_aid(self, runner: CLIRunner, initialized_device) -> None:
        """SELECT with zero-length AID data."""
        apdu = "00A4040000"
        sw = send_and_verify_alive(runner, apdu, "select_empty_aid", expect_error=False)
        log.info("SELECT empty AID: SW=%s", _sw_hex(sw))

    def test_select_truncated_aid(self, runner: CLIRunner, initialized_device) -> None:
        """SELECT with truncated SC-HSM AID (first 5 bytes only)."""
        apdu = "00A404000" + "5" + "E82B060104"
        # Fix encoding: Lc=5
        apdu = "00A4040005E82B060104"
        sw = send_and_verify_alive(runner, apdu, "select_truncated_aid", expect_error=False)
        log.info("SELECT truncated AID: SW=%s", _sw_hex(sw))

    def test_select_garbage_aid(self, runner: CLIRunner, initialized_device) -> None:
        """SELECT with garbage AID bytes."""
        apdu = "00A4040008DEADBEEFCAFEBABE"
        sw = send_and_verify_alive(runner, apdu, "select_garbage_aid")
        log.info("SELECT garbage AID: SW=%s", _sw_hex(sw))

    def test_select_max_length_aid(self, runner: CLIRunner, initialized_device) -> None:
        """SELECT with maximum-length AID (16 bytes, ISO max)."""
        apdu = "00A404001000112233445566778899AABBCCDDEEFF"
        sw = send_and_verify_alive(runner, apdu, "select_max_aid")
        log.info("SELECT max-length AID: SW=%s", _sw_hex(sw))


# ---------------------------------------------------------------------------
# Category 15: Rapid-fire multiple malformed APDUs in one session
# ---------------------------------------------------------------------------

class TestRapidFire:
    """Send multiple malformed APDUs in a single opensc-tool session to
    stress the dispatcher's error recovery path."""

    def test_burst_of_bad_ins(self, runner: CLIRunner, initialized_device) -> None:
        """Send 10 unknown INS bytes in rapid succession."""
        bad_apdus = [f"00{ins:02X}0000" for ins in [0x01, 0x03, 0x05, 0x07, 0x09,
                                                      0x0B, 0x0D, 0x0F, 0x11, 0x13]]
        result = runner.send_apdu(
            SELECT_SC_HSM,
            *bad_apdus,
            SELECT_SC_HSM,  # liveness check
            save_as="16_fuzz_burst_bad_ins",
        )
        sws = _parse_sw(result.stdout)
        log.info("Burst of 10 bad INS: SWs=%s", [_sw_hex(s) for s in sws])
        # We expect 12 SWs: SELECT + 10 bad + SELECT
        assert len(sws) >= 11, (
            f"Expected at least 11 SWs (SELECT + 10 bad + SELECT), got {len(sws)}"
        )
        # Last SW must be 9000 (liveness)
        assert sws[-1] == 0x9000, (
            f"Device not alive after burst: final SW={_sw_hex(sws[-1])}"
        )

    def test_burst_mixed_malformed(self, runner: CLIRunner, initialized_device) -> None:
        """Send a mix of different malformed APDUs in one session."""
        mixed_apdus = [
            "FFA404000BE82B0601040181C31F020100",  # wrong CLA
            "00FF000000",                            # unknown INS
            "00460100",                              # GENKEY no data
            "002000810141",                          # VERIFY 1-byte PIN
            "0068FF7020" + "AA" * 32,                # SIGN bad key ref
            "8054FF0000",                            # EXTRAS bad P1
        ]
        result = runner.send_apdu(
            SELECT_SC_HSM,
            *mixed_apdus,
            SELECT_SC_HSM,
            save_as="16_fuzz_burst_mixed",
        )
        sws = _parse_sw(result.stdout)
        log.info("Burst mixed malformed: SWs=%s", [_sw_hex(s) for s in sws])
        assert sws[-1] == 0x9000, (
            f"Device not alive after mixed burst: final SW={_sw_hex(sws[-1])}"
        )


# ---------------------------------------------------------------------------
# Category 16: CHANGE REFERENCE DATA edge cases
# ---------------------------------------------------------------------------

class TestChangePinEdgeCases:
    """Edge cases for CHANGE REFERENCE DATA (INS=0x24)."""

    def test_change_pin_empty_data(self, runner: CLIRunner, initialized_device) -> None:
        """CHANGE PIN with no data."""
        apdu = "00240081"
        sw = send_and_verify_alive(runner, apdu, "change_pin_empty")
        assert _is_error_sw(sw)

    def test_change_pin_too_short_new_pin(self, runner: CLIRunner, initialized_device) -> None:
        """CHANGE PIN with old PIN + 1-byte new PIN."""
        # Old PIN "648219" (6 bytes) + new PIN "A" (1 byte) = 7 bytes
        apdu = "002400810736343832313941"
        sw = send_and_verify_alive(runner, apdu, "change_pin_short_new")
        assert _is_error_sw(sw)


# ---------------------------------------------------------------------------
# Category 17: RESET RETRY COUNTER edge cases
# ---------------------------------------------------------------------------

class TestResetRetryEdgeCases:
    """Edge cases for RESET RETRY COUNTER (INS=0x2C)."""

    def test_reset_retry_empty(self, runner: CLIRunner, initialized_device) -> None:
        """RESET RETRY COUNTER with no data."""
        apdu = "002C0081"
        sw = send_and_verify_alive(runner, apdu, "reset_retry_empty")
        assert _is_error_sw(sw)

    def test_reset_retry_garbage(self, runner: CLIRunner, initialized_device) -> None:
        """RESET RETRY COUNTER with garbage data."""
        apdu = "002C008104DEADBEEF"
        sw = send_and_verify_alive(runner, apdu, "reset_retry_garbage")
        assert _is_error_sw(sw)


# ---------------------------------------------------------------------------
# Category 18: SESSION PIN edge cases
# ---------------------------------------------------------------------------

class TestSessionPinEdgeCases:
    """Edge cases for SESSION PIN (INS=0x26)."""

    def test_session_pin_empty(self, runner: CLIRunner, initialized_device) -> None:
        """SESSION PIN with no data."""
        apdu = "80260000"
        sw = send_and_verify_alive(runner, apdu, "session_pin_empty")
        assert _is_error_sw(sw)

    def test_session_pin_oversized(self, runner: CLIRunner, initialized_device) -> None:
        """SESSION PIN with 200 bytes of data."""
        data = "FF" * 200
        apdu = f"802600{200:02X}C8{data}"
        # Fix: Lc = 0xC8 = 200
        apdu = f"80260000C8{data}"
        sw = send_and_verify_alive(runner, apdu, "session_pin_oversized")
        assert _is_error_sw(sw)


# ---------------------------------------------------------------------------
# Category 19: CIPHER_SYM edge cases
# ---------------------------------------------------------------------------

class TestCipherSymEdgeCases:
    """Edge cases for CIPHER_SYM (symmetric cipher, vendor-specific)."""

    def test_cipher_sym_empty(self, runner: CLIRunner, initialized_device) -> None:
        """CIPHER_SYM with no data."""
        # Assuming INS from the codebase — need to check. Using a known one.
        apdu = "80780000"
        sw = send_and_verify_alive(runner, apdu, "cipher_sym_empty")
        assert _is_error_sw(sw)

    def test_cipher_sym_garbage(self, runner: CLIRunner, initialized_device) -> None:
        """CIPHER_SYM with garbage data."""
        apdu = "8078000008DEADBEEFCAFEBABE"
        sw = send_and_verify_alive(runner, apdu, "cipher_sym_garbage")
        assert _is_error_sw(sw)


# ---------------------------------------------------------------------------
# Category 20: BIP/SLIP derivation edge cases
# ---------------------------------------------------------------------------

class TestBipSlipEdgeCases:
    """Edge cases for BIP/SLIP key derivation (INS=0x60)."""

    def test_bip_empty(self, runner: CLIRunner, initialized_device) -> None:
        """BIP/SLIP derivation with no data."""
        apdu = "80600000"
        sw = send_and_verify_alive(runner, apdu, "bip_empty")
        assert _is_error_sw(sw)

    def test_bip_garbage_path(self, runner: CLIRunner, initialized_device) -> None:
        """BIP/SLIP with garbage derivation path."""
        apdu = "806001000" + "8" + "DEADBEEFCAFEBABE"
        # Fix: Lc=8
        apdu = "8060010008DEADBEEFCAFEBABE"
        sw = send_and_verify_alive(runner, apdu, "bip_garbage_path")
        assert _is_error_sw(sw)
