"""Tests for OpenPGP Card GENERATE KEY PAIR (INS=0x47) on the SIG slot.

The SIG slot is identified by the Control Reference Template tag B6.
By default, newly-manufactured cards use RSA 2048-bit keys.  pico2hsm
targets NIST P-256 for the SIG slot in its initial OpenPGP implementation.

GENERATE KEY PAIR APDU:
    00 47 80 00 02 B6 00 00   — generate new key in SIG slot
    00 47 81 00 02 B6 00      — read existing public key from SIG slot

Response (for EC keys):
    7F 49 [len]
      86 [len] <uncompressed EC point: 04 X Y>   — public key point
      (optionally 9F 2C [len] <supported algorithms> — curve OID etc.)

After key generation, `gpg --card-status` should show a non-empty key
fingerprint in the "Signature key" line.

"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
    SECP256R1,
)

from helpers import trace, sw_from_output, last_response_hex
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# OpenPGP AID prefix
OPENPGP_AID_PREFIX = "D27600012401"
_SELECT_OPENPGP = "00A404000 6" + OPENPGP_AID_PREFIX + "00"
_SELECT_OPENPGP_CLEAN = ("00A40400 06" + OPENPGP_AID_PREFIX + "00").replace(" ", "")

# Default PW3 (admin) PIN
_PW3_DEFAULT = "3132333435363738"   # "12345678"
_VERIFY_PW3  = f"002000830 8{_PW3_DEFAULT}".replace(" ", "")
# Algorithm attributes persist on the card (as on a real OpenPGP card), so
# an earlier test (e.g. curve25519) may have left Ed25519/X25519 set:
# put P-256 back explicitly before generating.  Needs PW3.
_P256_OID = "2A8648CE3D030107"
_SET_P256_ATTRS = (
    f"00DA00C1 09 13{_P256_OID}".replace(" ", ""),  # SIG: ECDSA P-256
    f"00DA00C2 09 12{_P256_OID}".replace(" ", ""),  # DEC: ECDH P-256
    f"00DA00C3 09 13{_P256_OID}".replace(" ", ""),  # AUTH: ECDSA P-256
)

# GENERATE KEY PAIR — SIG slot (B6):
#   00 47 80 00 02 B6 00 00  — generate new key
#   00 47 81 00 02 B6 00     — read public key (no generation)
_GENKEY_SIG   = "00478000 02B60000".replace(" ", "")
_READ_PUB_SIG = "0047810002B600".replace(" ", "")



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _send_apdus(runner: CLIRunner, *apdus: str, save_as: str | None = None, timeout: int = 120):
    args = ["opensc-tool"]
    for apdu in apdus:
        args.extend(["--send-apdu", apdu.replace(" ", "")])
    return runner.run(args, save_as=save_as, timeout=timeout)


def _sw_from_output(output: str) -> str | None:
    return sw_from_output(output)


def _decode_length(data: bytes, idx: int) -> tuple[int, int]:
    if idx >= len(data):
        return 0, 1
    first = data[idx]
    if first < 0x80:
        return first, 1
    elif first == 0x81:
        return data[idx + 1], 2
    elif first == 0x82:
        return int.from_bytes(data[idx + 1:idx + 3], "big"), 3
    return 0, 1


def _extract_ec_point_from_7f49(resp_hex: str) -> bytes | None:
    """Parse the 7F49 Public Key template and return the raw EC point (tag 86).

    Handles:
        7F 49 [len]
          86 [len] <uncompressed EC point>

    Returns the point bytes (including leading 0x04), or None.
    """
    data = bytes.fromhex(resp_hex.replace(" ", ""))
    i = 0
    while i < len(data) - 1:
        if data[i] == 0x7F and data[i + 1] == 0x49:
            i += 2
            inner_len, consumed = _decode_length(data, i)
            i += consumed
            inner = data[i:i + inner_len]
            j = 0
            while j < len(inner):
                tag = inner[j]
                point_len, pconsumed = _decode_length(inner, j + 1)
                if tag == 0x86:
                    return inner[j + 1 + pconsumed:j + 1 + pconsumed + point_len]
                j += 1 + pconsumed + point_len
        i += 1
    return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_openpgp_genkey_sig_succeeds(runner: CLIRunner, run_dir: Path) -> None:
    """GENERATE KEY PAIR for the SIG slot (B6) must return SW=9000."""
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN,
        _VERIFY_PW3,
        *_SET_P256_ATTRS,
        _GENKEY_SIG,
        save_as="openpgp_02_genkey_sig",
        timeout=120,
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / "openpgp_02_genkey_sig.json",
        "openpgp_genkey_sig",
        result,
        exchanges,
    )
    log.info(
        "OpenPGP GENKEY SIG: rc=%d  elapsed=%.0f ms  APDUs=%d",
        result.returncode, result.elapsed_ms, len(exchanges),
    )

    assert result.returncode == 0, (
        f"opensc-tool failed (rc={result.returncode}):\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("GENKEY SIG SW: %s", sw)
    assert sw == "9000", (
        f"Expected SW=9000 from GENERATE KEY PAIR; got SW={sw!r}."
    )


def test_openpgp_genkey_sig_returns_7f49_tlv(runner: CLIRunner) -> None:
    """GENERATE KEY PAIR response must contain a 7F49 Public Key template."""
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN,
        _VERIFY_PW3,
        *_SET_P256_ATTRS,
        _GENKEY_SIG,
        timeout=120,
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    if sw != "9000":
        pytest.skip(f"GENKEY returned SW={sw!r}; cannot inspect TLV.")

    resp_hex = last_response_hex(result.stdout)
    log.info("GENKEY SIG raw response: %s", resp_hex[:80])

    assert resp_hex, "No response data from GENERATE KEY PAIR."
    assert "7F49" in resp_hex.upper() or "7f49" in resp_hex, (
        f"Expected 7F49 (Public Key template) in GENKEY response; got: {resp_hex[:40]!r}"
    )

    ec_point = _extract_ec_point_from_7f49(resp_hex)
    assert ec_point is not None, (
        f"Could not extract EC point from 7F49 template.\nRaw: {resp_hex[:80]}"
    )
    log.info("Extracted EC point: %d bytes", len(ec_point))


def test_openpgp_genkey_sig_public_key_is_valid_p256(runner: CLIRunner) -> None:
    """The SIG slot public key must be a valid uncompressed P-256 point."""
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP_CLEAN,
        _VERIFY_PW3,
        *_SET_P256_ATTRS,
        _GENKEY_SIG,
        timeout=120,
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    if sw != "9000":
        pytest.skip(f"GENKEY returned SW={sw!r}.")

    resp_hex = last_response_hex(result.stdout)
    ec_point = _extract_ec_point_from_7f49(resp_hex)
    if ec_point is None:
        pytest.skip("Could not extract EC point from GENKEY response.")

    # P-256 uncompressed point: 04 || X (32 bytes) || Y (32 bytes) = 65 bytes
    assert len(ec_point) == 65 and ec_point[0] == 0x04, (
        f"Expected 65-byte uncompressed P-256 point; "
        f"got {len(ec_point)} bytes starting with {ec_point[0]:02X}."
    )

    x = int.from_bytes(ec_point[1:33], "big")
    y = int.from_bytes(ec_point[33:65], "big")
    pub_numbers = EllipticCurvePublicNumbers(x=x, y=y, curve=SECP256R1())
    try:
        pub_key = pub_numbers.public_key(backend=default_backend())
    except Exception as exc:
        pytest.fail(
            f"EC point is not on P-256: {exc}\nPoint: {ec_point.hex()}"
        )

    assert isinstance(pub_key, EllipticCurvePublicKey)
    assert type(pub_key.curve).__name__ == "SECP256R1"
    log.info("P-256 SIG public key validated: x=%064x", x)


def test_openpgp_read_pubkey_sig_after_genkey(runner: CLIRunner) -> None:
    """READ PUBLIC KEY (P1=0x81) for SIG slot must return the same key as GENKEY."""
    # Generate key and capture the point
    result_gen = _send_apdus(
        runner, _SELECT_OPENPGP_CLEAN, _VERIFY_PW3,
        *_SET_P256_ATTRS, _GENKEY_SIG, timeout=120,
    )
    gen_sw = _sw_from_output(result_gen.stdout + result_gen.stderr)
    if gen_sw != "9000":
        pytest.skip(f"Key generation failed (SW={gen_sw!r}).")

    gen_resp = last_response_hex(result_gen.stdout)
    gen_point = _extract_ec_point_from_7f49(gen_resp)
    if gen_point is None:
        pytest.skip("Could not extract EC point from GENKEY response.")

    # Read the stored public key
    result_read = _send_apdus(
        runner, _SELECT_OPENPGP_CLEAN, _READ_PUB_SIG, timeout=30,
    )
    read_sw = _sw_from_output(result_read.stdout + result_read.stderr)
    assert read_sw == "9000", (
        f"READ PUBLIC KEY for SIG slot returned SW={read_sw!r}."
    )

    read_resp = last_response_hex(result_read.stdout)
    read_point = _extract_ec_point_from_7f49(read_resp)
    assert read_point is not None, (
        f"Could not extract EC point from READ PUBLIC KEY response.\nRaw: {read_resp[:80]}"
    )

    assert read_point == gen_point, (
        f"READ PUBLIC KEY returned a different point than GENERATE KEY PAIR!\n"
        f"  GENKEY:   {gen_point.hex()}\n"
        f"  READ_PUB: {read_point.hex()}"
    )
    log.info("READ PUBLIC KEY matches GENKEY response: OK (%d bytes)", len(read_point))


def test_openpgp_gpg_card_status_shows_sig_fingerprint(
    runner: CLIRunner, run_dir: Path
) -> None:
    """After GENERATE KEY PAIR + PUT DATA C7, gpg --card-status shows the fingerprint.

    Per OpenPGP Card 3.4, GENERATE KEY PAIR does not set the fingerprint DO
    (C5): the host computes it from the public key and creation time and
    writes it with PUT DATA C7 (this is what `gpg --card-edit` does).  The
    test writes a known fingerprint and checks gpg reports exactly that.
    """
    from conftest import gpg_skip_reason

    if reason := gpg_skip_reason():
        pytest.skip(reason)
    fingerprint = bytes(range(0xA0, 0xB4))  # 20 recognisable bytes
    put_fp_sig = f"00DA00C714{fingerprint.hex()}"
    result_gen = _send_apdus(
        runner, _SELECT_OPENPGP_CLEAN, _VERIFY_PW3,
        *_SET_P256_ATTRS, _GENKEY_SIG, put_fp_sig, timeout=120,
    )
    gen_sw = _sw_from_output(result_gen.stdout + result_gen.stderr)
    if gen_sw != "9000":
        pytest.skip(f"Key generation failed (SW={gen_sw!r}); cannot check gpg fingerprint.")

    # scdaemon caches card data while it holds the card; the APDUs above went
    # through PC/SC behind its back, so restart it to read fresh data.
    subprocess.run(["gpgconf", "--kill", "scdaemon"], capture_output=True, timeout=30)
    cmd = ["gpg", "--no-tty", "--card-status"]
    log.info("Running: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=30, text=True)
    except FileNotFoundError:
        pytest.skip("gpg not found in PATH.")
    except subprocess.TimeoutExpired:
        pytest.fail("gpg --card-status timed out.")

    stdout = proc.stdout
    stderr = proc.stderr
    log.info("gpg --card-status rc=%d\n%s", proc.returncode, stdout.strip())

    out_path = run_dir / "openpgp_02_gpg_card_status_after_keygen.txt"
    out_path.write_text(
        f"returncode: {proc.returncode}\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}",
        encoding="utf-8",
    )

    # Skip if scdaemon is not available
    if proc.returncode != 0 and "scdaemon" in (stdout + stderr).lower():
        pytest.skip(f"scdaemon not available: {(stdout + stderr).strip()}")

    assert proc.returncode == 0, (
        f"gpg --card-status failed (rc={proc.returncode}):\n{stdout}\n{stderr}"
    )

    # Find the 'Signature key' line and confirm it is not '[none]'
    sig_key_line = ""
    for line in stdout.splitlines():
        if "signature key" in line.lower():
            sig_key_line = line
            break

    log.info("Signature key line: %r", sig_key_line)
    assert sig_key_line, (
        f"'Signature key' line not found in gpg --card-status output:\n{stdout}"
    )
    shown = sig_key_line.split(":", 1)[-1].replace(" ", "").lower()
    assert shown == fingerprint.hex(), (
        f"Signature key should show the PUT DATA fingerprint {fingerprint.hex()}.\n"
        f"Line: {sig_key_line!r}"
    )
