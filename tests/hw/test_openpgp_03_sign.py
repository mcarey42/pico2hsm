"""Tests for OpenPGP PSO:CDS (Compute Digital Signature) with the SIG key.

PSO:CDS (Perform Security Operation: Compute Digital Signature):
    CLA=00 INS=2A P1=9E P2=9A

The input is a DigestInfo structure (for RSA) or a raw hash (for EC keys).
For P-256, the input is the raw 32-byte SHA-256 digest; the card returns a
DER-encoded ECDSA signature in the 7F49/86 TLV structure — or, more precisely
for PSO:CDS, a plain DER ASN.1 SEQUENCE { INTEGER r, INTEGER s }.

Authentication requirement: PW1 verified in mode 0x81 (signing mode) before
each PSO:CDS invocation.  The sign-once flag means PW1 must be re-presented
before each signature unless the card is set to "multiple signatures" mode.

"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
    SECP256R1,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    encode_dss_signature,
)

from helpers import trace, sw_from_output, last_response_hex
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# OpenPGP AID prefix
OPENPGP_AID_PREFIX = "D27600012401"
_SELECT_OPENPGP = ("00A40400 06" + OPENPGP_AID_PREFIX + "00").replace(" ", "")

# Default PINs
_PW1_DEFAULT = "313233343536"        # "123456"
_PW3_DEFAULT = "3132333435363738"    # "12345678"
_VERIFY_PW1_81 = f"002000810 6{_PW1_DEFAULT}".replace(" ", "")
_VERIFY_PW3    = f"002000830 8{_PW3_DEFAULT}".replace(" ", "")

# GENERATE KEY PAIR — SIG slot (B6)
_GENKEY_SIG    = "00478000 02B60000".replace(" ", "")
_READ_PUB_SIG  = "0047810002B600".replace(" ", "")

# Test message
_TEST_MESSAGE  = b"pico2hsm OpenPGP PSO:CDS hardware test message"
_TEST_HASH     = hashlib.sha256(_TEST_MESSAGE).digest()  # 32 bytes



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _send_apdus(runner: CLIRunner, *apdus: str, save_as: str | None = None, timeout: int = 60):
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


def _build_pso_cds_apdu(hash_bytes: bytes) -> str:
    """Build a PSO:CDS APDU for EC signing.

    For P-256, the input is the raw 32-byte SHA-256 hash.
    Command: 00 2A 9E 9A Lc <hash> 00
    """
    lc = len(hash_bytes)
    apdu = bytes([0x00, 0x2A, 0x9E, 0x9A, lc]) + hash_bytes + bytes([0x00])
    return apdu.hex().upper()


def _extract_signature_from_pso_cds_response(resp_hex: str) -> bytes | None:
    """Extract and return a DER-encoded ECDSA signature from a PSO:CDS response.

    OpenPGP PSO:CDS for EC keys returns raw r||s (not DER).
    For P-256, this is exactly 64 bytes (32 bytes r, 32 bytes s).
    This function converts raw r||s to DER for use with the cryptography library.
    If the response already starts with 0x30 (DER), it is returned as-is.
    """
    data = bytes.fromhex(resp_hex.replace(" ", ""))
    if not data:
        return None
    # Already DER-encoded
    if data[0] == 0x30:
        return data
    # Raw r||s for P-256: exactly 64 bytes
    if len(data) == 64:
        r = int.from_bytes(data[:32], "big")
        s = int.from_bytes(data[32:64], "big")
        return encode_dss_signature(r, s)
    # Raw r||s for P-384: exactly 96 bytes
    if len(data) == 96:
        r = int.from_bytes(data[:48], "big")
        s = int.from_bytes(data[48:96], "big")
        return encode_dss_signature(r, s)
    return None


def _extract_ec_point_from_7f49(resp_hex: str) -> bytes | None:
    """Parse 7F49 Public Key template and return the uncompressed EC point (tag 86)."""
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


def _get_or_generate_sig_pubkey(runner: CLIRunner) -> EllipticCurvePublicKey | None:
    """Ensure SIG slot has a P-256 key and return the public key object."""
    # Try reading existing public key first
    result_read = _send_apdus(runner, _SELECT_OPENPGP, _READ_PUB_SIG, timeout=30)
    read_sw = _sw_from_output(result_read.stdout + result_read.stderr)
    if read_sw == "9000":
        resp_hex = last_response_hex(result_read.stdout)
        ec_point = _extract_ec_point_from_7f49(resp_hex)
        if ec_point and len(ec_point) == 65 and ec_point[0] == 0x04:
            x = int.from_bytes(ec_point[1:33], "big")
            y = int.from_bytes(ec_point[33:65], "big")
            pub_numbers = EllipticCurvePublicNumbers(x=x, y=y, curve=SECP256R1())
            try:
                return pub_numbers.public_key(backend=default_backend())
            except Exception:
                pass  # Fall through to generate

    # Generate a new key
    result_gen = _send_apdus(
        runner, _SELECT_OPENPGP, _VERIFY_PW3, _GENKEY_SIG, timeout=120,
    )
    gen_sw = _sw_from_output(result_gen.stdout + result_gen.stderr)
    if gen_sw != "9000":
        return None

    gen_resp = last_response_hex(result_gen.stdout)
    ec_point = _extract_ec_point_from_7f49(gen_resp)
    if not ec_point or len(ec_point) != 65 or ec_point[0] != 0x04:
        return None

    x = int.from_bytes(ec_point[1:33], "big")
    y = int.from_bytes(ec_point[33:65], "big")
    pub_numbers = EllipticCurvePublicNumbers(x=x, y=y, curve=SECP256R1())
    try:
        return pub_numbers.public_key(backend=default_backend())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_openpgp_pso_cds_returns_signature(runner: CLIRunner, run_dir: Path) -> None:
    """PSO:CDS after VERIFY PW1(81) must return SW=9000 and a non-empty DER signature."""
    pub_key = _get_or_generate_sig_pubkey(runner)
    if pub_key is None:
        pytest.skip("Could not obtain P-256 SIG public key.")

    pso_apdu = _build_pso_cds_apdu(_TEST_HASH)
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP,
        _VERIFY_PW1_81,
        pso_apdu,
        save_as="openpgp_03_pso_cds",
        timeout=60,
    )

    exchanges = trace.parse_apdu_trace(result.stderr)
    trace.save_json_trace(
        run_dir / "openpgp_03_pso_cds.json",
        "openpgp_pso_cds",
        result,
        exchanges,
    )
    log.info(
        "PSO:CDS: rc=%d  elapsed=%.0f ms  APDUs=%d",
        result.returncode, result.elapsed_ms, len(exchanges),
    )

    assert result.returncode == 0, (
        f"opensc-tool failed (rc={result.returncode}):\n{result.stderr}"
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("PSO:CDS SW: %s", sw)
    assert sw == "9000", (
        f"Expected SW=9000 from PSO:CDS; got SW={sw!r}."
    )

    resp_hex = last_response_hex(result.stdout)
    sig = _extract_signature_from_pso_cds_response(resp_hex)
    assert sig is not None and len(sig) > 0, (
        f"No DER signature in PSO:CDS response.\n"
        f"Expected response starting with 0x30 (ASN.1 SEQUENCE).\n"
        f"Raw response: {resp_hex[:80]}"
    )
    log.info("Signature extracted: %d bytes", len(sig))


def test_openpgp_pso_cds_signature_verifies(runner: CLIRunner, run_dir: Path) -> None:
    """The ECDSA signature from PSO:CDS must verify against the device SIG public key."""
    pub_key = _get_or_generate_sig_pubkey(runner)
    if pub_key is None:
        pytest.skip("Could not obtain P-256 SIG public key.")

    pso_apdu = _build_pso_cds_apdu(_TEST_HASH)
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP,
        _VERIFY_PW1_81,
        pso_apdu,
        save_as="openpgp_03_pso_cds_verify",
        timeout=60,
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    if sw != "9000":
        pytest.skip(f"PSO:CDS returned SW={sw!r}; cannot verify signature.")

    resp_hex = last_response_hex(result.stdout)
    sig = _extract_signature_from_pso_cds_response(resp_hex)
    if sig is None:
        pytest.skip("Could not extract signature from PSO:CDS response.")

    log.info("Verifying signature: %d bytes", len(sig))
    log.info("Signature (hex): %s", sig.hex())

    try:
        pub_key.verify(
            sig,
            _TEST_HASH,
            ec.ECDSA(Prehashed(hashes.SHA256())),
        )
        log.info("Signature verified OK.")
    except InvalidSignature:
        pytest.fail(
            f"PSO:CDS signature did NOT verify against the SIG public key.\n"
            f"Message hash: {_TEST_HASH.hex()}\n"
            f"Signature: {sig.hex()}"
        )


def test_openpgp_pso_cds_requires_pw1_verify(runner: CLIRunner) -> None:
    """PSO:CDS without prior VERIFY PW1(81) must fail with SW=6982 or 6984.

    The OpenPGP spec requires PW1 in signing mode (P2=0x81) before each
    PSO:CDS call (unless multiple-signature mode is enabled).
    """
    pub_key = _get_or_generate_sig_pubkey(runner)
    if pub_key is None:
        pytest.skip("Could not obtain P-256 SIG public key.")

    pso_apdu = _build_pso_cds_apdu(_TEST_HASH)
    # SELECT but do NOT verify PW1
    result = _send_apdus(runner, _SELECT_OPENPGP, pso_apdu, timeout=30)

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    log.info("PSO:CDS without PW1 verify SW: %s", sw)

    assert sw in ("6982", "6984", "6983"), (
        f"Expected security failure SW (6982/6984/6983) without PW1; got SW={sw!r}."
    )
    log.info("Correctly rejected PSO:CDS without PW1 (SW=%s)", sw)


def test_openpgp_pso_cds_two_signatures_both_valid(runner: CLIRunner) -> None:
    """Two consecutive PSO:CDS calls (each with fresh VERIFY PW1) must both produce valid signatures.

    OpenPGP's "sign-once" semantics mean PW1 must be re-verified before each
    signature.  This test exercises that path explicitly.
    """
    pub_key = _get_or_generate_sig_pubkey(runner)
    if pub_key is None:
        pytest.skip("Could not obtain P-256 SIG public key.")

    pso_apdu = _build_pso_cds_apdu(_TEST_HASH)
    signatures = []

    for attempt in range(1, 3):
        result = _send_apdus(
            runner,
            _SELECT_OPENPGP,
            _VERIFY_PW1_81,
            pso_apdu,
            timeout=60,
        )
        combined = result.stdout + result.stderr
        sw = _sw_from_output(combined)
        if sw != "9000":
            pytest.skip(f"PSO:CDS attempt {attempt} returned SW={sw!r}.")

        resp_hex = last_response_hex(result.stdout)
        sig = _extract_signature_from_pso_cds_response(resp_hex)
        if sig is None:
            pytest.skip(f"Could not extract signature on attempt {attempt}.")
        signatures.append(sig)

    for i, sig in enumerate(signatures):
        try:
            pub_key.verify(
                sig,
                _TEST_HASH,
                ec.ECDSA(Prehashed(hashes.SHA256())),
            )
        except InvalidSignature:
            pytest.fail(
                f"Signature {i + 1} of 2 did NOT verify.\nSignature: {sig.hex()}"
            )

    log.info(
        "Both PSO:CDS signatures valid (same=%s)",
        signatures[0] == signatures[1],
    )


def test_openpgp_pso_cds_verify_with_openssl(
    runner: CLIRunner, run_dir: Path,
) -> None:
    """Cross-verify the PSO:CDS signature using openssl dgst -verify.

    This is an end-to-end validation: public key written to a PEM file, message
    written to a file, signature written to a file, then openssl verifies them.
    """
    import tempfile, os

    pub_key = _get_or_generate_sig_pubkey(runner)
    if pub_key is None:
        pytest.skip("Could not obtain P-256 SIG public key.")

    pso_apdu = _build_pso_cds_apdu(_TEST_HASH)
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP,
        _VERIFY_PW1_81,
        pso_apdu,
        save_as="openpgp_03_pso_cds_openssl",
        timeout=60,
    )

    combined = result.stdout + result.stderr
    sw = _sw_from_output(combined)
    if sw != "9000":
        pytest.skip(f"PSO:CDS returned SW={sw!r}.")

    resp_hex = last_response_hex(result.stdout)
    sig = _extract_signature_from_pso_cds_response(resp_hex)
    if sig is None:
        pytest.skip("Could not extract signature from PSO:CDS response.")

    from cryptography.hazmat.primitives import serialization

    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        pubkey_path = os.path.join(tmpdir, "pubkey.pem")
        msg_path    = os.path.join(tmpdir, "message.bin")
        sig_path    = os.path.join(tmpdir, "signature.der")

        with open(pubkey_path, "wb") as f:
            f.write(pub_pem)
        with open(msg_path, "wb") as f:
            f.write(_TEST_MESSAGE)
        with open(sig_path, "wb") as f:
            f.write(sig)

        result_ossl = runner.openssl(
            "dgst", "-sha256", "-verify", pubkey_path,
            "-signature", sig_path, msg_path,
            save_as="openpgp_03_pso_cds_openssl_verify",
            timeout=30,
        )

    log.info(
        "openssl verify: rc=%d\n%s",
        result_ossl.returncode,
        (result_ossl.stdout + result_ossl.stderr).strip(),
    )

    assert result_ossl.returncode == 0, (
        f"openssl dgst -verify failed (rc={result_ossl.returncode}).\n"
        f"STDOUT:\n{result_ossl.stdout}\nSTDERR:\n{result_ossl.stderr}"
    )
    assert "verified ok" in (result_ossl.stdout + result_ossl.stderr).lower(), (
        "openssl did not report 'Verified OK'.\n"
        f"Output:\n{result_ossl.stdout}"
    )
    log.info("openssl verification of PSO:CDS signature: PASSED")
