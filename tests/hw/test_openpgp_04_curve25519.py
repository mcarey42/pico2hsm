"""Tests for OpenPGP Card Ed25519/X25519 key generation and operations.

Requires the firmware to be built with the `applet-openpgp-curve25519` feature.

Tests:
- GENERATE KEY PAIR for SIG slot with EdDSA (Ed25519) algorithm attributes
- PSO:CDS (sign) with Ed25519 key — returns 64-byte raw signature
- GENERATE KEY PAIR for DEC slot with X25519 algorithm attributes
- PSO:DECIPHER (X25519 ECDH) with X25519 key

PUT DATA (0xDA) is used to set algorithm attributes before key generation:
  - DO C1 (SIG algo attrs): 16 + Ed25519 OID (1.3.6.1.4.1.11591.15.1)
  - DO C2 (DEC algo attrs): 12 + X25519 OID (1.3.6.1.4.1.3029.1.5.1)

These tests are marked xfail(strict=False) so they report as xpass when
the feature is working on hardware and as xfail otherwise.
"""

from __future__ import annotations

import hashlib
import logging
import os
import struct
from pathlib import Path

import pytest
from helpers import trace, sw_from_output, last_response_hex
from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# OpenPGP AID
OPENPGP_AID_PREFIX = "D27600012401"
_SELECT_OPENPGP = ("00A40400 06" + OPENPGP_AID_PREFIX + "00").replace(" ", "")

# Default PINs
_PW1_DEFAULT = "313233343536"        # "123456"
_PW3_DEFAULT = "3132333435363738"    # "12345678"
_VERIFY_PW1_81 = f"002000810 6{_PW1_DEFAULT}".replace(" ", "")
_VERIFY_PW1_82 = f"002000820 6{_PW1_DEFAULT}".replace(" ", "")
_VERIFY_PW3    = f"002000830 8{_PW3_DEFAULT}".replace(" ", "")

# GENERATE KEY PAIR APDUs
_GENKEY_SIG   = "00478000 02B60000".replace(" ", "")
_GENKEY_DEC   = "00478000 02B80000".replace(" ", "")
_READ_PUB_SIG = "0047810002B600".replace(" ", "")
_READ_PUB_DEC = "0047810002B800".replace(" ", "")

# Ed25519 OID: 1.3.6.1.4.1.11591.15.1 = 2B 06 01 04 01 DA 47 0F 01 (9 bytes)
_ED25519_OID = "2B060104 01DA470F01".replace(" ", "")
# X25519 OID: 1.3.6.1.4.1.3029.1.5.1 = 2B 06 01 04 01 97 55 01 05 01 (10 bytes)
_X25519_OID = "2B060104 0197550105 01".replace(" ", "")

# EdDSA algorithm attributes: algo_id=16, then Ed25519 OID (9 bytes) → 10 bytes total
_EDDSA_ALGO_ATTRS = "16" + _ED25519_OID
# X25519 ECDH algorithm attributes: algo_id=12, then X25519 OID (10 bytes) → 11 bytes total
_X25519_ALGO_ATTRS = "12" + _X25519_OID

# PUT DATA (0xDA) — set algorithm attributes
# DO C1 = SIG algo attrs, DO C2 = DEC algo attrs
def _put_algo_sig(attrs_hex: str) -> str:
    ln = len(attrs_hex) // 2
    return f"00DA00C1{ln:02X}{attrs_hex}"

def _put_algo_dec(attrs_hex: str) -> str:
    ln = len(attrs_hex) // 2
    return f"00DA00C2{ln:02X}{attrs_hex}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _send_apdus(runner: CLIRunner, *apdus: str, save_as: str | None = None, timeout: int = 120):
    args = ["opensc-tool"]
    for apdu in apdus:
        args.extend(["--send-apdu", apdu.replace(" ", "")])
    return runner.run(args, save_as=save_as, timeout=timeout)


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


def _extract_key_from_7f49(resp_hex: str) -> bytes | None:
    """Parse the 7F49 Public Key template and return the raw key bytes (tag 86)."""
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


def _build_x25519_decipher_input(peer_pubkey_bytes: bytes) -> str:
    """Build the PSO:DECIPHER input: A6 [ 7F49 [ 86 len <peer_pubkey> ] ]"""
    key_len = len(peer_pubkey_bytes)
    inner = bytes([0x86, key_len]) + peer_pubkey_bytes
    template = bytes([0x7F, 0x49, len(inner)]) + inner
    wrapper = bytes([0xA6, len(template)]) + template
    return wrapper.hex()


# ---------------------------------------------------------------------------
# Ed25519 tests
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=False, reason="Requires applet-openpgp-curve25519 firmware feature")
def test_openpgp_ed25519_genkey_sig_succeeds(runner: CLIRunner, run_dir: Path) -> None:
    """GENERATE KEY PAIR for SIG slot with EdDSA attrs must return SW=9000 and 32-byte key."""
    put_algo = _put_algo_sig(_EDDSA_ALGO_ATTRS)
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP,
        _VERIFY_PW3,
        put_algo,
        _GENKEY_SIG,
        save_as="openpgp_04_ed25519_genkey",
        timeout=120,
    )

    combined = result.stdout + result.stderr
    sw = sw_from_output(combined)
    log.info("Ed25519 GENKEY SIG SW: %s", sw)
    assert sw == "9000", f"Expected SW=9000; got SW={sw!r}"

    resp_hex = last_response_hex(result.stdout)
    key_bytes = _extract_key_from_7f49(resp_hex)
    assert key_bytes is not None, "No 7F49/86 key bytes in response"
    assert len(key_bytes) == 32, f"Expected 32-byte Ed25519 public key; got {len(key_bytes)} bytes"
    log.info("Ed25519 public key: %s", key_bytes.hex())


@pytest.mark.xfail(strict=False, reason="Requires applet-openpgp-curve25519 firmware feature")
def test_openpgp_ed25519_sign_returns_64_bytes(runner: CLIRunner) -> None:
    """PSO:CDS with Ed25519 SIG key must return a 64-byte raw signature."""
    # Generate Ed25519 SIG key
    put_algo = _put_algo_sig(_EDDSA_ALGO_ATTRS)
    result_gen = _send_apdus(
        runner, _SELECT_OPENPGP, _VERIFY_PW3, put_algo, _GENKEY_SIG, timeout=120,
    )
    gen_sw = sw_from_output(result_gen.stdout + result_gen.stderr)
    if gen_sw != "9000":
        pytest.skip(f"Key generation failed (SW={gen_sw!r})")

    # Build a 32-byte digest (SHA-256 of a test message)
    digest = hashlib.sha256(b"test message for Ed25519 signing").digest()
    digest_hex = digest.hex()

    # PSO:CDS — input is the raw digest (32 bytes)
    lc = len(digest)
    pso_cds = f"002A9E9A{lc:02X}{digest_hex}00"

    result_sign = _send_apdus(
        runner,
        _SELECT_OPENPGP,
        _VERIFY_PW1_81,
        pso_cds,
        timeout=30,
    )
    sign_sw = sw_from_output(result_sign.stdout + result_sign.stderr)
    log.info("Ed25519 PSO:CDS SW: %s", sign_sw)
    assert sign_sw == "9000", f"Expected SW=9000 from PSO:CDS; got SW={sign_sw!r}"

    resp_hex = last_response_hex(result_sign.stdout)
    if resp_hex:
        sig_bytes = bytes.fromhex(resp_hex.replace(" ", ""))
        log.info("Ed25519 signature: %d bytes: %s", len(sig_bytes), sig_bytes.hex())
        assert len(sig_bytes) == 64, (
            f"Expected 64-byte Ed25519 signature (r||s); got {len(sig_bytes)} bytes"
        )


@pytest.mark.xfail(strict=False, reason="Requires applet-openpgp-curve25519 firmware feature")
def test_openpgp_ed25519_sign_verify(runner: CLIRunner) -> None:
    """Ed25519 signature must verify against the generated public key."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        pytest.skip("cryptography >= 2.6 with Ed25519 support required")

    put_algo = _put_algo_sig(_EDDSA_ALGO_ATTRS)
    result_gen = _send_apdus(
        runner, _SELECT_OPENPGP, _VERIFY_PW3, put_algo, _GENKEY_SIG, timeout=120,
    )
    gen_sw = sw_from_output(result_gen.stdout + result_gen.stderr)
    if gen_sw != "9000":
        pytest.skip(f"Key generation failed (SW={gen_sw!r})")

    resp_hex = last_response_hex(result_gen.stdout)
    pub_key_bytes = _extract_key_from_7f49(resp_hex)
    if pub_key_bytes is None or len(pub_key_bytes) != 32:
        pytest.skip("Could not extract 32-byte Ed25519 public key")

    # Message to sign
    message = b"test message for Ed25519 signing"
    digest = hashlib.sha256(message).digest()
    digest_hex = digest.hex()
    lc = len(digest)
    pso_cds = f"002A9E9A{lc:02X}{digest_hex}00"

    result_sign = _send_apdus(
        runner, _SELECT_OPENPGP, _VERIFY_PW1_81, pso_cds, timeout=30,
    )
    sign_sw = sw_from_output(result_sign.stdout + result_sign.stderr)
    if sign_sw != "9000":
        pytest.skip(f"Signing failed (SW={sign_sw!r})")

    sig_resp = last_response_hex(result_sign.stdout)
    sig_bytes = bytes.fromhex(sig_resp.replace(" ", "")) if sig_resp else b""
    if len(sig_bytes) != 64:
        pytest.skip(f"Unexpected signature length {len(sig_bytes)}")

    pub_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
    try:
        pub_key.verify(sig_bytes, digest)
        log.info("Ed25519 signature verified successfully")
    except InvalidSignature:
        pytest.fail("Ed25519 signature verification failed")


# ---------------------------------------------------------------------------
# X25519 tests
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=False, reason="Requires applet-openpgp-curve25519 firmware feature")
def test_openpgp_x25519_genkey_dec_succeeds(runner: CLIRunner, run_dir: Path) -> None:
    """GENERATE KEY PAIR for DEC slot with X25519 attrs must return SW=9000 and 32-byte key."""
    put_algo = _put_algo_dec(_X25519_ALGO_ATTRS)
    result = _send_apdus(
        runner,
        _SELECT_OPENPGP,
        _VERIFY_PW3,
        put_algo,
        _GENKEY_DEC,
        save_as="openpgp_04_x25519_genkey",
        timeout=120,
    )

    combined = result.stdout + result.stderr
    sw = sw_from_output(combined)
    log.info("X25519 GENKEY DEC SW: %s", sw)
    assert sw == "9000", f"Expected SW=9000; got SW={sw!r}"

    resp_hex = last_response_hex(result.stdout)
    key_bytes = _extract_key_from_7f49(resp_hex)
    assert key_bytes is not None, "No 7F49/86 key bytes in response"
    assert len(key_bytes) == 32, f"Expected 32-byte X25519 public key; got {len(key_bytes)} bytes"
    log.info("X25519 public key: %s", key_bytes.hex())


@pytest.mark.xfail(strict=False, reason="Requires applet-openpgp-curve25519 firmware feature")
def test_openpgp_x25519_decipher_succeeds(runner: CLIRunner) -> None:
    """PSO:DECIPHER with X25519 DEC key must return a 32-byte shared secret."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    except ImportError:
        pytest.skip("cryptography >= 2.5 with X25519 support required")

    put_algo = _put_algo_dec(_X25519_ALGO_ATTRS)
    result_gen = _send_apdus(
        runner, _SELECT_OPENPGP, _VERIFY_PW3, put_algo, _GENKEY_DEC, timeout=120,
    )
    gen_sw = sw_from_output(result_gen.stdout + result_gen.stderr)
    if gen_sw != "9000":
        pytest.skip(f"Key generation failed (SW={gen_sw!r})")

    resp_hex = last_response_hex(result_gen.stdout)
    card_pub_bytes = _extract_key_from_7f49(resp_hex)
    if card_pub_bytes is None or len(card_pub_bytes) != 32:
        pytest.skip("Could not extract 32-byte X25519 public key from card")

    # Generate ephemeral key pair on the test host
    ephemeral_priv = X25519PrivateKey.generate()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )

    # Build PSO:DECIPHER APDU: A6 [ 7F49 [ 86 len <ephemeral_pub> ] ]
    decipher_data = _build_x25519_decipher_input(ephemeral_pub_bytes)
    lc = len(decipher_data) // 2
    pso_decipher = f"002A8086{lc:02X}{decipher_data}00"

    result_decipher = _send_apdus(
        runner, _SELECT_OPENPGP, _VERIFY_PW1_82, pso_decipher, timeout=30,
    )
    decipher_sw = sw_from_output(result_decipher.stdout + result_decipher.stderr)
    log.info("X25519 PSO:DECIPHER SW: %s", decipher_sw)
    assert decipher_sw == "9000", f"Expected SW=9000 from PSO:DECIPHER; got SW={decipher_sw!r}"

    resp_hex = last_response_hex(result_decipher.stdout)
    if resp_hex:
        shared_bytes = bytes.fromhex(resp_hex.replace(" ", ""))
        log.info("X25519 shared secret: %d bytes: %s", len(shared_bytes), shared_bytes.hex())
        assert len(shared_bytes) == 32, (
            f"Expected 32-byte X25519 shared secret; got {len(shared_bytes)} bytes"
        )


@pytest.mark.xfail(strict=False, reason="Requires applet-openpgp-curve25519 firmware feature")
def test_openpgp_x25519_decipher_matches_expected(runner: CLIRunner) -> None:
    """X25519 shared secret from card must match the value computed on the host."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError:
        pytest.skip("cryptography >= 2.5 with X25519 support required")

    put_algo = _put_algo_dec(_X25519_ALGO_ATTRS)
    result_gen = _send_apdus(
        runner, _SELECT_OPENPGP, _VERIFY_PW3, put_algo, _GENKEY_DEC, timeout=120,
    )
    gen_sw = sw_from_output(result_gen.stdout + result_gen.stderr)
    if gen_sw != "9000":
        pytest.skip(f"Key generation failed (SW={gen_sw!r})")

    resp_hex = last_response_hex(result_gen.stdout)
    card_pub_bytes = _extract_key_from_7f49(resp_hex)
    if card_pub_bytes is None or len(card_pub_bytes) != 32:
        pytest.skip("Could not extract 32-byte X25519 public key from card")

    # Generate ephemeral X25519 key pair on the host
    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )

    # Compute expected shared secret on the host: ephemeral_priv * card_pub
    card_pub_key = X25519PublicKey.from_public_bytes(card_pub_bytes)
    expected_shared = ephemeral_priv.exchange(card_pub_key)

    # Ask the card to compute: card_priv * ephemeral_pub
    decipher_data = _build_x25519_decipher_input(ephemeral_pub_bytes)
    lc = len(decipher_data) // 2
    pso_decipher = f"002A8086{lc:02X}{decipher_data}00"

    result_decipher = _send_apdus(
        runner, _SELECT_OPENPGP, _VERIFY_PW1_82, pso_decipher, timeout=30,
    )
    decipher_sw = sw_from_output(result_decipher.stdout + result_decipher.stderr)
    if decipher_sw != "9000":
        pytest.skip(f"PSO:DECIPHER failed (SW={decipher_sw!r})")

    resp_hex = last_response_hex(result_decipher.stdout)
    card_shared = bytes.fromhex(resp_hex.replace(" ", "")) if resp_hex else b""
    if len(card_shared) != 32:
        pytest.skip(f"Unexpected shared secret length {len(card_shared)}")

    assert card_shared == expected_shared, (
        f"X25519 shared secret mismatch!\n"
        f"  card:     {card_shared.hex()}\n"
        f"  expected: {expected_shared.hex()}"
    )
    log.info("X25519 shared secret matches: OK")
