"""SC-HSM per-key usage policy (CardContact key attributes, audit S-10).

GENERATE ASYMMETRIC KEY PAIR accepts, after the CVC request body:
  90 04 <n>     key use counter: the key may be used n more times
  91 <k> <ids>  algorithm list: the only algorithm IDs (SIGN/DECIPHER P2,
                92 = WRAP) the key may be used with
  92 01 <d>     key domain (only domain 0 exists)

The card reports them in the FCP of SELECT CC<key ref>:
  A5 L { 90 04 <uses left | FFFFFFFF> [91 ...] [92 01 ...] }

Each test generates its own key in a slot no other test uses (0x30-0x33).
"""
from __future__ import annotations

import hashlib
import logging

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from helpers.pcsc import apdu, session

log = logging.getLogger(__name__)

SELECT_SC_HSM = bytes.fromhex("00A404000BE82B0601040181C31F020100")
P256_ORDER = bytes.fromhex(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
)
ALGO_EC_RAW = 0x70
ALGO_EC_SHA256 = 0x73
ALGO_EC_DH = 0x80
SW_OK = 0x9000
SW_CONDITIONS = 0x6985
SW_EXHAUSTED = 0x6A84
MESSAGE = b"pico2hsm key usage policy test"


def _gakp(attrs: bytes) -> bytes:
    """GENERATE KEY PAIR data for P-256 with key attributes appended."""
    pk = b"\x85\x20" + P256_ORDER
    return b"\x5F\x29\x01\x00" + b"\x7F\x49" + bytes([len(pk)]) + pk + attrs


def _login(s, config: dict) -> None:
    s.ok(SELECT_SC_HSM)
    pin = config["pin"].encode()
    s.ok(apdu(0x00, 0x20, 0x00, 0x81, pin))


def _generate(s, key_ref: int, attrs: bytes) -> ec.EllipticCurvePublicKey:
    cvc = s.ok(apdu(0x00, 0x46, key_ref, 0x00, _gakp(attrs), le=0))
    i = cvc.find(b"\x86\x41\x04")
    assert i >= 0, f"no public point in the CVC: {cvc.hex()}"
    point = cvc[i + 2 : i + 2 + 65]
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)


def _sign(s, key_ref: int, algo: int):
    data = MESSAGE if algo == ALGO_EC_SHA256 else hashlib.sha256(MESSAGE).digest()
    return s.send(apdu(0x80, 0x68, key_ref, algo, data, le=0))


@pytest.mark.hw
def test_algorithm_list_allows_only_listed_algorithm(initialized_device, config) -> None:
    """Key with 91 = {73}: ECDSA-SHA256 signs (and verifies), ECDSA raw and
    ECDH are refused with 6985."""
    with session() as s:
        _login(s, config)
        pub = _generate(s, 0x30, bytes([0x91, 0x01, ALGO_EC_SHA256]))

        sig, sw = _sign(s, 0x30, ALGO_EC_SHA256)
        assert sw == SW_OK, f"allowed algorithm refused: {sw:04X}"
        pub.verify(sig, MESSAGE, ec.ECDSA(hashes.SHA256()))

        _, sw = _sign(s, 0x30, ALGO_EC_RAW)
        assert sw == SW_CONDITIONS, f"ECDSA raw (70) not in the list: got {sw:04X}"

        peer = ec.generate_private_key(ec.SECP256R1()).public_key()
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        point = peer.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        _, sw = s.send(apdu(0x80, 0x62, 0x30, ALGO_EC_DH, point, le=0))
        assert sw == SW_CONDITIONS, f"ECDH (80) not in the list: got {sw:04X}"

        # Reported in the key file's FCP.
        fcp, sw = s.send(apdu(0x00, 0xA4, 0x00, 0x04, b"\xCC\x30", le=0))
        assert sw == SW_OK
        assert bytes.fromhex("A50990 04 FFFFFFFF 91 01 73".replace(" ", "")) in fcp, fcp.hex()


@pytest.mark.hw
def test_use_counter_two_uses_then_refused(initialized_device, config) -> None:
    """Key with 90 = 2: two signatures, the third is refused with 6A84."""
    with session() as s:
        _login(s, config)
        pub = _generate(s, 0x31, bytes([0x90, 0x04, 0, 0, 0, 2]))
        for n in (1, 2):
            sig, sw = _sign(s, 0x31, ALGO_EC_SHA256)
            assert sw == SW_OK, f"use {n} refused: {sw:04X}"
            pub.verify(sig, MESSAGE, ec.ECDSA(hashes.SHA256()))
        _, sw = _sign(s, 0x31, ALGO_EC_SHA256)
        assert sw == SW_EXHAUSTED, f"third use: expected 6A84, got {sw:04X}"
        fcp, _ = s.send(apdu(0x00, 0xA4, 0x00, 0x04, b"\xCC\x31", le=0))
        assert bytes.fromhex("A506900400000000") in fcp, fcp.hex()


@pytest.mark.hw
def test_use_counter_survives_a_new_session(initialized_device, config) -> None:
    """The counter is on flash: a new card session (and a reset) sees the
    uses already spent."""
    with session() as s:
        _login(s, config)
        _generate(s, 0x32, bytes([0x90, 0x04, 0, 0, 0, 1]))
        _, sw = _sign(s, 0x32, ALGO_EC_RAW)
        assert sw == SW_OK
    with session() as s:
        _login(s, config)
        _, sw = _sign(s, 0x32, ALGO_EC_RAW)
        assert sw == SW_EXHAUSTED, f"expected 6A84 after reconnect, got {sw:04X}"


@pytest.mark.hw
def test_key_without_attributes_is_unrestricted(initialized_device, config) -> None:
    """No 90/91: every algorithm valid for the key type works, any number
    of times, and the FCP reports no counter (FFFFFFFF)."""
    with session() as s:
        _login(s, config)
        _generate(s, 0x33, b"")
        for algo in (ALGO_EC_RAW, ALGO_EC_SHA256, ALGO_EC_RAW):
            _, sw = _sign(s, 0x33, algo)
            assert sw == SW_OK, f"algo {algo:02X}: {sw:04X}"
        fcp, _ = s.send(apdu(0x00, 0xA4, 0x00, 0x04, b"\xCC\x33", le=0))
        assert fcp.endswith(bytes.fromhex("A50690 04FFFFFFFF".replace(" ", ""))), fcp.hex()
