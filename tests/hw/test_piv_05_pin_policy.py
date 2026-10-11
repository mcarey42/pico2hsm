"""PIV PIN policy (Yubico AA tag) and slot key usage (audit S-10).

- 9A generated with PIN policy "always" (AC { 80 11, AA 03 }): each
  signature needs a VERIFY right before it.
- Touch policy "always" (AB 02) is refused with 6A80: no button.
- GET METADATA (INS F7) reports the stored policy.
- 9D (key management) does ECDH (tag 85) but does not sign.

Needs the factory-default management key and PIN (run after test_piv_00..04
or on a reset applet).  Everything runs in one card session.
"""
from __future__ import annotations

import os

import pytest
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from helpers.pcsc import apdu, session
from helpers.piv_admin import DEFAULT_MGMT_KEY, PIV_AID

SW_OK = 0x9000
PIN = b"123456\xFF\xFF"


def _tdes(block: bytes, decrypt: bool) -> bytes:
    c = Cipher(TripleDES(DEFAULT_MGMT_KEY), modes.ECB())
    op = c.decryptor() if decrypt else c.encryptor()
    return op.update(block) + op.finalize()


def _admin(s) -> None:
    s.ok(apdu(0x00, 0xA4, 0x04, 0x00, PIV_AID, le=0))
    resp = s.ok(apdu(0x00, 0x87, 0x03, 0x9B, bytes.fromhex("7C028000"), le=0))
    witness = _tdes(resp[4:12], decrypt=True)
    challenge = os.urandom(8)
    body = b"\x7C\x14\x80\x08" + witness + b"\x81\x08" + challenge
    resp = s.ok(apdu(0x00, 0x87, 0x03, 0x9B, body, le=0))
    assert resp[4:12] == _tdes(challenge, decrypt=False)


def _generate(s, slot: int, extra: bytes = b""):
    ac = b"\x80\x01\x11" + extra
    return s.send(apdu(0x00, 0x47, 0x00, slot, b"\xAC" + bytes([len(ac)]) + ac, le=0))


def _sign(s, slot: int) -> int:
    body = b"\x82\x00\x81\x20" + bytes(range(32))
    return s.send(apdu(0x00, 0x87, 0x11, slot, b"\x7C" + bytes([len(body)]) + body, le=0))[1]


def _verify(s) -> None:
    s.ok(apdu(0x00, 0x20, 0x00, 0x80, PIN))


@pytest.mark.hw
def test_piv_9a_pin_policy_always() -> None:
    with session() as s:
        _admin(s)
        _, sw = _generate(s, 0x9A, b"\xAA\x01\x03")
        assert sw == SW_OK, f"GENERATE 9A with PIN policy always: {sw:04X}"

        assert _sign(s, 0x9A) == 0x6982, "no VERIFY yet"
        _verify(s)
        assert _sign(s, 0x9A) == SW_OK
        assert _sign(s, 0x9A) == 0x6982, "PIN always: one use per VERIFY"
        _verify(s)
        assert _sign(s, 0x9A) == SW_OK

        meta = s.ok(apdu(0x00, 0xF7, 0x00, 0x9A, le=0))
        assert meta[:10] == bytes.fromhex("01011102020301030101"), meta.hex()


@pytest.mark.hw
def test_piv_touch_always_refused_without_button() -> None:
    with session() as s:
        _admin(s)
        _, sw = _generate(s, 0x9E, b"\xAB\x01\x02")
        assert sw == 0x6A80, f"touch policy always must be refused: {sw:04X}"
        _, sw = _generate(s, 0x9E, b"\xAB\x01\x01")
        assert sw == SW_OK


@pytest.mark.hw
def test_piv_9d_is_key_establishment_only() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    with session() as s:
        _admin(s)
        resp, sw = _generate(s, 0x9D)
        assert sw == SW_OK
        card_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), resp[resp.find(b"\x86\x41") + 2 :][:65]
        )
        _verify(s)
        assert _sign(s, 0x9D) == 0x6A80, "a key management key does not sign"

        peer = ec.generate_private_key(ec.SECP256R1())
        point = peer.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        body = b"\x82\x00\x85\x41" + point
        z, sw = s.send(apdu(0x00, 0x87, 0x11, 0x9D, b"\x7C" + bytes([len(body)]) + body, le=0))
        assert sw == SW_OK, f"ECDH on 9D: {sw:04X}"
        assert z[4:] == peer.exchange(ec.ECDH(), card_pub)
