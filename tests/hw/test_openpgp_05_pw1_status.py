"""OpenPGP PW1 status byte (DO C4) and signature counter (audit S-10).

C4 byte 1 = 00: PW1 (mode 81) is valid for one PSO:CDS only;
          = 01: for several.  Written with PUT DATA C4 (needs PW3).
DO 93 (in 7A) counts signatures and survives a new session.
7F74 = 81 01 00: no button.

Uses the factory-default PW1/PW3.  Leaves C4 at 00 (the default).
"""
from __future__ import annotations

import pytest

from helpers.pcsc import apdu, session

SW_OK = 0x9000
SELECT = bytes.fromhex("00A4040006D2760001240100")
PW1 = b"123456"
PW3 = b"12345678"
P256 = bytes.fromhex("2A8648CE3D030107")


def _cds(s) -> int:
    return s.send(apdu(0x00, 0x2A, 0x9E, 0x9A, bytes(32), le=0))[1]


def _counter(s) -> int:
    t = s.ok(apdu(0x00, 0xCA, 0x00, 0x7A, le=0))
    i = t.find(b"\x93\x03")
    return int.from_bytes(t[i + 2 : i + 5], "big")


@pytest.mark.hw
def test_openpgp_c4_00_single_signature() -> None:
    with session() as s:
        s.ok(SELECT)
        s.ok(apdu(0x00, 0x20, 0x00, 0x83, PW3))
        s.ok(apdu(0x00, 0xDA, 0x00, 0xC1, b"\x13" + P256))
        s.ok(apdu(0x00, 0xDA, 0x00, 0xC4, b"\x00"))
        s.ok(apdu(0x00, 0x47, 0x80, 0x00, b"\xB6\x00", le=0))
        assert _counter(s) == 0, "new signature key: counter reset"

        assert s.ok(apdu(0x00, 0xCA, 0x00, 0xC4, le=0))[0] == 0x00
        s.ok(apdu(0x00, 0x20, 0x00, 0x81, PW1))
        assert _cds(s) == SW_OK
        assert _cds(s) == 0x6982, "C4=00: one signature per VERIFY"
        assert _counter(s) == 1

        # 01: several signatures per VERIFY.
        s.ok(apdu(0x00, 0xDA, 0x00, 0xC4, b"\x01"))
        s.ok(apdu(0x00, 0x20, 0x00, 0x81, PW1))
        assert _cds(s) == SW_OK
        assert _cds(s) == SW_OK
        assert _counter(s) == 3

    with session() as s:
        s.ok(SELECT)
        assert _counter(s) == 3, "signature counter is persisted"
        assert s.ok(apdu(0x00, 0xCA, 0x00, 0xC4, le=0))[0] == 0x01, "C4 is persisted"
        assert s.ok(apdu(0x00, 0xCA, 0x7F, 0x74, le=0)) == bytes.fromhex("810100")
        # Back to the default.
        s.ok(apdu(0x00, 0x20, 0x00, 0x83, PW3))
        s.ok(apdu(0x00, 0xDA, 0x00, 0xC4, b"\x00"))
        # Wrong role for the algorithm: ECDH on the signature key.
        _, sw = s.send(apdu(0x00, 0xDA, 0x00, 0xC1, b"\x12" + P256))
        assert sw == 0x6A80
