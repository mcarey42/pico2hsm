"""PIV PUT DATA / GET DATA round trip of a certificate-sized object (R2-11).

A 1.5 KB object in the 9A certificate slot (5FC105) must be stored and read
back intact, in RSA and non-RSA builds alike.  The write is an extended-length
PUT DATA after management-key authentication; the read goes through a fresh
card session (GET RESPONSE chaining for the >256-byte reply).  The object is
deleted again (``53 00``) at the end.
"""

from __future__ import annotations

import os

import pytest

from helpers import sw_from_output
from helpers.piv_admin import PIV_AID, _transmit, admin_send

_TAG = bytes.fromhex("5FC105")


def _cert_object(size: int) -> bytes:
    """A 70/71/FE certificate container whose total length is ``size``."""
    pad = size - 4 - 3 - 2 - 4  # 70 82 LL LL, 71 01 00, FE 00, cert TLV header
    cert = bytes((i * 7 + 3) & 0xFF for i in range(pad))
    inner = b"\x70\x82" + len(cert).to_bytes(2, "big") + cert + b"\x71\x01\x00\xFE\x00"
    assert len(inner) == size
    return inner


def _put_data_ext(content: bytes) -> str:
    body = b"\x5C\x03" + _TAG + b"\x53\x82" + len(content).to_bytes(2, "big") + content
    return (b"\x00\xDB\x3F\xFF\x00" + len(body).to_bytes(2, "big") + body).hex()


def _get_data() -> bytes:
    from smartcard.System import readers

    idx = int(os.environ.get("OPENSC_DEFAULT_READER", "0"))
    conn = readers()[idx].createConnection()
    conn.connect()
    try:
        sel = [0x00, 0xA4, 0x04, 0x00, len(PIV_AID), *PIV_AID, 0x00]
        _, sw1, sw2 = _transmit(conn, sel)
        assert (sw1, sw2) == (0x90, 0x00)
        data, sw1, sw2 = _transmit(conn, [0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, *_TAG, 0x00])
        assert (sw1, sw2) == (0x90, 0x00), f"GET DATA SW={sw1:02X}{sw2:02X}"
        return bytes(data)
    finally:
        conn.disconnect()


@pytest.mark.parametrize("size", [600, 1500])
def test_piv_certificate_object_round_trip(size):
    pytest.importorskip("smartcard")
    content = _cert_object(size)
    r = admin_send(_put_data_ext(content))
    assert r.returncode == 0, r.stdout
    assert sw_from_output(r.stdout) == "9000", r.stdout
    try:
        got = _get_data()
        # Response: 53 82 LL LL <content>
        assert got[:2] == b"\x53\x82", got[:8].hex()
        assert int.from_bytes(got[2:4], "big") == size
        assert got[4:] == content
    finally:
        d = admin_send((b"\x00\xDB\x3F\xFF\x07\x5C\x03" + _TAG + b"\x53\x00").hex())
        assert sw_from_output(d.stdout) == "9000", d.stdout
