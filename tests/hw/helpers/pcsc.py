"""One PC/SC card session with GET RESPONSE chaining (pyscard).

Policy tests need several commands in the same card session (VERIFY then
the use it authorises, management-key authentication then GENERATE), which
separate opensc-tool invocations cannot guarantee.
"""
from __future__ import annotations

import logging
import os
from contextlib import contextmanager

log = logging.getLogger(__name__)


class Session:
    def __init__(self, conn):
        self.conn = conn

    def send(self, apdu: bytes | str) -> tuple[bytes, int]:
        """Send one APDU; return (response data, SW)."""
        if isinstance(apdu, str):
            apdu = bytes.fromhex(apdu.replace(" ", ""))
        data, sw1, sw2 = self.conn.transmit(list(apdu))
        while sw1 == 0x61:
            more, sw1, sw2 = self.conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
            data += more
        sw = (sw1 << 8) | sw2
        log.info("> %s\n< %s %04X", apdu.hex().upper(), bytes(data).hex().upper(), sw)
        return bytes(data), sw

    def ok(self, apdu: bytes | str) -> bytes:
        data, sw = self.send(apdu)
        assert sw == 0x9000, f"{apdu!r}: SW={sw:04X}"
        return data


def apdu(cla: int, ins: int, p1: int, p2: int, data: bytes = b"", le: int | None = None) -> bytes:
    """Short APDU (Lc only when there is data)."""
    out = bytes([cla, ins, p1, p2])
    if data:
        assert len(data) <= 255
        out += bytes([len(data)]) + data
    if le is not None:
        out += bytes([le])
    return out


@contextmanager
def session(reader: int | None = None):
    from smartcard.System import readers

    idx = int(os.environ.get("OPENSC_DEFAULT_READER", "0")) if reader is None else reader
    conn = readers()[idx].createConnection()
    conn.connect()
    try:
        yield Session(conn)
    finally:
        conn.disconnect()
