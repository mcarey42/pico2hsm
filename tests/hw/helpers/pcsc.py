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


def dut_index() -> int:
    """PC/SC index of the device under test, resolved now.

    PICO2HSM_READER (a substring of one reader name, e.g. the board's USB
    serial) wins over OPENSC_DEFAULT_READER (an index).  Indexes shift
    whenever a board re-enumerates (flash, probe-rs reset), so resolve on
    every connection rather than once per run.
    """
    sel = os.environ.get("PICO2HSM_READER")
    if sel:
        from smartcard.System import readers

        hits = [i for i, r in enumerate(readers()) if sel in str(r)]
        if len(hits) != 1:
            raise RuntimeError(f"PICO2HSM_READER={sel!r} matches {len(hits)} readers")
        return hits[0]
    return int(os.environ.get("OPENSC_DEFAULT_READER", "0"))


def peer_index() -> int:
    """PC/SC index of the second device for two-device tests, resolved now:
    PICO2HSM_PEER_READER (a reader-name substring), else the first reader
    that is not the device under test."""
    from smartcard.System import readers

    names = [str(r) for r in readers()]
    sel = os.environ.get("PICO2HSM_PEER_READER")
    if sel:
        hits = [i for i, n in enumerate(names) if sel in n]
        if len(hits) != 1:
            raise RuntimeError(f"PICO2HSM_PEER_READER={sel!r} matches {len(hits)} readers")
        return hits[0]
    dut = dut_index()
    return next(i for i in range(len(names)) if i != dut)


@contextmanager
def session(reader: int | None = None):
    from smartcard.System import readers

    idx = dut_index() if reader is None else reader
    conn = readers()[idx].createConnection()
    conn.connect()
    try:
        yield Session(conn)
    finally:
        conn.disconnect()
