"""PIV administrative session: SELECT PIV + management-key (9B) mutual auth.

PIV GENERATE KEY PAIR and PUT DATA require the management key, which is a
3DES challenge-response (GENERAL AUTHENTICATE, key ref 9B) — the host must
decrypt the card's witness within the same card session, which a fixed
opensc-tool APDU list cannot do.  This helper does the exchange with
pyscard and returns opensc-tool-style output so the existing parsers
(``sw_from_output``, ``last_response_hex``) keep working.
"""
from __future__ import annotations

import os
import time
from types import SimpleNamespace

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

PIV_AID = bytes.fromhex("A000000308000010000100")
# NIST SP 800-73 / Yubico factory default management key.
DEFAULT_MGMT_KEY = bytes.fromhex("010203040506070801020304050607080102030405060708")


def _tdes(key: bytes, block: bytes, decrypt: bool) -> bytes:
    cipher = Cipher(TripleDES(key), modes.ECB())
    op = cipher.decryptor() if decrypt else cipher.encryptor()
    return op.update(block) + op.finalize()


def _fmt(apdu: list[int], data: list[int], sw1: int, sw2: int) -> str:
    out = ["Sending: " + " ".join(f"{b:02X}" for b in apdu) + " "]
    out.append(f"Received (SW1=0x{sw1:02X}, SW2=0x{sw2:02X})" + (":" if data else ""))
    for i in range(0, len(data), 16):
        out.append(" ".join(f"{b:02X}" for b in data[i : i + 16]))
    return "\n".join(out) + "\n"


def _transmit(conn, apdu: list[int]):
    data, sw1, sw2 = conn.transmit(apdu)
    while sw1 == 0x61:  # GET RESPONSE chaining
        more, sw1, sw2 = conn.transmit([0x00, 0xC0, 0x00, 0x00, sw2])
        data += more
    return data, sw1, sw2


def admin_send(*apdus_hex: str, reader: int | None = None, key: bytes = DEFAULT_MGMT_KEY):
    """SELECT PIV, authenticate with the management key, send ``apdus_hex``.

    Returns an object with ``stdout`` (opensc-tool format), ``stderr`` and
    ``returncode`` (0 if the management-key authentication succeeded).
    """
    from smartcard.System import readers

    idx = int(os.environ.get("OPENSC_DEFAULT_READER", "0")) if reader is None else reader
    conn = readers()[idx].createConnection()
    conn.connect()
    stdout = ""
    start = time.monotonic()
    cmd = ["piv_admin", *apdus_hex]

    def result(rc: int) -> SimpleNamespace:
        # Same fields as CLIRunner results, so trace helpers work unchanged.
        return SimpleNamespace(
            cmd=cmd,
            stdout=stdout,
            stderr="",
            returncode=rc,
            elapsed_ms=(time.monotonic() - start) * 1000,
        )

    try:
        sel = [0x00, 0xA4, 0x04, 0x00, len(PIV_AID), *PIV_AID, 0x00]
        stdout += _fmt(sel, *_transmit(conn, sel))

        # Step 1: request the encrypted witness.
        req = [0x00, 0x87, 0x03, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00]
        resp, sw1, sw2 = _transmit(conn, req)
        if (sw1, sw2) != (0x90, 0x00) or len(resp) < 12:
            stdout += _fmt(req, resp, sw1, sw2)
            return result(1)
        witness = _tdes(key, bytes(resp[4:12]), decrypt=True)

        # Step 2: return the witness with our own challenge; check the card's answer.
        challenge = os.urandom(8)
        body = [0x7C, 0x14, 0x80, 0x08, *witness, 0x81, 0x08, *challenge]
        auth = [0x00, 0x87, 0x03, 0x9B, len(body), *body]
        resp, sw1, sw2 = _transmit(conn, auth)
        ok = (sw1, sw2) == (0x90, 0x00) and bytes(resp[4:12]) == _tdes(key, challenge, decrypt=False)
        if not ok:
            stdout += _fmt(auth, resp, sw1, sw2)
            return result(1)

        for apdu_hex in apdus_hex:
            apdu = list(bytes.fromhex(apdu_hex.replace(" ", "")))
            stdout += _fmt(apdu, *_transmit(conn, apdu))
        return result(0)
    finally:
        conn.disconnect()
