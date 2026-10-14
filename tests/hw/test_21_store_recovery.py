"""Hardware test: Storage V2 store recovery (STORAGE_V2 §9.3, §16 OD-1).

A store whose journal is behind its anchor (lost SD writes, a restored
image) is refused at boot.  With the SO-PIN, which lives in the binding
block and so still verifies, the host can:

1. read STORE STATUS (no PIN): refused, behind the anchor by N;
2. OPEN DEGRADED: the store mounts read-only, keys work, writes fail;
3. ACCEPT STORE with the count it was shown: a re-index makes that state
   the store, read-write again, and it stays so across a reboot.

The rollback is simulated with a `debug`-build hook (80 FE 13 <n>: move
the anchor n records ahead of the journal) and the board is rebooted with
another (80 FE 12 00: watchdog reset), so no debug probe is needed.  On a
build without the `debug` feature the test skips.

Leaves the device as it found it (initialized, every key in place).
"""

from __future__ import annotations

import logging
import time

import pytest

from helpers.pcsc import apdu, dut_index, session

log = logging.getLogger(__name__)

pytestmark = pytest.mark.hw

SELECT_SC_HSM = "00A404000BE82B0601040181C31F020100"
STORE_STATUS = apdu(0x80, 0x54, 0x52, 0x00)
OPEN_DEGRADED = apdu(0x80, 0x54, 0x4F, 0x00, b"OPEN-DEGRADED")
KEY_MANIFEST = apdu(0x80, 0x54, 0x39, 0x00)
REBOOT = apdu(0x80, 0xFE, 0x12, 0x00)
LOST = 3

P256_ORDER = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
KEYGEN_P256 = bytes.fromhex("5F290100" + "7F4922" + "8520" + P256_ORDER)
SCRATCH_REF = 0x7A


def _accept(lost: int) -> bytes:
    return apdu(0x80, 0x54, 0x53, 0x00, b"ACCEPT-STORE-V2" + lost.to_bytes(8, "big"))


def _status(s) -> dict:
    data = s.ok(STORE_STATUS)
    return {
        "state": data[0],
        "reason": data[1],
        "lost": int.from_bytes(data[2:10], "big"),
        "opens": int.from_bytes(data[10:14], "big"),
        "reanchors": int.from_bytes(data[14:18], "big"),
    }


def _reboot_and_wait(timeout: float = 30.0) -> None:
    """Watchdog-reset the board (debug hook) and wait for it to come back."""
    try:
        with session() as s:
            s.send(SELECT_SC_HSM)
            s.send(REBOOT)
    except Exception as e:  # the card goes away mid-command
        log.info("reboot: %s", e)
    time.sleep(2.0)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with session() as s:
                s.send(SELECT_SC_HSM)
                return
        except Exception:
            time.sleep(0.5)
    pytest.fail("the board did not come back after the watchdog reset")


def _login(s, pin: str) -> None:
    s.ok(apdu(0x00, 0x20, 0x00, 0x81, pin.encode()))


def _so_login(s, so_pin_hex: str) -> None:
    s.ok(apdu(0x00, 0x20, 0x00, 0x88, bytes.fromhex(so_pin_hex)))


def test_refused_store_open_degraded_and_accept(initialized_device, config):  # noqa: ARG001
    pin, so_pin = config["pin"], config["so_pin"]

    with session() as s:
        s.ok(SELECT_SC_HSM)
        _, sw = s.send(STORE_STATUS)
        if sw == 0x6D00:
            pytest.skip("firmware before STORE STATUS")
        before = _status(s)
        assert before["state"] == 0, f"store not up: {before}"
        _login(s, pin)
        manifest = s.ok(KEY_MANIFEST)
        # Lose LOST records (as far as the anchor knows).
        _, sw = s.send(apdu(0x80, 0xFE, 0x13, LOST))
        if sw in (0x6D00, 0x6A80):
            pytest.skip("needs a `debug` build (EXTRA_FEATURES=debug)")
        assert sw == 0x9000, f"anchor hook: {sw:04X}"

    _reboot_and_wait()

    with session() as s:
        s.ok(SELECT_SC_HSM)
        st = _status(s)
        assert (st["state"], st["reason"], st["lost"]) == (2, 4, LOST), st
        # The user PIN record is out of reach; the SO-PIN is not.
        _, sw = s.send(apdu(0x00, 0x20, 0x00, 0x81, pin.encode()))
        assert sw == 0x6983, f"user PIN on a refused store: {sw:04X}"
        _, sw = s.send(OPEN_DEGRADED)
        assert sw == 0x6982, f"OPEN DEGRADED without the SO-PIN: {sw:04X}"
        _so_login(s, so_pin)
        s.ok(OPEN_DEGRADED)

    with session() as s:
        s.ok(SELECT_SC_HSM)
        st = _status(s)
        assert (st["state"], st["lost"]) == (1, LOST), st
        assert st["opens"] == before["opens"] + 1
        # Read-only: the keys are all there, a key generation fails.
        _login(s, pin)
        assert s.ok(KEY_MANIFEST) == manifest
        _, sw = s.send(apdu(0x00, 0x46, SCRATCH_REF, 0x00, KEYGEN_P256, le=0))
        assert sw == 0x6581, f"GENERATE on a read-only store: {sw:04X}"
        # ACCEPT STORE: SO-PIN, and the count it was shown.
        _so_login(s, so_pin)
        _, sw = s.send(_accept(LOST - 1))
        assert sw == 0x6A80, f"ACCEPT STORE with the wrong count: {sw:04X}"
        s.ok(_accept(LOST))

    with session() as s:
        s.ok(SELECT_SC_HSM)
        st = _status(s)
        assert (st["state"], st["lost"]) == (0, 0), st
        assert st["reanchors"] == before["reanchors"] + 1
        _login(s, pin)
        assert s.ok(KEY_MANIFEST) == manifest
        # Read-write again.
        s.ok(apdu(0x00, 0x46, SCRATCH_REF, 0x00, KEYGEN_P256, le=0))

    _reboot_and_wait()

    with session() as s:
        s.ok(SELECT_SC_HSM)
        assert _status(s)["state"] == 0
        _login(s, pin)
        assert s.ok(KEY_MANIFEST) != manifest, "the new key survived the reboot"
        # Leave the device as it was.
        s.ok(apdu(0x00, 0xE4, 0x02, 0x00, bytes([0xCC, SCRATCH_REF])))
        assert s.ok(KEY_MANIFEST) == manifest
