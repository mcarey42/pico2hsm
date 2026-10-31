"""Hardware test: the 2.0 flash layout (docs/FLASH_LAYOUT_2_0.md).

Every board boots through a bootrom partition table: firmware slot A (and
slot B on the 16 MB boards), then the store regions as partitions of their
own, closed to the bootloader (BOOTSEL: picotool, UF2) and to Non-secure
code.  This test reads what the bootrom loaded through two `debug`-build
commands (80 FE 15: image version and boot info; 80 FE 16: the partition
table) and checks it against the layout the firmware is built for.

With PICO2HSM_ALLOW_BOOTSEL=1 it also reboots the board into BOOTSEL
(80 FE 14) and checks that picotool can read the firmware slot but not the
store, then boots it again.  The board must be the only one whose USB
serial is PICO2HSM_READER; picotool must be on PATH.

On a build without the `debug` feature the test skips.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from helpers.pcsc import apdu, session

SELECT_SC_HSM = "00A404000BE82B0601040181C31F020100"
IMAGE_INFO = apdu(0x80, 0xFE, 0x15, 0x00)
PT_INFO = apdu(0x80, 0xFE, 0x16, 0x00)
TO_BOOTSEL = apdu(0x80, 0xFE, 0x14, 0x00)
GET_STATUS = apdu(0x80, 0xF0, 0x00, 0x00)

_REPO = Path(__file__).resolve().parents[2]
_STORE_PARTITIONS = ("binding", "counters", "rsa-pool", "spare", "keystore")


def _kib(text: str) -> int:
    assert text.endswith("K"), text
    return int(text[:-1]) * 1024


def _store_regions(big: bool) -> dict[str, tuple[int, int]]:
    """Store regions as (first sector, last sector), from the committed
    partition table (boards/pt_16m.json or pt_4m.json), which CI keeps equal
    to the one pico2hsm-layout generates.  The `_prod` tables
    (pt_*_prod.json) differ only in their permissions; their store regions
    are the same, so reading the dev table covers both."""
    table = json.loads((_REPO / "boards" / f"pt_{'16m' if big else '4m'}.json").read_text())
    out = {}
    for p in table["partitions"]:
        if p["name"] in _STORE_PARTITIONS:
            first = _kib(p["start"]) // 4096
            out[p["name"]] = (first, first + _kib(p["size"]) // 4096 - 1)
    assert set(out) == set(_STORE_PARTITIONS), out
    return out


def test_store_regions_from_tables():
    """Host-only: the committed tables give the documented store sectors."""
    assert _store_regions(False) == {
        "binding": (0x1D8, 0x1DF),
        "counters": (0x1E0, 0x1EF),
        "rsa-pool": (0x1F0, 0x1FB),
        "spare": (0x1FC, 0x1FF),
        "keystore": (0x201, 0x3FF),
    }
    assert _store_regions(True) == {
        "binding": (0x801, 0x808),
        "counters": (0x809, 0x818),
        "rsa-pool": (0x819, 0x824),
        "spare": (0x825, 0x828),
        "keystore": (0x829, 0xFFE),
    }


SECURE_ONLY = 0b000011  # location word bits 26..31: S R, S W only


def _words(data: bytes) -> list[int]:
    return [int.from_bytes(data[i : i + 4], "little") for i in range(0, len(data), 4)]


def _read(cmd: bytes) -> bytes:
    with session() as s:
        s.ok(SELECT_SC_HSM)
        data, sw = s.send(cmd)
        if sw in (0x6D00, 0x6A80):
            pytest.skip("needs a `debug` build (EXTRA_FEATURES=debug)")
        assert sw == 0x9000, f"{cmd.hex()}: {sw:04X}"
        return bytes(data)


def _partitions() -> list[tuple[int, int, int]]:
    w = _words(_read(PT_INFO))
    assert len(w) >= 4 and w[0] & 0x11 == 0x11, f"no table info: {w}"
    assert w[1] & 0x100, "no partition table loaded"
    count = w[1] & 0xFF
    locs = [w[4 + 2 * i] for i in range(count)]
    return [(x & 0x1FFF, (x >> 13) & 0x1FFF, x >> 26) for x in locs]


@pytest.mark.hw
def test_boots_from_a_partition():
    data = _read(IMAGE_INFO)
    major, minor = int.from_bytes(data[0:2], "big"), int.from_bytes(data[2:4], "big")
    boot = _words(data[4:])
    assert boot and boot[0] & 0x40, f"no BOOT_INFO: {data.hex()}"
    partition = (boot[1] >> 16) & 0xFF
    assert partition in (0, 1), f"booted flat (partition byte {partition:#x})"
    assert major >= 1, f"image version {major}.{minor}"


def _status_tlv() -> dict[int, bytes]:
    """GET PROVISIONING STATUS (80 F0): every build, no PIN."""
    with session() as s:
        s.ok(SELECT_SC_HSM)
        data, sw = s.send(GET_STATUS)
    assert sw == 0x9000, f"GET PROVISIONING STATUS: {sw:04X}"
    data = bytes(data)
    assert data[0] == 0x6F and data[1] == len(data) - 2, data.hex()
    tags, i = {}, 2
    while i + 1 < len(data):
        tags[data[i]] = data[i + 2 : i + 2 + data[i + 1]]
        i += 2 + data[i + 1]
    return tags


@pytest.mark.hw
def test_status_reports_the_image_version():
    """Release builds report the running image's version (tag 85), so a
    host can recommend an update; debug builds must agree with 80 FE 15."""
    v = _status_tlv().get(0x85)
    assert v is not None and len(v) == 4, "no image version (tag 85)"
    major, minor = int.from_bytes(v[0:2], "big"), int.from_bytes(v[2:4], "big")
    assert major >= 1, f"image version {major}.{minor}"
    with session() as s:
        s.ok(SELECT_SC_HSM)
        data, sw = s.send(IMAGE_INFO)
    if sw == 0x9000:
        assert bytes(data[:4]) == v, f"80 FE 15 says {bytes(data[:4]).hex()}, status {v.hex()}"


@pytest.mark.hw
def test_store_regions_are_closed_partitions():
    parts = _partitions()
    big = any(first == 0x400 for first, _, _ in parts)  # slot B: 16 MB map
    store = _store_regions(big)
    for name, (first, last) in store.items():
        touching = [p for p in parts if not (p[0] > last or p[1] < first)]
        assert touching == [(first, last, SECURE_ONLY)], (
            f"{name}: expected sectors {first:#x}..{last:#x}, Secure only; "
            f"the table has {[(hex(a), hex(b), bin(c)) for a, b, c in touching]}"
        )


@pytest.mark.hw
@pytest.mark.skipif(
    os.environ.get("PICO2HSM_ALLOW_BOOTSEL") != "1" or not shutil.which("picotool"),
    reason="set PICO2HSM_ALLOW_BOOTSEL=1 (and have picotool) to test from BOOTSEL",
)
def test_bootsel_cannot_reach_the_store():
    ser = os.environ.get("PICO2HSM_READER")
    if not ser:
        pytest.skip("PICO2HSM_READER names the board's USB serial")
    big = any(first == 0x400 for first, _, _ in _partitions())
    store = _store_regions(big)

    def picotool(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["picotool", *args, "--ser", ser], capture_output=True, text=True, timeout=120
        )

    try:
        with session() as s:
            s.ok(SELECT_SC_HSM)
            s.send(TO_BOOTSEL)
    except Exception:  # the card goes away mid-command
        pass
    deadline = time.monotonic() + 60
    while picotool("info").returncode != 0:
        assert time.monotonic() < deadline, "the board did not enter BOOTSEL"
        time.sleep(1)
    fd, out = tempfile.mkstemp(suffix=".bin")
    os.close(fd)
    try:
        for name in ("binding", "counters", "keystore"):
            first, _ = store[name]
            a = 0x1000_0000 + first * 4096
            r = picotool("save", "-r", hex(a), hex(a + 4096), out)
            assert "permission failure" in r.stdout + r.stderr, f"{name} readable from BOOTSEL"
        r = picotool("save", "-r", "0x10002000", "0x10003000", out)
        assert r.returncode == 0, f"slot A not readable: {r.stdout}{r.stderr}"
    finally:
        os.remove(out)
        picotool("reboot")
        deadline = time.monotonic() + 60
        while True:
            try:
                with session() as s:
                    s.ok(SELECT_SC_HSM)
                    break
            except Exception:
                assert time.monotonic() < deadline, "the board did not come back"
                time.sleep(1)
