#!/usr/bin/env python3
"""provision-device.py — stage-by-stage secure provisioning of one pico2hsm.

Every OTP write is PERMANENT.  This tool performs one stage at a time (or a
range with `through`), checks each stage's preconditions first, reads every
written row back, and boots the firmware to confirm the board still works
before it reports success.  It never prints secret values (the storage IKM).

Stages (docs/PROVISIONING.md; the OTP map):
  0  preflight     no writes: device, revision, OTP state, key files
  1  bootkeys      BOOTKEY0/1 hashes            (inert until 3 + 5)
  2  ikm           storage IKM + chaff, page 4  (re-keys the keystore)
  3  key-slots     BOOT_FLAGS1 KEY_VALID / KEY_INVALID
  4  lock-page4    PAGE4_LOCK1 = 0x3D3D3D (S read-only, NS + BOOTSEL none)
  5  secure-boot   signed table + signed image installed, then CRIT1.SECURE_BOOT_ENABLE
  6  bootsel-trim  BOOT_FLAGS0: UART boot and OTP boot off (picotool, UF2 kept)
  7  glitch        CRIT1.GLITCH_DETECTOR_ENABLE (default sensitivity)
  8  production    SET PRODUCTION MODE (firmware APDU, SO-PIN)
Stage 9 (debug) and 10 (final locks) are deliberately not automated.

Usage:
  tools/provision-device.py --serial <SER> status
  tools/provision-device.py --serial <SER> stage <N|name> [--burn] [options]
  tools/provision-device.py --serial <SER> through <N> --burn [options]

Requires picotool (USB build) on PATH or --picotool, and pyscard for the
stages that talk to the firmware (2, 4, 5, 7, 8).  Build the boot-key
files first with tools/otp-bootkeys.sh.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── OTP layout (bootrom: picotool rp2350_otp_contents.json; ours:
#    firmware/src/security/otp_layout.rs) ─────────────────────────────────────
CRIT1 = 0x40              # 8 copies, 3-of-8 vote
BOOT_FLAGS0 = 0x48        # 3 copies
BOOT_FLAGS1 = 0x4B        # 3 copies
BOOTKEY0 = 0x80           # 16 ECC rows per key
IKM = 0x100               # 32 ECC rows = 64 bytes
CHAFF = 0x120             # 32 raw rows: 24-bit complement of each IKM row
BOOT_FLAGS_ROW = 0x140    # pico2hsm flags (raw)
PAGE4_LOCK1 = 0xF89
PAGE4_LOCK1_VALUE = 0x3D3D3D  # S read-only (1), NS (3) and bootloader (3) inaccessible

CRIT1_SECURE_BOOT = 1 << 0
CRIT1_GLITCH_ENABLE = 1 << 4
BF0_DISABLE_OTP_BOOT = 1 << 13
BF0_DISABLE_UART_BOOT = 1 << 19

SELECT_SC_HSM = "00A404000BE82B0601040181C31F020100"
TO_BOOTSEL = "80FE140000"       # debug builds only
GET_PROV_STATUS = "80F0000000"

STAGES = ["preflight", "bootkeys", "ikm", "key-slots", "lock-page4",
          "secure-boot", "bootsel-trim", "glitch", "production"]


def secret_dir() -> tempfile.TemporaryDirectory:
    """A private temporary directory, in RAM where the host has one."""
    shm = "/dev/shm"
    return tempfile.TemporaryDirectory(dir=shm if os.path.isdir(shm) and os.access(shm, os.W_OK) else None)


def write_secret(p: Path, data: bytes) -> None:
    """Create `p` owner-only (never pre-existing) and write `data`."""
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def wipe_secret(p: Path) -> None:
    """Overwrite `p` with zeros, then delete it (best effort on the medium)."""
    if not p.exists():
        return
    with open(p, "r+b") as f:
        f.write(b"\0" * p.stat().st_size)
        f.flush()
        os.fsync(f.fileno())
    p.unlink()


class Fail(Exception):
    pass


def say(msg: str) -> None:
    print(msg, flush=True)


# ── picotool ─────────────────────────────────────────────────────────────────

class Picotool:
    def __init__(self, exe: str, serial: str):
        self.exe, self.serial = exe, serial

    def run(self, *args: str, check: bool = True, timeout: int = 180, secret: bool = False) -> str:
        """Run picotool.  With `secret`, a failure reports only picotool's
        ERROR lines, never the rest of its output (which can hold OTP row
        values, the IKM among them)."""
        r = subprocess.run([self.exe, *args, "--ser", self.serial],
                           capture_output=True, text=True, timeout=timeout)
        out = (r.stdout + r.stderr).replace("\r", "\n")
        if check and (r.returncode != 0 or "ERROR" in out):
            if secret:
                errs = [l.strip() for l in out.splitlines() if "ERROR" in l and "0x" not in l]
                detail = "\n".join(errs[-3:]) or f"exit status {r.returncode} (output withheld)"
            else:
                detail = out.strip()[-600:]
            raise Fail(f"picotool {' '.join(args)} failed:\n{detail}")
        return out

    def in_bootsel(self) -> bool:
        try:
            r = subprocess.run([self.exe, "info", "--ser", self.serial],
                               capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            return False
        return r.returncode == 0 and "ERROR" not in (r.stdout + r.stderr)

    def rows(self, rows: list[int], ecc: bool = False) -> dict[int, int]:
        """Read rows; never echoed.  picotool prints every row raw (24
        bits, ECC included), so for ECC rows return the 16-bit data after
        checking the stored ECC matches it."""
        out = self.run("otp", "get", "-r", *[hex(r) for r in rows], secret=True)
        vals: dict[int, int] = {}
        cur = None
        for line in out.splitlines():
            m = re.match(r"\s*ROW 0x([0-9a-fA-F]+)", line)
            if m:
                cur = int(m.group(1), 16)
                continue
            m = re.match(r"\s*VALUE 0x([0-9a-fA-F]+)", line)
            if m and cur is not None:
                vals[cur] = int(m.group(1), 16)
                cur = None
        missing = [r for r in rows if r not in vals]
        if missing:
            raise Fail(f"could not read OTP rows {[hex(r) for r in missing]}")
        if ecc:
            bad = [hex(r) for r, v in vals.items() if v and ecc_row(v & 0xFFFF) != v & 0x3FFFFF]
            if bad:
                raise Fail(f"ECC rows {bad} do not hold a consistent ECC value")
            vals = {r: v & 0xFFFF for r, v in vals.items()}
        return vals

    def row(self, row: int, ecc: bool = False) -> int:
        return self.rows([row], ecc)[row]

    def row_readable(self, row: int) -> bool:
        out = self.run("otp", "get", "-r", hex(row), check=False)
        return "VALUE" in out and "ERROR" not in out


# ── the running firmware (pyscard) ───────────────────────────────────────────

class Card:
    def __init__(self, serial: str):
        self.serial = serial

    def _connect(self):
        try:
            from smartcard.System import readers
        except ImportError as e:
            raise Fail("pyscard is required for this stage (pip install pyscard)") from e
        for r in readers():
            if self.serial.upper() in str(r).upper():
                c = r.createConnection()
                c.connect()
                return c
        return None

    def present(self) -> bool:
        try:
            return self._connect() is not None
        except Exception:
            return False

    def apdus(self, *hexes: str) -> list[tuple[bytes, int]]:
        c = self._connect()
        if c is None:
            raise Fail("the board's reader is not present")
        out = []
        for h in hexes:
            data, sw1, sw2 = c.transmit(list(bytes.fromhex(h)))
            out.append((bytes(data), sw1 << 8 | sw2))
        return out

    def wait(self, present: bool = True, timeout: float = 90) -> None:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.present() == present:
                return
            time.sleep(1)
        raise Fail(f"timed out waiting for the reader to {'appear' if present else 'go'}")

    def prov_status(self) -> dict[str, int | str]:
        (_, sw), (data, sw2) = self.apdus(SELECT_SC_HSM, GET_PROV_STATUS)
        if sw2 != 0x9000:
            raise Fail(f"GET PROVISIONING STATUS: {sw2:04X}")
        tags = {0x80: "production", 0x81: "jtag_flag", 0x82: "key_page_locked",
                0x83: "secure_boot", 0x84: "glitch_armed"}
        res, i = {}, 2 if data[:1] == b"\x6f" else 0
        while i + 2 < len(data):
            t, ln = data[i], data[i + 1]
            if t in tags:
                res[tags[t]] = data[i + 2]
            elif t == 0x85 and ln == 4:   # image version: major, minor * 256 + patch
                minor = int.from_bytes(data[i + 4:i + 6], "big")
                res["image"] = f"{int.from_bytes(data[i + 2:i + 4], 'big')}.{minor >> 8}.{minor & 0xFF}"
            i += 2 + ln
        return res

    def store_state(self) -> int:
        (_, _), (data, sw) = self.apdus(SELECT_SC_HSM, "8054520000")
        if sw != 0x9000:
            raise Fail(f"STORE STATUS: {sw:04X}")
        return data[0]


# ── helpers ──────────────────────────────────────────────────────────────────

def ecc_row(x: int) -> int:
    """OTP ECC encoding of a 16-bit value (picotool otp_calculate_ecc)."""
    def par(v: int) -> int:
        return bin(v).count("1") & 1
    p0 = par(x & 0b1010110101011011)
    p1 = par(x & 0b0011011001101101)
    p2 = par(x & 0b1100011110001110)
    p3 = par(x & 0b0000011111110000)
    p4 = par(x & 0b1111100000000000)
    p5 = par(x) ^ p0 ^ p1 ^ p2 ^ p3 ^ p4
    return x | ((p0 | p1 << 1 | p2 << 2 | p3 << 3 | p4 << 4 | p5 << 5) << 16)


class Device:
    def __init__(self, args):
        self.args = args
        self.pt = Picotool(args.picotool, args.serial)
        self.card = Card(args.serial)

    # Moving between BOOTSEL and the firmware.
    def to_bootsel(self) -> None:
        if self.pt.in_bootsel():
            return
        if self.card.present():
            try:
                self.card.apdus(SELECT_SC_HSM, TO_BOOTSEL)
            except Exception:
                pass  # the board goes away mid-command
        end = time.monotonic() + 30
        while time.monotonic() < end:
            if self.pt.in_bootsel():
                return
            time.sleep(1)
        say("  The firmware cannot reboot into BOOTSEL (release build?).")
        say("  Hold the board's BOOT button and replug it now...")
        end = time.monotonic() + 600
        while time.monotonic() < end:
            if self.pt.in_bootsel():
                return
            time.sleep(1)
        raise Fail("the board did not enter BOOTSEL")

    def boot(self) -> None:
        if self.pt.in_bootsel():
            self.pt.run("reboot", check=False)
        self.card.wait(True)
        time.sleep(2)

    def require_burn(self, what: str) -> None:
        if not self.args.burn:
            raise Fail(f"{what} writes OTP permanently: rerun with --burn")

    # ── stages ───────────────────────────────────────────────────────────────

    def status(self) -> None:
        self.to_bootsel()
        info = self.pt.run("info", "-a")
        for k in ("chipid", "revision", "secure boot", "debug enable"):
            m = re.search(rf"{k}:\s*(\S+)", info)
            if m:
                say(f"  {k:14s} {m.group(1)}")
        crit = self.pt.rows(list(range(CRIT1, CRIT1 + 8)))
        bf0 = self.pt.rows(list(range(BOOT_FLAGS0, BOOT_FLAGS0 + 3)))
        bf1 = self.pt.rows(list(range(BOOT_FLAGS1, BOOT_FLAGS1 + 3)))
        keys = self.pt.rows(list(range(BOOTKEY0, BOOTKEY0 + 32)), ecc=True)
        say(f"  CRIT1 copies   {' '.join(f'{v:06x}' for v in crit.values())}")
        say(f"  BOOT_FLAGS0    {' '.join(f'{v:06x}' for v in bf0.values())}")
        say(f"  BOOT_FLAGS1    {' '.join(f'{v:06x}' for v in bf1.values())}")
        for k in range(2):
            h = b"".join(keys[BOOTKEY0 + 16 * k + i].to_bytes(2, "little") for i in range(16))
            say(f"  BOOTKEY{k}       {'blank' if not any(h) else h.hex()}")
        if self.pt.row_readable(IKM):
            raw = self.pt.rows(list(range(IKM, IKM + 64)))
            ikm_set = sum(1 for r in range(IKM, IKM + 32) if raw[r])
            chaff_set = sum(1 for r in range(CHAFF, CHAFF + 32) if raw[r])
            say(f"  page 4         IKM rows set {ikm_set}/32, chaff rows set {chaff_set}/32 (values not shown)")
        else:
            say("  page 4         not readable from BOOTSEL (locked)")
        say(f"  boot flags     {self.pt.row(BOOT_FLAGS_ROW):06x} (row 0x140)")
        say(f"  PAGE4_LOCK1    {self.pt.row(PAGE4_LOCK1):06x}")
        self.boot()
        if self.card.present():
            try:
                say(f"  firmware       {self.card.prov_status()}; store state {self.card.store_state()}")
            except Fail as e:
                say(f"  firmware       {e}")

    def preflight(self) -> None:
        self.to_bootsel()
        info = self.pt.run("info", "-a")
        rev = re.search(r"revision:\s*(\S+)", info)
        say(f"  silicon revision {rev.group(1) if rev else 'unknown'}")
        if rev and rev.group(1) in ("A2", "A3"):
            say("  NOTE: A2/A3 silicon: erratum RP2350-E24 (glitch + flash swap) is unfixed;"
                " secure boot raises the bar but is not a complete defence.")
        for f in ("stage1-bootkeys.json", "stage3-key-slots.json"):
            p = ROOT / "dist" / "otp" / f
            if not p.exists():
                raise Fail(f"{p} missing: run tools/otp-bootkeys.sh first")
            if "crit" in p.read_text().lower():
                raise Fail(f"{p} touches CRIT1: refusing")
        say("  boot-key files present and free of CRIT1")
        say("  preflight OK (nothing written)")

    def _expected_keys(self) -> dict[int, int]:
        doc = json.loads((ROOT / "dist" / "otp" / "stage1-bootkeys.json").read_text())
        exp = {}
        for name, byts in doc.items():
            k = int(name.removeprefix("bootkey"))
            for i in range(16):
                exp[BOOTKEY0 + 16 * k + i] = byts[2 * i] | byts[2 * i + 1] << 8
        return exp

    def bootkeys(self) -> None:
        self.to_bootsel()
        exp = self._expected_keys()
        cur = self.pt.rows(sorted(exp), ecc=True)
        if cur == exp:
            say("  boot keys already provisioned and correct")
            return
        if any(cur[r] for r in exp):
            raise Fail("BOOTKEY rows hold other values: stop (never write over them)")
        self.require_burn("stage 1 (boot-key hashes)")
        self.pt.run("otp", "load", str(ROOT / "dist" / "otp" / "stage1-bootkeys.json"))
        got = self.pt.rows(sorted(exp), ecc=True)
        bad = [hex(r) for r in exp if got[r] != exp[r]]
        if bad:
            raise Fail(f"BOOTKEY read-back mismatch at rows {bad}")
        say(f"  BOOTKEY rows written and verified ({len(exp)} rows)")

    def ikm(self) -> None:
        self.to_bootsel()
        if not self.pt.row_readable(IKM):
            raise Fail("page 4 is not readable: already locked?")
        raw = self.pt.rows(list(range(IKM, IKM + 64)))
        if any(raw.values()):
            ikm_set = all(raw[r] for r in range(IKM, IKM + 32))
            chaff_ok = all(raw[CHAFF + i] == (~raw[IKM + i]) & 0xFFFFFF for i in range(32))
            if ikm_set and chaff_ok:
                say("  IKM and chaff already provisioned and consistent")
                return
            raise Fail("page 4 is partly written: stop and inspect (values are not shown)")
        self.require_burn("stage 2 (storage IKM)")
        ikm = secrets.token_bytes(64)
        words = [ikm[2 * i] | ikm[2 * i + 1] << 8 for i in range(32)]
        expected_raw = [ecc_row(w) for w in words]
        with secret_dir() as d:
            p = Path(d) / "ikm.bin"
            write_secret(p, ikm)
            try:
                self.pt.run("otp", "load", "-e", "-s", hex(IKM), str(p), secret=True)
            finally:
                wipe_secret(p)
            # Each raw row must equal the ECC encoding of the data written,
            # except at most one 1-bit that failed to program, which the
            # hardware's ECC corrects on every read.
            raw = self.pt.rows(list(range(IKM, IKM + 32)))
            fixed = 0
            for i in range(32):
                diff = raw[IKM + i] ^ expected_raw[i]
                if diff and not (bin(diff).count("1") == 1 and diff & expected_raw[i]):
                    raise Fail(f"IKM row {IKM + i:#x} does not match what was written (values not shown)")
                fixed += bool(diff)
            say(f"  IKM written (64 random bytes) and verified; the host copy is wiped"
                f"{f' ({fixed} bit(s) corrected by ECC)' if fixed else ''}")
            # Chaff: the complement of each raw row as actually stored.
            actual = [raw[IKM + i] for i in range(32)]
            chaff = b"".join(((~r) & 0xFFFFFF).to_bytes(4, "little") for r in actual)
            # The chaff is the IKM's complement: as secret as the IKM.
            c = Path(d) / "chaff.bin"
            write_secret(c, chaff)
            try:
                self.pt.run("otp", "load", "-r", "-s", hex(CHAFF), str(c), secret=True)
            finally:
                wipe_secret(c)
            got = self.pt.rows(list(range(CHAFF, CHAFF + 32)))
            bad = [CHAFF + i for i in range(32) if got[CHAFF + i] != (~actual[i]) & 0xFFFFFF]
            if bad:
                raise Fail(f"chaff read-back mismatch at rows {[hex(r) for r in bad]}")
        del ikm, words, expected_raw, raw, actual, chaff
        say("  chaff (complement of each IKM row) written and verified")
        self.boot()
        st = self.card.prov_status()
        if not st.get("key_page_locked"):
            raise Fail(f"firmware did not read-lock the key page: {st}")
        say(f"  firmware boots provisioned: {st}")
        say("  the keystore is now sealed under the new IKM: FORMAT STORE, then INITIALIZE")

    def key_slots(self) -> None:
        self.to_bootsel()
        doc = json.loads((ROOT / "dist" / "otp" / "stage3-key-slots.json").read_text())
        valid = doc["boot_flags1"]["key_valid"]
        invalid = doc["boot_flags1"]["key_invalid"]
        want = valid | invalid << 8
        exp = self._expected_keys()
        if self.pt.rows(sorted(exp), ecc=True) != exp:
            raise Fail("boot keys not provisioned (stage 1) or different")
        cur = self.pt.rows([BOOT_FLAGS1, BOOT_FLAGS1 + 1, BOOT_FLAGS1 + 2])
        if all(v & 0xF0F == want for v in cur.values()):
            say("  key slots already set")
            return
        self.require_burn("stage 3 (key slots)")
        self.pt.run("otp", "load", str(ROOT / "dist" / "otp" / "stage3-key-slots.json"))
        got = self.pt.rows([BOOT_FLAGS1, BOOT_FLAGS1 + 1, BOOT_FLAGS1 + 2])
        if not all(v & 0xF0F == want for v in got.values()):
            raise Fail(f"BOOT_FLAGS1 read-back: {[hex(v) for v in got.values()]}")
        say(f"  BOOT_FLAGS1 = {want:#06x} in all 3 copies")

    def lock_page4(self) -> None:
        self.to_bootsel()
        if self.pt.row(PAGE4_LOCK1) == PAGE4_LOCK1_VALUE:
            say("  page 4 already locked")
            return
        raw = self.pt.rows(list(range(IKM, IKM + 64)))
        if not all(raw[r] for r in range(IKM, IKM + 32)) or \
           not all(raw[CHAFF + i] == (~raw[IKM + i]) & 0xFFFFFF for i in range(32)):
            raise Fail("IKM and chaff not complete (stage 2): locking now would freeze them")
        del raw
        self.require_burn("stage 4 (page-4 lock)")
        self.pt.run("otp", "set", "-r", hex(PAGE4_LOCK1), hex(PAGE4_LOCK1_VALUE))
        if self.pt.row(PAGE4_LOCK1) != PAGE4_LOCK1_VALUE:
            raise Fail("PAGE4_LOCK1 read-back mismatch")
        self.pt.run("reboot", "-u", check=False)
        time.sleep(4)
        self.to_bootsel()
        if self.pt.row_readable(IKM):
            raise Fail("page 4 still readable from BOOTSEL after the lock")
        say("  PAGE4_LOCK1 = 0x3D3D3D; page 4 is unreadable from BOOTSEL")
        self.boot()
        if self.card.store_state() not in (0, 3):
            raise Fail("the keystore no longer opens after the lock")
        say(f"  firmware still derives its key: {self.card.prov_status()}")

    def secure_boot(self) -> None:
        a = self.args
        self.to_bootsel()
        crit = self.pt.rows(list(range(CRIT1, CRIT1 + 8)))
        if sum(1 for v in crit.values() if v & CRIT1_SECURE_BOOT) >= 3:
            say("  secure boot already enabled")
            return
        bf1 = self.pt.row(BOOT_FLAGS1)
        if not bf1 & 0xF:
            raise Fail("no boot key marked valid (stage 3)")
        if self.pt.row(PAGE4_LOCK1) != PAGE4_LOCK1_VALUE:
            raise Fail("page 4 not locked (stage 4)")
        if not a.table or not a.image:
            raise Fail("stage 5 needs --table <signed production table UF2> and --image <signed firmware UF2>")
        say("  installing the signed production table and the signed image...")
        self.pt.run("load", a.table)
        self.pt.run("reboot", "-u", check=False)
        time.sleep(4)
        self.to_bootsel()
        self.pt.run("load", "-p", str(a.slot), "-x", a.image)
        self.card.wait(True)
        time.sleep(2)
        say(f"  signed image boots before secure boot: {self.card.prov_status()}")
        self.to_bootsel()
        self.require_burn("stage 5 (SECURE BOOT: permanent; RISC-V permanently disabled)")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "secure-boot.json"
            p.write_text(json.dumps({"crit1": {"secure_boot_enable": 1}}))
            self.pt.run("otp", "load", str(p))
        crit = self.pt.rows(list(range(CRIT1, CRIT1 + 8)))
        if sum(1 for v in crit.values() if v & CRIT1_SECURE_BOOT) != 8:
            raise Fail(f"CRIT1 read-back: {[hex(v) for v in crit.values()]}")
        say("  CRIT1.SECURE_BOOT_ENABLE set in all 8 copies")
        self.boot()
        st = self.card.prov_status()
        if not st.get("secure_boot"):
            raise Fail(f"firmware does not see secure boot: {st}")
        say(f"  signed firmware boots with secure boot on: {st}")
        if a.unsigned_image:
            say("  negative test: an unsigned image must not boot...")
            self.to_bootsel()
            self.pt.run("load", "-p", str(a.slot), a.unsigned_image)
            self.pt.run("reboot", check=False)
            time.sleep(8)
            if self.card.present() or not self.pt.in_bootsel():
                raise Fail("the unsigned image booted, or the board is not back in BOOTSEL")
            say("  unsigned image refused (board fell back to BOOTSEL); restoring the signed image")
            self.pt.run("load", "-p", str(a.slot), "-x", a.image)
            self.card.wait(True)
            time.sleep(2)
            say(f"  signed image restored: {self.card.prov_status()}")

    def bootsel_trim(self) -> None:
        self.to_bootsel()
        want = BF0_DISABLE_UART_BOOT | BF0_DISABLE_OTP_BOOT
        cur = self.pt.rows([BOOT_FLAGS0, BOOT_FLAGS0 + 1, BOOT_FLAGS0 + 2])
        if all(v & want == want for v in cur.values()):
            say("  BOOTSEL already trimmed")
            return
        self.require_burn("stage 6 (BOOTSEL trimming)")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bootsel.json"
            p.write_text(json.dumps({"boot_flags0": {"disable_bootsel_uart_boot": 1, "disable_otp_boot": 1}}))
            self.pt.run("otp", "load", str(p))
        got = self.pt.rows([BOOT_FLAGS0, BOOT_FLAGS0 + 1, BOOT_FLAGS0 + 2])
        if not all(v & want == want for v in got.values()):
            raise Fail(f"BOOT_FLAGS0 read-back: {[hex(v) for v in got.values()]}")
        self.pt.run("reboot", "-u", check=False)
        time.sleep(4)
        self.to_bootsel()
        say("  UART boot and OTP boot disabled (3 copies); picotool still reaches BOOTSEL")
        self.boot()
        say(f"  firmware boots: {self.card.prov_status()}")

    def glitch(self) -> None:
        self.to_bootsel()
        crit = self.pt.rows(list(range(CRIT1, CRIT1 + 8)))
        if sum(1 for v in crit.values() if v & CRIT1_SECURE_BOOT) < 3:
            raise Fail("secure boot not enabled (stage 5)")
        if all(v & CRIT1_GLITCH_ENABLE for v in crit.values()):
            say("  glitch detector already enabled")
        else:
            self.require_burn("stage 7 (glitch detector)")
            with tempfile.TemporaryDirectory() as d:
                p = Path(d) / "glitch.json"
                p.write_text(json.dumps({"crit1": {"glitch_detector_enable": 1}}))
                self.pt.run("otp", "load", str(p))
            crit = self.pt.rows(list(range(CRIT1, CRIT1 + 8)))
            if not all(v & (CRIT1_GLITCH_ENABLE | CRIT1_SECURE_BOOT) == (CRIT1_GLITCH_ENABLE | CRIT1_SECURE_BOOT)
                       for v in crit.values()):
                raise Fail(f"CRIT1 read-back: {[hex(v) for v in crit.values()]}")
            say("  CRIT1.GLITCH_DETECTOR_ENABLE set in all 8 copies (default sensitivity)")
        cycles = self.args.soak
        say(f"  soak: {cycles} reboot cycles through BOOTSEL and the firmware...")
        for i in range(cycles):
            self.boot()
            self.card.prov_status()
            self.to_bootsel()
        self.boot()
        say(f"  {cycles} cycles clean: {self.card.prov_status()}")

    def production(self) -> None:
        a = self.args
        self.boot()
        st = self.card.prov_status()
        if st.get("production"):
            say("  production mode already set")
            return
        if not st.get("secure_boot"):
            raise Fail("secure boot is not on (stage 5): the firmware would refuse anyway")
        if not a.so_pin_file:
            raise Fail("stage 8 needs --so-pin-file (16 hex digits; the device must be initialised)")
        so = Path(a.so_pin_file).read_text().strip()
        if not re.fullmatch(r"[0-9A-Fa-f]{16}", so):
            raise Fail("the SO-PIN file must hold 16 hex digits")
        self.require_burn("stage 8 (production mode)")
        r = self.card.apdus(SELECT_SC_HSM, "0020008808" + so, "80F1000000")
        if r[1][1] != 0x9000:
            raise Fail(f"SO-PIN verify: {r[1][1]:04X}")
        if r[2][1] != 0x9000:
            raise Fail(f"SET PRODUCTION MODE: {r[2][1]:04X}")
        self.to_bootsel()
        self.boot()
        st = self.card.prov_status()
        if not st.get("production"):
            raise Fail(f"production flag not visible after reboot: {st}")
        say(f"  production mode set; firmware boots: {st}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--serial", required=True, help="the board's USB serial (its chip ID, hex)")
    ap.add_argument("--picotool", default=shutil.which("picotool") or "picotool")
    ap.add_argument("--burn", action="store_true", help="allow permanent OTP writes")
    ap.add_argument("--table", help="stage 5: signed production partition table UF2")
    ap.add_argument("--image", help="stage 5: signed firmware UF2")
    ap.add_argument("--slot", type=int, default=0, help="stage 5: partition index of firmware slot A (default 0)")
    ap.add_argument("--unsigned-image", help="stage 5: also check an unsigned image is refused")
    ap.add_argument("--soak", type=int, default=10, help="stage 7: reboot cycles (default 10)")
    ap.add_argument("--so-pin-file", help="stage 8: file holding the SO-PIN (16 hex digits)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    s = sub.add_parser("stage")
    s.add_argument("which")
    t = sub.add_parser("through")
    t.add_argument("last", type=int)
    args = ap.parse_args()
    dev = Device(args)
    fns = [dev.preflight, dev.bootkeys, dev.ikm, dev.key_slots, dev.lock_page4,
           dev.secure_boot, dev.bootsel_trim, dev.glitch, dev.production]
    try:
        if args.cmd == "status":
            dev.status()
            return 0
        if args.cmd == "stage":
            w = args.which
            idx = int(w) if w.isdigit() else STAGES.index(w)
            todo = [idx]
        else:
            todo = list(range(0, args.last + 1))
        for i in todo:
            say(f"== stage {i}: {STAGES[i]}")
            fns[i]()
        say("done")
        return 0
    except Fail as e:
        say(f"STOPPED: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
