"""Hardware tests: the RSA key pool (pre-generated RSA keys, idle-time fill).

One device, `rsa` firmware.  Covers:

  - RSA_POOL_STATUS (80 54 50, no PIN): format, defaults, RNG and region
    health bits; INITIALIZE empties the pool;
  - the pool fills in idle time to its configured depth;
  - GENERATE KEY PAIR for RSA-2048/3072/4096 takes a pooled key: it
    answers in under POOL_GENERATE_MAX_SECS (default 5 s), the status shows
    one more issued key, and the key signs (SHA-256 PKCS#1 v1.5, on the
    card) and verifies (on the host, with the modulus from the CVC);
  - APDU latency while the pool is filling: SELECT and GET CHALLENGE
    round trips stay below POOL_LATENCY_MAX_MS (default 500 ms; a pool
    sector erase, typically ~45 ms and at most 400 ms per the flash
    datasheets, is the only long step an APDU can wait for) and their
    median below POOL_LATENCY_MEDIAN_MS (default 60 ms);
  - RSA_POOL_CONFIG (80 54 51, SO-PIN): refused without the SO-PIN;
    turning the pool off erases every pooled key; live keygen still works;
    turning it back on refills;
  - a reset (probe-rs) while the pool is filling: the device comes back,
    keeps the keys it had, and goes on filling.

Environment:
  POOL_FILL_TIMEOUT       seconds to wait for a full pool (default 1800)
  POOL_GENERATE_MAX_SECS  pooled GENERATE limit (default 5)
  POOL_LATENCY_MAX_MS     worst SELECT / GET CHALLENGE round trip (500)
  POOL_LATENCY_MEDIAN_MS  median round trip (60)
  PROBE_RS_PROBE          probe selector for the reset test (optional)
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import statistics
import struct
import subprocess
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from helpers.pcsc import apdu, session

log = logging.getLogger(__name__)

pytestmark = pytest.mark.hw

SELECT_SC_HSM = "00A404000BE82B0601040181C31F020100"
SIZES = (2048, 3072, 4096)
# Key references for the GENERATE tests (clear of the other modules' slots).
KEY_REF = {2048: 0x31, 3072: 0x32, 4096: 0x33}

FILL_TIMEOUT = float(os.environ.get("POOL_FILL_TIMEOUT", "1800"))
GENERATE_MAX = float(os.environ.get("POOL_GENERATE_MAX_SECS", "5"))
LATENCY_MAX_MS = float(os.environ.get("POOL_LATENCY_MAX_MS", "500"))
LATENCY_MEDIAN_MS = float(os.environ.get("POOL_LATENCY_MEDIAN_MS", "60"))


# ---------------------------------------------------------------------------
# Wire formats (docs/SC_HSM_APDU_REFERENCE.md, "RSA key pool")
# ---------------------------------------------------------------------------

class PoolStatus:
    """RSA_POOL_STATUS, 43 bytes, big-endian."""

    def __init__(self, raw: bytes):
        assert len(raw) == 43, f"status is {len(raw)} bytes, want 43"
        self.raw = raw
        self.version = raw[0]
        self.health = raw[1]
        self.flags = raw[2]
        self.max_age_min = struct.unpack(">I", raw[3:7])[0]
        self.depth = dict(zip(SIZES, raw[7:10]))
        self.ready = dict(zip(SIZES, raw[10:13]))
        self.generating_bits = struct.unpack(">H", raw[13:15])[0]
        self.clock_min = struct.unpack(">Q", raw[15:23])[0]
        (self.seq, self.generated, self.rotated, self.issued, self.live) = struct.unpack(
            ">IIIII", raw[23:43])

    @property
    def enabled(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def rotate(self) -> bool:
        return bool(self.flags & 0x02)

    @property
    def full(self) -> bool:
        return all(self.ready[s] >= self.depth[s] for s in SIZES)

    def __repr__(self) -> str:
        return (f"PoolStatus(health={self.health:#x} flags={self.flags:#x} "
                f"max_age={self.max_age_min} depth={self.depth} ready={self.ready} "
                f"generating={self.generating_bits} clock={self.clock_min} seq={self.seq} "
                f"generated={self.generated} rotated={self.rotated} issued={self.issued} "
                f"live={self.live})")


def config_bytes(flags: int, max_age_min: int, depth: tuple[int, int, int]) -> bytes:
    return bytes([flags]) + struct.pack(">I", max_age_min) + bytes(depth)


DEFAULT_CONFIG = config_bytes(0x03, 240, (4, 2, 2))


def status(s) -> PoolStatus:
    return PoolStatus(s.ok(apdu(0x80, 0x54, 0x50, 0x00)))


def verify_pin(s, config) -> None:
    s.ok(apdu(0x00, 0x20, 0x00, 0x81, config["pin"].encode()))


def verify_so_pin(s, config) -> None:
    s.ok(apdu(0x00, 0x20, 0x00, 0x88, bytes.fromhex(config["so_pin"])))


def gakp_rsa(bits: int) -> bytes:
    """GENERATE KEY PAIR data as OpenSC sends it for RSA (modulus size in 7F49)."""
    pk = b"\x02\x02" + bits.to_bytes(2, "big")
    return b"\x5F\x29\x01\x00" + b"\x7F\x49" + bytes([len(pk)]) + pk


def tlvs(data: bytes):
    """Walk a BER-TLV sequence (1- or 2-byte tags, lengths up to 82 xx xx),
    as OpenSC's CVC decoder does: yields (tag, value)."""
    i = 0
    while i < len(data):
        tag = data[i:i + 1]
        i += 1
        if tag[0] & 0x1F == 0x1F:
            tag += data[i:i + 1]
            i += 1
        ln = data[i]
        i += 1
        if ln & 0x80:
            n = ln & 0x7F
            assert 1 <= n <= 2, f"length form {ln:#x}"
            ln = int.from_bytes(data[i:i + n], "big")
            i += n
        assert i + ln <= len(data), "truncated TLV"
        yield tag, data[i:i + ln]
        i += ln


def find_tlv(data: bytes, path: list[bytes]) -> bytes | None:
    """The value at a path of tags, e.g. [67, 7F21, 7F4E, 7F49]."""
    for want in path:
        for tag, value in tlvs(data):
            if tag == want:
                data = value
                break
        else:
            return None
    return data


def public_key_from_cvc(cvc: bytes, bits: int) -> rsa.RSAPublicKey:
    pk = find_tlv(cvc, [b"\x67", b"\x7F\x21", b"\x7F\x4E", b"\x7F\x49"])
    assert pk is not None, "no 67/7F21/7F4E/7F49 in the GENERATE response"
    fields = dict(tlvs(pk))  # 06 OID, 81 modulus, 82 exponent
    assert b"\x06" in fields, "no algorithm OID in 7F49"
    n, e = fields.get(b"\x81"), fields.get(b"\x82")
    assert n is not None and e is not None
    assert len(n) * 8 == bits, f"modulus is {len(n) * 8} bits, want {bits}"
    assert int.from_bytes(e, "big") == 65537, f"exponent {e.hex()}"
    return rsa.RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key()


def generate(s, bits: int) -> tuple[rsa.RSAPublicKey, float]:
    t0 = time.monotonic()
    data, sw = s.send(apdu(0x00, 0x46, KEY_REF[bits], 0x00, gakp_rsa(bits)))
    dt = time.monotonic() - t0
    assert sw == 0x9000, f"GENERATE RSA-{bits}: SW={sw:04X}"
    return public_key_from_cvc(data, bits), dt


def sign_and_verify(s, bits: int, pub: rsa.RSAPublicKey) -> None:
    msg = f"pico2hsm RSA key pool {bits}".encode()
    sig = s.ok(apdu(0x00, 0x68, KEY_REF[bits], 0x33, msg))
    assert len(sig) == bits // 8
    pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())


def wait_for(pred, timeout: float, what: str, poll: float = 5.0) -> PoolStatus:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        with session() as s:
            s.ok(SELECT_SC_HSM)
            last = status(s)
        log.info("waiting for %s: %r", what, last)
        if pred(last):
            return last
        time.sleep(poll)
    pytest.fail(f"timed out after {timeout:.0f} s waiting for {what}; last {last!r}")


def initialize(config) -> None:
    r = subprocess.run(
        ["sc-hsm-tool", "--initialize", "--label", config["label"],
         "--so-pin", config["so_pin"], "--pin", config["pin"]],
        capture_output=True, timeout=120)
    assert r.returncode == 0, r.stderr.decode(errors="replace")


@pytest.fixture(scope="module")
def device(config):
    """A freshly initialised device with the default pool configuration."""
    with session() as s:
        s.ok(SELECT_SC_HSM)
        st = status(s)
        log.info("before: %r", st)
        if st.raw[2:10] != DEFAULT_CONFIG:
            # Leave the factory setting for the tests (needs the SO-PIN of
            # the current initialisation).
            verify_so_pin(s, config)
            s.ok(apdu(0x80, 0x54, 0x51, 0x00, DEFAULT_CONFIG))
    initialize(config)
    return config


class TestRsaPool:
    def test_status_after_initialize(self, device):
        with session() as s:
            s.ok(SELECT_SC_HSM)
            st = status(s)
        log.info("%r", st)
        assert st.version == 1
        assert st.health & 0x01, "RNG health check did not pass at boot"
        assert st.health & 0x02, "pool region missing (firmware built without rsa?)"
        assert not st.health & 0x04, "background filling stopped after write failures"
        assert not st.health & 0x08, "pool configuration / clock unreadable (fail-closed)"
        assert st.enabled and st.rotate
        assert st.max_age_min == 240
        assert st.depth == {2048: 4, 3072: 2, 4096: 2}
        # INITIALIZE is a trust reset: no pooled key survives it.  (A key
        # finished since then may already be there.)
        assert sum(st.ready.values()) <= 1

    def test_status_needs_no_pin_and_config_needs_the_so_pin(self, device):
        with session() as s:
            s.ok(SELECT_SC_HSM)
            status(s)
            _, sw = s.send(apdu(0x80, 0x54, 0x51, 0x00, DEFAULT_CONFIG))
            assert sw == 0x6982
            verify_pin(s, device)  # the user PIN is not enough
            _, sw = s.send(apdu(0x80, 0x54, 0x51, 0x00, DEFAULT_CONFIG))
            assert sw == 0x6982
            verify_so_pin(s, device)
            # Malformed: too short, depth > 4, max age < 60 min, unknown flag.
            for bad in (DEFAULT_CONFIG[:7], config_bytes(3, 240, (5, 2, 2)),
                        config_bytes(3, 59, (4, 2, 2)), config_bytes(0x83, 240, (4, 2, 2))):
                _, sw = s.send(apdu(0x80, 0x54, 0x51, 0x00, bad))
                assert sw in (0x6700, 0x6A80), f"{bad.hex()}: {sw:04X}"

    def test_latency_while_filling(self, device):
        """SELECT / GET CHALLENGE stay responsive while keys are generated."""
        times: list[float] = []
        with session() as s:
            s.ok(SELECT_SC_HSM)
            st = status(s)
            if st.full:
                pytest.skip("pool already full: nothing is being generated")
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                for cmd in (SELECT_SC_HSM, "0084000020"):
                    t0 = time.monotonic()
                    s.ok(cmd)
                    times.append((time.monotonic() - t0) * 1000)
                time.sleep(0.05)
            st = status(s)
        times.sort()
        median = statistics.median(times)
        p99 = times[int(len(times) * 0.99) - 1]
        log.info("round trips: n=%d median=%.1f ms p99=%.1f ms max=%.1f ms; %r",
                 len(times), median, p99, times[-1], st)
        assert times[-1] < LATENCY_MAX_MS, f"slowest round trip {times[-1]:.0f} ms"
        assert median < LATENCY_MEDIAN_MS, f"median round trip {median:.0f} ms"

    def test_pool_fills(self, device):
        st = wait_for(lambda st: st.full, FILL_TIMEOUT, "a full pool", poll=10)
        log.info("full: %r", st)
        assert st.generating_bits == 0
        assert st.generated >= sum(st.depth.values())

    @pytest.mark.parametrize("bits", SIZES)
    def test_generate_takes_a_pooled_key(self, device, bits):
        with session() as s:
            s.ok(SELECT_SC_HSM)
            before = status(s)
            if before.ready[bits] == 0:
                pytest.skip(f"no pooled RSA-{bits} key (run test_pool_fills first)")
            verify_pin(s, device)
            pub, dt = generate(s, bits)
            after = status(s)
            log.info("RSA-%d GENERATE from the pool: %.2f s; %r", bits, dt, after)
            assert after.issued == before.issued + 1
            assert after.live == before.live
            assert dt < GENERATE_MAX, f"pooled RSA-{bits} GENERATE took {dt:.1f} s"
            sign_and_verify(s, bits, pub)

    def test_disabling_wipes_the_pool_and_live_keygen_works(self, device):
        with session() as s:
            s.ok(SELECT_SC_HSM)
            verify_so_pin(s, device)
            st = PoolStatus(s.ok(apdu(0x80, 0x54, 0x51, 0x00,
                                      config_bytes(0x02, 240, (4, 2, 2)))))
            log.info("disabled: %r", st)
            assert not st.enabled
            assert st.ready == {2048: 0, 3072: 0, 4096: 0}
            time.sleep(3)
            st = status(s)
            assert st.ready == {2048: 0, 3072: 0, 4096: 0}
            assert st.generating_bits == 0, "pool off but still generating"
            # Live keygen (the sliced generator in the APDU) still works.
            verify_pin(s, device)
            pub, dt = generate(s, 2048)
            log.info("live RSA-2048 GENERATE with the pool off: %.1f s", dt)
            assert status(s).live == st.live + 1
            sign_and_verify(s, 2048, pub)
            # Back on: it refills.
            verify_so_pin(s, device)
            st = PoolStatus(s.ok(apdu(0x80, 0x54, 0x51, 0x00, DEFAULT_CONFIG)))
            assert st.enabled
        wait_for(lambda st: st.ready[2048] >= 1 or st.generating_bits != 0, 120,
                 "the pool to start refilling", poll=2)

    def test_reset_during_fill_recovers(self, device):
        if shutil.which("probe-rs") is None:
            pytest.skip("probe-rs not installed")
        # Do not depend on the previous test having switched the pool back
        # on (it may have failed half-way): set the factory configuration.
        with session() as s:
            s.ok(SELECT_SC_HSM)
            verify_so_pin(s, device)
            st = PoolStatus(s.ok(apdu(0x80, 0x54, 0x51, 0x00, DEFAULT_CONFIG)))
            assert st.enabled, f"pool not enabled: {st!r}"
        st = wait_for(lambda st: st.generating_bits != 0 and not st.full, 600,
                      "a key being generated", poll=1)
        kept = dict(st.ready)
        subprocess.run(["pkill", "-f", "probe-rs run"], capture_output=True, timeout=5)
        cmd = ["probe-rs", "reset", "--chip", "RP235x"]
        if os.environ.get("PROBE_RS_PROBE"):
            cmd += ["--probe", os.environ["PROBE_RS_PROBE"]]
        subprocess.run(cmd, capture_output=True, timeout=20)
        time.sleep(int(os.environ.get("PERSISTENCE_REBOOT_WAIT", "12")))
        after = wait_for(lambda st: True, 60, "the device after the reset", poll=2)
        log.info("after reset: %r (before %r)", after, st)
        assert after.health & 0x03 == 0x03
        assert not after.health & 0x04
        # Completed keys survive; the partial one is simply regenerated.
        for b in SIZES:
            assert after.ready[b] >= min(kept[b], after.depth[b]) or after.clock_min > st.clock_min
        assert after.clock_min >= st.clock_min, "pool clock went backwards"
        wait_for(lambda s2: s2.generated >= 1 or s2.full, FILL_TIMEOUT,
                 "a key pooled after the reset", poll=10)
        with session() as s:
            s.ok(SELECT_SC_HSM)
            verify_pin(s, device)
            pub, _ = generate(s, 2048)
            sign_and_verify(s, 2048, pub)
