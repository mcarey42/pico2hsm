"""Hardware tests: cluster plan V3 phase P1 (domains foundations).

One device.  Checks, against the independent Python reference
`tools/python/pico2hsm/domain.py`:

  - DOMAIN_STATUS (80 54 40) before any DKEK: no domain, own member ID =
    SHA-256(device key)[0:16];
  - after importing two known raw DKEK shares (the KAT shares of
    `firmware/tests/vectors/domain_v1.txt`): domain_id, KCV and Q_domain
    equal the reference, and the device has certified itself;
  - GET_MEMBERS (80 54 47): the self certificate verifies under Q_domain
    on the host;
  - the Lamport counter (80 54 3C) grows on GENERATE KEY PAIR and DELETE,
    and survives a reset (probe-rs, as test_14 does it);
  - GET_KEY_MANIFEST v2 (80 54 39, data 02): object ID = SHA-1(x), the
    OpenSC CKA_ID.

The V2 DKEK exchange with the single-use pinned peer is covered by
test_10_cluster_dkek_exchange.py (two devices).
"""

from __future__ import annotations

import hashlib
import importlib.util
import logging
import pathlib
import shutil
import struct
import subprocess
import sys

import pytest

from helpers.pcsc import apdu, session

log = logging.getLogger(__name__)

pytestmark = pytest.mark.hw

ROOT = pathlib.Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "domain_ref", ROOT / "tools" / "python" / "pico2hsm" / "domain.py")
dom = importlib.util.module_from_spec(_spec)
sys.modules["domain_ref"] = dom
_spec.loader.exec_module(dom)

SELECT_SC_HSM = "00A404000BE82B0601040181C31F020100"
# The KAT shares of domain_v1.txt / cardcontact_wrap.txt.
SHARE1 = hashlib.sha256(b"pico2hsm KAT DKEK share 1").digest()
SHARE2 = hashlib.sha256(b"pico2hsm KAT DKEK share 2").digest()
P256_ORDER = bytes.fromhex(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
KEY_REF = 0x21


def _status(s) -> "dom.DomainStatus":
    return dom.parse_domain_status(s.ok(apdu(0x80, 0x54, 0x40, 0x00)))


def _lamport(s) -> int:
    return struct.unpack(">Q", s.ok(apdu(0x80, 0x54, 0x3C, 0x00)))[0]


def _verify_pin(s, config) -> None:
    s.ok(apdu(0x00, 0x20, 0x00, 0x81, config["pin"].encode()))


def _gakp_p256() -> bytes:
    pk = b"\x85\x20" + P256_ORDER
    return b"\x5F\x29\x01\x00" + b"\x7F\x49" + bytes([len(pk)]) + pk


@pytest.fixture(scope="module")
def device(config):
    """INITIALIZE for two DKEK shares; nothing imported yet."""
    r = subprocess.run(
        ["sc-hsm-tool", "--initialize", "--label", config["label"],
         "--so-pin", config["so_pin"], "--pin", config["pin"], "--dkek-shares", "2"],
        capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    with session() as s:
        s.ok(SELECT_SC_HSM)
        pub = s.ok(apdu(0x80, 0x54, 0x30, 0x00))
    assert len(pub) == 65
    return {"pub": pub}


class TestDomainP1:
    def test_status_before_the_dkek(self, device):
        with session() as s:
            s.ok(SELECT_SC_HSM)
            st = _status(s)
        assert not st.has_dkek
        assert st.domain_id == bytes(16) and st.q_domain == bytes(65)
        assert st.member_id == dom.member_id(device["pub"])
        assert st.members == 0 and st.capacity == 32
        log.info("before DKEK: lamport=%d production=%s", st.lamport, st.production)

    def test_known_shares_give_the_reference_domain(self, device):
        dkek = dom.combine_shares(SHARE1, SHARE2)
        with session() as s:
            s.ok(SELECT_SC_HSM)
            before = _lamport(s)
            for share in (SHARE1, SHARE2):
                s.ok(apdu(0x80, 0x52, 0x00, 0x00, share))
            st = _status(s)
        q = dom.domain_q(dkek)
        assert st.has_dkek and st.self_member
        assert st.domain_id == dom.domain_id(q), "domain_id = Python reference"
        assert st.kcv == dom.kcv(dkek)
        assert st.q_domain == q
        assert st.members == 1
        assert st.lamport == before + 1, "the self certificate was numbered"
        log.info("domain_id %s KCV %s", st.domain_id.hex(), st.kcv.hex())

    def test_self_member_certificate_verifies_on_the_host(self, device):
        with session() as s:
            s.ok(SELECT_SC_HSM)
            st = _status(s)
            total, first, entries = dom.parse_members_page(
                s.ok(apdu(0x80, 0x54, 0x47, 0x00)))
        assert (total, first, len(entries)) == (1, 0, 1)
        e = entries[0]
        assert e.status == dom.STATUS_ACTIVE
        assert e.cert.member_pub == device["pub"]
        assert e.cert.member_id == e.cert.sponsor_id == st.member_id
        assert e.cert.flags & dom.FLAG_MAY_SPONSOR
        assert e.cert.verify(st.q_domain), "sig_domain verifies under Q_domain"

    def test_lamport_counts_generate_and_delete(self, device, config):
        with session() as s:
            s.ok(SELECT_SC_HSM)
            _verify_pin(s, config)
            n0 = _lamport(s)
            s.ok(apdu(0x00, 0x46, KEY_REF, 0x00, _gakp_p256(), le=0))
            n1 = _lamport(s)
            # The V1 call returns the low 32 bits of the same counter.
            assert struct.unpack(">I", s.ok(apdu(0x80, 0x54, 0x34, 0x00)))[0] == n1 & 0xFFFFFFFF
            s.ok(apdu(0x00, 0xE4, 0x02, 0x00, bytes([0xCC, KEY_REF])))
            n2 = _lamport(s)
        assert n1 == n0 + 1 and n2 == n1 + 1, (n0, n1, n2)

    def test_manifest_v2_lists_the_opensc_ckaid(self, device, config):
        with session() as s:
            s.ok(SELECT_SC_HSM)
            _verify_pin(s, config)
            s.ok(apdu(0x00, 0x46, KEY_REF, 0x00, _gakp_p256(), le=0))
            pages = []
            p2 = 0
            while True:
                page = s.ok(apdu(0x80, 0x54, 0x39, p2, b"\x02"))
                if not page:
                    break
                pages.append(page)
                p2 = page[-64] + 1
            entries = [p[i:i + 64] for p in pages for i in range(0, len(p), 64)]
            mine = [e for e in entries if e[0] == KEY_REF]
            assert len(mine) == 1
            # A raw GENERATE writes no PRKD, so the device synthesises one.
            prkd =s.ok(apdu(0x00, 0xB1, 0x00, 0x00, bytes([0x54, 0x04, 0xC4, KEY_REF, 0, 0])))
            s.ok(apdu(0x00, 0xE4, 0x02, 0x00, bytes([0xCC, KEY_REF])))
        e = mine[0]
        assert e[3] == 20, "intrinsic ID"
        object_id = e[44:64]
        # The synthesised PRKD carries the same ID as CKA_ID (04 14 <id>).
        assert bytes([0x04, 0x14]) + object_id in prkd

    @pytest.mark.skipif(shutil.which("probe-rs") is None, reason="needs probe-rs")
    def test_lamport_survives_a_reset(self, device, config):
        from test_14_persistence import _reset_device

        with session() as s:
            s.ok(SELECT_SC_HSM)
            before = _lamport(s)
        _reset_device()
        with session() as s:
            s.ok(SELECT_SC_HSM)
            after = _lamport(s)
            st = _status(s)
            _verify_pin(s, config)
            s.ok(apdu(0x00, 0x46, KEY_REF, 0x00, _gakp_p256(), le=0))
            bumped = _lamport(s)
            s.ok(apdu(0x00, 0xE4, 0x02, 0x00, bytes([0xCC, KEY_REF])))
        assert after == before, "persisted, not reset at boot"
        assert bumped == before + 1
        # The domain key is re-derived from the persisted DKEK at boot.
        assert st.domain_id == dom.domain_id(dom.domain_q(dom.combine_shares(SHARE1, SHARE2)))
        assert st.self_member and st.members == 1, "no second self certificate"
