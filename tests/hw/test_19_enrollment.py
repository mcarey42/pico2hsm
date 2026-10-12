"""Hardware tests: cluster plan V3 phase P2 (enrollment), two devices.

Requires TWO pico2hsm devices (readers 0 and 1).  Every test sets up its
own state from INITIALIZE (sc-hsm-tool), then keeps ONE PC/SC session per
device for all of its steps: the V2 exchange state, and the right to
certify the peer it served, live in the card session (cleared when the
host session ends, like the SO-PIN).

Covered:
  1. reader 1 enrolled through reader 0 (pin, V2 exchange, ISSUE_MEMBER_CERT,
     member lists copied both ways) -- both lists hold both members, every
     certificate verifies on the host under Q_domain;
  2. REVOKE_MEMBER on reader 0, IMPORT_REVOCATION on reader 1;
  3. re-enrolling the revoked device is refused (exchange 6985, ISSUE 6984,
     certificate import 6984); after re-INITIALIZE the device has a NEW
     member key (INITIALIZE generates it), so it can enroll again only as a
     new member, through a sponsor's SO-PIN and the SAS check -- the old
     member ID stays revoked;
  4. a device formed independently from the same shares imports the
     members (and the other way round), and a sponsor certifies it through
     a pinned key (§5.3);
  5. optional: the same through `pico2hsm-tool domain enroll`, local and
     remote mode (set PICO2HSM_TOOL to the binary).

Independent reference for every check: tools/python/pico2hsm/domain.py.
"""

from __future__ import annotations

import hashlib
import importlib.util
import logging
import os
import pathlib
import subprocess
import sys
import time

import pytest

from helpers.pcsc import session

log = logging.getLogger(__name__)

pytestmark = pytest.mark.hw

ROOT = pathlib.Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "domain_ref", ROOT / "tools" / "python" / "pico2hsm" / "domain.py")
dom = importlib.util.module_from_spec(_spec)
sys.modules["domain_ref"] = dom
_spec.loader.exec_module(dom)

SELECT_SC_HSM = "00A404000BE82B0601040181C31F020100"
SHARE1 = hashlib.sha256(b"pico2hsm P2 enrollment share 1").digest()
SHARE2 = hashlib.sha256(b"pico2hsm P2 enrollment share 2").digest()

SW_OK = 0x9000
SW_CONDITIONS = 0x6985
SW_REVOKED = 0x6984
SW_ALREADY = 0x6A89


@pytest.fixture(scope="module", autouse=True)
def require_two_readers():
    try:
        from smartcard.System import readers
        n = len(readers())
    except Exception:
        n = 0
    if n < 2:
        pytest.skip(f"two pico2hsm devices required; {n} reader(s) found")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def x(s, p1: int, data: bytes = b"", p2: int = 0) -> tuple[bytes, int]:
    """80 54 p1 p2 [data] (extended Lc above 255 bytes)."""
    a = bytes([0x80, 0x54, p1, p2])
    if len(data) > 255:
        a += b"\x00" + len(data).to_bytes(2, "big") + data
    elif data:
        a += bytes([len(data)]) + data
    return s.send(a)


def ok(s, p1: int, data: bytes = b"", p2: int = 0) -> bytes:
    r, sw = x(s, p1, data, p2)
    assert sw == SW_OK, f"80 54 {p1:02X}: SW={sw:04X}"
    return r


def initialize(reader: int, config: dict, shares: int) -> None:
    r = subprocess.run(
        ["sc-hsm-tool", "-r", str(reader), "--initialize", "--label", config["label"],
         "--so-pin", config["so_pin"], "--pin", config["pin"],
         "--dkek-shares", str(shares)],
        capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    time.sleep(3)  # USB re-enumeration


def open_dev(s, config: dict) -> bytes:
    """SELECT, VERIFY SO-PIN; return the member key."""
    s.ok(SELECT_SC_HSM)
    s.ok(bytes([0x00, 0x20, 0x00, 0x88, 0x08]) + bytes.fromhex(config["so_pin"]))
    pub = ok(s, 0x30)
    assert len(pub) == 65
    return pub


def status(s) -> "dom.DomainStatus":
    return dom.parse_domain_status(ok(s, 0x40))


def members(s) -> list:
    out, first = [], 0
    while True:
        total, first_, entries = dom.parse_members_page(ok(s, 0x47, b"\x02", p2=first),
                                                         v2=True)
        out += entries
        first = first_ + len(entries)
        if not entries or first >= total:
            return out


def verified(entries: list, q: bytes) -> None:
    for e in entries:
        assert e.cert.verify(q), f"certificate of {e.cert.member_id.hex()}"
        if e.status == dom.STATUS_REVOKED:
            assert e.revocation is not None and e.revocation.verify(q)


def exchange(src, tgt, sp: bytes, tp: bytes) -> None:
    """Pin each other, V2 exchange src -> tgt (same sessions throughout)."""
    ok(src, 0x3D, tp)
    ok(tgt, 0x3D, sp)
    init = ok(tgt, 0x35, sp)
    resp = ok(src, 0x36, init)
    enc = ok(src, 0x37, init[:65] + tp + init[65:97])
    ok(tgt, 0x38, resp + enc)


def copy_members(frm, to, q: bytes) -> None:
    """Every certificate, then every revocation (with its certificate)."""
    entries = members(frm)
    verified(entries, q)
    for e in sorted(entries, key=lambda e: e.status):
        if e.status == dom.STATUS_REVOKED:
            _, sw = x(to, 0x4A, e.revocation.encode() + e.cert.encode())
        else:
            _, sw = x(to, 0x49, e.cert.encode())
        assert sw in (SW_OK, SW_ALREADY), f"import {e.cert.member_id.hex()}: {sw:04X}"


def enroll(s0, s1, p0: bytes, p1: bytes) -> "dom.MemberCert":
    """Reader 1 joins through reader 0 (sessions open, SO-PIN verified)."""
    log.info("SAS %s", dom.sas(p0, p1))
    exchange(s0, s1, p0, p1)
    st0, st1 = status(s0), status(s1)
    assert st1.domain_id == st0.domain_id and st1.kcv == st0.kcv
    cert = dom.parse_cert(ok(s0, 0x45, p1))
    assert cert.verify(st0.q_domain)
    assert cert.member_pub == p1 and cert.member_id == dom.member_id(p1)
    assert cert.sponsor_id == dom.member_id(p0)
    assert cert.flags & dom.FLAG_MAY_SPONSOR
    copy_members(s0, s1, st0.q_domain)
    copy_members(s1, s0, st0.q_domain)
    return cert


def setup_pair(config: dict) -> None:
    """Reader 0 forms a domain from SHARE1+SHARE2; reader 1 is fresh."""
    initialize(0, config, 2)
    initialize(1, config, 1)
    with session(0) as s:
        s.ok(SELECT_SC_HSM)
        for share in (SHARE1, SHARE2):
            ok_share(s, share)


def ok_share(s, share: bytes) -> None:
    _, sw = s.send(bytes([0x80, 0x52, 0x00, 0x00, 32]) + share)
    assert sw == SW_OK, f"share import SW={sw:04X}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_enroll_reader1_through_reader0(config):
    setup_pair(config)
    with session(0) as s0, session(1) as s1:
        p0, p1 = open_dev(s0, config), open_dev(s1, config)
        lamport = status(s0).lamport
        cert = enroll(s0, s1, p0, p1)
        assert cert.issued_lamport == lamport + 1, "numbered on the sponsor"
        q = status(s0).q_domain
        for s in (s0, s1):
            entries = members(s)
            verified(entries, q)
            ids = {e.cert.member_id for e in entries}
            assert ids == {dom.member_id(p0), dom.member_id(p1)}
        # The joiner holds the sponsor's certificate, not its self certificate.
        mine = next(e for e in members(s1) if e.cert.member_id == dom.member_id(p1))
        assert mine.cert.sponsor_id == dom.member_id(p0)
        # The binding was single use.
        _, sw = x(s0, 0x45, p1)
        assert sw == SW_CONDITIONS


def test_revoke_and_carry_the_revocation(config):
    setup_pair(config)
    with session(0) as s0, session(1) as s1:
        p0, p1 = open_dev(s0, config), open_dev(s1, config)
        enroll(s0, s1, p0, p1)
        q = status(s0).q_domain
        id1 = dom.member_id(p1)
        _, sw = x(s0, 0x46, dom.member_id(p0))
        assert sw == 0x6A80, "a device cannot revoke itself"
        rev = dom.parse_revocation(ok(s0, 0x46, id1))
        assert rev.verify(q)
        assert (rev.member_id, rev.revoker_id) == (id1, dom.member_id(p0))
        r, sw = x(s1, 0x4A, rev.encode())
        assert sw == SW_OK and r == b"\x00", "marked revoked on reader 1"
        _, sw = x(s1, 0x4A, rev.encode())
        assert sw == SW_ALREADY
        for s in (s0, s1):
            e = next(e for e in members(s) if e.cert.member_id == id1)
            assert e.status == dom.STATUS_REVOKED
            assert e.revocation.encode() == rev.encode()
        assert status(s1).flags & 0x20, "reader 1 knows it is revoked"


def test_reenrolling_a_revoked_device_is_refused(config):
    setup_pair(config)
    with session(0) as s0, session(1) as s1:
        p0, p1 = open_dev(s0, config), open_dev(s1, config)
        enroll(s0, s1, p0, p1)
        id1 = dom.member_id(p1)
        ok(s0, 0x46, id1)
        mine = next(e for e in members(s1) if e.cert.member_id == id1)

        # The device still holds the DKEK: no exchange.
        ok(s1, 0x3D, p0)
        _, sw = x(s1, 0x35, p0)
        assert sw == SW_CONDITIONS
        # The sponsor never certifies a revoked member, however it is pinned.
        ok(s0, 0x3D, p1)
        _, sw = x(s0, 0x45, p1)
        assert sw == SW_REVOKED
        # Nor does it re-admit it from a certificate (any Lamport value).
        _, sw = x(s0, 0x49, mine.cert.encode())
        assert sw == SW_REVOKED

    # Re-INITIALIZE: INITIALIZE generates a new device key, so the device
    # comes back as a NEW member, and only through the full enrollment
    # (sponsor SO-PIN + SAS).  The old member ID stays revoked.
    initialize(1, config, 1)
    with session(0) as s0, session(1) as s1:
        p0, p1b = open_dev(s0, config), open_dev(s1, config)
        assert dom.member_id(p1b) != id1, "INITIALIZE gave a new member key"
        enroll(s0, s1, p0, p1b)
        by_id = {e.cert.member_id: e for e in members(s0)}
        assert by_id[id1].status == dom.STATUS_REVOKED
        assert by_id[dom.member_id(p1b)].status == dom.STATUS_ACTIVE
        # The new joiner learnt the revocation too.
        assert {e.cert.member_id: e.status for e in members(s1)}[id1] == dom.STATUS_REVOKED


def test_device_formed_from_the_same_shares_imports_the_members(config):
    initialize(0, config, 2)
    initialize(1, config, 2)
    with session(0) as s0, session(1) as s1:
        for s in (s0, s1):
            s.ok(SELECT_SC_HSM)
            for share in (SHARE1, SHARE2):
                ok_share(s, share)
        p0, p1 = open_dev(s0, config), open_dev(s1, config)
        st0, st1 = status(s0), status(s1)
        assert st0.domain_id == st1.domain_id and st0.member_id != st1.member_id
        assert st0.self_member and st1.self_member
        copy_members(s0, s1, st0.q_domain)
        copy_members(s1, s0, st0.q_domain)
        for s in (s0, s1):
            entries = members(s)
            verified(entries, st0.q_domain)
            assert {e.cert.member_id for e in entries} == {st0.member_id, st1.member_id}
            assert all(e.cert.sponsor_id == e.cert.member_id for e in entries), "self-issued"
        # §5.3: reader 0 certifies reader 1 through a pinned key; the
        # sponsor-issued certificate replaces the self certificate.
        ok(s0, 0x3D, p1)
        cert = dom.parse_cert(ok(s0, 0x45, p1))
        r = ok(s1, 0x49, cert.encode())
        assert r == b"\x00", "replaced, not added"
        mine = next(e for e in members(s1) if e.cert.member_id == st1.member_id)
        assert mine.cert.sponsor_id == st0.member_id
        _, sw = x(s1, 0x49, members(s1)[0].cert.encode())
        assert sw == SW_ALREADY


# ---------------------------------------------------------------------------
# Optional: the same through pico2hsm-tool
# ---------------------------------------------------------------------------

TOOL = os.environ.get("PICO2HSM_TOOL")


@pytest.mark.skipif(not TOOL, reason="set PICO2HSM_TOOL to the pico2hsm-tool binary")
def test_cli_local_enroll(config, tmp_path):
    setup_pair(config)
    pin = tmp_path / "so-pin"
    pin.write_text(config["so_pin"] + "\n")
    r = subprocess.run(
        [TOOL, "domain", "enroll", "--sponsor", "0", "--joiner", "1",
         "--so-pin-file", str(pin)],
        input="y\n", capture_output=True, text=True, timeout=180)
    log.info("%s\n%s", r.stdout, r.stderr)
    assert r.returncode == 0, r.stdout + r.stderr
    for reader in ("0", "1"):
        m = subprocess.run([TOOL, "-r", reader, "domain", "members"],
                           capture_output=True, text=True, timeout=60)
        assert m.returncode == 0, m.stdout + m.stderr
        assert m.stdout.count("verified") == 2, m.stdout


@pytest.mark.skipif(not TOOL, reason="set PICO2HSM_TOOL to the pico2hsm-tool binary")
def test_cli_remote_enroll_by_message_files(config, tmp_path):
    setup_pair(config)
    pin = tmp_path / "so-pin"
    pin.write_text(config["so_pin"] + "\n")
    msgs = tmp_path / "msgs"
    msgs.mkdir()
    common = ["domain", "enroll", "--remote", "--msg-dir", str(msgs),
              "--so-pin-file", str(pin), "--timeout", "120"]
    sponsor = subprocess.Popen([TOOL, "-r", "0", *common, "--role", "sponsor"],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
    joiner = subprocess.Popen([TOOL, "-r", "1", *common, "--role", "joiner"],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True)
    s_out, _ = sponsor.communicate("y\n", timeout=300)
    j_out, _ = joiner.communicate("y\n", timeout=300)
    log.info("sponsor:\n%s\njoiner:\n%s", s_out, j_out)
    assert sponsor.returncode == 0 and joiner.returncode == 0
    sas_lines = [ln for ln in (s_out + j_out).splitlines() if "authentication string" in ln]
    assert len(sas_lines) == 2 and sas_lines[0].split()[-2:] == sas_lines[1].split()[-2:]
    m = subprocess.run([TOOL, "-r", "1", "domain", "members"],
                       capture_output=True, text=True, timeout=60)
    assert m.returncode == 0 and m.stdout.count("verified") == 2, m.stdout
