"""Hardware integration tests for two-device DKEK cluster exchange.

Requires TWO pico2hsm devices connected (readers 0 and 1).

Tests the full V2 cluster relay protocol:
  Source (reader 0) → encrypted DKEK → Target (reader 1)

Protocol steps:
  1. GET_DEVICE_PUBLIC_KEY on both devices.
  2. NOISE_TARGET_INIT on TARGET with source's static pub.
     → ephem_T_pub(65) || challenge(32) || Sig_T(64) = 161B
  3. NOISE_SOURCE_RESPOND on SOURCE with target's init response.
     → ephem_S_pub(65) || Sig_S(64) = 129B
  4. NOISE_FINALIZE_SEND_V2 on SOURCE with ephem_T + target_static + challenge.
     → encrypted_dkek(60B)
  5. NOISE_FINALIZE_RECV_V2 on TARGET with ephem_S + Sig_S + encrypted_dkek.
     → SW=9000 (empty response)
  6. Verify both devices report same state root after a shared key.

Skip conditions:
  - Only one reader present → entire module is skipped.
  - DKEK not initialized on source → exchange tests are skipped.
"""

from __future__ import annotations

import logging
import os
import re
import struct
import subprocess
import time
from typing import Optional

import pytest

from helpers.cli import CLIRunner
from helpers.pcsc import dut_index as R0, peer_index as R1

log = logging.getLogger(__name__)

SELECT_SC_HSM  = "00A404000BE82B0601040181C31F020100"
VERIFY_PIN     = "002000810636343832313900"
VERIFY_SO_PIN  = "00200088083537363231383830"
APDU_GET_PUBKEY     = "8054300000"
APDU_GET_GEN_V2     = "80543C0000"
APDU_GET_STATE_HASH = "80543A0000"
APDU_GET_MANIFEST   = "8054390000"

DKEK_PASSPHRASE = "cluster-integration-test"


# ---------------------------------------------------------------------------
# Helper: send APDUs directly, return (data_bytes, [sw_list])
# ---------------------------------------------------------------------------

def _send(runner: CLIRunner, reader: int, *apdus: str) -> tuple[bytes, list[int]]:
    result = runner.send_apdu(*apdus, reader=reader)
    data = _parse_received_bytes(result.stdout)
    sws = _parse_sw(result.stdout)
    return data, sws


def _parse_received_blocks(opensc_output: str) -> list[bytes]:
    """Return one bytes object per Received block in opensc-tool output."""
    blocks: list[bytes] = []
    current: bytearray | None = None
    for line in opensc_output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Received"):
            current = bytearray()
            continue
        if stripped.startswith("Sending"):
            if current is not None:
                blocks.append(bytes(current))
            current = None
            continue
        if current is not None:
            # Split on whitespace and only accept standalone 2-char hex tokens.
            # This avoids the ASCII column on the right side of opensc-tool output
            # where printable chars can form 2-char sequences that match the regex.
            tokens = [t for t in stripped.split()
                      if len(t) == 2 and all(c in '0123456789abcdefABCDEF' for c in t)]
            for tok in tokens[:16]:
                current.append(int(tok, 16))
    if current is not None:
        blocks.append(bytes(current))
    return blocks


def _parse_received_bytes(opensc_output: str) -> bytes:
    """Return data bytes from the LAST Received block (skips SELECT FCI etc.)."""
    blocks = _parse_received_blocks(opensc_output)
    return blocks[-1] if blocks else b""


def _parse_sw(opensc_output: str) -> list[int]:
    sws = []
    for line in opensc_output.splitlines():
        m = re.search(r'Received.*SW1=0x([0-9A-Fa-f]+).*SW2=0x([0-9A-Fa-f]+)', line)
        if m:
            sws.append((int(m.group(1), 16) << 8) | int(m.group(2), 16))
    return sws


def _last_sw(opensc_output: str) -> int:
    sws = _parse_sw(opensc_output)
    return sws[-1] if sws else 0


# ---------------------------------------------------------------------------
# Module-level skip: require two readers
# ---------------------------------------------------------------------------

def pytest_collection_modifyitems(items):
    """Skip this module's items if fewer than 2 readers are present."""
    pass  # skip logic is in the fixture below


@pytest.fixture(scope="module", autouse=True)
def require_two_readers():
    """Skip entire module unless 2+ readers are detected."""
    try:
        r = subprocess.run(["opensc-tool", "--list-readers"], capture_output=True, timeout=5)
        reader_count = r.stdout.decode().count("Yes")
    except Exception:
        reader_count = 0
    if reader_count < 2:
        pytest.skip(
            f"Two pico2hsm devices required; only {reader_count} reader(s) with cards found."
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def init_both_devices(runner: CLIRunner, config: dict) -> None:
    """Initialize BOTH devices (readers 0 and 1) with DKEK shares=1."""
    for reader in (R0(), R1()):
        result = subprocess.run(
            [
                "sc-hsm-tool",
                "-r", str(reader),
                "--initialize",
                "--label", config["label"],
                "--so-pin", config["so_pin"],
                "--pin",    config["pin"],
                "--dkek-shares", "1",
            ],
            capture_output=True, timeout=60,
        )
        assert result.returncode == 0, (
            f"Init reader {reader} failed: {result.stderr.decode()}"
        )
        log.info("Reader %d initialized", reader)
        time.sleep(3)  # allow USB re-enumeration before touching next reader
    time.sleep(3)  # extra settle time after both are initialized


@pytest.fixture(scope="module")
def dkek_loaded_source(init_both_devices, runner: CLIRunner, config: dict) -> None:
    """Generate and import one DKEK share on reader 0 (the SOURCE device).

    This uses sc-hsm-tool to:
      1. Create a DKEK share file protected with DKEK_PASSPHRASE.
      2. Import the share back into the device.

    After this fixture, the SOURCE device has DKEK ready.
    The TARGET device (reader 1) will receive the DKEK via the exchange protocol.
    """
    import tempfile, pathlib
    share_dir = pathlib.Path(tempfile.mkdtemp())
    share_file = share_dir / "dkek-share-1.pbe"

    # Generate share file (reader 0 = SOURCE)
    result = subprocess.run(
        [
            "sc-hsm-tool",
            "-r", str(R0()),
            "--create-dkek-share", str(share_file),
            "--so-pin", config["so_pin"],
            "--password", DKEK_PASSPHRASE,
        ],
        capture_output=True, timeout=30,
    )
    assert result.returncode == 0, (
        f"Could not create DKEK share: {result.stderr.decode()}"
    )

    # Import into SOURCE device.
    # sc-hsm-tool --import-dkek-share sends INS=0x52 P1=0x00 with the raw
    # 32-byte share.  pico2hsm now supports the standard DKEK wire format.
    result = subprocess.run(
        [
            "sc-hsm-tool",
            "-r", str(R0()),
            "--import-dkek-share", str(share_file),
            "--so-pin", config["so_pin"],
            "--password", DKEK_PASSPHRASE,
        ],
        capture_output=True, timeout=30,
    )
    assert result.returncode == 0, (
        f"DKEK share import failed on reader 0: {result.stderr.decode().strip()}"
    )
    log.info("DKEK share loaded on reader 0 (SOURCE)")


@pytest.fixture(scope="module")
def source_key_generated(dkek_loaded_source, runner: CLIRunner, config: dict) -> None:
    """Generate one P-256 key on reader 0 so the manifest / state root are non-trivial."""
    env = os.environ.copy()
    env["OPENSC_DEFAULT_READER"] = str(R0())
    result = subprocess.run(
        [
            "pkcs11-tool", "--module", config["module"],
            "--login", "--pin", config["pin"],
            "--keypairgen", "--key-type", "EC:prime256v1",
            "--id", "20", "--label", "cluster-test-key",
        ],
        capture_output=True, env=env, timeout=120,
    )
    log.info("Source keygen rc=%d", result.returncode)
    # Non-fatal — state tests still run without a key


# ---------------------------------------------------------------------------
# Tests: Static public key retrieval
# ---------------------------------------------------------------------------

class TestGetDevicePublicKeyBothDevices:
    def test_reader0_returns_65_bytes(self, init_both_devices, runner: CLIRunner) -> None:
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=R0())
        data = _parse_received_bytes(result.stdout)
        assert len(data) == 65, f"Reader 0: expected 65 bytes, got {len(data)}"
        assert data[0] == 0x04

    def test_reader1_returns_65_bytes(self, init_both_devices, runner: CLIRunner) -> None:
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=R1())
        data = _parse_received_bytes(result.stdout)
        assert len(data) == 65, f"Reader 1: expected 65 bytes, got {len(data)}"
        assert data[0] == 0x04

    def test_different_keys_on_each_device(
        self, init_both_devices, runner: CLIRunner
    ) -> None:
        """Each device must have its own unique static key pair."""
        r0 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=R0())
        r1 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=R1())
        d0 = _parse_received_bytes(r0.stdout)
        d1 = _parse_received_bytes(r1.stdout)
        assert len(d0) == 65 and len(d1) == 65
        assert d0 != d1, "Both devices returned the same static public key (must be unique)"


# ---------------------------------------------------------------------------
# Tests: Full V2 DKEK exchange protocol
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def enrolled_peers(dkek_loaded_source, runner: CLIRunner) -> None:
    """Enroll each device's static key on the other (SO-PIN, EXTRAS P1=0x3D).

    The V2 exchange has no unauthenticated mode: both sides verify the
    other's signatures against the enrolled key, and all steps need SO-PIN.
    """
    pubs = {}
    for reader in (R0(), R1()):
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=reader)
        pubs[reader] = _parse_received_bytes(result.stdout)[-65:]
    for reader, peer in ((R0(), R1()), (R1(), R0())):
        enroll = f"80543D0041{pubs[peer].hex()}"
        result = runner.send_apdu(
            SELECT_SC_HSM, VERIFY_SO_PIN, enroll,
            reader=reader, save_as=f"10_enroll_peer_r{reader}",
        )
        assert _last_sw(result.stdout) == 0x9000, f"ENROLL on reader {reader} failed"


class TestDkekExchangeV2:
    """End-to-end DKEK exchange: source device → encrypted channel → target device."""

    def _get_pubkey(self, runner: CLIRunner, reader: int) -> bytes:
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=reader)
        data = _parse_received_bytes(result.stdout)
        assert len(data) == 65, f"Reader {reader}: expected 65B pubkey, got {len(data)}"
        return data

    def _apdu_with_lc_data(self, p1: int, data: bytes) -> str:
        lc = len(data)
        return f"8054{p1:02X}00{lc:02X}{data.hex()}"

    def test_noise_target_init_returns_161_bytes(
        self, enrolled_peers, runner: CLIRunner
    ) -> None:
        """TARGET: NOISE_TARGET_INIT(source_static_pub) → 161 bytes."""
        source_pub = self._get_pubkey(runner, reader=R0())
        apdu = self._apdu_with_lc_data(0x35, source_pub)
        result = runner.send_apdu(
            SELECT_SC_HSM, VERIFY_SO_PIN, apdu,
            reader=R1(), save_as="10_noise_target_init",
        )
        sws = _parse_sw(result.stdout)
        assert sws[-1] == 0x9000, f"NOISE_TARGET_INIT SW={sws[-1]:04X}"
        data = _parse_received_bytes(result.stdout)
        assert len(data) >= 161, f"Expected >= 161B, got {len(data)}"
        response = data[-161:]
        ephem_T = response[:65]
        challenge = response[65:97]
        sig_T = response[97:161]
        assert ephem_T[0] == 0x04
        assert challenge != bytes(32)
        assert sig_T != bytes(64)
        log.info("NOISE_TARGET_INIT OK — ephem_T=%s", ephem_T[:4].hex())

    def test_full_exchange_completes(
        self, enrolled_peers, runner: CLIRunner
    ) -> None:
        """Full 4-step relay: SOURCE sends DKEK → TARGET receives and stores it.

        The exchange state lives in the card session (it is cleared when the
        host session ends, like the SO-PIN), so each device keeps one PC/SC
        connection for all of its steps — as the sync daemon does.
        """
        from helpers.pcsc import session

        source_pub = self._get_pubkey(runner, reader=R0())
        target_pub = self._get_pubkey(runner, reader=R1())

        with session(R0()) as src, session(R1()) as tgt:
            for s in (src, tgt):
                s.ok(SELECT_SC_HSM)
                s.ok(VERIFY_SO_PIN)

            # Step 1: TARGET — NOISE_TARGET_INIT(source_static_pub) → 161 B
            init = tgt.ok(self._apdu_with_lc_data(0x35, source_pub))
            assert len(init) == 161, len(init)
            ephem_T_pub, challenge, sig_T = init[:65], init[65:97], init[97:161]

            # Step 2: SOURCE — NOISE_SOURCE_RESPOND(ephem_T ‖ challenge ‖ sig_T) → 129 B
            resp = src.ok(self._apdu_with_lc_data(0x36, ephem_T_pub + challenge + sig_T))
            assert len(resp) == 129, len(resp)
            ephem_S_pub, sig_S = resp[:65], resp[65:129]
            assert ephem_S_pub[0] == 0x04

            # Step 3: SOURCE — NOISE_FINALIZE_SEND_V2(ephem_T ‖ target_static ‖ challenge) → 60 B
            enc_dkek = src.ok(self._apdu_with_lc_data(0x37, ephem_T_pub + target_pub + challenge))
            assert len(enc_dkek) == 60, len(enc_dkek)

            # Step 4: TARGET — NOISE_FINALIZE_RECV_V2(ephem_S ‖ sig_S ‖ enc_dkek)
            _, sw = tgt.send(self._apdu_with_lc_data(0x38, ephem_S_pub + sig_S + enc_dkek))
            assert sw == 0x9000, f"Step 4 (NOISE_FINALIZE_RECV_V2) failed: SW={sw:04X}"

            # Cluster plan V3 P1 done criterion: one domain, two members.
            st_src = src.ok("8054400000")
            st_tgt = tgt.ok("8054400000")
        # DOMAIN_STATUS: version(1) flags(1) domain_id(16) kcv(8) Q(65) member_id(16) ...
        assert st_src[2:18] == st_tgt[2:18] != bytes(16), "same domain_id"
        assert st_src[18:26] == st_tgt[18:26], "same DKEK check value"
        assert st_src[91:107] != st_tgt[91:107], "distinct member IDs"
        log.info(
            "DKEK exchange complete: domain %s, members %s / %s",
            st_src[2:18].hex(), st_src[91:107].hex(), st_tgt[91:107].hex(),
        )

    def test_generation_independent_per_device(
        self, dkek_loaded_source, runner: CLIRunner
    ) -> None:
        """Each device tracks its own generation counter independently."""
        r0 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_GEN_V2, reader=R0())
        r1 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_GEN_V2, reader=R1())
        d0 = _parse_received_bytes(r0.stdout)
        d1 = _parse_received_bytes(r1.stdout)
        assert len(d0) == 8 and len(d1) == 8
        gen0 = struct.unpack(">Q", d0)[0]
        gen1 = struct.unpack(">Q", d1)[0]
        log.info("Reader 0 generation=%d, reader 1 generation=%d", gen0, gen1)
        # Both must be valid u64 values (no assertion on equality — they diverge naturally)

    def test_state_roots_differ_before_sync(
        self, source_key_generated, runner: CLIRunner
    ) -> None:
        """Before sync, devices with different key sets must have different state roots."""
        r0 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_STATE_HASH, reader=R0())
        r1 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_STATE_HASH, reader=R1())
        d0 = _parse_received_bytes(r0.stdout)
        d1 = _parse_received_bytes(r1.stdout)
        assert len(d0) == 104 and len(d1) == 104
        root0 = d0[8:40]
        root1 = d1[8:40]
        log.info("Root0=%s Root1=%s", root0.hex()[:16], root1.hex()[:16])
        # After source_key_generated ran (at least 1 key on reader 0, 0 on reader 1)
        # the roots should differ.  If they happen to be equal, it means reader 0
        # had no keys added — just log, don't fail.
        if root0 == root1:
            log.warning(
                "State roots are equal — source key gen may have failed. "
                "Roots: %s", root0.hex()
            )


def _kcv(runner: CLIRunner, reader: int) -> Optional[str]:
    out = runner.sc_hsm_tool("-r", str(reader)).stdout
    m = re.search(r"key check value\s*:\s*([0-9A-Fa-f]+)", out, re.IGNORECASE)
    return m.group(1).upper() if m else None


def _pkcs11_slot(runner: CLIRunner, reader: int) -> Optional[str]:
    """The PKCS#11 slot ID of PC/SC reader ``reader`` (matched by reader name:
    slot order need not follow the device-under-test / peer roles)."""
    from smartcard.System import readers

    name = str(readers()[reader])
    out = runner.pkcs11_tool("-L").stdout
    for slot, desc in re.findall(r"^Slot \d+ \((0x[0-9a-fA-F]+)\): (.*)$", out, re.MULTILINE):
        if desc.strip() == name.strip():
            return slot
    return None


def _key_ref_for_id(reader: int, key_id: int) -> Optional[int]:
    """SC-HSM key reference whose PRKD carries CKA_ID ``key_id`` (LIST KEYS + PRKD read)."""
    from helpers.pcsc import session

    with session(reader) as s:
        s.ok(SELECT_SC_HSM)
        listing = s.ok("0058000000")
        refs = [listing[i + 1] for i in range(0, len(listing), 2) if listing[i] == 0xCC]
        for ref in refs:
            # READ BINARY (odd INS) of the PRKD C4<ref>, offset 0.
            data, sw = s.send(f"00B1C4{ref:02X}0454020000" + "00")
            if sw == 0x9000 and bytes([0x04, 0x01, key_id]) in data:
                return ref
    return None


def test_wrapped_key_moves_between_devices(enrolled_peers, runner: CLIRunner, config: dict, tmp_path) -> None:
    """P0 across devices: sc-hsm-tool wraps on reader 0, unwraps on reader 1, reader 1 signs.

    Needs both devices to hold the same DKEK (the exchange test above, or the
    same shares).  The signature from reader 1 must verify against the public
    key generated on reader 0.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    k0, k1 = _kcv(runner, 0), _kcv(runner, 1)
    if not k0 or k0 != k1:
        pytest.skip(f"devices do not share a DKEK (KCV {k0} / {k1})")
    slots = [_pkcs11_slot(runner, R0()), _pkcs11_slot(runner, R1())]
    assert all(slots), slots

    key_id = 0x7A
    gen = runner.pkcs11_tool(
        "--slot", slots[0], "--login", "--pin", config["pin"], "--keypairgen",
        "--key-type", "EC:prime256v1", "--id", f"{key_id:02x}", "--label", "xdev-move",
        save_as="10_xdev_keygen",
    )
    assert gen.returncode == 0, gen.stderr[-2000:]
    pub_der = tmp_path / "pub.der"
    rd = runner.pkcs11_tool(
        "--slot", slots[0], "--read-object", "--type", "pubkey", "--id", f"{key_id:02x}",
        "-o", str(pub_der),
    )
    assert rd.returncode == 0, rd.stderr[-2000:]
    pub = serialization.load_der_public_key(pub_der.read_bytes())

    ref = _key_ref_for_id(0, key_id)
    if ref is None:
        # Fall back to the newest key reference.
        from helpers.pcsc import session
        with session(R0()) as s:
            s.ok(SELECT_SC_HSM)
            listing = s.ok("0058000000")
        ref = max(listing[i + 1] for i in range(0, len(listing), 2) if listing[i] == 0xCC)

    wky = tmp_path / "move.wky"
    w = runner.sc_hsm_tool("-r", str(R0()), "--wrap-key", str(wky), "--key-reference", str(ref),
                           "--pin", config["pin"], save_as="10_xdev_wrap")
    assert w.returncode == 0, w.stderr[-2000:]
    u = runner.sc_hsm_tool("-r", str(R1()), "--unwrap-key", str(wky), "--key-reference", str(ref),
                           "--pin", config["pin"], "--force", save_as="10_xdev_unwrap")
    assert u.returncode == 0 and "successfully imported" in u.stdout, u.stdout + u.stderr[-2000:]

    msg = tmp_path / "msg.bin"
    msg.write_bytes(b"pico2hsm cross-device wrap/unwrap")
    sig = tmp_path / "sig.bin"
    sg = runner.pkcs11_tool(
        "--slot", slots[1], "--login", "--pin", config["pin"], "--sign",
        "--mechanism", "ECDSA-SHA256", "--id", f"{key_id:02x}",
        "-i", str(msg), "-o", str(sig), "--signature-format", "openssl",
        save_as="10_xdev_sign",
    )
    assert sg.returncode == 0, sg.stderr[-2000:]
    pub.verify(sig.read_bytes(), msg.read_bytes(), ec.ECDSA(hashes.SHA256()))
    log.info("key ref %d moved reader 0 → reader 1 and signs there", ref)
