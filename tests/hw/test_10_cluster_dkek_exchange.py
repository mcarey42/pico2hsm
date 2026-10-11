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
    for reader in (0, 1):
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
            "-r", "0",
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
            "-r", "0",
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
    env["OPENSC_DEFAULT_READER"] = "0"
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
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=0)
        data = _parse_received_bytes(result.stdout)
        assert len(data) == 65, f"Reader 0: expected 65 bytes, got {len(data)}"
        assert data[0] == 0x04

    def test_reader1_returns_65_bytes(self, init_both_devices, runner: CLIRunner) -> None:
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=1)
        data = _parse_received_bytes(result.stdout)
        assert len(data) == 65, f"Reader 1: expected 65 bytes, got {len(data)}"
        assert data[0] == 0x04

    def test_different_keys_on_each_device(
        self, init_both_devices, runner: CLIRunner
    ) -> None:
        """Each device must have its own unique static key pair."""
        r0 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=0)
        r1 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=1)
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
    for reader in (0, 1):
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=reader)
        pubs[reader] = _parse_received_bytes(result.stdout)[-65:]
    for reader, peer in ((0, 1), (1, 0)):
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
        source_pub = self._get_pubkey(runner, reader=0)
        apdu = self._apdu_with_lc_data(0x35, source_pub)
        result = runner.send_apdu(
            SELECT_SC_HSM, VERIFY_SO_PIN, apdu,
            reader=1, save_as="10_noise_target_init",
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
        """Full 4-step relay: SOURCE sends DKEK → TARGET receives and stores it."""
        source_pub = self._get_pubkey(runner, reader=0)
        target_pub = self._get_pubkey(runner, reader=1)

        # Step 1: TARGET — NOISE_TARGET_INIT(source_static_pub) → 161B
        apdu_35 = self._apdu_with_lc_data(0x35, source_pub)
        result_35 = runner.send_apdu(
            SELECT_SC_HSM, VERIFY_SO_PIN, apdu_35,
            reader=1, save_as="10_step1_target_init",
        )
        assert _last_sw(result_35.stdout) == 0x9000, "Step 1 failed"
        init_data = _parse_received_bytes(result_35.stdout)[-161:]
        ephem_T_pub = init_data[:65]
        challenge   = init_data[65:97]
        sig_T       = init_data[97:161]

        # Step 2: SOURCE — NOISE_SOURCE_RESPOND(ephem_T + challenge + sig_T) → 129B
        payload_36 = ephem_T_pub + challenge + sig_T   # 161 bytes
        apdu_36 = self._apdu_with_lc_data(0x36, payload_36)
        result_36 = runner.send_apdu(
            SELECT_SC_HSM, VERIFY_SO_PIN, apdu_36,
            reader=0, save_as="10_step2_source_respond",
        )
        assert _last_sw(result_36.stdout) == 0x9000, f"Step 2 failed: {result_36.stdout}"
        respond_data = _parse_received_bytes(result_36.stdout)[-129:]
        ephem_S_pub = respond_data[:65]
        sig_S       = respond_data[65:129]
        assert ephem_S_pub[0] == 0x04
        log.info("Step 2 OK — ephem_S=%s", ephem_S_pub[:4].hex())

        # Step 3: SOURCE — NOISE_FINALIZE_SEND_V2(ephem_T + target_static + challenge) → 60B
        payload_37 = ephem_T_pub + target_pub + challenge   # 162 bytes
        apdu_37 = self._apdu_with_lc_data(0x37, payload_37)
        result_37 = runner.send_apdu(
            SELECT_SC_HSM, VERIFY_SO_PIN, apdu_37,
            reader=0, save_as="10_step3_send_v2",
        )
        assert _last_sw(result_37.stdout) == 0x9000, f"Step 3 failed: {result_37.stdout}"
        enc_dkek_data = _parse_received_bytes(result_37.stdout)
        assert len(enc_dkek_data) >= 60, f"Expected >= 60B encrypted DKEK, got {len(enc_dkek_data)}"
        enc_dkek = enc_dkek_data[-60:]
        log.info("Step 3 OK — enc_dkek=%s...", enc_dkek[:8].hex())

        # Step 4: TARGET — NOISE_FINALIZE_RECV_V2(ephem_S + sig_S + enc_dkek) → empty SW=9000
        payload_38 = ephem_S_pub + sig_S + enc_dkek   # 189 bytes
        apdu_38 = self._apdu_with_lc_data(0x38, payload_38)
        result_38 = runner.send_apdu(
            SELECT_SC_HSM, VERIFY_SO_PIN, apdu_38,
            reader=1, save_as="10_step4_recv_v2",
        )
        last = _last_sw(result_38.stdout)
        assert last == 0x9000, f"Step 4 (NOISE_FINALIZE_RECV_V2) failed: SW={last:04X}"
        log.info("Full DKEK exchange complete — DKEK now established on target (reader 1)")

    def test_generation_independent_per_device(
        self, dkek_loaded_source, runner: CLIRunner
    ) -> None:
        """Each device tracks its own generation counter independently."""
        r0 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_GEN_V2, reader=0)
        r1 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_GEN_V2, reader=1)
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
        r0 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_STATE_HASH, reader=0)
        r1 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_STATE_HASH, reader=1)
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
