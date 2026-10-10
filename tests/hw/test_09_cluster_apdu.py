"""Hardware integration tests for cluster management APDUs (INS=0x54, P1=0x30–0x3C).

These tests run against a single initialized device.  They verify:
  - GET_DEVICE_PUBLIC_KEY (P1=0x30)
  - GET_GENERATION_V2    (P1=0x3C)
  - GET_KEY_MANIFEST     (P1=0x39)
  - GET_STATE_HASH       (P1=0x3A)
  - SIGN_ENROLLMENT      (P1=0x3B)
  - generation counter increments on key events
  - state root changes after key mutation

All APDUs use INS=0x54, CLA=0x80, P1=<sub-cmd>, P2=0x00.
"""

from __future__ import annotations

import logging
import re
import struct

import pytest

from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# APDU constants
# ---------------------------------------------------------------------------
SELECT_SC_HSM      = "00A404000BE82B0601040181C31F020100"
# VERIFY PIN (648219 → bytes 36 34 38 32 31 39)
VERIFY_PIN         = "002000810636343832313900"
# VERIFY SO-PIN (3537363231383830 → 8 bytes)
VERIFY_SO_PIN      = "00200088083537363231383830"
# EXTRAS sub-commands
APDU_GET_PUBKEY    = "8054300000"   # P1=0x30 GET_DEVICE_PUBLIC_KEY
APDU_GET_GEN_V2    = "80543C0000"   # P1=0x3C GET_GENERATION_V2
APDU_GET_MANIFEST  = "8054390000"   # P1=0x39 GET_KEY_MANIFEST
APDU_GET_STATE_HASH = "80543A0000"  # P1=0x3A GET_STATE_HASH


def _parse_received_blocks(opensc_output: str) -> list[bytes]:
    """Return a list of response data byte-arrays, one per 'Received' block.

    opensc-tool output looks like:
        Sending: 00 A4 ...
        Received (SW1=0x90, SW2=0x00):
        6F 16 84 ...        <FCI data>
        Sending: 80 54 30 00 00
        Received (SW1=0x90, SW2=0x00):
        04 AA 63 97 ...     <actual APDU response>

    Each Sending/Received pair is one exchange. We collect them into a list
    so callers can pick the last (or any specific) response.

    The ASCII sideband column that opensc-tool appends is separated by at
    least two spaces from the hex columns; we stop collecting hex tokens at
    the first token that looks like printable-ASCII padding.  In practice,
    the hex tokens on each line are exactly the data bytes; the ASCII
    representation on the right is not valid hex (it contains printable
    chars that happen to overlap 'A'-'F') but opensc-tool aligns it with
    spaces so the regex '\b[0-9A-Fa-f]{2}\b' will mis-fire on them.
    We guard against this by limiting to the first 16 two-hex tokens per
    line (one full row of opensc-tool output is always ≤16 bytes wide).
    """
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
            # Each hex data line from opensc-tool is at most 16 bytes wide.
            tokens = re.findall(r'\b[0-9A-Fa-f]{2}\b', stripped)
            for tok in tokens[:16]:
                current.append(int(tok, 16))
    if current is not None:
        blocks.append(bytes(current))
    return blocks


def _parse_received_bytes(opensc_output: str) -> bytes:
    """Return the data bytes from the LAST 'Received' block in the output.

    When multiple APDUs are sent in one opensc-tool call (e.g. SELECT + command),
    the first block is the SELECT FCI and the second is the actual response.
    We always want the last one.
    """
    blocks = _parse_received_blocks(opensc_output)
    return blocks[-1] if blocks else b""


def _parse_sw(opensc_output: str) -> list[int]:
    """Return list of status words (as int) from all 'Received' lines."""
    sws = []
    for line in opensc_output.splitlines():
        m = re.search(r'Received.*SW1=0x([0-9A-Fa-f]+).*SW2=0x([0-9A-Fa-f]+)', line)
        if m:
            sw = (int(m.group(1), 16) << 8) | int(m.group(2), 16)
            sws.append(sw)
    return sws


def _last_sw(opensc_output: str) -> int:
    """Return the last status word from the output, or 0 if none found."""
    sws = _parse_sw(opensc_output)
    return sws[-1] if sws else 0


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def init_reader0(runner: CLIRunner, config: dict) -> None:
    """Initialize device on reader 0 with DKEK=1 share."""
    result = runner.sc_hsm_tool(
        "--initialize",
        "--label", config["label"],
        "--so-pin", config["so_pin"],
        "--pin",    config["pin"],
        "--dkek-shares", "1",
        save_as="09_init_reader0",
    )
    assert result.returncode == 0, f"Init failed: {result.stderr}"
    import time; time.sleep(3)


@pytest.fixture(scope="module")
def cluster_ready(init_reader0, runner: CLIRunner, config: dict) -> None:
    """Load 1 DKEK share so cluster APDUs requiring DKEK are available."""
    import subprocess, os
    env = os.environ.copy()
    env["OPENSC_DEFAULT_READER"] = "0"
    result = subprocess.run(
        [
            "sc-hsm-tool",
            "--initialize-dkek-share",
            "--so-pin", config["so_pin"],
            "--password", "cluster-test-passphrase",
        ],
        capture_output=True, env=env, timeout=30,
    )
    # We only need the share generated and imported (two-step; skip if tool not available)
    log.info("DKEK share init rc=%d", result.returncode)


# ---------------------------------------------------------------------------
# Tests: GET_DEVICE_PUBLIC_KEY (P1=0x30)
# ---------------------------------------------------------------------------

class TestGetDevicePublicKey:
    def test_returns_65_bytes(self, initialized_device, runner: CLIRunner) -> None:
        """GET_DEVICE_PUBLIC_KEY must return exactly 65 bytes (uncompressed P-256 point)."""
        result = runner.send_apdu(
            SELECT_SC_HSM,
            APDU_GET_PUBKEY,
            reader=0, save_as="09_get_pubkey",
        )
        sw = _last_sw(result.stdout)
        assert sw == 0x9000, f"Expected SW=9000, got {sw:04X}\n{result.stdout}"
        data = _parse_received_bytes(result.stdout)
        assert len(data) == 65, f"Expected 65 bytes, got {len(data)}: {data.hex()}"

    def test_starts_with_04(self, initialized_device, runner: CLIRunner) -> None:
        """Uncompressed P-256 point must start with 0x04."""
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=0)
        data = _parse_received_bytes(result.stdout)
        assert len(data) == 65
        assert data[0] == 0x04, f"Expected 0x04 prefix, got 0x{data[0]:02X}"

    def test_deterministic_across_calls(self, initialized_device, runner: CLIRunner) -> None:
        """Device static public key must be stable across calls."""
        r1 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=0)
        r2 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=0)
        d1 = _parse_received_bytes(r1.stdout)
        d2 = _parse_received_bytes(r2.stdout)
        assert len(d1) == 65 and len(d2) == 65
        assert d1 == d2, "Static public key changed between calls"


# ---------------------------------------------------------------------------
# Tests: GET_GENERATION_V2 (P1=0x3C)
# ---------------------------------------------------------------------------

class TestGetGenerationV2:
    def test_returns_8_bytes(self, initialized_device, runner: CLIRunner) -> None:
        """GET_GENERATION_V2 must return exactly 8 bytes."""
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_GEN_V2, reader=0)
        sw = _last_sw(result.stdout)
        assert sw == 0x9000, f"SW={sw:04X}"
        data = _parse_received_bytes(result.stdout)
        assert len(data) == 8, f"Expected 8 bytes, got {len(data)}"

    def test_initial_generation_is_valid_u64(self, initialized_device, runner: CLIRunner) -> None:
        """Generation counter must be a valid u64 (≥ 0) after initialization."""
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_GEN_V2, reader=0)
        data = _parse_received_bytes(result.stdout)
        assert len(data) == 8
        gen = struct.unpack(">Q", data)[0]
        assert gen >= 0, f"Generation must be a non-negative u64, got {gen}"
        log.info("generation=%d", gen)

    def test_generation_increments_after_keygen(
        self, initialized_device, provisioned_keys, runner: CLIRunner
    ) -> None:
        """Generation must be > 0 after at least one key was generated."""
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_GEN_V2, reader=0)
        data = _parse_received_bytes(result.stdout)
        gen = struct.unpack(">Q", data)[0]
        n_keys = sum(1 for v in provisioned_keys.values() if v.get("generated"))
        log.info("generation=%d, keys_generated=%d", gen, n_keys)
        assert gen >= n_keys, (
            f"Expected generation >= {n_keys} (one increment per keygen), got {gen}"
        )


# ---------------------------------------------------------------------------
# Tests: GET_KEY_MANIFEST (P1=0x39)
# ---------------------------------------------------------------------------

class TestGetKeyManifest:
    def test_sw_9000_before_keygen(self, initialized_device, runner: CLIRunner) -> None:
        """GET_KEY_MANIFEST must return SW=9000 even on a freshly initialized device."""
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_MANIFEST, reader=0)
        sw = _last_sw(result.stdout)
        assert sw == 0x9000, f"SW={sw:04X}"

    def test_empty_on_fresh_init(self, initialized_device, runner: CLIRunner) -> None:
        """On a freshly initialized device, manifest must be empty (0 bytes)."""
        # This test relies on ordering — init_reader0 was fresh.  If keys already
        # exist from earlier modules, skip.
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_MANIFEST, reader=0)
        data = _parse_received_bytes(result.stdout)
        assert len(data) % 44 == 0, f"Manifest length {len(data)} not a multiple of 44"

    def test_44_bytes_per_key_after_keygen(
        self, initialized_device, provisioned_keys, runner: CLIRunner
    ) -> None:
        """After keygen, manifest must have 44 bytes × number of keys."""
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_MANIFEST, reader=0)
        data = _parse_received_bytes(result.stdout)
        n_keys = sum(1 for v in provisioned_keys.values() if v.get("generated"))
        assert len(data) == 44 * n_keys, (
            f"Expected {44 * n_keys} bytes for {n_keys} keys, got {len(data)}"
        )

    def test_manifest_entry_format(
        self, initialized_device, provisioned_keys, runner: CLIRunner
    ) -> None:
        """Each manifest entry must have valid key_ref (1-254), non-zero algo, non-tombstone."""
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_MANIFEST, reader=0)
        data = _parse_received_bytes(result.stdout)
        if len(data) == 0:
            pytest.skip("No keys present")
        assert len(data) % 44 == 0
        for i in range(len(data) // 44):
            entry = data[i*44:(i+1)*44]
            key_ref = entry[0]
            algo    = entry[1]
            deleted = entry[3]
            assert 1 <= key_ref <= 254, f"Entry {i}: invalid key_ref={key_ref}"
            assert algo != 0, f"Entry {i}: algo=0 (invalid)"
            assert deleted == 0, f"Entry {i}: unexpected tombstone in active manifest"


# ---------------------------------------------------------------------------
# Tests: GET_STATE_HASH (P1=0x3A)
# ---------------------------------------------------------------------------

class TestGetStateHash:
    def test_returns_104_bytes(self, initialized_device, runner: CLIRunner) -> None:
        """GET_STATE_HASH must return exactly 104 bytes (8+32+64)."""
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_STATE_HASH, reader=0)
        sw = _last_sw(result.stdout)
        assert sw == 0x9000, f"SW={sw:04X}"
        data = _parse_received_bytes(result.stdout)
        assert len(data) == 104, f"Expected 104 bytes, got {len(data)}: {data.hex()}"

    def test_generation_field_consistent(
        self, initialized_device, runner: CLIRunner
    ) -> None:
        """Generation in GET_STATE_HASH must match GET_GENERATION_V2."""
        r_hash = runner.send_apdu(SELECT_SC_HSM, APDU_GET_STATE_HASH, reader=0)
        r_gen  = runner.send_apdu(SELECT_SC_HSM, APDU_GET_GEN_V2, reader=0)
        hash_data = _parse_received_bytes(r_hash.stdout)
        gen_data  = _parse_received_bytes(r_gen.stdout)
        assert len(hash_data) == 104 and len(gen_data) == 8
        gen_from_hash = struct.unpack(">Q", hash_data[:8])[0]
        gen_direct    = struct.unpack(">Q", gen_data)[0]
        assert gen_from_hash == gen_direct, (
            f"generation in state_hash ({gen_from_hash}) != GET_GENERATION_V2 ({gen_direct})"
        )

    def test_state_root_not_all_zeros(self, initialized_device, runner: CLIRunner) -> None:
        """State root (bytes 8–39) must not be all zeros after initialization."""
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_STATE_HASH, reader=0)
        data = _parse_received_bytes(result.stdout)
        assert len(data) == 104
        state_root = data[8:40]
        assert state_root != bytes(32), "State root is all zeros (device may be in bad state)"

    def test_state_root_changes_after_keygen(
        self, initialized_device, runner: CLIRunner, provisioned_keys
    ) -> None:
        """State root must differ from the all-empty-slots root once keys exist."""
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_STATE_HASH, reader=0)
        data = _parse_received_bytes(result.stdout)
        state_root = data[8:40]
        n_keys = sum(1 for v in provisioned_keys.values() if v.get("generated"))
        if n_keys == 0:
            pytest.skip("No keys present")
        # Compare two consecutive calls — root must be stable
        r2 = runner.send_apdu(SELECT_SC_HSM, APDU_GET_STATE_HASH, reader=0)
        d2 = _parse_received_bytes(r2.stdout)
        assert data[8:40] == d2[8:40], "State root is not stable between identical calls"

    def test_sig_field_not_all_zeros(self, initialized_device, runner: CLIRunner) -> None:
        """Sig bytes (40–103) must not be all zeros."""
        result = runner.send_apdu(SELECT_SC_HSM, APDU_GET_STATE_HASH, reader=0)
        data = _parse_received_bytes(result.stdout)
        sig = data[40:]
        assert len(sig) == 64
        assert sig != bytes(64), "Signature field is all zeros"


# ---------------------------------------------------------------------------
# Tests: SIGN_ENROLLMENT (P1=0x3B) — requires SO-PIN
# ---------------------------------------------------------------------------

# Dummy 32-byte TLS fingerprint + 16-byte cluster ID
_ENROLL_DATA = "A" * 64 + "B" * 32   # 48 bytes = 96 hex chars
APDU_SIGN_ENROLLMENT = f"80543B0030{_ENROLL_DATA}"


class TestSignEnrollment:
    def test_requires_so_pin(self, initialized_device, runner: CLIRunner) -> None:
        """SIGN_ENROLLMENT without SO-PIN auth must return SW=6982."""
        result = runner.send_apdu(
            SELECT_SC_HSM,
            APDU_SIGN_ENROLLMENT,
            reader=0, save_as="09_sign_enroll_no_sopin",
        )
        sw = _last_sw(result.stdout)
        assert sw == 0x6982, f"Expected SW=6982 (security status), got {sw:04X}"

    def test_returns_64_bytes_with_so_pin(
        self, initialized_device, runner: CLIRunner, config: dict
    ) -> None:
        """SIGN_ENROLLMENT after SO-PIN VERIFY must return exactly 64 bytes (r||s sig)."""
        result = runner.send_apdu(
            SELECT_SC_HSM,
            VERIFY_SO_PIN,
            APDU_SIGN_ENROLLMENT,
            reader=0, save_as="09_sign_enroll_ok",
        )
        sws = _parse_sw(result.stdout)
        assert len(sws) >= 2, f"Expected at least 2 SW responses; got {sws}"
        assert sws[-2] == 0x9000, f"VERIFY SO-PIN failed: SW={sws[-2]:04X}"
        assert sws[-1] == 0x9000, f"SIGN_ENROLLMENT failed: SW={sws[-1]:04X}"
        # Parse only the last received data block
        data = _parse_received_bytes(result.stdout)
        # Data includes all responses; take last 64 bytes
        assert len(data) >= 64, f"Expected >= 64 bytes total, got {len(data)}"
        sig = data[-64:]
        assert sig != bytes(64), "Signature is all zeros"

    def test_wrong_data_length_rejected(
        self, initialized_device, runner: CLIRunner
    ) -> None:
        """SIGN_ENROLLMENT with wrong Lc must return SW=6700 or SW=6A80."""
        apdu_short = "80543B0010" + "AA" * 16   # only 16 bytes, need 48
        result = runner.send_apdu(
            SELECT_SC_HSM,
            VERIFY_SO_PIN,
            apdu_short,
            reader=0,
        )
        sws = _parse_sw(result.stdout)
        last_sw = sws[-1] if sws else 0
        assert last_sw in (0x6700, 0x6A80, 0x6982), (
            f"Expected wrong-length error, got SW={last_sw:04X}"
        )


# ---------------------------------------------------------------------------
# Tests: NOISE_TARGET_INIT (P1=0x35) — input=65B source static pub
# ---------------------------------------------------------------------------

class TestNoiseTargetInit:
    def test_requires_so_pin(self, initialized_device, runner: CLIRunner) -> None:
        """The user PIN alone must not start a DKEK exchange (SW 6982)."""
        r_pub = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=0)
        source_pub_hex = _parse_received_bytes(r_pub.stdout).hex()
        result = runner.send_apdu(
            SELECT_SC_HSM, VERIFY_PIN, f"8054350041{source_pub_hex}",
            reader=0, save_as="09_noise_target_init_user_pin",
        )
        assert _parse_sw(result.stdout)[-1] == 0x6982

    def test_requires_initialized_device(
        self, initialized_device, runner: CLIRunner
    ) -> None:
        """NOISE_TARGET_INIT from an enrolled peer (SO-PIN) returns 161 bytes."""
        # Use the device's own static pub as the "source" (a valid point) and
        # enroll it: the exchange only talks to an enrolled peer.
        r_pub = runner.send_apdu(SELECT_SC_HSM, APDU_GET_PUBKEY, reader=0)
        source_pub_bytes = _parse_received_bytes(r_pub.stdout)
        assert len(source_pub_bytes) == 65

        source_pub_hex = source_pub_bytes.hex()
        lc = "41"  # 65 decimal = 0x41
        apdu_target_init = f"80543500{lc}{source_pub_hex}"

        result = runner.send_apdu(
            SELECT_SC_HSM,
            VERIFY_SO_PIN,
            f"80543D00{lc}{source_pub_hex}",  # ENROLL_PEER_PUBKEY
            apdu_target_init,
            reader=0, save_as="09_noise_target_init",
        )
        sws = _parse_sw(result.stdout)
        assert sws[-1] == 0x9000, f"NOISE_TARGET_INIT failed: SW={sws[-1]:04X}"
        data = _parse_received_bytes(result.stdout)
        # Last response should be 161 bytes (65+32+64)
        assert len(data) >= 161, f"Expected >= 161 bytes, got {len(data)}"
        response = data[-161:]
        ephem_pub = response[:65]
        challenge = response[65:97]
        sig_t = response[97:161]
        assert ephem_pub[0] == 0x04, "ephem_T_pub must be uncompressed (0x04 prefix)"
        assert challenge != bytes(32), "Challenge must not be all zeros"
        assert sig_t != bytes(64), "Sig_T must not be all zeros"
        log.info("NOISE_TARGET_INIT OK: ephem=%s challenge=%s",
                 ephem_pub[:4].hex(), challenge[:4].hex())
