"""Hardware integration tests for DKEK wrap/unwrap key backup round-trip.

Status: implementation complete; requires hardware validation with a physical device.

The firmware DKEK subsystem (DkekManager::wrap/unwrap, export_key::handle INS=0x72,
import_key::handle INS=0x74) is fully implemented with real AES-256-CBC crypto,
KCV verification, PKCS#7 padding, and persistent key storage.  Unit tests in
firmware/src/security/dkek.rs and firmware/src/protocol/sc_hsm/commands/ pass.
This hardware integration test exercises the end-to-end sc-hsm-tool workflow.

Tests the standard sc-hsm-tool DKEK key backup workflow:
  1. Initialize device with DKEK shares=1
  2. Create and import a DKEK share
  3. Generate a key on the device
  4. Wrap (export) the key via --wrap-key
  5. Re-initialize device (wipes all keys)
  6. Re-import the same DKEK share
  7. Unwrap (import) the key via --unwrap-key
  8. Verify the restored key works (sign + verify with original public key)

Also tests that a key wrapped under one DKEK cannot be unwrapped with a
different DKEK (share mismatch).

Wire format (sc-hsm-tool standard):
  - Import DKEK share:  80 52 00 00 20 <32 raw bytes>
  - Wrap key:           80 72 <key_ref> 92 00
  - Unwrap key:         80 74 <key_ref> 93 Lc <blob>
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from pathlib import Path

import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from helpers.cli import CLIRunner

log = logging.getLogger(__name__)

pytestmark = pytest.mark.hw

DKEK_PASSPHRASE = "dkek-roundtrip-test"
KEY_LABEL = "dkek-test"
KEY_ID = "30"   # PKCS#15 CKA_ID passed to pkcs11-tool --id (hex string)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _wait_for_device(timeout: float = 20.0) -> bool:
    """Poll until pcscd reports a card present."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = subprocess.run(
                ["opensc-tool", "--list-readers"],
                capture_output=True, timeout=5,
            )
            if r.returncode == 0 and b"Yes" in r.stdout:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        time.sleep(0.5)
    return False


def _initialize_with_dkek(config: dict, dkek_shares: int = 1) -> None:
    """Initialize the device with the specified number of DKEK shares."""
    result = subprocess.run(
        [
            "sc-hsm-tool",
            "--initialize",
            "--label", config["label"],
            "--so-pin", config["so_pin"],
            "--pin", config["pin"],
            "--dkek-shares", str(dkek_shares),
        ],
        capture_output=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"INITIALIZE with dkek-shares={dkek_shares} failed: "
        f"{result.stderr.decode()}"
    )
    log.info("Device initialized with dkek-shares=%d", dkek_shares)
    assert _wait_for_device(timeout=20.0), "Device did not re-enumerate after INITIALIZE"


def _create_dkek_share(share_path: Path, passphrase: str) -> None:
    """Create a DKEK share file."""
    result = subprocess.run(
        [
            "sc-hsm-tool",
            "--create-dkek-share", str(share_path),
            "--password", passphrase,
        ],
        capture_output=True, timeout=30,
    )
    assert result.returncode == 0, (
        f"Failed to create DKEK share: {result.stderr.decode()}"
    )
    assert share_path.exists(), f"DKEK share file not created at {share_path}"
    log.info("DKEK share created: %s", share_path)


def _get_first_key_slot(reader: int = 0) -> int | None:
    """Return the first device key slot number from LIST KEYS, or None if no keys.

    SC-HSM LIST KEYS (CLA=0x80 INS=0x58 P1=0x00 P2=0x00 Le=0x00) returns
    pairs of bytes [hi, lo] where hi identifies the file type:
      0xCC = key blob → lo is the key reference (device slot number)
      0xC4 = PRKD descriptor → lo is the key reference

    The device slot number (CC xx) is what sc-hsm-tool --key-reference expects.
    This is NOT the same as the PKCS#15 CKA_ID passed to pkcs11-tool --id.
    """
    SELECT_SC_HSM_HEX = "00A404000BE82B0601040181C31F020100"
    LIST_KEYS_HEX = "8058000000"
    result = subprocess.run(
        ["opensc-tool", f"-r{reader}", "-s", SELECT_SC_HSM_HEX, "-s", LIST_KEYS_HEX],
        capture_output=True, timeout=10,
    )
    output = result.stdout.decode(errors="replace")
    # Parse the last Received block (response to LIST KEYS)
    blocks: list[bytearray] = []
    current: bytearray | None = None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Received"):
            current = bytearray()
        elif stripped.startswith("Sending") and current is not None:
            blocks.append(current)
            current = None
        elif current is not None:
            tokens = [t for t in stripped.split()
                      if len(t) == 2 and all(c in "0123456789abcdefABCDEF" for c in t)]
            for tok in tokens[:16]:
                current.append(int(tok, 16))
    if current is not None:
        blocks.append(current)
    if not blocks:
        # Same diagnostic as below: an empty parse is the case worth seeing.
        log.warning("_get_first_key_slot: no response blocks; stdout=%r stderr=%r",
                    output, result.stderr.decode(errors="replace"))
        return None
    resp = blocks[-1]
    # Walk pairs looking for 0xCC (key blob), skip slot 0 (device sentinel)
    # and reserved slots (>= 0xF0).  Slot 0 is pre-populated by INITIALIZE as
    # a sentinel to prevent sc_hsm_determine_free_id from assigning it;
    # it has no actual key material and cannot be wrapped.
    i = 0
    while i + 1 < len(resp):
        hi, lo = resp[i], resp[i + 1]
        if hi == 0xCC and lo != 0x00 and lo < 0xF0:
            return lo
        i += 2
    # Diagnostic: no usable 0xCC slot found.  Log the raw opensc-tool output
    # and the parsed block list so firmware-side reset/reconnect bugs are
    # visible in the test log instead of just returning None silently.
    log.warning("_get_first_key_slot returning None; stdout=%r stderr=%r",
                output, result.stderr.decode(errors="replace"))
    log.warning("parsed blocks (%d): %s",
                len(blocks), [bytes(b).hex() for b in blocks])
    return None


def _import_dkek_share(share_path: Path, passphrase: str) -> None:
    """Import a DKEK share into the device."""
    result = subprocess.run(
        [
            "sc-hsm-tool",
            "--import-dkek-share", str(share_path),
            "--password", passphrase,
        ],
        capture_output=True, timeout=30,
    )
    assert result.returncode == 0, (
        f"Failed to import DKEK share: {result.stderr.decode()}"
    )
    log.info("DKEK share imported from %s", share_path)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def dkek_initialized_device(runner: CLIRunner, config: dict, tmp_path_factory) -> dict:
    """Initialize device with 1 DKEK share, create and import the share.

    Returns a dict with:
        share_path: Path to the DKEK share file
        passphrase: The passphrase protecting the share
    """
    # Check hardware is present
    if not _wait_for_device(timeout=10.0):
        pytest.skip("No HSM device found")

    share_dir = tmp_path_factory.mktemp("dkek")
    share_path = share_dir / "dkek-share.pbe"

    _initialize_with_dkek(config, dkek_shares=1)
    _create_dkek_share(share_path, DKEK_PASSPHRASE)
    _import_dkek_share(share_path, DKEK_PASSPHRASE)

    return {
        "share_path": share_path,
        "passphrase": DKEK_PASSPHRASE,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDkekWrapUnwrapRoundtrip:
    """Full backup/restore round-trip: generate -> wrap -> wipe -> unwrap -> verify."""

    def test_dkek_wrap_unwrap_roundtrip(
        self,
        dkek_initialized_device: dict,
        runner: CLIRunner,
        config: dict,
        tmp_path: Path,
    ) -> None:
        """A key wrapped (exported) via DKEK can be unwrapped (restored) after re-init."""
        share_path = dkek_initialized_device["share_path"]
        passphrase = dkek_initialized_device["passphrase"]

        # 1. Generate a P-256 key on the device
        log.info("Generating P-256 key (pkcs15-id=%s) for wrap/unwrap test...", KEY_ID)
        keygen = runner.pkcs11_tool(
            "--login",
            "--pin", config["pin"],
            "--keypairgen",
            "--key-type", "EC:prime256v1",
            "--id", KEY_ID,
            "--label", KEY_LABEL,
            save_as="11_keygen",
        )
        assert keygen.returncode == 0, (
            f"Key generation failed: rc={keygen.returncode}\n{keygen.stderr}"
        )
        log.info("Key generated (pkcs15-id=%s)", KEY_ID)

        # Discover the actual device key slot (device-assigned, not PKCS#15 id).
        # OpenSC's sc_hsm_determine_free_id picks the first free slot; after
        # fresh initialization the first key always lands in slot 1, but we
        # query to be safe.
        device_slot = _get_first_key_slot(reader=0)
        assert device_slot is not None, "Could not detect device key slot after keygen"
        log.info("Device key slot (for wrap/unwrap): %d (0x%02X)", device_slot, device_slot)

        # 2. Export the public key (to verify after restore)
        pubkey_der_path = tmp_path / "pubkey_original.der"
        export = runner.pkcs11_tool(
            "--login",
            "--pin", config["pin"],
            "--read-object",
            "--type", "pubkey",
            "--id", KEY_ID,
            "--output-file", str(pubkey_der_path),
            save_as="11_pubkey_export",
        )
        assert export.returncode == 0, (
            f"Public key export failed: {export.stderr}"
        )
        original_pub_der = pubkey_der_path.read_bytes()
        original_pub_key = serialization.load_der_public_key(
            original_pub_der, backend=default_backend()
        )
        original_pub_pem = original_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        log.info("Original public key exported (%d bytes DER)", len(original_pub_der))

        # 3. Wrap (export) the key using the actual device slot number
        wrap_file = tmp_path / "wrapped_key.bin"
        wrap = runner.sc_hsm_tool(
            "--wrap-key", str(wrap_file),
            "--key-reference", str(device_slot),
            "--pin", config["pin"],
            save_as="11_wrap_key",
        )
        assert wrap.returncode == 0, (
            f"Wrap key failed: rc={wrap.returncode}\n{wrap.stderr}"
        )
        assert wrap_file.exists() and wrap_file.stat().st_size > 0, (
            "Wrap file is empty or missing"
        )
        log.info("Key wrapped to %s (%d bytes)", wrap_file, wrap_file.stat().st_size)

        # 4. Re-initialize the device (wipes all keys)
        log.info("Re-initializing device (wipes all keys)...")
        _initialize_with_dkek(config, dkek_shares=1)

        # 5. Re-import the same DKEK share
        _import_dkek_share(share_path, passphrase)

        # 6. Unwrap (restore) the key — restore to same device slot
        unwrap = runner.sc_hsm_tool(
            "--unwrap-key", str(wrap_file),
            "--key-reference", str(device_slot),
            "--pin", config["pin"],
            save_as="11_unwrap_key",
        )
        assert unwrap.returncode == 0, (
            f"Unwrap key failed: rc={unwrap.returncode}\n{unwrap.stderr}"
        )
        log.info("Key unwrapped (restored) to slot %d (0x%02X)", device_slot, device_slot)

        # 7. Sign something with the restored key
        msg_file = tmp_path / "message.bin"
        sig_file = tmp_path / "signature.bin"
        msg_file.write_bytes(b"DKEK roundtrip verification message")

        sign = runner.pkcs11_tool(
            "--login",
            "--pin", config["pin"],
            "--sign",
            "--mechanism", "ECDSA-SHA256",
            "--id", KEY_ID,
            "--input-file", str(msg_file),
            "--output-file", str(sig_file),
            save_as="11_sign_after_restore",
        )
        assert sign.returncode == 0, (
            f"Sign with restored key failed: rc={sign.returncode}\n{sign.stderr}"
        )
        assert sig_file.exists() and sig_file.stat().st_size > 0, (
            "Signature file is empty or missing"
        )
        log.info("Signed with restored key (%d bytes)", sig_file.stat().st_size)

        # 8. Verify signature with the original public key
        sig_bytes = sig_file.read_bytes()
        msg_bytes = msg_file.read_bytes()

        # pkcs11-tool outputs raw r||s signature; convert to DER for cryptography lib
        r_len = len(sig_bytes) // 2
        r = int.from_bytes(sig_bytes[:r_len], "big")
        s = int.from_bytes(sig_bytes[r_len:], "big")
        der_sig = utils.encode_dss_signature(r, s)

        original_pub_key.verify(
            der_sig,
            msg_bytes,
            ec.ECDSA(hashes.SHA256()),
        )
        log.info("Signature verified with original public key — round-trip OK")


class TestDkekDifferentSharesIncompatible:
    """Verify that a key wrapped under one DKEK cannot be unwrapped with a different DKEK."""

    def test_dkek_different_shares_incompatible(
        self,
        runner: CLIRunner,
        config: dict,
        tmp_path: Path,
    ) -> None:
        """Unwrap must fail when the DKEK share does not match the one used to wrap."""
        # Check hardware is present
        if not _wait_for_device(timeout=10.0):
            pytest.skip("No HSM device found")

        share_a = tmp_path / "share_a.pbe"
        share_b = tmp_path / "share_b.pbe"
        passphrase_a = "share-alpha"
        passphrase_b = "share-bravo"

        # Create two independent DKEK shares
        _create_dkek_share(share_a, passphrase_a)
        _create_dkek_share(share_b, passphrase_b)

        # Initialize with share A, generate a key, wrap it
        _initialize_with_dkek(config, dkek_shares=1)
        _import_dkek_share(share_a, passphrase_a)

        keygen = runner.pkcs11_tool(
            "--login",
            "--pin", config["pin"],
            "--keypairgen",
            "--key-type", "EC:prime256v1",
            "--id", KEY_ID,
            "--label", "dkek-mismatch-test",
            save_as="11_mismatch_keygen",
        )
        assert keygen.returncode == 0, (
            f"Key generation failed: {keygen.stderr}"
        )

        # Detect the actual device slot assigned to this key
        mismatch_slot = _get_first_key_slot(reader=0)
        assert mismatch_slot is not None, "Could not detect device key slot after mismatch keygen"
        log.info("Mismatch test key in device slot %d (0x%02X)", mismatch_slot, mismatch_slot)

        wrap_file = tmp_path / "wrapped_share_a.bin"
        wrap = runner.sc_hsm_tool(
            "--wrap-key", str(wrap_file),
            "--key-reference", str(mismatch_slot),
            "--pin", config["pin"],
            save_as="11_mismatch_wrap",
        )
        assert wrap.returncode == 0, (
            f"Wrap failed: {wrap.stderr}"
        )
        log.info("Key wrapped under share A (%d bytes)", wrap_file.stat().st_size)

        # Re-initialize with share B (different DKEK)
        _initialize_with_dkek(config, dkek_shares=1)
        _import_dkek_share(share_b, passphrase_b)

        # Attempt to unwrap — must fail because the DKEK does not match
        unwrap = runner.sc_hsm_tool(
            "--unwrap-key", str(wrap_file),
            "--key-reference", str(mismatch_slot),
            "--pin", config["pin"],
            save_as="11_mismatch_unwrap",
        )
        assert unwrap.returncode != 0, (
            "Unwrap should have FAILED with a different DKEK share, "
            f"but returned rc=0.\nstdout: {unwrap.stdout}\nstderr: {unwrap.stderr}"
        )
        log.info(
            "Unwrap correctly rejected with mismatched DKEK (rc=%d)",
            unwrap.returncode,
        )
