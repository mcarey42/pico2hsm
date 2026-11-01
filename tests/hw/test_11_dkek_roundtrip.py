"""Hardware integration tests for DKEK key backup (WRAP / UNWRAP KEY).

WRAP KEY (80 72) writes, and UNWRAP KEY (80 74) reads, the SmartCard-HSM
(CardContact) key blob, as real SmartCard-HSMs and `sc-hsm-tool` do
(docs/SC_HSM_APDU_REFERENCE.md, "Key backup blob").  The KCV that KEY
DOMAIN reports (and `sc-hsm-tool` prints) is SHA-256(DKEK)[0..8].

TestDkekWrapUnwrapRoundtrip:
  generate -> wrap -> re-initialize -> re-import share -> unwrap -> sign.
TestDkekDifferentSharesIncompatible:
  a blob does not unwrap under another DKEK.
TestCardContactInterop:
  1. INITIALIZE with two DKEK shares created by sc-hsm-tool;
  2. the KCV sc-hsm-tool prints equals SHA-256(share1 XOR share2)[0..8],
     computed on the host from the decrypted share files;
  3. sc-hsm-tool --wrap-key: the blob in the .wky file opens with the host
     reference (tools/python/pico2hsm/cardcontact_wrap.py) and holds the
     private key of the public key the device reports;
  4. delete the key, sc-hsm-tool --unwrap-key it back, sign, verify;
  5. a blob made on the host by the reference unwraps with sc-hsm-tool
     and signs.

Wire format (sc-hsm-tool standard):
  - Import DKEK share:  80 52 00 00 20 <32 raw bytes>
  - Key domain status:  80 52 00 00 00
  - Wrap key:           80 72 <key_ref> 92 00
  - Unwrap key:         WRITE EF 2F10 <blob>; 80 74 <key_ref> 93
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from pathlib import Path

import pytest

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from helpers.cli import CLIRunner
from helpers.pcsc import dut_index

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
    # Walk pairs looking for 0xCC (key blob), skip slot 0 (the device key's
    # reference, always listed so sc_hsm_determine_free_id never assigns
    # it; no key material, cannot be wrapped) and reserved slots (>= 0xF0).
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
        device_slot = _get_first_key_slot(reader=dut_index())
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
        mismatch_slot = _get_first_key_slot(reader=dut_index())
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


# ---------------------------------------------------------------------------
# CardContact interoperability (P0)
# ---------------------------------------------------------------------------

def _load_reference():
    """The host reference implementation of the CardContact key blob."""
    import importlib.util
    import sys

    path = Path(__file__).resolve().parents[2] / "tools" / "python" / "pico2hsm" / "cardcontact_wrap.py"
    spec = importlib.util.spec_from_file_location("cardcontact_wrap", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cardcontact_wrap"] = mod
    spec.loader.exec_module(mod)
    return mod


def _evp_bytes_to_key_md5(password: bytes, salt: bytes, count: int, n: int) -> bytes:
    """OpenSSL EVP_BytesToKey(MD5, count) — what sc-hsm-tool uses for share files."""
    import hashlib

    out, prev = b"", b""
    while len(out) < n:
        d = hashlib.md5(prev + password + salt).digest()
        for _ in range(count - 1):
            d = hashlib.md5(d).digest()
        out += d
        prev = d
    return out[:n]


def _decrypt_share_file(path: Path, password: str) -> bytes:
    """The 32-byte share in an sc-hsm-tool DKEK share file.

    File: "Salted__" | salt(8) | AES-256-CBC(EVP_BytesToKey(MD5, 10^7)) of
    the share, PKCS#7 padded (OpenSC sc-hsm-tool.c create_dkek_share).
    About 30 s of MD5 on the host per share.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    data = path.read_bytes()
    assert len(data) == 64 and data[:8] == b"Salted__", "not a DKEK share file"
    kiv = _evp_bytes_to_key_md5(password.encode(), data[8:16], 10_000_000, 48)
    dec = Cipher(algorithms.AES(kiv[:32]), modes.CBC(kiv[32:])).decryptor()
    plain = dec.update(data[16:]) + dec.finalize()
    assert plain[32:] == bytes([16]) * 16, "wrong share password"
    return plain[:32]


def _der_items(data: bytes) -> list[tuple[int, bytes]]:
    """Top-level (tag, value) items of a DER string (one-byte tags)."""
    items, i = [], 0
    while i < len(data):
        tag, l0 = data[i], data[i + 1]
        i += 2
        if l0 & 0x80:
            n = l0 & 0x7F
            length = int.from_bytes(data[i:i + n], "big")
            i += n
        else:
            length = l0
        items.append((tag, data[i:i + length]))
        i += length
    return items


def _wky_blob(path: Path) -> bytes:
    """The key blob inside a .wky file: SEQUENCE { OCTET STRING blob, [PRKD], [cert] }."""
    [(tag, seq)] = _der_items(path.read_bytes())
    assert tag == 0x30
    items = _der_items(seq)
    assert items[0][0] == 0x04
    return items[0][1]


def _printed_kcv(text: str) -> str:
    import re

    found = re.findall(r"key check value\s*:\s*([0-9A-Fa-f ]+)", text, re.IGNORECASE)
    assert found, f"no Key Check Value in:\n{text}"
    return found[-1].replace(" ", "").strip().lower()


class TestCardContactInterop:
    """SmartCard-HSM / OpenSC compatibility of DKEK shares, KCV and key blobs."""

    def test_cardcontact_wrap_unwrap_and_kcv(
        self, runner: CLIRunner, config: dict, tmp_path: Path,
    ) -> None:
        if not _wait_for_device(timeout=10.0):
            pytest.skip("No HSM device found")
        cc = _load_reference()

        # 1. Two shares from sc-hsm-tool, INITIALIZE for two, import both.
        shares = [(tmp_path / f"share{i}.pbe", f"cc-interop-share-{i}") for i in (1, 2)]
        for path, pw in shares:
            _create_dkek_share(path, pw)
        _initialize_with_dkek(config, dkek_shares=2)
        for path, pw in shares:
            _import_dkek_share(path, pw)

        # 2. The KCV sc-hsm-tool prints is SHA-256(share1 ^ share2)[0..8].
        info = runner.sc_hsm_tool(save_as="11cc_info")
        assert info.returncode == 0, info.stderr[-2000:]
        assert re.search(r"DKEK shares\s*:\s*2\b", info.stdout), info.stdout
        printed = _printed_kcv(info.stdout)
        dkek = cc.combine_shares(*(_decrypt_share_file(p, pw) for p, pw in shares))
        assert printed == cc.kcv(dkek).hex(), (printed, cc.kcv(dkek).hex())
        log.info("KCV %s matches SHA-256(DKEK)[0..8]", printed)

        # 3. Generate, wrap with sc-hsm-tool, open the blob on the host.
        keygen = runner.pkcs11_tool(
            "--login", "--pin", config["pin"], "--keypairgen",
            "--key-type", "EC:prime256v1", "--id", "31", "--label", "cc-interop",
            save_as="11cc_keygen",
        )
        assert keygen.returncode == 0, keygen.stderr[-2000:]
        slot = _get_first_key_slot(reader=dut_index())
        assert slot is not None
        pub_der_path = tmp_path / "pub.der"
        export = runner.pkcs11_tool(
            "--login", "--pin", config["pin"], "--read-object", "--type", "pubkey",
            "--id", "31", "--output-file", str(pub_der_path), save_as="11cc_pub",
        )
        assert export.returncode == 0, export.stderr[-2000:]
        pub = serialization.load_der_public_key(pub_der_path.read_bytes())

        wky = tmp_path / "cc.wky"
        wrap = runner.sc_hsm_tool(
            "--wrap-key", str(wky), "--key-reference", str(slot), "--pin", config["pin"],
            save_as="11cc_wrap",
        )
        assert wrap.returncode == 0, wrap.stderr[-2000:]
        blob = _wky_blob(wky)
        assert blob[:8] == cc.kcv(dkek), "blob KCV"
        assert blob[8] == cc.KEY_TYPE_EC, "CardContact EC key blob"
        opened = cc.unwrap(dkek, blob)
        d = int.from_bytes(opened.fields[5], "big")
        assert ec.derive_private_key(d, ec.SECP256R1()).public_key().public_numbers() \
            == pub.public_numbers(), "blob holds the device's key"
        log.info("Device blob (%d bytes) opened with the host reference", len(blob))

        # 4. Delete the key, unwrap it back with sc-hsm-tool, sign, verify.
        delete = runner.pkcs11_tool(
            "--login", "--pin", config["pin"], "--delete-object", "--type", "privkey",
            "--id", "31", save_as="11cc_delete",
        )
        log.info("delete privkey rc=%d", delete.returncode)
        unwrap = runner.sc_hsm_tool(
            "--unwrap-key", str(wky), "--key-reference", str(slot), "--pin", config["pin"],
            "--force", save_as="11cc_unwrap",
        )
        assert unwrap.returncode == 0, unwrap.stdout + unwrap.stderr[-2000:]
        self._sign_and_verify(runner, config, tmp_path, "31", pub, "11cc_sign")

        # 5. A blob made on the host unwraps on the device and signs.
        d2 = int.from_bytes(os.urandom(32), "big") % (cc.CURVES["P-256"].n - 1) + 1
        size, mat = cc.ec_material(cc.CURVES["P-256"], d2)
        host_blob = cc.wrap(dkek, cc.KEY_TYPE_EC, cc.OID_ECDSA_SHA256, size, mat, os.urandom(8))
        host_wky = tmp_path / "host.wky"
        inner = bytes([0x04, 0x82]) + len(host_blob).to_bytes(2, "big") + host_blob
        host_wky.write_bytes(bytes([0x30, 0x82]) + len(inner).to_bytes(2, "big") + inner)
        slot2 = slot + 1
        unwrap2 = runner.sc_hsm_tool(
            "--unwrap-key", str(host_wky), "--key-reference", str(slot2),
            "--pin", config["pin"], "--force", save_as="11cc_unwrap_host",
        )
        assert unwrap2.returncode == 0, unwrap2.stdout + unwrap2.stderr[-2000:]
        # No PRKD came with the host blob: sign with the raw SC-HSM APDU
        # (80 68 <ref> 70: ECDSA over a SHA-256 hash) and verify on the host.
        import hashlib

        msg = b"host-made CardContact blob"
        digest = hashlib.sha256(msg).digest()
        pin = config["pin"].encode("ascii")
        apdus = [
            "00A404000BE82B0601040181C31F020100",
            f"00200081{len(pin):02X}{pin.hex()}",
        ]
        apdus.append(f"8068{slot2:02X}7020{digest.hex()}00")
        args = ["opensc-tool", f"-r{dut_index()}"]
        for a in apdus:
            args += ["-s", a]
        res = runner.run(args, save_as="11cc_host_sign")
        assert res.returncode == 0, res.stderr[-2000:]
        sig = _last_response(res.stdout)
        pub2 = ec.derive_private_key(d2, ec.SECP256R1()).public_key()
        pub2.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        log.info("Host-made blob unwrapped and signed on the device")

    @staticmethod
    def _sign_and_verify(runner, config, tmp_path, key_id, pub, save_as) -> None:
        msg_file = tmp_path / f"{save_as}.msg"
        sig_file = tmp_path / f"{save_as}.sig"
        msg_file.write_bytes(b"CardContact interop " + save_as.encode())
        sign = runner.pkcs11_tool(
            "--login", "--pin", config["pin"], "--sign", "--mechanism", "ECDSA-SHA256",
            "--id", key_id, "--input-file", str(msg_file), "--output-file", str(sig_file),
            save_as=save_as,
        )
        assert sign.returncode == 0, sign.stderr[-2000:]
        raw = sig_file.read_bytes()
        r = int.from_bytes(raw[: len(raw) // 2], "big")
        s_ = int.from_bytes(raw[len(raw) // 2:], "big")
        pub.verify(utils.encode_dss_signature(r, s_), msg_file.read_bytes(),
                   ec.ECDSA(hashes.SHA256()))


def _last_response(stdout: str) -> bytes:
    """Data bytes of the last opensc-tool response (SW 9000 required)."""
    blocks, cur = [], None
    for line in stdout.splitlines():
        t = line.strip()
        if t.startswith("Received"):
            assert "SW1=0x90, SW2=0x00" in t, t
            cur = bytearray()
            blocks.append(cur)
        elif t.startswith("Sending"):
            cur = None
        elif cur is not None:
            for tok in t.split()[:16]:
                if len(tok) == 2 and all(c in "0123456789abcdefABCDEF" for c in tok):
                    cur.append(int(tok, 16))
    assert blocks, stdout
    return bytes(blocks[-1])

