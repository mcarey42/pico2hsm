"""Session-scoped pytest fixtures for pico2hsm hardware integration tests."""

from __future__ import annotations

import logging
import os
import subprocess
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from helpers.cli import CLIRunner
from helpers import trace

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Target reader selection
# ---------------------------------------------------------------------------
# PICO2HSM_READER=<substring of one reader name> (e.g. the board's USB serial,
# its chip ID) selects the device under test, resolved on every connection:
# reader indexes shift whenever a board re-enumerates (flash, probe-rs reset).
# OPENSC_DEFAULT_READER=N selects it by index instead.  The pyscard helpers
# honour both, but OpenSC's tools and GnuPG do not (they always use reader 0),
# so with several devices attached a bare `opensc-tool` would silently test
# another device.  When either is set, the shims in helpers/bin add the reader to
# opensc-tool / sc-hsm-tool / pkcs11-tool.  GnuPG 2.4's scdaemon opens every
# reader and ignores reader-port; `gpg_card_status_cmd()` reads the device
# under test by its OpenPGP serial (`gpg-card list <serial>`; per device since
# 2.0; older firmware shares one, so gpg can then only test reader 0).

_HW_DIR = Path(__file__).resolve().parent


def target_reader() -> int:
    from helpers.pcsc import dut_index

    return dut_index()


def _reader_name(index: int) -> str | None:
    try:
        from smartcard.System import readers

        return str(readers()[index])
    except Exception:
        return None


def probe_reset_skip_reason() -> str | None:
    """Why a probe-rs reset can't target the device under test, if it can't."""
    if os.environ.get("PROBE_RS_PROBE"):
        return None
    try:
        out = subprocess.run(["probe-rs", "list"], capture_output=True, timeout=15).stdout.decode()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "probe-rs not available"
    probes = [l for l in out.splitlines() if l.strip().startswith("[")]
    if not probes:
        return "no debug probe attached"
    if len(probes) > 1:
        return "several debug probes attached: set PROBE_RS_PROBE=VID:PID:SERIAL for the device under test"
    if target_reader() != 0:
        return "OPENSC_DEFAULT_READER selects another device: set PROBE_RS_PROBE for its probe"
    return None


def _dut_openpgp_serial() -> str | None:
    """The device under test's OpenPGP AID (scdaemon's card serial), hex."""
    from helpers.pcsc import session

    try:
        with session(target_reader()) as s:
            data, sw = s.send(bytes.fromhex("00A4040006D27600012401"))
    except Exception:
        return None
    i = data.find(b"\x84\x10")
    return data[i + 2:i + 18].hex().upper() if sw == 0x9000 and i >= 0 else None


def gpg_card_status_cmd(learn: bool = False) -> tuple[list[str] | None, str | None]:
    """Restart scdaemon; return (command printing the card status of the
    device under test, None) or (None, skip reason).

    scdaemon's current card is per connection, so `scd switchcard` can't
    steer a later `gpg --card-status`; `gpg-card list <serial>` selects the
    card in its own session.  It shows keygrips, not fingerprints, for keys
    not in the keyring, so `learn=True` returns an agent session that selects
    the card and prints scdaemon's status lines (`S KEY-FPR 1 <hex>`).
    """
    try:
        subprocess.run(["gpgconf", "--kill", "scdaemon"], capture_output=True, timeout=30)
        serial = _dut_openpgp_serial()
        cards = subprocess.run(
            ["gpg-connect-agent", "scd serialno --all", "scd getinfo card_list", "/bye"],
            capture_output=True, text=True, timeout=30).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None, "gpg / scdaemon not available"
    # One reply per command: `serialno --all` (the current card), then the
    # card list.
    replies = cards.split("\nOK")
    listed = [l.split()[2] for l in replies[1].splitlines()
              if l.startswith("S SERIALNO ")] if len(replies) > 1 else []
    if serial is not None and listed.count(serial) == 1:
        if learn:
            return ["gpg-connect-agent", "scd serialno --all", f"scd switchcard {serial}",
                    "scd learn --force", "/bye"], None
        return ["gpg-card", "--no-history", "list", serial], None
    if target_reader() != 0:
        return None, "gpg/scdaemon can only reach reader 0 (devices share one OpenPGP serial)"
    return ["gpg", "--no-tty", "--card-status"], None


def pytest_configure(config):
    # OpenSC's PKCS#11 module lists only four readers by default; see
    # helpers/opensc.conf.
    os.environ.setdefault("OPENSC_CONF", str(_HW_DIR / "helpers" / "opensc.conf"))
    if "OPENSC_DEFAULT_READER" not in os.environ and "PICO2HSM_READER" not in os.environ:
        return
    os.environ["PATH"] = f"{_HW_DIR / 'helpers' / 'bin'}{os.pathsep}{os.environ['PATH']}"
    name = _reader_name(target_reader())
    log.info("device under test: reader %d (%s)", target_reader(), name)

# ---------------------------------------------------------------------------
# Key slot definitions (used in multiple test modules)
# ---------------------------------------------------------------------------

KEY_SLOTS: list[dict] = [
    {
        "name":        "p256",
        "curve_openssl": "prime256v1",
        "curve_display": "P-256",
        "key_id":      "01",
        "hash":        "sha256",
        "mechanism":   "ECDSA-SHA256",
        "ecdh":        True,
    },
    {
        "name":        "p384",
        "curve_openssl": "secp384r1",
        "curve_display": "P-384",
        "key_id":      "02",
        "hash":        "sha384",
        "mechanism":   "ECDSA-SHA384",
        "ecdh":        True,
    },
    {
        "name":        "p521",
        "curve_openssl": "secp521r1",
        "curve_display": "P-521",
        "key_id":      "03",
        "hash":        "sha512",
        "mechanism":   "ECDSA-SHA512",
        "ecdh":        True,
    },
    {
        "name":        "k256",
        "curve_openssl": "secp256k1",
        "curve_display": "K-256 (secp256k1)",
        "key_id":      "04",
        "hash":        "sha256",
        "mechanism":   "ECDSA-SHA256",
        "ecdh":        True,
    },
]

# RSA key slot definitions (used by RSA-specific test modules).
RSA_KEY_SLOTS: list[dict] = [
    {
        "name":        "rsa2048",
        "key_size":    2048,
        "key_id":      "10",   # slot 0x0A — after EC slots 01-04
        "mechanism_pkcs": "SHA256-RSA-PKCS",
        "mechanism_pss":  "SHA256-RSA-PKCS-PSS",
        "mechanism_enc":  "RSA-PKCS",
        "hash":        "sha256",
        "sig_len":     256,    # RSA-2048 signature = 256 bytes
    },
    {
        "name":        "rsa3072",
        "key_size":    3072,
        "key_id":      "11",   # slot 0x0B — after rsa2048
        "mechanism_pkcs": "SHA256-RSA-PKCS",
        "mechanism_pss":  "SHA256-RSA-PKCS-PSS",
        "mechanism_enc":  "RSA-PKCS",
        "hash":        "sha256",
        "sig_len":     384,    # RSA-3072 signature = 384 bytes
    },
    {
        "name":        "rsa4096",
        "key_size":    4096,
        "key_id":      "12",   # slot 0x0C — after rsa3072
        "mechanism_pkcs": "SHA256-RSA-PKCS",
        "mechanism_pss":  "SHA256-RSA-PKCS-PSS",
        "mechanism_enc":  "RSA-PKCS",
        "hash":        "sha256",
        "sig_len":     512,    # RSA-4096 signature = 512 bytes
    },
]


# ---------------------------------------------------------------------------
# DKEK test prerequisites
# ---------------------------------------------------------------------------
# DKEK exchange and key sync tests (when added) require:
#   1. Device initialized with DKEK shares loaded (via key_domain P1=0x03)
#   2. At least one key generated on the device
# These are currently tested only in tools/python/tests/test_dkek_exchange.py
# using mocks.  Hardware DKEK tests should be xfail until two physical
# devices are available on the CI rig.

# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------

_FORMAT_STORE = "80544E000F" + b"FORMAT-STORE-V2".hex().upper()


def _format_store_if_needed(index: int) -> None:
    """Storage V2: a board flashed with 2.0 over a 1.x keystore refuses its
    store until FORMAT STORE.  The PIN-less form only works when there is
    no valid binding, so on a board that already has a 2.0 store this is
    refused (6982) and changes nothing; firmware before 2.0 does not know
    it."""
    from helpers.pcsc import session

    try:
        with session(index) as s:
            s.send(bytes.fromhex("00A404000BE82B0601040181C31F020100"))
            _, sw = s.send(bytes.fromhex(_FORMAT_STORE))
        if sw == 0x9000:
            log.info("reader %d: Storage V2 store formatted (was a 1.x keystore)", index)
    except Exception as e:  # no device, or no pyscard: the tests will say so
        log.debug("format-store probe on reader %d: %s", index, e)


@pytest.fixture(scope="session", autouse=True)
def storage_v2_ready():
    from helpers.pcsc import dut_index, peer_index

    indexes = set()
    for pick in (dut_index, peer_index):
        try:
            indexes.add(pick())
        except Exception:  # no such device (single-board run)
            pass
    for idx in indexes:
        _format_store_if_needed(idx)
    yield


@pytest.fixture(autouse=True)
def _skip_absent_applet(request):
    """test_piv_* / test_openpgp_* skip when the build lacks that applet."""
    from helpers.applets import APPLETS, applet_present, module_applet

    key = module_applet(request.module.__name__.rsplit(".", 1)[-1])
    if key is not None and not applet_present(key):
        pytest.skip(f"{APPLETS[key][0]} applet not present in this build")


@pytest.fixture(scope="session")
def config() -> dict:
    """Return HSM configuration from environment variables (with defaults)."""
    return {
        "pin":    os.environ.get("HSM_PIN",    "648219"),
        "so_pin": os.environ.get("HSM_SO_PIN", "3537363231383830"),
        "module": os.environ.get(
            "HSM_MODULE",
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        ),
        "label":  os.environ.get("HSM_LABEL",  "pico2hsm"),
    }


@pytest.fixture(scope="session")
def run_dir(request: pytest.FixtureRequest) -> Path:
    """Create a timestamped reports directory and update the 'latest' symlink."""
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    # Resolve relative to the tests/hw directory (where this conftest lives)
    hw_dir = Path(__file__).parent
    reports_root = hw_dir / "reports"
    reports_root.mkdir(parents=True, exist_ok=True)

    dest = reports_root / ts
    dest.mkdir(parents=True, exist_ok=True)

    latest = reports_root / "latest"
    if latest.is_symlink():
        latest.unlink()
    elif latest.is_dir():
        import shutil
        shutil.rmtree(latest)
    latest.symlink_to(dest.name)

    log.info("Report directory: %s", dest)
    return dest


@pytest.fixture(scope="session")
def runner(config: dict, run_dir: Path) -> CLIRunner:
    """Return a CLIRunner configured for this session."""
    return CLIRunner(config=config, run_dir=run_dir)


@pytest.fixture(scope="session")
def initialized_device(runner: CLIRunner, config: dict, run_dir: Path):
    """Initialize the HSM device and return the CLIResult.

    This fixture must succeed for all subsequent tests; it is session-scoped
    so initialization happens exactly once.
    """
    # Wait for the device to be visible to pcscd before attempting INITIALIZE.
    # pcscd may take a few seconds after USB enumeration to list the reader.
    log.info("Waiting for device to be visible before INITIALIZE...")
    if not _wait_for_device(timeout=20.0):
        pytest.fail(
            "HSM device not found by pcscd before INITIALIZE.\n"
            "Make sure the device is connected, pcscd is running, and the\n"
            "USB reader appears in: opensc-tool --list-readers"
        )

    result = runner.sc_hsm_tool(
        "--initialize",
        "--label",  config["label"],
        "--so-pin", config["so_pin"],
        "--pin",    config["pin"],
        save_as="00_initialize",
    )

    # Parse and save APDU trace
    exchanges = trace.parse_apdu_trace(result.stderr)
    json_path = run_dir / "00_initialize.json"
    trace.save_json_trace(json_path, "initialized_device", result, exchanges)

    log.info(
        "INITIALIZE: rc=%d  elapsed=%.0f ms  APDUs=%d",
        result.returncode,
        result.elapsed_ms,
        len(exchanges),
    )

    # sc-hsm-tool returns rc=0 even when no card is found — check stderr too.
    no_card = (
        "No smart card readers found" in result.stderr
        or "No readers found" in result.stderr
        or "Failed to connect to card" in result.stderr
        or "SCardListReaders failed" in result.stderr
    )
    if result.returncode != 0 or no_card:
        pytest.fail(
            f"HSM initialization failed (rc={result.returncode}).\n"
            f"Make sure the device is connected and pcscd is running.\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )

    # After INITIALIZE the device resets and USB re-enumerates.
    # Wait up to 20 s for pcscd to re-detect it before proceeding.
    log.info("Waiting for device to re-enumerate after INITIALIZE...")
    _wait_for_device(timeout=20.0)

    return result


def _wait_for_device(timeout: float = 20.0, poll_interval: float = 0.5) -> bool:
    """Poll opensc-tool until the HSM card is present and accessible.

    Returns True once the card column shows "Yes" (card inserted and
    recognised by pcscd), False if the timeout expired.

    We check for card presence, not just reader presence, because adding
    the CDC-ACM interface means USB re-enumeration takes slightly longer
    and pcscd may report the reader before the card is accessible.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = subprocess.run(
                ["opensc-tool", "--list-readers"],
                capture_output=True,
                timeout=5,
            )
            # The card column shows "Yes" when a card is inserted and accessible.
            # Example line: "0    Yes             pico2hsm SC-HSM (0001) 00 00"
            if r.returncode == 0 and b"Yes" in r.stdout:
                log.info("Device card detected and accessible by pcscd.")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        time.sleep(poll_interval)
    log.warning("Device did not appear within %.0f s.", timeout)
    return False


@pytest.fixture(scope="session")
def provisioned_keys(
    initialized_device,  # noqa: ARG001 – ensures init ran first
    runner: CLIRunner,
    config: dict,
    run_dir: Path,
) -> dict[str, dict]:
    """Generate EC key pairs for all KEY_SLOTS on the device.

    Returns a dict keyed by slot name:
        {
            "p256": {
                "generated": True,
                "pub_pem": "-----BEGIN PUBLIC KEY-----\\n...",
                "keygen_trace": CLIResult,
            },
            ...
        }

    Slots that fail are recorded with generated=False and pub_pem=None;
    a pytest warning is issued but the fixture does not fail.
    """
    results: dict[str, dict] = {}

    for slot in KEY_SLOTS:
        name     = slot["name"]
        curve    = slot["curve_openssl"]
        key_id   = slot["key_id"]
        save_key = f"01_keygen_{name}"

        log.info("Generating %s key (id=%s)...", slot["curve_display"], key_id)

        keygen = runner.pkcs11_tool(
            "--login",
            "--pin",         config["pin"],
            "--keypairgen",
            "--key-type",    f"EC:{curve}",
            "--id",          key_id,
            "--label",       name,
            save_as=save_key,
        )

        if keygen.returncode != 0:
            warnings.warn(
                f"Key generation FAILED for {slot['curve_display']} (id={key_id}): "
                f"rc={keygen.returncode}\n{keygen.stderr}",
                stacklevel=1,
            )
            results[name] = {"generated": False, "pub_pem": None, "keygen_trace": keygen}
            continue

        # Export the public key to a file (avoids binary-on-stdout issues)
        pub_pem: str | None = None
        pubkey_der_path = run_dir / f"pubkey_{name}.der"
        export = runner.pkcs11_tool(
            "--login",
            "--pin",          config["pin"],
            "--read-object",
            "--type",         "pubkey",
            "--id",           key_id,
            "--output-file",  str(pubkey_der_path),
            save_as=f"01_pubkey_{name}",
        )

        if export.returncode == 0 and pubkey_der_path.exists():
            raw = pubkey_der_path.read_bytes()
            try:
                pub_key = serialization.load_der_public_key(raw, backend=default_backend())
                pub_pem = pub_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("ascii")
            except Exception:
                # Some pkcs11-tool versions write PEM instead of DER
                raw_text = raw.decode("ascii", errors="replace")
                if "-----BEGIN PUBLIC KEY-----" in raw_text:
                    pub_pem = raw_text
                else:
                    warnings.warn(
                        f"Could not parse public key for {name}: {raw[:80]!r}",
                        stacklevel=1,
                    )
        else:
            warnings.warn(
                f"Public key export failed for {name}: rc={export.returncode}\n{export.stderr}",
                stacklevel=1,
            )

        # Save a JSON trace for the keygen step
        exchanges = trace.parse_apdu_trace(keygen.stderr)
        trace.save_json_trace(
            run_dir / f"01_keygen_{name}.json",
            f"keygen_{name}",
            keygen,
            exchanges,
        )

        results[name] = {
            "generated": True,
            "pub_pem":   pub_pem,
            "keygen_trace": keygen,
        }
        log.info("  %s: generated=True  pub_pem=%s", name, "OK" if pub_pem else "MISSING")

    return results


@pytest.fixture(scope="session")
def provisioned_rsa_keys(
    initialized_device,  # noqa: ARG001 – ensures init ran first
    runner: CLIRunner,
    config: dict,
    run_dir: Path,
) -> dict[str, dict]:
    """Generate RSA key pairs on the device.

    Returns a dict keyed by slot name:
        {
            "rsa2048": {
                "generated": True,
                "pub_pem": "-----BEGIN PUBLIC KEY-----\\n...",
                "keygen_trace": CLIResult,
            },
            ...
        }
    """
    import warnings as _warnings

    results: dict[str, dict] = {}

    for slot in RSA_KEY_SLOTS:
        name     = slot["name"]
        key_size = slot["key_size"]
        key_id   = slot["key_id"]
        save_key = f"06_rsa_keygen_{name}"

        # RSA keygen on a debug Cortex-M33 (opt-level=1) is slow:
        #   RSA-2048: typically 10–60 s (rarely >120 s)
        #   RSA-4096: highly variable; 15–60 min is not unusual due to large
        #             prime-finding with pure-Rust big-integer arithmetic.
        # Allow 3600 s (1 h) so that the test can complete on unlucky runs.
        keygen_timeout = 3600

        log.info("Generating %s key (id=%s, timeout=%ds)...", name, key_id, keygen_timeout)

        keygen = runner.pkcs11_tool(
            "--login",
            "--pin",         config["pin"],
            "--keypairgen",
            "--key-type",    f"RSA:{key_size}",
            "--id",          key_id,
            "--label",       name,
            save_as=save_key,
            timeout=keygen_timeout,
        )

        if keygen.returncode != 0:
            _warnings.warn(
                f"RSA key generation FAILED for {name} (id={key_id}): "
                f"rc={keygen.returncode}\n{keygen.stderr}",
                stacklevel=1,
            )
            results[name] = {"generated": False, "pub_pem": None, "keygen_trace": keygen}
            continue

        # Export the public key
        pub_pem: str | None = None
        pubkey_der_path = run_dir / f"pubkey_{name}.der"
        export = runner.pkcs11_tool(
            "--login",
            "--pin",          config["pin"],
            "--read-object",
            "--type",         "pubkey",
            "--id",           key_id,
            "--output-file",  str(pubkey_der_path),
            save_as=f"06_rsa_pubkey_{name}",
        )

        if export.returncode == 0 and pubkey_der_path.exists():
            raw = pubkey_der_path.read_bytes()
            try:
                pub_key = serialization.load_der_public_key(raw, backend=default_backend())
                pub_pem = pub_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("ascii")
            except Exception:
                raw_text = raw.decode("ascii", errors="replace")
                if "-----BEGIN PUBLIC KEY-----" in raw_text:
                    pub_pem = raw_text
                else:
                    _warnings.warn(
                        f"Could not parse RSA public key for {name}: {raw[:80]!r}",
                        stacklevel=1,
                    )

        exchanges = trace.parse_apdu_trace(keygen.stderr)
        trace.save_json_trace(
            run_dir / f"06_rsa_keygen_{name}.json",
            f"rsa_keygen_{name}",
            keygen,
            exchanges,
        )

        results[name] = {
            "generated":    True,
            "pub_pem":      pub_pem,
            "keygen_trace": keygen,
        }
        log.info("  %s: generated=True  pub_pem=%s", name, "OK" if pub_pem else "MISSING")

    return results
