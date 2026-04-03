"""Session-scoped pytest fixtures for pico2hsm hardware integration tests."""

from __future__ import annotations

import logging
import os
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
        "ecdh":        False,
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
]


# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------

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

    if result.returncode != 0:
        pytest.fail(
            f"HSM initialization failed (rc={result.returncode}).\n"
            f"Make sure the device is connected and pcscd is running.\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )

    return result


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

        log.info("Generating %s key (id=%s)...", name, key_id)

        keygen = runner.pkcs11_tool(
            "--login",
            "--pin",         config["pin"],
            "--keypairgen",
            "--key-type",    f"RSA:{key_size}",
            "--id",          key_id,
            "--label",       name,
            save_as=save_key,
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
