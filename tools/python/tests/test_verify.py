"""Thin wrapper that runs verify.sh and asserts all checks pass.

Requires two pico2hsm devices connected.  Skips daemon checks
since the test environment may not have the systemd service installed.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

# Resolve verify.sh relative to this file:
#   this file:  tools/python/tests/test_verify.py
#   verify.sh:  <repo_root>/verify.sh
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
VERIFY_SCRIPT = REPO_ROOT / "verify.sh"


def _reader_count() -> int:
    """Return the number of readers with cards present."""
    try:
        r = subprocess.run(
            ["opensc-tool", "--list-readers"],
            capture_output=True,
            timeout=5,
        )
        return r.stdout.decode().count("Yes")
    except Exception:
        return 0


@pytest.fixture(autouse=True)
def require_two_devices():
    count = _reader_count()
    if count < 2:
        pytest.skip(
            f"Two pico2hsm devices required; only {count} reader(s) with cards found."
        )


def test_verify_script_passes():
    """verify.sh must exit 0 with both devices connected."""
    assert VERIFY_SCRIPT.exists(), f"verify.sh not found at {VERIFY_SCRIPT}"

    result = subprocess.run(
        ["bash", str(VERIFY_SCRIPT), "--skip-daemon"],
        capture_output=True,
        timeout=120,
        cwd=str(REPO_ROOT),
    )

    stdout = result.stdout.decode(errors="replace")
    stderr = result.stderr.decode(errors="replace")

    assert result.returncode == 0, (
        f"verify.sh exited with code {result.returncode}\n"
        f"--- stdout ---\n{stdout}\n"
        f"--- stderr ---\n{stderr}"
    )


def test_verify_script_full_passes():
    """verify.sh --full must exit 0 with both devices connected."""
    assert VERIFY_SCRIPT.exists(), f"verify.sh not found at {VERIFY_SCRIPT}"

    result = subprocess.run(
        ["bash", str(VERIFY_SCRIPT), "--skip-daemon", "--full"],
        capture_output=True,
        timeout=180,
        cwd=str(REPO_ROOT),
    )

    stdout = result.stdout.decode(errors="replace")
    stderr = result.stderr.decode(errors="replace")

    assert result.returncode == 0, (
        f"verify.sh --full exited with code {result.returncode}\n"
        f"--- stdout ---\n{stdout}\n"
        f"--- stderr ---\n{stderr}"
    )
