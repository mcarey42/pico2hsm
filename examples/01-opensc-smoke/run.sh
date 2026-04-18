#!/bin/bash
# Example 01: OpenSC smoke test.
# Verifies pcscd sees the pico2hsm, reads its ATR, and reads its serial.
set -euo pipefail
cd "$(dirname "$0")"

# Expected SC-HSM ATR for pico2hsm. The "HSM1" ASCII marker (48:53:4d:31)
# is what OpenSC uses to bind the sc-hsm driver.
EXPECTED_ATR_MARKER="48:53:4d:31"

command -v opensc-tool >/dev/null || {
  echo "Error: opensc-tool not found."
  echo "  Install:  sudo apt install opensc   (Debian/Ubuntu)"
  echo "            brew install opensc        (macOS)"
  exit 1
}

READER_FLAGS=()
if [[ -n "${OPENSC_DEFAULT_READER:-}" ]]; then
  READER_FLAGS+=("--reader" "${OPENSC_DEFAULT_READER}")
  echo "[info] Targeting reader index ${OPENSC_DEFAULT_READER} (OPENSC_DEFAULT_READER)"
fi

echo "=== Step 1: list readers ==="
if ! opensc-tool --list-readers; then
  echo "Error: opensc-tool --list-readers failed."
  echo "  On Linux, make sure pcscd is running: sudo systemctl start pcscd"
  exit 1
fi
echo

echo "=== Step 2: read ATR ==="
if ! ATR=$(opensc-tool "${READER_FLAGS[@]}" --atr 2>&1); then
  echo "Error: could not read ATR."
  echo "  Details: $ATR"
  echo "  Common causes:"
  echo "    - Device plugged in less than 2 s ago (wait and retry)"
  echo "    - Charge-only USB cable (needs data lines)"
  echo "    - Another reader came up as reader 0; use OPENSC_DEFAULT_READER=<N>"
  exit 1
fi
echo "$ATR"
echo

if ! grep -qi "$EXPECTED_ATR_MARKER" <<<"$ATR"; then
  echo "Warning: ATR does not contain expected marker '$EXPECTED_ATR_MARKER'."
  echo "  This may mean a non-pico2hsm smartcard is selected."
  echo "  Run: opensc-tool --list-readers   and pick the pico2hsm index via OPENSC_DEFAULT_READER."
  # Not a hard failure — other cards may still pass the remaining steps.
fi

echo "=== Step 3: read serial ==="
if ! SERIAL=$(opensc-tool "${READER_FLAGS[@]}" --serial 2>&1); then
  echo "Error: could not read serial."
  echo "  Details: $SERIAL"
  exit 1
fi
echo "$SERIAL"
echo

echo "[ok] pico2hsm smoke test passed"
