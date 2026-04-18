#!/bin/bash
# Example 03: PIV CLI auth.
# Generates a P-256 keypair in PIV slot 9A, signs a challenge, verifies.
set -euo pipefail
cd "$(dirname "$0")"

# Default PIV user PIN (NIST). Override:  PIV_PIN=<pin> ./run.sh
PIV_PIN="${PIV_PIN:-123456}"

# Default PIV management key (NIST default).  Override:  MGMT_KEY=<hex> ./run.sh
MGMT_KEY="${MGMT_KEY:-010203040506070801020304050607080102030405060708}"

command -v yubico-piv-tool >/dev/null || {
  echo "Error: yubico-piv-tool not found."
  echo "  Install:  sudo apt install yubico-piv-tool   (Debian/Ubuntu)"
  echo "            brew install yubico-piv-tool        (macOS)"
  exit 1
}

command -v opensc-tool >/dev/null || {
  echo "Error: opensc-tool not found (needed for reader auto-detect)."
  echo "  Install:  sudo apt install opensc   (Debian/Ubuntu)"
  echo "            brew install opensc        (macOS)"
  exit 1
}

# Reader selection: READER env wins; else take the first reader from opensc-tool.
if [[ -n "${READER:-}" ]]; then
  echo "[info] Using READER='$READER'"
else
  READER=$(opensc-tool --list-readers 2>/dev/null \
    | awk -F'   *' '/^[0-9]+/ { sub(/ +[0-9]+ [0-9]+$/, ""); print $2; exit }')
  if [[ -z "$READER" ]]; then
    echo "Error: no smartcard readers found."
    echo "  Run:  opensc-tool --list-readers"
    echo "  Then: READER='<reader name>' ./run.sh"
    exit 1
  fi
  echo "[info] Auto-detected READER='$READER'"
fi

echo "=== Step 0: verify PIV applet is responsive ==="
if ! yubico-piv-tool -r "$READER" -a status 2>&1 | tee /tmp/piv-status.txt; then
  echo
  echo "Error: PIV applet did not respond."
  echo "  - Check firmware was built with --features applet-piv"
  echo "  - Test applet selection directly:"
  echo "      opensc-tool --send-apdu 00:A4:04:00:0B:A0:00:00:03:08:00:00:10:00:01:00"
  echo "    Expect response ending in 9000 (applet present) or 6A82 (applet missing)."
  exit 1
fi
echo

echo "=== Step 1: remove any stale 'slot-9a.pub' from previous runs ==="
rm -f slot-9a.pub challenge.bin
echo "(clean)"
echo

echo "=== Step 2: generate P-256 keypair in slot 9A ==="
if ! yubico-piv-tool -r "$READER" -a generate -s 9a -A ECCP256 \
    --key "$MGMT_KEY" -o slot-9a.pub; then
  echo
  echo "Error: slot 9A keygen failed."
  echo "  - 'Authentication failed': pass your non-default mgmt key as MGMT_KEY=<hex>"
  echo "  - 'Algorithm not supported': use -A ECCP256 or -A RSA2048 (others not supported)"
  echo "  - status 6A82: applet-piv feature not compiled into firmware"
  exit 1
fi
echo "[ok] Generated slot-9a.pub"
cat slot-9a.pub
echo

echo "=== Step 3: build challenge and sign via test-signature ==="
echo -n "hello pico2hsm PIV" > challenge.bin

# test-signature signs a built-in challenge and verifies the signature against
# the public key on stdin. It exercises the PIV VERIFY + GENERAL AUTHENTICATE
# path exactly as an SSH or macOS PIV login would.
if ! yubico-piv-tool -r "$READER" -a verify-pin -P "$PIV_PIN" \
     -a test-signature -s 9a < slot-9a.pub; then
  echo
  echo "Error: PIV test-signature failed."
  echo "  - 'PIN verification failed': wrong PIV_PIN (default: 123456)."
  echo "  - 'Key data does not match': regenerate slot-9a.pub (stale)."
  exit 1
fi
echo

echo "[ok] PIV slot 9A keygen + test-signature passed"
