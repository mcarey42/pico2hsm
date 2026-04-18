#!/bin/bash
# Example 02: PKCS#11 keygen.
# Generates a P-256 EC keypair on the pico2hsm, lists it, deletes it.
set -euo pipefail
cd "$(dirname "$0")"

LABEL="pico2hsm-example-02"
CURVE="EC:prime256v1"

# Default user PIN from QUICKSTART. Override via:  PIN=<your-pin> ./run.sh
PIN="${PIN:-648219}"

# Default PKCS#11 module path (Debian/Ubuntu). Override via:  PKCS11_MODULE=<path> ./run.sh
PKCS11_MODULE="${PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"

command -v pkcs11-tool >/dev/null || {
  echo "Error: pkcs11-tool not found."
  echo "  Install:  sudo apt install opensc            (Debian/Ubuntu)"
  echo "            brew install opensc                 (macOS)"
  exit 1
}

if [[ ! -f "$PKCS11_MODULE" ]]; then
  echo "Error: PKCS#11 module not found at: $PKCS11_MODULE"
  echo "  Override via the PKCS11_MODULE environment variable."
  echo "  Common paths:"
  echo "    /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so   (Debian/Ubuntu)"
  echo "    /usr/lib/opensc-pkcs11.so                    (Arch/Fedora)"
  echo "    /opt/homebrew/lib/opensc-pkcs11.so           (macOS Apple Silicon)"
  echo "    /usr/local/lib/opensc-pkcs11.so              (macOS Intel)"
  echo "  Locate:  find / -name 'opensc-pkcs11.so' 2>/dev/null"
  exit 1
fi

# Honour OPENSC_DEFAULT_READER if multiple readers are attached.
SLOT_FLAG=()
if [[ -n "${OPENSC_DEFAULT_READER:-}" ]]; then
  SLOT_FLAG+=("--slot-index" "${OPENSC_DEFAULT_READER}")
  echo "[info] Targeting slot-index ${OPENSC_DEFAULT_READER} (OPENSC_DEFAULT_READER)"
fi

echo "=== Step 1: list slots ==="
pkcs11-tool --module "$PKCS11_MODULE" --list-slots
echo

echo "=== Step 2: delete any pre-existing '$LABEL' keypair (idempotency) ==="
# "|| true" — delete may not find anything on first run.
pkcs11-tool --module "$PKCS11_MODULE" "${SLOT_FLAG[@]}" --login --pin "$PIN" \
  --delete-object --type privkey --label "$LABEL" 2>/dev/null || true
pkcs11-tool --module "$PKCS11_MODULE" "${SLOT_FLAG[@]}" --login --pin "$PIN" \
  --delete-object --type pubkey  --label "$LABEL" 2>/dev/null || true
echo "(pre-clean done)"
echo

echo "=== Step 3: generate P-256 keypair labelled '$LABEL' ==="
if ! pkcs11-tool --module "$PKCS11_MODULE" "${SLOT_FLAG[@]}" --login --pin "$PIN" \
    --keypairgen --key-type "$CURVE" --label "$LABEL"; then
  echo
  echo "Error: keypair generation failed."
  echo "  - CKR_PIN_INCORRECT: wrong PIN — rerun with PIN=<correct> ./run.sh"
  echo "  - CKR_DEVICE_ERROR:  device storage full — delete old keys or re-initialize"
  echo "  - CKR_ATTRIBUTE_VALUE_INVALID: wrong curve — use prime256v1, not P-256"
  exit 1
fi
echo

echo "=== Step 4: list objects (verify keypair exists) ==="
pkcs11-tool --module "$PKCS11_MODULE" "${SLOT_FLAG[@]}" --login --pin "$PIN" \
  --list-objects
echo

echo "=== Step 5: cleanup — delete the test keypair ==="
pkcs11-tool --module "$PKCS11_MODULE" "${SLOT_FLAG[@]}" --login --pin "$PIN" \
  --delete-object --type privkey --label "$LABEL"
pkcs11-tool --module "$PKCS11_MODULE" "${SLOT_FLAG[@]}" --login --pin "$PIN" \
  --delete-object --type pubkey  --label "$LABEL"
echo

echo "[ok] pkcs11 keygen example complete — device is PKCS#11-operational"
