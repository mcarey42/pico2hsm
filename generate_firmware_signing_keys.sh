#!/usr/bin/env bash
#
# generate_firmware_signing_keys.sh — Generate EC secp256k1 firmware signing keys for RP2350 secure boot
#
# The RP2350 secure boot mechanism works as follows:
#   1. A SHA-256 hash of the signing public key is burned into the RP2350's OTP (one-time programmable) memory.
#   2. Firmware images (ELF/UF2) are signed with the corresponding private key.
#   3. At boot, the RP2350 bootrom verifies the firmware image signature against the public key
#      whose hash matches the OTP value. If verification fails, the device refuses to boot.
#
# Usage: ./generate_firmware_signing_keys.sh [0|1]   (default 0)
#
# Generates the key for one OTP boot-key slot:
#   - ec_firmware_signing_key-bootkey<N>.pem — EC secp256k1 private key (PKCS#8 PEM, unencrypted)
#   - ec_firmware_signing_key-bootkey<N>.pub — corresponding public key (PEM)
# Slot 0 (BOOTKEY0) signs every build; slot 1 (BOOTKEY1) is the offline backup,
# used only if key 0 is ever revoked.  tools/otp-bootkeys.sh turns both into the
# OTP file that provisions them (docs/PROVISIONING.md).
#
# These keys are generated once per device family (or per device for higher security).
# The private key is used by the build/release pipeline to sign firmware images.
#

set -euo pipefail

SLOT="${1:-0}"
case "$SLOT" in 0|1) ;; *) echo "usage: $0 [0|1]  (OTP boot-key slot)" >&2; exit 1 ;; esac
PRIVATE_KEY="ec_firmware_signing_key-bootkey${SLOT}.pem"
PUBLIC_KEY="ec_firmware_signing_key-bootkey${SLOT}.pub"

# --- Safety check: never overwrite existing keys ---
if [[ -e "$PRIVATE_KEY" ]]; then
    echo "ERROR: $PRIVATE_KEY already exists. Refusing to overwrite." >&2
    echo "If you need new keys, move or delete the existing files first." >&2
    exit 1
fi

if [[ -e "$PUBLIC_KEY" ]]; then
    echo "ERROR: $PUBLIC_KEY already exists. Refusing to overwrite." >&2
    echo "If you need new keys, move or delete the existing files first." >&2
    exit 1
fi

# --- Check for openssl ---
if ! command -v openssl &>/dev/null; then
    echo "ERROR: openssl is not installed or not in PATH." >&2
    exit 1
fi

echo "Generating EC secp256k1 firmware signing key pair for RP2350 secure boot..."
echo
# NOTE: The RP2350 bootrom uses secp256k1 (not NIST P-256) for signature
# verification.  picotool's sign/verify pipeline also uses secp256k1.
# Using any other curve (e.g. P-256) will produce "Signature verification
# failed" from picotool even though the key itself is technically valid.

# Generate private key (PKCS#8 PEM, unencrypted)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 -out "$PRIVATE_KEY"
chmod 600 "$PRIVATE_KEY"

# Extract public key
openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

echo
echo "Keys generated:"
echo "  Private key: $PRIVATE_KEY"
echo "  Public key:  $PUBLIC_KEY"
echo

# --- SHA-256 fingerprint of the public key (DER encoding) ---
FINGERPRINT=$(openssl pkey -pubin -in "$PUBLIC_KEY" -outform DER 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //')
echo "SHA-256 fingerprint of public key (record this):"
echo "  $FINGERPRINT"
echo

# --- Security warning ---
echo "==============================================================================="
echo "  WARNING: The private key ($PRIVATE_KEY) is EXTREMELY SENSITIVE."
echo ""
echo "  - Store it in a hardware security module (HSM) or offline vault."
echo "  - Do NOT commit it to version control."
echo "  - Do NOT leave it on networked machines longer than necessary."
echo "  - Losing this key means you CANNOT sign future firmware updates"
echo "    for devices that have the corresponding public key hash in OTP."
echo "  - There is NO recovery mechanism. OTP is permanent."
echo "==============================================================================="
echo

# --- Next steps ---
FPR=$(openssl pkey -in "$PRIVATE_KEY" -pubout -outform DER 2>/dev/null | tail -c 64 | sha256sum | cut -d' ' -f1)
echo "Public fingerprint (the OTP BOOTKEY${SLOT} hash): $FPR"
echo ""
echo "Next steps:"
echo "  1. Back up the private key to a secure offline location now."
echo "  2. Builds sign with ec_firmware_signing_key-bootkey0.pem automatically"
echo "     (build-all.sh, build-all-debug.sh; picotool seal --hash --sign)."
echo "  3. For secure boot, tools/otp-bootkeys.sh turns the slot-0 and slot-1 keys"
echo "     into the OTP files that provision them.  Every OTP write is"
echo "     irreversible: follow docs/PROVISIONING.md stage by stage."
