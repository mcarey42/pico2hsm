#!/usr/bin/env bash
#
# generate_firmware_signing_keys.sh — Generate EC P-256 firmware signing keys for RP2350 secure boot
#
# The RP2350 secure boot mechanism works as follows:
#   1. A SHA-256 hash of the signing public key is burned into the RP2350's OTP (one-time programmable) memory.
#   2. Firmware images (ELF/UF2) are signed with the corresponding private key.
#   3. At boot, the RP2350 bootrom verifies the firmware image signature against the public key
#      whose hash matches the OTP value. If verification fails, the device refuses to boot.
#
# This script generates:
#   - ec_firmware_signing_key.pem  — EC P-256 private key (PKCS#8 PEM, unencrypted)
#   - ec_firmware_signing_key.pub  — Corresponding public key (PEM)
#
# These keys are generated once per device family (or per device for higher security).
# The private key is used by the build/release pipeline to sign firmware images.
#

set -euo pipefail

PRIVATE_KEY="ec_firmware_signing_key.pem"
PUBLIC_KEY="ec_firmware_signing_key.pub"

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

echo "Generating EC P-256 firmware signing key pair for RP2350 secure boot..."
echo

# Generate private key (PKCS#8 PEM, unencrypted)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$PRIVATE_KEY"
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
echo "Next steps for RP2350 secure boot:"
echo ""
echo "  1. Back up the private key to a secure offline location immediately."
echo ""
echo "  2. Extract the raw public key bytes and burn the SHA-256 hash into"
echo "     RP2350 OTP. Using picotool:"
echo ""
echo "       picotool otp set-key $PUBLIC_KEY"
echo ""
echo "     Consult the RP2350 datasheet and picotool documentation for the"
echo "     exact OTP row addresses and lock bits for your configuration."
echo ""
echo "  3. Sign firmware images before flashing. Using picotool:"
echo ""
echo "       picotool sign <firmware.elf> <signed-firmware.elf> $PRIVATE_KEY"
echo ""
echo "  4. Once OTP is programmed and secure boot is enabled, only firmware"
echo "     signed with this private key will be accepted by the bootrom."
