#!/usr/bin/env bash
#
# otp-bootkeys.sh — build the OTP files that provision the RP2350 boot keys.
#
# Writes NOTHING to any device.  It reads the two signing keys, checks them,
# and writes picotool OTP JSON files for two separate provisioning stages
# (docs/PROVISIONING.md, the OTP map):
#
#   dist/otp/stage1-bootkeys.json   BOOTKEY0 (and BOOTKEY1): SHA-256 of each
#                                   public key.  Inert until the key slots are
#                                   marked valid AND secure boot is enabled.
#   dist/otp/stage3-key-slots.json  BOOT_FLAGS1: KEY_VALID for the provisioned
#                                   slots, KEY_INVALID for the rest (permanent).
#
# Neither file contains CRIT1 (secure boot, debug, glitch detector): the OTP
# file `picotool seal` writes does, so never load that one.  Secure boot is a
# separate, deliberate step.
#
# Usage:
#   tools/otp-bootkeys.sh [bootkey0.pem [bootkey1.pem]]
#     defaults: ec_firmware_signing_key-bootkey0.pem, ec_firmware_signing_key-bootkey1.pem
#   tools/otp-bootkeys.sh --primary-only [bootkey0.pem]
#     one key: slot 0 valid, slots 1-3 invalid
#
# Then, with the board in BOOTSEL and only after approving each stage:
#   picotool otp load --ser <serial> dist/otp/stage1-bootkeys.json
#   picotool otp get  --ser <serial> OTP_DATA_BOOTKEY0     # compare with the rows printed below
#   picotool otp load --ser <serial> dist/otp/stage3-key-slots.json
#   picotool otp get  --ser <serial> OTP_DATA_BOOT_FLAGS1 OTP_DATA_BOOT_FLAGS1_R1 OTP_DATA_BOOT_FLAGS1_R2

set -euo pipefail

cd "$(dirname "$0")/.."

PRIMARY_ONLY=0
if [[ "${1:-}" == "--primary-only" ]]; then
    PRIMARY_ONLY=1
    shift
fi
KEY0="${1:-ec_firmware_signing_key-bootkey0.pem}"
KEY1="${2:-ec_firmware_signing_key-bootkey1.pem}"
OUT_DIR="${OTP_OUT_DIR:-dist/otp}"

die() { echo "ERROR: $*" >&2; exit 1; }
command -v openssl >/dev/null || die "openssl is required"
command -v python3 >/dev/null || die "python3 is required"

# Check a key and print its fingerprint: SHA-256 of the raw public point X||Y,
# which is what the bootrom compares (and what `picotool seal` writes).
fingerprint() {
    local key="$1" text
    [[ -f "$key" ]] || die "$key not found"
    text=$(openssl pkey -in "$key" -noout -text 2>/dev/null) || die "$key: not a readable private key"
    grep -q "ASN1 OID: secp256k1" <<<"$text" || die "$key: not secp256k1 (the RP2350 bootrom only accepts secp256k1)"
    grep -q "Private-Key: (256 bit)" <<<"$text" || die "$key: not a 256-bit key"
    openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | tail -c 64 | sha256sum | cut -d' ' -f1
}

FPR0=$(fingerprint "$KEY0")
FPR1=""
if [[ $PRIMARY_ONLY -eq 0 ]]; then
    FPR1=$(fingerprint "$KEY1")
    [[ "$FPR0" != "$FPR1" ]] || die "$KEY0 and $KEY1 are the same key"
fi

mkdir -p "$OUT_DIR"
python3 - "$OUT_DIR" "$FPR0" "$FPR1" <<'EOF'
import json, sys
out, fpr0, fpr1 = sys.argv[1], sys.argv[2], sys.argv[3]
keys = [bytes.fromhex(fpr0)] + ([bytes.fromhex(fpr1)] if fpr1 else [])

stage1 = {f"bootkey{i}": list(k) for i, k in enumerate(keys)}
valid = (1 << len(keys)) - 1           # slots in use
invalid = 0b1111 & ~valid              # every other slot, revoked for good
stage3 = {"boot_flags1": {"key_valid": valid, "key_invalid": invalid}}

for name, doc in (("stage1-bootkeys.json", stage1), ("stage3-key-slots.json", stage3)):
    text = json.dumps(doc, indent=4) + "\n"
    # Never let a provisioning file switch secure boot (or debug) on.
    assert "crit" not in text.lower(), name
    with open(f"{out}/{name}", "w") as f:
        f.write(text)

for i, k in enumerate(keys):
    print(f"BOOTKEY{i} = {k.hex()}")
    rows = [k[2 * j] | (k[2 * j + 1] << 8) for j in range(16)]
    base = 0x80 + 0x10 * i
    print("  expected read-back (ECC rows, low byte first):")
    for j in range(0, 16, 4):
        print("   " + "  ".join(f"{base + j + n:#05x}={rows[j + n]:#06x}" for n in range(4)))
print(f"BOOT_FLAGS1: KEY_VALID={valid:#06b}  KEY_INVALID={invalid:#06b}  "
      f"(row value {valid | invalid << 8:#08x}, written to all 3 copies 0x04b-0x04d)")
EOF

echo
echo "Wrote $OUT_DIR/stage1-bootkeys.json and $OUT_DIR/stage3-key-slots.json."
echo "Nothing was written to any device.  Each OTP stage is irreversible:"
echo "load one file at a time, read it back, and boot the board before the next."
