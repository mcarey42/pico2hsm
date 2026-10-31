#!/usr/bin/env bash
# build-all-debug.sh — Build one pico2hsm board variant in DEBUG profile and flash it.
#
# Usage:
#   ./build-all-debug.sh <board-feature>
#
# Examples:
#   ./build-all-debug.sh pico2_4m
#   ./build-all-debug.sh rp2350_one_4m
#   ./build-all-debug.sh rp2350_geek_16m
#   EXTRA_FEATURES=debug ./build-all-debug.sh pico2_4m   # adds the debug-only APDUs
#   PROFILE=release ./build-all-debug.sh pico2_4m       # release optimisation (opt-level z,
#                                                       # as shipped), symbols kept for RTT;
#                                                       # for benchmarks
#
# Valid board features:
#   pico2_4m               Raspberry Pi Pico 2 4MB
#   rp2350_one_4m          Waveshare RP2350-One  4MB
#   rp2350_one_16m         Waveshare RP2350-One with a 16MB chip fitted
#   rp2350_geek_16m        Waveshare RP2350-Geek 16MB
#   rp2350_geek_sdcard     Waveshare RP2350-Geek SDCard
#   waveshare_rp2350_lcd_16m           Waveshare RP2350-LCD-1.47-B 16MB
#   waveshare_rp2350_lcd_sdcard        Waveshare RP2350-LCD-1.47-B SD-only keystore
#
# Unlike build-all.sh this uses the dev (debug) profile so that:
#   - #[cfg(debug_assertions)] blocks are compiled in (delay loop, sentinels)
#   - defmt RTT output is visible via probe-rs
#   - Optimisation is off (easier to correlate addresses with source)

set -euo pipefail

RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[info]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
ok()      { echo -e "${GREEN}[ ok ]${NC} $*"; }
die()     { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}══ $* ══${NC}"; }

# ── Argument ──────────────────────────────────────────────────────────────────
FEAT="${1:-}"
if [[ -z "$FEAT" ]]; then
    die "Usage: $0 <board-feature>  (e.g. pico2_4m, rp2350_one_4m)"
fi

VALID_FEATURES=(
    pico2_4m
    rp2350_one_4m
    rp2350_one_16m
    rp2350_geek_16m
    rp2350_geek_sdcard
    waveshare_rp2350_lcd_16m
    waveshare_rp2350_lcd_sdcard
)
VALID=0
for f in "${VALID_FEATURES[@]}"; do
    [[ "$f" == "$FEAT" ]] && VALID=1 && break
done
[[ $VALID -eq 1 ]] || die "Unknown board feature '$FEAT'.  Valid: ${VALID_FEATURES[*]}"

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PROFILE="${PROFILE:-debug}"
case "$PROFILE" in
    debug)   PROFILE_ARGS=() ;;
    release) PROFILE_ARGS=(--release)
             # probe-rs needs the symbols (RTT control block, defmt).
             export CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=true ;;
    *)       echo "PROFILE must be debug or release" >&2; exit 1 ;;
esac
ELF="target/thumbv8m.main-none-eabihf/$PROFILE/pico2hsm"
CHIP="RP235x"
# Signing key: the OTP BOOTKEY0 key by default (BOOTKEY1, the offline
# backup, only via SIGNING_KEY=ec_firmware_signing_key-bootkey1.pem).
KEY_FILE="${SIGNING_KEY:-ec_firmware_signing_key-bootkey0.pem}"
# picotool used to seal: needs a build with `seal` (mbedtls); point
# PICOTOOL at one if the picotool on PATH lacks it.
PICOTOOL_SEAL="${PICOTOOL:-picotool}"
if [[ ! -f "$KEY_FILE" && -f ec_firmware_signing_key.pem ]]; then
    echo "[WARN] ec_firmware_signing_key.pem is the old name: rename it to ec_firmware_signing_key-bootkey0.pem" >&2
fi

# ── Build (debug profile) ─────────────────────────────────────────────────────
FEATURES="$FEAT,rsa,applet-piv,applet-openpgp-curve25519${EXTRA_FEATURES:+,$EXTRA_FEATURES}"
section "Build ($PROFILE): $FEAT"
info "cargo build --no-default-features --features $FEATURES"

DEFMT_LOG=trace \
cargo build "${PROFILE_ARGS[@]}" \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features "$FEATURES"

[[ -f "$ELF" ]] || die "ELF not found at $ELF"
ok "Build complete: $ELF"
arm-none-eabi-size "$ELF" 2>/dev/null || true

# ── Firmware signing ───────────────────────────────────────────────────────────
# Sign the debug ELF if a signing key is present.
# The RP2350 bootrom only enforces the signature when secure_boot_enable is
# set in OTP. Signing debug builds is safe and ensures the same artifact
# pipeline is exercised in both debug and production.
FLASH_ELF="$ELF"
if [[ -f "$KEY_FILE" ]] && ! "$PICOTOOL_SEAL" help seal >/dev/null 2>&1; then
    # A debug flash must not depend on signing: warn and flash unsigned.
    warn "$KEY_FILE found but $PICOTOOL_SEAL cannot seal (built without mbedtls?) — set PICOTOOL=/path/to/picotool to sign"
    warn "Flashing UNSIGNED debug build"
elif [[ -f "$KEY_FILE" ]]; then
    mkdir -p dist
    SIGNED_ELF="dist/pico2hsm-${FEAT}-${PROFILE}-signed.elf"
    OTP_JSON="dist/pico2hsm-${FEAT}-${PROFILE}-seal-otp-ENABLES-SECURE-BOOT.json"
    section "Signing debug build: $FEAT"
    info "$PICOTOOL_SEAL seal --hash --sign $ELF → $SIGNED_ELF"
    SIGN_OUT=$("$PICOTOOL_SEAL" seal --hash --sign \
            "$ELF" -t elf \
            "$SIGNED_ELF" -t elf \
            "$KEY_FILE" \
            "$OTP_JSON" \
            2>&1)
    SIGN_RC=$?
    if [[ $SIGN_RC -eq 0 ]]; then
        ok "Signed → $SIGNED_ELF"
        warn "seal OTP file → $OTP_JSON: it ENABLES SECURE BOOT; never load it (use tools/otp-bootkeys.sh)"
        # NOTE: probe-rs 0.31.0 rejects picotool-signed debug ELFs due to a
        # defmt parse bug (.sigx section alignment=0). Flash the unsigned ELF;
        # the signed artifact in dist/ is kept for OTP provisioning workflows.
        warn "Flashing UNSIGNED ELF (probe-rs 0.31.0 defmt bug with signed debug ELFs)"
        # FLASH_ELF stays as $ELF (unsigned)
    else
        echo -e "${RED}[WARN]${NC} picotool seal failed (rc=$SIGN_RC) — flashing unsigned debug build"
        echo "       picotool output: $SIGN_OUT"
        echo "       (Secure boot is likely disabled on this dev device; unsigned flash is safe.)"
    fi
else
    warn "No signing key found ($KEY_FILE) — flashing unsigned debug build"
    warn "Run ./generate_firmware_signing_keys.sh to create the key pair"
fi

# ── Partition table + slot image ──────────────────────────────────────────────
# Every board boots through a bootrom partition table (docs/FLASH_LAYOUT_2_0.md):
# the table at 0x10000000, the image in slot A at 0x10002000 (it runs there
# through address translation).  The store regions are closed partitions at
# the offsets they always had, so flashing never touches the keystore.
# The profile comes from pico2hsm-layout (an unknown board aborts).  The
# repo's cargo config defaults to the ARM target, so name the host.
PT_SIZE="$(cargo run -q -p pico2hsm-layout --features std --target "$(rustc -vV | sed -n 's/^host: //p')" -- profile "$FEAT")" \
    || die "no flash layout profile for board '$FEAT'"
PT_JSON="boards/pt_${PT_SIZE}.json"
SLOT_A_ADDR=0x10002000
command -v picotool >/dev/null 2>&1 || die "picotool is required (it builds the partition table)"
OBJCOPY="$(command -v arm-none-eabi-objcopy || command -v rust-objcopy || command -v llvm-objcopy || true)"
[[ -n "$OBJCOPY" ]] || die "an objcopy is required (arm-none-eabi-objcopy, rust-objcopy or llvm-objcopy)"
mkdir -p dist
PT_BIN="dist/pt_${PT_SIZE}.bin"
IMG_BIN="dist/pico2hsm-${FEAT}-${PROFILE}.bin"
picotool partition create "$PT_JSON" "$PT_BIN" -t bin >/dev/null || die "picotool partition create $PT_JSON failed"
"$OBJCOPY" -O binary "$FLASH_ELF" "$IMG_BIN" || die "objcopy failed"
ok "Partition table $PT_JSON → $PT_BIN; image → $IMG_BIN"

# ── Flash + run ───────────────────────────────────────────────────────────────
section "Flash + RTT monitor: $FEAT"

# if the environment defines a PROBE_SERIAL value we add the --probe argument to target a specific probe. This is useful when multiple probes are connected.
if [[ -n "${PROBE_SERIAL:-}" ]]; then
    info "PROBE_SERIAL is set to '$PROBE_SERIAL', adding --probe $PROBE_SERIAL to probe-rs arguments"
    PROBE_ARG="--probe 2e8a:000c:$PROBE_SERIAL"
else
    PROBE_ARG=""
fi
info "probe-rs: partition table at 0x10000000, image at $SLOT_A_ADDR ..."
probe-rs download ${PROBE_ARG} --chip "$CHIP" --binary-format bin --base-address 0x10000000 "$PT_BIN" \
    || die "flashing the partition table failed"
probe-rs download ${PROBE_ARG} --chip "$CHIP" --binary-format bin --base-address "$SLOT_A_ADDR" "$IMG_BIN" \
    || die "flashing the image failed"
probe-rs reset ${PROBE_ARG} --chip "$CHIP" || die "reset failed"
info "RTT output will appear below.  Press Ctrl+C to stop monitoring."
echo ""
probe-rs attach ${PROBE_ARG} --chip "$CHIP" "$FLASH_ELF"
