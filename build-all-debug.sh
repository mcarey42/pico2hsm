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
#
# Valid board features:
#   pico2_4m               Raspberry Pi Pico 2 4MB
#   pico2_4m_sdcard        Raspberry Pi Pico 2 4MB with SD card (SPI1, CS=GPIO15)
#   pico2_4m_sdcard_hybrid Raspberry Pi Pico 2 4MB QMI flash + SD card RAID-1 hybrid
#   rp2350_one_4m          Waveshare RP2350-One  4MB
#   rp2350_one_16m         Waveshare RP2350-One 16MB
#   rp2350_geek_16m        Waveshare RP2350-Geek 16MB
#   rp2350_geek_sdcard     Waveshare RP2350-Geek SDCard
#   rp2350_geek_sdcard_dual  Waveshare RP2350-Geek Dual-SDCard
#   waveshare_rp2350_lcd_16m           Waveshare RP2350-LCD-1.47-B 16MB
#   waveshare_rp2350_lcd_sdcard_dual   Waveshare RP2350-LCD-1.47-B Dual-SDCard
#   waveshare_rp2350_lcd_sdcard        Waveshare RP2350-LCD-1.47-B SD-only keystore
#   waveshare_rp2350_lcd_sdcard_hybrid Waveshare RP2350-LCD-1.47-B Flash+SD RAID-1
#   rp2354_embedded        RP2354 Embedded
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
    pico2_4m_sdcard
    pico2_4m_sdcard_hybrid
    rp2350_one_4m
    rp2350_one_16m
    rp2350_geek_16m
    rp2350_geek_sdcard
    rp2350_geek_sdcard_dual
    waveshare_rp2350_lcd_16m
    waveshare_rp2350_lcd_sdcard
    waveshare_rp2350_lcd_sdcard_dual
    waveshare_rp2350_lcd_sdcard_hybrid
    rp2354_embedded
)
VALID=0
for f in "${VALID_FEATURES[@]}"; do
    [[ "$f" == "$FEAT" ]] && VALID=1 && break
done
[[ $VALID -eq 1 ]] || die "Unknown board feature '$FEAT'.  Valid: ${VALID_FEATURES[*]}"

# ── Paths ─────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ELF="target/thumbv8m.main-none-eabihf/debug/pico2hsm"
CHIP="RP235x"
KEY_FILE="ec_firmware_signing_key.pem"

# ── Build (debug profile) ─────────────────────────────────────────────────────
section "Debug build: $FEAT"
info "cargo build --no-default-features --features $FEAT,rsa,applet-piv,applet-openpgp-curve25519"

DEFMT_LOG=trace \
cargo build \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features "$FEAT,rsa,applet-piv,applet-openpgp-curve25519"

[[ -f "$ELF" ]] || die "ELF not found at $ELF"
ok "Build complete: $ELF"
arm-none-eabi-size "$ELF" 2>/dev/null || true

# ── Firmware signing ───────────────────────────────────────────────────────────
# Sign the debug ELF if a signing key is present.
# The RP2350 bootrom only enforces the signature when secure_boot_enable is
# set in OTP. Signing debug builds is safe and ensures the same artifact
# pipeline is exercised in both debug and production.
FLASH_ELF="$ELF"
if [[ -f "$KEY_FILE" ]]; then
    if ! command -v picotool >/dev/null 2>&1; then
        die "ec_firmware_signing_key.pem found but picotool is not installed — cannot sign"
    fi
    mkdir -p dist
    SIGNED_ELF="dist/pico2hsm-${FEAT}-debug-signed.elf"
    OTP_JSON="dist/pico2hsm-${FEAT}-debug-otp.json"
    section "Signing debug build: $FEAT"
    info "picotool seal --hash --sign $ELF → $SIGNED_ELF"
    SIGN_OUT=$(picotool seal --hash --sign \
            "$ELF" -t elf \
            "$SIGNED_ELF" -t elf \
            "$KEY_FILE" \
            "$OTP_JSON" \
            2>&1)
    SIGN_RC=$?
    if [[ $SIGN_RC -eq 0 ]]; then
        ok "Signed → $SIGNED_ELF"
        ok "OTP config → $OTP_JSON"
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
    warn "No signing key found (ec_firmware_signing_key.pem) — flashing unsigned debug build"
    warn "Run ./generate_firmware_signing_keys.sh to create the key pair"
fi

# ── Flash + run ───────────────────────────────────────────────────────────────
section "Flash + RTT monitor: $FEAT"
info "Flashing with probe-rs run --chip $CHIP ..."
info "RTT output will appear below.  Press Ctrl+C to stop monitoring."
echo ""

probe-rs run --chip "$CHIP" "$FLASH_ELF"
