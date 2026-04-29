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
#   rp2350_one_4m          Waveshare RP2350-One  4MB
#   rp2350_geek_16m        Waveshare RP2350-Geek 16MB
#   rp2350_geek_sdcard     Waveshare RP2350-Geek SDCard
#   waveshare_rp2350_lcd_16m           Waveshare RP2350-LCD-1.47-B 16MB
#   waveshare_rp2350_lcd_sdcard        Waveshare RP2350-LCD-1.47-B SD-only keystore
#
# Unlike build-all.sh this uses the dev (debug) profile so that:
#   - #[cfg(debug_assertions)] blocks are compiled in (delay loop, sentinels)
#   - defmt RTT output is visible via probe-rs
#   - Optimisation is off (easier to correlate addresses with source)
#
# Optional environment variables (experimental):
#   OVERCLOCK_200=1   Add the experiment-overclock-200 feature (200 MHz @ V1_10).
#   OVERCLOCK_300=1   Add the experiment-overclock-300 feature (300 MHz @ V1_15).
#   OVERCLOCK_400=1   Add the experiment-overclock-400 feature (400 MHz @ V1_30).
#                     At most one OVERCLOCK_* may be set; firmware compile_error
#                     enforces this if multiple are passed.
#   BOOTSEL=1         Skip probe-rs / RTT and flash via picotool over USB
#                     instead.  Use this when the board is in BOOTSEL mode
#                     (no Debugprobe, just the USB cable).  The unsigned ELF
#                     is loaded with `picotool load -x` so the device reboots
#                     into the application immediately after flash.

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

ELF="target/thumbv8m.main-none-eabihf/debug/pico2hsm"
CHIP="RP235x"
KEY_FILE="ec_firmware_signing_key.pem"

# ── Optional experimental features ────────────────────────────────────────────
EXTRA_FEATS=""
if [[ "${OVERCLOCK_200:-0}" == "1" ]]; then
    EXTRA_FEATS=",experiment-overclock-200"
    warn "OVERCLOCK_200=1 — adding experiment-overclock-200 (clk_sys=200 MHz, V1_10)"
fi
if [[ "${OVERCLOCK_300:-0}" == "1" ]]; then
    EXTRA_FEATS="${EXTRA_FEATS},experiment-overclock-300"
    warn "OVERCLOCK_300=1 — adding experiment-overclock-300 (clk_sys=300 MHz, V1_15)"
fi
if [[ "${OVERCLOCK_400:-0}" == "1" ]]; then
    EXTRA_FEATS="${EXTRA_FEATS},experiment-overclock-400"
    warn "OVERCLOCK_400=1 — adding experiment-overclock-400 (clk_sys=400 MHz, V1_30)"
fi

# ── Build (debug profile) ─────────────────────────────────────────────────────
section "Debug build: $FEAT"
info "cargo build --no-default-features --features ${FEAT},rsa,applet-piv,applet-openpgp-curve25519${EXTRA_FEATS}"

DEFMT_LOG=trace \
cargo build \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features "${FEAT},rsa,applet-piv,applet-openpgp-curve25519${EXTRA_FEATS}"

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
if [[ "${BOOTSEL:-0}" == "1" ]]; then
    section "Flash via picotool (BOOTSEL mode): $FEAT"
    command -v picotool >/dev/null 2>&1 || die "picotool not installed"
    info "picotool load -x $FLASH_ELF"
    # -t elf  : input format
    # -x      : execute (reboot to application) immediately after load
    picotool load "$FLASH_ELF" -t elf -x
    ok "Flashed via picotool — device should be re-enumerating on USB"
    info "Wait ~5 s for USB CCID re-enumeration before invoking ./run_tests.sh"
    exit 0
fi

section "Flash + RTT monitor: $FEAT"
info "Flashing with probe-rs run --chip $CHIP ..."
info "RTT output will appear below.  Press Ctrl+C to stop monitoring."
echo ""

# if the environment defines a PROBE_SERIAL value we add the --probe argument to target a specific probe. This is useful when multiple probes are connected.
if [[ -n "${PROBE_SERIAL:-}" ]]; then
    info "PROBE_SERIAL is set to '$PROBE_SERIAL', adding --probe $PROBE_SERIAL to probe-rs arguments"
    PROBE_ARG="--probe 2e8a:000c:$PROBE_SERIAL"
else
    PROBE_ARG=""
fi
probe-rs run ${PROBE_ARG} --chip "$CHIP" "$FLASH_ELF"
