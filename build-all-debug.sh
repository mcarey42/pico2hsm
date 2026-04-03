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
#   rp2350_one_16m         Waveshare RP2350-One 16MB
#   rp2350_geek_16m        Waveshare RP2350-Geek 16MB
#   rp2350_geek_sdcard     Waveshare RP2350-Geek SDCard
#   rp2350_geek_sdcard_dual  Waveshare RP2350-Geek Dual-SDCard
#   rp2354_embedded        RP2354 Embedded
#
# Unlike build-all.sh this uses the dev (debug) profile so that:
#   - #[cfg(debug_assertions)] blocks are compiled in (delay loop, sentinels)
#   - defmt RTT output is visible via probe-rs
#   - Optimisation is off (easier to correlate addresses with source)

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[info]${NC} $*"; }
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
    rp2350_geek_sdcard_dual
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

# ── Build (debug profile) ─────────────────────────────────────────────────────
section "Debug build: $FEAT"
info "cargo build --no-default-features --features $FEAT"

DEFMT_LOG=trace \
cargo build \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features "$FEAT"

[[ -f "$ELF" ]] || die "ELF not found at $ELF"
ok "Build complete: $ELF"
arm-none-eabi-size "$ELF" 2>/dev/null || true

# ── Flash + run ───────────────────────────────────────────────────────────────
section "Flash + RTT monitor: $FEAT"
info "Flashing with probe-rs run --chip $CHIP ..."
info "RTT output will appear below.  Press Ctrl+C to stop monitoring."
echo ""

probe-rs run --chip "$CHIP" "$ELF"
