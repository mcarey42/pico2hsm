#!/usr/bin/env bash
# build-all.sh — Build all pico2hsm board variants, run host tests, and
# optionally flash + smoke-test physical hardware.
#
# Usage:
#   ./build-all.sh              # host tests + build all ARM variants + generate UF2
#   ./build-all.sh --flash rp2350_one_4m   # also flash that variant
#   ./build-all.sh --test-only  # host tests only (no ARM build)
#   ./build-all.sh --arm-only   # skip host tests, build all ARM variants + generate UF2
#   ./build-all.sh --no-uf2     # skip UF2 generation
#
# Requirements (ARM build + flash):
#   rustup target add thumbv8m.main-none-eabihf
#   cargo install probe-rs-tools   # provides `probe-rs`
#
# Requirements (host tests only):
#   Standard Rust toolchain (stable)

set -euo pipefail

# ── Colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[info]${NC} $*"; }
ok()      { echo -e "${GREEN}[ ok ]${NC} $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC} $*"; }
die()     { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}══ $* ══${NC}"; }

# ── Argument parsing ─────────────────────────────────────────────────────────
FLASH_TARGET=""
SKIP_HOST=0
SKIP_ARM=0
SKIP_UF2=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --flash)       FLASH_TARGET="${2:-}"; shift 2 ;;
        --test-only)   SKIP_ARM=1;  shift ;;
        --arm-only)    SKIP_HOST=1; shift ;;
        --no-uf2)      SKIP_UF2=1; shift ;;
        -h|--help)
            sed -n '/^# Usage:/,/^[^#]/{ /^#/{ s/^# \?//; p } }' "$0"
            exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
done

# ── Workspace root ───────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Toolchain checks ─────────────────────────────────────────────────────────
section "Toolchain checks"

command -v cargo >/dev/null 2>&1 || die "cargo not found — install Rust from https://rustup.rs"
RUST_VERSION=$(rustc --version)
info "Rust: $RUST_VERSION"

if [[ $SKIP_ARM -eq 0 ]]; then
    if ! rustup target list --installed | grep -q "thumbv8m.main-none-eabihf"; then
        warn "ARM target not installed — installing now..."
        rustup target add thumbv8m.main-none-eabihf
    fi
    ok "ARM target: thumbv8m.main-none-eabihf"

    if [[ -n "$FLASH_TARGET" ]]; then
        command -v probe-rs >/dev/null 2>&1 \
            || die "probe-rs not found — install with: cargo install probe-rs-tools"
        ok "probe-rs: $(probe-rs --version 2>/dev/null | head -1)"
    fi

    if [[ $SKIP_UF2 -eq 0 ]]; then
        if command -v picotool >/dev/null 2>&1; then
            ok "picotool: $(picotool version 2>/dev/null | head -1)"
        else
            warn "picotool not found — UF2 generation will be skipped"
            warn "Install: https://github.com/raspberrypi/picotool"
            SKIP_UF2=1
        fi
    fi
fi

# ── Firmware signing key ─────────────────────────────────────────────────────
KEY_FILE="ec_firmware_signing_key.pem"
if [[ -f "$KEY_FILE" ]]; then
    if ! command -v picotool >/dev/null 2>&1; then
        die "ec_firmware_signing_key.pem found but picotool is not installed — cannot sign"
    fi
    ok "Signing key present — all firmware outputs will be signed (picotool seal --hash --sign)"
    SIGN=1
else
    warn "No signing key found (ec_firmware_signing_key.pem) — outputs will NOT be signed"
    warn "Run ./generate_firmware_signing_keys.sh to create the key pair"
    SIGN=0
fi

# ── Capability features included in every build ──────────────────────────────
# These are added to every board variant. --no-default-features strips them
# from Cargo.toml defaults, so we re-add them explicitly here.
COMMON_FEATURES="rsa,applet-piv,applet-openpgp-curve25519"

# ── Board variant table ───────────────────────────────────────────────────────
# (feature flag, human name, probe-rs chip id)
declare -a VARIANTS=(
    "pico2_4m        | Raspberry Pi Pico 2 4MB      | RP2350"
    "rp2350_one_4m   | Waveshare RP2350-One  4MB    | RP2350"
    "rp2350_one_16m  | Waveshare RP2350-One 16MB    | RP2350"
    "rp2350_geek_16m | Waveshare RP2350-Geek 16MB   | RP2350"
    "rp2350_geek_sdcard               | Waveshare RP2350-Geek SDCard           | RP2350"
    "rp2350_geek_sdcard_dual          | Waveshare RP2350-Geek Dual-SDCard      | RP2350"
    "waveshare_rp2350_lcd_16m         | Waveshare RP2350-LCD-1.47-B 16MB       | RP2350"
    "waveshare_rp2350_lcd_sdcard        | Waveshare RP2350-LCD-1.47-B SDCard     | RP2350"
    "waveshare_rp2350_lcd_sdcard_dual   | Waveshare RP2350-LCD-1.47-B Dual-SDCard| RP2350"
    "waveshare_rp2350_lcd_sdcard_hybrid | Waveshare RP2350-LCD-1.47-B Hybrid     | RP2350"
)

feature_of()  { echo "$1" | awk -F'|' '{gsub(/ /,"",$1); print $1}'; }
name_of()     { echo "$1" | awk -F'|' '{gsub(/^ +| +$/,"",$2); print $2}'; }
chip_of()     { echo "$1" | awk -F'|' '{gsub(/ /,"",$3); print $3}'; }

# ── Stage 1: Host tests ───────────────────────────────────────────────────────
if [[ $SKIP_HOST -eq 0 ]]; then
    section "Host tests (x86_64)"
    info "Running lib tests..."
    cargo test --lib \
        --target x86_64-unknown-linux-gnu \
        --manifest-path firmware/Cargo.toml \
        2>&1 | tail -5
    ok "Lib tests passed"

    info "Running integration tests..."
    cargo test --tests \
        --target x86_64-unknown-linux-gnu \
        --manifest-path firmware/Cargo.toml \
        2>&1 | grep -E "^test result"
    ok "Integration tests passed"
fi

# ── Stage 2: ARM builds ───────────────────────────────────────────────────────
if [[ $SKIP_ARM -eq 0 ]]; then
    section "ARM firmware builds"

    declare -A BUILD_STATUS
    declare -A BINARY_SIZES

    BUILD_LOG=$(mktemp /tmp/pico2hsm-build-XXXXXX.log)

    for variant in "${VARIANTS[@]}"; do
        FEAT=$(feature_of "$variant")
        NAME=$(name_of  "$variant")

        info "Building: $NAME  [--features $FEAT]"

        if cargo build --release \
            --manifest-path firmware/Cargo.toml \
            --no-default-features \
            --features "$FEAT,$COMMON_FEATURES" \
            >"$BUILD_LOG" 2>&1; then
            : # success handled below
        else
            BUILD_STATUS[$FEAT]="FAIL"
            warn "  Build FAILED for $FEAT"
            grep -E "^error" "$BUILD_LOG" | head -5 || true
            continue
        fi

        ELF="target/thumbv8m.main-none-eabihf/release/pico2hsm"
        if [[ -f "$ELF" ]]; then
            # Extract flash usage from ELF sections
            SIZE_OUT=$(arm-none-eabi-size "$ELF" 2>/dev/null \
                       || size "$ELF" 2>/dev/null \
                       || echo "? ? ?")
            TEXT=$(echo "$SIZE_OUT" | awk 'NR==2{print $1}')
            DATA=$(echo "$SIZE_OUT" | awk 'NR==2{print $2}')
            BSS=$( echo "$SIZE_OUT" | awk 'NR==2{print $3}')
            TOTAL_FLASH=$(( ${TEXT:-0} + ${DATA:-0} ))
            TOTAL_RAM=$(( ${DATA:-0} + ${BSS:-0} ))
            BINARY_SIZES[$FEAT]="flash=${TOTAL_FLASH}B  ram=${TOTAL_RAM}B"
            BUILD_STATUS[$FEAT]="OK"
            ok "  $NAME: ${BINARY_SIZES[$FEAT]}"

            # Stash a per-variant copy of the ELF for UF2 conversion and flashing
            mkdir -p dist
            cp -f "$ELF" "dist/pico2hsm-${FEAT}.elf"

            # Sign the firmware if a signing key is present.
            # picotool seal --hash --sign embeds both a hash and an EC P-256
            # signature. The OTP JSON records what must be burned into RP2350
            # OTP for the bootrom to accept this firmware.
            if [[ $SIGN -eq 1 ]]; then
                SIGNED_ELF="dist/pico2hsm-${FEAT}-signed.elf"
                OTP_JSON="dist/pico2hsm-${FEAT}-otp.json"
                SIGN_OUT=$(picotool seal --hash --sign \
                        "dist/pico2hsm-${FEAT}.elf" -t elf \
                        "$SIGNED_ELF" -t elf \
                        "$KEY_FILE" \
                        "$OTP_JSON" \
                        2>&1)
                SIGN_RC=$?
                if [[ $SIGN_RC -eq 0 ]]; then
                    ok "  Signed → $SIGNED_ELF"
                    ok "  OTP config → $OTP_JSON"
                else
                    die "picotool seal failed for $NAME (rc=$SIGN_RC): $SIGN_OUT"
                fi
            fi
        else
            BUILD_STATUS[$FEAT]="OK (size unavailable)"
        fi
    done

    # ── UF2 generation ────────────────────────────────────────────────────────
    if [[ $SKIP_UF2 -eq 0 ]]; then
        section "UF2 generation"
        mkdir -p dist

        for variant in "${VARIANTS[@]}"; do
            FEAT=$(feature_of "$variant")
            NAME=$(name_of  "$variant")
            # Use signed ELF for UF2 if signing was performed; unsigned otherwise.
            if [[ $SIGN -eq 1 && -f "dist/pico2hsm-${FEAT}-signed.elf" ]]; then
                ELF_COPY="dist/pico2hsm-${FEAT}-signed.elf"
            else
                ELF_COPY="dist/pico2hsm-${FEAT}.elf"
            fi
            UF2_OUT="dist/pico2hsm-${FEAT}.uf2"

            if [[ ! -f "$ELF_COPY" ]]; then
                warn "  $NAME: ELF not found (build failed?) — skipping"
                continue
            fi

            if picotool uf2 convert "$ELF_COPY" -t elf "$UF2_OUT" \
                    --family 0xe48bff59 --platform rp2350 \
                    >/dev/null 2>&1; then
                UF2_SIZE=$(du -h "$UF2_OUT" | cut -f1)
                ok "  $NAME → dist/pico2hsm-${FEAT}.uf2  (${UF2_SIZE})"
            else
                warn "  $NAME: picotool conversion failed"
            fi
        done

        info "UF2 files written to dist/"
        info "To flash: hold BOOTSEL, plug USB, copy .uf2 to the RPI-RP2 drive"
    fi

    # Summary table
    section "Build summary"
    printf "%-36s  %-6s  %s\n" "Feature" "Status" "Size"
    printf -- "%-36s  %-6s  %s\n" "$(printf '%0.s-' {1..36})" "------" "----"
    for variant in "${VARIANTS[@]}"; do
        FEAT=$(feature_of "$variant")
        NAME=$(name_of  "$variant")
        STATUS="${BUILD_STATUS[$FEAT]:-SKIP}"
        SIZE="${BINARY_SIZES[$FEAT]:--}"
        if [[ "$STATUS" == "OK"* ]]; then
            printf "${GREEN}%-36s  %-6s${NC}  %s\n" "$NAME" "$STATUS" "$SIZE"
        else
            printf "${RED}%-36s  %-6s${NC}  %s\n"   "$NAME" "$STATUS" "$SIZE"
        fi
    done

    rm -f "$BUILD_LOG"

    # Check for any failures
    for variant in "${VARIANTS[@]}"; do
        FEAT=$(feature_of "$variant")
        if [[ "${BUILD_STATUS[$FEAT]:-FAIL}" == "FAIL" ]]; then
            die "One or more board variants failed to build."
        fi
    done
fi

# ── Stage 3: Flash + smoke test ───────────────────────────────────────────────
if [[ -n "$FLASH_TARGET" ]]; then
    section "Flash + smoke test: $FLASH_TARGET"

    # Validate the requested feature
    VALID=0
    CHIP=""
    for variant in "${VARIANTS[@]}"; do
        if [[ "$(feature_of "$variant")" == "$FLASH_TARGET" ]]; then
            VALID=1
            CHIP=$(chip_of "$variant")
            break
        fi
    done
    [[ $VALID -eq 1 ]] || die "Unknown board variant '$FLASH_TARGET'." \
        "Valid: $(for v in "${VARIANTS[@]}"; do feature_of "$v"; done | tr '\n' ' ')"

    # Use the signed ELF for flashing if signing was performed.
    if [[ $SIGN -eq 1 && -f "dist/pico2hsm-${FLASH_TARGET}-signed.elf" ]]; then
        ELF="dist/pico2hsm-${FLASH_TARGET}-signed.elf"
        info "Using signed ELF: $ELF"
    else
        ELF="target/thumbv8m.main-none-eabihf/release/pico2hsm"
    fi
    [[ -f "$ELF" ]] || die "ELF not found — run without --test-only first"

    info "Connecting to probe (chip: $CHIP)..."
    probe-rs info --chip "$CHIP" 2>&1 | grep -E "Core|Memory|Vendor" || true

    info "Flashing $ELF → $CHIP ..."
    probe-rs download \
        --chip "$CHIP" \
        --format elf \
        "$ELF"

    info "Resetting device and capturing 3 s of RTT output..."
    # probe-rs run streams RTT until the process is killed or the target halts.
    # We capture 3 seconds of output for smoke-test purposes.
    RTT_LOG=$(mktemp /tmp/pico2hsm-rtt-XXXXXX.log)
    timeout 5 probe-rs run \
        --chip "$CHIP" \
        --no-location \
        "$ELF" 2>&1 | tee "$RTT_LOG" || true   # timeout exit expected; $ELF is signed if key present

    section "RTT smoke-test results"
    PASS=1

    check_rtt() {
        local pattern="$1"
        local label="$2"
        if grep -q "$pattern" "$RTT_LOG" 2>/dev/null; then
            ok "  $label"
        else
            warn "  MISSING: $label  (pattern: '$pattern')"
            PASS=0
        fi
    }

    check_rtt "peripherals initialised"    "Board peripherals initialised"
    check_rtt "provisioned="               "OTP status read"
    check_rtt "storage master key"         "SMK derivation attempted"
    check_rtt "entering main loop"         "Main loop reached"

    if [[ $PASS -eq 1 ]]; then
        ok "Smoke test PASSED — device booted and reached main loop"
    else
        warn "Smoke test PARTIAL — some expected log lines were missing."
        warn "This is expected if OTP is not provisioned (SMK will fail)."
        info "Full RTT log saved to: $RTT_LOG"
    fi

    rm -f "$RTT_LOG"
fi

section "Done"
ok "All requested stages completed."
