#!/usr/bin/env bash
# build-all.sh — Build all pico2hsm board variants, run host tests, and
# optionally flash + smoke-test physical hardware.
#
# Usage:
#   ./build-all.sh              # host tests + build all ARM variants + generate UF2
#   ./build-all.sh --flash rp2350_one_4m   # also flash that variant over SWD (table + slot A;
#                                          # PROBE_SERIAL=<serial> with several probes)
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
# Signing key: the OTP BOOTKEY0 key by default (BOOTKEY1, the offline
# backup, only via SIGNING_KEY=ec_firmware_signing_key-bootkey1.pem).
KEY_FILE="${SIGNING_KEY:-ec_firmware_signing_key-bootkey0.pem}"
# picotool used to seal: needs a build with `seal` (mbedtls); point
# PICOTOOL at one if the picotool on PATH lacks it.
PICOTOOL_SEAL="${PICOTOOL:-picotool}"
if [[ ! -f "$KEY_FILE" && -f ec_firmware_signing_key.pem ]]; then
    echo "[WARN] ec_firmware_signing_key.pem is the old name: rename it to ec_firmware_signing_key-bootkey0.pem" >&2
fi
if [[ -f "$KEY_FILE" ]]; then
    if ! "$PICOTOOL_SEAL" help seal >/dev/null 2>&1; then
        die "$KEY_FILE found but $PICOTOOL_SEAL cannot seal (not installed, or built without mbedtls) — set PICOTOOL=/path/to/picotool"
    fi
    ok "Signing key present — all firmware outputs will be signed (picotool seal --hash --sign)"
    SIGN=1
else
    warn "No signing key found ($KEY_FILE) — outputs will NOT be signed"
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
    "pico2_4m                 | Raspberry Pi Pico 2 4MB                | RP2350"
    "rp2350_one_4m            | Waveshare RP2350-One  4MB              | RP2350"
    "rp2350_one_16m           | Waveshare RP2350-One 16MB (chip swap)  | RP2350"
    "rp2350_geek_16m          | Waveshare RP2350-Geek 16MB             | RP2350"
    "rp2350_geek_sdcard               | Waveshare RP2350-Geek SDCard           | RP2350"
    "waveshare_rp2350_lcd_16m         | Waveshare RP2350-LCD-1.47-B 16MB       | RP2350"
    "waveshare_rp2350_lcd_sdcard        | Waveshare RP2350-LCD-1.47-B SDCard     | RP2350"
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
            # picotool seal --hash --sign embeds both a hash and a secp256k1
            # signature. The OTP JSON records what must be burned into RP2350
            # OTP for the bootrom to accept this firmware.
            if [[ $SIGN -eq 1 ]]; then
                SIGNED_ELF="dist/pico2hsm-${FEAT}-signed.elf"
                OTP_JSON="dist/pico2hsm-${FEAT}-seal-otp-ENABLES-SECURE-BOOT.json"
                SIGN_OUT=$("$PICOTOOL_SEAL" seal --hash --sign \
                        "dist/pico2hsm-${FEAT}.elf" -t elf \
                        "$SIGNED_ELF" -t elf \
                        "$KEY_FILE" \
                        "$OTP_JSON" \
                        2>&1)
                SIGN_RC=$?
                if [[ $SIGN_RC -eq 0 ]]; then
                    ok "  Signed → $SIGNED_ELF"
                    warn "  seal OTP file → $OTP_JSON: it ENABLES SECURE BOOT; never load it (use tools/otp-bootkeys.sh)"
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
        # The per-variant copy: target/…/release/pico2hsm holds whichever
        # board was built last.
        ELF="dist/pico2hsm-${FLASH_TARGET}.elf"
    fi
    [[ -f "$ELF" ]] || die "ELF not found — run without --test-only first"

    # Every 2.0 board boots through a partition table (docs/FLASH_LAYOUT_2_0.md):
    # the table at 0x10000000, the image in slot A at 0x10002000.  Writing the
    # ELF to its link address (0x10000000) would overwrite the table.
    # The profile comes from pico2hsm-layout (an unknown board aborts).  The
    # repo's cargo config defaults to the ARM target, so name the host.
    PT_SIZE="$(cargo run -q -p pico2hsm-layout --features std --target "$(rustc -vV | sed -n 's/^host: //p')" -- profile "$FLASH_TARGET")" \
        || die "no flash layout profile for board '$FLASH_TARGET'"
    OBJCOPY="$(command -v arm-none-eabi-objcopy || command -v rust-objcopy || command -v llvm-objcopy || true)"
    [[ -n "$OBJCOPY" ]] || die "an objcopy is required (arm-none-eabi-objcopy, rust-objcopy or llvm-objcopy)"
    PT_BIN="dist/pt_${PT_SIZE}.bin"
    IMG_BIN="dist/pico2hsm-${FLASH_TARGET}-flash.bin"
    picotool partition create "boards/pt_${PT_SIZE}.json" "$PT_BIN" -t bin >/dev/null \
        || die "picotool partition create boards/pt_${PT_SIZE}.json failed"
    "$OBJCOPY" -O binary "$ELF" "$IMG_BIN" || die "objcopy failed"

    # PROBE_SERIAL picks one probe when several are attached (as in build-all-debug.sh).
    PROBE_ARG=""
    [[ -n "${PROBE_SERIAL:-}" ]] && PROBE_ARG="--probe 2e8a:000c:$PROBE_SERIAL"

    info "Connecting to probe (chip: $CHIP)..."
    probe-rs info ${PROBE_ARG} --chip "$CHIP" 2>&1 | grep -E "Core|Memory|Vendor" || true

    # Readers before flashing: the smoke test waits for the count to return.
    count_readers() { opensc-tool --list-readers 2>/dev/null | grep -c "pico2hsm" || true; }
    BEFORE=0
    command -v opensc-tool >/dev/null 2>&1 && BEFORE=$(count_readers)

    info "Flashing partition table (pt_${PT_SIZE}) and $ELF into slot A → $CHIP ..."
    probe-rs download ${PROBE_ARG} --chip "$CHIP" --binary-format bin --base-address 0x10000000 "$PT_BIN" \
        || die "flashing the partition table failed"
    probe-rs download ${PROBE_ARG} --chip "$CHIP" --binary-format bin --base-address 0x10002000 "$IMG_BIN" \
        || die "flashing the image failed"
    probe-rs reset ${PROBE_ARG} --chip "$CHIP" || die "reset failed"

    # Release images carry no defmt version symbol, so probe-rs cannot decode
    # their RTT log (build-all-debug.sh streams it for debug builds).  The
    # smoke test is that the board comes back as a CCID reader.
    info "Waiting for the device to enumerate..."
    if command -v opensc-tool >/dev/null 2>&1; then
        # The flashed board drops off USB during the flash; wait until it is
        # back (one more reader than before if it was not enumerated then).
        WANT=$BEFORE
        sleep 3
        [[ $WANT -gt 0 ]] || WANT=1
        FOUND=0
        for _ in $(seq 1 30); do
            if [[ $(count_readers) -ge $WANT ]]; then FOUND=1; break; fi
            sleep 1
        done
        if [[ $FOUND -eq 1 ]]; then
            ok "Smoke test PASSED — $(count_readers) pico2hsm reader(s) present (${BEFORE} before flashing)"
        else
            warn "Smoke test FAILED — $(count_readers) pico2hsm reader(s) after 30 s, ${BEFORE} before flashing"
        fi
    else
        warn "opensc-tool not found: check that the device enumerates (lsusb, pcsc_scan)"
    fi
fi

section "Done"
ok "All requested stages completed."
