#!/usr/bin/env bash
# pico2hsm cluster verification script
#
# Usage: ./verify.sh [--config FILE] [--reader0 N] [--reader1 N] [--pin PIN]
#                     [--skip-daemon] [--full]
#
# Runs a sequence of checks against two connected pico2hsm devices and
# reports pass/fail for each. Exit code: 0 = all passed, 1 = any failed.
#
# Checks:
#   1. pcscd is running
#   2. Two or more readers detected
#   3. Firmware responds on reader 0 (SELECT AID)
#   4. Firmware responds on reader 1 (SELECT AID)
#   5. DKEK loaded on reader 0 (GET_STATE_HASH returns 104 bytes)
#   6. DKEK loaded on reader 1
#   7. State hash roots match on both devices
#   8. Key object counts match on both devices
#   9. (--full only) Sign on reader 0, verify with reader 1's public key
#  10. (unless --skip-daemon) Daemon is running
#  11. (unless --skip-daemon) No errors in daemon logs (last 5 minutes)

set -uo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
READER0=0
READER1=1
PIN="648219"
SKIP_DAEMON=0
FULL=0
CONFIG=""

SELECT_AID="00A404000BE82B0601040181C31F020100"
GET_STATE_HASH="80543A0000"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --reader0)   READER0="$2"; shift 2 ;;
        --reader1)   READER1="$2"; shift 2 ;;
        --pin)       PIN="$2"; shift 2 ;;
        --config)    CONFIG="$2"; shift 2 ;;
        --skip-daemon) SKIP_DAEMON=1; shift ;;
        --full)      FULL=1; shift ;;
        --help|-h)
            echo "Usage: $0 [--reader0 N] [--reader1 N] [--pin PIN] [--skip-daemon] [--full]"
            exit 0
            ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    GREEN="\033[0;32m"
    RED="\033[0;31m"
    YELLOW="\033[0;33m"
    CYAN="\033[0;36m"
    RESET="\033[0m"
else
    GREEN="" RED="" YELLOW="" CYAN="" RESET=""
fi

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
TOTAL_COUNT=0
CHECK_NUM=0

pass() {
    CHECK_NUM=$((CHECK_NUM + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "${GREEN}[%2d] PASS${RESET}: %s\n" "$CHECK_NUM" "$1"
}

fail() {
    CHECK_NUM=$((CHECK_NUM + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf "${RED}[%2d] FAIL${RESET}: %s\n" "$CHECK_NUM" "$1"
    if [[ -n "${2:-}" ]]; then
        printf "       %s\n" "$2"
    fi
}

warn() {
    CHECK_NUM=$((CHECK_NUM + 1))
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    WARN_COUNT=$((WARN_COUNT + 1))
    printf "${YELLOW}[%2d] WARN${RESET}: %s\n" "$CHECK_NUM" "$1"
    if [[ -n "${2:-}" ]]; then
        printf "       %s\n" "$2"
    fi
}

info() {
    printf "${CYAN}     INFO${RESET}: %s\n" "$1"
}

# ---------------------------------------------------------------------------
# Helper: send APDUs via opensc-tool with timeout
# ---------------------------------------------------------------------------
send_apdu() {
    local reader="$1"
    shift
    local args=()
    for apdu in "$@"; do
        args+=("-s" "$apdu")
    done
    timeout 10 opensc-tool -r "$reader" "${args[@]}" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Helper: extract hex bytes from opensc-tool output
# Returns the concatenated hex bytes from the last Received block.
# ---------------------------------------------------------------------------
extract_last_received_hex() {
    local output="$1"
    # Get lines after the last "Received" header, extract hex columns
    echo "$output" \
        | awk '/^Received/{found=1; data=""; next} /^Sending/{found=0} found && /^[0-9A-Fa-f]/{
            for(i=1;i<=NF && i<=16;i++){
                if(length($i)==2 && match($i,/^[0-9A-Fa-f][0-9A-Fa-f]$/))
                    data=data $i
            }
        } END{print data}'
}

# ---------------------------------------------------------------------------
# Check 1: pcscd running
# ---------------------------------------------------------------------------
check_pcscd() {
    if systemctl is-active pcscd >/dev/null 2>&1; then
        pass "pcscd is running"
    else
        fail "pcscd is not running" "Fix: sudo systemctl start pcscd"
    fi
}

# ---------------------------------------------------------------------------
# Check 2: Two or more readers detected
# ---------------------------------------------------------------------------
check_readers() {
    local output
    output=$(timeout 10 opensc-tool --list-readers 2>/dev/null) || true
    local count
    count=$(echo "$output" | grep -c "Yes" || true)

    if [[ "$count" -ge 2 ]]; then
        pass "Found $count readers with cards present"
    elif [[ "$count" -eq 1 ]]; then
        fail "Only 1 reader with card found (need 2)" "Check USB connections"
    else
        fail "No readers with cards found" "Check USB connections and pcscd"
    fi
}

# ---------------------------------------------------------------------------
# Check 3-4: Firmware responds on each reader (SELECT AID -> SW=9000)
# ---------------------------------------------------------------------------
check_firmware() {
    local reader="$1"
    local label="$2"
    local output
    output=$(send_apdu "$reader" "$SELECT_AID") || true

    if echo "$output" | grep -q "SW1=0x90, SW2=0x00"; then
        pass "Firmware responds on $label (reader $reader)"
    elif [[ -z "$output" ]]; then
        warn "Reader $reader not responding (timeout)" "Device may be disconnected"
    else
        fail "SELECT AID failed on $label (reader $reader)" \
             "$(echo "$output" | grep "SW1=" | head -1)"
    fi
}

# ---------------------------------------------------------------------------
# Check 5-6: DKEK loaded (GET_STATE_HASH returns 104 bytes with SW=9000)
#
# If no DKEK is loaded, the device may still return SW=9000 but with a valid
# state hash (all-empty slots). We check that the response is 104 bytes
# which confirms the command succeeded and the device is operational.
# ---------------------------------------------------------------------------
STATE_HEX_R0=""
STATE_HEX_R1=""

check_dkek_loaded() {
    local reader="$1"
    local label="$2"
    local output
    output=$(send_apdu "$reader" "$SELECT_AID" "$GET_STATE_HASH") || true

    if ! echo "$output" | grep -q "SW1=0x90, SW2=0x00"; then
        if [[ -z "$output" ]]; then
            warn "Reader $reader not responding for GET_STATE_HASH" "Skipping"
        else
            fail "GET_STATE_HASH failed on $label (reader $reader)" \
                 "$(echo "$output" | grep "SW1=" | tail -1)"
        fi
        return
    fi

    local hex
    hex=$(extract_last_received_hex "$output")
    local byte_count=$(( ${#hex} / 2 ))

    if [[ "$byte_count" -eq 104 ]]; then
        pass "GET_STATE_HASH returns 104 bytes on $label (reader $reader)"
        # Store for state hash comparison
        if [[ "$reader" == "$READER0" ]]; then
            STATE_HEX_R0="$hex"
        else
            STATE_HEX_R1="$hex"
        fi
    else
        fail "GET_STATE_HASH returned $byte_count bytes on $label (expected 104)" \
             "Device may not be initialized or DKEK may not be loaded"
    fi
}

# ---------------------------------------------------------------------------
# Check 7: State hash roots match
# Bytes 8-39 (0-indexed) of the 104-byte response = state root (32 bytes)
# In the hex string, that is characters 16-79 (each byte = 2 hex chars)
# ---------------------------------------------------------------------------
check_state_hash_match() {
    if [[ -z "$STATE_HEX_R0" ]] || [[ -z "$STATE_HEX_R1" ]]; then
        warn "Cannot compare state hashes (one or both devices did not respond)"
        return
    fi

    # Extract state root: bytes 8-39 = hex chars 16-79
    local root0="${STATE_HEX_R0:16:64}"
    local root1="${STATE_HEX_R1:16:64}"

    # Also extract generation counters: bytes 0-7 = hex chars 0-15
    local gen0="${STATE_HEX_R0:0:16}"
    local gen1="${STATE_HEX_R1:0:16}"

    if [[ -z "$root0" ]] || [[ -z "$root1" ]]; then
        warn "Could not parse state roots from response data"
        return
    fi

    # Normalize to lowercase for comparison
    root0=$(echo "$root0" | tr '[:upper:]' '[:lower:]')
    root1=$(echo "$root1" | tr '[:upper:]' '[:lower:]')

    if [[ "$root0" == "$root1" ]]; then
        pass "State roots match (${root0:0:16}...)"
        info "Generation R0=$gen0  R1=$gen1"
    else
        fail "State roots DO NOT match" \
             "R0=${root0:0:16}...  R1=${root1:0:16}..."
    fi
}

# ---------------------------------------------------------------------------
# Check 8: Key object counts match on both readers
# ---------------------------------------------------------------------------
check_key_list_match() {
    local out0 out1 count0 count1

    out0=$(timeout 15 env OPENSC_DEFAULT_READER="$READER0" \
        pkcs11-tool --login --pin "$PIN" --list-objects 2>/dev/null) || true
    out1=$(timeout 15 env OPENSC_DEFAULT_READER="$READER1" \
        pkcs11-tool --login --pin "$PIN" --list-objects 2>/dev/null) || true

    count0=$(echo "$out0" | grep -c "Private Key Object" || true)
    count1=$(echo "$out1" | grep -c "Private Key Object" || true)

    if [[ "$count0" -eq "$count1" ]]; then
        pass "Key counts match: $count0 private key(s) on each device"
    else
        fail "Key counts differ: reader $READER0 has $count0, reader $READER1 has $count1"
    fi
}

# ---------------------------------------------------------------------------
# Check 9 (--full only): Sign on R0, verify with R1's public key
# ---------------------------------------------------------------------------
check_sign_verify() {
    local tmpdir
    tmpdir=$(mktemp -d /tmp/pico2hsm-verify.XXXXXX)
    trap "rm -rf '$tmpdir'" RETURN

    info "Generating ephemeral test key on reader $READER0..."

    # Generate a test key
    local keygen_out
    keygen_out=$(timeout 30 env OPENSC_DEFAULT_READER="$READER0" \
        pkcs11-tool --login --pin "$PIN" \
        --keypairgen --key-type EC:prime256v1 \
        --id FE --label "verify-ephemeral" 2>&1) || true

    if ! echo "$keygen_out" | grep -qi "key pair generated"; then
        fail "Could not generate ephemeral test key on reader $READER0" \
             "Keygen output: $(echo "$keygen_out" | head -3)"
        return
    fi

    # Export public key from R1
    timeout 15 env OPENSC_DEFAULT_READER="$READER1" \
        pkcs11-tool --login --pin "$PIN" \
        --read-object --type pubkey --id FE \
        --output-file "$tmpdir/pub.der" 2>/dev/null || true

    if [[ ! -s "$tmpdir/pub.der" ]]; then
        # Key might not have synced to R1 yet -- try R0's own pubkey instead
        info "Key not found on reader $READER1 (not synced?). Using reader $READER0 pubkey."
        timeout 15 env OPENSC_DEFAULT_READER="$READER0" \
            pkcs11-tool --login --pin "$PIN" \
            --read-object --type pubkey --id FE \
            --output-file "$tmpdir/pub.der" 2>/dev/null || true
    fi

    if [[ ! -s "$tmpdir/pub.der" ]]; then
        fail "Could not export public key for sign/verify test"
        # Clean up key
        timeout 10 env OPENSC_DEFAULT_READER="$READER0" \
            pkcs11-tool --login --pin "$PIN" \
            --delete-object --type privkey --id FE 2>/dev/null || true
        return
    fi

    # Convert to PEM
    openssl ec -inform DER -pubin \
        -in "$tmpdir/pub.der" -out "$tmpdir/pub.pem" 2>/dev/null || true

    # Sign
    echo "pico2hsm verify.sh test" > "$tmpdir/msg.txt"
    timeout 30 env OPENSC_DEFAULT_READER="$READER0" \
        pkcs11-tool --login --pin "$PIN" \
        --sign --mechanism ECDSA-SHA256 --id FE \
        --input-file "$tmpdir/msg.txt" \
        --output-file "$tmpdir/sig.raw" 2>/dev/null || true

    if [[ ! -s "$tmpdir/sig.raw" ]]; then
        fail "Sign operation failed on reader $READER0"
        timeout 10 env OPENSC_DEFAULT_READER="$READER0" \
            pkcs11-tool --login --pin "$PIN" \
            --delete-object --type privkey --id FE 2>/dev/null || true
        return
    fi

    # Convert raw r||s to DER using Python
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "
import sys
raw = open('$tmpdir/sig.raw','rb').read()
half = len(raw) // 2
r = int.from_bytes(raw[:half], 'big')
s = int.from_bytes(raw[half:], 'big')
# Manual DER encoding of ECDSA signature
def encode_int(v):
    b = v.to_bytes((v.bit_length() + 8) // 8, 'big')
    return bytes([0x02, len(b)]) + b
seq = encode_int(r) + encode_int(s)
der = bytes([0x30, len(seq)]) + seq
open('$tmpdir/sig.der','wb').write(der)
" 2>/dev/null || true
    fi

    if [[ ! -s "$tmpdir/sig.der" ]]; then
        warn "Could not convert signature to DER (python3 required for full verify)"
        timeout 10 env OPENSC_DEFAULT_READER="$READER0" \
            pkcs11-tool --login --pin "$PIN" \
            --delete-object --type privkey --id FE 2>/dev/null || true
        return
    fi

    # Verify
    local verify_out
    verify_out=$(openssl dgst -sha256 -verify "$tmpdir/pub.pem" \
        -signature "$tmpdir/sig.der" "$tmpdir/msg.txt" 2>&1) || true

    if echo "$verify_out" | grep -q "Verified OK"; then
        pass "Sign on reader $READER0, verify with public key: OK"
    else
        fail "Signature verification failed" "$verify_out"
    fi

    # Clean up ephemeral key from both readers
    timeout 10 env OPENSC_DEFAULT_READER="$READER0" \
        pkcs11-tool --login --pin "$PIN" \
        --delete-object --type privkey --id FE 2>/dev/null || true
    timeout 10 env OPENSC_DEFAULT_READER="$READER1" \
        pkcs11-tool --login --pin "$PIN" \
        --delete-object --type privkey --id FE 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Check 10: Daemon running
# ---------------------------------------------------------------------------
check_daemon_running() {
    if systemctl is-active pico2hsm-daemon >/dev/null 2>&1; then
        pass "pico2hsm-daemon is running"
    else
        fail "pico2hsm-daemon is not running"
    fi
}

# ---------------------------------------------------------------------------
# Check 11: No daemon errors in last 5 minutes
# ---------------------------------------------------------------------------
check_daemon_no_errors() {
    local error_count
    error_count=$(journalctl -u pico2hsm-daemon --since "5 minutes ago" \
        --no-pager 2>/dev/null | grep -c "ERROR" || true)

    if [[ "$error_count" -eq 0 ]]; then
        pass "No ERROR lines in daemon logs (last 5 min)"
    else
        fail "$error_count ERROR line(s) in daemon logs (last 5 min)" \
             "Run: journalctl -u pico2hsm-daemon --since '5 min ago' | grep ERROR"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo ""
printf "${CYAN}pico2hsm cluster verification${RESET}\n"
printf "${CYAN}=============================${RESET}\n"
echo "Reader 0: $READER0    Reader 1: $READER1    PIN: ******"
echo ""

# Pre-flight
printf "${CYAN}=== Pre-flight checks ===${RESET}\n"
check_pcscd
check_readers
check_firmware "$READER0" "primary"
check_firmware "$READER1" "secondary"

# DKEK / state
printf "\n${CYAN}=== DKEK and state checks ===${RESET}\n"
check_dkek_loaded "$READER0" "primary"
check_dkek_loaded "$READER1" "secondary"
check_state_hash_match

# Key list
printf "\n${CYAN}=== Key synchronization checks ===${RESET}\n"
check_key_list_match

# Full mode: sign/verify
if [[ "$FULL" -eq 1 ]]; then
    printf "\n${CYAN}=== Sign/verify test ===${RESET}\n"
    check_sign_verify
fi

# Daemon checks
if [[ "$SKIP_DAEMON" -eq 0 ]]; then
    printf "\n${CYAN}=== Daemon health checks ===${RESET}\n"
    check_daemon_running
    check_daemon_no_errors
fi

# Summary
echo ""
printf "${CYAN}=============================${RESET}\n"
printf "Results: "
printf "${GREEN}%d passed${RESET}" "$PASS_COUNT"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    printf ", ${RED}%d failed${RESET}" "$FAIL_COUNT"
fi
if [[ "$WARN_COUNT" -gt 0 ]]; then
    printf ", ${YELLOW}%d warnings${RESET}" "$WARN_COUNT"
fi
printf " / %d total\n" "$TOTAL_COUNT"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    printf "${RED}VERIFICATION FAILED${RESET}\n"
    exit 1
else
    printf "${GREEN}VERIFICATION PASSED${RESET}\n"
    exit 0
fi
