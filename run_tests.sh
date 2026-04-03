#!/usr/bin/env bash
# run_tests.sh — Top-level runner for pico2hsm hardware integration tests.
#
# Usage:
#   ./run_tests.sh [pytest args...]
#
# Environment variables (optional overrides):
#   HSM_PIN      — user PIN         (default: 648219)
#   HSM_SO_PIN   — SO-PIN (hex)     (default: 3537363231383830)
#   HSM_MODULE   — PKCS#11 module   (auto-detected if unset)
#   HSM_LABEL    — token label      (default: pico2hsm)

set -euo pipefail

# ---------------------------------------------------------------------------
# Locate project root (directory containing this script)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="tests/hw/.venv"

echo "============================================================"
echo "  pico2hsm Hardware Integration Test Suite"
echo "============================================================"

# ---------------------------------------------------------------------------
# 1. Dependency checks (warn, do not abort)
# ---------------------------------------------------------------------------
DEPS_OK=true

check_dep() {
    local dep="$1"
    if ! command -v "$dep" &>/dev/null; then
        echo "  [WARN] '$dep' not found in PATH — some tests may be skipped."
        DEPS_OK=false
    else
        echo "  [OK]   $dep → $(command -v "$dep")"
    fi
}

echo ""
echo "Checking system dependencies..."
check_dep pkcs11-tool
check_dep sc-hsm-tool
check_dep openssl
check_dep python3

# Check pcscd separately (it's a daemon, not a command-line tool)
if ! pgrep -x pcscd &>/dev/null; then
    echo "  [WARN] pcscd does not appear to be running. Start with: sudo systemctl start pcscd"
    DEPS_OK=false
else
    echo "  [OK]   pcscd is running"
fi

if [ "$DEPS_OK" = false ]; then
    echo ""
    echo "  Some dependencies are missing or pcscd is not running."
    echo "  Tests will proceed but hardware-dependent tests may fail."
fi

# ---------------------------------------------------------------------------
# 2. Auto-detect PKCS#11 module if HSM_MODULE is not set
# ---------------------------------------------------------------------------
if [ -z "${HSM_MODULE:-}" ]; then
    CANDIDATE_MODULES=(
        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
        "/usr/lib/opensc-pkcs11.so"
        "/usr/local/lib/opensc-pkcs11.so"
        "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so"
        "/usr/lib/arm-linux-gnueabihf/opensc-pkcs11.so"
    )
    echo ""
    echo "Auto-detecting PKCS#11 module (HSM_MODULE not set)..."
    for candidate in "${CANDIDATE_MODULES[@]}"; do
        if [ -f "$candidate" ]; then
            export HSM_MODULE="$candidate"
            echo "  [FOUND] $HSM_MODULE"
            break
        fi
    done
    if [ -z "${HSM_MODULE:-}" ]; then
        echo "  [WARN] No PKCS#11 module found in common locations."
        echo "         Set HSM_MODULE=/path/to/opensc-pkcs11.so and re-run."
        export HSM_MODULE="/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
        echo "         Using default (may not exist): $HSM_MODULE"
    fi
else
    echo ""
    echo "Using HSM_MODULE=$HSM_MODULE"
fi

# ---------------------------------------------------------------------------
# 3. Create venv and install Python dependencies
# ---------------------------------------------------------------------------
echo ""
echo "Setting up Python virtual environment..."

if [ ! -f "$VENV_DIR/bin/python" ]; then
    echo "  Creating venv at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
    echo "  [OK] venv created"
else
    echo "  [OK] venv exists at $VENV_DIR"
fi

PYTHON="$SCRIPT_DIR/$VENV_DIR/bin/python"
PIP="$SCRIPT_DIR/$VENV_DIR/bin/pip"

echo "  Installing/updating Python dependencies..."
"$PIP" install -q --upgrade pip
"$PIP" install -q -r tests/hw/requirements.txt
echo "  [OK] dependencies ready"

# ---------------------------------------------------------------------------
# 4. Ensure report directories exist
# ---------------------------------------------------------------------------
mkdir -p tests/hw/reports

# ---------------------------------------------------------------------------
# 5. Run pytest inside the venv
# ---------------------------------------------------------------------------
echo ""
echo "Running hardware integration tests..."
echo "------------------------------------------------------------"

REPORT_DIR="tests/hw/reports/latest"

# Run pytest; capture exit code without triggering set -e
set +e
"$PYTHON" -m pytest \
    tests/hw/ \
    --html="${REPORT_DIR}/report.html" \
    --self-contained-html \
    --json-report \
    --json-report-file="${REPORT_DIR}/results.json" \
    "$@"
PYTEST_EXIT=$?
set -e

# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
if [ $PYTEST_EXIT -eq 0 ]; then
    echo "  RESULT: PASS"
else
    echo "  RESULT: FAIL  (pytest exit code: $PYTEST_EXIT)"
fi
echo ""
echo "  Reports written to: $SCRIPT_DIR/tests/hw/reports/latest/"
echo "    HTML: $SCRIPT_DIR/${REPORT_DIR}/report.html"
echo "    JSON: $SCRIPT_DIR/${REPORT_DIR}/results.json"
echo "    APDU traces: $SCRIPT_DIR/${REPORT_DIR}/*.txt"
echo "============================================================"

exit $PYTEST_EXIT
