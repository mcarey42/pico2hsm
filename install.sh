#!/usr/bin/env bash
# pico2hsm daemon installation script.
#
# Installs the Python daemon, creates the service user, sets up directories,
# and installs the systemd unit file.
#
# Tested on: Ubuntu 22.04+, Debian 12+.
# Requires: root privileges (sudo).
#
# Usage:
#   sudo ./install.sh
#
# The script is idempotent -- safe to run multiple times.

set -euo pipefail

# ---- Colours (no external deps) ----
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BOLD=''
    NC=''
fi

ok()   { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
err()  { printf "${RED}[ERROR]${NC} %s\n" "$*"; }
info() { printf "${BOLD}[INFO]${NC}  %s\n" "$*"; }

# ---- Locate repository root (directory containing this script) ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- OS detection ----
OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
    warn "macOS detected. systemd is not available on macOS."
    warn "The Python package will be installed, but you must start the daemon manually:"
    warn "  hsm_daemon.py start --config ~/.pico2hsm/config.yaml"
    warn ""
    MACOS=1
else
    MACOS=0
fi

# ---- Root check ----
if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (use sudo)."
    exit 1
fi

# ---- Check prerequisites ----
info "Checking prerequisites..."

MISSING=0

# Python 3.9+
if command -v python3 >/dev/null 2>&1; then
    PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 9 ]; then
        ok "Python $PY_VERSION"
    else
        err "Python 3.9+ required (found $PY_VERSION)"
        MISSING=1
    fi
else
    err "python3 not found"
    MISSING=1
fi

# pip
if command -v pip3 >/dev/null 2>&1 || python3 -m pip --version >/dev/null 2>&1; then
    ok "pip3"
else
    err "pip3 not found (install python3-pip)"
    MISSING=1
fi

# opensc (provides opensc-tool, pkcs15-tool, etc.)
if command -v opensc-tool >/dev/null 2>&1; then
    ok "opensc"
else
    warn "opensc-tool not found (install opensc). Required for smartcard access."
fi

# pcscd
if command -v pcscd >/dev/null 2>&1; then
    ok "pcscd"
else
    err "pcscd not found (install pcscd). Required for smartcard communication."
    MISSING=1
fi

if [ "$MISSING" -ne 0 ]; then
    err "Missing prerequisites. Install them and re-run this script."
    exit 1
fi

# ---- Create system user ----
info "Creating service user..."

if id pico2hsm >/dev/null 2>&1; then
    ok "User 'pico2hsm' already exists"
else
    useradd --system --no-create-home --shell /bin/false pico2hsm
    ok "Created system user 'pico2hsm'"
fi

# ---- Add user to plugdev group ----
if getent group plugdev >/dev/null 2>&1; then
    if id -nG pico2hsm | grep -qw plugdev; then
        ok "User 'pico2hsm' already in group 'plugdev'"
    else
        usermod -aG plugdev pico2hsm
        ok "Added 'pico2hsm' to group 'plugdev'"
    fi
else
    warn "Group 'plugdev' does not exist. Smartcard access may require manual group setup."
fi

# ---- Create directories ----
info "Creating directories..."

for DIR in /etc/pico2hsm /etc/pico2hsm/keys /etc/pico2hsm/certs /var/lib/pico2hsm /run/pico2hsm; do
    if [ ! -d "$DIR" ]; then
        mkdir -p "$DIR"
        ok "Created $DIR"
    else
        ok "$DIR already exists"
    fi
done

chown pico2hsm:pico2hsm /var/lib/pico2hsm
chmod 700 /var/lib/pico2hsm
chown pico2hsm:pico2hsm /run/pico2hsm
chmod 755 /run/pico2hsm
chown root:pico2hsm /etc/pico2hsm
chmod 750 /etc/pico2hsm

ok "Directory permissions set"

# ---- Install Python package ----
info "Installing pico2hsm Python package..."

PYTHON_PKG_DIR="${SCRIPT_DIR}/tools/python"

if [ ! -d "$PYTHON_PKG_DIR" ]; then
    err "Python package directory not found: $PYTHON_PKG_DIR"
    exit 1
fi

pip3 install -e "$PYTHON_PKG_DIR" 2>&1 | tail -1
ok "Python package installed"

# ---- Install hsm_daemon.py ----
info "Installing hsm_daemon.py..."

HSM_DAEMON_SRC="${SCRIPT_DIR}/tools/python/hsm_daemon.py"
HSM_DAEMON_DST="/usr/local/bin/hsm_daemon.py"

if [ ! -f "$HSM_DAEMON_SRC" ]; then
    err "hsm_daemon.py not found at: $HSM_DAEMON_SRC"
    exit 1
fi

cp "$HSM_DAEMON_SRC" "$HSM_DAEMON_DST"
chmod 755 "$HSM_DAEMON_DST"
ok "Installed $HSM_DAEMON_DST"

# ---- Install example config ----
info "Installing configuration..."

CONFIG_DST="/etc/pico2hsm/daemon.yaml"

if [ -f "$CONFIG_DST" ]; then
    ok "$CONFIG_DST already exists (not overwriting)"
else
    cp "${SCRIPT_DIR}/examples/config-local-two-hsm.yaml" "$CONFIG_DST"
    chown root:pico2hsm "$CONFIG_DST"
    chmod 640 "$CONFIG_DST"
    ok "Installed example config to $CONFIG_DST"
    warn "NOTE: Edit $CONFIG_DST to match your setup before starting the daemon."
    warn "      At minimum, set the peer public_key_file paths to your device keys."
fi

# ---- Install systemd units (Linux only) ----
if [ "$MACOS" -eq 0 ]; then
    info "Installing systemd units..."

    SYSTEMD_DIR="/etc/systemd/system"

    for UNIT in pico2hsm-daemon.service pico2hsm-daemon.timer pico2hsm-verify-sync.service; do
        SRC="${SCRIPT_DIR}/systemd/${UNIT}"
        DST="${SYSTEMD_DIR}/${UNIT}"
        if [ -f "$SRC" ]; then
            cp "$SRC" "$DST"
            chmod 644 "$DST"
            ok "Installed ${UNIT}"
        else
            warn "Unit file not found: $SRC"
        fi
    done

    systemctl daemon-reload
    ok "systemctl daemon-reload complete"
fi

# ---- Done ----
echo ""
info "Installation complete."
echo ""
printf "${BOLD}Next steps:${NC}\n"
echo ""
echo "  1. Edit the configuration file:"
echo "       sudo nano /etc/pico2hsm/daemon.yaml"
echo ""
echo "  2. Extract device public keys and update the config:"
echo "       See examples/ for annotated configuration templates."
echo ""
if [ "$MACOS" -eq 0 ]; then
    echo "  3. Enable and start the daemon:"
    echo "       sudo systemctl enable pico2hsm-daemon.service"
    echo "       sudo systemctl start pico2hsm-daemon.service"
    echo ""
    echo "  4. (Optional) Enable the periodic verify-sync timer:"
    echo "       sudo systemctl enable pico2hsm-daemon.timer"
    echo "       sudo systemctl start pico2hsm-daemon.timer"
    echo ""
    echo "  5. Monitor the daemon:"
    echo "       journalctl -u pico2hsm-daemon -f"
    echo ""
else
    echo "  3. Start the daemon manually:"
    echo "       hsm_daemon.py start --config ~/.pico2hsm/config.yaml"
    echo ""
fi
echo "  Documentation: ${SCRIPT_DIR}/docs/PYTHON_DAEMON.md"
echo ""
