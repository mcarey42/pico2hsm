#!/usr/bin/env bash
# pico2hsm daemon uninstallation script.
#
# Stops the daemon, disables systemd units, and removes installed files.
# Does NOT remove the pico2hsm user or /var/lib/pico2hsm (data preservation).
#
# Usage:
#   sudo ./uninstall.sh
#
# Use --yes to skip the confirmation prompt.

set -euo pipefail

# ---- Colours ----
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

# ---- Root check ----
if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (use sudo)."
    exit 1
fi

# ---- Confirmation ----
AUTO_YES=0
for arg in "$@"; do
    if [ "$arg" = "--yes" ] || [ "$arg" = "-y" ]; then
        AUTO_YES=1
    fi
done

if [ "$AUTO_YES" -eq 0 ]; then
    echo ""
    warn "This will stop the pico2hsm daemon, remove systemd units, and delete"
    warn "installed files from /usr/local/bin and /etc/pico2hsm."
    warn ""
    warn "The following are PRESERVED (not removed):"
    warn "  - System user 'pico2hsm'"
    warn "  - State directory /var/lib/pico2hsm (contains sync state and keys)"
    echo ""
    printf "Continue? [y/N] "
    read -r REPLY
    if [ "$REPLY" != "y" ] && [ "$REPLY" != "Y" ]; then
        echo "Aborted."
        exit 0
    fi
fi

# ---- Stop and disable systemd units ----
info "Stopping and disabling systemd units..."

UNITS="pico2hsm-daemon.service pico2hsm-daemon.timer pico2hsm-verify-sync.service pico2hsm-rust-daemon.service"

for UNIT in $UNITS; do
    if systemctl is-active --quiet "$UNIT" 2>/dev/null; then
        systemctl stop "$UNIT"
        ok "Stopped $UNIT"
    fi
    if systemctl is-enabled --quiet "$UNIT" 2>/dev/null; then
        systemctl disable "$UNIT"
        ok "Disabled $UNIT"
    fi
done

# ---- Remove systemd unit files ----
info "Removing systemd unit files..."

for UNIT in $UNITS; do
    UNIT_PATH="/etc/systemd/system/${UNIT}"
    if [ -f "$UNIT_PATH" ]; then
        rm "$UNIT_PATH"
        ok "Removed $UNIT_PATH"
    fi
done

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    ok "systemctl daemon-reload complete"
fi

# ---- Remove installed binaries ----
info "Removing installed files..."

for FILE in /usr/local/bin/hsm_daemon.py; do
    if [ -f "$FILE" ]; then
        rm "$FILE"
        ok "Removed $FILE"
    fi
done

# ---- Remove PID file ----
if [ -f /run/pico2hsm/daemon.pid ]; then
    rm /run/pico2hsm/daemon.pid
    ok "Removed /run/pico2hsm/daemon.pid"
fi

if [ -d /run/pico2hsm ]; then
    rmdir /run/pico2hsm 2>/dev/null || true
fi

# ---- Remove config directory ----
if [ -d /etc/pico2hsm ]; then
    warn "Removing /etc/pico2hsm (configuration files)..."
    rm -rf /etc/pico2hsm
    ok "Removed /etc/pico2hsm"
fi

# ---- Uninstall Python package ----
info "Uninstalling pico2hsm Python package..."

if pip3 show pico2hsm >/dev/null 2>&1; then
    pip3 uninstall -y pico2hsm 2>&1 | tail -1
    ok "Uninstalled pico2hsm Python package"
else
    ok "pico2hsm Python package not installed (nothing to do)"
fi

# ---- Done ----
echo ""
info "Uninstallation complete."
echo ""
warn "The following were intentionally preserved:"
warn "  - System user 'pico2hsm' (remove with: userdel pico2hsm)"
warn "  - State directory /var/lib/pico2hsm (remove with: rm -rf /var/lib/pico2hsm)"
echo ""
