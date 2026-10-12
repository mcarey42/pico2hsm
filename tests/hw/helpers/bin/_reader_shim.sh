#!/usr/bin/env bash
# Shared logic for the OpenSC tool shims in this directory.
#
# OpenSC tools ignore OPENSC_DEFAULT_READER (only the pyscard helpers honour
# it), so with several devices attached a bare `opensc-tool` / `sc-hsm-tool`
# / `pkcs11-tool` talks to reader 0 whatever the test intended.  conftest.py
# puts this directory first on PATH when OPENSC_DEFAULT_READER is set; each
# shim adds the reader selection unless the caller chose one explicitly.
set -euo pipefail
tool="$1"; shift
self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
real=""
IFS=: read -ra dirs <<< "$PATH"
for d in "${dirs[@]}"; do
    [[ "$(cd "$d" 2>/dev/null && pwd)" == "$self_dir" ]] && continue
    if [[ -x "$d/$tool" ]]; then real="$d/$tool"; break; fi
done
[[ -n "$real" ]] || { echo "shim: $tool not found on PATH" >&2; exit 127; }

reader="${OPENSC_DEFAULT_READER:-}"
[[ -n "$reader" ]] || exec "$real" "$@"

for a in "$@"; do
    case "$a" in
        -r|-r[0-9]*|--reader|--reader=*) exec "$real" "$@" ;;
        --slot|--slot=*|--slot-index|--slot-index=*|--slot-description|--slot-description=*) exec "$real" "$@" ;;
        -L|--list-slots|-T|--list-token-slots|-I|--show-info|-M|--list-mechanisms) [[ "$tool" == pkcs11-tool ]] && exec "$real" "$@" ;;
        -l|--list-readers) [[ "$tool" == opensc-tool ]] && exec "$real" "$@" ;;
    esac
done

case "$tool" in
    opensc-tool|sc-hsm-tool) exec "$real" -r "$reader" "$@" ;;
    pkcs11-tool)
        # Slot descriptions are the PC/SC reader names.
        name="$(opensc-tool --list-readers 2>/dev/null | awk -v n="$reader" '$1 == n { sub(/^[ ]*[0-9]+[ ]+(Yes|No)[ ]+/, ""); print; exit }')"
        [[ -n "$name" ]] || { echo "shim: no PC/SC reader $reader" >&2; exit 1; }
        exec "$real" --slot-description "$name" "$@" ;;
    *) exec "$real" "$@" ;;
esac
