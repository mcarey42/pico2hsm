#!/bin/bash
# Example 04: GnuPG signing.
# Part A: automated precondition check + scdaemon reset + card-status.
# Part B: instructs the user on the interactive `gpg --card-edit` flow.
# Part C: (after Part B) sign + verify a test message.
set -euo pipefail
cd "$(dirname "$0")"

command -v gpg >/dev/null || {
  echo "Error: gpg not found."
  echo "  Install:  sudo apt install gnupg    (Debian/Ubuntu)"
  echo "            brew install gnupg         (macOS)"
  exit 1
}

command -v gpg-connect-agent >/dev/null || {
  echo "Error: gpg-connect-agent not found (should ship with gnupg)."
  exit 1
}

GPG_VER=$(gpg --version | head -n1 | awk '{print $3}')
echo "[info] GnuPG version: $GPG_VER"
case "$GPG_VER" in
  2.[2-9]*|2.[1-9][0-9]*) ;;
  *)
    echo "Warning: GnuPG 2.2 or later is recommended (you have $GPG_VER)."
    echo "         OpenPGP Card 3.4 / Ed25519 support may be incomplete."
    ;;
esac
echo

echo "=== Step 1: reset scdaemon (clears any stale card handle) ==="
# "|| true" — these may print harmless errors if scdaemon wasn't running.
gpg-connect-agent "scd killscd" /bye >/dev/null 2>&1 || true
gpgconf --kill scdaemon 2>/dev/null || true
gpgconf --kill gpg-agent 2>/dev/null || true
echo "(scdaemon reset)"
echo

echo "=== Step 2: gpg --card-status (detects the pico2hsm OpenPGP applet) ==="
if ! gpg --card-status; then
  echo
  echo "Error: gpg could not talk to the card."
  echo "  - Check the device is plugged in:  opensc-tool --list-readers"
  echo "  - Confirm firmware has the OpenPGP applet:"
  echo "      opensc-tool --send-apdu 00:A4:04:00:06:D2:76:00:01:24:01"
  echo "    Expect response ending in 9000 (applet present) or 6A82 (applet missing)."
  echo "  - If the applet is missing, rebuild firmware with --features applet-openpgp"
  echo "    (or --features applet-openpgp-curve25519 for Ed25519 support)."
  exit 1
fi
echo

cat <<'EOF'

================================================================================
  Part A complete.  The OpenPGP applet is responsive.

  Part B (interactive) — generate on-card keys:

    $ gpg --card-edit

    gpg/card> admin
    gpg/card> key-attr         # (optional — skip for RSA-2048 default)
                               #   2 → ECC
                               #   1 → Curve 25519
                               #   Repeat for encryption + auth subkeys.
                               #   Requires applet-openpgp-curve25519 firmware.
    gpg/card> generate
      Make off-card backup: n
      PIN (PW3):  12345678     (admin PIN; change for production)
      PIN (PW1):  123456       (user PIN; change for production)
      Key expiry:             (press enter → does not expire)
      Real name:  pico2hsm example 04
      Email:      example@pico2hsm.local
      Comment:    (blank)
      Okay?       O
    gpg/card> quit

  Ed25519 keygen ~5 s.  RSA-2048 ~60 s.  RSA-4096 up to 16 min — don't unplug.

  Part C (after Part B completes):

    $ echo "signed by pico2hsm example 04" > msg.txt
    $ gpg --output msg.txt.sig --sign msg.txt         # prompts for PW1
    $ gpg --verify msg.txt.sig                        # → "Good signature"

================================================================================
EOF

echo
echo "[ok] Part A complete — proceed to interactive Part B (see above)."
