# Example 04: GnuPG signing

## What this demonstrates

Uses the pico2hsm OpenPGP Card 3.4 applet as a backing store for a GnuPG
signing subkey, then signs a test file and verifies the signature.

If this passes, your pico2hsm is interchangeable with a YubiKey or Nitrokey
for PGP email signing (`git commit -S`, `mutt`, `Thunderbird/Enigmail`,
`pass-otp`, etc.) — the on-card private key never leaves the device.

Because `gpg --card-edit` is an interactive curses-style command, parts of
this example are deliberately manual. `run.sh` handles all the
pre-conditions (applet detection, scdaemon reset, `gpg --card-status`) and
then hands off to an interactive step with exact keystrokes to type.

## Prerequisites

- Flashed pico2hsm device on USB (see [QUICKSTART](../../QUICKSTART.md)).
- Firmware built with **`applet-openpgp`** (RSA / NIST ECC only) or
  **`applet-openpgp-curve25519`** (adds Ed25519 / X25519). The default
  `build-all.sh` firmware enables the `-curve25519` variant.
  Verify applet presence:
  ```sh
  gpg --card-status
  ```
  Should print an `OpenPGP card no. D2 76 00 01 24 01 ...` block. If you
  get `Operation not supported` or `6A82`, the applet is not compiled in.
- Tools:
  - GnuPG 2.2+ (`gpg --version`)
    - Debian / Ubuntu: `sudo apt install gnupg`
    - macOS: `brew install gnupg`
  - `scdaemon` (bundled with GnuPG on all platforms)
- Firmware feature: **`applet-openpgp`** at minimum; `applet-openpgp-curve25519`
  required if you want to generate Ed25519 (not RSA) subkeys.

### About PW1 / PW3

OpenPGP Card has two PINs:

- **PW1** (user PIN, default `123456`) — used for signing and decryption.
- **PW3** (admin PIN, default `12345678`) — used to generate keys and
  set card holder data.

Both defaults are used in this example. Change them in production with
`gpg --card-edit` → `admin` → `passwd`.

## Steps

### Part A — automated (run.sh)

1. Confirm the OpenPGP applet is responsive:
   ```sh
   ./run.sh
   ```
   This runs `scdaemon` restart (clears stale card-handle state),
   `gpg --card-status`, and prints the card serial. If that succeeds, it
   prints the exact `gpg --card-edit` keystrokes for Part B and exits.

### Part B — interactive (gpg --card-edit)

1. Start the edit session:
   ```sh
   gpg --card-edit
   ```

2. At the `gpg/card>` prompt, enter admin mode:
   ```
   gpg/card> admin
   Admin commands are allowed
   ```

3. Generate on-card keys:
   ```
   gpg/card> generate
   Make off-card backup of encryption key? (Y/n) n
   ```
   Prompts follow for:
   - **PIN (PW3)** — default `12345678`.
   - **PIN (PW1)** — default `123456` (may be asked twice).
   - **Key expiry** — press enter for "does not expire".
   - **Real name** — `pico2hsm example 04`.
   - **Email** — `example@pico2hsm.local`.
   - **Comment** — leave blank.
   - **Confirmation** — type `O` for "Okay".

   The card now generates sign / encrypt / auth subkeys on-device. This
   takes ~5 s for Ed25519, ~60 s for RSA-2048, and **up to 16 minutes**
   for RSA-4096 — do not unplug the device. If your firmware has
   `applet-openpgp-curve25519`, select Ed25519 via `key-attr` before
   `generate` for the fastest path:
   ```
   gpg/card> key-attr
     Your selection? 2           (ECC)
     Please select which elliptic curve you want: 1  (Curve 25519)
     [repeat for encryption and authentication]
   gpg/card> generate
   ```

4. Exit `gpg --card-edit`:
   ```
   gpg/card> quit
   ```

### Part C — sign and verify

5. Create a test message:
   ```sh
   echo "signed by pico2hsm example 04" > msg.txt
   ```

6. Sign with the on-card signing subkey:
   ```sh
   gpg --output msg.txt.sig --sign msg.txt
   ```
   GnuPG prompts for PW1 (default `123456`). The signature file
   `msg.txt.sig` contains the message and signature.

7. Verify:
   ```sh
   gpg --verify msg.txt.sig
   ```
   Expected output:
   ```
   gpg: Signature made <date> using EDDSA key <keyid>
   gpg: Good signature from "pico2hsm example 04 <example@pico2hsm.local>"
   ```

## Expected result

Part A's `run.sh` exits 0 with a card-status dump and Part B instructions.
Part C produces a "Good signature" line from `gpg --verify`.

## Troubleshooting

**`gpg: selecting card failed: No SmartCard daemon`**

`scdaemon` isn't running. Restart it:
```sh
gpg-connect-agent "scd killscd" /bye
gpg-connect-agent "scd learn" /bye
gpg --card-status
```

**`gpg: OpenPGP card not available: Card error`**

Usually a stale scdaemon handle after unplug/replug. Full reset:
```sh
gpgconf --kill scdaemon
gpgconf --kill gpg-agent
gpg --card-status
```

**"Card is already personalised" / "Invalid value" on `generate`**

An OpenPGP key already exists on the card. Factory-reset the OpenPGP
applet from inside `gpg --card-edit`:
```
gpg/card> admin
gpg/card> factory-reset
  y, yes to confirm
```
Then retry `generate`. Note: this only wipes the OpenPGP applet's keys;
SC-HSM and PIV keys are in separate namespaces and remain untouched.

**`gpg: agent_genkey failed: Timeout`**

RSA-4096 on-card generation exceeds GnuPG's default agent timeout
(`default-cache-ttl` and related). Either:
- Use Ed25519 (requires `applet-openpgp-curve25519` firmware feature) —
  completes in a few seconds.
- Use RSA-2048 (default) — completes in ~60 s.
- Extend GnuPG's card-timeout: set `disable-scdaemon` to `no` and add
  `reader-port "pico2hsm"` in `~/.gnupg/scdaemon.conf`, then restart
  `scdaemon`. (Not usually required.)

**`gpg: card error: unsupported algorithm`**

You tried to generate Ed25519 but the firmware was built without
`applet-openpgp-curve25519`. Either rebuild with that feature, or stick
to RSA / NIST P-256 from `key-attr`.

## Cleanup

To remove the OpenPGP keys from the card (so the example is re-runnable):

```
$ gpg --card-edit
gpg/card> admin
gpg/card> factory-reset
  y, yes to confirm
gpg/card> quit
```

Also remove the imported public key from your local keyring:
```sh
gpg --list-keys          # find the key fingerprint for 'pico2hsm example 04'
gpg --delete-secret-keys <fingerprint>
gpg --delete-keys        <fingerprint>
```

Generated files to remove:
```sh
rm -f msg.txt msg.txt.sig
```
