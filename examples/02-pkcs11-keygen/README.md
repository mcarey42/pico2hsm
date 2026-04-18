# Example 02: PKCS#11 keygen

## What this demonstrates

Generates a P-256 EC keypair on the pico2hsm via the OpenSC PKCS#11 module,
lists the resulting object, and optionally deletes it. This is the standard
cross-platform way that applications (SSH, X.509, VPN clients, signing
tooling) talk to smartcards — if this example works, any PKCS#11-aware
application will work.

## Prerequisites

- Flashed pico2hsm device on USB (see [QUICKSTART](../../QUICKSTART.md)).
- `opensc` / `opensc-pkcs11` installed:
  - Debian / Ubuntu: `sudo apt install opensc opensc-pkcs11`
  - macOS: `brew install opensc` (PKCS#11 module bundled)
- Firmware feature: **SC-HSM** (always on — no feature flag required).

### PIN state

This example assumes the device is already initialized with a user PIN.
If you just flashed a blank device, initialize it first:

```sh
sc-hsm-tool --initialize \
  --label "example-02" \
  --so-pin 3537363231383830 \
  --pin 648219 \
  --dkek-shares 0
```

`--dkek-shares 0` is fine for a throwaway example. For production use with
key backup, see [SINGLE_DEVICE_SETUP](../../docs/SINGLE_DEVICE_SETUP.md).

The PIN used throughout this example is `648219` (the same test PIN used in
QUICKSTART). Override by exporting `PIN` before running `./run.sh`.

### PKCS#11 module path

The script defaults to the Debian/Ubuntu module path
(`/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`). Override via the
`PKCS11_MODULE` environment variable if yours lives elsewhere:

```sh
# macOS Homebrew (Apple Silicon):
export PKCS11_MODULE=/opt/homebrew/lib/opensc-pkcs11.so

# macOS Homebrew (Intel):
export PKCS11_MODULE=/usr/local/lib/opensc-pkcs11.so

# Arch / Fedora:
export PKCS11_MODULE=/usr/lib/opensc-pkcs11.so
```

## Steps

1. (Optional) Confirm module visibility:
   ```sh
   pkcs11-tool --module "$PKCS11_MODULE" --list-slots
   ```
   Expected: a slot labelled `SmartCard-HSM (UserPIN)` (or similar).

2. Delete any pre-existing key with our label (so the example is
   re-runnable):
   ```sh
   pkcs11-tool --module "$PKCS11_MODULE" --login --pin "$PIN" \
     --delete-object --type privkey --label pico2hsm-example-02 || true
   ```

3. Generate a P-256 keypair:
   ```sh
   pkcs11-tool --module "$PKCS11_MODULE" --login --pin "$PIN" \
     --keypairgen --key-type EC:prime256v1 \
     --label pico2hsm-example-02
   ```
   Expected output ends with `Generating key pair done`.

4. Verify the object:
   ```sh
   pkcs11-tool --module "$PKCS11_MODULE" --list-objects --login --pin "$PIN"
   ```
   You should see both a public and a private key object with
   `label: pico2hsm-example-02`.

5. Run everything via the script:
   ```sh
   PIN=648219 ./run.sh
   ```

## Expected result

`./run.sh` exits 0 and the final `--list-objects` output contains two
entries with label `pico2hsm-example-02` (one `Private Key Object`, one
`Public Key Object`). EC P-256 keygen on pico2hsm takes well under one
second.

## Troubleshooting

**`CKR_PIN_INCORRECT`**

The user PIN is wrong. Either:
- You initialized with a different PIN — re-run `sc-hsm-tool --initialize`
  or pass the correct PIN via `PIN=... ./run.sh`.
- The PIN is locked from too many bad attempts — unlock with the SO PIN:
  ```sh
  sc-hsm-tool --reset-pin --so-pin 3537363231383830 --new-pin 648219
  ```

**`CKR_DEVICE_ERROR` on keygen**

Usually means the on-device key slot store is full (default SC-HSM flash
keystore holds a limited number of keys). Delete old keys:

```sh
pkcs11-tool --module "$PKCS11_MODULE" --list-objects --login --pin "$PIN"
# identify the labels of stale keys, then:
pkcs11-tool --module "$PKCS11_MODULE" --login --pin "$PIN" \
  --delete-object --type privkey --label <old-label>
```

Or re-initialize the SC-HSM to wipe all SC-HSM keys (PIV/OpenPGP keys are
preserved — they live in separate applet namespaces):

```sh
sc-hsm-tool --initialize --so-pin 3537363231383830 --pin 648219 --dkek-shares 0
```

**`CKR_ATTRIBUTE_VALUE_INVALID` on keygen**

The curve name is wrong. pico2hsm supports `prime256v1` (P-256),
`secp384r1` (P-384), `secp521r1` (P-521), and `secp256k1` (K-256). Don't
pass `P-256` or `nistp256` — they aren't recognized as PKCS#11 curve
names; use `prime256v1`.

**PKCS#11 module not found**

Most distributions put the OpenSC PKCS#11 module at one of:
`/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` (Debian/Ubuntu),
`/usr/lib/opensc-pkcs11.so` (Arch/Fedora),
`/opt/homebrew/lib/opensc-pkcs11.so` (macOS Apple Silicon Homebrew),
`/usr/local/lib/opensc-pkcs11.so` (macOS Intel Homebrew). Locate yours:

```sh
find / -name 'opensc-pkcs11.so' 2>/dev/null
```

## Cleanup

The script's final step deletes the example keypair so the example is
fully idempotent. To clean up manually:

```sh
pkcs11-tool --module "$PKCS11_MODULE" --login --pin "$PIN" \
  --delete-object --type privkey --label pico2hsm-example-02
pkcs11-tool --module "$PKCS11_MODULE" --login --pin "$PIN" \
  --delete-object --type pubkey  --label pico2hsm-example-02
```
