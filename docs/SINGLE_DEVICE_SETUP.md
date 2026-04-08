# Single Device Setup

A complete guide for setting up one pico2hsm device as a day-to-day
PKCS#11 hardware security module with key backup and recovery.

For building and flashing firmware, see [QUICKSTART.md](../QUICKSTART.md).
For a two-device redundant setup, see
[SETUP_LOCAL_CLUSTER.md](SETUP_LOCAL_CLUSTER.md).

---

## Prerequisites

- pico2hsm device plugged in with firmware already flashed
- `pcscd` running (`sudo systemctl start pcscd`)
- OpenSC installed (`sudo apt install opensc` on Debian/Ubuntu, `brew install opensc` on macOS)
- Device visible in `pkcs11-tool --list-slots`

If `pkcs11-tool` shows no slots, see the Troubleshooting section in
[QUICKSTART.md](../QUICKSTART.md).

---

## Step 1 -- Initialize the device

```sh
sc-hsm-tool --initialize \
  --label "MyHSM" \
  --so-pin 3537363231383830 \
  --pin 648219 \
  --dkek-shares 1
```

What each parameter does:

- `--label` -- A human-readable name for the token. Shows up in `pkcs11-tool --list-slots`.
- `--so-pin` -- The Security Officer PIN (SO-PIN). This is an 8-byte hex string used for administrative operations like resetting the user PIN. The value `3537363231383830` is the hex encoding of `"57621880"`. Choose a strong value for production.
- `--pin` -- The user PIN. This is what you type every time you sign, decrypt, or use a key. The default `648219` is for testing only -- pick something stronger for real use.
- `--dkek-shares 1` -- Configures the device to accept one DKEK (Device Key Encryption Key) share. The DKEK is required for key backup and restore. Setting this to `0` disables key export entirely.

**Warning:** `--initialize` erases all SC-HSM keys on the device. PIV and OpenPGP keys (if present) are not affected.

---

## Step 2 -- Create and import a DKEK share

The DKEK encrypts every key stored on the device. Without the DKEK share
file, keys cannot be backed up or restored to a new device. This is the
most important file you will create.

```sh
# Create an encrypted DKEK share file
sc-hsm-tool --create-dkek-share dkek-share-1.pbe \
  --password "my-strong-passphrase"

# Import the share into the device
sc-hsm-tool --import-dkek-share dkek-share-1.pbe \
  --password "my-strong-passphrase"
```

The `.pbe` file contains the DKEK share encrypted under your passphrase
(PKCS#5 / PBKDF2). Store it securely:

- **Offline USB drive** in a physically secure location
- **Password manager** (Bitwarden, 1Password) as an attached file
- **Encrypted backup drive**

Do not lose this file. If your device fails and you do not have the `.pbe`
file, all keys on the device are permanently unrecoverable.

---

## Step 3 -- Generate your first key

```sh
pkcs11-tool --login --pin 648219 \
  --keypairgen --key-type EC:prime256v1 \
  --id 01 --label "signing-key-1"
```

This generates an ECDSA P-256 key pair on the device. The private key never
leaves the HSM. The `--id 01` sets the key reference (hex byte); valid
range is `01` to `FE`.

Other supported key types:

| `--key-type` value | Algorithm |
|---|---|
| `EC:prime256v1` | ECDSA / ECDH P-256 |
| `EC:secp384r1` | ECDSA / ECDH P-384 |
| `EC:secp521r1` | ECDSA / ECDH P-521 |
| `EC:secp256k1` | ECDSA secp256k1 (Bitcoin curve) |
| `EC:brainpoolP256r1` | ECDSA Brainpool 256 |
| `EC:brainpoolP384r1` | ECDSA Brainpool 384 |
| `EC:brainpoolP512r1` | ECDSA Brainpool 512 |

---

## Step 4 -- Verify the key works

Sign a test message and confirm the operation completes without error:

```sh
echo "hello pico2hsm" > /tmp/msg.txt

pkcs11-tool --login --pin 648219 --sign \
  --mechanism ECDSA-SHA256 --id 01 \
  --input-file /tmp/msg.txt --output-file /tmp/sig.bin
```

If this returns without error, the key is operational. You can list all keys
on the device with:

```sh
pkcs11-tool --login --pin 648219 --list-objects --type privkey
```

---

## Step 5 -- Back up your keys

Each key can be exported as a DKEK-wrapped blob. The blob is encrypted under
the DKEK -- it cannot be decrypted without the DKEK share file from Step 2.

```sh
sc-hsm-tool --wrap-key wrapped-key-01.bin --key-reference 1 --pin 648219
```

This creates `wrapped-key-01.bin` containing key reference 1 encrypted under
the device's DKEK. Store this file alongside (or separately from) your DKEK
share file. Together, these two files are sufficient to restore the key to
any pico2hsm device.

Back up every key you generate. A good practice is to wrap and store each key
immediately after generating it.

---

## Restore procedure

If your device is lost, damaged, or reset, you can restore all keys to a new
pico2hsm device.

### 1. Initialize the new device with the same DKEK configuration

```sh
sc-hsm-tool --initialize \
  --label "MyHSM-replacement" \
  --so-pin 3537363231383830 \
  --pin 648219 \
  --dkek-shares 1
```

The SO-PIN and PIN can be different from the original device. The critical
requirement is that `--dkek-shares` matches the original (1 in this guide).

### 2. Import the original DKEK share

```sh
sc-hsm-tool --import-dkek-share dkek-share-1.pbe \
  --password "my-strong-passphrase"
```

This must be the same `.pbe` file created in Step 2. The same passphrase
derives the same DKEK, which is what allows the wrapped key blobs to be
decrypted.

### 3. Restore each key

```sh
sc-hsm-tool --unwrap-key wrapped-key-01.bin --key-reference 1 --pin 648219
```

Repeat for each wrapped key file. The `--key-reference` can be different from
the original if needed, but using the same reference preserves compatibility
with any configuration that references the key by ID.

### 4. Verify

```sh
pkcs11-tool --login --pin 648219 --list-objects --type privkey
```

Confirm all expected keys are present.

---

## Use cases

### SSH authentication

Generate a key on the device and extract the public key for `~/.ssh/authorized_keys`:

```sh
pkcs11-tool --login --pin 648219 \
  --keypairgen --key-type EC:prime256v1 \
  --id 02 --label "ssh-key"

# Use the key with ssh-agent
ssh-add -s /usr/lib/opensc-pkcs11.so

# Or specify the PKCS#11 provider directly
ssh -I /usr/lib/opensc-pkcs11.so user@host
```

On macOS, the PKCS#11 library is at `/usr/local/lib/opensc-pkcs11.so` (Homebrew).

### OpenPGP card (GPG, email signing)

The device also presents as an OpenPGP Card 3.4 applet. Use it with GnuPG:

```sh
gpg --card-edit
```

From the `gpg/card>` prompt, use `generate` to create keys directly on the
card, or `keytocard` to move existing GPG keys onto it. The OpenPGP applet
supports ECDSA (P-256, P-384, P-521) and optionally Ed25519/X25519 if the
firmware was built with `applet-openpgp-curve25519`.

### PIV smart card

The device supports the PIV standard (NIST SP 800-73-4), compatible with:

- macOS smart card login (CryptoTokenKit detects it automatically)
- Windows Hello for Business (PIV credential provider)
- SSH via `ssh-agent` with PIV middleware

PIV operations use separate key slots (9A, 9C, 9D, 9E) and a separate PIN
from the SC-HSM applet. Initialize PIV keys using the PIV-compatible
tools or via APDU commands documented in
[PIV_APDU_REFERENCE.md](PIV_APDU_REFERENCE.md).

---

## PIN management

### Change the user PIN

```sh
pkcs11-tool --change-pin --pin 648219 --new-pin 123456
```

### Reset a locked PIN

If the user PIN is locked (too many wrong attempts), use the SO-PIN to reset it:

```sh
sc-hsm-tool --initialize \
  --label "MyHSM" \
  --so-pin 3537363231383830 \
  --pin 648219 \
  --dkek-shares 1
```

**Warning:** Re-initialization erases all SC-HSM keys. Restore from DKEK
backups after re-initializing.
