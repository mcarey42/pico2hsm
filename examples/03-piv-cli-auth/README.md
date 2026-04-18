# Example 03: PIV CLI auth

## What this demonstrates

Exercises the pico2hsm PIV applet (NIST SP 800-73-4) using the standard
Yubico CLI:

- Selects the PIV applet (AID `A0 00 00 03 08 00 00 10 00 01 00`).
- Generates an ECC P-256 keypair on slot `9A` (PIV Authentication).
- Exports the public key.
- Signs a challenge with the slot-9A private key and verifies the signature
  with OpenSSL using the exported public key.

If this passes, your pico2hsm is usable as a PIV smartcard for any
application that speaks the PIV protocol — OpenSSH with
`PKCS11Provider=libykcs11.so`, macOS PIV/CAC login, `ssh-agent` backed by
YubiKey-compatible stacks, etc.

## Prerequisites

- Flashed pico2hsm device on USB (see [QUICKSTART](../../QUICKSTART.md)).
- Firmware built with the **`applet-piv`** feature flag. The default
  `build-all.sh` firmware enables this; a minimal custom build may not.
  Verify by selecting the AID:
  ```sh
  opensc-tool --send-apdu 00:A4:04:00:0B:A0:00:00:03:08:00:00:10:00:01:00
  ```
  Response should end with `9000` (applet selected successfully). `6A82`
  means the applet is not compiled in.
- Tools:
  - `yubico-piv-tool`
    - Debian / Ubuntu: `sudo apt install yubico-piv-tool`
    - macOS: `brew install yubico-piv-tool`
  - `openssl` (for off-card signature verification)
- Firmware feature: **`applet-piv`**.

### About the management key

PIV's key-generation and cert-write operations are gated by a 24-byte
"management key" (also called the administrative key). pico2hsm ships with
the standard PIV default management key
`010203040506070801020304050607080102030405060708` (per NIST SP 800-73-4).
This example uses that default — rotate it before deploying in anger.

## Steps

1. Reset the PIV applet to a known state (removes any existing slot-9A key):
   ```sh
   yubico-piv-tool -r "$READER" -a verify-pin -P 000000 || true
   yubico-piv-tool -r "$READER" -a verify-pin -P 000000 || true
   yubico-piv-tool -r "$READER" -a verify-pin -P 000000 || true
   yubico-piv-tool -r "$READER" -a change-puk -P 000000 -N 000000 || true
   yubico-piv-tool -r "$READER" -a change-puk -P 000000 -N 000000 || true
   yubico-piv-tool -r "$READER" -a change-puk -P 000000 -N 000000 || true
   yubico-piv-tool -r "$READER" -a reset
   ```
   (The three failed `verify-pin` + three failed `change-puk` calls are
   required to satisfy the PIV spec's "both PIN and PUK blocked before
   factory reset" rule. `run.sh` handles this automatically.)

2. Generate a P-256 keypair in slot 9A:
   ```sh
   yubico-piv-tool -r "$READER" -a generate -s 9a -A ECCP256 -o slot-9a.pub
   ```
   Expected: a PEM public key is written to `slot-9a.pub`.

3. Sign a challenge:
   ```sh
   echo -n "hello pico2hsm PIV" > challenge.bin
   yubico-piv-tool -r "$READER" -a verify-pin -P 123456
   yubico-piv-tool -r "$READER" -a test-signature -s 9a < slot-9a.pub
   ```

4. (Alternative) Sign arbitrary data with OpenSSL via the PKCS#11 engine
   and verify off-card:
   ```sh
   openssl dgst -sha256 -verify slot-9a.pub -signature slot-9a.sig challenge.bin
   ```

5. Run everything with the script:
   ```sh
   ./run.sh
   ```

## Expected result

`./run.sh` exits 0 and the final line reads:

```
[ok] PIV slot 9A keygen + test-signature passed
```

A PEM file `slot-9a.pub` is created in the current directory — it is safe
to keep or delete; the corresponding private key never leaves the device.

## Troubleshooting

**"The card reader was not found"**

`yubico-piv-tool` matches readers by name, not index. List reader names:

```sh
opensc-tool --list-readers
```

…then pass the full name via `-r`:

```sh
yubico-piv-tool -r 'Nitrokey Nitrokey 3 [CCID/ICCD Interface] (0000...)' -a status
```

…or export `READER` before `./run.sh`:

```sh
READER='Nitrokey Nitrokey 3 [CCID/ICCD Interface] (0000...)' ./run.sh
```

The script tries to auto-detect the reader if `READER` is not set.

**`Unsuccessful command: status: 6A82` on any PIV APDU**

The PIV applet isn't compiled into the firmware. Rebuild with
`--features ...,applet-piv` (the default `build-all.sh` already enables it
— double-check you didn't pass `--no-default-features` without re-adding
`applet-piv`).

**`Algorithm not supported: 8a`**

pico2hsm does not advertise P-384 or RSA-4096 on PIV in the shipped build.
Use `-A ECCP256` (P-256) or `-A RSA2048`.

**"Key data does not match that expected for slot"**

`test-signature` compares the signature against the public key you pass on
stdin. If you re-generated the key between calls but still have an old
`slot-9a.pub` on disk, the mismatch is expected — delete `slot-9a.pub`
and re-run.

**"Authentication failed"**

The management key on the device is not the default. Use your key:

```sh
yubico-piv-tool -r "$READER" -a generate -s 9a -A ECCP256 \
  --key 112233445566778899AABBCCDDEEFF00112233445566778899 \
  -o slot-9a.pub
```

## Cleanup

The script leaves slot 9A populated with the generated key. To remove it:

```sh
yubico-piv-tool -r "$READER" -a reset   # after blocking PIN+PUK as in Step 1
```

Generated files to remove:

```sh
rm -f slot-9a.pub slot-9a.sig challenge.bin
```
