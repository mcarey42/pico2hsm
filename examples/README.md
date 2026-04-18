# pico2hsm Examples

These examples demonstrate using pico2hsm as a real smartcard-compatible HSM
from common host tooling. All examples assume a flashed device on USB; see
[QUICKSTART](../QUICKSTART.md) for first-time setup.

Each example is a self-contained directory with its own `README.md` and a
`run.sh` script that exercises a single, well-scoped workflow end-to-end. They
are intentionally short, non-interactive where possible, and idempotent so you
can re-run them to verify your setup after plugging/unplugging the device.

## Prerequisites (common to all examples)

1. **A flashed pico2hsm device on USB.** Verify:
   ```sh
   opensc-tool --list-readers
   ```
   The device should appear as a CCID reader (usually labelled containing
   "CCID" or the firmware's ATR string).

2. **`pcscd` running.** On Linux:
   ```sh
   sudo systemctl start pcscd
   systemctl is-active pcscd   # → active
   ```
   On macOS, `pcscd` runs automatically as part of the system CryptoTokenKit
   stack and does not require manual start.

3. **Linux or macOS host.** Windows is untested — use WSL2 on Windows.

4. **Host tools.** Each example lists exactly which tools it needs. The full
   set used across all four examples:

   | Tool | Debian / Ubuntu | macOS (Homebrew) |
   |---|---|---|
   | `opensc-tool`, `pkcs11-tool` | `sudo apt install opensc` | `brew install opensc` |
   | OpenSC PKCS#11 module | `sudo apt install opensc-pkcs11` | (bundled with `opensc`) |
   | `yubico-piv-tool` | `sudo apt install yubico-piv-tool` | `brew install yubico-piv-tool` |
   | `gpg` (GnuPG 2.2+) | `sudo apt install gnupg` | `brew install gnupg` |

## Example index

| # | Title | What it shows | Firmware feature |
|---|---|---|---|
| [01](01-opensc-smoke/README.md) | OpenSC smoke test | Device enumerates and responds to `opensc-tool` | (always on) |
| [02](02-pkcs11-keygen/README.md) | PKCS#11 keygen | Generate an EC P-256 keypair via `pkcs11-tool` | SC-HSM (always on) |
| [03](03-piv-cli-auth/README.md) | PIV CLI auth | Generate a key in slot 9A and sign a challenge | `applet-piv` |
| [04](04-gnupg-signing/README.md) | GnuPG signing | Sign a test message with a smartcard subkey | `applet-openpgp` (or `-curve25519`) |

The default shipped firmware builds (`build-all.sh`) enable `applet-piv` and
`applet-openpgp-curve25519`, so all four examples work out of the box with a
stock build. If you built a minimal firmware with those features disabled,
examples 03 and 04 will fail with "applet not supported" — rebuild with the
required feature flags (see [BUILDING.md](../BUILDING.md)).

## Running an example

Every example has an executable `run.sh`:

```sh
cd examples/01-opensc-smoke
./run.sh
```

Scripts use `set -euo pipefail` and exit non-zero on the first failure, with a
troubleshooting hint. If a tool required by the example is missing, the script
tells you exactly what to install and stops before touching the device.

## Example state and cleanup

Examples 02 and 03 create persistent objects on the device (a PKCS#11 keypair
and a PIV slot 9A key, respectively). Re-running those examples is safe —
each one deletes/overwrites its own objects as the first step of `run.sh`. If
you want to fully reset the device between examples, re-run
`sc-hsm-tool --initialize` (SC-HSM keys) or `yubico-piv-tool -a reset` (PIV)
as documented in each per-example README.

## Targeting a specific reader

If you have more than one pico2hsm (or other) smartcard reader plugged in,
select by index:

```sh
opensc-tool --list-readers           # lists readers with indices 0, 1, ...
OPENSC_DEFAULT_READER=1 ./run.sh     # target the second reader
```

Examples honour `OPENSC_DEFAULT_READER` for `pkcs11-tool` invocations. For
`yubico-piv-tool` (example 03) and `gpg` (example 04), the reader is selected
by its full pcscd name (`-r`/`--reader` flag) — see the per-example READMEs.
