# Building pico2hsm Firmware

## Prerequisites

### Rust toolchain

```sh
# Install Rust (if not already present)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add bare-metal ARM target
rustup target add thumbv8m.main-none-eabihf
```

### Probe tool (for flashing physical hardware)

```sh
cargo install probe-rs-tools
```

`probe-rs` supports CMSIS-DAP, JLink, and STLink probes. A Raspberry Pi Debug
Probe or any CMSIS-DAP compatible SWD adapter works with both RP2350 boards.

### picotool (for UF2 generation)

`build-all.sh` uses `picotool` to convert ELF → UF2 files and to sign them;
`build-all-debug.sh` uses it to build the partition table. Signing needs a
picotool built with `seal` (mbedtls); CI builds 2.2.0 from source. Download
from https://github.com/raspberrypi/picotool or install via your package
manager:

```sh
# Debian/Ubuntu (24.04+)
sudo apt install picotool
# macOS
brew install picotool
```

If `picotool` is not found, `build-all.sh` skips UF2 generation with a
warning; `build-all-debug.sh` stops (it needs picotool for the partition
table).

### Optional: arm-none-eabi-size (for binary size reporting)

```sh
# Debian/Ubuntu
sudo apt install binutils-arm-none-eabi
# macOS
brew install arm-none-eabi-binutils
```

---

## Board Variants

| Feature flag | Hardware | Flash | Keystore | Partition table |
|---|---|---|---|---|
| `rp2350_one_4m` (default) | Waveshare RP2350-One | 4 MB | 2,044 KB internal | `boards/pt_4m.json` |
| `rp2350_one_16m` | Waveshare RP2350-One with a 16 MB chip | 16 MB | ~7.8 MB internal | `boards/pt_16m.json` |
| `rp2350_geek_16m` | Waveshare RP2350-Geek | 16 MB | ~7.8 MB internal | `boards/pt_16m.json` |
| `rp2350_geek_sdcard` | Waveshare RP2350-Geek + SDCard | 16 MB + SD | SD card | `boards/pt_16m.json` |
| `waveshare_rp2350_lcd_16m` | Waveshare RP2350-LCD-1.47-B | 16 MB | ~7.8 MB internal | `boards/pt_16m.json` |
| `waveshare_rp2350_lcd_sdcard` | Waveshare RP2350-LCD-1.47-B + SDCard | 16 MB + SD | SD card | `boards/pt_16m.json` |
| `pico2_4m` | Raspberry Pi Pico 2 (stock) | 4 MB | 2,044 KB internal | `boards/pt_4m.json` |

Every board boots through a bootrom partition table: one firmware slot on
4 MB boards, A/B slots with try-before-you-buy on 16 MB boards, and the
store regions as partitions closed to BOOTSEL
([docs/FLASH_LAYOUT_2_0.md](docs/FLASH_LAYOUT_2_0.md)).

> **Note:** Board feature flags are mutually exclusive. Always pass
> `--no-default-features --features <flag>` when building for a specific board.
> Omitting `--no-default-features` activates both the specified flag and the
> default `rp2350_one_4m`, causing a compile error.

### Optional feature flags (combine with any board)

| Feature | Effect | Default? |
|---|---|---|
| `rsa` | Enable RSA-2048/3072/4096 and the RSA key pool (adds ~115 KB flash; 48 KB heap) | **Yes** |
| `applet-piv` | Enable PIV applet (NIST SP 800-73-4); slots 9A/9C/9D/9E | **Yes** |
| `applet-openpgp` | Enable OpenPGP Card 3.4 applet; NIST ECC (P-256/384/521) | implied by curve25519 |
| `applet-openpgp-curve25519` | Add Ed25519/X25519 to OpenPGP (implies `applet-openpgp`) | **Yes** |
| `debug` | Enable the debug APDUs (INS `0xFE`: watchdog and recovery test hooks, BOOTSEL reboot, boot/partition info); skip the production-mode boot checks | No — never in production |
| `insecure-dev-keystore` | Let a release build use the fixed, public development storage key on unprovisioned OTP (debug builds always do) | No — never in production |

The four capabilities (`rsa` and the three applet flags) are on by default. Use `--no-default-features`
plus explicit `--features` to opt out of specific capabilities for size-constrained builds.

---

## Default build — all features enabled

The default build includes all three applets (SC-HSM, PIV, OpenPGP with
Ed25519/X25519) plus RSA support. This is the recommended configuration for
production use. You do not need to specify any extra flags:

```sh
# Build for Waveshare RP2350-One 4MB (the default board)
cargo build --release --manifest-path firmware/Cargo.toml
```

To build for a different board, always use `--no-default-features` (board flags
are mutually exclusive) and explicitly list the capabilities you want:

```sh
# Pico 2 — all features
cargo build --release \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519

# RP2350-Geek 16MB — all features
cargo build --release \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features rp2350_geek_16m,rsa,applet-piv,applet-openpgp-curve25519
```

`applet-openpgp-curve25519` implies `applet-openpgp`; you do not need to list
both.

---

## Firmware signing

**All firmware outputs should be signed before deployment.** The build scripts
do this automatically if `ec_firmware_signing_key-bootkey0.pem` exists in the project
root. Generate the key pair once:

```sh
./generate_firmware_signing_keys.sh
```

This creates `ec_firmware_signing_key-bootkey0.pem` (private — keep it safe) and
`ec_firmware_signing_key-bootkey0.pub` (public — safe to share). Both are gitignored.

After generating the key, every `./build-all.sh` run produces signed
outputs in `dist/`:

```
dist/pico2hsm-<board>-signed.elf                          ← signed ELF
dist/pico2hsm-<board>.uf2                                 ← generated from the signed ELF
dist/pico2hsm-<board>-seal-otp-ENABLES-SECURE-BOOT.json   ← never load this
```

`./build-all-debug.sh` also writes `dist/pico2hsm-<board>-debug-signed.elf`,
but flashes the unsigned ELF (probe-rs cannot parse picotool-signed debug
ELFs).

> The RP2350 bootrom only enforces the signature when secure boot is
> enabled in OTP. Signing debug builds is safe — unsigned devices boot
> normally; locked devices reject unsigned images.
>
> The `-seal-otp-ENABLES-SECURE-BOOT.json` file `picotool seal` writes sets
> `crit1.secure_boot_enable` in one step: **never load it**. Boot keys are
> provisioned with `tools/otp-bootkeys.sh` and `tools/provision-device.py`;
> see [docs/PROVISIONING.md](docs/PROVISIONING.md).

---

## Quick start

### Run host tests (no hardware required)

```sh
cd /path/to/pico2hsm
./build-all.sh --test-only
```

### Build all board variants (with signing)

```sh
# Generate key first (once only)
./generate_firmware_signing_keys.sh

# Build everything — signs if key is present
./build-all.sh
```

### Build a single variant manually

```sh
# All features — recommended
cargo build --release \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features rp2350_one_4m,rsa,applet-piv,applet-openpgp-curve25519
```

The ELF is written to:

```
target/thumbv8m.main-none-eabihf/release/pico2hsm
```

### Minimal build (SC-HSM only, no RSA, no extra applets)

For constrained builds or quick iteration:

```sh
cargo build --release \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features rp2350_one_4m
```

---

## Flashing hardware (without OTP burn)

> **Note — OTP state**: The RP2350 OTP is blank on a fresh board. A
> **release** build then has no storage key and disables its keystore
> (`OTP: unprovisioned — keystore disabled (no storage key)`); key
> operations fail. A **debug** build, or a release build with
> `insecure-dev-keystore`, uses the fixed public development key and warns
> at boot. A release build also disables its keystore if the loaded
> partition table is not the one it was built for.

### 1. Wire the SWD probe

Connect your debug probe to the board's SWD pads or header (SWDIO, SWCLK,
GND). The RP2350's SWD port has dedicated pins; it does not use GPIOs.
If you cannot reach the SWD pads (the project flashes its Waveshare
RP2350-One and LCD boards without a probe), use BOOTSEL (step 3).

### 2. Flash with the debug script (probe)

```sh
./build-all-debug.sh pico2_4m                    # debug profile
PROFILE=release ./build-all-debug.sh pico2_4m    # release profile, symbols kept
```

This builds the board with all applets and RSA, writes the partition table
(`boards/pt_4m.json` or `pt_16m.json`) at `0x10000000` and the image into
slot A at `0x10002000` with `probe-rs download`, resets, and attaches for
RTT. Set `PROBE_SERIAL=<serial>` when several probes are connected.

`./build-all.sh --flash <board>` predates the partition table: it downloads
the ELF to `0x10000000`, over the table's sector. Do not use it on a 2.0
board.

### 3. BOOTSEL and picotool (no probe needed)

`build-all.sh` generates UF2 files for every board variant in its list:

```
dist/pico2hsm-pico2_4m.uf2
dist/pico2hsm-rp2350_one_4m.uf2
dist/pico2hsm-rp2350_geek_16m.uf2
dist/pico2hsm-rp2350_geek_sdcard.uf2
dist/pico2hsm-waveshare_rp2350_lcd_16m.uf2
dist/pico2hsm-waveshare_rp2350_lcd_sdcard.uf2
```

Install the partition table once per board, then the firmware:

```sh
# 1. Hold BOOTSEL and plug in USB (or send 80 FE 14 00 to a debug build)
# 2. The partition table (pt_16m.json on 16 MB boards):
picotool partition create boards/pt_4m.json /tmp/pt_4m.uf2
picotool load /tmp/pt_4m.uf2
picotool reboot -u
# 3. The firmware into partition 0 (slot A); -x runs it
picotool load -p 0 -x dist/pico2hsm-rp2350_one_4m.uf2
```

With several boards in BOOTSEL, pass `--ser <serial>` to every picotool
command. Later updates are step 3 alone. CI release assets ship the
tables ready-made as `pico2hsm-<board>-pt-dev.uf2` / `-pt-prod.uf2`.

To generate a firmware UF2 manually (requires `picotool` ≥ 2.1):

```sh
cargo build --release \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features rp2350_one_4m,rsa,applet-piv,applet-openpgp-curve25519
cp target/thumbv8m.main-none-eabihf/release/pico2hsm /tmp/pico2hsm.elf

# Convert ELF → UF2 (RP2350 Arm Secure family, 0xe48bff59)
picotool uf2 convert /tmp/pico2hsm.elf -t elf /tmp/pico2hsm-rp2350_one_4m.uf2 \
    --family rp2350-arm-s
```

> BOOTSEL flashing gives no RTT output. Debug builds also log to the CDC
> serial port (`/dev/ttyACMx`) once a terminal opens it.

---

## Boot log (RTT)

The first lines of every boot say why the last reset happened
(`reset: …`), then which slot booted and `pico2hsm: peripherals
initialised`, the OTP state (`OTP: provisioned=… production=…`), the store
state, and `… entering main loop`. On debug builds the watchdog feeder
later logs `core1 stack high water: N of 98304 bytes` as the stack grows.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `probe-rs: target not found` | Probe not connected or wrong chip ID | Check USB connection; try `probe-rs list` |
| `error: invalid instruction mnemonic 'sev'` | ARM target not installed | `rustup target add thumbv8m.main-none-eabihf` |
| `cc: error: unrecognized command-line option '--nmagic'` | Host tests run without `--target x86_64-unknown-linux-gnu` | `.cargo/config.toml` defaults to thumbv8m; pass the host target to `cargo test` |
| `can't find crate for std` in `pico2hsm-integration-tests` | `cargo build` from the root without naming the package | Add `-p pico2hsm-firmware` or `--manifest-path firmware/Cargo.toml` |
| `OTP: unprovisioned — keystore disabled` | Release build on blank OTP | Expected; use a debug or `insecure-dev-keystore` build for development, or provision ([docs/PROVISIONING.md](docs/PROVISIONING.md)) |
| `layout: … — keystore disabled` | Release build without its partition table | Install the board's table (see above) |
| No RTT output | BOOTSEL path used (no probe) | Attach a probe and use `build-all-debug.sh` |

---

## Running only host tests

All crypto, PIN, DKEK, key management, and APDU tests run on x86_64 with no
hardware:

```sh
# Firmware library tests (the bulk)
cargo test --lib --target x86_64-unknown-linux-gnu \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519

# Firmware integration tests (firmware/tests)
cargo test --test '*' --target x86_64-unknown-linux-gnu \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519

# Core crate and the std integration crate
cargo test -p pico2hsm-core --target x86_64-unknown-linux-gnu
cargo test -p pico2hsm-integration-tests --target x86_64-unknown-linux-gnu

# A specific module
cargo test --lib --target x86_64-unknown-linux-gnu \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519 \
    -- security::dkek::tests
```

These are the commands CI runs (`.github/workflows/build.yml`, every board
for the library tests).
