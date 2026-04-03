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

`build-all.sh` uses `picotool` to convert ELF → UF2 files for drag-and-drop
flashing. Download from https://github.com/raspberrypi/picotool or install via
your package manager:

```sh
# Debian/Ubuntu (24.04+)
sudo apt install picotool
# macOS
brew install picotool
```

If `picotool` is not found, UF2 generation is skipped with a warning.

### Optional: arm-none-eabi-size (for binary size reporting)

```sh
# Debian/Ubuntu
sudo apt install binutils-arm-none-eabi
# macOS
brew install arm-none-eabi-binutils
```

---

## Board Variants

| Feature flag | Hardware | Flash | Storage |
|---|---|---|---|
| `rp2350_one_4m` (default) | Waveshare RP2350-One | 4 MB | 2 MB keystore |
| `rp2350_one_16m` | Waveshare RP2350-One | 16 MB | 14 MB keystore |
| `rp2350_geek_16m` | Waveshare RP2350-Geek | 16 MB | 6 MB keystore |
| `rp2350_geek_sdcard` | Waveshare RP2350-Geek + SDCard | 16 MB + SD | 14 MB keystore |
| `rp2350_geek_sdcard_dual` | Waveshare RP2350-Geek + 2× SDCard | 16 MB + 2× SD | 14 MB keystore |
| `pico2_4m` | Raspberry Pi Pico 2 (stock) | 4 MB | 2 MB keystore |

> **Note:** Board feature flags are mutually exclusive. Always pass
> `--no-default-features --features <flag>` when building for a specific board.
> Omitting `--no-default-features` activates both the specified flag and the
> default `rp2350_one_4m`, causing a compile error.

### Optional feature flags (combine with any board)

| Feature | Effect |
|---|---|
| `rsa` | Enable RSA key operations (adds ~1 MB; requires 48 KB heap) |
| `debug` | Enable RAM dump APDUs; disable secure-boot enforcement |

---

## Quick start

### Run host tests (no hardware required)

```sh
cd /path/to/pico2hsm
./build-all.sh --test-only
```

### Build all board variants

```sh
./build-all.sh
```

### Build a single variant

```sh
cargo build --release \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features rp2350_one_4m
```

The ELF is written to:

```
target/thumbv8m.main-none-eabihf/release/pico2hsm
```

### Build with RSA support

```sh
cargo build --release \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features rp2350_one_16m,rsa
```

---

## Flashing hardware (without OTP burn)

> **Note — OTP state**: The RP2350 OTP is blank on a fresh board. The firmware
> detects this and logs `OTP: device may be unprovisioned`. Storage Master Key
> derivation will fail gracefully. The main loop still starts; RTT output and
> LED status can be verified without provisioning OTP.

### 1. Wire the SWD probe

Connect your debug probe to the 3-pin SWD header on the board:

| Signal | RP2350 pin |
|--------|-----------|
| SWDIO  | GPIO 24 (or board-specific pad) |
| SWDCLK | GPIO 25 (or board-specific pad) |
| GND    | GND |

Do **not** connect SWDIO/SWDCLK to JTAG pins — the RP2350 defaults to SWD.

### 2. Flash using the build script

```sh
./build-all.sh --flash rp2350_one_4m
```

This will:
1. Run host tests
2. Build the selected variant in release mode
3. Flash via `probe-rs download`
4. Reset the device and capture 5 s of RTT output
5. Verify expected boot-sequence log lines

### 3. Flash manually

```sh
# Build first
cargo build --release \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features rp2350_one_4m

# Flash (probe-rs auto-detects the probe)
probe-rs download \
    --chip RP2350 \
    --format elf \
    target/thumbv8m.main-none-eabihf/release/pico2hsm

# Run with live RTT log
probe-rs run \
    --chip RP2350 \
    target/thumbv8m.main-none-eabihf/release/pico2hsm
```

### 4. UF2 drag-and-drop (no probe needed)

`build-all.sh` automatically generates UF2 files for every board variant:

```
dist/pico2hsm-pico2_4m.uf2
dist/pico2hsm-rp2350_one_4m.uf2
dist/pico2hsm-rp2350_one_16m.uf2
dist/pico2hsm-rp2350_geek_16m.uf2
dist/pico2hsm-rp2350_geek_sdcard.uf2
dist/pico2hsm-rp2350_geek_sdcard_dual.uf2
```

To flash via UF2:

```sh
# 1. Hold the BOOTSEL button on the board
# 2. Plug in USB — the board appears as a mass-storage drive (RPI-RP2)
# 3. Copy the correct UF2 file

cp dist/pico2hsm-rp2350_one_4m.uf2 /media/$USER/RPI-RP2/
```

The board will reboot and run the firmware automatically.

To generate UF2 files manually (requires `picotool` ≥ 2.1):

```sh
# Build
cargo build --release \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features rp2350_one_4m

# Convert ELF → UF2 (RP2350 family ID = 0xe48bff59)
picotool uf2 convert \
    target/thumbv8m.main-none-eabihf/release/pico2hsm \
    -t elf \
    pico2hsm-rp2350_one_4m.uf2 \
    --family 0xe48bff59 \
    --platform rp2350
```

> UF2 flashing gives no RTT output. Use the probe path to see boot logs.

---

## Expected boot sequence (RTT output)

When the device boots against a blank (unprovisioned) OTP, you should see:

```
INFO  pico2hsm: peripherals initialised
INFO  OTP: provisioned=false, production_mode=false
WARN  OTP: derive_smk failed — device may be unprovisioned
INFO  Storage: manager init stub — not yet scanning chips
INFO  USB: transport init stub — CCID not yet enabled
INFO  Board: RP2350-One initialising
INFO  pico2hsm (RP2350-One): entering main loop
TRACE heartbeat
TRACE heartbeat
...
```

The LED will cycle through `Busy` → `Ready` (solid green / white on RGB LED).

### What "passing" means at this firmware stage

The USB CCID transport and storage manager are stubs — they are not yet wired
up. A hardware test at this stage confirms:

- [x] Embassy executor starts and runs async tasks
- [x] Board peripheral init completes (SPI, LED)
- [x] OTP driver reads device state without panicking
- [x] Security checks complete (debugger detection, JTAG OTP flag)
- [x] Main loop is reached and heartbeat timer fires
- [x] LED transitions from Busy → Ready

---

## Hardware smoke test — manual checklist

After flashing, verify the following with a probe attached:

```sh
# 1. Check probe can connect and read device info
probe-rs info --chip RP2350

# 2. Verify RTT boot messages (Ctrl-C to stop after a few seconds)
probe-rs run --chip RP2350 \
    target/thumbv8m.main-none-eabihf/release/pico2hsm

# 3. Check LED colour (physical inspection)
#    Busy = red/orange during init, Ready = green/white after main loop entry
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `probe-rs: target not found` | Probe not connected or wrong chip ID | Check USB connection; try `probe-rs list` |
| `error: invalid instruction mnemonic 'sev'` | ARM target not installed | `rustup target add thumbv8m.main-none-eabihf` |
| `cc: error: unrecognized command-line option '--nmagic'` | Building for x86 with wrong target | Use `--target thumbv8m.main-none-eabihf` or run `cargo test` not `cargo build` |
| Build fails with `No board feature flag set` | No `--features` passed | Always pass `--no-default-features --features <variant>` or rely on the workspace default |
| RTT shows `derive_smk failed` | OTP not provisioned | Expected on blank hardware; OTP provisioning is a separate step |
| No RTT output | UF2 path used (no probe) | Attach probe and use `probe-rs run` |

---

## Running only host tests

All crypto, PIN, DKEK, key management, and APDU tests run on x86_64 with no
hardware:

```sh
# All tests (lib + integration)
cargo test --target x86_64-unknown-linux-gnu \
    --manifest-path firmware/Cargo.toml

# Lib tests only (faster)
cargo test --lib --target x86_64-unknown-linux-gnu \
    --manifest-path firmware/Cargo.toml

# A specific test
cargo test --lib --target x86_64-unknown-linux-gnu \
    --manifest-path firmware/Cargo.toml \
    -- security::dkek::tests
```

Expected output: **222 tests pass, 0 fail** (1 ignored: SLIP-10 child key
spec divergence under investigation).
