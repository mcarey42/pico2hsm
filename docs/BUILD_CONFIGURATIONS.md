# Build Configurations Reference

This document lists every supported build configuration for pico2hsm firmware,
with exact cargo commands and flash/RAM budget estimates.

---

## Quick reference: default features

`Cargo.toml` sets:
```toml
default = ["rp2350_one_4m", "rsa", "applet-piv", "applet-openpgp-curve25519"]
```

This means `cargo build --release --manifest-path firmware/Cargo.toml` (no
extra flags) builds the Waveshare RP2350-One 4MB with all applets and RSA
enabled — the recommended production configuration.

**When changing the board target, always pass `--no-default-features`.**
Board feature flags are mutually exclusive. Adding `--features other_board`
without `--no-default-features` activates both `rp2350_one_4m` and the new
board simultaneously, causing a compile error.

```sh
# Correct — explicit board, re-add capabilities manually
cargo build --release --no-default-features \
    --features rp2350_geek_sdcard,rsa,applet-piv,applet-openpgp-curve25519

# Wrong — activates rp2350_one_4m AND rp2350_geek_sdcard simultaneously
cargo build --release --features rp2350_geek_sdcard
```

The `build-all-debug.sh` and `build-all.sh` scripts handle this correctly.

---

## Recommended full-featured builds

All three applets plus RSA. These are the configurations `build-all.sh` produces.

```sh
# Raspberry Pi Pico 2 (internal flash)
cargo build --release --no-default-features \
    --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519

# Waveshare RP2350-One 4MB
cargo build --release --no-default-features \
    --features rp2350_one_4m,rsa,applet-piv,applet-openpgp-curve25519

# Waveshare RP2350-One 16MB
cargo build --release --no-default-features \
    --features rp2350_one_16m,rsa,applet-piv,applet-openpgp-curve25519

# Waveshare RP2350-Geek 16MB
cargo build --release --no-default-features \
    --features rp2350_geek_16m,rsa,applet-piv,applet-openpgp-curve25519

# Waveshare RP2350-Geek with SD card
cargo build --release --no-default-features \
    --features rp2350_geek_sdcard,rsa,applet-piv,applet-openpgp-curve25519
```

---

## Board-only builds (SC-HSM applet only, minimal size)

### Raspberry Pi Pico 2 (development board)

```sh
# Pico 2 — 4 MB flash, GPIO25 LED, USB debug
cargo build --release --no-default-features --features pico2_4m

```

### Waveshare RP2350-One

```sh
# 4 MB flash variant
cargo build --release --no-default-features --features rp2350_one_4m

# 16 MB flash variant (no SD card)
cargo build --release --no-default-features --features rp2350_one_16m

```

### Waveshare RP2350-Geek

```sh
# 16 MB flash, no SD card
cargo build --release --no-default-features --features rp2350_geek_16m

# 16 MB flash + built-in SD card slot (GPIO5 CS)
cargo build --release --no-default-features --features rp2350_geek_sdcard

```

### Waveshare RP2350-LCD-1.47-B

```sh
# 16 MB flash + built-in SD card (SPI1 GPIO10/11/12/15) + 1.47" LCD
cargo build --release --no-default-features --features waveshare_rp2350_lcd_16m

# SD card as sole keystore (replaces QMI flash)
cargo build --release --no-default-features --features waveshare_rp2350_lcd_sdcard

```

#### SD-only keystore (`waveshare_rp2350_lcd_sdcard`)

Replaces QMI flash with a single microSD card as the sole keystore. Raw block I/O — no filesystem. Requires a microSD card in the SPI1 slot (GPIO10/11/12, CS=GPIO15).

```sh
cargo build --release --no-default-features \
    --features waveshare_rp2350_lcd_sdcard,rsa,applet-piv,applet-openpgp-curve25519
```

**Flash budget**: Same as `waveshare_rp2350_lcd_16m`.
**RAM budget**: Same as `waveshare_rp2350_lcd_16m`; no framebuffer change.
**Keystore**: SD card raw blocks. Keys do not survive SD card removal without the hybrid variant.

---

## Applet combinations

Applet feature flags compose freely with any board feature flag.

### SC-HSM + PIV

```sh
# PIV on Pico 2
cargo build --release --no-default-features --features pico2_4m,applet-piv

# PIV on RP2350-Geek with SD card
cargo build --release --no-default-features --features rp2350_geek_sdcard,applet-piv

# PIV on Waveshare LCD
cargo build --release --no-default-features --features waveshare_rp2350_lcd_16m,applet-piv
```

### SC-HSM + OpenPGP (NIST ECC curves only)

```sh
# OpenPGP on RP2350-One 16 MB
cargo build --release --no-default-features --features rp2350_one_16m,applet-openpgp

# OpenPGP on Waveshare LCD
cargo build --release --no-default-features --features waveshare_rp2350_lcd_16m,applet-openpgp
```

### SC-HSM + OpenPGP + Ed25519 / X25519 (curve25519)

`applet-openpgp-curve25519` implies `applet-openpgp`; specifying both is
harmless but redundant.

```sh
# OpenPGP + curve25519 on RP2350-Geek with SD card
cargo build --release --no-default-features \
  --features rp2350_geek_sdcard,applet-openpgp-curve25519

# OpenPGP + curve25519 on Waveshare LCD
cargo build --release --no-default-features \
  --features waveshare_rp2350_lcd_16m,applet-openpgp-curve25519
```

### SC-HSM + PIV + OpenPGP (all three applets)

```sh
# All three applets, NIST curves only — RP2350-One 16 MB
cargo build --release --no-default-features \
  --features rp2350_one_16m,applet-piv,applet-openpgp

# All three applets + Ed25519/X25519 — Waveshare LCD
cargo build --release --no-default-features \
  --features waveshare_rp2350_lcd_16m,applet-piv,applet-openpgp,applet-openpgp-curve25519

# All three applets + Ed25519/X25519 — RP2350-Geek with SD card
cargo build --release --no-default-features \
  --features rp2350_geek_sdcard,applet-piv,applet-openpgp,applet-openpgp-curve25519
```

### With RSA support

RSA support is feature-gated (`rsa`) because it adds approximately 1 MB to the
binary. It can be combined with any board and applet combination:

```sh
# SC-HSM + RSA on RP2350-Geek (no SD)
cargo build --release --no-default-features --features rp2350_geek_16m,rsa

# All features on Waveshare LCD
cargo build --release --no-default-features \
  --features waveshare_rp2350_lcd_16m,rsa,applet-piv,applet-openpgp,applet-openpgp-curve25519
```

---

## Flash / RAM budget

Measurements are from release builds on `pico2_4m` (RP2350A, 4 MB flash,
512 KB SRAM). Other boards with the same MCU will produce similar numbers.

| Configuration | Applets | Flash (approx.) | RAM (approx.) |
|---------------|---------|-----------------|---------------|
| Any board     | SC-HSM only | ~366 KB     | ~377 KB       |
| Any board     | SC-HSM + PIV | ~384–393 KB | ~379 KB      |
| Any board     | SC-HSM + OpenPGP (NIST) | ~376–381 KB | ~379 KB |
| Any board     | SC-HSM + OpenPGP + curve25519 | ~421–441 KB | ~379 KB |
| Any board     | All three + curve25519 | ~439–476 KB | ~381 KB |
| Any board     | SC-HSM + RSA | ~1366 KB (est.) | ~377 KB |

Device limits (RP2350A with 4 MB external flash):
- Flash: 4096 KB (QSPI, XIP)
- SRAM: 520 KB total; core1 stack is 128 KB of that

RAM is the metric to watch. The 128 KB core1 stack and SC-HSM key caches
dominate; applet state structs are small by comparison. Current worst-case
(all applets + curve25519) uses approximately 74% of available SRAM.

**RSA note**: The `rsa` feature pulls in `num-bigint-dig` which generates very
large code. It is only recommended for boards with 16 MB flash
(`rp2350_one_16m`, `rp2350_geek_16m`, `rp2350_geek_sdcard`, etc.).

**RSA debug build speed**: Without optimization, RSA-4096 keygen takes >30
minutes on Cortex-M33 in debug builds. The workspace `Cargo.toml` adds
`opt-level = 3` overrides for `num-bigint-dig` and `rsa` packages under
`[profile.dev.package.*]`, cutting keygen to ~2 minutes. This is already
present in the repo and applies automatically to all debug builds.

---

## Debug builds (hardware flash + RTT streaming)

Always use `build-all-debug.sh` for hardware debugging. It sets
`DEFMT_LOG=trace` at compile time (required for defmt log levels to survive
optimisation), uses the debug profile (activates `#[cfg(debug_assertions)]`
code paths), and streams RTT output via probe-rs.

```sh
# Pico 2 (default development target)
./build-all-debug.sh pico2_4m

# RP2350-One 16 MB
./build-all-debug.sh rp2350_one_16m

# RP2350-Geek with built-in SD card
./build-all-debug.sh rp2350_geek_sdcard

# Waveshare RP2350-LCD-1.47-B
./build-all-debug.sh waveshare_rp2350_lcd_16m

# Waveshare RP2350-LCD-1.47-B — SD card as sole keystore
./build-all-debug.sh waveshare_rp2350_lcd_sdcard

```

The script blocks on RTT streaming. To run the integration test suite, start
the script in the background first, wait ~5 s for USB re-enumeration, then run:

```sh
./run_tests.sh
```

If `probe-rs` reports "interface is busy (errno 16)", kill any stale process:

```sh
pkill -9 -f "probe-rs"
```

### Debug + applets

`build-all-debug.sh` builds with all applets and RSA enabled, matching the
production default. This is required for the integration test suite
(`run_tests.sh`) to pass — PIV and OpenPGP tests will receive SW=6D00 if those
applets are not compiled in.

```sh
# Pico 2 — builds SC-HSM + RSA + PIV + OpenPGP + Ed25519/X25519
./build-all-debug.sh pico2_4m
```

The features included are: `rsa,applet-piv,applet-openpgp-curve25519`
(`applet-openpgp-curve25519` implies `applet-openpgp`).

To build manually with the same set:

```sh
cargo build --no-default-features \
  --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519
```

---

## cargo check (lint only, no flash)

For fast iteration without a connected board:

```sh
# Check default target (rp2350_one_4m)
cargo check

# Check a specific board
cargo check --no-default-features --features rp2350_geek_sdcard

# Check with applets
cargo check --no-default-features --features pico2_4m,applet-piv,applet-openpgp

# Run unit tests (x86_64 host, no hardware needed)
cargo test
```

Unit tests compile only the platform-agnostic crates. ARM-only dependencies
(Embassy, probe-rs, defmt) are excluded by the
`[target.'cfg(target_arch = "arm")'.dependencies]` section in `Cargo.toml`.
