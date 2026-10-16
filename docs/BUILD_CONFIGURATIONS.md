# Build Configurations Reference

This document lists every supported build configuration for pico2hsm firmware,
with exact cargo commands and flash/RAM budget estimates.

---

## Quick reference: default features

`Cargo.toml` sets:
```toml
default = ["rp2350_one_4m", "rsa", "applet-piv", "applet-openpgp-curve25519"]
```

This means `cargo build --release -p pico2hsm-firmware` (no extra flags)
builds the Waveshare RP2350-One 4MB with all applets and RSA enabled — the
recommended production configuration.

From the repository root, always name the firmware package (`-p
pico2hsm-firmware` or `--manifest-path firmware/Cargo.toml`): the workspace
also holds the host-only `tests/integration` crate, which does not build for
the default `thumbv8m.main-none-eabihf` target.

**When changing the board target, always pass `--no-default-features`.**
Board feature flags are mutually exclusive. Adding `--features other_board`
without `--no-default-features` activates both `rp2350_one_4m` and the new
board simultaneously, causing a compile error.

```sh
# Correct — explicit board, re-add capabilities manually
cargo build --release -p pico2hsm-firmware --no-default-features \
    --features rp2350_geek_sdcard,rsa,applet-piv,applet-openpgp-curve25519

# Wrong — activates rp2350_one_4m AND rp2350_geek_sdcard simultaneously
cargo build --release -p pico2hsm-firmware --features rp2350_geek_sdcard
```

The `build-all-debug.sh` and `build-all.sh` scripts handle this correctly.

---

## Recommended full-featured builds

All three applets plus RSA. `build-all.sh` builds these for every board
except `rp2350_one_16m` (not yet in its variant list). The CI release
artifacts (`pico2hsm-<board>-unsigned.uf2`) are built **without** `rsa`.

```sh
# Raspberry Pi Pico 2 (internal flash)
cargo build --release -p pico2hsm-firmware --no-default-features \
    --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519

# Waveshare RP2350-One 4MB
cargo build --release -p pico2hsm-firmware --no-default-features \
    --features rp2350_one_4m,rsa,applet-piv,applet-openpgp-curve25519

# Waveshare RP2350-Geek 16MB
cargo build --release -p pico2hsm-firmware --no-default-features \
    --features rp2350_geek_16m,rsa,applet-piv,applet-openpgp-curve25519

# Waveshare RP2350-One with a 16MB chip
cargo build --release -p pico2hsm-firmware --no-default-features \
    --features rp2350_one_16m,rsa,applet-piv,applet-openpgp-curve25519

# Waveshare RP2350-Geek with SD card
cargo build --release -p pico2hsm-firmware --no-default-features \
    --features rp2350_geek_sdcard,rsa,applet-piv,applet-openpgp-curve25519

# Waveshare RP2350-LCD-1.47-B, internal flash / SD card
cargo build --release -p pico2hsm-firmware --no-default-features \
    --features waveshare_rp2350_lcd_16m,rsa,applet-piv,applet-openpgp-curve25519
cargo build --release -p pico2hsm-firmware --no-default-features \
    --features waveshare_rp2350_lcd_sdcard,rsa,applet-piv,applet-openpgp-curve25519
```

---

## Board-only builds (SC-HSM applet only, minimal size)

### Raspberry Pi Pico 2 (development board)

```sh
# Pico 2 — 4 MB flash, GPIO25 LED, USB debug
cargo build --release -p pico2hsm-firmware --no-default-features --features pico2_4m

```

### Waveshare RP2350-One

```sh
# 4 MB flash (stock): one firmware slot, 128 SC-HSM keys
cargo build --release -p pico2hsm-firmware --no-default-features --features rp2350_one_4m

# 16 MB flash chip fitted: the One board code with the 16 MB map
# (A/B slots, try-before-you-buy, all 251 SC-HSM keys)
cargo build --release -p pico2hsm-firmware --no-default-features --features rp2350_one_16m
```

Every board boots through a partition table: 4 MB boards use
`boards/pt_4m.json`, 16 MB boards `boards/pt_16m.json` (production:
`pt_*_prod.json`).  See [FLASH_LAYOUT_2_0.md](FLASH_LAYOUT_2_0.md).

### Waveshare RP2350-Geek

```sh
# 16 MB flash, no SD card
cargo build --release -p pico2hsm-firmware --no-default-features --features rp2350_geek_16m

# SD card as keystore (built-in slot on SPI0, CS=GPIO23)
cargo build --release -p pico2hsm-firmware --no-default-features --features rp2350_geek_sdcard

```

### Waveshare RP2350-LCD-1.47-B

```sh
# 16 MB flash, keystore on internal flash, 1.47" LCD (SD slot unused)
cargo build --release -p pico2hsm-firmware --no-default-features --features waveshare_rp2350_lcd_16m

# SD card as sole keystore (replaces QMI flash)
cargo build --release -p pico2hsm-firmware --no-default-features --features waveshare_rp2350_lcd_sdcard

```

#### SD-only keystore (`waveshare_rp2350_lcd_sdcard`)

Replaces QMI flash with a single microSD card as the sole keystore. Raw block I/O — no filesystem. Requires a microSD card in the SPI1 slot (GPIO10/11/12, CS=GPIO15).

```sh
cargo build --release -p pico2hsm-firmware --no-default-features \
    --features waveshare_rp2350_lcd_sdcard,rsa,applet-piv,applet-openpgp-curve25519
```

**Flash / RAM budget**: within a few KB of `waveshare_rp2350_lcd_16m` (see
the table below).
**Keystore**: SD card raw blocks. Keys, the DKEK and domain records live on
the card; the binding block, the PIN/PUK retry counters (with the
keystore anchor) and the RSA key pool stay on internal flash. With the card
removed, the device holds no user keys.

#### Why SD-card builds exist

Both SD-card builds (`rp2350_geek_sdcard`, `waveshare_rp2350_lcd_sdcard`)
serve one use case. An SD-card board is enrolled in a domain, then shipped
to a remote party with the card sent separately. The card alone is useless:
its objects are encrypted under keys derived from the device's OTP-based
storage master key. The device alone holds no user keys. When the card goes
back in, the device verifies it and resumes domain sync.

Card verification on reinsertion (store ID, MACs, a rollback anchor on
internal flash) is implemented by Storage V2; see `docs/STORAGE_V2.md` §8
and §11, and `docs/KEYSTORE_RECOVERY.md` when a card is refused.
Domain sync is designed in `docs/CLUSTER_PLAN_V3.md`.

---

## Applet combinations

Applet feature flags compose freely with any board feature flag.

### SC-HSM + PIV

```sh
# PIV on Pico 2
cargo build --release -p pico2hsm-firmware --no-default-features --features pico2_4m,applet-piv

# PIV on RP2350-Geek with SD card
cargo build --release -p pico2hsm-firmware --no-default-features --features rp2350_geek_sdcard,applet-piv

# PIV on Waveshare LCD
cargo build --release -p pico2hsm-firmware --no-default-features --features waveshare_rp2350_lcd_16m,applet-piv
```

### SC-HSM + OpenPGP (NIST ECC curves only)

```sh
# OpenPGP on Waveshare LCD
cargo build --release -p pico2hsm-firmware --no-default-features --features waveshare_rp2350_lcd_16m,applet-openpgp
```

### SC-HSM + OpenPGP + Ed25519 / X25519 (curve25519)

`applet-openpgp-curve25519` implies `applet-openpgp`; specifying both is
harmless but redundant.

```sh
# OpenPGP + curve25519 on RP2350-Geek with SD card
cargo build --release -p pico2hsm-firmware --no-default-features \
  --features rp2350_geek_sdcard,applet-openpgp-curve25519

# OpenPGP + curve25519 on Waveshare LCD
cargo build --release -p pico2hsm-firmware --no-default-features \
  --features waveshare_rp2350_lcd_16m,applet-openpgp-curve25519
```

### SC-HSM + PIV + OpenPGP (all three applets)

```sh
# All three applets + Ed25519/X25519 — Waveshare LCD
cargo build --release -p pico2hsm-firmware --no-default-features \
  --features waveshare_rp2350_lcd_16m,applet-piv,applet-openpgp,applet-openpgp-curve25519

# All three applets + Ed25519/X25519 — RP2350-Geek with SD card
cargo build --release -p pico2hsm-firmware --no-default-features \
  --features rp2350_geek_sdcard,applet-piv,applet-openpgp,applet-openpgp-curve25519
```

### With RSA support

RSA support is feature-gated (`rsa`). It adds ~115 KB of flash and ~57 KB of
RAM (the 48 KB RSA heap and the key pool's generator state). It can be
combined with any board and applet combination:

```sh
# SC-HSM + RSA on RP2350-Geek (no SD)
cargo build --release -p pico2hsm-firmware --no-default-features --features rp2350_geek_16m,rsa

# All features on Waveshare LCD
cargo build --release -p pico2hsm-firmware --no-default-features \
  --features waveshare_rp2350_lcd_16m,rsa,applet-piv,applet-openpgp,applet-openpgp-curve25519
```

---

## Flash / RAM budget

Measured 2026-10-15 (workspace version 1.0.1, Storage V2 phase 6) from
release builds with `arm-none-eabi-size -A`:

- **Flash** = `.boot2` + `.vector_table` + `.text` + `.rodata` + `.data`
  (what goes into the firmware slot).
- **Static RAM** = `.data` + `.bss` + `.uninit`, of 520 KB SRAM. Core0's
  stack is what is left; the 96 KB core1 stack is in `.bss`.

```sh
cargo build --release -p pico2hsm-firmware --no-default-features \
    --features <board>,rsa,applet-piv,applet-openpgp-curve25519
arm-none-eabi-size -A target/thumbv8m.main-none-eabihf/release/pico2hsm
```

### Per board, all applets + RSA + curve25519

| Board | Flash | Static RAM | SRAM % |
|-------|-------|------------|--------|
| `pico2_4m` | 647 KB | 251 KB | 48% |
| `rp2350_one_4m` | 650 KB | 251 KB | 48% |
| `rp2350_one_16m` | 650 KB | 254 KB | 49% |
| `rp2350_geek_16m` | 679 KB | 246 KB | 47% |
| `rp2350_geek_sdcard` | 684 KB | 246 KB | 47% |
| `waveshare_rp2350_lcd_16m` | 684 KB | 248 KB | 48% |
| `waveshare_rp2350_lcd_sdcard` | 689 KB | 248 KB | 48% |

### Per applet combination, `pico2_4m`

| Applets | Flash | Static RAM |
|---------|-------|------------|
| SC-HSM only | 500 KB | 186 KB |
| SC-HSM + PIV | 515 KB | 194 KB |
| SC-HSM + OpenPGP (NIST) | 500 KB | 186 KB |
| SC-HSM + OpenPGP + curve25519 | 517 KB | 186 KB |
| All three + curve25519 (no RSA) | 532 KB | 194 KB |
| SC-HSM + RSA | 614 KB | 243 KB |
| All three + curve25519 + RSA | 647 KB | 251 KB |

The display boards add ~30–40 KB of flash for the display code; they hold
no framebuffer (a 16-row band buffer of 5.6 KB on the Geek, 7.5 KB on the
Waveshare LCD). A debug build (all applets + RSA) is ~1.3 MB of flash.

Device limits:
- Flash slot: 1,880 KB on 4 MB boards (one slot), 4,088 KB per slot on
  16 MB boards (A/B); see [FLASH_LAYOUT_2_0.md](FLASH_LAYOUT_2_0.md).
- SRAM: 520 KB total; the core1 stack is 96 KB of that.

RAM is the metric to watch. The 96 KB core1 stack dominates, then the RSA
heap (48 KB, `rsa`); applet state structs are small by comparison.

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
cargo check -p pico2hsm-firmware

# Check a specific board
cargo check -p pico2hsm-firmware --no-default-features --features rp2350_geek_sdcard

# Check with applets
cargo check -p pico2hsm-firmware --no-default-features --features pico2_4m,applet-piv,applet-openpgp

# Run host tests (x86_64, no hardware needed); --target is mandatory,
# .cargo/config.toml defaults to thumbv8m
cargo test -p pico2hsm-core --target x86_64-unknown-linux-gnu
cargo test -p pico2hsm-integration-tests --target x86_64-unknown-linux-gnu
cargo test --manifest-path firmware/Cargo.toml --lib --no-default-features \
    --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519 \
    --target x86_64-unknown-linux-gnu
```

Host tests compile the firmware library for x86_64. ARM-only dependencies
(Embassy, defmt) are excluded by the
`[target.'cfg(target_arch = "arm")'.dependencies]` section in
`firmware/Cargo.toml`.
