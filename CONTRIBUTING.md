# Contributing to pico2hsm

Thank you for your interest in contributing to pico2hsm. This is an open-source hardware security module firmware for the RP2350, and contributions from experienced engineers and security researchers are welcome.

## Welcome and scope

The areas where contributions are most needed: new board support for RP2350-based boards, PKCS#11 and OpenSC compatibility improvements, hardware integration test coverage (especially PIN lifecycle and security-state isolation tests), documentation of APDU edge cases, and security research. What is out of scope for now: alternative MCU ports (RP2350-only), PKCS#15 applet, and multi-partition keystore -- see `PUNCHOUT.md` for rationale on each deferred item.

## Before you start

- Read `CLAUDE.md` for the full architecture overview: dual-core Embassy async model, APDU dispatch chain, feature flag discipline, board peripheral implementation, and known pitfalls. Note that `CLAUDE.md` doubles as the AI-assistant context file for this repository and the developer architecture guide.
- Review `PUNCHOUT.md` for known issues and pick one to work on. Items are tagged by severity (CRITICAL, HIGH, LOW) and include suggested fixes.
- Security-sensitive changes -- anything under `firmware/src/security/`, `firmware/src/crypto/`, or `firmware/src/protocol/` -- require a maintainer review pass before merge. Please request review from `@mcarey42` explicitly.

## Development environment

### Hardware required

- Any supported RP2350 board (see the board matrix in `README.md`)
- A Debugprobe (CMSIS-DAP) or Picoprobe on the SWD port for RTT log streaming and flashing

### Toolchain setup

```sh
# Rust target for Cortex-M33
rustup target add thumbv8m.main-none-eabihf

# Flashing and debugging tools
cargo install probe-rs-tools picotool elf2uf2-rs

# Host-side smartcard tools (Ubuntu/Debian)
sudo apt install opensc pcscd pkcs11-tools

# Python test dependencies are installed automatically by run_tests.sh
```

## Build discipline

This section is critical. Getting the build flags wrong is the most common contributor mistake.

**Never run `cargo build` directly.** The debug script handles `DEFMT_LOG=trace` (required for defmt log output to survive optimization), the correct target, feature flags, and optional firmware signing.

### Build and flash

```sh
./build-all-debug.sh pico2_4m
```

Replace `pico2_4m` with your board. Valid board arguments:

| Argument | Board |
|----------|-------|
| `pico2_4m` | Raspberry Pi Pico 2 (4MB) |
| `rp2350_one_4m` | Waveshare RP2350-One (4MB) |
| `rp2350_geek_16m` | Waveshare RP2350-Geek (16MB) |
| `rp2350_geek_sdcard` | Waveshare RP2350-Geek (SDCard) |
| `waveshare_rp2350_lcd_16m` | Waveshare RP2350-LCD-1.47-B (16MB) |
| `waveshare_rp2350_lcd_sdcard` | Waveshare RP2350-LCD-1.47-B (SDCard) |

### Feature flag discipline

Board features are mutually exclusive. The `Cargo.toml` defaults include `rp2350_one_4m`, so using bare `--features X` will add to the defaults and cause a compile failure. Always use `--no-default-features`:

```sh
# Correct -- specifies board explicitly
cargo build --release --manifest-path firmware/Cargo.toml \
    --no-default-features --features pico2_4m,applet-piv

# Wrong -- adds pico2_4m on top of the default rp2350_one_4m
cargo build --release --manifest-path firmware/Cargo.toml --features pico2_4m
```

### Host-side unit tests (no hardware needed)

```sh
cargo test -p pico2hsm-core --target x86_64-unknown-linux-gnu
cargo test -p pico2hsm-firmware --lib --no-default-features \
    --features pico2_4m --target x86_64-unknown-linux-gnu
```

## Running the test suite

The hardware integration test suite runs against a physical device over USB CCID. CI cannot run these tests; you must run them locally before submitting any PR that changes firmware behavior.

```sh
# Flash firmware first (blocks on RTT streaming, run in background)
./build-all-debug.sh pico2_4m &
sleep 5

# Run the full hardware integration test suite
./run_tests.sh

# Skip RSA tests during development (keygen takes 2-16 min on hardware)
./run_tests.sh --no-rsa

# Target a specific reader if multiple devices are connected
OPENSC_DEFAULT_READER=1 ./run_tests.sh
```

Run `opensc-tool --list-readers` to see which reader index corresponds to which device.

If `probe-rs` reports "interface is busy (errno 16)", kill the previous session:

```sh
pkill -9 -f "probe-rs"
```

### What CI checks

CI runs on every push and pull request. It verifies:

- Firmware compiles for all seven board targets (release profile)
- `cargo fmt --all -- --check` passes
- `cargo clippy` passes for `pico2hsm-core` (warnings are errors)
- Host-side unit tests pass (`pico2hsm-core` and `pico2hsm-integration-tests`)

CI does not run hardware integration tests. Those are your responsibility.

## Commit style

This repository uses conventional commits. Keep the first line under 72 characters.

| Prefix | Usage |
|--------|-------|
| `feat(component):` | New feature |
| `fix(component):` | Bug fix |
| `docs:` | Documentation only |
| `test:` | Test additions or fixes |
| `refactor:` | No behavior change |
| `release:` | Version bump commits |

Reference PUNCHOUT items by their ID in the commit body when applicable:

```
fix(dkek): verify Sig_T in V2 mutual auth finalize

Implements ECDSA signature verification against enrolled peer public
keys in the V2 Noise finalize handlers.

Closes PUNCHOUT C1
```

## Pull request process

1. Fork and create a branch from `main`.
2. All firmware changes must compile for **all** board targets. CI checks all seven variants.
3. Run `cargo fmt` and `cargo clippy --no-default-features --features pico2_4m` before pushing.
4. If you changed firmware behavior, the hardware integration test suite must pass (`./run_tests.sh`). State this in the PR description.
5. Add or update unit tests in `firmware/src/` for any new `#[cfg(test)]` modules.
6. Update `PUNCHOUT.md` if your PR closes an item.
7. For security-sensitive changes (anything under `firmware/src/security/`, `firmware/src/crypto/`, or `firmware/src/protocol/`), request review from `@mcarey42` explicitly.

## What we are looking for

- **New board support** -- other RP2350-based boards with SPI flash, LEDs, or displays
- **OpenSC / PKCS#11 compatibility** -- edge cases in SELECT, GET DATA, or other commands that differ from real hardware tokens
- **Documentation** -- APDU edge cases, setup guides, troubleshooting
- **Hardware integration tests** -- especially the gaps identified in PUNCHOUT C4 (PIN lifecycle) and C5 (security-state isolation across SELECT AID)
- **Performance improvements** -- ECC operations on Cortex-M33, flash I/O, display rendering

## What we are not looking for (yet)

- Alternative MCU ports (RP2350-only for now)
- Multi-partition keystore (deferred -- see PUNCHOUT)
- PKCS#15 applet (deferred -- see PUNCHOUT)
- Windows or macOS native build system changes (cross-compilation from Linux is the supported workflow)

## Questions?

Open a GitHub Discussion or file an issue. For security vulnerabilities, see `SECURITY.md`.
