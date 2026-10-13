# pico2hsm

[![Build](https://github.com/mcarey42/pico2hsm/actions/workflows/build.yml/badge.svg)](https://github.com/mcarey42/pico2hsm/actions/workflows/build.yml)
[![Release](https://github.com/mcarey42/pico2hsm/actions/workflows/release.yml/badge.svg)](https://github.com/mcarey42/pico2hsm/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust Edition](https://img.shields.io/badge/rust-2024-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/)

A production-grade, open-source Hardware Security Module (HSM) firmware written in Rust for the Raspberry Pi RP2350 microcontroller. MIT licensed.

## Overview

pico2hsm implements multiple smartcard applet protocols over USB CCID, with PKCS#15 file structures. It is compatible with OpenSC, pkcs11-tool, GnuPG, and any PKCS#11-aware application that supports smart cards.

### Supported Applets

| Applet | Feature Flag | Standard | Status |
|--------|-------------|----------|--------|
| SmartCard-HSM 2 (SC-HSM) | *(always on)* | OpenSC sc-hsm driver | Hardware-validated |
| PIV | `applet-piv` | NIST SP 800-73-4 | Hardware-validated |
| OpenPGP Card 3.4 | `applet-openpgp` | OpenPGP Card 3.4 | Hardware-validated |
| OpenPGP + Ed25519/X25519 | `applet-openpgp-curve25519` | OpenPGP Card 3.4 | Implemented |

All applets share one flash keystore with per-applet key namespace isolation. Applets are selected at compile time via feature flags and at runtime via `SELECT AID`. Multiple applets can be active in the same firmware build.

The firmware provides hardware-backed key storage with:
- On-chip TRNG for key generation (ChaCha20 keystream seeded from hardware TRNG)
- Device-tied AES-256-GCM storage encryption (key derived from OTP fuses)
- Keystore on the board's internal flash, or on its microSD card (SD-card builds)
- A/B directory sectors for power-cut safety (a journaled keystore replaces them in 2.0)
- BLAKE2s + CRC32 integrity verification on every read
- PIN-protected key access with configurable retry lockout

## Supported Boards

pico2hsm runs on off-the-shelf RP2350 boards only, used as sold. There is
no custom board and no added hardware: no external flash chips and no
RAID. SC-HSM key references are one byte, for SmartCard-HSM / OpenSC
compatibility. That bounds what one device can usefully hold, so extra or
mirrored flash would buy nothing.

| Board | Flash | Keystore | Display / LED | Feature flag |
|-------|-------|----------|---------------|--------------|
| Raspberry Pi Pico 2 | 4MB | 2MB internal | GPIO LED | `pico2_4m` |
| Waveshare RP2350-One | 4MB | 2MB internal | WS2812B LED | `rp2350_one_4m` |
| Waveshare RP2350-Geek | 16MB | 2MB internal | ST7789 LCD | `rp2350_geek_16m` |
| Waveshare RP2350-Geek, SD-card build | 16MB | microSD card | ST7789 LCD | `rp2350_geek_sdcard` |
| Waveshare RP2350-LCD-1.47-B | 16MB | 2MB internal | ST7789V3 LCD, WS2812B LED | `waveshare_rp2350_lcd_16m` |
| Waveshare RP2350-LCD-1.47-B, SD-card build | 16MB | microSD card | ST7789V3 LCD, WS2812B LED | `waveshare_rp2350_lcd_sdcard` |

The 1.x keystore uses 2MB of internal flash on every board, 16MB boards
included. The PIN/PUK retry counters always stay on internal flash.

### Why SD-card builds

An SD-card board can be enrolled in a domain and shipped to a remote party
with the card sent separately. The card alone is useless: its objects are
encrypted under keys derived from the device's OTP-based storage master
key. The device alone holds no user keys. When the card goes back in, the
device verifies it (store ID, MACs, a rollback anchor on internal flash)
and resumes domain sync. The card checks are **planned for 2.0**
([docs/STORAGE_V2.md](docs/STORAGE_V2.md) §8, §11); domains and sync are
designed in [docs/CLUSTER_PLAN_V3.md](docs/CLUSTER_PLAN_V3.md).

### 2.0.0 (upcoming): breaking

The next release series is 2.0.0. It brings a new flash layout and a
journaled keystore format ([docs/STORAGE_V2.md](docs/STORAGE_V2.md)), and
removes the unused RAID-1 / WAL / multi-chip storage code. There is no
migration from 1.x: **1.x keys do not carry over.**

What happens on the first boot of 2.0 on a 1.x device:

- The PIN/PUK retry counters, the RSA key pool and the domain counter
  carry over (the counter log is moved to its new place automatically).
- The keystore itself is **refused**, not erased: the device reports that
  it needs **FORMAT STORE** and every key operation fails until then.
  Boards with a display show **E12 FORMAT STORE NEEDED** until it is done.
  FORMAT STORE (`80 54 4E 00 0F "FORMAT-STORE-V2"` on the SC-HSM applet)
  creates the new, empty store; on a device whose store is not a 2.0 one
  it needs no PIN.  Afterwards initialise the applets as on a new device.
- A device that was never used (blank keystore) formats itself.

The default feature flag is `rp2350_one_4m` for historical reasons; the primary debug/test target is `pico2_4m` (Raspberry Pi Pico 2 stock board) as documented in `CLAUDE.md`. See `docs/BUILD_CONFIGURATIONS.md` for all flag combinations.

## Build Requirements

- Rust stable (1.75+): `rustup target add thumbv8m.main-none-eabihf`
- `picotool` ≥ 2.1 for UF2 generation and firmware signing
- `probe-rs` for SWD flashing: `cargo install probe-rs-tools`

**New to embedded development?** See [QUICKSTART.md](QUICKSTART.md) for a
step-by-step guide written for first-time builders.

## Build Instructions

The default build includes all three applets (SC-HSM, PIV, OpenPGP with
Ed25519/X25519) and RSA support. Generate your signing key first, then build:

```bash
git clone https://github.com/mcarey42/pico2hsm
cd pico2hsm
rustup target add thumbv8m.main-none-eabihf

# Generate firmware signing key (once — keep it safe)
./generate_firmware_signing_keys.sh

# Build all board variants, sign outputs, generate UF2 files
./build-all.sh

# Flash via BOOTSEL: hold button, plug USB, copy the right UF2:
cp dist/pico2hsm-rp2350_one_4m.uf2 /media/$USER/RPI-RP2/
```

To build for a specific board manually (always use `--no-default-features`
because board flags are mutually exclusive):

```bash
cargo build --release \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features rp2350_one_4m,rsa,applet-piv,applet-openpgp-curve25519
```

See [BUILDING.md](BUILDING.md) for the full reference.

## Feature Flags

### Board selection (mutually exclusive — always use `--no-default-features`)
- `rp2350_one_4m` — Waveshare RP2350-One 4MB (default)
- `rp2350_geek_16m` — Waveshare RP2350-Geek 16MB
- `rp2350_geek_sdcard` — Waveshare RP2350-Geek with SDCard
- `waveshare_rp2350_lcd_16m` — Waveshare RP2350-LCD-1.47-B 16MB
- `waveshare_rp2350_lcd_sdcard` — Waveshare RP2350-LCD-1.47-B with SDCard
- `pico2_4m` — Raspberry Pi Pico 2 (stock RP2350A, GPIO 25 LED, 4MB flash)

### Optional capabilities
- `rsa` — Enable RSA-2048/4096 support (adds ~1MB to binary)
- `applet-piv` — PIV applet (NIST SP 800-73-4); slots 9A/9C/9D/9E
- `applet-openpgp` — OpenPGP Card 3.4 applet; NIST ECC (P-256/384/521)
- `applet-openpgp-curve25519` — Add Ed25519/X25519 to OpenPGP (implies `applet-openpgp`)
- `debug` — Debug mode: enable memory dump APDUs, relax secure boot enforcement (NEVER use in production)

## Project Structure

```
pico2hsm/
├── Cargo.toml                  # Workspace root
├── .cargo/config.toml          # Build target and runner config
├── boards/                     # Linker scripts (one per board variant)
├── pico2hsm-core/              # Shared no_std types and traits
│   └── src/
│       ├── apdu.rs             # APDU types and status words
│       ├── error.rs            # Error enums
│       ├── flash.rs            # FlashChip trait
│       ├── key.rs              # Key object types (KeyId, AppletId)
│       ├── protocol.rs         # HsmProtocol trait
│       └── storage.rs          # Storage layout constants
├── firmware/                   # RP2350 no_std firmware
│   └── src/
│       ├── board/              # Board-specific GPIO/LED/LCD
│       ├── transport/          # USB CCID + T=1 protocol
│       ├── apdu/               # APDU dispatcher (multi-applet routing)
│       ├── protocol/
│       │   ├── sc_hsm/         # SC-HSM command implementations (always on)
│       │   ├── piv/            # PIV applet (applet-piv feature)
│       │   └── openpgp/        # OpenPGP Card 3.4 (applet-openpgp feature)
│       ├── crypto/             # ECDSA, ECDH, AES, KDFs, RNG
│       ├── storage/            # Keystore, flash/SD drivers, integrity, retry counters
│       ├── security/           # OTP, secure boot, PIN management
│       └── dkek/               # DKEK exchange via Noise_XX
├── tests/hw/                   # Hardware integration tests (Python/pytest)
└── tests/integration/          # Unit/integration tests (std)
```

## Security Model

See [ARCHITECTURE.md](ARCHITECTURE.md) for full design documentation.

Key security properties:
- Private keys never leave the device in plaintext
- All key material is encrypted under a device-tied Storage Master Key derived from OTP fuses
- HSM-to-HSM backup uses DKEK wrap (AES-256 + CMAC), not plaintext export
- PIN retry counter prevents brute force; lockout is enforced in constant time
- JTAG is permanently disabled after provisioning
- Secure boot verifies firmware signature before execution

## License

MIT License. See [LICENSE](LICENSE) for details.
