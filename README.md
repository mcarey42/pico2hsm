# pico2hsm

[![Build](https://github.com/mcarey42/pico2hsm/actions/workflows/build.yml/badge.svg)](https://github.com/mcarey42/pico2hsm/actions/workflows/build.yml)
[![Release](https://github.com/mcarey42/pico2hsm/actions/workflows/release.yml/badge.svg)](https://github.com/mcarey42/pico2hsm/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust Edition](https://img.shields.io/badge/rust-2021-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2021/)

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
- A journaled keystore (Storage V2): power-cut safe, journal and index MACed,
  every object sealed with its header as AAD, and a rollback anchor on
  internal flash
- PIN-protected key access with retry counters spent on flash before each comparison

## Supported Boards

pico2hsm runs on off-the-shelf RP2350 boards only, used as sold. There is
no custom board and no added hardware: no external flash chips and no
RAID. SC-HSM key references are one byte, for SmartCard-HSM / OpenSC
compatibility. That bounds what one device can usefully hold, so extra or
mirrored flash would buy nothing.

| Board | Flash | Keystore | SC-HSM keys | Display / LED | Feature flag |
|-------|-------|----------|-------------|---------------|--------------|
| Raspberry Pi Pico 2 | 4MB | 2,044 KB internal | 128 | GPIO LED | `pico2_4m` |
| Waveshare RP2350-One | 4MB | 2,044 KB internal | 128 | WS2812B LED | `rp2350_one_4m` |
| Waveshare RP2350-One, 16 MB chip fitted | 16MB | ~7.8 MB internal | 251 | WS2812B LED | `rp2350_one_16m` |
| Waveshare RP2350-Geek | 16MB | ~7.8 MB internal | 251 | ST7789 LCD | `rp2350_geek_16m` |
| Waveshare RP2350-Geek, SD-card build | 16MB | microSD card | 251 | ST7789 LCD | `rp2350_geek_sdcard` |
| Waveshare RP2350-LCD-1.47-B | 16MB | ~7.8 MB internal | 251 | ST7789V3 LCD, WS2812B LED | `waveshare_rp2350_lcd_16m` |
| Waveshare RP2350-LCD-1.47-B, SD-card build | 16MB | microSD card | 251 | ST7789V3 LCD, WS2812B LED | `waveshare_rp2350_lcd_sdcard` |

Every board boots through a bootrom partition table. The 4 MB boards have
one firmware slot; the 16 MB boards have A/B slots with try-before-you-buy.
The store regions (binding block, retry-counter log, RSA key pool,
keystore) are partitions closed to BOOTSEL, and the binding, the counters
and the RSA pool stay on internal flash on the SD-card builds too. See
[docs/FLASH_LAYOUT_2_0.md](docs/FLASH_LAYOUT_2_0.md).

### Why SD-card builds

An SD-card board can be enrolled in a domain and shipped to a remote party
with the card sent separately. The card alone is useless: its objects are
encrypted under keys derived from the device's OTP-based storage master
key. The device alone holds no user keys. When the card goes back in, the
device verifies it (store ID, MACs, a rollback anchor on internal flash)
and resumes domain sync. The card checks are implemented (Storage V2,
[docs/STORAGE_V2.md](docs/STORAGE_V2.md) §8, §11); domains and sync are
designed in [docs/CLUSTER_PLAN_V3.md](docs/CLUSTER_PLAN_V3.md).

### 2.0.0 (upcoming): breaking

The next release series is 2.0.0 (`main` already carries it; no 2.0.0
tag yet). It brings a new flash layout with a partition table on every
board ([docs/FLASH_LAYOUT_2_0.md](docs/FLASH_LAYOUT_2_0.md)) and a
journaled keystore format ([docs/STORAGE_V2.md](docs/STORAGE_V2.md)), and
removes the unused RAID-1 / WAL / multi-chip storage code. There is no
migration from 1.x: **1.x keys do not carry over.**

Upgrading a 1.x device:

- **Install the partition table first.** 2.0 firmware runs from a slot
  of the bootrom partition table and a release build refuses its store
  without the table it was built for. Install the board's table UF2
  (`pico2hsm-<board>-pt-dev.uf2`, or `-pt-prod.uf2` for production),
  then the firmware; `build-all-debug.sh` writes both over SWD. See
  [docs/FLASH_LAYOUT_2_0.md](docs/FLASH_LAYOUT_2_0.md) §4.
- On 4 MB boards the keystore partition starts one sector later than
  the 1.x keystore did, and on 16 MB boards the store moved to 8 MB.

What happens on the first boot of 2.0 on a 1.x device:

- The PIN/PUK retry counters, the RSA key pool and the domain counter
  carry over on 4 MB boards (the counter log is moved to its new place
  automatically); on 16 MB boards the store regions moved, so they start
  fresh.
- Where the 1.x keystore data is still in the keystore region (4 MB
  boards, SD cards), the keystore is **refused**, not erased: the device reports that
  it needs **FORMAT STORE** and every key operation fails until then.
  Boards with a display show **E12 FORMAT STORE NEEDED** until it is done.
  FORMAT STORE (`80 54 4E 00 0F "FORMAT-STORE-V2"` on the SC-HSM applet)
  creates the new, empty store; on a device whose store is not a 2.0 one
  it needs no PIN.  Afterwards initialise the applets as on a new device.
- A device whose keystore region is blank formats itself: a device that
  was never used, and a 16 MB QMI board, whose 2.0 keystore at 8 MB has
  never been written (its 1.x keystore lay in what is now firmware slot A).

If a 2.0 device later refuses its keystore (a swapped or damaged SD card,
lost writes, OTP provisioning), see
[docs/KEYSTORE_RECOVERY.md](docs/KEYSTORE_RECOVERY.md): STORE STATUS,
OPEN DEGRADED, ACCEPT STORE and FORMAT STORE, and what each one costs.

The default feature flag is `rp2350_one_4m` for historical reasons; the primary debug/test target is `pico2_4m` (Raspberry Pi Pico 2 stock board) as documented in `CLAUDE.md`. See `docs/BUILD_CONFIGURATIONS.md` for all flag combinations.

## Build Requirements

- Rust stable (1.75+): `rustup target add thumbv8m.main-none-eabihf`
- `picotool` ≥ 2.1 for UF2 generation, partition tables and firmware signing (CI uses 2.2.0; signing needs a build with `seal`, i.e. mbedtls)
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

# Flash via BOOTSEL (hold the button, plug USB). Once per board, the
# partition table (4 MB boards: pt_4m.json, 16 MB boards: pt_16m.json):
picotool partition create boards/pt_4m.json /tmp/pt_4m.uf2
picotool load /tmp/pt_4m.uf2
picotool reboot -u
# then the firmware, into slot 0:
picotool load -p 0 -x dist/pico2hsm-rp2350_one_4m.uf2
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
- `rp2350_one_16m` — Waveshare RP2350-One with a 16MB flash chip fitted (implies the One board code)
- `rp2350_geek_16m` — Waveshare RP2350-Geek 16MB
- `rp2350_geek_sdcard` — Waveshare RP2350-Geek with SDCard
- `waveshare_rp2350_lcd_16m` — Waveshare RP2350-LCD-1.47-B 16MB
- `waveshare_rp2350_lcd_sdcard` — Waveshare RP2350-LCD-1.47-B with SDCard
- `pico2_4m` — Raspberry Pi Pico 2 (stock RP2350A, GPIO 25 LED, 4MB flash)

### Optional capabilities
- `rsa` — Enable RSA-2048/3072/4096 support and the RSA key pool (adds ~115 KB flash, ~57 KB RAM)
- `applet-piv` — PIV applet (NIST SP 800-73-4); slots 9A/9C/9D/9E
- `applet-openpgp` — OpenPGP Card 3.4 applet; NIST ECC (P-256/384/521)
- `applet-openpgp-curve25519` — Add Ed25519/X25519 to OpenPGP (implies `applet-openpgp`)
- `debug` — Debug mode: debug APDUs (INS `0xFE`: test hooks, BOOTSEL reboot, boot info), skips the production-mode boot checks (NEVER use in production)
- `insecure-dev-keystore` — let a release build use the fixed, public development storage key on unprovisioned OTP (NEVER use in production)

## Project Structure

```
pico2hsm/
├── Cargo.toml                  # Workspace root
├── .cargo/config.toml          # Build target and runner config
├── boards/                     # Linker scripts and partition tables (pt_*.json)
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
│       ├── storage/            # Storage V2 store, binding, flash map, flash/SD drivers, retry counters
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
- Secure boot verifies the firmware signature before execution once the device is provisioned ([docs/PROVISIONING.md](docs/PROVISIONING.md)); debug access is then left open, key-protected or disabled for good, as the owner chooses
- The store partitions are closed to BOOTSEL: picotool and UF2 cannot read, write or erase them

## License

MIT License. See [LICENSE](LICENSE) for details.
