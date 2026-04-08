# pico2hsm

A production-grade, open-source Hardware Security Module (HSM) firmware written in Rust for the Raspberry Pi RP2350/RP2354 microcontroller. MIT licensed.

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
- RAID-1 mirrored key storage across multiple SPI flash chips
- Write-ahead logging for power-failure safety
- BLAKE2s + CRC32 integrity verification on every read
- PIN-protected key access with configurable retry lockout

## Supported Boards

| Board | Flash | Keystore Capacity | Features |
|-------|-------|-------------------|---------|
| Raspberry Pi Pico 2 | 4MB | 2MB internal | GPIO LED |
| Waveshare RP2350-One 4MB | 4MB | 2MB internal | WS2812B LED |
| Waveshare RP2350-One 16MB | 16MB | 14MB internal | WS2812B LED |
| Waveshare RP2350-Geek 16MB | 16MB | 14MB internal | SPI LCD |
| Waveshare RP2350-Geek + SDCard | 16MB | 14MB + SDCard | SPI LCD, SDCard |
| Waveshare RP2350-LCD-1.47-B | 16MB | 14MB internal | ST7789V3 LCD, WS2812B LED |
| Waveshare RP2350-LCD-1.47-B + SDCard | 16MB | SDCard | ST7789V3 LCD, SDCard |

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
git clone https://github.com/yourorg/pico2hsm
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
- `rp2350_one_16m` — Waveshare RP2350-One 16MB
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
│       ├── storage/            # RAID, WAL, filesystem, integrity
│       ├── security/           # OTP, secure boot, PIN management
│       └── dkek/               # DKEK exchange via Noise_XX
├── tools/hsm-tool/             # Host-side CLI tool (std)
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
