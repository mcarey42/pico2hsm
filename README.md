# pico2hsm

A production-grade, open-source Hardware Security Module (HSM) firmware written in Rust for the Raspberry Pi RP2350/RP2354 microcontroller. MIT licensed.

## Overview

pico2hsm implements the SmartCard-HSM 2 (SC-HSM) APDU command set over USB CCID, with PKCS#15 file structures. It is compatible with OpenSC, pkcs11-tool, and any PKCS#11-aware application that supports smart cards.

The firmware provides hardware-backed key storage with:
- On-chip TRNG for key generation
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
| Waveshare RP2350-Geek + dual SDCard | 16MB | 14MB + 2× SDCard | SPI LCD, RAID SDCard |
| Waveshare RP2350-LCD-1.47-B | 16MB | 14MB internal | ST7789V3 LCD, WS2812B LED |
| Waveshare RP2350-LCD-1.47-B + SDCard | 16MB | 14MB + 2× SDCard | ST7789V3 LCD, RAID SDCard |
| RP2354 (embedded flash) | Built-in | External SPI only | Forward-looking |

## Build Requirements

- Rust stable (1.75+)
- `thumbv8m.main-none-eabihf` target: `rustup target add thumbv8m.main-none-eabihf`
- `probe-rs` for flashing: `cargo install probe-rs-tools`

## Build Instructions

```bash
# Clone the repository
git clone https://github.com/example/pico2hsm
cd pico2hsm

# Add the embedded target
rustup target add thumbv8m.main-none-eabihf

# Build for Waveshare RP2350-One 4MB (default)
cargo build --release -p pico2hsm-firmware

# Build for a specific board
cargo build --release -p pico2hsm-firmware --no-default-features --features rp2350_geek_sdcard

# Build with RSA support (adds ~1MB to binary)
cargo build --release -p pico2hsm-firmware --features rsa

# Flash to device
cargo run --release -p pico2hsm-firmware

# Run host tests
cargo test -p pico2hsm-core
cargo test -p pico2hsm-integration-tests
```

## Feature Flags

### Board selection (mutually exclusive — always use `--no-default-features`)
- `rp2350_one_4m` — Waveshare RP2350-One 4MB (default)
- `rp2350_one_16m` — Waveshare RP2350-One 16MB
- `rp2350_geek_16m` — Waveshare RP2350-Geek 16MB
- `rp2350_geek_sdcard` — Waveshare RP2350-Geek with SDCard
- `rp2350_geek_sdcard_dual` — Waveshare RP2350-Geek with dual SDCard
- `waveshare_rp2350_lcd_16m` — Waveshare RP2350-LCD-1.47-B 16MB
- `waveshare_rp2350_lcd_sdcard_dual` — Waveshare RP2350-LCD-1.47-B with dual SDCard
- `rp2354_embedded` — RP2354 with embedded flash
- `pico2_4m` — Raspberry Pi Pico 2 (stock RP2350A, GPIO 25 LED, 4MB flash)

### Optional capabilities
- `rsa` — Enable RSA-2048/4096 support (adds ~1MB to binary)
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
│       ├── key.rs              # Key object types
│       ├── protocol.rs         # HsmProtocol trait
│       └── storage.rs          # Storage layout constants
├── firmware/                   # RP2350 no_std firmware
│   └── src/
│       ├── board/              # Board-specific GPIO/LED/LCD
│       ├── transport/          # USB CCID + T=1 protocol
│       ├── apdu/               # APDU dispatcher
│       ├── protocol/
│       │   ├── sc_hsm/         # SC-HSM command implementations
│       │   ├── piv/            # PIV stub
│       │   └── openpgp/        # OpenPGP stub
│       ├── crypto/             # ECDSA, ECDH, AES, KDFs, RNG
│       ├── storage/            # RAID, WAL, filesystem, integrity
│       ├── security/           # OTP, secure boot, PIN management
│       └── dkek/               # DKEK exchange via Noise_XX
├── tools/hsm-tool/             # Host-side CLI tool (std)
└── tests/integration/          # Integration tests (std)
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
