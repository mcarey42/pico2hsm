# Board: Raspberry Pi Pico 2 with SD Card (`pico2_4m_sdcard`)

This variant is a stock **Raspberry Pi Pico 2** (RP2350A, 4 MB QSPI flash) with
an external microSD card module wired to SPI1.  The SD card replaces internal
QMI flash as the sole keystore.  No LCD or WS2812B LED is driven; status is
shown on the onboard GPIO25 LED only.

The SPI1 pin assignment is identical to the Waveshare RP2350-LCD-1.47-B
built-in SD slot, so the same wiring guide applies.

---

## GPIO pin assignments

### Status LED

| Signal | GPIO | Note                   |
|--------|------|------------------------|
| LED    |  25  | Onboard GPIO LED       |

### SPI1 — SD card bus

| Signal | GPIO | RP2350 peripheral | Direction | Active state |
|--------|------|-------------------|-----------|--------------|
| SCK    |  10  | SPI1 CLK          | Output    | —            |
| MOSI   |  11  | SPI1 TX           | Output    | —            |
| MISO   |  12  | SPI1 RX           | Input     | —            |
| CS     |  15  | GPIO (software)   | Output    | Low          |

SPI1 operates at **400 kHz** in SPI mode 0 (CPOL=0, CPHA=0).

> **Why 400 kHz?** The SD specification requires ≤400 kHz for card identification.
> `embedded-sdmmc` does not change the bus speed after initialization, so the
> host must supply the correct clock from the start.  On PCB traces 25 MHz works
> (as on the Waveshare board), but jumper wires require the spec-compliant speed.

### SPI0 — unused (not connected)

SPI0 (SCK=GPIO18, MOSI=GPIO19, MISO=GPIO20) is not initialised in this
variant.  Those header pins are free for other purposes.

---

## Wiring diagram

```
Pico 2 header          SD card module
─────────────          ──────────────
GPIO10 (SPI1 SCK)  →   CLK
GPIO11 (SPI1 MOSI) →   MOSI / DI
GPIO12 (SPI1 MISO) ←   MISO / DO
GPIO15             →   CS (active low)
3V3 (pin 36)       →   VCC  (3.3 V)
GND                →   GND
```

> **Note**: Most breakout SD card modules include a 3.3 V LDO and level
> shifters, so 3.3 V power and direct GPIO connections (no pull-ups needed)
> are correct for the Pico 2.

---

## Storage behaviour

- **Sole keystore**: The SD card is the only storage medium.  Keys do not
  survive SD card removal.
- **Init failure**: If `SdCardFlash::new()` fails (no card, wrong format),
  the firmware panics with `"SD card init failed"`.  Insert a card and
  reflash.
- **Raw block I/O**: The keystore uses raw 512-byte sectors directly via
  `embedded-sdmmc`.  No FAT32 filesystem is required or created.

---

## `pico2_4m_sdcard_hybrid` — Flash+SD RAID-1 variant

The `pico2_4m_sdcard_hybrid` feature activates a **hybrid RAID-1 keystore**: every
write goes to both the internal RP2350 QMI flash (primary) and the SD card on SPI1
(secondary). Reads prefer the primary flash.

| Aspect               | `pico2_4m_sdcard_hybrid`                    |
|----------------------|---------------------------------------------|
| Primary keystore     | Internal QMI flash (always authoritative)   |
| Secondary keystore   | SD card on SPI1 (mirrored copy)             |
| SD failure behaviour | Degraded mode — HSM stays operational via flash |
| SD recovery          | Automatic resync on card reinsertion        |
| Pin assignment       | Identical to `pico2_4m_sdcard` (SPI1 SCI=GPIO10/11/12, CS=GPIO15) |

**When to use**: Use `pico2_4m_sdcard_hybrid` when you want both the portability of
an SD card keystore and the reliability of internal flash as a fallback.

```sh
./build-all-debug.sh pico2_4m_sdcard_hybrid

cargo build --release --no-default-features --features pico2_4m_sdcard_hybrid
cargo build --release --no-default-features \
    --features pico2_4m_sdcard_hybrid,rsa,applet-piv,applet-openpgp-curve25519
```

---

## Feature flag

`pico2_4m_sdcard` — activates `run_pico2_sdcard_board()` in `main.rs`.

This feature is mutually exclusive with all other board features.  Always
pass `--no-default-features` when selecting it:

```sh
cargo build --release --no-default-features --features pico2_4m_sdcard
```

---

## Build commands

```sh
# Debug build + flash via probe-rs (recommended for development):
./build-all-debug.sh pico2_4m_sdcard

# Release build — SC-HSM only:
cargo build --release --no-default-features --features pico2_4m_sdcard

# Release build — all applets + RSA:
cargo build --release --no-default-features \
    --features pico2_4m_sdcard,rsa,applet-piv,applet-openpgp-curve25519
```

---

## Differences from `pico2_4m`

| Aspect           | `pico2_4m`                     | `pico2_4m_sdcard`              | `pico2_4m_sdcard_hybrid`             |
|------------------|--------------------------------|--------------------------------|--------------------------------------|
| Keystore         | Internal RP2350 QMI flash      | External SD card on SPI1       | QMI flash (primary) + SD card (mirror) |
| SPI1             | Idle (no device attached)      | SD card bus at 400 kHz         | SD card bus at 400 kHz               |
| SD card required | No                             | Yes — firmware panics without  | No — degrades gracefully without     |
| LED              | GPIO25 (same)                  | GPIO25 (same)                  | GPIO25 (same)                        |
| OTP / secure boot | Supported (same)              | Supported (same)               | Supported (same)                     |
