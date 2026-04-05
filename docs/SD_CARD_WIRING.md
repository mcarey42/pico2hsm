# SD Card Wiring Guide

This document covers how to wire SPI-mode SD card modules to each supported
board variant and which feature flag to enable for each configuration.

---

## SD Card Module Specifications

A standard SPI SD card breakout module exposes six signals:

| Module pin | Signal  | Description                        |
|------------|---------|------------------------------------|
| VCC        | Power   | 3.3 V supply (some modules accept 5 V via on-board regulator) |
| GND        | Ground  | Common ground                      |
| MISO       | SPI RX  | Card → RP2350 data                 |
| MOSI       | SPI TX  | RP2350 → card data                 |
| SCK        | SPI CLK | SPI clock from RP2350              |
| CS         | CS      | Active-low chip select (one per card) |

**Voltage**: The RP2350 is a 3.3 V device. Use modules that operate at 3.3 V
logic directly — no level shifter is required. Many cheap modules include a
3.3 V LDO regulator and level shifters for 5 V Arduino use; these work fine
when powered from the RP2350's 3V3 pin.

**SPI mode**: SD cards accept SPI mode 0 (CPOL=0, CPHA=0) or mode 3 (CPOL=1,
CPHA=1). `embedded-sdmmc` uses **mode 0** by default.

**Initial clock speed**: SD cards must be initialised at ≤ 400 kHz, then
switched to full speed (up to 25 MHz) after the card responds to CMD0. The
`embedded-sdmmc` `SdCard` type handles this sequence automatically; the SPI
bus speed configured in the board init is used for post-init transfers.

---

## Waveshare RP2350-One — External SD Card Wiring

The RP2350-One has **no built-in SD card slot**. SD cards are connected via
external SPI modules using free GPIO pins.

### SPI bus allocation on RP2350-One

| SPI bus | SCK | MOSI | MISO | Existing CS uses               |
|---------|-----|------|------|-------------------------------|
| SPI0    | 18  | 19   | 20   | GPIO 17, 21, 22, 26 (flash)   |
| SPI1    | 10  | 11   | 12   | GPIO 9, 13, 14, 15 (flash)    |

The flash keystore uses **all** CS pins on both buses for up to 8 flash chips.
External SD card CS pins must therefore come from the remaining free GPIOs.

For a single SD card (`rp2350_one_sdcard`), SPI1 is used with **GPIO9** as CS.
This requires that SPI1 flash chip slot 0 (GPIO9) is not populated — the CS
line is shared, so only one device (flash chip or SD card) may be connected
per CS pin.

For dual SD cards (`rp2350_one_sdcard_dual`), a second CS on **GPIO13** is
added (SPI1 slot 1).

> **Hardware note**: If you are using fewer than four flash chips on SPI1,
> the unused CS pins (GPIO9, GPIO13, GPIO14, GPIO15) are available for SD
> card use. A typical pico2hsm deployment uses 1–2 flash chips per bus, so
> GPIO9 and GPIO13 are usually free.

### Wiring table — `rp2350_one_sdcard`

| SD card signal | RP2350-One GPIO | Feature flag         |
|----------------|-----------------|----------------------|
| SCK            | GPIO10          | rp2350_one_sdcard    |
| MOSI           | GPIO11          | rp2350_one_sdcard    |
| MISO           | GPIO12          | rp2350_one_sdcard    |
| CS (card 0)    | GPIO9           | rp2350_one_sdcard    |
| CS (card 1)    | GPIO13          | rp2350_one_sdcard_dual |

Connect VCC to the RP2350-One's **3V3** pin and GND to any **GND** pin.

### Build commands

```sh
# Single SD card
cargo build --release --no-default-features --features rp2350_one_sdcard

# Dual SD cards
cargo build --release --no-default-features --features rp2350_one_sdcard_dual
```

---

## Waveshare RP2350-Geek — SD Card Wiring

The RP2350-Geek has a **built-in microSD slot** connected to SPI1. The SD card
interface shares the SPI1 bus with the RAID mirror flash chips.

### Pin assignments

| SD card signal | RP2350-Geek GPIO | Notes                    |
|----------------|------------------|--------------------------|
| SCK            | GPIO10           | SPI1 clock               |
| MOSI           | GPIO11           | SPI1 TX                  |
| MISO           | GPIO12           | SPI1 RX                  |
| CS (card 0)    | GPIO5            | Built-in slot CS         |
| CS (card 1)    | GPIO4            | Second slot (dual only)  |

### Feature flags

| Feature flag              | Description                              |
|---------------------------|------------------------------------------|
| `rp2350_geek_16m`         | No SD card — flash keystore only         |
| `rp2350_geek_sdcard`      | Built-in SD slot (GPIO5 CS)              |
| `rp2350_geek_sdcard_dual` | Built-in + second SD slot (GPIO4 CS)     |

The second SD slot uses **GPIO4**, which is the SPI1 MISO pin on the RP2350-One
but is **not** a SPI1 pin on the Geek — it is wired solely as a GPIO output CS
line on this board.

### Build commands

```sh
# No SD card
cargo build --release --no-default-features --features rp2350_geek_16m

# Built-in SD slot
cargo build --release --no-default-features --features rp2350_geek_sdcard

# Dual SD slots
cargo build --release --no-default-features --features rp2350_geek_sdcard_dual
```

---

## Waveshare RP2350-LCD-1.47-B — SD Card Wiring

The RP2350-LCD-1.47-B has a **built-in microSD slot** on SPI1. The LCD uses
SPI0. A second external SD card can be added using an unused SPI1 CS pin.

### Built-in SD card (SPI1)

| SD card signal | GPIO | Notes              |
|----------------|------|--------------------|
| SCK            | 10   | SPI1 clock         |
| MOSI           | 11   | SPI1 TX            |
| MISO           | 12   | SPI1 RX            |
| CS             | 15   | Built-in slot CS   |

### Second SD card (`waveshare_rp2350_lcd_sdcard_dual`)

The SPI1 bus (GPIO10/11/12) is shared. Only the CS line differs for the
second card. **GPIO13** is recommended as the CS for the external module —
it is a valid SPI1 CS pin with no other assignment on this board.

| SD card signal | GPIO | Notes                         |
|----------------|------|-------------------------------|
| SCK            | 10   | Shared SPI1 clock             |
| MOSI           | 11   | Shared SPI1 TX                |
| MISO           | 12   | Shared SPI1 RX                |
| CS (card 0)    | 15   | Built-in slot (existing)      |
| CS (card 1)    | 13   | External module CS            |

Connect the external module's VCC to **3V3** and GND to **GND**.

### Feature flags

| Feature flag                         | Description                              |
|--------------------------------------|------------------------------------------|
| `waveshare_rp2350_lcd_16m`           | Built-in SD slot only (GPIO15 CS)        |
| `waveshare_rp2350_lcd_sdcard_dual`   | Built-in + external second SD (GPIO13 CS)|

### Build commands

```sh
# Built-in SD slot only
cargo build --release --no-default-features --features waveshare_rp2350_lcd_16m

# Dual SD slots (built-in + external)
cargo build --release --no-default-features --features waveshare_rp2350_lcd_sdcard_dual
```

---

## embedded-sdmmc Integration Notes

`embedded-sdmmc` 0.9 is already a dependency in `firmware/Cargo.toml`. The
`SdCard` type is constructed by providing a SPI device (bus + CS) and a delay
source:

```rust
use embedded_sdmmc::{SdCard, VolumeManager, NoTimestampGenerator};

// spi_dev: impl embedded_hal::spi::SpiDevice (bus + CS already combined)
// delay:   impl embedded_hal::delay::DelayNs
let sd_card = SdCard::new(spi_dev, delay);

// Mount FAT32 volume manager (no timestamp support — pass NoTimestampGenerator)
let mut volume_mgr = VolumeManager::new(sd_card, NoTimestampGenerator);

// Open volume 0 (first FAT32 partition)
let mut volume = volume_mgr.open_volume(embedded_sdmmc::VolumeIdx(0)).unwrap();
```

The SPI device must implement `embedded_hal::spi::SpiDevice`, which handles
CS assertion/de-assertion around each transfer. Use
`embedded_hal_bus::spi::ExclusiveDevice` to wrap an `SpiBus` + output `CS` pin
into an `SpiDevice`:

```rust
use embedded_hal_bus::spi::ExclusiveDevice;
use embassy_rp::gpio::{Level, Output};

let cs_pin = Output::new(p.PIN_15, Level::High);
// spi1: embassy_rp::spi::Spi (SpiBus impl)
let spi_device = ExclusiveDevice::new(spi1, cs_pin, embassy_time::Delay).unwrap();
let sd_card = SdCard::new(spi_device, embassy_time::Delay);
```

`embedded-hal-bus` is pulled in transitively via `embassy-embedded-hal`; no
additional `Cargo.toml` entry is needed.
