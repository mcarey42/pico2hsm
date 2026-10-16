# SD Card Wiring Guide

This document covers the SD card wiring of the supported boards and which
feature flag to enable for each configuration.

Two off-the-shelf boards have a built-in microSD slot: the Waveshare
RP2350-Geek and the Waveshare RP2350-LCD-1.47-B.  pico2hsm uses that slot
only, with one card per device.  No external module or added wiring is
needed or supported.

The SD-card builds exist for one use case: enroll the board in a domain,
then ship it with the card sent separately.  The card alone is useless (its
objects are encrypted under keys derived from the device's OTP-based storage
master key); the device alone holds no user keys.  The device verifies the
card on reinsertion (store ID, MACs, the rollback anchor on internal flash;
`docs/STORAGE_V2.md` §8, §11; `docs/KEYSTORE_RECOVERY.md` if it refuses).

---

## SD Card Module Specifications

For reference, an SPI-mode SD card uses six signals:

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

## Waveshare RP2350-Geek — SD Card Wiring

The RP2350-Geek has a **built-in microSD slot** connected to SPI0. The PCB
wires the slot for SDIO 4-bit mode (GPIO18–23), but the RP2350 lacks an SDIO
controller, so we use SPI mode with SCK/MOSI/MISO/CS only.

### Pin assignments

| SD card signal | RP2350-Geek GPIO | Notes                              |
|----------------|------------------|------------------------------------|
| SCK            | GPIO18           | SPI0 clock                         |
| MOSI           | GPIO19           | SPI0 TX (SD CMD line)              |
| MISO           | GPIO20           | SPI0 RX (SD DAT0)                  |
| CS             | GPIO23           | Directly driven (SD DAT3 in SDIO)  |

### Feature flags

| Feature flag              | Description                              |
|---------------------------|------------------------------------------|
| `rp2350_geek_16m`         | No SD card — flash keystore only         |
| `rp2350_geek_sdcard`      | Built-in SD slot as keystore (GPIO23 CS) |

### Build commands

```sh
# No SD card
cargo build --release -p pico2hsm-firmware --no-default-features --features rp2350_geek_16m

# Built-in SD slot
cargo build --release -p pico2hsm-firmware --no-default-features --features rp2350_geek_sdcard
```

---

## Waveshare RP2350-LCD-1.47-B — SD Card Wiring

The RP2350-LCD-1.47-B has a **built-in microSD slot** on SPI1. The LCD uses
SPI0. A second card is not supported.

### Built-in SD card (SPI1)

| SD card signal | GPIO | Notes              |
|----------------|------|--------------------|
| SCK            | 10   | SPI1 clock         |
| MOSI           | 11   | SPI1 TX            |
| MISO           | 12   | SPI1 RX            |
| CS             | 15   | Built-in slot CS   |

### Feature flags

| Feature flag                         | Description                              |
|--------------------------------------|------------------------------------------|
| `waveshare_rp2350_lcd_16m`           | 16 MB flash keystore (built-in SD not used for keystore) |
| `waveshare_rp2350_lcd_sdcard`        | SD card as sole keystore (GPIO15 CS)     |

### Build commands

```sh
# 16 MB flash keystore
cargo build --release -p pico2hsm-firmware --no-default-features --features waveshare_rp2350_lcd_16m

# SD card as sole keystore
cargo build --release -p pico2hsm-firmware --no-default-features --features waveshare_rp2350_lcd_sdcard
```

---

## embedded-sdmmc Integration Notes

`embedded-sdmmc` 0.9 is already a dependency in `firmware/Cargo.toml`.
pico2hsm uses only its block driver: `SdCardFlash`
(`firmware/src/storage/sdcard.rs`) reads and writes raw 512-byte blocks and
never mounts a FAT volume.  The `VolumeManager` lines below show the crate's
general API, not what the firmware does.  The
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
