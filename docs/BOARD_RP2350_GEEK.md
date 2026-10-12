# Waveshare RP2350-Geek — Hardware Reference

This document is the definitive hardware reference for the Waveshare RP2350-Geek
board as used in the pico2hsm firmware.  Pin assignments, bus topology, and
build instructions for all three firmware variants are covered.

---

## 1. Board Overview

| Attribute         | Value                                    |
|-------------------|------------------------------------------|
| MCU               | RP2350A (Cortex-M33 dual-core, 150 MHz)  |
| External flash    | 16 MB QSPI (W25Q128JV or equivalent)     |
| Form factor       | USB-A dongle (no castellated edge)       |
| Display           | 1.14" ST7789 LCD, 240×135 px, RGB444     |
| SD card           | Built-in microSD slot (used by `rp2350_geek_sdcard`) |
| Keystore          | Internal flash, or the SD card (see §4)  |
| USB connector     | USB-A male (plug-in directly)            |

The RP2350-Geek is a compact USB-A dongle with a built-in colour LCD and an
optional microSD slot.  Unlike the RP2350-One (which has a WS2812B LED and
castellated headers), the Geek exposes its GPIO as a standard 2.54 mm header
row along the bottom edge.

pico2hsm uses the board as sold.  It adds no hardware: no external flash
chips, no carrier board.

---

## 2. Full GPIO Pinout

| GPIO | Primary function        | pico2hsm use                     |
|------|-------------------------|----------------------------------|
|   0  | UART0 TX / SPI0 RX      | —                                |
|   1  | UART0 RX / SPI0 CS0     | —                                |
|   2  | SPI0 SCK                | —                                |
|   3  | SPI0 MOSI               | —                                |
|   4  | UART1 TX                | **Debug UART TX** (115200 8N1)   |
|   5  | UART1 RX                | **Debug UART RX**                |
|   6  | I2C1 SDA                | —                                |
|   7  | I2C1 SCL                | —                                |
|   8  | SPI1 RX / GPIO          | **LCD DC** (Data/Command select)  |
|   9  | SPI1 CS0 / GPIO         | **LCD CS** (chip select)          |
|  10  | SPI1 SCK                | **LCD SCK** + SPI1 clock          |
|  11  | SPI1 MOSI               | **LCD MOSI**                      |
|  12  | SPI1 MISO / GPIO        | **LCD RST** (hardware reset)      |
|  13  | GPIO                    | —                                 |
|  14  | GPIO                    | —                                 |
|  15  | GPIO                    | —                                 |
|  16  | GPIO                    | —                                 |
|  17  | GPIO                    | —                                 |
|  18  | SPI0 SCK                | **SD card SCK**                   |
|  19  | SPI0 MOSI               | **SD card MOSI**                  |
|  20  | SPI0 MISO               | **SD card MISO**                  |
|  21  | GPIO                    | SDIO D1 (unused in SPI mode)      |
|  22  | GPIO                    | SDIO D2 (unused in SPI mode)      |
|  23  | GPIO                    | **SD card CS** (SDIO D3)          |
|  24  | GPIO                    | —                                 |
|  25  | GPIO                    | **LCD BL** (backlight enable)     |
|  26  | ADC0                    | —                                 |
|  27  | ADC1                    | —                                 |
|  28  | ADC2                    | —                                 |
|  29  | ADC3 / VBUS sense       | —                                 |

---

## 3. ST7789 LCD

### Pin assignments

Confirmed from official Waveshare MicroPython example
(`scripsi/rp2350-geek-mpy / firmware/color_setup.py`) and the mipidsi Rust
example (`melastmohican/rp2350-geek-rust-examples / examples/mipidsi.rs`):

| Signal | GPIO | Direction | Note                           |
|--------|------|-----------|--------------------------------|
| DC     |   8  | Output    | LOW = command, HIGH = data     |
| CS     |   9  | Output    | Active-low chip select         |
| SCK    |  10  | Output    | SPI1 clock                     |
| MOSI   |  11  | Output    | SPI1 data out                  |
| RST    |  12  | Output    | Active-low hardware reset      |
| BL     |  25  | Output    | Active-high backlight enable   |

MISO is not connected to the ST7789 (write-only display).

### Display parameters

| Parameter       | Value                              |
|-----------------|------------------------------------|
| Controller      | ST7789                             |
| Panel size      | 1.14 inch                          |
| Resolution      | 240 × 135 pixels (landscape)       |
| Colour format   | RGB444 (12-bit, COLMOD = 0x33)     |
| Colour inversion| Required (INVON must be sent)      |
| Column offset   | 52 (CASET start = 52, end = 291)   |
| Row offset      | 40 (RASET start = 40, end = 174)   |
| Orientation     | Landscape (MADCTL = 0x70: MX+MV+BGR)|
| SPI bus         | SPI1                               |
| SPI frequency   | 30 MHz (rated up to 62.5 MHz)      |
| SPI mode        | Mode 0 (CPOL=0, CPHA=0)            |

### Colour mapping (pico2hsm `LedStatus`)

| `LedStatus`    | RGB565     | Colour description |
|----------------|------------|--------------------|
| Off            | `0x0000`   | Black              |
| Ready          | `0x07E0`   | Green              |
| Busy           | `0x001F`   | Blue               |
| Error          | `0xF800`   | Red                |
| Degraded       | `0xFFE0`   | Yellow             |
| Resyncing      | `0x07FF`   | Cyan               |
| WaitingForPin  | `0x031F`   | Bright blue        |

### ST7789 init sequence

The init sequence sent by `St7789StatusDisplay::st7789_init()`:

```
RST LOW  10 ms  → RST HIGH
delay 150 ms
SWRESET (0x01)
delay 150 ms
SLPOUT  (0x11)
delay 255 ms
COLMOD  (0x3A) data=[0x33]   — 12-bit RGB444
delay  10 ms
MADCTL  (0x36) data=[0x70]   — MX | MV | BGR = landscape, correct colour order
CASET   (0x2A) data=[0x00,0x34,0x01,0x23]   — columns 52..291
RASET   (0x2B) data=[0x00,0x28,0x00,0xB6]   — rows 40..174
INVON   (0x21)               — inversion on (required for ST7789 correct colours)
delay  10 ms
NORON   (0x13)               — normal display mode
delay  10 ms
DISPON  (0x29)               — display on
delay  10 ms
BL HIGH                      — backlight on
fill_screen(0x0000)          — clear to black
```

---

## 4. Keystore

The keystore location depends on the build:

| Feature flag          | Keystore                                              |
|-----------------------|-------------------------------------------------------|
| `rp2350_geek_16m`     | Internal QSPI flash via QMI (`QmiFlash`), 2 MB at offset 0x200000 |
| `rp2350_geek_sdcard`  | The microSD card on SPI0 (`SdCardFlash`, §6)          |

On both, the PIN/PUK retry-counter log stays on internal flash
(16 KB at offset 0x1FC000).  The linker script reserves 14 MB above the
firmware, but the 1.x keystore uses only the first 2 MB of it
(`docs/STORAGE_V2.md` F3).  No external SPI flash chips are used or
supported.

---

## 5. SPI1 Bus — LCD

SPI1 drives the ST7789 LCD only (pins in §3).  It runs at **30 MHz**,
Mode 0, async with DMA.  `St7789StatusDisplay` owns the bus.

---

## 6. SD Card

### Single SD card variant (`rp2350_geek_sdcard`)

The built-in microSD slot connects to SPI0 (separate from the LCD on SPI1).
In this build the card is the keystore.
The SD card interface is wired for SDIO 4-bit mode on the PCB, but the RP2350
lacks an SDIO controller, so we use SPI mode with only SCK, MOSI, MISO, and
CS (DAT3).  SDIO D1 (GPIO21) and D2 (GPIO22) are unused.

| Signal   | GPIO | Note                            |
|----------|------|---------------------------------|
| SCK      |  18  | SPI0 clock                      |
| MOSI     |  19  | SPI0 TX (SD CMD)                |
| MISO     |  20  | SPI0 RX (SD DAT0)               |
| CS       |  23  | SD card chip select (SD DAT3)   |

---

## 7. Feature Flags

| Feature flag              | LCD | SD slot |
|---------------------------|-----|---------|
| `rp2350_geek_16m`         | yes | no      |
| `rp2350_geek_sdcard`      | yes | 1       |

Both variants include the full ST7789 LCD driver.  The SD card feature
flag gates the `SDCARD0_CS` constant and any SD-specific init logic.

**Why an SD-card build?**  An SD-card board can be enrolled in a domain and
shipped to a remote party with the card sent separately.  The card alone is
useless: its objects are encrypted under keys derived from the device's
OTP-based storage master key.  The device alone holds no user keys.  When
the card goes back in, the device checks it and resumes domain sync.  The
card checks (store ID, MACs, rollback anchor on internal flash) are planned
for 2.0; see `docs/STORAGE_V2.md` §8 and §11 and `docs/CLUSTER_PLAN_V3.md`.

---

## 8. Build Commands

Always use `--no-default-features` when specifying a non-default board to
avoid conflicting feature combinations (see `CLAUDE.md` for the rationale).

### SC-HSM only (no SD card)

```sh
cargo build --release --no-default-features --features rp2350_geek_16m
```

### SC-HSM + single SD card slot

```sh
cargo build --release --no-default-features --features rp2350_geek_sdcard
```

### With additional applets (example: PIV + OpenPGP)

```sh
cargo build --release --no-default-features \
    --features rp2350_geek_16m,applet-piv,applet-openpgp
```

### Debug build and flash (standard workflow)

```sh
./build-all-debug.sh rp2350_geek_16m
```

The `build-all-debug.sh` script sets `DEFMT_LOG=trace`, uses the debug
profile, and streams RTT output via probe-rs.  See `CLAUDE.md` for full
workflow details.

---

## 9. Implementation Notes

### GPIO ownership at construction

`Rp2350GeekBoard::new(spi1)` takes the SPI1 bus.  SPI1 is
immediately transferred into `St7789StatusDisplay`, which also acquires the
four LCD GPIO pins (DC=8, CS=9, RST=12, BL=25) via
`embassy_rp::gpio::AnyPin::steal()`.  This avoids changing the `new()`
signature (which main.rs calls without GPIO arguments).

The steal is safe because those four GPIOs are exclusively wired to the
ST7789 LCD on this board and are not claimed anywhere else in the firmware.

### Screen fill performance

`fill_screen()` writes 240 × 135 = 32,400 pixels (48,600 bytes in RGB444) over SPI.
At 30 MHz with 8-bit transfers, theoretical minimum is ~17 ms per fill.
In practice, including CS toggling and CASET/RASET commands, a full fill
takes approximately 20–25 ms on hardware.  This is acceptable for status
updates (which change at most once per APDU).
