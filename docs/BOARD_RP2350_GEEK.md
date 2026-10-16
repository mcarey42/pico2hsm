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
| Column offset   | 52 (CASET start = 52, end = 291) — unverified, see below |
| Row offset      | 40 (RASET start = 40, end = 174) — unverified, see below |
| Orientation     | Landscape (MADCTL = 0x70: MX+MV+ML, RGB order)|
| SPI bus         | SPI1                               |
| SPI frequency   | 40 MHz requested = 37.5 MHz actual (150 MHz / 4); never request more (next step 75 MHz is out of spec) |
| SPI mode        | Mode 0 (CPOL=0, CPHA=0)            |

### What the display shows

The status UI (status band, PIN / KEYS / DOMAIN tiles, activity line,
footer, boot splash, error and SAS screens) is drawn by the display task;
see `DISPLAY_ARCHITECTURE.md` and `DISPLAY_LAYOUT.md`.  The screen is sent
as 16-row bands from a 5 760-byte band buffer — there is no framebuffer.

### Window offsets (unverified, design spec B13)

52 / 40 are the *portrait* offsets of the 135 × 240 panel
(52 = (240 − 135) / 2, 40 = (320 − 240) / 2).  With MADCTL 0x70 (MV = 1)
the landscape window would be expected at CASET 40..279 × RASET 53..187,
so the image may sit about 12 px off.  The offsets stay unchanged until
checked on a Geek: debug builds draw a 1 px border at the panel edge on the
boot splash — all four edges must be visible.

### ST7789 init sequence

The init sequence sent by `St7789StatusDisplay::init()` (async: the
delays are `embassy_time` awaits, so the executor and the watchdog feeder
keep running):

```
RST LOW  10 ms  → RST HIGH
delay 150 ms
SWRESET (0x01)
delay 150 ms
SLPOUT  (0x11)
delay 255 ms
COLMOD  (0x3A) data=[0x33]   — 12-bit RGB444
MADCTL  (0x36) data=[0x70]   — MX | MV | ML = landscape; bit 3 clear = RGB order
CASET/RASET 0..319 × 0..239, RAMWR zeros — clear all of GRAM (from the band buffer, by DMA)
INVON   (0x21)               — inversion on (required for ST7789 correct colours)
NORON   (0x13)               — normal display mode
DISPON  (0x29)               — display on
delay  10 ms
BL HIGH                      — backlight on
```

Each band is then sent as CASET 52..291, RASET 40+y..40+y+rows−1, RAMWR,
one DMA transfer.  Screensaver: BL low, DISPOFF (0x28), SLPIN (0x10);
wake: SLPOUT, 120 ms, DISPON, full redraw, then BL high (the stale
pre-sleep GRAM is never lit).

---

## 4. Keystore

The keystore location depends on the build:

| Feature flag          | Keystore                                              |
|-----------------------|-------------------------------------------------------|
| `rp2350_geek_16m`     | Internal QSPI flash via QMI, the `keystore` partition at 0x829000 (~7.8 MB) |
| `rp2350_geek_sdcard`  | The microSD card on SPI0 (`SdCardFlash`, §6)          |

Both boot through the 16 MB partition table (`boards/pt_16m.json`): A/B
firmware slots of 4,088 KB at 0x002000 and 0x400000, then the store
regions from 0x801000.  On both, the binding block (0x801000), the counter
log with the PIN/PUK retry counters and the keystore anchor (0x809000) and
the RSA key pool (0x819000) stay on internal flash; on the SD-card build the
`keystore` partition is reserved and unused.  See
[FLASH_LAYOUT_2_0.md](FLASH_LAYOUT_2_0.md).  No external SPI flash chips
are used or supported.

---

## 5. SPI1 Bus — LCD

SPI1 drives the ST7789 LCD only (pins in §3).  It runs at **37.5 MHz**
(40 MHz requested), Mode 0, async with DMA.  `St7789StatusDisplay` owns the
bus.

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
cargo build --release -p pico2hsm-firmware --no-default-features --features rp2350_geek_16m
```

### SC-HSM + single SD card slot

```sh
cargo build --release -p pico2hsm-firmware --no-default-features --features rp2350_geek_sdcard
```

### With additional applets (example: PIV + OpenPGP)

```sh
cargo build --release -p pico2hsm-firmware --no-default-features \
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

### Screen update performance

A full screen is 240 × 135 × 1.5 = 48,600 bytes: about 10.5 ms of SPI at
37.5 MHz, sent as nine band transfers.  Typical updates are partial (the
1 Hz uptime tick redraws only the footer band), and commands shorter than
300 ms cause no status repaint at all.
