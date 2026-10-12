# Waveshare RP2350-LCD-1.47-B Board Reference

**Feature flag**: `waveshare_rp2350_lcd_16m`
**Source file**: `firmware/src/board/waveshare_rp2350_lcd.rs`

---

## Board overview

The Waveshare RP2350-LCD-1.47-B is a compact RP2350A development board with an
integrated 1.47" colour LCD and a single WS2812B RGB LED.

| Parameter       | Value                                            |
|-----------------|--------------------------------------------------|
| MCU             | RP2350A (dual Cortex-M33 + dual RISC-V, 150 MHz) |
| SRAM            | 520 KB on-chip                                   |
| External flash  | Winbond W25Q128JVSIQ 16 MB QSPI NOR              |
| Display         | 1.47" ST7789V3 IPS, 172 × 320 pixels, RGB444     |
| RGB LED         | Single WS2812B RGB LED                           |
| SD card         | MicroSD slot (SPI1)                              |
| USB             | USB 1.1 full-speed (USB-C connector)             |
| Power           | 3.3 V from USB via onboard regulator             |

Pin source: official Waveshare example code (`RP2350-LCD-1.47.zip`, waveshare.net 2025),
cross-referenced with schematic `RP2350-LCD-1.47-A.pdf`.

---

## Full GPIO pinout

| GPIO | Function          | Direction | Notes                                     |
|------|-------------------|-----------|-------------------------------------------|
|  0   | UART0 TX          | out       | Debug UART (optional)                     |
|  1   | UART0 RX          | in        | Debug UART (optional)                     |
|  2   | —                 | —         | Available                                 |
|  3   | —                 | —         | Available                                 |
|  4   | SPI0 MISO         | in        | LCD hardware netlist pin; display is write-only, pin never driven by ST7789V3 |
|  5   | —                 | —         | Available                                 |
|  6   | —                 | —         | Available                                 |
|  7   | —                 | —         | Available                                 |
|  8   | —                 | —         | Available                                 |
|  9   | —                 | —         | Available                                 |
| 10   | SPI1 SCK          | out       | SD card clock                             |
| 11   | SPI1 MOSI         | out       | SD card data in                           |
| 12   | SPI1 MISO         | in        | SD card data out                          |
| 13   | —                 | —         | Available                                 |
| 14   | —                 | —         | Available                                 |
| 15   | SPI1 CS           | out       | SD card chip-select (active-low)          |
| 16   | LCD DC            | out       | ST7789V3 Data/Command select              |
| 17   | LCD CS            | out       | ST7789V3 chip-select (active-low)         |
| 18   | SPI0 SCK          | out       | ST7789V3 SPI clock                        |
| 19   | SPI0 MOSI         | out       | ST7789V3 SPI data in                      |
| 20   | LCD RST           | out       | ST7789V3 hardware reset (active-low)      |
| 21   | LCD BL            | out       | ST7789V3 backlight enable (active-high)   |
| 22   | WS2812B DIN       | out       | RGB LED data (PIO0 SM0)                   |
| 23   | —                 | —         | Available                                 |
| 24   | —                 | —         | Available                                 |
| 25   | —                 | —         | Available (no onboard LED on this board)  |
| 26   | ADC0              | in/out    | Available                                 |
| 27   | ADC1              | in/out    | Available                                 |
| 28   | ADC2              | in/out    | Available                                 |
| 29   | ADC3 / VSYS sense | in        | Internal VSYS voltage divider             |

QSPI flash (W25Q128) is connected to the RP2350A QSPI interface (not general GPIO).

---

## ST7789V3 LCD

### Pin assignments

| Signal     | GPIO | Embassy-rp peripheral  | Note                           |
|------------|------|-------------------------|--------------------------------|
| SCK        |  18  | SPI0 CLK                | 40 MHz, SPI mode 0 (CPOL=0/CPHA=0); async DMA for band transfers (no framebuffer) |
| MOSI / DIN |  19  | SPI0 TX                 | Data to display                |
| MISO       |   4  | SPI0 RX (hardware only) | Display never drives this pin  |
| DC         |  16  | GPIO Output             | Low = command, High = data     |
| CS         |  17  | GPIO Output             | Active-low chip-select         |
| RST        |  20  | GPIO Output             | Active-low hardware reset      |
| BL         |  21  | GPIO Output             | High = backlight on            |

### Display geometry

| Parameter         | Value                                                    |
|-------------------|----------------------------------------------------------|
| Physical panel    | 172 × 320 pixels (portrait)                              |
| Firmware mode     | **Landscape 320 × 172** (MADCTL MY+MV = 0xA0)           |
| Colour depth      | 12-bit RGB444                                            |
| CASET range       | 0x0000 – 0x013F (0–319, landscape width)                 |
| RASET range       | 0x0022 – 0x00CD (34–205, landscape height with offset)   |
| Column offset     | 34 — physical GRAM columns 0–33 are outside the panel    |
| Pixel count       | 55 040 pixels (320 × 172)                                |
| Frame size        | 110 080 bytes                                            |
| Byte order        | Big-endian (MSB first)                                   |

**Row offset note (landscape):** The ST7789V3 has 240 GRAM columns. With MV=1,
RASET addresses physical GRAM columns. Only columns 34–205 are connected to the
172-pixel panel; the 68 columns outside this window must be cleared during init
to prevent border artefacts.

### Init sequence

Derived from Waveshare C reference `LCD_1in47_Init()`, corrected for landscape
orientation and 34-pixel column offset.

```
Hardware reset: RST high → low (10 ms) → high → wait 120 ms

SWRESET  (01h)              Software reset                       150 ms delay
SLPOUT   (11h)              Sleep out (enable oscillator)        255 ms delay
COLMOD   (3Ah) 03h          12-bit/pixel RGB444
MADCTL   (36h) A0h          Landscape: MY=1, MV=1 (90° CCW / 180° from 0x60)
INVON    (21h)              Display inversion on (required for V3 panel)
NORON    (13h)              Normal display mode
[clear full 240×320 GRAM: CASET 0–319, RASET 0–239, RAMWR 76 800 black pixels]
CASET    (2Ah) 00 00 01 3F  Landscape columns 0–319
RASET    (2Bh) 00 22 00 CD  Landscape rows 34–205 (panel window)
DISPON   (29h)              Display on                           255 ms delay
BL → high                   Backlight on (GPIO21)
```

### Pixel write protocol

After `CASET`/`RASET`, send `RAMWR (2Ch)` then stream pixel data:
- CS asserted (low) for the entire `RAMWR` + data transfer
- DC high during data bytes
- Each pixel pair: 3 bytes packed RGB444 (ST7789 Interface II)
- No framebuffer: the screen is sent as 16-row full-width bands (7 680
  bytes each, one window + one DMA transfer); only changed bands are
  redrawn (see `DISPLAY_ARCHITECTURE.md`)
- A full screen is 82 560 bytes (~18 ms at 37.5 MHz); the 1 Hz uptime
  tick redraws only the footer bands

### Screens

Status band, tiles, activity line and footer, plus the boot splash, error
and SAS screens: see `DISPLAY_LAYOUT.md`.  The palette is RGB444
(`display/color.rs`).

---------------|----------|--------|--------------------|
| Off           | Black    | 0x0000 | Display blank      |
| Ready         | Green    | 0x07E0 | HSM idle           |
| Busy          | Blue     | 0x001F | Command processing |
| Error         | Red      | 0xF800 | Unrecoverable error|
| Degraded      | Yellow   | 0xFFE0 | Storage degraded   |
| Resyncing     | Cyan     | 0x07FF | RAID resync        |
| WaitingForPin | Bright blue | 0x031F | PIN entry required |

---

## WS2812B RGB LED

### Pin assignment

| Signal  | GPIO | Peripheral  | Note                        |
|---------|------|-------------|-----------------------------|
| DIN     |  22  | PIO0 SM0    | 800 kHz, GRB byte order     |

### Protocol

The WS2812B uses a single-wire protocol at 800 kHz.  The embassy-rp
`pio_programs::ws2812` driver implements the timing in PIO assembly with
DMA transfer.

**Byte order**: Green, Red, Blue (GRB) — the LED expects green byte first.
The `PioWs2812<_, _, _, Grb>` driver handles GRB packing automatically;
callers pass standard `RGB8 { r, g, b }` values.  (Firmware before the
display redesign swapped R and G itself as well, so the two swaps cancelled
and READY showed red.  `PioWs2812Writer::write_rgb` now passes the channels
through unswapped.  Confirm on hardware: READY must be green.)

**Reset signal**: 55 µs low after the last bit (handled automatically by
`PioWs2812::write()`).

### Required resources

| Resource    | Value                                |
|-------------|--------------------------------------|
| PIO         | PIO0                                 |
| State machine | SM0 (or any free SM)               |
| DMA channel | DMA_CH0                             |
| Pixel count | N = 1                                |

> **DMA channel allocation**: DMA_CH0 is used by the WS2812B PIO driver. DMA_CH1 and DMA_CH2 are used by the async SPI0 LCD band transfers (`WavesharePanel`). All three channels are registered in the `DMA_IRQ_0` handler in `main.rs`.

### LED colours

| Display status | RGB (per channel 8; 2 while the screen sleeps) |
|---|---|
| READY | green (0, 8, 0) |
| WORKING | blue (0, 0, 8) |
| NO HOST | cyan (0, 8, 8) |
| DEGRADED, notices | yellow (8, 8, 0) |
| ERROR, LOCKED, error screens | red (8, 0, 0) |
| SAS pending | magenta (8, 0, 8) |

The LED is written only when its colour changes.  Low levels keep the
current draw within the USB 100 mA budget.

### Wiring the PIO driver in `main.rs`

```rust
use embassy_rp::gpio::{Level, Output};
use embassy_rp::pio::Pio;
use embassy_rp::pio_programs::ws2812::{PioWs2812, PioWs2812Program};

// Obtain PIO0 — bind the DMA interrupt in the embassy_rp bind_interrupts! macro.
let Pio { mut common, sm0, .. } = Pio::new(p.PIO0, Irqs);
let ws2812_prog = PioWs2812Program::new(&mut common);

// Single-pixel chain on GPIO22, DMA channel 0.
let mut ws2812 = PioWs2812::new(
    &mut common, sm0, p.DMA_CH0, Irqs, p.PIN_22, &ws2812_prog,
);

// Wrap with the adapter from waveshare_rp2350_lcd.
use pico2hsm_firmware::board::waveshare_rp2350_lcd::PioWs2812Writer;
let mut led_writer = PioWs2812Writer::new(ws2812);
```

---

## SD card

### Pin assignments (SPI1)

| Signal | GPIO | Note                                  |
|--------|------|---------------------------------------|
| SCK    |  10  | SPI1 clock (up to 25 MHz for SD)      |
| MOSI   |  11  | SPI1 data to SD card                  |
| MISO   |  12  | SPI1 data from SD card                |
| CS     |  15  | Chip-select (active-low, GPIO Output) |

Source: Waveshare MicroPython example `MicroPython/02-SD/boot.py`
(`machine.SPI(1, sck=Pin(10), mosi=Pin(11), miso=Pin(12))`).

### Integration with `embedded-sdmmc`

The `embedded-sdmmc` crate (v0.9, already in `Cargo.toml`) provides `SdCard`
and `VolumeManager` for FAT32 access.

```rust
use embedded_sdmmc::{SdCard, VolumeManager};
use embassy_rp::gpio::{Level, Output};

let cs = Output::new(p.PIN_15, Level::High);
let sdcard = SdCard::new(board.spi1(), cs, embassy_time::Delay);
let mut volume_mgr = VolumeManager::new(sdcard, FakeTimesource);
```

SPI1 is already constructed at 40 MHz in `run_waveshare_lcd_board()`.  SD
cards accept up to 25 MHz in SPI mode; 40 MHz may work but 25 MHz is safer
for long traces or non-SDHC cards.  Reduce `SPI_FREQ_HZ` for SPI1 or use a
separate SPI1 config if needed.

---

## Feature flags

| Feature flag                  | Effect                                          |
|-------------------------------|-------------------------------------------------|
| `waveshare_rp2350_lcd_16m`    | Enables `WaveshareRp2350LcdBoard` and the `Board` trait impl |

The feature flag activates:
- `impl Board for WaveshareRp2350LcdBoard` in `waveshare_rp2350_lcd.rs`
- `run_waveshare_lcd_board()` in `main.rs`
- Flash layout matching the 16 MB W25Q128 chip (via QSPI / `embassy_rp::flash`)

---

## Build command

```sh
# SC-HSM only (default applet set):
./build-all-debug.sh waveshare_rp2350_lcd_16m

# Or manually with cargo:
cargo build --release \
  --no-default-features \
  --features waveshare_rp2350_lcd_16m
```

The debug script sets `DEFMT_LOG=trace` and uses the debug profile; see
`CLAUDE.md` for the full workflow.

---

## Async rendering wiring

The LCD and the LED are one `WavesharePanel` (`crate::display::Panel`),
owned by the display task.  `run_waveshare_lcd_board()` builds it from
SPI0, the four control pins and the `PioWs2812Writer`, runs the async
`init()` (reset, init sequence, GRAM clear from the band buffer), draws the
boot splash, and then hands it to `display::task::run` (see
`DISPLAY_ARCHITECTURE.md`).  `LedController::set_status()` on the board
struct only records a status.

SPI0 operates in async mode; `WavesharePanel::write_rows()` sends each
16-row band as one DMA transfer and yields to the executor while it runs.

---

