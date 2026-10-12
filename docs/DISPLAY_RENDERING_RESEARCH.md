# Display Rendering Research — embedded-graphics + ST7789

> **Status (2026-10, display redesign).**  This is the background research.
> What the firmware does now is in `DISPLAY_ARCHITECTURE.md` and
> `DISPLAY_LAYOUT.md`.  Where it differs from the notes below:
> - Both panels run **RGB444** (COLMOD 0x03 / 0x33), not RGB565, with a
>   palette defined in RGB444 (`display/color.rs`) and a custom `C444`
>   colour type; nothing converts from RGB565 any more.
> - There is **no framebuffer**.  The screen is rendered in 16-row
>   full-width bands into a 7 680 B (Waveshare) / 5 760 B (Geek) buffer and
>   each band is one window + one DMA transfer; only bands whose content
>   changed are redrawn.  The shared `Rgb444Band` target uses span fills.
> - Waveshare MADCTL is **0xA0** (MY + MV), landscape 320 × 172 with RASET
>   34–205; the Geek uses 0x70 = MX + MV + ML (RGB order, not BGR).
> - SPI runs at 37.5 MHz on both LCDs (40 MHz requested; 150 MHz / 4).
>   75 MHz would be out of spec.
> - Controller init on both boards uses async `embassy_time` delays.

**Target boards:** Waveshare RP2350-Geek (240×135, SPI1, 30 MHz) and Waveshare RP2350-LCD-1.47-B (172×320 portrait / 320×172 landscape, SPI0, 40 MHz)
**Runtime:** no_std + no_alloc, Embassy async, Cortex-M33 (RP2350)

---

## 1. embedded-graphics — no_std compatibility

### Version

```toml
embedded-graphics = "0.8.2"        # latest stable as of April 2026
embedded-graphics-core = "0.4.1"   # trait-only crate (subset)
```

### no_std + no_alloc

`embedded-graphics` 0.8.x is **fully no_std and no_alloc**.

- No `extern crate std` dependency at any level.
- No heap allocation. All drawing primitives are zero-allocation iterator types.
- The crate declares `#![no_std]` in its root.
- The optional `nalgebra` geometry integration is not needed here and is gated behind a `nalgebra` feature flag that we leave disabled.

**No feature flags are required for no_std usage.** The default feature set is correct:

```toml
embedded-graphics = { version = "0.8.2", default-features = true }
```

`default-features = false` would disable nothing meaningful — the crate has no std-only features. Leave it at defaults.

### DrawTarget trait

`DrawTarget` is the core trait a display driver must implement to accept drawing commands from embedded-graphics primitives and text.

```rust
// In embedded_graphics::draw_target
pub trait DrawTarget: OriginDimensions {
    type Color: PixelColor;
    type Error;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>;
}

pub trait OriginDimensions {
    fn size(&self) -> Size;
}
```

Where `Pixel<C>` is:
```rust
pub struct Pixel<C: PixelColor>(pub Point, pub C);
// Point is: pub struct Point { pub x: i32, pub y: i32 }
```

For our ST7789 drivers with RGB565 colour format:
- `type Color = Rgb565`
- `type Error = core::convert::Infallible` (SPI writes do not propagate errors in our blocking driver)
- `size()` returns `Size::new(width, height)` matching the display's active pixel area

---

## 2. Text rendering — MonoFont options

### All MonoFonts in embedded-graphics 0.8.x

All fonts are in `embedded_graphics::mono_font::ascii` (ASCII-only) and `embedded_graphics::mono_font::iso_8859_*` (Latin extended). The complete list of pixel-grid sizes:

| Constant | Size (W×H px) | Notes |
|---|---|---|
| `FONT_4X6` | 4×6 | Tiny; lowercase only for status codes |
| `FONT_5X7` | 5×7 | Small; good for dense data |
| `FONT_5X8` | 5×8 | Slightly taller variant |
| `FONT_6X9` | 6×9 | Readable at a glance |
| `FONT_6X10` | 6×10 | Readable |
| `FONT_6X12` | 6×12 | Good for secondary labels |
| `FONT_6X13` | 6×13 | Default "readable" font; good for labels |
| `FONT_6X13_BOLD` | 6×13 | Bold variant — use for headings |
| `FONT_6X13_ITALIC` | 6×13 | Italic variant |
| `FONT_7X13` | 7×13 | Slightly wider, good readability |
| `FONT_7X13_BOLD` | 7×13 | Bold; use for key count / status labels |
| `FONT_7X13_ITALIC` | 7×13 | Italic |
| `FONT_7X14` | 7×14 | Tall variant |
| `FONT_7X14_BOLD` | 7×14 | Bold tall |
| `FONT_8X13` | 8×13 | Spacious; recommended for status values |
| `FONT_8X13_BOLD` | 8×13 | Bold spacious |
| `FONT_8X13_ITALIC` | 8×13 | Italic |
| `FONT_9X15` | 9×15 | Large; suitable for headers |
| `FONT_9X15_BOLD` | 9×15 | Bold large; suitable for main status line |
| `FONT_9X18` | 9×18 | Very large |
| `FONT_9X18_BOLD` | 9×18 | Bold very large |
| `FONT_10X20` | 10×20 | Maximum size in built-in set |

All fonts use a 1-pixel vertical gap between the character bounding box and the baseline. The `character_size` field gives the full bounding box (W×H) and `baseline` gives the offset from the top of the bounding box to the text baseline.

### Recommendations by display

**Geek display — 240 wide × 135 tall (landscape)**

The 135 px height comfortably fits:
- Header bar: 18 px tall → `FONT_9X15_BOLD` (header title)
- Body rows: ~20 px each → `FONT_9X15` (status values), `FONT_6X13` (labels)
- Status line at bottom: `FONT_6X13_BOLD` (state name)

Maximum rows at 18 px row height: 135 / 18 = 7 rows. Use 5–6 rows for a clean UI.

**Waveshare LCD — landscape (320 wide × 172 tall)**

The 172 px height allows:
- Header bar: 20 px → `FONT_9X15_BOLD` or `FONT_10X20`
- Body rows: 20–25 px each → `FONT_9X15_BOLD` (values), `FONT_7X13` (labels)
- Maximum 8 rows at 20 px height

Recommended layout:
- Row 0 (header, y=0–19): `FONT_9X18_BOLD` for "pico2hsm" title
- Rows 1–6 (y=20–172): `FONT_8X13` for key: value pairs, 2 px padding

### External font crates

**profont 0.7.0**
- Provides the ProFont monospace bitmap font (originally designed for small screens)
- Sizes: 7×11, 9×15, 12×22, 14×22, 17×30, 22×37, 29×49 (in pixels)
- Usage: `use profont::PROFONT_9_POINT;` — each is a `MonoFont` reference
- Fully no_std, no_alloc
- Good for: the 9×15 size is an attractive alternative to `FONT_9X15`
- Cargo.toml: `profont = "0.7"`

**u8g2-fonts 0.7.2**
- Ports ~200 fonts from the Arduino u8g2 library
- NOT a `MonoFont` — uses its own `FontRenderer` that takes a `DrawTarget`
- Proportional and monospaced fonts available
- Fully no_std, no_alloc
- More complex API than embedded-graphics MonoFont
- Overkill for a status display; skip unless proportional fonts are needed
- Cargo.toml: `u8g2-fonts = "0.7"` (with `embedded-graphics` as dependency)

**Recommendation:** Use built-in MonoFonts from `embedded-graphics` for initial implementation. Add `profont` only if the built-in sizes are unsatisfactory. Skip `u8g2-fonts`.

---

## 3. Drawing primitives API

### Import path

```rust
use embedded_graphics::{
    mono_font::{ascii::FONT_6X13, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{Line, PrimitiveStyleBuilder, Rectangle},
    text::Text,
};
```

### Filled rectangle (status background / header bar)

```rust
let style = PrimitiveStyleBuilder::new()
    .fill_color(Rgb565::new(0, 10, 31))   // dark blue header background
    .build();

Rectangle::new(
    Point::new(0, 0),
    Size::new(display_width as u32, 18),  // full-width, 18 px tall header
)
.into_styled(style)
.draw(&mut display)?;
```

For a rectangle with both fill and stroke (border):
```rust
let style = PrimitiveStyleBuilder::new()
    .fill_color(Rgb565::CSS_NAVY)
    .stroke_color(Rgb565::WHITE)
    .stroke_width(1)
    .build();
```

### Text rendering with MonoFont

```rust
use embedded_graphics::mono_font::{ascii::FONT_6X13_BOLD, MonoTextStyle};
use embedded_graphics::text::Text;
use embedded_graphics::prelude::*;

let text_style = MonoTextStyle::new(&FONT_6X13_BOLD, Rgb565::WHITE);

Text::new("pico2hsm", Point::new(4, 13), text_style)
    .draw(&mut display)?;
```

Note: `Point::new(x, y)` where `y` is the **baseline** position, not the top of the character bounding box. To position text so its top is at `y_top`:

```rust
let y_baseline = y_top + FONT_6X13_BOLD.baseline as i32;
Text::new("label:", Point::new(x, y_baseline), style).draw(&mut display)?;
```

`MonoFont::baseline` is a `u32` giving the offset from the top of the bounding box to the text baseline. For `FONT_6X13`, `baseline = 10`; for `FONT_9X15`, `baseline = 12`.

### Text with background color (`MonoTextStyle`)

```rust
let style = MonoTextStyleBuilder::new()
    .font(&FONT_8X13)
    .text_color(Rgb565::WHITE)
    .background_color(Rgb565::new(0, 0, 10))  // fills character background cells
    .build();
```

Background color fills the full character bounding box, which is efficient for
updating values in-place without redrawing the whole row.

### Horizontal line (divider)

```rust
use embedded_graphics::primitives::{Line, PrimitiveStyle};

Line::new(Point::new(0, 18), Point::new(display_width as i32 - 1, 18))
    .into_styled(PrimitiveStyle::with_stroke(Rgb565::CSS_GRAY, 1))
    .draw(&mut display)?;
```

### TextStyle vs MonoTextStyle

| Type | When to use |
|---|---|
| `MonoTextStyle` | Use this. It is the concrete style type for `MonoFont` bitmap fonts. Contains font reference, text color, background color. |
| `TextStyle` | Layout-only configuration: `alignment` (Left/Right/Center) and `baseline` (Alphabetic/Middle/Top/Bottom). |

In practice, `Text::new(str, point, mono_text_style)` is sufficient for all status-display text. `TextStyle` is only needed when combining with `Text::with_text_style()` for centered or right-aligned text:

```rust
use embedded_graphics::text::{Alignment, TextStyleBuilder};

let text_layout = TextStyleBuilder::new()
    .alignment(Alignment::Right)
    .build();

Text::with_text_style(
    "READY",
    Point::new(display_width as i32 - 4, 13),
    mono_style,
    text_layout,
).draw(&mut display)?;
```

### Rgb565 color construction

```rust
// From raw 5-6-5 components (r: 0–31, g: 0–63, b: 0–31)
Rgb565::new(r5, g6, b5)

// Named CSS colors
Rgb565::WHITE
Rgb565::BLACK
Rgb565::RED
Rgb565::GREEN
Rgb565::BLUE
Rgb565::YELLOW
Rgb565::CYAN
Rgb565::MAGENTA

// CSS named colors (more options)
Rgb565::CSS_NAVY        // dark blue
Rgb565::CSS_DARK_GREEN
Rgb565::CSS_DARK_CYAN
Rgb565::CSS_GRAY
Rgb565::CSS_DARK_GRAY

// Convert from Rgb888 at compile time (truncates bits)
use embedded_graphics::pixelcolor::RgbColor;
// Rgb565::new(r >> 3, g >> 2, b >> 3) manually
```

---

## 4. ST7789 DrawTarget implementation

### Required traits

To use embedded-graphics with the existing raw SPI drivers, implement two traits on `St7789StatusDisplay` / `St7789V3StatusDisplay`:

```rust
use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{OriginDimensions, Size},
    pixelcolor::Rgb565,
    Pixel,
};

impl OriginDimensions for St7789StatusDisplay {
    fn size(&self) -> Size {
        Size::new(LCD_WIDTH as u32, LCD_HEIGHT as u32)
    }
}

impl DrawTarget for St7789StatusDisplay {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        for Pixel(point, color) in pixels {
            // Bounds check
            if point.x < 0 || point.y < 0
                || point.x >= LCD_WIDTH as i32
                || point.y >= LCD_HEIGHT as i32
            {
                continue;
            }
            let x = point.x as u16;
            let y = point.y as u16;

            // Set 1×1 pixel window
            self.set_window(x, y, x, y);

            // Write one RGB565 pixel (2 bytes, big-endian)
            let raw: u16 = RawU16::from(color).into_inner();
            let bytes = [(raw >> 8) as u8, (raw & 0xFF) as u8];
            self.dc.set_low();
            self.cs_assert();
            let _ = self.spi.blocking_write(&[ST7789_RAMWR]);
            self.dc.set_high();
            let _ = self.spi.blocking_write(&bytes);
            self.cs_deassert();
        }
        Ok(())
    }
}
```

Where `set_window` wraps the existing `CASET`/`RASET` sequence.

### Efficient row-batched draw_iter

The naive per-pixel `draw_iter` above issues a `CASET`/`RASET`/`RAMWR` sequence for every pixel — prohibitively slow for filled rectangles (32,400 pixels on the Geek). The efficient approach is to sort pixels by row and batch each row into a single SPI burst:

```rust
fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
where
    I: IntoIterator<Item = Pixel<Rgb565>>,
{
    use embedded_graphics::pixelcolor::raw::RawU16;

    // Collect one row at a time. We cannot sort without alloc, so use
    // fill_contiguous() or draw_iter() with a row buffer instead.
    //
    // For rectangles and text, embedded-graphics calls fill_contiguous()
    // directly (an optional optimisation hook). Implement that instead.
    for Pixel(point, color) in pixels {
        if point.x < 0 || point.y < 0
            || point.x >= LCD_WIDTH as i32
            || point.y >= LCD_HEIGHT as i32
        {
            continue;
        }
        // ... per-pixel path as fallback
    }
    Ok(())
}
```

**Important optimisation: override `fill_contiguous()`**

`DrawTarget` provides a default `fill_contiguous()` method that is called by `Rectangle::draw()`, `Text::draw()` (character cells), and other area-filling operations. Override it to write a full rectangular bounding box in one SPI burst:

```rust
fn fill_contiguous<I>(
    &mut self,
    area: &Rectangle,
    colors: I,
) -> Result<(), Self::Error>
where
    I: IntoIterator<Item = Self::Color>,
{
    use embedded_graphics::pixelcolor::raw::RawU16;

    let drawable_area = area.intersection(&self.bounding_box());
    if drawable_area.size == Size::zero() {
        return Ok(());
    }

    let x0 = drawable_area.top_left.x as u16 + LCD_COL_OFFSET;
    let y0 = drawable_area.top_left.y as u16 + LCD_ROW_OFFSET;
    let x1 = x0 + drawable_area.size.width as u16 - 1;
    let y1 = y0 + drawable_area.size.height as u16 - 1;

    // Set window
    self.write_command_data(ST7789_CASET, &[
        (x0 >> 8) as u8, (x0 & 0xFF) as u8,
        (x1 >> 8) as u8, (x1 & 0xFF) as u8,
    ]);
    self.write_command_data(ST7789_RASET, &[
        (y0 >> 8) as u8, (y0 & 0xFF) as u8,
        (y1 >> 8) as u8, (y1 & 0xFF) as u8,
    ]);

    // Enter RAM write
    self.dc.set_low();
    self.cs_assert();
    let _ = self.spi.blocking_write(&[ST7789_RAMWR]);
    self.dc.set_high();

    // Stream pixels two bytes each; buffer in a row-sized stack array
    // to avoid per-pixel SPI overhead
    let row_w = drawable_area.size.width as usize;
    let mut row_buf = [0u8; LCD_WIDTH as usize * 2]; // 480 bytes on stack
    let mut row_buf = &mut row_buf[..row_w * 2];

    let mut col_idx = 0usize;
    for color in colors {
        let raw: u16 = RawU16::from(color).into_inner();
        row_buf[col_idx * 2]     = (raw >> 8) as u8;
        row_buf[col_idx * 2 + 1] = (raw & 0xFF) as u8;
        col_idx += 1;
        if col_idx == row_w {
            let _ = self.spi.blocking_write(&row_buf[..row_w * 2]);
            col_idx = 0;
        }
    }

    self.cs_deassert();
    Ok(())
}

fn fill_solid(
    &mut self,
    area: &Rectangle,
    color: Self::Color,
) -> Result<(), Self::Error> {
    self.fill_contiguous(area, core::iter::repeat(color))
}
```

### Existing ST7789 crates — evaluation

**`st7789` crate (0.7.0)**
- Provides a `ST7789` driver struct that implements `DrawTarget<Color = Rgb565>`
- Depends on `embedded-hal 1.0` `SpiDevice` (not `SpiBus` — requires a CS-managing wrapper)
- Fully no_std, no_alloc
- Does NOT use embassy-rp directly; works with any `embedded-hal 1.0` blocking SPI
- **Problem**: requires `SpiDevice` (includes CS management) not a raw `SpiBus`. Adapting our `Rp2350GeekSpi1` (a raw `SpiBus`) to `SpiDevice` requires an `embedded-hal-bus::ExclusiveDevice` wrapper, which adds a small dependency but is straightforward
- **Conclusion**: viable but unnecessary — our raw driver already works and adding the wrapper for no functional gain is complexity without benefit. Implement `DrawTarget` directly on our struct instead.

**`mipidsi` crate (0.10.0)**
- Generic MIPI DCS driver supporting ST7789, ILI9341, and many others
- Implements `DrawTarget` via `embedded-graphics-core`
- Requires `display-interface-spi` adapter or `display-interface` trait
- Fully no_std
- **Problem**: the `display-interface-spi` crate expects a specific SPI + DC pin abstraction that does not map cleanly to our existing `write_command` / `write_command_data` pattern, and it manages CASET/RASET internally, which would conflict with our existing MADCTL/offset setup
- **Conclusion**: mipidsi would replace our entire driver, not just add graphics. The migration cost exceeds the benefit for a single-purpose status display. Skip.

**Recommendation: implement `DrawTarget` directly on the existing structs.** The implementation is ~60 lines, does not require new dependencies, and preserves the existing SPI transaction structure.

---

## 5. MADCTL rotation — Waveshare portrait to landscape

### MADCTL bit field (ST7789 datasheet)

| Bit | Name | Value=0 | Value=1 |
|---|---|---|---|
| 7 | MY | Row address: top to bottom | Row address: bottom to top |
| 6 | MX | Column address: left to right | Column address: right to left |
| 5 | MV | Normal scan (row/col as natural) | Row/column exchange (transposes matrix) |
| 4 | ML | LCD refresh: top to bottom | LCD refresh: bottom to top |
| 3 | BGR | RGB colour order | BGR colour order |
| 2 | MH | LCD refresh: left to right | LCD refresh: right to left |
| 1–0 | — | Reserved (always 0) | — |

**Shorthand:** MV=1 transposes the pixel matrix (swaps X and Y axes), effectively rotating 90°. MY and MX control the mirror axes applied on top of the transpose.

### Current MADCTL values

**Geek (rp2350_geek.rs line 289):**
```
MADCTL = 0x70 = 0b0111_0000
```
Bits: MY=0, MX=1, MV=1, ML=1 (refresh bottom-to-top), BGR=0, MH=0

- MX=1 + MV=1: column mirror + row/col exchange → landscape with column mirror → produces correct left-to-right landscape with CASET offset 52, RASET offset 40
- BGR=0: RGB colour order (correct for this ST7789 variant)

**Waveshare LCD (waveshare_rp2350_lcd.rs line 585):**
```
MADCTL = 0x00 = 0b0000_0000
```
Bits: MY=0, MX=0, MV=0, ML=0, BGR=0, MH=0

- Normal (portrait) orientation: CASET 0–171 (172 wide), RASET 0–319 (320 tall)
- The physical panel is 172 px wide × 320 px tall in this orientation

### Rotation to landscape (320 wide × 172 tall)

To make the 172×320 portrait panel appear as a 320×172 landscape display, we need to transpose the matrix with correct mirroring so that:
- The left edge of the landscape frame maps to the top of the portrait panel
- The top edge of the landscape frame maps to the right of the portrait panel

**MADCTL = 0x60 = 0b0110_0000**

Bits: MY=0, MX=1, MV=1, ML=0, BGR=0, MH=0

This applies MX (horizontal mirror) + MV (transpose), yielding 90° clockwise rotation. The resulting pixel layout:
- Landscape X axis (0→319) maps to portrait Y axis (top→bottom)
- Landscape Y axis (0→171) maps to portrait X axis (right→left) — MX mirrors this

After applying MADCTL = 0x60, the CASET and RASET window must be updated to match the transposed (landscape) dimensions:

```
CASET: 0x0000 – 0x013F   (columns 0–319, 320 px wide in landscape)
RASET: 0x0000 – 0x00AB   (rows 0–171, 172 px tall in landscape)
```

In bytes:
```
CASET: [0x00, 0x00, 0x01, 0x3F]
RASET: [0x00, 0x00, 0x00, 0xAB]
```

The new constants for the landscape driver:
```rust
const LCD_WIDTH: u16  = 320;   // landscape width
const LCD_HEIGHT: u16 = 172;   // landscape height
// No column/row offset needed for this panel (0-based addressing)
```

### Alternative rotations

| MADCTL | MY | MX | MV | Description |
|---|---|---|---|---|
| 0x00 | 0 | 0 | 0 | Portrait, normal (current) |
| 0x60 | 0 | 1 | 1 | Landscape, 90° CW — **recommended** |
| 0xC0 | 1 | 1 | 0 | Portrait, 180° |
| 0xA0 | 1 | 0 | 1 | Landscape, 90° CCW |

Test 0x60 first. If the image is mirrored horizontally, try 0xA0 (CCW). The exact correct value depends on which physical edge of the panel is connector-side; verify against the Waveshare schematic PDF (connector at bottom of portrait → use 0x60).

---

## 6. Pixel write performance

### Theoretical SPI throughput

Each pixel = 2 bytes = 16 bits. SPI clock speed is the dominant factor, with a small overhead per SPI transaction (CS assert/deassert + DC toggle + RAMWR command = ~5 bytes overhead per window).

For a full-screen write (one CASET/RASET/RAMWR setup + pixel data in one CS assertion), the overhead is negligible relative to pixel data.

**Bytes per second:**
- Geek (SPI1, 30 MHz): 30,000,000 / 8 = 3,750,000 bytes/s
- Waveshare LCD (SPI0, 40 MHz): 40,000,000 / 8 = 5,000,000 bytes/s

### Full-screen fill time

| Display | Pixels | Bytes | SPI speed | Time |
|---|---|---|---|---|
| Geek | 240×135 = 32,400 | 64,800 | 30 MHz | **17.3 ms** |
| Waveshare LCD portrait | 172×320 = 55,040 | 110,080 | 40 MHz | **22.0 ms** |
| Waveshare LCD landscape | 320×172 = 55,040 | 110,080 | 40 MHz | **22.0 ms** |

These are theoretical minimums. Practical timing with `blocking_write()` in Embassy on RP2350:
- DMA is not used in blocking mode — the CPU drives all bytes through the SPI FIFO
- Embassy `spi::Blocking` uses `spi.blocking_write()` which spins on the FIFO drain
- Add ~10–20% overhead for FIFO stalls and loop overhead
- Practical full-screen fill: ~20 ms (Geek) and ~26 ms (Waveshare LCD)

### Single character write time

Character bounding box bytes = W × H × 2 bytes:

| Font | W×H | Bytes | Time (30 MHz) | Time (40 MHz) |
|---|---|---|---|---|
| FONT_4X6 | 4×6 | 48 | 0.013 ms | 0.010 ms |
| FONT_6X13 | 6×13 | 156 | 0.042 ms | 0.031 ms |
| FONT_8X13 | 8×13 | 208 | 0.056 ms | 0.042 ms |
| FONT_9X15 | 9×15 | 270 | 0.072 ms | 0.054 ms |
| FONT_10X20 | 10×20 | 400 | 0.107 ms | 0.080 ms |

Note: each character requires its own CASET/RASET/RAMWR setup (~40 bytes command overhead) unless characters are rendered left-to-right in a contiguous row. With `fill_contiguous()` overridden to set the window once per text string, the overhead is amortised:
- A 20-character string in FONT_6X13: window = (120 wide × 13 tall) = 3,120 bytes = 0.83 ms at 30 MHz

### Header bar write time

Full-width × 18 px header bar:

| Display | Width | Bytes | Time (30 MHz) | Time (40 MHz) |
|---|---|---|---|---|
| Geek | 240 | 240×18×2 = 8,640 | 2.3 ms | — |
| Waveshare LCD (landscape) | 320 | 320×18×2 = 11,520 | — | 2.3 ms |

### Conclusion: is partial update worth the complexity?

**Yes, for text-heavy UIs. No, for solid-colour status screens.**

Current behaviour (fill_screen solid colour): ~20–26 ms, perfectly fast enough — well below the 1.5 s time-extension threshold. No partial update needed for solid-colour mode.

For text rendering with embedded-graphics:
- Drawing 5 rows of 2-column label/value text on Geek: approximately 5 × 2 strings × 0.83 ms = 8.3 ms — still fast.
- A full redraw of the text UI from scratch: ~35–50 ms including background fill. Acceptable; no visible flicker.

**Recommendation:** Implement full-screen redraw on status change. Only consider partial updates (dirty-rect tracking) if the display update is called more than ~10 times per second, which is not expected for an HSM status display.

---

## 7. Recommended Cargo.toml additions

Add to `[target.'cfg(target_arch = "arm")'.dependencies]` in `firmware/Cargo.toml`:

```toml
# embedded-graphics for text and UI primitives on ST7789 displays
embedded-graphics = { version = "0.8.2" }
```

That is the only required addition.

Optionally, if ProFont's aesthetics are preferred over the built-in MonoFonts:
```toml
# ProFont monospace bitmap font for embedded-graphics
profont = { version = "0.7" }
```

**Do not add:**
- `mipidsi` — would require replacing the existing raw SPI driver
- `st7789` — implements DrawTarget but requires SpiDevice wrapper; simpler to implement DrawTarget directly
- `u8g2-fonts` — overkill for a status display; proportional fonts add complexity with no benefit
- `embedded-graphics-core` separately — it is a re-exported dependency of `embedded-graphics`; only add it directly if needed by a crate that does not pull in the full `embedded-graphics`
- `tinybmp` / `tinytga` — no bitmap logos needed for a text status display

### Full dependency block after additions

```toml
[target.'cfg(target_arch = "arm")'.dependencies]

# Embassy async runtime for Cortex-M / RP2350
embassy-rp = { version = "0.10", features = ["rp235xa", "unstable-pac", "time-driver", "defmt", "imagedef-none"] }
embassy-executor = { version = "0.10", features = ["platform-cortex-m", "executor-thread"] }
static_cell = { version = "2", default-features = false }

embassy-usb = { version = "0.6" }
embassy-futures = { version = "0.1" }
embassy-sync = { version = "0.8" }
embassy-time = { version = "0.5" }
embassy-embedded-hal = { version = "0.6" }

# Hardware abstraction
embedded-hal = { version = "1.0" }
embedded-hal-async = { version = "1.0" }
embedded-sdmmc = { version = "0.9" }

# Display rendering
embedded-graphics = { version = "0.8.2" }
# profont = { version = "0.7" }   # optional: ProFont sizes if built-in fonts are insufficient

# Logging / diagnostics
defmt = { version = "0.3" }
defmt-rtt = { version = "0.4" }

# ARM Cortex-M runtime
cortex-m = { version = "0.7", features = ["critical-section-single-core"] }
cortex-m-rt = { version = "0.7" }
panic-probe = { version = "0.3", features = ["print-defmt"] }

# Noise Protocol Framework (DKEK exchange)
snow = { version = "0.10", default-features = false }
```

---

## 8. Implementation sketch — St7789StatusDisplay with embedded-graphics

Below is a minimal complete implementation for `St7789StatusDisplay` on the Geek board (ARM only). This shows the exact types and method calls the implementation agent should use.

```rust
// firmware/src/board/rp2350_geek.rs — additions

#[cfg(target_arch = "arm")]
use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{OriginDimensions, Size},
    pixelcolor::{raw::RawU16, Rgb565},
    primitives::Rectangle,
    Pixel,
};

#[cfg(target_arch = "arm")]
impl OriginDimensions for St7789StatusDisplay {
    fn size(&self) -> Size {
        Size::new(LCD_WIDTH as u32, LCD_HEIGHT as u32)
    }
}

#[cfg(target_arch = "arm")]
impl DrawTarget for St7789StatusDisplay {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        for Pixel(point, color) in pixels {
            if point.x < 0 || point.y < 0
                || point.x >= LCD_WIDTH as i32
                || point.y >= LCD_HEIGHT as i32
            {
                continue;
            }
            let x = point.x as u16 + LCD_COL_OFFSET;
            let y = point.y as u16 + LCD_ROW_OFFSET;
            // 1×1 window
            self.write_command_data(ST7789_CASET, &[
                (x >> 8) as u8, (x & 0xFF) as u8,
                (x >> 8) as u8, (x & 0xFF) as u8,
            ]);
            self.write_command_data(ST7789_RASET, &[
                (y >> 8) as u8, (y & 0xFF) as u8,
                (y >> 8) as u8, (y & 0xFF) as u8,
            ]);
            let raw: u16 = RawU16::from(color).into_inner();
            let bytes = [(raw >> 8) as u8, (raw & 0xFF) as u8];
            self.dc.set_low();
            self.cs_assert();
            let _ = self.spi.blocking_write(&[ST7789_RAMWR]);
            self.dc.set_high();
            let _ = self.spi.blocking_write(&bytes);
            self.cs_deassert();
        }
        Ok(())
    }

    fn fill_contiguous<I>(
        &mut self,
        area: &Rectangle,
        colors: I,
    ) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Self::Color>,
    {
        use embedded_graphics::prelude::*;

        let drawable = area.intersection(&self.bounding_box());
        if drawable.size == Size::zero() {
            return Ok(());
        }

        let x0 = drawable.top_left.x as u16 + LCD_COL_OFFSET;
        let y0 = drawable.top_left.y as u16 + LCD_ROW_OFFSET;
        let x1 = x0 + drawable.size.width as u16 - 1;
        let y1 = y0 + drawable.size.height as u16 - 1;
        let row_w = drawable.size.width as usize;

        self.write_command_data(ST7789_CASET, &[
            (x0 >> 8) as u8, (x0 & 0xFF) as u8,
            (x1 >> 8) as u8, (x1 & 0xFF) as u8,
        ]);
        self.write_command_data(ST7789_RASET, &[
            (y0 >> 8) as u8, (y0 & 0xFF) as u8,
            (y1 >> 8) as u8, (y1 & 0xFF) as u8,
        ]);

        self.dc.set_low();
        self.cs_assert();
        let _ = self.spi.blocking_write(&[ST7789_RAMWR]);
        self.dc.set_high();

        // Row buffer on stack (240 px × 2 bytes = 480 bytes max)
        let mut row_buf = [0u8; LCD_WIDTH as usize * 2];
        let mut col = 0usize;

        for color in colors {
            let raw: u16 = RawU16::from(color).into_inner();
            row_buf[col * 2]     = (raw >> 8) as u8;
            row_buf[col * 2 + 1] = (raw & 0xFF) as u8;
            col += 1;
            if col == row_w {
                let _ = self.spi.blocking_write(&row_buf[..row_w * 2]);
                col = 0;
            }
        }
        // Flush any partial row (should not happen for well-formed rectangles)
        if col > 0 {
            let _ = self.spi.blocking_write(&row_buf[..col * 2]);
        }

        self.cs_deassert();
        Ok(())
    }

    fn fill_solid(
        &mut self,
        area: &Rectangle,
        color: Self::Color,
    ) -> Result<(), Self::Error> {
        let n = (area.size.width * area.size.height) as usize;
        self.fill_contiguous(area, core::iter::repeat(color).take(n))
    }
}
```

### Render function using embedded-graphics

```rust
// Example render function (ARM only)
#[cfg(target_arch = "arm")]
fn render_status_screen(display: &mut St7789StatusDisplay, state: &DisplayState) {
    use embedded_graphics::{
        mono_font::{ascii::{FONT_6X13, FONT_6X13_BOLD, FONT_9X15_BOLD}, MonoTextStyle},
        pixelcolor::Rgb565,
        prelude::*,
        primitives::{Line, PrimitiveStyle, PrimitiveStyleBuilder, Rectangle},
        text::Text,
    };

    // ── Header bar ──────────────────────────────────────────────────────────
    let header_style = PrimitiveStyleBuilder::new()
        .fill_color(Rgb565::new(0, 5, 20))  // dark navy
        .build();
    Rectangle::new(Point::zero(), Size::new(LCD_WIDTH as u32, 18))
        .into_styled(header_style)
        .draw(display).ok();

    Text::new(
        "pico2hsm",
        Point::new(4, FONT_9X15_BOLD.baseline as i32 + 1),
        MonoTextStyle::new(&FONT_9X15_BOLD, Rgb565::WHITE),
    ).draw(display).ok();

    // ── Divider ─────────────────────────────────────────────────────────────
    Line::new(Point::new(0, 18), Point::new(LCD_WIDTH as i32 - 1, 18))
        .into_styled(PrimitiveStyle::with_stroke(Rgb565::CSS_GRAY, 1))
        .draw(display).ok();

    // ── Status rows ─────────────────────────────────────────────────────────
    let label_style = MonoTextStyle::new(&FONT_6X13, Rgb565::CSS_GRAY);
    let value_style = MonoTextStyle::new(&FONT_6X13_BOLD, Rgb565::WHITE);
    let body_bg = Rgb565::BLACK;

    // Row 1: Keys
    let y1 = 18 + 2 + FONT_6X13.baseline as i32;
    Text::new("Keys:", Point::new(4, y1), label_style).draw(display).ok();
    // ... format key_count as heapless string then draw

    // Row 2: Auth
    let y2 = y1 + 16;
    Text::new("Auth:", Point::new(4, y2), label_style).draw(display).ok();
    let auth_val = if state.authenticated { "YES" } else { "no" };
    Text::new(auth_val, Point::new(52, y2), value_style).draw(display).ok();

    // Row 3: Storage
    let y3 = y2 + 16;
    Text::new("Store:", Point::new(4, y3), label_style).draw(display).ok();
    let store_val = if state.storage_ok { "OK" } else { "ERR" };
    Text::new(store_val, Point::new(52, y3), value_style).draw(display).ok();
}
```

Note: formatting integers requires `heapless::String` or `write!` with a `heapless::String` buffer:
```rust
use heapless::String;
use core::fmt::Write;
let mut buf: String<8> = String::new();
write!(buf, "{}", state.key_count).ok();
Text::new(&buf, Point::new(52, y1), value_style).draw(display).ok();
```

---

## 9. Key decisions summary

| Decision | Recommendation | Rationale |
|---|---|---|
| embedded-graphics version | 0.8.2 | Latest stable; no_std+no_alloc confirmed |
| Use mipidsi or st7789 crate | No — implement DrawTarget directly | Avoids new dependency; 60-line impl on existing struct |
| DrawTarget::draw_iter | Implement as per-pixel fallback | Required by trait |
| DrawTarget::fill_contiguous | Override with row-buffer batching | Critical for performance; used by all filled shapes and text |
| Font for header / large text | FONT_9X15_BOLD | Good readability at 135–172 px display height |
| Font for labels / body text | FONT_6X13 / FONT_6X13_BOLD | Fits 5–7 rows on Geek; 6–8 rows on Waveshare |
| profont crate | Optional / skip for now | Built-in fonts are sufficient |
| u8g2-fonts | Skip | Overkill; adds complexity |
| Full vs partial screen update | Full redraw on state change | ~20–26 ms is imperceptible; no dirty-rect needed |
| Waveshare LCD landscape MADCTL | 0x60 | MX+MV = 90° CW; CASET 0–319, RASET 0–171 |
| Pixel write budget | 20–26 ms full screen | Well within the 1.5 s CCID time-extension window |
