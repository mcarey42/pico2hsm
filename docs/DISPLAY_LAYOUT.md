# pico2hsm — Display Layout Specification

This document is the authoritative UI/UX specification for the pico2hsm status
display.  It covers both supported display targets, the shared zone system, color
palette, font selection, and pixel-precise bounds that an implementation agent can
use directly.

---

## 1. Color Palette

All colors expressed as RGB565 hex values (16-bit, big-endian as transmitted over SPI).

### 1.1 Background and Structure

| Role                    | RGB565   | Approximate sRGB  | Notes                              |
|-------------------------|----------|-------------------|------------------------------------|
| Screen background       | `0x0841` | #080808 (near-black) | Avoids pure black; allows subtle border visibility |
| Header bar background   | `0x18C3` | #181818           | Slightly lighter than screen background |
| Divider / border line   | `0x2945` | #292929           | Used for zone separators           |
| Info cell background    | `0x10A2` | #101010           | Subtle card background within grid |
| Banner background (overlay) | `0x0020` | #000040       | Dark navy — clearly differs from status colors |

### 1.2 Text Colors

| Role             | RGB565   | Approximate sRGB | Notes                                   |
|------------------|----------|------------------|-----------------------------------------|
| Primary text     | `0xEF7D` | #EFEFEF          | Labels and values (high contrast on dark) |
| Secondary text   | `0x9CF3` | #9C9C9C          | Sub-labels, units, "Keys:", "Auth:" prefixes |
| Dim text         | `0x6B4D` | #686868          | Uptime, low-priority metadata           |
| Disabled/Off     | `0x4228` | #404040          | Fields that are inactive (e.g., no error) |

### 1.3 Status Colors (matching existing `LedStatus` mapping)

These are the canonical status pill/indicator fill colors used in the existing
`status_color()` function in both board drivers.  Do not alter these values.

| `LedStatus`    | RGB565   | Color name   |
|----------------|----------|--------------|
| Off            | `0x0000` | Black        |
| Ready          | `0x07E0` | Green        |
| Busy           | `0x001F` | Blue         |
| Error          | `0xF800` | Red          |
| Degraded       | `0xFFE0` | Yellow       |
| Resyncing      | `0x07FF` | Cyan         |
| WaitingForPin  | `0x031F` | Bright blue  |

### 1.4 Semantic Colors

| Role                   | RGB565   | Color name         | Notes                              |
|------------------------|----------|--------------------|------------------------------------|
| Success accent         | `0x07E0` | Green              | Same as Ready; for "OK" indicators |
| Warning accent         | `0xFFE0` | Yellow             | Same as Degraded                   |
| Error/alert accent     | `0xF800` | Red                | Same as Error; for error border/banner |
| Authentication active  | `0x3666` | Teal-ish green     | Auth=YES indicator text tint       |
| Authentication inactive| `0x6B4D` | Dim gray           | Auth=NO                            |
| Storage OK             | `0x07E0` | Green              | storage_ok = true                  |
| Storage degraded       | `0xF800` | Red                | storage_ok = false                 |
| Context banner (success)| `0x0320`| Very dark green    | Banner background when op succeeded |
| Context banner (error) | `0x4000` | Very dark red      | Banner background when op failed    |

---

## 2. Main Screen Layout — RP2350-Geek (240×135)

### 2.1 Physical Properties

- Controller: ST7789, MADCTL=0x70 (landscape, MX+MV+BGR)
- Logical resolution: 240 wide × 135 tall (already in landscape orientation)
- Column offset in CASET: 52; row offset in RASET: 40 (handled by driver, not layout)
- All layout coordinates are in logical pixels (0,0 = top-left of the 240×135 frame)

### 2.2 Zone Definitions

```
x=0                                                       x=239
y=0  ┌─────────────────────────────────────────────────────┐
     │ HEADER BAR                          (240 × 18 px)   │
     │ "pico2hsm"  [STATUS PILL 48×12]  00:00:00           │
y=18 ├─────────────────────────────────────────────────────┤  ← 1px divider line
y=19 │                                                     │
     │  INFO GRID  (240 × 114 px, y=19..132)               │
     │                                                     │
     │  ┌──────────────┬──────────────┬──────────────────┐ │
     │  │  KEYS CELL   │  AUTH CELL   │   STORAGE CELL   │ │
     │  │  (78×50)     │  (78×50)     │   (82×50)        │ │
     │  │  y=21..70    │  y=21..70    │   y=21..70       │ │
     │  │              │              │                  │ │
     │  │  Keys        │  Auth        │   Storage        │ │
     │  │  12          │  YES         │   OK             │ │
     │  ├──────────────┴──────────────┴──────────────────┤ │
     │  │  LAST OP / UPTIME ROW  (236 × 42 px, y=72..113)│ │
     │  │  Last op: Sign        Up: 00:23:41              │ │
     │  └─────────────────────────────────────────────────┘ │
y=133├─────────────────────────────────────────────────────┤  ← 1px bottom divider
y=134│ STATUS BAR  (240 × 1 px)  — filled with status color│
y=135└─────────────────────────────────────────────────────┘
```

### 2.3 Zone Pixel Bounds

#### Header Bar
| Property     | Value                           |
|--------------|---------------------------------|
| Bounds       | x=0, y=0, w=240, h=18          |
| Background   | `0x18C3` (header bg)           |
| Left text    | "pico2hsm" — FONT_6X10, primary text, x=4, y=4 |
| Center       | Status pill — x=86, y=3, w=68, h=12 |
| Right text   | Uptime HH:MM:SS — FONT_6X10, dim text, right-aligned at x=236, y=4 |

**Status pill** (within header):
- Bounds: x=86, y=3, w=68, h=12
- Fill: status color from `LedStatus` mapping
- Text (inside pill): status name string, FONT_6X10, contrasting color
  - For dark status fills (Busy, Error): white `0xFFFF`
  - For light status fills (Ready/green, Degraded/yellow, Resyncing/cyan): black `0x0000`
  - "READY" / "BUSY" / "ERROR" / "DEGRADED" / "RESYNCING" / "PIN WAIT" / "OFF"

**Uptime** (within header, right side):
- Format: `HH:MM:SS` when uptime < 24 h; `Dd HH:MM` when uptime >= 24 h
- Text: FONT_6X10, dim text `0x6B4D`
- Bounds: right-aligned, x=168, y=4, w=68, h=10

#### Divider Line (header/body separator)
| Property | Value                        |
|----------|------------------------------|
| Bounds   | x=0, y=18, w=240, h=1       |
| Fill     | `0x2945` (divider color)     |

#### Info Grid — Upper Row (3 cells)
The 236 px interior (240 minus 2px for left/right margins) is divided into 3 cells
with 2px inter-cell gaps.

| Cell     | x   | y  | w  | h  | Content                                  |
|----------|-----|----|----|----|------------------------------------------|
| Keys     | 2   | 21 | 76 | 49 | Label "Keys" + value (key_count as decimal) |
| Auth     | 80  | 21 | 76 | 49 | Label "Auth" + value "YES"/"NO"          |
| Storage  | 158 | 21 | 80 | 49 | Label "Storage" + value "OK"/"FAIL"      |

Each cell:
- Background: `0x10A2` (info cell bg), filled rectangle
- Label: FONT_6X10, secondary text `0x9CF3`, y-offset +4 from cell top, x-offset +4
- Value: FONT_8X13, primary text (or status-colored), y-offset +18 from cell top, x-offset +4
- Auth "YES": teal `0x3666`; Auth "NO": dim `0x6B4D`
- Storage "OK": green `0x07E0`; Storage "FAIL": red `0xF800`
- key_count value: primary text `0xEF7D`

#### Info Grid — Lower Row (last op + uptime)
| Property | Value                                          |
|----------|------------------------------------------------|
| Bounds   | x=2, y=72, w=236, h=42                        |
| Background | `0x10A2`                                    |
| Left column | "Last op:" label FONT_6X10 secondary, x=6, y=76 |
| Left value  | Operation name FONT_8X13 primary, x=6, y=88  |
| Right column | "Up:" label FONT_6X10 secondary, x=150, y=76 |
| Right value  | Uptime FONT_8X13 dim, x=150, y=88           |

When `last_op` is None, left value shows "--" in dim text.
When `last_op` is Some, left value shows the operation name (see Section 4 for naming).

#### Status Stripe (bottom)
| Property | Value                                          |
|----------|------------------------------------------------|
| Bounds   | x=0, y=134, w=240, h=1                        |
| Fill     | Current `LedStatus` status color               |

This 1px stripe gives a persistent at-a-glance color indicator at the very bottom
edge, similar to a status LED. It is always the status color regardless of other
display content.

### 2.4 Per-Status Appearance Changes

| Status         | Header pill        | Bottom stripe  | Background | Notes               |
|----------------|--------------------|----------------|------------|---------------------|
| Off            | Black pill, "OFF"  | Black          | Normal     | Screensaver if >5min |
| Ready          | Green, "READY"     | Green          | Normal     |                      |
| Busy           | Blue, "BUSY"       | Blue           | Normal     | Animate with spinner if feasible |
| Error          | Red, "ERROR"       | Red            | Red border | See Section 5        |
| Degraded       | Yellow, "DEGRADED" | Yellow         | Normal     |                      |
| Resyncing      | Cyan, "RESYNCING"  | Cyan           | Normal     |                      |
| WaitingForPin  | Bright blue, "PIN WAIT" | Bright blue | Normal  |                      |

---

## 3. Main Screen Layout — Waveshare LCD-1.47 (logical 320×172 landscape)

### 3.1 Physical Properties

- Controller: ST7789V3, MADCTL=0x00 (portrait native: 172 wide × 320 tall)
- **After MADCTL rotation** the firmware uses MADCTL=0x70 (or equivalent) to present
  a **logical 320 wide × 172 tall** landscape surface to the renderer.
- All layout coordinates below are in logical landscape pixels (0,0 = top-left of
  the 320×172 rotated frame).
- Effective rendering area: 320×172 px.

**Note for implementation**: The Waveshare LCD-1.47 board doc specifies `MADCTL=0x00`
(normal portrait) in the current init sequence.  To use landscape orientation, change
MADCTL to `0x70` (same as the Geek board: MX|MV|BGR).  With MADCTL=0x70, CASET
covers 0–171 (172 columns), RASET covers 0–319 (320 rows), producing a 320×172
logical landscape frame.  Alternatively, MADCTL=0x60 (MY|MV|BGR) gives 320×172
with the opposite horizontal flip — test on hardware to confirm preferred orientation.

### 3.2 Zone Definitions

```
x=0                                                                  x=319
y=0  ┌──────────────────────────────────────────────────────────────────┐
     │  HEADER BAR                                  (320 × 22 px)       │
     │  "pico2hsm"   [STATUS PILL 80×14]  00:00:00                      │
y=22 ├──────────────────────────────────────────────────────────────────┤  1px divider
y=23 │                                                                  │
     │  INFO GRID  (320 × 147 px, y=23..169)                            │
     │                                                                  │
     │  ┌───────────┬───────────┬───────────┬──────────────────────┐    │
     │  │KEYS CELL  │AUTH CELL  │STORAGE    │  UPTIME CELL         │    │
     │  │(74×62)    │(74×62)    │(74×62)    │  (90×62)             │    │
     │  │x=2,y=25   │x=78,y=25  │x=154,y=25 │  x=230,y=25         │    │
     │  │           │           │           │                      │    │
     │  │Keys       │Auth       │Storage    │  Uptime              │    │
     │  │12         │YES        │OK         │  00:23:41            │    │
     │  ├───────────┴───────────┴───────────┴──────────────────────┤    │
     │  │  LAST OPERATION ROW  (316 × 52 px, y=90..141)            │    │
     │  │  Last operation:  ECDSA-P256 Sign                        │    │
     │  └──────────────────────────────────────────────────────────┘    │
y=170├──────────────────────────────────────────────────────────────────┤  1px divider
y=171│  STATUS STRIPE  (320 × 1 px) — filled with status color          │
y=172└──────────────────────────────────────────────────────────────────┘
```

### 3.3 Zone Pixel Bounds

#### Header Bar
| Property    | Value                              |
|-------------|------------------------------------|
| Bounds      | x=0, y=0, w=320, h=22             |
| Background  | `0x18C3`                          |
| Left text   | "pico2hsm" — FONT_8X13, primary text, x=5, y=5 |
| Center      | Status pill — x=110, y=4, w=100, h=14 |
| Right text  | Uptime — FONT_8X13, dim text, right-aligned at x=315, y=5 |

**Status pill** (within header):
- Bounds: x=110, y=4, w=100, h=14
- Fill: `LedStatus` color
- Text: status name, FONT_6X10 centered, contrasting color
- Status name strings: same as Geek (READY / BUSY / ERROR / DEGRADED / RESYNCING / PIN WAIT / OFF)

**Uptime** (within header, right side):
- Format: `HH:MM:SS` when < 24 h; `Nd HH:MM` when >= 24 h (N = days)
- Text: FONT_8X13, dim text `0x6B4D`
- Bounds: x=220, y=5, w=95, h=13

#### Divider Line
| Property | Value                        |
|----------|------------------------------|
| Bounds   | x=0, y=22, w=320, h=1       |
| Fill     | `0x2945`                     |

#### Info Grid — Upper Row (4 cells)
The 316 px interior is divided into 4 cells with 2px gaps.

| Cell     | x   | y  | w  | h  | Content                                    |
|----------|-----|----|----|----|---------------------------------------------|
| Keys     | 2   | 25 | 74 | 62 | "Keys" label + key_count decimal            |
| Auth     | 78  | 25 | 74 | 62 | "Auth" label + "YES"/"NO"                   |
| Storage  | 154 | 25 | 74 | 62 | "Storage" label + "OK"/"FAIL"              |
| Uptime   | 230 | 25 | 88 | 62 | "Uptime" label + HH:MM:SS value            |

Each cell:
- Background: `0x10A2`
- Label: FONT_6X10, secondary text `0x9CF3`, y-offset +5, x-offset +5
- Value: FONT_8X13, appropriate color, y-offset +22, x-offset +5
- Auth/Storage colors: same as Geek definition above
- Uptime value color: dim text `0x6B4D`

#### Last Operation Row
| Property    | Value                                              |
|-------------|----------------------------------------------------|
| Bounds      | x=2, y=90, w=316, h=52                            |
| Background  | `0x10A2`                                          |
| Label text  | "Last operation:" FONT_6X10, secondary, x=6, y=94 |
| Value text  | Operation name FONT_8X13, primary, x=6, y=108     |
| Sub-label   | "slot 0x??" if applicable, FONT_6X10, secondary, x=6, y=124 |

When `last_op` is None: value text shows "—" in dim text.
Operation names for the larger display use the verbose form (see Section 4).

#### Status Stripe (bottom)
| Property | Value                          |
|----------|--------------------------------|
| Bounds   | x=0, y=171, w=320, h=1        |
| Fill     | Current `LedStatus` color      |

---

## 4. Context Banner (both displays)

The context banner is a full-width overlay strip that appears at the bottom of the
screen for 3 seconds after a `last_op` becomes Some, then dismisses itself and
returns to the main info grid view.

### 4.1 Geek (240×135) — Context Banner

| Property     | Value                                         |
|--------------|-----------------------------------------------|
| Bounds       | x=0, y=98, w=240, h=36                       |
| Background   | Dark green `0x0320` (success) or dark red `0x4000` (error) |
| Border top   | 1px line in `0x07E0` (success) or `0xF800` (error) |
| Icon text    | "+" (success) or "!" (error), FONT_8X13, at x=8, y=103 |
| Operation text | Short op name, FONT_8X13, primary `0xEF7D`, x=24, y=103 |
| Sub-text     | Slot/detail if available, FONT_6X10, secondary `0x9CF3`, x=24, y=117 |

The banner **overlays** the lower info row (y=72..113); the upper grid cells remain
fully visible while the banner is active.

#### Operation Short Names (Geek, space-constrained)

| `LastOperation` | Short display string |
|-----------------|----------------------|
| Sign            | `Sign`               |
| Verify          | `Verify`             |
| KeyGen          | `Key Generated`      |
| ECDH            | `ECDH`               |
| Decrypt         | `Decrypt`            |
| Encrypt         | `Encrypt`            |
| DeriveKey       | `Key Derived`        |
| Initialize      | `Initialize`         |
| DeleteKey       | `Key Deleted`        |

When a key slot is known: append ` [0x??]` to the operation string, FONT_6X10, dim,
on the sub-text line.

### 4.2 Waveshare LCD-1.47 (320×172) — Context Banner

| Property     | Value                                         |
|--------------|-----------------------------------------------|
| Bounds       | x=0, y=120, w=320, h=50                      |
| Background   | Dark green `0x0320` (success) or dark red `0x4000` (error) |
| Border top   | 1px in `0x07E0` / `0xF800`                   |
| Icon text    | "+" or "!", FONT_8X13, x=10, y=127           |
| Operation text | Verbose op name, FONT_8X13, primary, x=30, y=127 |
| Sub-text     | "slot 0x??" or detail, FONT_6X10, secondary, x=30, y=143 |

#### Operation Verbose Names (LCD-1.47, wider display)

| `LastOperation` | Verbose display string |
|-----------------|------------------------|
| Sign            | `ECDSA Sign`           |
| Verify          | `Signature Verify`     |
| KeyGen          | `Key Generated`        |
| ECDH            | `ECDH Exchange`        |
| Decrypt         | `Decrypt`              |
| Encrypt         | `Encrypt`              |
| DeriveKey       | `Key Derived`          |
| Initialize      | `HSM Initialize`       |
| DeleteKey       | `Key Deleted`          |

### 4.3 Banner Lifecycle

1. `last_op` transitions from None to Some(op) — immediately render banner.
2. Timer starts (3 000 ms).
3. On timer expiry: re-render info grid over the banner area; set `last_op` display
   back to showing the persistent "last op" label in the lower info cell.
4. If a new `last_op` arrives during the 3 s window: restart timer, update banner text.

---

## 5. Error State

When `error_msg` is Some, the layout is modified as follows on both displays.

### 5.1 Visual Treatment

1. **Red border** — a 2px red (`0xF800`) border is drawn around the outermost screen
   rectangle on all four edges.  This is rendered after all content and persists for
   as long as `error_msg` is Some.
2. **Info grid — lower row replaced** — the lower info row (Last op / Uptime) is
   replaced by the `error_msg` string.
   - FONT_6X10, red text `0xF800`, word-wrapped within the cell bounds.
   - If the error string is longer than the cell width allows, truncate with "…"
     (Unicode U+2026 is not available in MonoFont; use `...` three dots instead).
3. **Status pill** — always shows "ERROR" with red fill while `error_msg` is Some,
   regardless of the `LedStatus` value reported.
4. **Bottom stripe** — always red `0xF800` while error is active.

### 5.2 Error Dismissal

`error_msg` is persistent — it stays until the firmware clears it (e.g., after a
successful INITIALIZE or a power cycle).  No auto-dismiss timer.

### 5.3 Geek Error Layout Specifics

| Modified zone        | Change                                               |
|----------------------|------------------------------------------------------|
| Outer border         | 2px `0xF800` on x=0..1, x=238..239, y=0..1, y=133..134 |
| Lower info row (y=72..113) | Replaced by error_msg text, `0xF800`, FONT_6X10 |
| Header pill          | "ERROR", red fill                                    |

### 5.4 LCD-1.47 Error Layout Specifics

| Modified zone        | Change                                               |
|----------------------|------------------------------------------------------|
| Outer border         | 2px `0xF800` on x=0..1, x=318..319, y=0..1, y=170..171 |
| Last op row (y=90..141) | Replaced by error_msg text, `0xF800`, FONT_6X10 |
| Header pill          | "ERROR", red fill                                    |

---

## 6. Screensaver

After 300 seconds (5 minutes) of idle (no APDU received, `status` == Ready):

- **Fill the entire screen with `0x0000` (black).**
- **Disable the backlight** (BL pin LOW).
- No animation; no burn-in pattern.  Pure off.

On any APDU arrival or status change:
- **Re-enable backlight** (BL pin HIGH).
- **Re-render the full main screen.**

Idle tracking: maintained by core0; reset on every APDU dispatch.  The screensaver
trigger is a timer task that checks idle seconds after each 30 s tick.

---

## 7. Scaling Rules

The layout is parameterized by `(W, H)` where `W` and `H` are the logical landscape
dimensions of the target display.

### 7.1 Zone Height Formulas

| Zone                | Formula                        | Geek (135) | LCD-1.47 (172) |
|---------------------|--------------------------------|------------|----------------|
| Header bar height   | `max(18, H / 7)`               | 19 → 18px  | 24 → 22px      |
| Header divider      | 1px fixed                      | 1          | 1              |
| Upper info cells h  | `(H - header_h - 1 - lower_row_h - 2) / 2 * 1.1` | 49px | 62px |
| Lower row height    | `H - header_h - 1 - upper_cell_h - 3` | 42px | 52px |
| Bottom stripe       | 1px fixed                      | 1          | 1              |

In practice, for any display with `H < 150`: use the Geek layout constants.
For `H >= 150`: use the LCD-1.47 layout constants.

### 7.2 Info Grid Column Count

| Condition    | Column count | Rationale                                      |
|--------------|--------------|------------------------------------------------|
| W < 280      | 3 columns    | Geek 240px — Keys, Auth, Storage               |
| W >= 280     | 4 columns    | LCD-1.47 320px — Keys, Auth, Storage, Uptime   |

When 4 columns are available, move the uptime value from the header right-side to
the 4th info cell, and use the header right slot only for a more compact `HH:MM`
format.

### 7.3 Font Selection Rule

| Condition         | Primary value font | Label/secondary font |
|-------------------|--------------------|----------------------|
| H < 150           | FONT_8X13          | FONT_6X10            |
| 150 <= H < 200    | FONT_8X13          | FONT_6X10            |
| H >= 200          | FONT_10X20         | FONT_8X13            |

The Geek (H=135) and LCD-1.47 (H=172) both fall below H=200, so both use
FONT_8X13 for values and FONT_6X10 for labels.

### 7.4 Status Pill Width Rule

`pill_width = min(W / 4, 100)` pixels.  On Geek: min(60, 100) = 60 → round to 68
(text padding).  On LCD-1.47: min(80, 100) = 80 → round to 100.

### 7.5 Minimum Useful Display Size

- Minimum W: 200 px — below this, the 3-column grid is too narrow for readable labels.
- Minimum H: 100 px — below this, the header + two rows cannot fit at any font size.

---

## 8. Font Recommendations

All fonts are from the `embedded-graphics` crate, `mono_font` module.  The crate
must be added to `Cargo.toml` as a target-agnostic dependency (it has no hardware
requirements):

```toml
[dependencies]
embedded-graphics = { version = "0.8", default-features = false }
```

The `embedded-graphics` 0.8.x font names and pixel sizes are:

### 8.1 Font Table

| Role                          | Font constant (embedded-graphics 0.8.x)         | Glyph size | Use                             |
|-------------------------------|--------------------------------------------------|------------|---------------------------------|
| Header title ("pico2hsm")     | `mono_font::ascii::FONT_8X13`                   | 8×13 px    | Title text in header bar        |
| Status pill text              | `mono_font::ascii::FONT_6X10`                   | 6×10 px    | Status name inside 12–14 px pill |
| Info cell value (large)       | `mono_font::ascii::FONT_8X13`                   | 8×13 px    | key_count, YES/NO, OK/FAIL      |
| Info cell label (small)       | `mono_font::ascii::FONT_6X10`                   | 6×10 px    | "Keys", "Auth", "Storage" captions |
| Uptime value                  | `mono_font::ascii::FONT_8X13`                   | 8×13 px    | HH:MM:SS display                |
| Context banner operation name | `mono_font::ascii::FONT_8X13`                   | 8×13 px    | "ECDSA Sign", "Key Generated"   |
| Context banner detail         | `mono_font::ascii::FONT_6X10`                   | 6×10 px    | Slot number, sub-detail         |
| Error message text            | `mono_font::ascii::FONT_6X10`                   | 6×10 px    | Wrapped error string            |
| Dim metadata (secondary)      | `mono_font::ascii::FONT_6X10`                   | 6×10 px    | Low-priority info               |

### 8.2 Text Rendering Notes

- `embedded-graphics` `Text` + `MonoTextStyle` is the correct abstraction.
  Use `MonoTextStyleBuilder` to set font, text color, and background color.
- Background color for text: use `None` (transparent) over colored cells, or set to
  the cell background color to avoid rendering artifacts on partial updates.
- For right-aligned text (uptime in header), calculate the string pixel width as
  `string.len() * font.character_size.width` and subtract from the right edge x.
- Clipping: wrap text rendering in an embedded-graphics `Clipped` viewport bounded
  to the target cell rectangle to prevent overflow into adjacent zones.

### 8.3 Character Width Reference

| Font        | Char width | Max chars in 76px cell | Max chars in 240px row |
|-------------|------------|------------------------|------------------------|
| FONT_6X10   | 6 px       | 12                     | 40                     |
| FONT_8X13   | 8 px       | 9                      | 30                     |
| FONT_10X20  | 10 px      | 7                      | 24                     |

Within a 76px-wide cell using FONT_8X13: 9 characters maximum.  Key count values
are at most 3 digits; "YES"/"NO" are 2–3 chars; "OK"/"FAIL" are 2–4 chars —
all fit comfortably.

---

## 9. Implementation Checklist

The following items must be addressed when implementing this spec:

- [ ] Add `embedded-graphics = { version = "0.8", default-features = false }` to
  `firmware/Cargo.toml` under platform-agnostic dependencies.
- [ ] Add `embedded-graphics-core = { version = "0.4" }` if needed for `DrawTarget`.
- [ ] Implement a `DrawTarget` wrapper over the existing `fill_screen()` / row-write
  SPI path, or adopt `mipidsi` crate which provides a ready `DrawTarget` for ST7789.
- [ ] For the Waveshare LCD-1.47, change MADCTL from `0x00` to `0x70` in
  `waveshare_rp2350_lcd.rs` `st7789v3_init()` to enable logical landscape orientation,
  and update CASET (0–171) / RASET (0–319) accordingly.
- [ ] Add `DisplayState` struct fields for `uptime_secs: u64`, `last_op: Option<LastOperation>`,
  and `error_msg: Option<&'static str>` to the existing `DisplayState` struct in
  `rp2350_geek.rs` (and create an equivalent in `waveshare_rp2350_lcd.rs`).
- [ ] Implement screensaver idle timer on core0 — increment `idle_secs` counter,
  reset on APDU, trigger screensaver at 300 s.
- [ ] Context banner timer: 3 s countdown, re-render on expiry.  Use Embassy
  `embassy_time::Timer::after(Duration::from_secs(3))` in the display task.
