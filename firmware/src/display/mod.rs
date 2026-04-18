//! Status display rendering for pico2hsm.
//!
//! Provides [`DisplayState`], [`LastOperation`], [`ScreensaverState`], and
//! the [`render()`] free function that draws a complete info-dense UI onto any
//! `DrawTarget<Color = Rgb565>` — currently sized for the 240×135 Geek board.
//!
//! The module is ARM-only (gated at `lib.rs` level); no `#[cfg]` guards are
//! needed here.  No heap allocation is used — number formatting goes through
//! [`heapless::String`].

use crate::board::LedStatus;
use core::fmt::Write as FmtWrite;
use embedded_graphics::{
    mono_font::{
        ascii::{FONT_6X10, FONT_8X13},
        MonoTextStyle,
    },
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
    text::{Baseline, Text, TextStyle, TextStyleBuilder},
    Drawable,
};
use heapless::String;

// ── Constants ────────────────────────────────────────────────────────────────

/// How long to show last_op before reverting to "--" (seconds).
pub const LAST_OP_DISPLAY_SECS: u32 = 3;

/// Screensaver activates after this many idle seconds.
pub const SCREENSAVER_TIMEOUT_SECS: u32 = 300;

// ── Enums ────────────────────────────────────────────────────────────────────

/// The most recent HSM operation, shown in the Last op cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, defmt::Format)]
pub enum LastOperation {
    Sign,
    Verify,
    KeyGen,
    Ecdh,
    Decrypt,
    Encrypt,
    DeriveKey,
    Initialize,
    DeleteKey,
    Other,
}

/// Whether the display is actively rendering or blanked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreensaverState {
    Active,
    Sleeping,
}

// ── DisplayState ─────────────────────────────────────────────────────────────

/// Complete state for one display frame.  All fields are `Copy`.
#[derive(Debug, Clone, Copy)]
pub struct DisplayState {
    /// Overall HSM status — maps to status pill colour.
    pub status: LedStatus,
    /// Number of stored key objects.
    pub key_count: u8,
    /// RAID health (`true` = both mirrors healthy).
    pub storage_ok: bool,
    /// PIN session active.
    pub authenticated: bool,
    /// Last op and the `uptime_secs` when it completed.
    /// Expires after [`LAST_OP_DISPLAY_SECS`].
    pub last_op: Option<(LastOperation, u32)>,
    /// Persistent error message (static string literal).
    pub error_msg: Option<&'static str>,
    /// Seconds since firmware boot (wraps at ~136 years).
    pub uptime_secs: u32,
    /// Health of QMI flash primary store. None = not tracked (non-hybrid boards).
    pub qmi_ok: Option<bool>,
    /// Health of SD card secondary store. None = not present/tracked.
    pub sd_ok: Option<bool>,
    /// Whether the device OTP is provisioned.
    pub provisioned: bool,
}

impl DisplayState {
    /// Construct a zeroed-out initial state.
    pub const fn new() -> Self {
        Self {
            status: LedStatus::Off,
            key_count: 0,
            storage_ok: true,
            authenticated: false,
            last_op: None,
            error_msg: None,
            uptime_secs: 0,
            qmi_ok: None,
            sd_ok: None,
            provisioned: true,
        }
    }
}

// ── Color palette ─────────────────────────────────────────────────────────────

/// Convert a raw RGB565 `u16` to an embedded-graphics [`Rgb565`].
const fn rgb565(raw: u16) -> Rgb565 {
    Rgb565::new(
        ((raw >> 11) & 0x1F) as u8,
        ((raw >> 5) & 0x3F) as u8,
        (raw & 0x1F) as u8,
    )
}

// Background / structure
const COLOR_BG: Rgb565 = rgb565(0x0841); // near-black
const COLOR_HEADER_BG: Rgb565 = rgb565(0x18C3); // dark gray header
const COLOR_DIVIDER: Rgb565 = rgb565(0x2945); // separator line
const COLOR_CELL_BG: Rgb565 = rgb565(0x10A2); // info cell background

// Text
const COLOR_TEXT_PRI: Rgb565 = rgb565(0xEF7D); // primary text (near-white)
const COLOR_TEXT_SEC: Rgb565 = rgb565(0x9CF3); // secondary text (gray)
const COLOR_TEXT_DIM: Rgb565 = rgb565(0x6B4D); // dim text (dark gray)

// Semantic
const COLOR_GREEN: Rgb565 = rgb565(0x07E0);
const COLOR_RED: Rgb565 = rgb565(0xF800);
const COLOR_TEAL: Rgb565 = rgb565(0x3666); // auth=YES

// ── Status helpers ────────────────────────────────────────────────────────────

fn status_color(s: LedStatus) -> Rgb565 {
    match s {
        LedStatus::Off => rgb565(0x0000),
        LedStatus::Ready => rgb565(0x07E0),
        LedStatus::Busy => rgb565(0x001F),
        LedStatus::Error => rgb565(0xF800),
        LedStatus::Degraded => rgb565(0xFFE0),
        LedStatus::Resyncing => rgb565(0x07FF),
        LedStatus::WaitingForPin => rgb565(0x031F),
    }
}

fn status_name(s: LedStatus) -> &'static str {
    match s {
        LedStatus::Off => "OFF",
        LedStatus::Ready => "READY",
        LedStatus::Busy => "BUSY",
        LedStatus::Error => "ERROR",
        LedStatus::Degraded => "DEGRADED",
        LedStatus::Resyncing => "RESYNCING",
        LedStatus::WaitingForPin => "PIN WAIT",
    }
}

fn status_text_color(s: LedStatus) -> Rgb565 {
    // Use black text on light backgrounds, white on dark.
    match s {
        LedStatus::Ready | LedStatus::Degraded | LedStatus::Resyncing => rgb565(0x0000),
        _ => rgb565(0xFFFF),
    }
}

fn last_op_name(op: LastOperation) -> &'static str {
    match op {
        LastOperation::Sign => "Sign",
        LastOperation::Verify => "Verify",
        LastOperation::KeyGen => "Key Gen",
        LastOperation::Ecdh => "ECDH",
        LastOperation::Decrypt => "Decrypt",
        LastOperation::Encrypt => "Encrypt",
        LastOperation::DeriveKey => "Key Derive",
        LastOperation::Initialize => "Initialize",
        LastOperation::DeleteKey => "Key Delete",
        LastOperation::Other => "Other",
    }
}

// ── ScreenLayout ──────────────────────────────────────────────────────────────

/// Pre-computed pixel layout for one display size.
///
/// Pass a `ScreenLayout` to [`render()`] so that the rendering code contains
/// no hardcoded coordinates; the same function works for the 240 × 135 Geek
/// board and the 320 × 172 Waveshare board (or any future display).
///
/// All coordinates are in logical pixels (0,0 = top-left of the display).
/// Hardware column/row offsets are handled by the [`DrawTarget`] impl.
#[derive(Debug, Clone, Copy)]
pub struct ScreenLayout {
    /// Logical display width (e.g. 240 for Geek, 320 for Waveshare).
    pub width: u16,
    /// Logical display height (e.g. 135 for Geek, 172 for Waveshare).
    pub height: u16,
    /// Height of the header bar in pixels.
    pub header_h: u16,
    /// X position of the status pill inside the header.
    pub pill_x: u16,
    /// Y position of the status pill inside the header.
    pub pill_y: u16,
    /// Width of the status pill.
    pub pill_w: u16,
    /// Height of the status pill.
    pub pill_h: u16,
    /// X position of the uptime text (right-aligned start).
    pub uptime_x: u16,
    /// Y of the top info-cell row.
    pub cells_y: u16,
    /// Height of the top info-cell row.
    pub cells_h: u16,
    /// Y of the last-op row.
    pub lastop_y: u16,
    /// Height of the last-op row.
    pub lastop_h: u16,
    /// Y position for the storage health row ("QMI: OK  |  SD: DEGRAD").
    pub storage_health_y: u16,
    /// Y position for the keys + provisioning row.
    pub keys_y: u16,
    /// Y of the bottom status stripe (last pixel row).
    pub stripe_y: u16,
}

impl ScreenLayout {
    /// Layout for the Waveshare RP2350-Geek (ST7789, 240 × 135 landscape).
    pub const fn geek_240x135() -> Self {
        Self {
            width: 240,
            height: 135,
            header_h: 18,
            pill_x: 86,
            pill_y: 3,
            pill_w: 68,
            pill_h: 12,
            uptime_x: 168,
            cells_y: 21,
            cells_h: 36,
            lastop_y: 59,
            lastop_h: 32,
            storage_health_y: 93,
            keys_y: 105,
            stripe_y: 134,
        }
    }

    /// Layout for the Waveshare RP2350-LCD-1.47 (ST7789V3, 320 × 172 landscape).
    pub const fn waveshare_320x172() -> Self {
        Self {
            width: 320,
            height: 172,
            header_h: 22,
            pill_x: 110,
            pill_y: 4,
            pill_w: 100,
            pill_h: 14,
            uptime_x: 220,
            cells_y: 25,
            cells_h: 50,
            lastop_y: 78,
            lastop_h: 42,
            storage_health_y: 123,
            keys_y: 137,
            stripe_y: 171,
        }
    }

    /// Layout for the Waveshare RP2350-LCD-1.47-B (ST7789V3, 172 × 320 portrait).
    ///
    /// Two-row header: "pico2hsm" + uptime on the first row, status pill centred
    /// on the second row.  The remaining 280 px is split between the info grid
    /// and the last-op area.
    pub const fn waveshare_172x320() -> Self {
        Self {
            width: 172,
            height: 320,
            header_h: 38, // two text rows (2 × 19 px)
            pill_x: 36,   // centred: (172 − 100) / 2
            pill_y: 22,   // second header row
            pill_w: 100,
            pill_h: 14,
            uptime_x: 116, // right-aligned: 172 − 8 chars × 6 px − 8 px margin
            cells_y: 41,
            cells_h: 80,
            lastop_y: 126,
            lastop_h: 120,
            storage_health_y: 252,
            keys_y: 268,
            stripe_y: 319,
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Apply a `DisplayState` update, called each tick or on state change.
///
/// Currently a thin pass-through; callers may replace `*state` directly or
/// call this function for a single consistent update point.
pub fn apply_update(state: &mut DisplayState, update: DisplayState) {
    *state = update;
}

/// Render the full status screen onto `display` using the given `layout`.
///
/// The same render function works for any display size — pass
/// [`ScreenLayout::geek_240x135()`] for the Geek board or
/// [`ScreenLayout::waveshare_320x172()`] for the Waveshare LCD-1.47.
///
/// Draw errors are silently ignored — this is an informational display.
pub fn render<D>(display: &mut D, state: &DisplayState, layout: &ScreenLayout)
where
    D: DrawTarget<Color = Rgb565>,
{
    let _ = render_inner(display, state, layout);
}

// ── Internal rendering ────────────────────────────────────────────────────────

fn render_inner<D>(
    display: &mut D,
    state: &DisplayState,
    layout: &ScreenLayout,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    let text_top = TextStyleBuilder::new().baseline(Baseline::Top).build();
    let style_pri = MonoTextStyle::new(&FONT_6X10, COLOR_TEXT_PRI);
    let style_sec = MonoTextStyle::new(&FONT_6X10, COLOR_TEXT_SEC);
    let style_dim = MonoTextStyle::new(&FONT_6X10, COLOR_TEXT_DIM);

    let w = layout.width as u32;
    let h = layout.height as u32;

    // ── 1. Screen background ─────────────────────────────────────────────────
    Rectangle::new(Point::new(0, 0), Size::new(w, h))
        .into_styled(PrimitiveStyle::with_fill(COLOR_BG))
        .draw(display)?;

    // ── 2. Header bar ────────────────────────────────────────────────────────
    Rectangle::new(Point::new(0, 0), Size::new(w, layout.header_h as u32))
        .into_styled(PrimitiveStyle::with_fill(COLOR_HEADER_BG))
        .draw(display)?;

    // "pico2hsm" label — fixed small margin from top-left
    Text::with_text_style("pico2hsm", Point::new(4, 4), style_pri, text_top).draw(display)?;

    // Status pill
    let pill_color = status_color(state.status);
    Rectangle::new(
        Point::new(layout.pill_x as i32, layout.pill_y as i32),
        Size::new(layout.pill_w as u32, layout.pill_h as u32),
    )
    .into_styled(PrimitiveStyle::with_fill(pill_color))
    .draw(display)?;
    let pill_text_style = MonoTextStyle::new(&FONT_6X10, status_text_color(state.status));
    Text::with_text_style(
        status_name(state.status),
        Point::new(layout.pill_x as i32 + 2, layout.pill_y as i32),
        pill_text_style,
        text_top,
    )
    .draw(display)?;

    // Uptime (right side of header)
    {
        let s = state.uptime_secs;
        let mut buf: String<9> = String::new();
        if s < 86400 {
            let _ = write!(
                &mut buf,
                "{:02}:{:02}:{:02}",
                s / 3600,
                (s / 60) % 60,
                s % 60
            );
        } else {
            let _ = write!(
                &mut buf,
                "{}d{:02}:{:02}",
                s / 86400,
                (s / 3600) % 24,
                (s / 60) % 60
            );
        }
        Text::with_text_style(
            &buf,
            Point::new(layout.uptime_x as i32, 4),
            style_dim,
            text_top,
        )
        .draw(display)?;
    }

    // ── 3. Divider line ──────────────────────────────────────────────────────
    Rectangle::new(Point::new(0, layout.header_h as i32), Size::new(w, 1))
        .into_styled(PrimitiveStyle::with_fill(COLOR_DIVIDER))
        .draw(display)?;

    // ── 4. Info grid — 3 equal cells ────────────────────────────────────────
    // Divide available width into 3 cells with 2px gaps and 2px side margins.
    // cell_w = (width - 2*margin - 2*gap) / 3; last cell gets the remainder.
    let margin: u32 = 2;
    let gap: u32 = 2;
    let avail = w - 2 * margin - 2 * gap;
    let cell_w0 = avail / 3;
    let cell_w2 = avail - 2 * cell_w0; // last cell gets any rounding remainder
    let cy = layout.cells_y as i32;
    let ch = layout.cells_h as u32;

    let cx0 = margin as i32;
    let cx1 = cx0 + cell_w0 as i32 + gap as i32;
    let cx2 = cx1 + cell_w0 as i32 + gap as i32;

    {
        let mut s: String<4> = String::new();
        let _ = write!(&mut s, "{}", state.key_count);
        draw_info_cell(
            display,
            cx0,
            cy,
            cell_w0,
            ch,
            "Keys",
            &s,
            COLOR_TEXT_PRI,
            text_top,
        )?;
    }
    let (auth_str, auth_color) = if state.authenticated {
        ("YES", COLOR_TEAL)
    } else {
        ("NO", COLOR_TEXT_DIM)
    };
    draw_info_cell(
        display, cx1, cy, cell_w0, ch, "Auth", auth_str, auth_color, text_top,
    )?;

    let (storage_str, storage_color) = if state.storage_ok {
        ("OK", COLOR_GREEN)
    } else {
        ("FAIL", COLOR_RED)
    };
    draw_info_cell(
        display,
        cx2,
        cy,
        cell_w2,
        ch,
        "Storage",
        storage_str,
        storage_color,
        text_top,
    )?;

    // ── 5. Last op row ───────────────────────────────────────────────────────
    let lo_y = layout.lastop_y as i32;
    let lo_h = layout.lastop_h as u32;
    let lo_w = w - 2 * margin;

    Rectangle::new(Point::new(margin as i32, lo_y), Size::new(lo_w, lo_h))
        .into_styled(PrimitiveStyle::with_fill(COLOR_CELL_BG))
        .draw(display)?;

    let lx = margin as i32 + 4;
    Text::with_text_style("Last op:", Point::new(lx, lo_y + 4), style_sec, text_top)
        .draw(display)?;

    let op_str = match state.last_op {
        None => "--",
        Some((op, _)) => last_op_name(op),
    };
    let op_style = MonoTextStyle::new(&FONT_8X13, COLOR_TEXT_PRI);
    Text::with_text_style(op_str, Point::new(lx, lo_y + 16), op_style, text_top).draw(display)?;

    // Right column: uptime
    let ux = (w / 2) as i32;
    Text::with_text_style("Up:", Point::new(ux, lo_y + 4), style_sec, text_top).draw(display)?;
    {
        let s = state.uptime_secs;
        let mut buf: String<9> = String::new();
        let _ = write!(
            &mut buf,
            "{:02}:{:02}:{:02}",
            s / 3600,
            (s / 60) % 60,
            s % 60
        );
        let uptime_style = MonoTextStyle::new(&FONT_8X13, COLOR_TEXT_DIM);
        Text::with_text_style(&buf, Point::new(ux, lo_y + 16), uptime_style, text_top)
            .draw(display)?;
    }

    // ── 6. Error banner (overlays last-op row if set) ────────────────────────
    if let Some(err) = state.error_msg {
        let banner_y = lo_y;
        let banner_h = lo_h;
        Rectangle::new(Point::new(0, banner_y), Size::new(w, banner_h))
            .into_styled(PrimitiveStyle::with_fill(rgb565(0x4000)))
            .draw(display)?;
        Rectangle::new(Point::new(0, banner_y), Size::new(w, 1))
            .into_styled(PrimitiveStyle::with_fill(COLOR_RED))
            .draw(display)?;
        let err_style = MonoTextStyle::new(&FONT_6X10, COLOR_RED);
        Text::with_text_style("!", Point::new(8, banner_y + 4), err_style, text_top)
            .draw(display)?;
        let err_txt_style = MonoTextStyle::new(&FONT_6X10, COLOR_TEXT_PRI);
        Text::with_text_style(err, Point::new(24, banner_y + 4), err_txt_style, text_top)
            .draw(display)?;
    }

    // ── 7. Storage health row ──────────────────────────────────────────────
    if state.qmi_ok.is_some() || state.sd_ok.is_some() {
        let sy = layout.storage_health_y as i32;
        let style_green = MonoTextStyle::new(&FONT_6X10, COLOR_GREEN);
        let style_red = MonoTextStyle::new(&FONT_6X10, COLOR_RED);
        let style_yellow = MonoTextStyle::new(&FONT_6X10, rgb565(0xFFE0));
        let style_gray = MonoTextStyle::new(&FONT_6X10, COLOR_TEXT_DIM);
        let style_white = MonoTextStyle::new(&FONT_6X10, COLOR_TEXT_PRI);

        let mut x = margin as i32 + 4;
        if let Some(ok) = state.qmi_ok {
            Text::with_text_style("QMI:", Point::new(x, sy), style_sec, text_top).draw(display)?;
            x += 30;
            if ok {
                Text::with_text_style("OK", Point::new(x, sy), style_green, text_top)
                    .draw(display)?;
            } else {
                Text::with_text_style("FAIL", Point::new(x, sy), style_red, text_top)
                    .draw(display)?;
            }
            x += 30;
        }

        // Separator
        if state.qmi_ok.is_some() && state.sd_ok.is_some() {
            Text::with_text_style("|", Point::new(x, sy), style_white, text_top).draw(display)?;
            x += 12;
        }

        if let Some(ok) = state.sd_ok {
            Text::with_text_style("SD:", Point::new(x, sy), style_sec, text_top).draw(display)?;
            x += 24;
            if ok {
                Text::with_text_style("OK", Point::new(x, sy), style_green, text_top)
                    .draw(display)?;
            } else {
                Text::with_text_style("DEGRAD", Point::new(x, sy), style_yellow, text_top)
                    .draw(display)?;
            }
        } else if state.qmi_ok.is_some() {
            // Show SD as absent
            Text::with_text_style("SD:", Point::new(x, sy), style_sec, text_top).draw(display)?;
            x += 24;
            let _ = x;
            Text::with_text_style("----", Point::new(x, sy), style_gray, text_top).draw(display)?;
        }
    }

    // ── 8. Keys + provisioning row ──────────────────────────────────────────
    {
        let ky = layout.keys_y as i32;
        let mut buf: String<20> = String::new();
        let _ = write!(&mut buf, "Keys: {}", state.key_count);
        Text::with_text_style(&buf, Point::new(margin as i32 + 4, ky), style_pri, text_top)
            .draw(display)?;
        if !state.provisioned {
            let unprov_x = margin as i32 + 4 + buf.len() as i32 * 6 + 6;
            let style_yellow = MonoTextStyle::new(&FONT_6X10, rgb565(0xFFE0));
            Text::with_text_style("[UNPROV]", Point::new(unprov_x, ky), style_yellow, text_top)
                .draw(display)?;
        }
    }

    // ── 9. Status stripe (bottom 1 px) ───────────────────────────────────────
    Rectangle::new(Point::new(0, layout.stripe_y as i32), Size::new(w, 1))
        .into_styled(PrimitiveStyle::with_fill(status_color(state.status)))
        .draw(display)?;

    Ok(())
}

/// Draw a labelled info cell with a large value string.
///
/// The cell is filled with [`COLOR_CELL_BG`], the `label` is rendered in
/// [`FONT_6X10`] / [`COLOR_TEXT_SEC`], and `value` in [`FONT_8X13`] with
/// the caller-supplied `value_color`.
fn draw_info_cell<D>(
    display: &mut D,
    x: i32,
    y: i32,
    w: u32,
    h: u32,
    label: &str,
    value: &str,
    value_color: Rgb565,
    text_top: TextStyle,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    // Cell background
    Rectangle::new(Point::new(x, y), Size::new(w, h))
        .into_styled(PrimitiveStyle::with_fill(COLOR_CELL_BG))
        .draw(display)?;
    // Label (small, secondary colour)
    let label_style = MonoTextStyle::new(&FONT_6X10, COLOR_TEXT_SEC);
    Text::with_text_style(label, Point::new(x + 4, y + 4), label_style, text_top).draw(display)?;
    // Value (large, caller colour)
    let val_style = MonoTextStyle::new(&FONT_8X13, value_color);
    Text::with_text_style(value, Point::new(x + 4, y + 18), val_style, text_top).draw(display)?;
    Ok(())
}
