//! Pixel layouts for the two panels (design spec §2).
//!
//! All coordinates are logical (0,0 = top-left of the visible panel);
//! controller offsets live in the board drivers.

use embedded_graphics::{
    geometry::{Point, Size},
    mono_font::{
        ascii::{FONT_10X20, FONT_6X10, FONT_6X13, FONT_9X18, FONT_9X18_BOLD},
        MonoFont,
    },
    primitives::Rectangle,
};

/// A font reference.
pub type Font = &'static MonoFont<'static>;

const fn r(x: i32, y: i32, w: u32, h: u32) -> Rectangle {
    Rectangle::new(Point::new(x, y), Size::new(w, h))
}

/// Every coordinate the renderer uses.
#[derive(Debug)]
pub struct Layout {
    /// Panel width.
    pub w: u16,
    /// Panel height.
    pub h: u16,
    /// Short labels (Geek).
    pub compact: bool,

    // ── Status band ──────────────────────────────────────────────────────
    /// Band.
    pub band: Rectangle,
    /// Status bar width.
    pub bar_w: u32,
    /// Status word position and font.
    pub status_at: Point,
    /// Status word font.
    pub status_font: Font,
    /// Applet chip.
    pub applet_chip: Rectangle,
    /// Admin chip.
    pub admin_chip: Rectangle,
    /// Chip font.
    pub chip_font: Font,

    // ── Tiles ────────────────────────────────────────────────────────────
    /// PIN, KEYS, DOMAIN.
    pub tiles: [Rectangle; 3],
    /// Inner left padding.
    pub tile_pad: i32,
    /// Label font and offset.
    pub tile_label_font: Font,
    /// Label y offset.
    pub tile_label_dy: i32,
    /// Value font.
    pub tile_value_font: Font,
    /// Value y offset.
    pub tile_value_dy: i32,
    /// Sub-line font.
    pub tile_sub_font: Font,
    /// Sub-line y offset.
    pub tile_sub_dy: i32,

    // ── Activity ─────────────────────────────────────────────────────────
    /// Area.
    pub act: Rectangle,
    /// Left padding.
    pub act_pad: i32,
    /// Line 1 font.
    pub act_font1: Font,
    /// Line 1 y offset.
    pub act_dy1: i32,
    /// Line 2 font.
    pub act_font2: Font,
    /// Line 2 y offset.
    pub act_dy2: i32,
    /// Progress bar.
    pub act_bar: Rectangle,

    // ── Footer ───────────────────────────────────────────────────────────
    /// Home footer.
    pub footer: Rectangle,
    /// Footer font.
    pub footer_font: Font,

    // ── Error / notice template ──────────────────────────────────────────
    /// Band.
    pub err_band: Rectangle,
    /// Code / title font.
    pub err_font: Font,
    /// Code position.
    pub err_code_at: Point,
    /// Title x.
    pub err_title_x: i32,
    /// Action area.
    pub err_action: Rectangle,
    /// Action font.
    pub err_action_font: Font,
    /// Action line pitch.
    pub err_action_pitch: i32,
    /// Detail area.
    pub err_detail: Rectangle,
    /// Detail font.
    pub err_detail_font: Font,
    /// Footer.
    pub err_footer: Rectangle,

    // ── Boot splash ──────────────────────────────────────────────────────
    /// Title y and font.
    pub splash_title_y: i32,
    /// Title font.
    pub splash_title_font: Font,
    /// Version line y.
    pub splash_sub_y: i32,
    /// Version line font.
    pub splash_sub_font: Font,
    /// Step line y.
    pub splash_step_y: i32,
    /// Step line font.
    pub splash_step_font: Font,
    /// Reset warning y.
    pub splash_reset_y: i32,
    /// Reset warning font.
    pub splash_reset_font: Font,

    // ── SAS ──────────────────────────────────────────────────────────────
    /// Frame thickness.
    pub sas_frame: u32,
    /// Title y.
    pub sas_title_y: i32,
    /// Title text.
    pub sas_title: &'static str,
    /// Digits top y.
    pub sas_digits_y: i32,
    /// Digit font (drawn ×2).
    pub sas_digit_font: Font,
    /// Gap between the two groups of four.
    pub sas_gap: i32,
    /// Role / peer line y.
    pub sas_role_y: i32,
    /// Instruction lines.
    pub sas_lines: [(i32, &'static str); 2],
    /// Countdown bar.
    pub sas_bar: Rectangle,
}

/// Waveshare RP2350-LCD-1.47 (ST7789V3, 320 × 172 landscape).
pub static WAVESHARE_320X172: Layout = Layout {
    w: 320,
    h: 172,
    compact: false,

    band: r(0, 0, 320, 34),
    bar_w: 6,
    status_at: Point::new(14, 7),
    status_font: &FONT_10X20,
    applet_chip: r(260, 5, 57, 24),
    admin_chip: r(186, 5, 67, 24),
    chip_font: &FONT_9X18_BOLD,

    tiles: [r(2, 36, 104, 62), r(108, 36, 104, 62), r(214, 36, 104, 62)],
    tile_pad: 6,
    tile_label_font: &FONT_6X13,
    tile_label_dy: 4,
    tile_value_font: &FONT_9X18_BOLD,
    tile_value_dy: 20,
    tile_sub_font: &FONT_6X13,
    tile_sub_dy: 44,

    act: r(2, 100, 316, 44),
    act_pad: 8,
    act_font1: &FONT_9X18,
    act_dy1: 3,
    act_font2: &FONT_6X13,
    act_dy2: 23,
    act_bar: r(10, 138, 300, 4),

    footer: r(0, 150, 320, 22),
    footer_font: &FONT_6X13,

    err_band: r(0, 0, 320, 36),
    err_font: &FONT_10X20,
    err_code_at: Point::new(14, 8),
    err_title_x: 64,
    err_action: r(0, 44, 320, 72),
    err_action_font: &FONT_9X18,
    err_action_pitch: 24,
    err_detail: r(0, 124, 320, 23),
    err_detail_font: &FONT_6X13,
    err_footer: r(0, 150, 320, 22),

    splash_title_y: 40,
    splash_title_font: &FONT_10X20,
    splash_sub_y: 66,
    splash_sub_font: &FONT_6X13,
    splash_step_y: 100,
    splash_step_font: &FONT_9X18,
    splash_reset_y: 130,
    splash_reset_font: &FONT_6X13,

    sas_frame: 3,
    sas_title_y: 7,
    sas_title: "ENROLL - COMPARE CODE",
    sas_digits_y: 40,
    sas_digit_font: &FONT_10X20,
    sas_gap: 20,
    sas_role_y: 92,
    sas_lines: [
        (114, "Same code on both devices? Continue on host."),
        (131, "Different? Abort and revoke."),
    ],
    sas_bar: r(10, 156, 300, 4),
};

/// Waveshare RP2350-Geek (ST7789, 240 × 135 landscape).
pub static GEEK_240X135: Layout = Layout {
    w: 240,
    h: 135,
    compact: true,

    band: r(0, 0, 240, 26),
    bar_w: 4,
    status_at: Point::new(8, 4),
    status_font: &FONT_9X18_BOLD,
    applet_chip: r(196, 4, 41, 18),
    admin_chip: r(146, 4, 45, 18),
    chip_font: &FONT_6X13,

    tiles: [r(2, 28, 77, 46), r(81, 28, 77, 46), r(160, 28, 77, 46)],
    tile_pad: 4,
    tile_label_font: &FONT_6X10,
    tile_label_dy: 3,
    tile_value_font: &FONT_9X18_BOLD,
    tile_value_dy: 14,
    tile_sub_font: &FONT_6X10,
    tile_sub_dy: 33,

    act: r(2, 76, 235, 36),
    act_pad: 4,
    act_font1: &FONT_6X13,
    act_dy1: 3,
    act_font2: &FONT_6X13,
    act_dy2: 17,
    act_bar: r(6, 107, 227, 3),

    footer: r(0, 120, 240, 15),
    footer_font: &FONT_6X10,

    err_band: r(0, 0, 240, 28),
    err_font: &FONT_9X18_BOLD,
    err_code_at: Point::new(8, 5),
    err_title_x: 44,
    err_action: r(0, 34, 240, 56),
    err_action_font: &FONT_6X13,
    err_action_pitch: 16,
    err_detail: r(0, 96, 240, 23),
    err_detail_font: &FONT_6X13,
    err_footer: r(0, 122, 240, 13),

    splash_title_y: 20,
    splash_title_font: &FONT_9X18,
    splash_sub_y: 42,
    splash_sub_font: &FONT_6X10,
    splash_step_y: 70,
    splash_step_font: &FONT_6X13,
    splash_reset_y: 100,
    splash_reset_font: &FONT_6X13,

    sas_frame: 2,
    sas_title_y: 4,
    sas_title: "COMPARE CODE",
    sas_digits_y: 28,
    sas_digit_font: &FONT_9X18,
    sas_gap: 18,
    sas_role_y: 72,
    sas_lines: [
        (90, "Same code? Continue on host."),
        (104, "Different? Abort and revoke."),
    ],
    sas_bar: r(8, 126, 224, 4),
};
