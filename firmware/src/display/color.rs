//! RGB444 colour and the display palette (design spec §2.1).
//!
//! The panels run in 12-bit RGB444 (COLMOD 0x03), so the palette is
//! defined in that space directly: no RGB565 value can collapse onto a
//! neighbour after truncation (the old header and cell backgrounds both
//! became #111, and "teal" became green).

use embedded_graphics::pixelcolor::{raw::RawU16, PixelColor};

/// A 12-bit colour, `0x0RGB`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct C444(u16);

impl C444 {
    /// From `0xRGB`.
    pub const fn hex(rgb: u16) -> Self {
        C444(rgb & 0x0FFF)
    }

    /// Red nibble.
    pub const fn r(self) -> u8 {
        ((self.0 >> 8) & 0xF) as u8
    }

    /// Green nibble.
    pub const fn g(self) -> u8 {
        ((self.0 >> 4) & 0xF) as u8
    }

    /// Blue nibble.
    pub const fn b(self) -> u8 {
        (self.0 & 0xF) as u8
    }

    /// 8-bit RGB (each nibble × 17), for host previews and the LED.
    pub const fn rgb888(self) -> [u8; 3] {
        [self.r() * 17, self.g() * 17, self.b() * 17]
    }
}

impl PixelColor for C444 {
    type Raw = RawU16;
}

// ── Backgrounds ──────────────────────────────────────────────────────────────
/// Screen background.
pub const BG: C444 = C444::hex(0x000);
/// Status band, tiles.
pub const PANEL: C444 = C444::hex(0x111);
/// Activity area.
pub const PANEL2: C444 = C444::hex(0x222);
/// Chip borders, rules.
pub const RULE: C444 = C444::hex(0x333);

// ── Text ─────────────────────────────────────────────────────────────────────
/// Primary text.
pub const TEXT: C444 = C444::hex(0xEEE);
/// Secondary text, labels.
pub const TEXT2: C444 = C444::hex(0xAAA);
/// De-emphasised text.
pub const DIM: C444 = C444::hex(0x888);

// ── Status (always paired with a word) ───────────────────────────────────────
/// Ready / verified.
pub const OK: C444 = C444::hex(0x3D5);
/// Admin, notices, policy hint, refusal.
pub const WARN: C444 = C444::hex(0xFB2);
/// Error, locked, failure.
pub const ERR: C444 = C444::hex(0xF44);
/// Work in progress.
pub const BUSY: C444 = C444::hex(0x4AF);
/// PIN verified.
pub const INFO: C444 = C444::hex(0x6CF);
/// No host: cyan, so it never reads as WORKING's blue (the LED shows only
/// the colour).
pub const CYAN: C444 = C444::hex(0x2DD);

/// Reserved for the pending-SAS screen: nothing else may use it.
pub const SAS: C444 = C444::hex(0xD4F);

/// Pure black / white for text on status fills.
pub const BLACK: C444 = C444::hex(0x000);
/// See [`BLACK`].
pub const WHITE: C444 = C444::hex(0xFFF);

/// Text colour on a fill of `c`: black on the light status colours (OK,
/// WARN, INFO, CYAN), white on the dark ones (ERR, BUSY) and everything else.
pub const fn on(c: C444) -> C444 {
    if c.0 == OK.0 || c.0 == WARN.0 || c.0 == INFO.0 || c.0 == CYAN.0 {
        BLACK
    } else {
        WHITE
    }
}
