//! Screen driver: band-by-band rendering with partial updates.
//!
//! The driver keeps the last screen it sent.  For the next one it works out
//! which regions changed, maps them to 16-row bands and renders and sends
//! only those bands (design spec §3).  It is generic over [`Panel`], so the
//! host tests drive exactly the code the firmware runs, against a panel
//! that collects the bands into a full frame.

use embedded_graphics::primitives::Rectangle;

use super::band::{band_bytes, Rgb444Band, BAND_ROWS};
use super::layout::Layout;
use super::render::render;
use super::view::{HomeView, LedTone, Screen};

/// A display panel that takes full-width row bands.
pub trait Panel {
    /// Write `rows` rows starting at logical row `y0`; `data` is packed
    /// RGB444, `band_bytes(width, rows)` long.
    async fn write_rows(&mut self, y0: u16, rows: u16, data: &[u8]);
    /// Backlight off, display off, sleep in.
    async fn sleep(&mut self);
    /// Sleep out, display on — backlight still off: GRAM holds the
    /// pre-sleep frame.  The caller redraws everything, then calls
    /// [`Self::backlight_on`].
    async fn wake(&mut self);
    /// Backlight on (after the first full redraw following [`Self::wake`]).
    async fn backlight_on(&mut self);
    /// Set the status LED (boards without one ignore it).
    async fn set_led(&mut self, _tone: LedTone, _dim: bool) {}
}

/// Bands of `l`.
pub fn band_count(l: &Layout) -> u16 {
    l.h.div_ceil(BAND_ROWS)
}

/// Bit mask of every band of `l`.
pub fn all_bands(l: &Layout) -> u32 {
    (1u32 << band_count(l)) - 1
}

/// Bands touched by rows of `r`.
pub fn bands_of(r: &Rectangle) -> u32 {
    if r.size.height == 0 {
        return 0;
    }
    let y0 = r.top_left.y.max(0) as u32;
    let y1 = y0 + r.size.height - 1;
    let (b0, b1) = (y0 / u32::from(BAND_ROWS), y1 / u32::from(BAND_ROWS));
    let mut m = 0;
    for b in b0..=b1.min(31) {
        m |= 1 << b;
    }
    m
}

fn home_dirty(a: &HomeView, b: &HomeView, l: &Layout) -> u32 {
    let mut m = 0;
    if a.status != b.status || a.applet != b.applet || a.admin != b.admin {
        m |= bands_of(&l.band);
    }
    if a.pin != b.pin {
        m |= bands_of(&l.tiles[0]);
    }
    if a.keys != b.keys {
        m |= bands_of(&l.tiles[1]);
    }
    if a.domain != b.domain {
        m |= bands_of(&l.tiles[2]);
    }
    if a.activity != b.activity {
        m |= bands_of(&l.act);
    }
    if a.footer != b.footer {
        m |= bands_of(&l.footer);
    }
    m
}

/// Bands that differ between `prev` and `next`.
pub fn dirty_bands(prev: &Screen, next: &Screen, l: &Layout) -> u32 {
    use super::view::Screen as S;
    if prev == next {
        return 0;
    }
    let step_rows = |y: i32, font_h: u32| {
        Rectangle::new(
            embedded_graphics::geometry::Point::new(0, y),
            embedded_graphics::geometry::Size::new(u32::from(l.w), font_h),
        )
    };
    match (prev, next) {
        (S::Home(a), S::Home(b)) => home_dirty(a, b, l),
        (S::Splash(a), S::Splash(b)) if a.border == b.border && a.board == b.board => {
            let mut m = 0;
            if a.step != b.step {
                m |= bands_of(&step_rows(
                    l.splash_step_y,
                    l.splash_step_font.character_size.height,
                ));
            }
            if a.reset != b.reset {
                m |= bands_of(&step_rows(
                    l.splash_reset_y,
                    l.splash_reset_font.character_size.height,
                ));
            }
            m
        }
        (S::Sas(a), S::Sas(b)) if a.digits == b.digits && a.role == b.role && a.peer == b.peer => {
            bands_of(&l.sas_bar)
        }
        (S::Error(a), S::Error(b)) if a.code == b.code => bands_of(&l.err_footer),
        (S::Notice(a), S::Notice(b)) if a.kind == b.kind => bands_of(&l.err_footer),
        _ => all_bands(l),
    }
}

/// Drives one panel; see the module docs.
pub struct ScreenDriver<'b, P> {
    /// The panel.
    pub panel: P,
    layout: &'static Layout,
    band: &'b mut [u8],
    shown: Option<Screen>,
    asleep: bool,
    /// Woken but the backlight is still off until a full frame is drawn.
    dark: bool,
    led: Option<(LedTone, bool)>,
    /// Strings that overflowed their box so far (host tests assert 0).
    pub overflow: u32,
    /// Bands sent so far.
    pub bands_sent: u32,
}

impl<'b, P: Panel> ScreenDriver<'b, P> {
    /// A driver for `panel` with `layout`, rendering through `band`
    /// (at least `band_bytes(layout.w, BAND_ROWS)` bytes).
    pub fn new(panel: P, layout: &'static Layout, band: &'b mut [u8]) -> Self {
        assert!(band.len() >= band_bytes(layout.w, BAND_ROWS));
        ScreenDriver {
            panel,
            layout,
            band,
            shown: None,
            asleep: false,
            dark: false,
            led: None,
            overflow: 0,
            bands_sent: 0,
        }
    }

    /// The layout.
    pub fn layout(&self) -> &'static Layout {
        self.layout
    }

    /// Whether the panel is asleep.
    pub fn is_asleep(&self) -> bool {
        self.asleep
    }

    /// Show `next`, sending only the bands that changed.  No-op while
    /// asleep.
    pub async fn show(&mut self, next: &Screen) {
        if self.asleep {
            return;
        }
        let l = self.layout;
        let mask = match &self.shown {
            Some(prev) => dirty_bands(prev, next, l),
            None => all_bands(l),
        };
        for b in 0..band_count(l) {
            if mask & (1 << b) == 0 {
                continue;
            }
            let y0 = b * BAND_ROWS;
            let rows = BAND_ROWS.min(l.h - y0);
            let n = band_bytes(l.w, rows);
            {
                let mut t = Rgb444Band::new(&mut self.band[..n], l.w, y0, rows);
                self.overflow += render(next, l, &mut t);
            }
            self.panel.write_rows(y0, rows, &self.band[..n]).await;
            self.bands_sent += 1;
        }
        self.shown = Some(*next);
        // Light the panel only once it holds a full new frame, never the
        // stale pre-sleep GRAM.
        if self.dark {
            self.panel.backlight_on().await;
            self.dark = false;
        }
    }

    /// Put the panel to sleep.
    pub async fn sleep(&mut self) {
        if !self.asleep {
            self.panel.sleep().await;
            self.asleep = true;
        }
    }

    /// Wake the panel; the next [`Self::show`] redraws everything and
    /// then turns the backlight on.
    pub async fn wake(&mut self) {
        if self.asleep {
            self.panel.wake().await;
            self.asleep = false;
            self.dark = true;
            self.shown = None;
        }
    }

    /// Set the LED, writing only on a change.
    pub async fn led(&mut self, tone: LedTone, dim: bool) {
        if self.led != Some((tone, dim)) {
            self.panel.set_led(tone, dim).await;
            self.led = Some((tone, dim));
        }
    }
}
