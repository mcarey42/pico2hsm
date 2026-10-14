//! Draw a [`Screen`] with a [`Layout`] onto any RGB444 target.
//!
//! The renderer is called once per 16-row band; [`Painter`] skips every
//! element whose box does not touch the target's rows, so a band costs
//! roughly its share of the screen.  It also checks that every string fits
//! the box it belongs to (`overflow`, asserted by the host tests).

use core::fmt::Write as _;

use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{Dimensions, Point, Size},
    mono_font::MonoTextStyle,
    primitives::Rectangle,
    text::{Baseline, Text},
    Drawable,
};
use heapless::String;
use pico2hsm_core::op::{Applet, OpCode, OpResult};

use super::band::Scale2;
use super::color::{self as c, C444};
use super::fmt::{fmt_elapsed, fmt_uptime, hex4};
use super::layout::{Font, Layout};
use super::view::*;
use crate::display_snapshot::{algo, SasRole};

/// Firmware version shown on screen.
pub const FW_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Drawing helper over a target; see the module docs.
pub struct Painter<'a, D> {
    t: &'a mut D,
    clip: Rectangle,
    /// Strings that did not fit their box.
    pub overflow: u32,
}

fn text_box(s: &str, at: Point, font: Font) -> Rectangle {
    let n = s.chars().count() as u32;
    let cw = font.character_size.width + font.character_spacing;
    let w = (n * cw).saturating_sub(font.character_spacing);
    Rectangle::new(at, Size::new(w, font.character_size.height))
}

fn text_width(s: &str, font: Font) -> i32 {
    text_box(s, Point::zero(), font).size.width as i32
}

fn contains(outer: &Rectangle, inner: &Rectangle) -> bool {
    inner.size.width == 0 || outer.intersection(inner) == *inner
}

impl<'a, D: DrawTarget<Color = C444>> Painter<'a, D> {
    /// Paint on `t`.
    pub fn new(t: &'a mut D) -> Self {
        let clip = t.bounding_box();
        Painter {
            t,
            clip,
            overflow: 0,
        }
    }

    fn visible(&self, r: &Rectangle) -> bool {
        let i = r.intersection(&self.clip);
        i.size.width > 0 && i.size.height > 0
    }

    /// Fill `r`.
    pub fn fill(&mut self, r: Rectangle, col: C444) {
        if self.visible(&r) {
            let _ = self.t.fill_solid(&r, col);
        }
    }

    /// A `t`-pixel outline just inside `r`.
    pub fn frame(&mut self, r: Rectangle, t: u32, col: C444) {
        let (x, y, w, h) = (r.top_left.x, r.top_left.y, r.size.width, r.size.height);
        self.fill(Rectangle::new(r.top_left, Size::new(w, t)), col);
        self.fill(
            Rectangle::new(Point::new(x, y + h as i32 - t as i32), Size::new(w, t)),
            col,
        );
        self.fill(Rectangle::new(r.top_left, Size::new(t, h)), col);
        self.fill(
            Rectangle::new(Point::new(x + w as i32 - t as i32, y), Size::new(t, h)),
            col,
        );
    }

    /// `s` with its top-left at `at`; it must fit inside `region`.
    /// Returns the x just past it.
    pub fn text(&mut self, s: &str, at: Point, font: Font, col: C444, region: Rectangle) -> i32 {
        let bb = text_box(s, at, font);
        if !contains(&region, &bb) {
            self.overflow += 1;
        }
        if self.visible(&bb) {
            let style = MonoTextStyle::new(font, col);
            let _ = Text::with_baseline(s, at, style, Baseline::Top).draw(self.t);
        }
        at.x + bb.size.width as i32
    }

    /// `s` double-struck (drawn again 1 px to the right): a bold weight
    /// from a regular font, with no extra font data.  Returns the x just
    /// past it.
    pub fn text_bold(
        &mut self,
        s: &str,
        at: Point,
        font: Font,
        col: C444,
        region: Rectangle,
    ) -> i32 {
        let small = text_box(s, at, font);
        let bb = Rectangle::new(at, small.size + Size::new(1, 0));
        if !contains(&region, &bb) {
            self.overflow += 1;
        }
        if self.visible(&bb) {
            let style = MonoTextStyle::new(font, col);
            for dx in 0..2 {
                let _ = Text::with_baseline(s, at + Point::new(dx, 0), style, Baseline::Top)
                    .draw(self.t);
            }
        }
        at.x + bb.size.width as i32
    }

    /// `s` centred horizontally in `region` at `y`.
    pub fn text_center(&mut self, s: &str, y: i32, font: Font, col: C444, region: Rectangle) {
        let x = region.top_left.x + (region.size.width as i32 - text_width(s, font)) / 2;
        self.text(s, Point::new(x, y), font, col, region);
    }

    /// `s` centred in `region` both ways.
    pub fn text_mid(&mut self, s: &str, font: Font, col: C444, region: Rectangle) {
        let y =
            region.top_left.y + (region.size.height as i32 - font.character_size.height as i32) / 2;
        self.text_center(s, y, font, col, region);
    }

    /// `s` ending at `right` (exclusive).
    pub fn text_right(
        &mut self,
        s: &str,
        right: i32,
        y: i32,
        font: Font,
        col: C444,
        region: Rectangle,
    ) {
        let x = right - text_width(s, font);
        self.text(s, Point::new(x, y), font, col, region);
    }

    /// `s` drawn ×2 with its top-left at `at`.
    pub fn text_x2(&mut self, s: &str, at: Point, font: Font, col: C444, region: Rectangle) {
        let small = text_box(s, Point::zero(), font);
        let bb = Rectangle::new(at, Size::new(small.size.width * 2, small.size.height * 2));
        if !contains(&region, &bb) {
            self.overflow += 1;
        }
        if self.visible(&bb) {
            let style = MonoTextStyle::new(font, col);
            let mut s2 = Scale2::new(self.t, at);
            let _ = Text::with_baseline(s, Point::zero(), style, Baseline::Top).draw(&mut s2);
        }
    }
}

/// Draw `screen` with `l` on `target`; returns the overflow count.
pub fn render<D: DrawTarget<Color = C444>>(screen: &Screen, l: &Layout, target: &mut D) -> u32 {
    let mut p = Painter::new(target);
    let full = Rectangle::new(Point::zero(), Size::new(u32::from(l.w), u32::from(l.h)));
    p.fill(full, c::BG);
    match screen {
        Screen::Home(v) => home(&mut p, v, l),
        Screen::Splash(v) => splash(&mut p, v, l),
        Screen::Error(v) => error(&mut p, v, l),
        Screen::Sas(v) => sas(&mut p, v, l),
        Screen::Notice(v) => notice(&mut p, v, l),
    }
    p.overflow
}

fn screen_rect(l: &Layout) -> Rectangle {
    Rectangle::new(Point::zero(), Size::new(u32::from(l.w), u32::from(l.h)))
}

fn at(r: &Rectangle, dx: i32, dy: i32) -> Point {
    Point::new(r.top_left.x + dx, r.top_left.y + dy)
}

// ── Home ─────────────────────────────────────────────────────────────────────

fn home<D: DrawTarget<Color = C444>>(p: &mut Painter<'_, D>, v: &HomeView, l: &Layout) {
    // Status band.
    let band = l.band;
    p.fill(band, c::PANEL);
    p.fill(
        Rectangle::new(band.top_left, Size::new(l.bar_w, band.size.height)),
        v.status.color(),
    );
    if l.status_bold {
        p.text_bold(
            v.status.word(),
            l.status_at,
            l.status_font,
            v.status.color(),
            band,
        );
    } else {
        p.text(
            v.status.word(),
            l.status_at,
            l.status_font,
            v.status.color(),
            band,
        );
    }
    p.frame(l.applet_chip, 1, c::RULE);
    let (name, col) = match v.applet {
        Applet::Hsm => ("HSM", c::TEXT),
        Applet::Piv => ("PIV", c::TEXT),
        Applet::Pgp => ("PGP", c::TEXT),
        Applet::None => ("--", c::DIM),
    };
    p.text_mid(name, l.chip_font, col, l.applet_chip);
    if v.admin {
        p.fill(l.admin_chip, c::WARN);
        p.text_mid("ADMIN", l.chip_font, c::on(c::WARN), l.admin_chip);
    }

    pin_tile(p, &v.pin, l);
    keys_tile(p, &v.keys, l);
    domain_tile(p, &v.domain, l);
    activity(p, &v.activity, l);
    footer(p, &v.footer, l.footer, l);
}

fn tile_frame<D: DrawTarget<Color = C444>>(
    p: &mut Painter<'_, D>,
    l: &Layout,
    i: usize,
    label: &str,
    fill: C444,
    label_col: C444,
) -> Rectangle {
    let t = l.tiles[i];
    p.fill(t, fill);
    p.text(
        label,
        at(&t, l.tile_pad, l.tile_label_dy),
        l.tile_label_font,
        label_col,
        t,
    );
    t
}

fn pin_tile<D: DrawTarget<Color = C444>>(p: &mut Painter<'_, D>, v: &PinTile, l: &Layout) {
    let blocked = v.value == PinValue::Blocked;
    let (fill, label_col) = if blocked {
        (c::ERR, c::on(c::ERR))
    } else {
        (c::PANEL, c::TEXT2)
    };
    let t = tile_frame(p, l, 0, "PIN", fill, label_col);
    let (val, col) = match v.value {
        PinValue::NoApplet | PinValue::NotVerified => ("--", c::DIM),
        PinValue::Verified => ("OK", c::INFO),
        PinValue::Blocked => ("BLOCK", c::on(c::ERR)),
    };
    p.text(
        val,
        at(&t, l.tile_pad, l.tile_value_dy),
        l.tile_value_font,
        col,
        t,
    );
    let sub_at = at(&t, l.tile_pad, l.tile_sub_dy);
    if v.value == PinValue::NoApplet {
        p.text("no applet", sub_at, l.tile_sub_font, c::DIM, t);
        return;
    }
    let mut s: String<16> = String::new();
    let _ = if l.compact || v.sig_armed {
        write!(s, "{}/{}", v.left, v.max)
    } else {
        write!(s, "{}/{} left", v.left, v.max)
    };
    let col = if blocked {
        c::on(c::ERR)
    } else {
        match v.left {
            0 => c::ERR,
            1 => c::WARN,
            _ => c::TEXT2,
        }
    };
    let x = p.text(&s, sub_at, l.tile_sub_font, col, t);
    if v.sig_armed {
        let armed = if l.compact { " SIG1" } else { " SIG x1" };
        p.text(armed, Point::new(x, sub_at.y), l.tile_sub_font, c::WARN, t);
    }
}

fn keys_tile<D: DrawTarget<Color = C444>>(p: &mut Painter<'_, D>, v: &KeysTile, l: &Layout) {
    let t = tile_frame(p, l, 1, "KEYS", c::PANEL, c::TEXT2);
    let mut s: String<8> = String::new();
    let _ = write!(s, "{}", v.total);
    p.text(
        &s,
        at(&t, l.tile_pad, l.tile_value_dy),
        l.tile_value_font,
        c::TEXT,
        t,
    );
    let mut sub: String<16> = String::new();
    match v.split {
        Some([h, pv, g]) if l.compact => {
            let _ = write!(sub, "H{h}P{pv}G{g}");
        }
        Some([h, pv, g]) => {
            let _ = write!(sub, "H{h} P{pv} G{g}");
        }
        None => {
            let _ = sub.push_str("keys");
        }
    }
    p.text(
        &sub,
        at(&t, l.tile_pad, l.tile_sub_dy),
        l.tile_sub_font,
        c::TEXT2,
        t,
    );
}

fn domain_tile<D: DrawTarget<Color = C444>>(p: &mut Painter<'_, D>, v: &DomainTile, l: &Layout) {
    let t = tile_frame(p, l, 2, "DOMAIN", c::PANEL, c::TEXT2);
    let value_at = at(&t, l.tile_pad, l.tile_value_dy);
    let sub_at = at(&t, l.tile_pad, l.tile_sub_dy);
    let (id, sub, sub_col): (Option<u16>, String<16>, C444) = match *v {
        DomainTile::None => (None, str16("no domain"), c::DIM),
        DomainTile::SelfOnly { id } => (Some(id), str16("self"), c::WARN),
        DomainTile::Revoked { id } => (Some(id), str16("REVOKED"), c::ERR),
        DomainTile::Member { id, members } => {
            let mut s = String::new();
            let _ = write!(
                s,
                "{} member{}",
                members,
                if members == 1 { "" } else { "s" }
            );
            (Some(id), s, c::TEXT2)
        }
    };
    match id {
        Some(id) => p.text(&hex4(id), value_at, l.tile_value_font, c::TEXT, t),
        None => p.text("--", value_at, l.tile_value_font, c::DIM, t),
    };
    p.text(&sub, sub_at, l.tile_sub_font, sub_col, t);
}

fn str16(s: &str) -> String<16> {
    let mut o = String::new();
    let _ = o.push_str(s);
    o
}

fn note_text(n: Note, l: &Layout) -> &'static str {
    match n {
        Note::NotSaved => "Last change NOT saved",
        Note::StorageUnreadable => "Keystore unreadable",
        Note::StoreReadOnly => "Keystore READ-ONLY",
        Note::SdMissing => "SD card missing",
        Note::Unblock(Applet::Hsm) => "Unblock: PUK or SO-PIN",
        Note::Unblock(Applet::Piv) => "Unblock: PIV PUK",
        Note::Unblock(Applet::Pgp) if l.compact => "Unblock: PW3 / RC",
        Note::Unblock(Applet::Pgp) => "Unblock: PW3 or reset code",
        Note::Unblock(Applet::None) => "Unblock the PIN",
    }
}

fn activity<D: DrawTarget<Color = C444>>(p: &mut Painter<'_, D>, v: &ActivityView, l: &Layout) {
    let a = l.act;
    p.fill(a, c::PANEL2);
    let line1 = at(&a, l.act_pad, l.act_dy1);
    let line2 = at(&a, l.act_pad, l.act_dy2);
    match *v {
        ActivityView::Idle => {
            p.text("Idle", line1, l.act_font1, c::DIM, a);
        }
        ActivityView::Working { op, elapsed, phase } => {
            let mut s: String<24> = String::new();
            let name = if matches!(op, OpCode::Other | OpCode::None) {
                "command"
            } else {
                op.name()
            };
            let _ = write!(s, "Working: {name}");
            p.text(&s, line1, l.act_font1, c::TEXT, a);
            let right = a.top_left.x + a.size.width as i32 - l.act_pad;
            p.text_right(
                &fmt_elapsed(elapsed),
                right,
                line1.y,
                l.act_font1,
                c::TEXT2,
                a,
            );
            // Indeterminate bar: a 40 px segment moving 8 px a step.
            let bar = l.act_bar;
            p.fill(bar, c::RULE);
            let span = bar.size.width as i32 + 40;
            let x = (i32::from(phase) * 8) % span - 40;
            let seg = Rectangle::new(
                Point::new(bar.top_left.x + x, bar.top_left.y),
                Size::new(40, bar.size.height),
            )
            .intersection(&bar);
            p.fill(seg, c::BUSY);
        }
        ActivityView::Done {
            op,
            result,
            age,
            fade,
            hint,
            detail,
            note,
            ended,
        } => {
            // An operation from a session that has ended stays, all DIM.
            let fade_col = if ended { c::DIM } else { fade.color() };
            let mut s: String<24> = String::new();
            let _ = s.push_str(op.name());
            let col = match result {
                OpResult::Ok => fade_col,
                OpResult::Refused => {
                    let _ = s.push_str(" REFUSED");
                    if ended {
                        c::DIM
                    } else {
                        c::WARN
                    }
                }
                OpResult::Error => {
                    let _ = s.push_str(" FAILED");
                    if ended {
                        c::DIM
                    } else {
                        c::ERR
                    }
                }
            };
            p.text(&s, line1, l.act_font1, col, a);
            if let Some(n) = note {
                p.text(note_text(n, l), line2, l.act_font2, c::ERR, a);
                return;
            }
            let x = p.text(&age.text(false), line2, l.act_font2, fade_col, a);
            let gap = l.act_font2.character_size.width as i32 * 2;
            let hint_text = match hint {
                Hint::None => None,
                Hint::PivPinAlways => Some("PIN-always: re-verify next"),
                Hint::PgpSingleUse => Some("PW1 single-use spent"),
            };
            if let Some(h) = hint_text {
                p.text(h, Point::new(x + gap, line2.y), l.act_font2, c::TEXT2, a);
            } else if let Some(d) = detail {
                let mut s: String<24> = String::new();
                let name = algo::name(d.algo);
                if !name.is_empty() {
                    let _ = write!(s, "{name} ");
                }
                let _ = write!(s, "#{:02X} {:04X}", d.key_ref, d.sw);
                p.text(&s, Point::new(x + gap, line2.y), l.act_font2, c::DIM, a);
            }
        }
    }
}

fn storage_text(s: StorageLine, l: &Layout) -> (&'static str, C444) {
    match s {
        StorageLine::QmiOk => ("QMI ok", l.footer_text),
        StorageLine::QmiFail => ("QMI FAIL", c::ERR),
        StorageLine::SdOk => ("SD ok", l.footer_text),
        StorageLine::SdFail => ("SD FAIL", c::ERR),
        StorageLine::SdMissing => ("SD MISSING", c::ERR),
    }
}

/// Where a footer strip's parts go: the storage token at the right, the
/// text left of it.
pub struct FooterBoxes {
    /// The storage token's box (the dark chip on a WARN strip).
    pub token: Rectangle,
    /// What is left for the text.
    pub text: Rectangle,
}

/// Footer geometry for `storage` in the footer `r`; `chip` for a strip on
/// a WARN fill.
pub fn footer_boxes(storage: StorageLine, chip: bool, r: Rectangle, l: &Layout) -> FooterBoxes {
    let font = l.footer_font;
    let pad = if l.compact { 4 } else { 6 };
    let (st, _) = storage_text(storage, l);
    let right = r.top_left.x + r.size.width as i32;
    let token = if chip {
        // Inset from the strip edge, padded around the text.
        let inset: u32 = if l.compact { 1 } else { 2 };
        let w = text_width(st, font) as u32 + 2 * (pad as u32 / 2);
        Rectangle::new(
            Point::new(right - inset as i32 - w as i32, r.top_left.y + inset as i32),
            Size::new(w, r.size.height - 2 * inset),
        )
    } else {
        let w = text_width(st, font) as u32;
        Rectangle::new(
            Point::new(right - pad - w as i32, r.top_left.y),
            Size::new(w, r.size.height),
        )
    };
    let gap = font.character_size.width as i32;
    let text_w = (token.top_left.x - gap - r.top_left.x).max(0) as u32;
    FooterBoxes {
        token,
        text: Rectangle::new(r.top_left, Size::new(text_w, r.size.height)),
    }
}

fn footer<D: DrawTarget<Color = C444>>(
    p: &mut Painter<'_, D>,
    v: &FooterView,
    r: Rectangle,
    l: &Layout,
) {
    let font = l.footer_font;
    let pad = if l.compact { 4 } else { 6 };
    let y = r.top_left.y + (r.size.height as i32 - font.character_size.height as i32) / 2;
    let start = Point::new(r.top_left.x + pad, y);
    let sep = if l.compact { " " } else { "  " };
    // Every strip keeps the storage token at its right.  The text is a
    // main part and an optional tail, the first thing to go when the two
    // do not fit left of the token.
    let mut main: String<40> = String::new();
    let mut tail: String<24> = String::new();
    let (storage, strip) = match *v {
        FooterView::Normal {
            uptime,
            storage,
            reset,
        } => {
            let fw = if l.compact { "fw" } else { "fw " };
            let _ = write!(main, "up {}{sep}{fw}{}", fmt_uptime(uptime), FW_VERSION);
            if let Some(k) = reset {
                let _ = write!(tail, "{sep}rst: {}", k.short());
            }
            (storage, false)
        }
        FooterView::ResetWarning { info, storage } => {
            let _ = write!(main, "Last reset: {}", info.kind.name());
            if info.count > 1 {
                let _ = write!(tail, " x{}", info.count);
            }
            (storage, true)
        }
        FooterView::DevUnprovisioned { uptime, storage } => {
            let _ = main.push_str("DEV - UNPROVISIONED");
            let _ = write!(tail, "{sep}up {}", fmt_uptime(uptime));
            (storage, true)
        }
    };
    let boxes = footer_boxes(storage, strip, r, l);
    let text_col = if strip {
        p.fill(r, c::WARN);
        c::on(c::WARN)
    } else {
        l.footer_text
    };
    let room = boxes.text.top_left.x + boxes.text.size.width as i32;
    if start.x + text_width(&main, font) + text_width(&tail, font) > room {
        tail.clear();
    }
    let x = p.text(&main, start, font, text_col, boxes.text);
    p.text(&tail, Point::new(x, y), font, text_col, boxes.text);
    let (st, col) = storage_text(storage, l);
    if strip {
        // A dark chip keeps the token legible, in the normal footer's
        // colours, on the WARN fill.
        p.fill(boxes.token, c::PANEL);
        p.text_mid(st, font, col, boxes.token);
    } else {
        p.text(
            st,
            Point::new(boxes.token.top_left.x, y),
            font,
            col,
            boxes.token,
        );
    }
}

// ── Boot splash ──────────────────────────────────────────────────────────────

fn splash<D: DrawTarget<Color = C444>>(p: &mut Painter<'_, D>, v: &SplashView, l: &Layout) {
    let full = screen_rect(l);
    if v.border {
        p.frame(full, 1, c::TEXT2);
    }
    p.text_center(
        "pico2hsm",
        l.splash_title_y,
        l.splash_title_font,
        c::TEXT,
        full,
    );
    let mut s: String<40> = String::new();
    let _ = write!(s, "fw {}  {}", FW_VERSION, v.board);
    p.text_center(&s, l.splash_sub_y, l.splash_sub_font, c::DIM, full);
    let mut step: String<24> = String::new();
    let _ = match v.step {
        BootStep::Storage => write!(step, "Storage..."),
        BootStep::Keys(n) => write!(step, "Keys ({n})..."),
        BootStep::Usb => write!(step, "USB..."),
        BootStep::Starting => write!(step, "Starting..."),
    };
    p.text_center(&step, l.splash_step_y, l.splash_step_font, c::TEXT2, full);
    if let Some(info) = v.reset {
        let mut s: String<40> = String::new();
        let _ = write!(s, "Last reset: {}", info.kind.name());
        if info.count > 1 {
            let _ = write!(s, " x{}", info.count);
        }
        p.text_center(&s, l.splash_reset_y, l.splash_reset_font, c::WARN, full);
    }
}

// ── Error and notice template ────────────────────────────────────────────────

fn template<D: DrawTarget<Color = C444>>(
    p: &mut Painter<'_, D>,
    l: &Layout,
    code: Option<&str>,
    title: &str,
    level: C444,
    actions: &[&str],
    detail: &str,
    foot: &FooterView,
) {
    let band = l.err_band;
    p.fill(band, c::PANEL);
    p.fill(
        Rectangle::new(band.top_left, Size::new(l.bar_w, band.size.height)),
        level,
    );
    let title_x = match code {
        Some(code) => {
            p.text(code, l.err_code_at, l.err_font, level, band);
            l.err_title_x
        }
        None => l.err_code_at.x,
    };
    // An error's code carries its colour and the title is plain; a notice
    // has no code, so its title word takes the level colour (OK / WARN).
    let title_color = if code.is_some() { c::TEXT } else { level };
    p.text(
        title,
        Point::new(title_x, l.err_code_at.y),
        l.err_font,
        title_color,
        band,
    );
    let act = l.err_action;
    let x = l.err_code_at.x;
    for (i, line) in actions.iter().enumerate() {
        let y = act.top_left.y + 4 + i as i32 * l.err_action_pitch;
        p.text(line, Point::new(x, y), l.err_action_font, c::TEXT2, act);
    }
    let d = l.err_detail;
    p.text(
        detail,
        Point::new(x, d.top_left.y + 4),
        l.err_detail_font,
        c::DIM,
        d,
    );
    footer(p, foot, l.err_footer, l);
}

fn error<D: DrawTarget<Color = C444>>(p: &mut Painter<'_, D>, v: &ErrorView, l: &Layout) {
    let mut retry: String<24> = String::new();
    let (code, title, a1, a2, detail) = match v.code {
        ErrorCode::E10NoSdCard { attempt } => {
            let _ = write!(retry, "Retrying (try {attempt}).");
            (
                "E10",
                "NO SD CARD",
                "Insert microSD card.",
                retry.as_str(),
                if l.compact {
                    "Restarts every 8 s until found."
                } else {
                    "The device restarts every 8 s until found."
                },
            )
        }
        ErrorCode::E11StorageUnreadable => (
            "E11",
            "STORAGE UNREADABLE",
            "Keys not loaded.",
            "Run pico2hsm-tool diag.",
            "Keystore directory could not be read.",
        ),
        ErrorCode::E12FormatStoreNeeded => (
            "E12",
            "FORMAT STORE NEEDED",
            "No 2.0 keystore found.",
            "See README, 2.0.0 notes.",
            if l.compact {
                "1.x keys can't be read by 2.0."
            } else {
                "Keys stored by 1.x can't be read by 2.0."
            },
        ),
        ErrorCode::E20NotProvisioned => (
            "E20",
            "NOT PROVISIONED",
            "Keys cannot be stored.",
            "See PROVISIONING.md.",
            "No storage key in OTP.",
        ),
        ErrorCode::E31RngFailure => (
            "E31",
            "RNG FAILURE",
            "Hardware RNG failed self-test.",
            "Device halted.",
            "TRNG health test failed.",
        ),
    };
    template(
        p,
        l,
        Some(code),
        title,
        c::ERR,
        &[a1, a2],
        detail,
        &v.footer,
    );
}

fn notice<D: DrawTarget<Color = C444>>(p: &mut Painter<'_, D>, v: &NoticeView, l: &Layout) {
    let mut line: String<32> = String::new();
    let (title, level, a1, a2, detail) = match v.kind {
        NoticeKind::Enrolled { peer, domain } => {
            let _ = write!(line, "{} into {}", hex4(peer), hex4(domain));
            (
                "ENROLLED",
                c::OK,
                line.as_str(),
                "Member certificate issued.",
                "Peer and domain shown by key fingerprint.",
            )
        }
        NoticeKind::Cancelled => (
            "CANCELLED",
            c::WARN,
            "Enrollment cancelled.",
            "No key was exchanged.",
            "Start again from the host.",
        ),
        NoticeKind::Expired => (
            "CODE EXPIRED",
            c::WARN,
            "Not confirmed in 120 s.",
            "Restart enrollment on host.",
            "The old code is no longer valid.",
        ),
    };
    let detail = if l.compact && matches!(v.kind, NoticeKind::Enrolled { .. }) {
        "Fingerprints: peer, domain."
    } else {
        detail
    };
    template(p, l, None, title, level, &[a1, a2], detail, &v.footer);
}

// ── SAS ──────────────────────────────────────────────────────────────────────

fn sas<D: DrawTarget<Color = C444>>(p: &mut Painter<'_, D>, v: &SasView, l: &Layout) {
    let full = screen_rect(l);
    p.frame(full, l.sas_frame, c::SAS);
    let inner = Rectangle::new(
        Point::new(l.sas_frame as i32, l.sas_frame as i32),
        Size::new(
            u32::from(l.w) - 2 * l.sas_frame,
            u32::from(l.h) - 2 * l.sas_frame,
        ),
    );
    p.text_center(
        l.sas_title,
        l.sas_title_y,
        &embedded_graphics::mono_font::ascii::FONT_9X18_BOLD,
        c::TEXT,
        inner,
    );
    let mut d: String<8> = String::new();
    let _ = write!(d, "{:08}", v.digits % 100_000_000);
    let font = l.sas_digit_font;
    let glyph_w = font.character_size.width as i32 * 2;
    let total = 8 * glyph_w + l.sas_gap;
    let x0 = (i32::from(l.w) - total) / 2;
    p.text_x2(
        &d[..4],
        Point::new(x0, l.sas_digits_y),
        font,
        c::TEXT,
        inner,
    );
    p.text_x2(
        &d[4..],
        Point::new(x0 + 4 * glyph_w + l.sas_gap, l.sas_digits_y),
        font,
        c::TEXT,
        inner,
    );
    let mut role: String<40> = String::new();
    let _ = write!(
        role,
        "This device: {}  peer {}",
        match v.role {
            SasRole::Sponsor => "SPONSOR",
            SasRole::Joiner => "JOINER",
        },
        hex4(v.peer)
    );
    let small = &embedded_graphics::mono_font::ascii::FONT_6X13;
    p.text_center(&role, l.sas_role_y, small, c::TEXT2, inner);
    for (y, line) in l.sas_lines {
        p.text_center(line, y, small, c::TEXT, inner);
    }
    let bar = l.sas_bar;
    let w =
        bar.size.width * u32::from(v.remaining.min(SAS_TIMEOUT_SECS)) / u32::from(SAS_TIMEOUT_SECS);
    p.fill(
        Rectangle::new(bar.top_left, Size::new(w, bar.size.height)),
        c::SAS,
    );
}
