//! Host render harness: every screen and state at both resolutions.
//!
//! - Golden FNV-1a hashes of each frame (a changed pixel fails the test;
//!   the failure prints the new table to paste in after review).
//! - Text fit: no string outside its box (`ScreenDriver::overflow`).
//! - Partial updates: a frame reached by dirty-band updates equals the
//!   same frame drawn from scratch.
//! - Images: PPMs in `target/display-snapshots/<res>/`, and PNGs (1:1 and
//!   3× upscaled) in `$DISPLAY_PREVIEW_DIR/<res>/` when that is set:
//!
//! ```sh
//! DISPLAY_PREVIEW_DIR=/tmp/previews cargo test -p pico2hsm-firmware --lib \
//!     --no-default-features --features pico2_4m --target x86_64-unknown-linux-gnu display::
//! ```

extern crate std;

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::{format, path::PathBuf, string::String, vec, vec::Vec};

use pico2hsm_core::op::{Applet, OpCode, OpResult};

use super::band::{band_bytes, BAND_ROWS};
use super::driver::{Panel, ScreenDriver};
use super::fmt::Age;
use super::layout::{Layout, GEEK_240X135, WAVESHARE_320X172};
use super::view::*;
use crate::display_snapshot::{algo, SasRole};

// ── Mock panel and executor ──────────────────────────────────────────────────

struct FramePanel {
    w: usize,
    fb: Vec<u8>,
    writes: Vec<(u16, u16)>,
    /// Bands written when the backlight last came on.
    lit_after: Option<usize>,
}

impl FramePanel {
    fn new(l: &Layout) -> Self {
        FramePanel {
            w: l.w as usize,
            fb: vec![0xA5; l.w as usize * l.h as usize * 3 / 2],
            writes: Vec::new(),
            lit_after: None,
        }
    }

    fn rgb888(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.fb.len() * 2);
        for pair in self.fb.chunks_exact(3) {
            let px = [
                (pair[0] >> 4, pair[0] & 0xF, pair[1] >> 4),
                (pair[1] & 0xF, pair[2] >> 4, pair[2] & 0xF),
            ];
            for (r, g, b) in px {
                out.extend_from_slice(&[r * 17, g * 17, b * 17]);
            }
        }
        out
    }
}

impl Panel for FramePanel {
    async fn write_rows(&mut self, y0: u16, rows: u16, data: &[u8]) {
        let start = y0 as usize * self.w * 3 / 2;
        self.fb[start..start + data.len()].copy_from_slice(data);
        assert_eq!(data.len(), band_bytes(self.w as u16, rows));
        self.writes.push((y0, rows));
    }
    async fn sleep(&mut self) {
        self.lit_after = None;
    }
    async fn wake(&mut self) {}
    async fn backlight_on(&mut self) {
        self.lit_after = Some(self.writes.len());
    }
}

fn block_on<F: Future>(f: F) -> F::Output {
    fn noop(_: *const ()) {}
    fn clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    // SAFETY: the vtable functions ignore the data pointer.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut f = pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn driver<'b>(l: &'static Layout, band: &'b mut [u8]) -> ScreenDriver<'b, FramePanel> {
    ScreenDriver::new(FramePanel::new(l), l, band)
}

fn draw(l: &'static Layout, s: &Screen) -> (Vec<u8>, u32) {
    let mut band = vec![0u8; band_bytes(l.w, BAND_ROWS)];
    let mut d = driver(l, &mut band);
    block_on(d.show(s));
    (d.panel.fb.clone(), d.overflow)
}

fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

// ── Fixtures ─────────────────────────────────────────────────────────────────

const NORMAL_FOOTER: FooterView = FooterView::Normal {
    uptime: 2 * 86_400 + 4 * 3600 + 11 * 60,
    storage: StorageLine::QmiOk,
    reset: None,
};

fn home_base() -> HomeView {
    HomeView {
        status: Status::Ready,
        applet: Applet::Piv,
        admin: false,
        pin: PinTile {
            value: PinValue::NotVerified,
            left: 3,
            max: 3,
            sig_armed: false,
        },
        keys: KeysTile {
            total: 6,
            split: Some([4, 1, 1]),
        },
        domain: DomainTile::Member {
            id: 0x3F9A,
            members: 3,
        },
        activity: ActivityView::Done {
            op: OpCode::Sign,
            result: OpResult::Ok,
            age: Age::Secs(4),
            fade: Fade::Fresh,
            hint: Hint::None,
            detail: Some(OpDetail {
                algo: algo::P256,
                key_ref: 0x9A,
                sw: 0x9000,
            }),
            note: None,
        },
        footer: NORMAL_FOOTER,
    }
}

/// Every screen and state, by name, for the board with layout `l`.  Each
/// fixture is a state the firmware can reach (footers consistent with the
/// uptime and health, last-op ages within the uptime, hints consistent
/// with the PIN tile).
#[allow(clippy::vec_init_then_push)] // one entry per push reads best here
fn fixtures(l: &Layout) -> Vec<(&'static str, Screen)> {
    let board = if l.compact {
        "RP2350-Geek"
    } else {
        "RP2350-LCD-1.47"
    };
    let base = home_base();
    let mut v = Vec::new();
    v.push(("home_ready", Screen::Home(base)));
    v.push((
        "home_ready_production",
        Screen::Home(HomeView {
            keys: KeysTile {
                total: 6,
                split: None,
            },
            activity: ActivityView::Done {
                op: OpCode::Sign,
                result: OpResult::Ok,
                age: Age::Mins(3),
                fade: Fade::Old,
                hint: Hint::None,
                detail: None,
                note: None,
            },
            ..base
        }),
    ));
    v.push((
        "home_idle",
        Screen::Home(HomeView {
            applet: Applet::None,
            pin: PinTile {
                value: PinValue::NoApplet,
                left: 0,
                max: 0,
                sig_armed: false,
            },
            domain: DomainTile::None,
            activity: ActivityView::Idle,
            ..base
        }),
    ));
    v.push((
        "home_working",
        Screen::Home(HomeView {
            status: Status::Working,
            applet: Applet::Hsm,
            pin: PinTile {
                value: PinValue::Verified,
                ..base.pin
            },
            activity: ActivityView::Working {
                op: OpCode::KeyGen,
                elapsed: 75,
                phase: 9,
            },
            ..base
        }),
    ));
    v.push((
        "home_locked",
        Screen::Home(HomeView {
            status: Status::Locked,
            applet: Applet::Pgp,
            pin: PinTile {
                value: PinValue::Blocked,
                left: 0,
                max: 3,
                sig_armed: false,
            },
            activity: ActivityView::Done {
                op: OpCode::Verify,
                result: OpResult::Refused,
                age: Age::Secs(12),
                fade: Fade::Recent,
                hint: Hint::None,
                detail: Some(OpDetail {
                    algo: algo::NONE,
                    key_ref: 0,
                    sw: 0x6983,
                }),
                note: Some(Note::Unblock(Applet::Pgp)),
            },
            ..base
        }),
    ));
    v.push((
        "home_admin",
        Screen::Home(HomeView {
            applet: Applet::Piv,
            admin: true,
            // The 9C signature spent the PIN-always authorisation: not
            // armed any more, "re-verify next".
            pin: PinTile {
                value: PinValue::Verified,
                left: 3,
                max: 3,
                sig_armed: false,
            },
            activity: ActivityView::Done {
                op: OpCode::Sign,
                result: OpResult::Ok,
                age: Age::Secs(1),
                fade: Fade::Fresh,
                hint: Hint::PivPinAlways,
                detail: None,
                note: None,
            },
            ..base
        }),
    ));
    v.push((
        "home_self_domain",
        Screen::Home(HomeView {
            domain: DomainTile::SelfOnly { id: 0x7E21 },
            pin: PinTile {
                left: 1,
                ..base.pin
            },
            activity: ActivityView::Done {
                op: OpCode::Verify,
                result: OpResult::Refused,
                age: Age::Secs(4),
                fade: Fade::Fresh,
                hint: Hint::None,
                detail: Some(OpDetail {
                    algo: algo::NONE,
                    key_ref: 0,
                    sw: 0x63C1,
                }),
                note: None,
            },
            ..base
        }),
    ));
    v.push((
        "home_no_host",
        Screen::Home(HomeView {
            status: Status::NoHost,
            applet: Applet::None,
            pin: PinTile {
                value: PinValue::NoApplet,
                ..base.pin
            },
            // USB down ended the session: no last op.
            activity: ActivityView::Idle,
            // Past the 60 s reset warning, within the 24 h reset note.
            footer: FooterView::Normal {
                uptime: 75,
                storage: StorageLine::SdOk,
                reset: Some(ResetKind::Core1Stall),
            },
            ..base
        }),
    ));
    v.push((
        "home_error",
        Screen::Home(HomeView {
            status: Status::Error,
            applet: Applet::Hsm,
            domain: DomainTile::Revoked { id: 0x3F9A },
            activity: ActivityView::Done {
                op: OpCode::KeyGen,
                result: OpResult::Error,
                age: Age::Secs(2),
                fade: Fade::Fresh,
                hint: Hint::None,
                detail: Some(OpDetail {
                    algo: algo::P384,
                    key_ref: 3,
                    sw: 0x6581,
                }),
                note: Some(Note::NotSaved),
            },
            // A write to a pulled card: NOT saved, SD MISSING.  The reset
            // note is gone after 24 h.
            footer: FooterView::Normal {
                uptime: 999 * 86_400 + 23 * 3600 + 59 * 60,
                storage: StorageLine::SdMissing,
                reset: None,
            },
            ..base
        }),
    ));
    v.push((
        "home_dev_unprovisioned",
        Screen::Home(HomeView {
            // Widest strings: the age stays within the uptime.
            footer: FooterView::DevUnprovisioned {
                uptime: 9999 * 86_400 + 3599,
            },
            pin: PinTile {
                value: PinValue::Verified,
                left: 15,
                max: 15,
                sig_armed: true,
            },
            keys: KeysTile {
                total: 218,
                split: Some([200, 15, 3]),
            },
            domain: DomainTile::Member {
                id: 0xFFFF,
                members: 32,
            },
            activity: ActivityView::Done {
                op: OpCode::KeyGen,
                result: OpResult::Refused,
                age: Age::Days(9999),
                fade: Fade::Old,
                hint: Hint::None,
                detail: Some(OpDetail {
                    algo: algo::ED25519,
                    key_ref: 0x9C,
                    sw: 0x6A80,
                }),
                note: None,
            },
            ..base
        }),
    ));
    v.push((
        "home_reset_warning",
        Screen::Home(HomeView {
            // Under 60 s since boot: an OpenPGP signature 20 s ago.
            applet: Applet::Pgp,
            pin: PinTile {
                value: PinValue::NotVerified,
                left: 3,
                max: 3,
                sig_armed: false,
            },
            footer: FooterView::ResetWarning(ResetInfo {
                kind: ResetKind::Core1Stall,
                count: 2,
            }),
            activity: ActivityView::Done {
                op: OpCode::Sign,
                result: OpResult::Ok,
                age: Age::Secs(20),
                fade: Fade::Recent,
                hint: Hint::PgpSingleUse,
                detail: None,
                note: None,
            },
            ..base
        }),
    ));
    let err = |code, footer| Screen::Error(ErrorView { code, footer });
    // E10 is drawn by the boot code a few seconds after power-on.
    v.push((
        "error_e10",
        err(
            ErrorCode::E10NoSdCard { attempt: 3 },
            FooterView::Normal {
                uptime: 3,
                storage: StorageLine::SdMissing,
                reset: None,
            },
        ),
    ));
    // E11: the keystore failed to initialise, so the footer says so.
    v.push((
        "error_e11",
        err(
            ErrorCode::E11StorageUnreadable,
            FooterView::Normal {
                uptime: 12,
                storage: StorageLine::QmiFail,
                reset: None,
            },
        ),
    ));
    // E20: no storage key; the keystore itself opened fine.
    v.push((
        "error_e20",
        err(
            ErrorCode::E20NotProvisioned,
            FooterView::Normal {
                uptime: 12,
                storage: StorageLine::QmiOk,
                reset: None,
            },
        ),
    ));
    v.push(("error_e31", err(ErrorCode::E31RngFailure, NORMAL_FOOTER)));
    v.push((
        "sas",
        Screen::Sas(SasView {
            digits: 12_345_678,
            role: SasRole::Sponsor,
            peer: 0x04AA,
            remaining: 87,
        }),
    ));
    v.push((
        "sas_joiner",
        Screen::Sas(SasView {
            digits: 90_210,
            role: SasRole::Joiner,
            peer: 0x7E21,
            remaining: 120,
        }),
    ));
    let notice = |kind| {
        Screen::Notice(NoticeView {
            kind,
            footer: NORMAL_FOOTER,
        })
    };
    v.push((
        "notice_enrolled",
        notice(NoticeKind::Enrolled {
            peer: 0x7E21,
            domain: 0x3F9A,
        }),
    ));
    v.push(("notice_cancelled", notice(NoticeKind::Cancelled)));
    v.push(("notice_expired", notice(NoticeKind::Expired)));
    v.push((
        "splash",
        Screen::Splash(SplashView {
            step: BootStep::Keys(6),
            reset: None,
            border: true,
            board,
        }),
    ));
    v.push((
        "splash_reset",
        Screen::Splash(SplashView {
            step: BootStep::Usb,
            reset: Some(ResetInfo {
                kind: ResetKind::Watchdog,
                count: 1,
            }),
            border: false,
            board,
        }),
    ));
    v.push((
        "splash_starting",
        Screen::Splash(SplashView {
            step: BootStep::Starting,
            reset: None,
            border: false,
            board,
        }),
    ));
    v
}

fn layouts() -> [(&'static str, &'static Layout); 2] {
    [("320x172", &WAVESHARE_320X172), ("240x135", &GEEK_240X135)]
}

// ── Golden hashes ────────────────────────────────────────────────────────────

/// FNV-1a of each packed RGB444 frame.  After an intended visual change,
/// review the previews and paste the table the failing test prints.
const GOLDEN: &[(&str, &str, u64)] = &[
    ("320x172", "home_ready", 0x627da0ed0972c0a9),
    ("320x172", "home_ready_production", 0xbdd5f623ac2c39e7),
    ("320x172", "home_idle", 0xe917a05fac71d61d),
    ("320x172", "home_working", 0xcf10ea33a4fc3da0),
    ("320x172", "home_locked", 0xe1b89a2fb34f69a9),
    ("320x172", "home_admin", 0xf6c7c3f816325526),
    ("320x172", "home_self_domain", 0xc8936cce938314c1),
    ("320x172", "home_no_host", 0xb126811dab17f7d3),
    ("320x172", "home_error", 0x26df370bde651cb6),
    ("320x172", "home_dev_unprovisioned", 0x5271f4d02322a7e1),
    ("320x172", "home_reset_warning", 0xbd7d495c2866c8e2),
    ("320x172", "error_e10", 0x4f3f75292f218a24),
    ("320x172", "error_e11", 0xdb4282bc268bdebf),
    ("320x172", "error_e20", 0x3f98f14b030b7f27),
    ("320x172", "error_e31", 0x189a3a0be0fb7940),
    ("320x172", "sas", 0x9d50546a1ae4fd33),
    ("320x172", "sas_joiner", 0xd6fd795734312e93),
    ("320x172", "notice_enrolled", 0x9dcb42f99313328f),
    ("320x172", "notice_cancelled", 0x4b8795ad7198a0b8),
    ("320x172", "notice_expired", 0x0625dbda9ef5338c),
    ("320x172", "splash", 0x6bb098a138ac7399),
    ("320x172", "splash_reset", 0x8c4f3e6f6c5a1859),
    ("320x172", "splash_starting", 0xc5c875866acee383),
    ("240x135", "home_ready", 0x43a389b4412bd678),
    ("240x135", "home_ready_production", 0x274611b82e4763c7),
    ("240x135", "home_idle", 0x46e9af0bf86674b8),
    ("240x135", "home_working", 0x720c47340248b528),
    ("240x135", "home_locked", 0x4d9a3814a22c279f),
    ("240x135", "home_admin", 0x51119cfb949c1799),
    ("240x135", "home_self_domain", 0xb3d6ab1e23558354),
    ("240x135", "home_no_host", 0xfb794b54e7e657a8),
    ("240x135", "home_error", 0x6ec642baafd8b35b),
    ("240x135", "home_dev_unprovisioned", 0x1ba5d7cf9e4340cd),
    ("240x135", "home_reset_warning", 0x5977d6371adcba64),
    ("240x135", "error_e10", 0xdffc3e2658f794a8),
    ("240x135", "error_e11", 0x48d93efaa1149e07),
    ("240x135", "error_e20", 0x6f7cf50a6b61c279),
    ("240x135", "error_e31", 0x0e7574f1ca5c6759),
    ("240x135", "sas", 0x23a77eb2546c997f),
    ("240x135", "sas_joiner", 0xb14ceabcb49fd407),
    ("240x135", "notice_enrolled", 0xc62a492f0411f347),
    ("240x135", "notice_cancelled", 0x4873b63b9609a86a),
    ("240x135", "notice_expired", 0x07cccb611ba46863),
    ("240x135", "splash", 0x7f35e6b0ed0ee6bb),
    ("240x135", "splash_reset", 0x08735cb2a3511dd1),
    ("240x135", "splash_starting", 0xa5dd5e3c52b01ee1),
];

#[test]
fn golden_frames() {
    let mut table = String::new();
    let mut mismatches = 0;
    for (res, l) in layouts() {
        for (name, s) in fixtures(l) {
            let (fb, _) = draw(l, &s);
            let h = fnv1a(&fb);
            table += &format!("    (\"{res}\", \"{name}\", 0x{h:016x}),\n");
            match GOLDEN.iter().find(|(r, n, _)| *r == res && *n == name) {
                Some((_, _, g)) if *g == h => {}
                _ => mismatches += 1,
            }
        }
    }
    assert!(
        mismatches == 0,
        "{mismatches} frame(s) differ from the golden table; new table:\n{table}"
    );
}

#[test]
fn text_fits_its_box() {
    for (res, l) in layouts() {
        for (name, s) in fixtures(l) {
            let (_, overflow) = draw(l, &s);
            assert_eq!(overflow, 0, "{res}/{name}: text outside its box");
        }
    }
}

#[test]
fn partial_updates_equal_full_redraws() {
    for (res, l) in layouts() {
        let all = fixtures(l);
        let mut band = vec![0u8; band_bytes(l.w, BAND_ROWS)];
        let mut d = driver(l, &mut band);
        // Walk every pair in both directions.
        for (i, (_, a)) in all.iter().enumerate() {
            for (name, b) in all.iter().skip(i) {
                for s in [a, b] {
                    block_on(d.show(s));
                    let (full, _) = draw(l, s);
                    assert!(
                        d.panel.fb == full,
                        "{res}: partial update to {name} differs"
                    );
                }
            }
        }
    }
}

#[test]
fn one_hz_tick_redraws_only_the_footer() {
    for (res, l) in layouts() {
        let mut band = vec![0u8; band_bytes(l.w, BAND_ROWS)];
        let mut d = driver(l, &mut band);
        let a = home_base();
        block_on(d.show(&Screen::Home(a)));
        let full = d.panel.writes.len();
        assert_eq!(full, l.h.div_ceil(BAND_ROWS) as usize);
        let b = HomeView {
            footer: FooterView::Normal {
                uptime: 2 * 86_400 + 4 * 3600 + 12 * 60,
                storage: StorageLine::QmiOk,
                reset: None,
            },
            ..a
        };
        block_on(d.show(&Screen::Home(b)));
        let sent = d.panel.writes.len() - full;
        assert!(sent <= 2, "{res}: footer tick sent {sent} bands");
        // Nothing changed: nothing sent.
        block_on(d.show(&Screen::Home(b)));
        assert_eq!(d.panel.writes.len() - full, sent);
    }
}

#[test]
fn backlight_comes_on_after_the_full_redraw() {
    for (res, l) in layouts() {
        let mut band = vec![0u8; band_bytes(l.w, BAND_ROWS)];
        let mut d = driver(l, &mut band);
        let a = Screen::Home(home_base());
        block_on(d.show(&a));
        block_on(d.sleep());
        block_on(d.wake());
        assert_eq!(d.panel.lit_after, None, "{res}: dark until redrawn");
        let before = d.panel.writes.len();
        block_on(d.show(&a));
        let bands = l.h.div_ceil(BAND_ROWS) as usize;
        assert_eq!(
            d.panel.lit_after,
            Some(before + bands),
            "{res}: backlight on only after every band"
        );
    }
}

#[test]
fn sas_colour_is_reserved() {
    // Only the pending-SAS screen may contain the SAS colour.
    let sas = super::color::SAS.rgb888();
    for (res, l) in layouts() {
        for (name, s) in fixtures(l) {
            let (fb, _) = draw(l, &s);
            let mut p = FramePanel::new(l);
            p.fb = fb;
            let has = p.rgb888().chunks_exact(3).any(|px| px == sas);
            assert_eq!(has, matches!(s, Screen::Sas(_)), "{res}/{name}");
        }
    }
}

// ── Image output ─────────────────────────────────────────────────────────────

fn write_ppm(path: &PathBuf, w: usize, h: usize, rgb: &[u8]) {
    let mut out = format!("P6\n{w} {h}\n255\n").into_bytes();
    out.extend_from_slice(rgb);
    std::fs::write(path, out).unwrap();
}

fn write_png(path: &PathBuf, w: usize, h: usize, rgb: &[u8]) {
    let file = std::fs::File::create(path).unwrap();
    let mut enc = png::Encoder::new(std::io::BufWriter::new(file), w as u32, h as u32);
    enc.set_color(png::ColorType::Rgb);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header().unwrap().write_image_data(rgb).unwrap();
}

fn upscale(rgb: &[u8], w: usize, h: usize, k: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(rgb.len() * k * k);
    for y in 0..h * k {
        for x in 0..w * k {
            let i = ((y / k) * w + x / k) * 3;
            out.extend_from_slice(&rgb[i..i + 3]);
        }
    }
    out
}

#[test]
fn write_previews() {
    let ppm_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/display-snapshots");
    let png_root = std::env::var_os("DISPLAY_PREVIEW_DIR").map(PathBuf::from);
    for (res, l) in layouts() {
        let (w, h) = (l.w as usize, l.h as usize);
        let ppm_dir = ppm_root.join(res);
        std::fs::create_dir_all(&ppm_dir).unwrap();
        for (name, s) in fixtures(l) {
            let mut p = FramePanel::new(l);
            p.fb = draw(l, &s).0;
            let rgb = p.rgb888();
            write_ppm(&ppm_dir.join(format!("{name}.ppm")), w, h, &rgb);
            if let Some(root) = &png_root {
                let dir = root.join(res);
                std::fs::create_dir_all(dir.join("3x")).unwrap();
                write_png(&dir.join(format!("{name}.png")), w, h, &rgb);
                let big = upscale(&rgb, w, h, 3);
                write_png(
                    &dir.join("3x").join(format!("{name}.png")),
                    w * 3,
                    h * 3,
                    &big,
                );
            }
        }
    }
}
