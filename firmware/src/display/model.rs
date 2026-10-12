//! What to show, decided from core1's snapshot and core0's inputs.
//!
//! [`Controller::step`] is pure apart from its own small memory (when the
//! last operation finished, when the screen last changed, the SAS
//! deadline), so the display task's behaviour is host-tested: status
//! priority, stale authentication, screensaver rules, SAS expiry.

use pico2hsm_core::op::{Applet, OpCode};

use super::fmt::Age;
use super::view::*;
use crate::display_snapshot::{
    auth, blocked, health, hint, oneshot, Activity, DomainState, OpState, SasMail, SasState,
    Snapshot,
};
use crate::watchdog::{BootReport, LastReset, ResetCause};

/// WORKING shows only after an operation has run this long.
pub const WORKING_AFTER_MS: u32 = 300;
/// Idle time before the screen sleeps.
pub const SCREENSAVER_MS: u64 = 300_000;
/// Progress-bar step while WORKING.
pub const WORKING_TICK_MS: u64 = 250;
/// Enrollment notices stay this long.
pub const NOTICE_MS: u64 = 10_000;
/// The reset warning replaces the footer this long after boot.
pub const RESET_WARNING_MS: u64 = 60_000;
/// The footer names a non-power-on reset this long after boot.
pub const RESET_NOTE_MS: u64 = 24 * 3600 * 1000;

/// Which keystore the board has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageKind {
    /// Internal QSPI flash.
    Qmi,
    /// SD card.
    Sd,
}

/// Facts fixed at boot.
#[derive(Clone, Copy, Debug)]
pub struct StaticInfo {
    /// Keystore medium.
    pub storage: StorageKind,
    /// Debug build: per-applet key split, op detail.
    pub detail: bool,
    /// The previous run's end, if not a power-on.
    pub reset: Option<ResetInfo>,
    /// Board name (boot splash, and the "starting" screen shown while no
    /// snapshot has been published yet).
    pub board: &'static str,
}

/// Map a boot report to what the display says about it (`None` for a
/// power-on / RUN-pin / debugger reset).
pub fn reset_info(r: &BootReport) -> Option<ResetInfo> {
    let kind = match r.last {
        LastReset::Other => return None,
        LastReset::Timeout(None) => ResetKind::Watchdog,
        LastReset::Forced(None) => ResetKind::Forced,
        LastReset::Timeout(Some(c)) | LastReset::Forced(Some(c)) => match c {
            ResetCause::Core1Stall | ResetCause::FeederCore1Stall => ResetKind::Core1Stall,
            ResetCause::RngFailure => ResetKind::Rng,
            ResetCause::BootCheck => ResetKind::BootCheck,
            ResetCause::DebugTest => ResetKind::Test,
        },
    };
    Some(ResetInfo {
        kind,
        count: r.wdt_resets.max(1),
    })
}

/// One sample of every input.
#[derive(Clone, Copy, Debug)]
pub struct Inputs {
    /// Core0 uptime, ms.
    pub now_ms: u64,
    /// Core1's latest snapshot.
    pub snap: Option<Snapshot>,
    /// SAS mailbox.
    pub sas: SasMail,
    /// USB configured by a host.
    pub usb_configured: bool,
    /// The current `SESSION_EPOCH` (all 32 bits).
    pub session_epoch: u32,
    /// How long the APDU in flight has run, if any.
    pub busy_ms: Option<u32>,
}

/// What the display task does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    /// What to show.
    pub screen: Screen,
    /// The panel should be asleep.
    pub sleep: bool,
    /// LED colour.
    pub led: LedTone,
    /// Wake up again by then (ms), besides the 1 Hz tick and kicks.
    pub deadline_ms: Option<u64>,
}

/// The last finished operation, as first seen by core0.
#[derive(Clone, Copy, Debug)]
struct Finished {
    activity: Activity,
    sw: u16,
    at_ms: u64,
    epoch: u32,
}

/// The display task's memory; see the module docs.
#[derive(Debug)]
pub struct Controller {
    info: StaticInfo,
    last: Option<Finished>,
    seen_op: bool,
    activity_ms: u64,
    prev_key: Option<(Snapshot, SasMail, bool, bool)>,
    sas_gen: Option<u32>,
    sas_deadline_ms: u64,
    sas_prev_state: SasState,
    notice: Option<(NoticeKind, u64)>,
}

impl Controller {
    /// A controller for a board.
    pub fn new(info: StaticInfo, now_ms: u64) -> Self {
        Controller {
            info,
            last: None,
            seen_op: false,
            activity_ms: now_ms,
            prev_key: None,
            sas_gen: None,
            sas_deadline_ms: 0,
            sas_prev_state: SasState::None,
            notice: None,
        }
    }

    /// Footer for `snap` at `now_ms`.
    pub fn footer(&self, snap: &Snapshot, now_ms: u64) -> FooterView {
        let uptime = (now_ms / 1000) as u32;
        let f = snap.health.flags;
        // Every footer strip carries storage health, so neither warning
        // strip can hide it.
        let failed = f & (health::KS_INIT_FAILED | health::STORE_WRITE_FAILED) != 0;
        let storage = match (self.info.storage, failed) {
            (StorageKind::Sd, _) if f & health::SD_MISSING != 0 => StorageLine::SdMissing,
            (StorageKind::Sd, true) => StorageLine::SdFail,
            (StorageKind::Sd, false) => StorageLine::SdOk,
            (StorageKind::Qmi, true) => StorageLine::QmiFail,
            (StorageKind::Qmi, false) => StorageLine::QmiOk,
        };
        if let Some(info) = self.info.reset {
            if now_ms < RESET_WARNING_MS {
                return FooterView::ResetWarning { info, storage };
            }
        }
        if f & health::PROVISIONED == 0 && f & health::SMK_MISSING == 0 {
            return FooterView::DevUnprovisioned { uptime, storage };
        }
        let reset = self
            .info
            .reset
            .filter(|_| now_ms < RESET_NOTE_MS)
            .map(|r| r.kind);
        FooterView::Normal {
            uptime,
            storage,
            reset,
        }
    }

    /// Decide the next frame.
    pub fn step(&mut self, i: &Inputs) -> Frame {
        let now = i.now_ms;
        // No snapshot yet: fail closed.  A neutral "starting" screen, never
        // READY, never authentication (an all-zero default would read as a
        // healthy, provisioned-looking READY).
        let Some(snap) = i.snap else {
            return Frame {
                screen: Screen::Splash(SplashView {
                    step: BootStep::Starting,
                    reset: self.info.reset,
                    border: self.info.detail,
                    board: self.info.board,
                }),
                sleep: false,
                led: LedTone::Off,
                deadline_ms: None,
            };
        };
        let busy = i.busy_ms.is_some();

        // Anything that changed counts as activity for the screensaver.
        let key = (snap, i.sas, i.usb_configured, busy);
        if self.prev_key != Some(key) {
            self.prev_key = Some(key);
            self.activity_ms = now;
        }

        // Track the last finished operation (first seen now).
        let a = snap.activity;
        if a.state == OpState::Done && a.op != OpCode::None {
            // Same op_seq with a new result or SW: a GET RESPONSE completed
            // it (the age is kept below).
            let new = self.last.map_or(true, |f| {
                f.activity.op_seq != a.op_seq || f.activity != a || f.sw != snap.last_sw
            });
            if new {
                let same_op = self.last.is_some_and(|f| f.activity.op_seq == a.op_seq);
                self.last = Some(Finished {
                    activity: a,
                    sw: snap.last_sw,
                    at_ms: if same_op {
                        self.last.map_or(now, |f| f.at_ms)
                    } else {
                        now
                    },
                    epoch: i.session_epoch,
                });
                self.seen_op = true;
            }
        }
        if a.state == OpState::InProgress {
            self.seen_op = true;
        }

        let footer = self.footer(&snap, now);
        let flags = snap.health.flags;

        // ── SAS mailbox ──────────────────────────────────────────────────
        // A pending code is shown only in the session it was published for,
        // with USB up (spec §4.7: it never outlives its session).  Core1
        // clears the mailbox only at the next APDU; until then a stale code
        // reads as cancelled, never as the old digits.
        let mut mail = i.sas;
        if mail.state == SasState::Pending && (!i.usb_configured || mail.epoch != i.session_epoch) {
            mail.state = SasState::Cancelled;
            mail.digits = 0;
        }
        if mail.state == SasState::Pending && self.sas_gen != Some(mail.gen) {
            self.sas_gen = Some(mail.gen);
            self.sas_deadline_ms = now + u64::from(SAS_TIMEOUT_SECS) * 1000;
            self.notice = None;
        }
        if self.sas_prev_state == SasState::Pending && mail.state != SasState::Pending {
            let kind = match mail.state {
                SasState::Enrolled => Some(NoticeKind::Enrolled {
                    peer: mail.peer_fp,
                    domain: snap.health.domain_id_hi16,
                }),
                SasState::Cancelled => Some(NoticeKind::Cancelled),
                SasState::Expired => Some(NoticeKind::Expired),
                SasState::None | SasState::Pending => None,
            };
            if let Some(k) = kind {
                self.notice = Some((k, now + NOTICE_MS));
            }
        }
        self.sas_prev_state = mail.state;
        if mail.state == SasState::Pending {
            if now < self.sas_deadline_ms {
                let remaining = ((self.sas_deadline_ms - now).div_ceil(1000)) as u16;
                return Frame {
                    screen: Screen::Sas(SasView {
                        digits: mail.digits,
                        role: mail.role,
                        peer: mail.peer_fp,
                        remaining,
                    }),
                    sleep: false,
                    led: LedTone::Magenta,
                    deadline_ms: Some(now + 1000),
                };
            }
            // Past the deadline: never the stale code.
            if self.notice.is_none() {
                self.notice = Some((NoticeKind::Expired, now + NOTICE_MS));
            }
        }
        if let Some((kind, until)) = self.notice {
            if now < until {
                let led = match kind {
                    NoticeKind::Enrolled { .. } => LedTone::Green,
                    _ => LedTone::Yellow,
                };
                return Frame {
                    screen: Screen::Notice(NoticeView { kind, footer }),
                    sleep: false,
                    led,
                    deadline_ms: Some(until),
                };
            }
            if mail.state != SasState::Pending {
                self.notice = None;
            }
        }

        // ── Full-screen errors ───────────────────────────────────────────
        let error = if flags & health::SMK_MISSING != 0 {
            Some(ErrorCode::E20NotProvisioned)
        } else if flags & health::KS_INIT_FAILED != 0 && !self.seen_op {
            Some(ErrorCode::E11StorageUnreadable)
        } else {
            None
        };
        if let Some(code) = error {
            return Frame {
                screen: Screen::Error(ErrorView { code, footer }),
                sleep: false,
                led: LedTone::Red,
                deadline_ms: None,
            };
        }

        // ── Home ─────────────────────────────────────────────────────────
        let s = snap.session;
        // Authentication is shown only for the current session with USB up.
        let live = i.usb_configured && s.epoch == i.session_epoch;
        let (applet, auth_bits, oneshot_bits) = if live {
            (s.applet, s.auth, s.oneshot)
        } else {
            (Applet::None, 0, 0)
        };
        let blocked_bit = match applet {
            Applet::Hsm => blocked::HSM,
            Applet::Piv => blocked::PIV,
            Applet::Pgp => blocked::PGP,
            Applet::None => 0,
        };
        let is_blocked = s.blocked & blocked_bit != 0;
        let working = i.busy_ms.is_some_and(|ms| ms >= WORKING_AFTER_MS);

        let status = if flags
            & (health::STORE_WRITE_FAILED | health::KS_INIT_FAILED | health::SD_MISSING)
            != 0
        {
            Status::Error
        } else if is_blocked {
            Status::Locked
        } else if working {
            Status::Working
        } else if !i.usb_configured {
            Status::NoHost
        } else {
            Status::Ready
        };

        let verified = match applet {
            Applet::Hsm => auth_bits & auth::HSM_USER != 0,
            Applet::Piv => auth_bits & auth::PIV_PIN != 0,
            Applet::Pgp => auth_bits & (auth::PGP_PW1_81 | auth::PGP_PW1_82) != 0,
            Applet::None => false,
        };
        let pin = PinTile {
            value: if applet == Applet::None {
                PinValue::NoApplet
            } else if is_blocked {
                PinValue::Blocked
            } else if verified {
                PinValue::Verified
            } else {
                PinValue::NotVerified
            },
            left: s.pri_left,
            max: s.pri_max,
            sig_armed: match applet {
                Applet::Piv => oneshot_bits & oneshot::PIV_9C_ARMED != 0,
                Applet::Pgp => oneshot_bits & oneshot::PGP_SIG_SINGLE != 0,
                _ => false,
            },
        };

        let inv = snap.inventory;
        let keys = KeysTile {
            total: u16::from(inv.keys_hsm) + u16::from(inv.keys_piv) + u16::from(inv.keys_pgp),
            split: self
                .info
                .detail
                .then_some([inv.keys_hsm, inv.keys_piv, inv.keys_pgp]),
        };
        let id = snap.health.domain_id_hi16;
        let domain = match inv.domain {
            DomainState::None => DomainTile::None,
            DomainState::SelfOnly => DomainTile::SelfOnly { id },
            DomainState::Member => DomainTile::Member {
                id,
                members: inv.members,
            },
            DomainState::Revoked => DomainTile::Revoked { id },
        };

        let note = if flags & health::STORE_WRITE_FAILED != 0 {
            Some(Note::NotSaved)
        } else if flags & health::SD_MISSING != 0 {
            Some(Note::SdMissing)
        } else if flags & health::KS_INIT_FAILED != 0 {
            Some(Note::StorageUnreadable)
        } else if is_blocked {
            Some(Note::Unblock(applet))
        } else {
            None
        };

        let activity = if let Some(ms) = i.busy_ms.filter(|_| working) {
            let op = if a.state == OpState::InProgress {
                a.op
            } else {
                OpCode::Other
            };
            ActivityView::Working {
                op,
                elapsed: ms / 1000,
                phase: ((ms / WORKING_TICK_MS as u32) % 256) as u8,
            }
        } else {
            // The last operation outlives its session (pcscd ends sessions
            // between commands), dimmed once that session has ended; "Idle"
            // means nothing since boot.  It shows what production already
            // shows (category, result, age; detail only in debug builds),
            // and drops the hint, which is about the ended session's PIN.
            match self.last {
                Some(f) => {
                    let age = (now.saturating_sub(f.at_ms) / 1000) as u32;
                    let ended = !(i.usb_configured && f.epoch == i.session_epoch);
                    ActivityView::Done {
                        op: f.activity.op,
                        result: f.activity.result,
                        age: Age::of_secs(age),
                        fade: Fade::of_secs(age),
                        hint: match f.activity.hint {
                            _ if ended => Hint::None,
                            hint::PIV_PIN_ALWAYS => Hint::PivPinAlways,
                            hint::PGP_SINGLE_USE => Hint::PgpSingleUse,
                            _ => Hint::None,
                        },
                        detail: self.info.detail.then_some(OpDetail {
                            algo: f.activity.algo,
                            key_ref: f.activity.key_ref,
                            sw: f.sw,
                        }),
                        note,
                        ended,
                    }
                }
                None => ActivityView::Idle,
            }
        };

        let admin = auth_bits & auth::ADMIN != 0;
        // The screensaver never hides an error, a lock, live admin
        // authorisation or work in progress.
        let may_sleep = matches!(status, Status::Ready | Status::NoHost) && !admin;
        let sleep = may_sleep && now.saturating_sub(self.activity_ms) >= SCREENSAVER_MS;

        let deadline_ms = match i.busy_ms {
            Some(ms) if ms < WORKING_AFTER_MS => Some(now + u64::from(WORKING_AFTER_MS - ms)),
            Some(_) => Some(now + WORKING_TICK_MS),
            None => None,
        };

        Frame {
            screen: Screen::Home(HomeView {
                status,
                applet,
                admin,
                pin,
                keys,
                domain,
                activity,
                footer,
            }),
            sleep,
            led: LedTone::of_status(status),
            deadline_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display_snapshot::{Health, SasRole, Session};
    use pico2hsm_core::op::OpResult;

    fn info() -> StaticInfo {
        StaticInfo {
            storage: StorageKind::Qmi,
            detail: false,
            reset: None,
            board: "test",
        }
    }

    fn snap() -> Snapshot {
        Snapshot {
            session: Session {
                epoch: 3,
                applet: Applet::Piv,
                pri_left: 3,
                pri_max: 3,
                ..Default::default()
            },
            health: Health {
                domain_id_hi16: 0,
                flags: health::PROVISIONED,
            },
            ..Default::default()
        }
    }

    fn inputs(now_ms: u64, s: Snapshot) -> Inputs {
        Inputs {
            now_ms,
            snap: Some(s),
            sas: SasMail::default(),
            usb_configured: true,
            session_epoch: 3,
            busy_ms: None,
        }
    }

    fn home(f: &Frame) -> HomeView {
        match f.screen {
            Screen::Home(h) => h,
            other => panic!("not home: {other:?}"),
        }
    }

    #[test]
    fn status_priority() {
        let mut c = Controller::new(info(), 0);
        let mut s = snap();
        assert_eq!(home(&c.step(&inputs(1, s))).status, Status::Ready);
        let mut i = inputs(1, s);
        i.usb_configured = false;
        assert_eq!(home(&c.step(&i)).status, Status::NoHost);
        i.busy_ms = Some(299);
        assert_eq!(
            home(&c.step(&i)).status,
            Status::NoHost,
            "no flicker < 300 ms"
        );
        i.busy_ms = Some(300);
        assert_eq!(home(&c.step(&i)).status, Status::Working);
        s.session.blocked = blocked::PIV;
        i.snap = Some(s);
        i.usb_configured = true;
        assert_eq!(home(&c.step(&i)).status, Status::Locked);
        s.health.flags |= health::STORE_WRITE_FAILED;
        i.snap = Some(s);
        let h = home(&c.step(&i));
        assert_eq!(h.status, Status::Error);
        assert_eq!(h.footer, c.footer(&s, 1), "footer reports the failure");
    }

    #[test]
    fn stale_session_shows_no_authentication() {
        let mut c = Controller::new(info(), 0);
        let mut s = snap();
        s.session.auth = auth::PIV_PIN | auth::PIV_MGMT;
        let h = home(&c.step(&inputs(1, s)));
        assert_eq!(h.pin.value, PinValue::Verified);
        assert!(h.admin);
        // Card power-off / USB reset: SESSION_EPOCH moved on.
        let mut i = inputs(2, s);
        i.session_epoch = 4;
        let h = home(&c.step(&i));
        assert_eq!(h.pin.value, PinValue::NoApplet);
        assert!(!h.admin);
        // 256 sessions later the low byte matches again: still stale.
        let mut i = inputs(2, s);
        i.session_epoch = 3 + 256;
        let h = home(&c.step(&i));
        assert_eq!(h.pin.value, PinValue::NoApplet);
        assert!(!h.admin);
        assert_eq!(h.applet, Applet::None);
        // USB gone.
        let mut i = inputs(3, s);
        i.usb_configured = false;
        assert!(!home(&c.step(&i)).admin);
    }

    #[test]
    fn last_op_ages_and_fades_but_stays() {
        let mut c = Controller::new(info(), 0);
        let mut s = snap();
        assert_eq!(home(&c.step(&inputs(0, s))).activity, ActivityView::Idle);
        s.activity = Activity {
            op_seq: 1,
            op: OpCode::Sign,
            state: OpState::Done,
            result: OpResult::Ok,
            ..Default::default()
        };
        let at = |c: &mut Controller, t: u64| match home(&c.step(&inputs(t, s))).activity {
            ActivityView::Done { age, fade, .. } => (age, fade),
            other => panic!("{other:?}"),
        };
        assert_eq!(at(&mut c, 1_000), (Age::Secs(0), Fade::Fresh));
        assert_eq!(at(&mut c, 5_000), (Age::Secs(4), Fade::Fresh));
        assert_eq!(at(&mut c, 30_000), (Age::Secs(29), Fade::Recent));
        assert_eq!(at(&mut c, 3_601_000), (Age::Hours(1), Fade::Old));
    }

    #[test]
    fn last_op_outlives_its_session_dimmed() {
        let mut c = Controller::new(info(), 0);
        let mut s = snap();
        s.session.auth = auth::PIV_PIN | auth::PIV_MGMT;
        s.activity = Activity {
            op_seq: 1,
            op: OpCode::Sign,
            state: OpState::Done,
            result: OpResult::Ok,
            hint: hint::PIV_PIN_ALWAYS,
            ..Default::default()
        };
        let done = |f: &Frame| match home(f).activity {
            ActivityView::Done {
                op,
                age,
                hint,
                ended,
                detail,
                ..
            } => (op, age, hint, ended, detail),
            other => panic!("{other:?}"),
        };
        let f = c.step(&inputs(1_000, s));
        assert_eq!(
            done(&f),
            (OpCode::Sign, Age::Secs(0), Hint::PivPinAlways, false, None)
        );
        assert!(home(&f).admin);
        // pcscd ended the session: the op stays, dimmed, with its age and
        // without the hint; authentication and ADMIN clear as before.
        let mut i = inputs(5_000, s);
        i.session_epoch = 4;
        let f = c.step(&i);
        assert_eq!(
            done(&f),
            (OpCode::Sign, Age::Secs(4), Hint::None, true, None),
            "production shows no detail"
        );
        let h = home(&f);
        assert!(!h.admin);
        assert_eq!(h.pin.value, PinValue::NoApplet);
        assert_eq!(h.applet, Applet::None);
        // USB down ends it too.
        let mut i = inputs(6_000, s);
        i.usb_configured = false;
        let f = c.step(&i);
        assert!(done(&f).3);
        assert!(!home(&f).admin);
        assert_eq!(home(&f).status, Status::NoHost);
    }

    #[test]
    fn idle_only_before_the_first_op() {
        let mut c = Controller::new(info(), 0);
        let s = snap();
        let mut i = inputs(1_000, s);
        assert_eq!(home(&c.step(&i)).activity, ActivityView::Idle);
        i.session_epoch = 9;
        i.usb_configured = false;
        assert_eq!(home(&c.step(&i)).activity, ActivityView::Idle);
    }

    #[test]
    fn working_names_core1s_op() {
        let mut c = Controller::new(info(), 0);
        let mut s = snap();
        s.activity = Activity {
            op_seq: 4,
            op: OpCode::KeyGen,
            state: OpState::InProgress,
            ..Default::default()
        };
        let mut i = inputs(10_000, s);
        i.busy_ms = Some(61_000);
        let f = c.step(&i);
        match home(&f).activity {
            ActivityView::Working { op, elapsed, .. } => {
                assert_eq!((op, elapsed), (OpCode::KeyGen, 61));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(f.deadline_ms, Some(10_000 + WORKING_TICK_MS));
        assert!(!f.sleep);
    }

    #[test]
    fn screensaver_rules() {
        let mut c = Controller::new(info(), 0);
        let s = snap();
        assert!(!c.step(&inputs(1, s)).sleep);
        assert!(c.step(&inputs(SCREENSAVER_MS + 1, s)).sleep);
        // Any change wakes it.
        let mut t = s;
        t.inventory.keys_hsm = 1;
        assert!(!c.step(&inputs(SCREENSAVER_MS + 2, t)).sleep);
        // Never while admin is live, or locked.
        let mut a = t;
        a.session.auth = auth::HSM_SO;
        assert!(!c.step(&inputs(2 * SCREENSAVER_MS + 10, a)).sleep);
        assert!(!c.step(&inputs(4 * SCREENSAVER_MS, a)).sleep);
        let mut b = t;
        b.session.blocked = blocked::PIV;
        c.step(&inputs(5 * SCREENSAVER_MS, b));
        assert!(!c.step(&inputs(7 * SCREENSAVER_MS, b)).sleep);
    }

    #[test]
    fn sas_shows_then_expires_never_stale() {
        let mut c = Controller::new(info(), 0);
        let s = snap();
        let mut i = inputs(1_000, s);
        i.sas = SasMail {
            gen: 1,
            digits: 12_345_678,
            role: SasRole::Sponsor,
            peer_fp: 0x04AA,
            state: SasState::Pending,
            epoch: 3,
        };
        let f = c.step(&i);
        assert!(matches!(
            f.screen,
            Screen::Sas(SasView { remaining: 120, .. })
        ));
        assert_eq!(f.led, LedTone::Magenta);
        // The screensaver never hides it.
        i.now_ms = 1_000 + 119_000;
        assert!(matches!(
            c.step(&i).screen,
            Screen::Sas(SasView { remaining: 1, .. })
        ));
        i.now_ms = 1_000 + 120_000;
        let f = c.step(&i);
        assert!(
            matches!(
                f.screen,
                Screen::Notice(NoticeView {
                    kind: NoticeKind::Expired,
                    ..
                })
            ),
            "{f:?}"
        );
        // A new code (new gen) restarts the deadline.
        i.sas.gen = 2;
        i.now_ms += 1;
        assert!(matches!(c.step(&i).screen, Screen::Sas(_)));
        // Completion shows a notice, then home.
        i.sas.state = SasState::Enrolled;
        i.now_ms += 1;
        assert!(matches!(c.step(&i).screen, Screen::Notice(_)));
        i.now_ms += NOTICE_MS;
        assert!(matches!(c.step(&i).screen, Screen::Home(_)));
    }

    #[test]
    fn no_snapshot_fails_closed() {
        let mut c = Controller::new(info(), 0);
        let mut i = inputs(1, snap());
        i.snap = None;
        let f = c.step(&i);
        assert!(
            matches!(
                f.screen,
                Screen::Splash(SplashView {
                    step: BootStep::Starting,
                    ..
                })
            ),
            "{f:?}"
        );
        assert_ne!(f.led, LedTone::of_status(Status::Ready));
        assert!(!f.sleep);
    }

    #[test]
    fn sd_missing_is_an_error() {
        let mut c = Controller::new(
            StaticInfo {
                storage: StorageKind::Sd,
                ..info()
            },
            0,
        );
        let mut s = snap();
        s.activity = Activity {
            op_seq: 1,
            op: OpCode::Sign,
            state: OpState::Done,
            result: OpResult::Error,
            ..Default::default()
        };
        s.health.flags |= health::SD_MISSING;
        let h = home(&c.step(&inputs(1, s)));
        assert_eq!(h.status, Status::Error);
        assert!(matches!(
            h.footer,
            FooterView::Normal {
                storage: StorageLine::SdMissing,
                ..
            }
        ));
        assert!(matches!(
            h.activity,
            ActivityView::Done {
                note: Some(Note::SdMissing),
                ..
            }
        ));
        // The card answers again: READY.
        s.health.flags &= !health::SD_MISSING;
        assert_eq!(home(&c.step(&inputs(2, s))).status, Status::Ready);
    }

    #[test]
    fn get_response_result_updates_the_same_op() {
        let mut c = Controller::new(
            StaticInfo {
                detail: true,
                ..info()
            },
            0,
        );
        let mut s = snap();
        s.activity = Activity {
            op_seq: 1,
            op: OpCode::Sign,
            state: OpState::Done,
            ..Default::default()
        };
        s.last_sw = 0x6110;
        c.step(&inputs(1_000, s));
        s.activity.result = OpResult::Error;
        s.last_sw = 0x6F00;
        match home(&c.step(&inputs(3_000, s))).activity {
            ActivityView::Done {
                result,
                age,
                detail,
                ..
            } => {
                assert_eq!(result, OpResult::Error);
                assert_eq!(age, Age::Secs(2), "same op: its age is kept");
                assert_eq!(detail.map(|d| d.sw), Some(0x6F00));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn sas_never_outlives_its_session() {
        let pending = SasMail {
            gen: 1,
            digits: 12_345_678,
            role: SasRole::Sponsor,
            peer_fp: 0x04AA,
            state: SasState::Pending,
            epoch: 3,
        };
        // Published for this session: shown.
        let mut c = Controller::new(info(), 0);
        let mut i = inputs(1_000, snap());
        i.sas = pending;
        assert!(matches!(c.step(&i).screen, Screen::Sas(_)));
        // Card power cycle (epoch moved): the code goes, a notice says so.
        i.session_epoch = 4;
        i.now_ms += 1;
        let f = c.step(&i);
        assert!(
            matches!(
                f.screen,
                Screen::Notice(NoticeView {
                    kind: NoticeKind::Cancelled,
                    ..
                })
            ),
            "{f:?}"
        );
        // Never the code again in the new session.
        i.now_ms += NOTICE_MS;
        assert!(matches!(c.step(&i).screen, Screen::Home(_)));
        // USB gone: not shown either, even for the same epoch.
        let mut c = Controller::new(info(), 0);
        let mut i = inputs(1_000, snap());
        i.sas = pending;
        i.usb_configured = false;
        assert!(!matches!(c.step(&i).screen, Screen::Sas(_)));
        // Same low byte 256 sessions later: still another session.
        let mut c = Controller::new(info(), 0);
        let mut i = inputs(1_000, snap());
        i.sas = pending;
        i.session_epoch = 3 + 256;
        assert!(!matches!(c.step(&i).screen, Screen::Sas(_)));
    }

    #[test]
    fn errors_and_footer() {
        let mut c = Controller::new(info(), 0);
        let mut s = snap();
        s.health.flags = health::SMK_MISSING;
        assert!(matches!(
            c.step(&inputs(1, s)).screen,
            Screen::Error(ErrorView {
                code: ErrorCode::E20NotProvisioned,
                ..
            })
        ));
        s.health.flags = health::KS_INIT_FAILED | health::PROVISIONED;
        assert!(matches!(
            c.step(&inputs(2, s)).screen,
            Screen::Error(ErrorView {
                code: ErrorCode::E11StorageUnreadable,
                ..
            })
        ));
        // Once the host works with the device, it is an ERROR band.
        s.activity = Activity {
            op_seq: 1,
            op: OpCode::Verify,
            state: OpState::Done,
            ..Default::default()
        };
        let h = home(&c.step(&inputs(3, s)));
        assert_eq!(h.status, Status::Error);
        s.health.flags = 0;
        assert!(matches!(
            c.footer(&s, 0),
            FooterView::DevUnprovisioned {
                storage: StorageLine::QmiOk,
                ..
            }
        ));
        // A dev board still reports a failed store.
        s.health.flags = health::STORE_WRITE_FAILED;
        assert!(matches!(
            c.footer(&s, 0),
            FooterView::DevUnprovisioned {
                storage: StorageLine::QmiFail,
                ..
            }
        ));
        let mut c = Controller::new(
            StaticInfo {
                reset: Some(ResetInfo {
                    kind: ResetKind::Core1Stall,
                    count: 2,
                }),
                ..info()
            },
            0,
        );
        let s = snap();
        assert!(matches!(
            c.footer(&s, 59_999),
            FooterView::ResetWarning {
                storage: StorageLine::QmiOk,
                ..
            }
        ));
        assert!(matches!(
            c.footer(&s, 60_000),
            FooterView::Normal {
                reset: Some(ResetKind::Core1Stall),
                ..
            }
        ));
        assert!(matches!(
            c.footer(&s, RESET_NOTE_MS),
            FooterView::Normal { reset: None, .. }
        ));
        let _ = c.step(&inputs(1, s));
    }

    #[test]
    fn reset_info_mapping() {
        let r = |last, n| BootReport {
            last,
            wdt_resets: n,
            chip_reset: 0,
        };
        assert_eq!(reset_info(&r(LastReset::Other, 0)), None);
        assert_eq!(
            reset_info(&r(LastReset::Forced(Some(ResetCause::Core1Stall)), 2)),
            Some(ResetInfo {
                kind: ResetKind::Core1Stall,
                count: 2
            })
        );
        assert_eq!(
            reset_info(&r(LastReset::Timeout(None), 1)).map(|i| i.kind),
            Some(ResetKind::Watchdog)
        );
    }
}
