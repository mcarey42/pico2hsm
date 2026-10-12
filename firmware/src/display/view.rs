//! View model: everything one frame shows, as plain data.
//!
//! A [`Screen`] is `Copy + PartialEq`.  The driver compares the previous
//! and the next screen region by region and redraws only the bands whose
//! rows changed.  Every string drawn is chosen by the renderer from these
//! fields: firmware-static text and numbers from firmware state only, never
//! host-supplied bytes (design spec §4.1).

use pico2hsm_core::op::{Applet, OpCode, OpResult};

use super::color::{self, C444};
use super::fmt::Age;
use crate::display_snapshot::SasRole;

/// The status word (design spec §2.2), highest priority first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The keystore failed (init, the last write, or the SD card is gone).
    Error,
    /// The active applet's primary credential is blocked.
    Locked,
    /// An operation has been running for more than 300 ms.
    Working,
    /// USB is not configured by a host.
    NoHost,
    /// Idle and healthy.
    Ready,
}

impl Status {
    /// The word.
    pub fn word(self) -> &'static str {
        match self {
            Status::Error => "ERROR",
            Status::Locked => "LOCKED",
            Status::Working => "WORKING",
            Status::NoHost => "NO HOST",
            Status::Ready => "READY",
        }
    }

    /// Its colour (band bar, word, LED).
    pub fn color(self) -> C444 {
        match self {
            Status::Error | Status::Locked => color::ERR,
            Status::Working => color::BUSY,
            Status::NoHost => color::CYAN,
            Status::Ready => color::OK,
        }
    }
}

/// The PIN tile's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinValue {
    /// No applet selected in this session.
    NoApplet,
    /// Not verified.
    NotVerified,
    /// Verified in this session.
    Verified,
    /// No tries left.
    Blocked,
}

/// PIN tile: the active applet's primary credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinTile {
    /// Value.
    pub value: PinValue,
    /// Tries left.
    pub left: u8,
    /// Maximum tries.
    pub max: u8,
    /// A one-shot signature authorisation is armed (PIV 9C, PGP C4=00).
    pub sig_armed: bool,
}

/// KEYS tile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeysTile {
    /// User keys in all applets.
    pub total: u16,
    /// Debug builds: SC-HSM / PIV / OpenPGP split.
    pub split: Option<[u8; 3]>,
}

/// DOMAIN tile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainTile {
    /// No DKEK.
    None,
    /// A DKEK but no member certificate.
    SelfOnly {
        /// Domain ID, first two bytes.
        id: u16,
    },
    /// A certified member.
    Member {
        /// Domain ID, first two bytes.
        id: u16,
        /// Member-list entries.
        members: u8,
    },
    /// This device's certificate is revoked.
    Revoked {
        /// Domain ID, first two bytes.
        id: u16,
    },
}

/// Text emphasis of an ageing last operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fade {
    /// Under 10 s: TEXT.
    Fresh,
    /// Under 60 s: TEXT2.
    Recent,
    /// Older: DIM.
    Old,
}

impl Fade {
    /// For an event `secs` old.
    pub fn of_secs(secs: u32) -> Self {
        match secs {
            0..=9 => Fade::Fresh,
            10..=59 => Fade::Recent,
            _ => Fade::Old,
        }
    }

    /// Text colour.
    pub fn color(self) -> C444 {
        match self {
            Fade::Fresh => color::TEXT,
            Fade::Recent => color::TEXT2,
            Fade::Old => color::DIM,
        }
    }
}

/// Policy note after a signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hint {
    /// Nothing to note.
    None,
    /// PIV slot 9C signed: the PIN must be verified again.
    PivPinAlways,
    /// OpenPGP single-signature mode spent PW1.
    PgpSingleUse,
}

/// Debug detail of the last operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpDetail {
    /// `display_snapshot::algo` id.
    pub algo: u8,
    /// Key reference.
    pub key_ref: u8,
    /// Status word.
    pub sw: u16,
}

/// A static note that replaces the age line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Note {
    /// A keystore write failed (E12).
    NotSaved,
    /// The keystore failed to initialise.
    StorageUnreadable,
    /// The SD card stopped answering.
    SdMissing,
    /// How to unblock the active applet's PIN (E40).
    Unblock(Applet),
}

/// The activity area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityView {
    /// No operation since boot.
    Idle,
    /// An operation is running.
    Working {
        /// What (`Other` when core1 has not said yet).
        op: OpCode,
        /// Seconds since it started.
        elapsed: u32,
        /// Progress-bar animation step.
        phase: u8,
    },
    /// The last operation (kept across sessions).
    Done {
        /// What.
        op: OpCode,
        /// How it ended.
        result: OpResult,
        /// When.
        age: Age,
        /// Emphasis.
        fade: Fade,
        /// Policy note.
        hint: Hint,
        /// Debug builds only.
        detail: Option<OpDetail>,
        /// Overrides the age line.
        note: Option<Note>,
        /// Its session has ended (card power-off, USB down): drawn DIM,
        /// without the hint.
        ended: bool,
    },
}

/// Storage health in the footer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageLine {
    /// Internal flash keystore, healthy.
    QmiOk,
    /// Internal flash keystore, failed.
    QmiFail,
    /// SD card keystore, healthy.
    SdOk,
    /// SD card keystore, failed.
    SdFail,
    /// No SD card.
    SdMissing,
}

/// Why the previous run ended (not shown after a power-on reset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetKind {
    /// Watchdog timeout with no recorded cause (core0 hang).
    Watchdog,
    /// Core1 stalled.
    Core1Stall,
    /// TRNG failure.
    Rng,
    /// A boot security check failed.
    BootCheck,
    /// Debug test reset.
    Test,
    /// Forced, cause not recorded.
    Forced,
}

impl ResetKind {
    /// Short name.
    pub fn name(self) -> &'static str {
        match self {
            ResetKind::Watchdog => "watchdog",
            ResetKind::Core1Stall => "core1 stall",
            ResetKind::Rng => "rng fail",
            ResetKind::BootCheck => "boot check",
            ResetKind::Test => "test",
            ResetKind::Forced => "forced",
        }
    }

    /// Footer abbreviation.
    pub fn short(self) -> &'static str {
        match self {
            ResetKind::Watchdog => "wdt",
            ResetKind::Core1Stall => "core1",
            ResetKind::Rng => "rng",
            ResetKind::BootCheck => "boot",
            ResetKind::Test => "test",
            ResetKind::Forced => "forced",
        }
    }
}

/// A non-power-on reset and how many happened in a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetInfo {
    /// Cause.
    pub kind: ResetKind,
    /// Consecutive watchdog resets.
    pub count: u32,
}

/// The footer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FooterView {
    /// Uptime, firmware, storage, reset cause.
    Normal {
        /// Seconds since boot.
        uptime: u32,
        /// Storage health.
        storage: StorageLine,
        /// Shown for 24 h after a non-power-on reset.
        reset: Option<ResetKind>,
    },
    /// First 60 s after a non-power-on reset.
    ResetWarning {
        /// Cause and count.
        info: ResetInfo,
        /// Storage health (kept at the right of the strip).
        storage: StorageLine,
    },
    /// Unprovisioned device with the development storage key.
    DevUnprovisioned {
        /// Seconds since boot.
        uptime: u32,
        /// Storage health (kept at the right of the strip).
        storage: StorageLine,
    },
}

/// The home screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HomeView {
    /// Status word.
    pub status: Status,
    /// Active applet (`None` when stale or unselected).
    pub applet: Applet,
    /// An administrator credential is live in some applet.
    pub admin: bool,
    /// PIN tile.
    pub pin: PinTile,
    /// KEYS tile.
    pub keys: KeysTile,
    /// DOMAIN tile.
    pub domain: DomainTile,
    /// Activity area.
    pub activity: ActivityView,
    /// Footer.
    pub footer: FooterView,
}

/// Boot progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootStep {
    /// Opening the keystore.
    Storage,
    /// Loading keys (count so far).
    Keys(u16),
    /// Starting USB.
    Usb,
    /// Boot is done but core1 has published nothing yet (the display
    /// task's fail-closed default).
    Starting,
}

/// The boot splash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplashView {
    /// Current step.
    pub step: BootStep,
    /// The previous run's end, if not a power-on.
    pub reset: Option<ResetInfo>,
    /// Debug builds: 1 px border at the panel edge (offset check).
    pub border: bool,
    /// Board name.
    pub board: &'static str,
}

/// Full-screen error codes (design spec §2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    /// No SD card; `attempt` counts boots in a row.
    E10NoSdCard {
        /// Attempt number.
        attempt: u32,
    },
    /// The keystore could not be read at boot.
    E11StorageUnreadable,
    /// Release build without a storage key.
    E20NotProvisioned,
    /// The TRNG failed its self-test.
    E31RngFailure,
}

/// A full-screen error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorView {
    /// Which.
    pub code: ErrorCode,
    /// Footer.
    pub footer: FooterView,
}

/// The pending-SAS comparison screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SasView {
    /// The code, `0..100_000_000`.
    pub digits: u32,
    /// This device's role.
    pub role: SasRole,
    /// Peer key fingerprint (two bytes).
    pub peer: u16,
    /// Seconds left before the code expires.
    pub remaining: u16,
}

/// Seconds a code stays on screen.
pub const SAS_TIMEOUT_SECS: u16 = 120;

/// Enrollment outcome notices (shown for 10 s).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeKind {
    /// Enrollment completed.
    Enrolled {
        /// Peer fingerprint.
        peer: u16,
        /// Domain ID, first two bytes.
        domain: u16,
    },
    /// Enrollment cancelled.
    Cancelled,
    /// The code was not confirmed in time.
    Expired,
}

/// A notice screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoticeView {
    /// Which.
    pub kind: NoticeKind,
    /// Footer.
    pub footer: FooterView,
}

/// One frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    /// Boot splash.
    Splash(SplashView),
    /// Home (steady state).
    Home(HomeView),
    /// Full-screen error.
    Error(ErrorView),
    /// Pending SAS.
    Sas(SasView),
    /// Enrollment notice.
    Notice(NoticeView),
}

/// LED colour (WS2812 boards).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedTone {
    /// Off.
    Off,
    /// Ready.
    Green,
    /// Working.
    Blue,
    /// No host.
    Cyan,
    /// Notices.
    Yellow,
    /// Error / locked.
    Red,
    /// SAS pending (reserved, like the SAS colour).
    Magenta,
}

impl LedTone {
    /// `[r, g, b]` at `level` per lit channel.
    pub fn rgb(self, level: u8) -> [u8; 3] {
        let l = level;
        match self {
            LedTone::Off => [0, 0, 0],
            LedTone::Green => [0, l, 0],
            LedTone::Blue => [0, 0, l],
            LedTone::Cyan => [0, l, l],
            LedTone::Yellow => [l, l, 0],
            LedTone::Red => [l, 0, 0],
            LedTone::Magenta => [l, 0, l],
        }
    }

    /// The tone for a status word.
    pub fn of_status(s: Status) -> Self {
        match s {
            Status::Error | Status::Locked => LedTone::Red,
            Status::Working => LedTone::Blue,
            Status::NoHost => LedTone::Cyan,
            Status::Ready => LedTone::Green,
        }
    }
}
