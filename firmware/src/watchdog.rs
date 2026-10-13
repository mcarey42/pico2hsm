//! RP2350 hardware watchdog: arming, the feeding policy, deliberate resets
//! and the boot-time reset report.
//!
//! # Timeout
//! [`HW_TIMEOUT_MS`] = 8 s (hardware maximum 0xFF_FFFF µs ≈ 16.7 s; the
//! watchdog tick is 1 µs, set up by `embassy_rp::init`).  The longest stretch
//! core0 spends without yielding to the executor *and* without calling
//! [`progress`] is one flash sector erase (≤ 0.4 s datasheet maximum) or one
//! display render; 8 s leaves a wide margin over that and still resets a
//! wedged core0 quickly.
//!
//! # Who feeds
//! Only core0 feeds, and only while the system is healthy:
//! * A spawned executor task (`watchdog_feeder` in `main.rs`) runs every
//!   [`FEED_INTERVAL_MS`].  Running at all proves core0's executor is alive.
//!   It feeds unless [`Core1Monitor`] reports core1 `Stalled`: a request is
//!   outstanding (core0 handed core1 an APDU or reset signal and has not had
//!   the reply) and for [`CORE1_STALL_MS`] neither the heartbeat
//!   (`WATCHDOG_HEARTBEAT`) nor the request/response counters moved and no
//!   `WatchdogSuppressGuard` deadline is in force.  That rule is the same one
//!   the CCID time-extension loop uses, and it covers every place core0
//!   waits on core1, including the USB-disconnect drain.
//! * [`progress`] (called by flash/SD sector writes and erases and by every
//!   key load) feeds directly when it runs on core0, so blocking storage work
//!   on core0 (boot mount and key load, `FlashOp`s, formats, wipes) keeps the
//!   watchdog quiet without the executor.  It runs from flash (XIP) *after*
//!   each erase/program returns, so nothing needs to live in RAM.
//! * Core1 never feeds; it only bumps the heartbeat.
//!
//! Once a reset is decided ([`starve`] / [`reset_now`]) nothing feeds again.
//!
//! # Reset scope
//! `PSM.WDSEL` selects everything except the oscillators (as the Pico SDK
//! does), so a watchdog reset restarts both cores, the bootrom (secure boot
//! runs again), all peripherals including USB, and SRAM/XIP state.
//! (`embassy_rp::watchdog::Watchdog::start` writes the RP2040 bit layout,
//! which on RP2350 leaves both processors out — so it is not used.)
//! On RP2350 `SCB::sys_reset` (SYSRESETREQ) is a processor warm reset (the
//! datasheet's `WATCHDOG.REASON` text calls it a "warm reset of either
//! core"); it is not documented to reset the other core or USB, so
//! deliberate resets go through the watchdog trigger ([`reset_now`]).
//!
//! # Debugging
//! `CTRL.PAUSE_DBG0/1/JTAG` stop the countdown while either core is halted
//! by a debugger or the probe is accessing the bus, so breakpoints and
//! probe-rs halts don't reset the chip.
//!
//! # Scratch registers
//! `WATCHDOG.SCRATCH0` holds the reason for a deliberate reset
//! ([`ResetCause`]), `SCRATCH1` counts watchdog resets since the last
//! non-watchdog reset.  Both survive a watchdog reset.  `SCRATCH4..7`
//! belong to the bootrom (reboot magic; probe-rs uses them too).

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Hardware watchdog timeout.
pub const HW_TIMEOUT_MS: u32 = 8_000;

/// Largest value `WATCHDOG.LOAD` accepts (µs).
pub const HW_MAX_TIMEOUT_US: u32 = 0x00FF_FFFF;

/// How often the feeder task runs.
pub const FEED_INTERVAL_MS: u64 = 1_000;

/// Core1 counts as stuck after this long with a request outstanding and no
/// progress — the same 30 s as the CCID stall detector
/// (`WATCHDOG_STALL_LIMIT` × 1.5 s time-extension interval).
pub const CORE1_STALL_MS: u64 = crate::WATCHDOG_STALL_LIMIT as u64 * 1_500;

const _: () = assert!(HW_TIMEOUT_MS as u64 * 1_000 <= HW_MAX_TIMEOUT_US as u64);
const _: () = assert!(FEED_INTERVAL_MS * 4 <= HW_TIMEOUT_MS as u64);

/// Requests core0 has handed to core1 (APDUs and reset signals).
static CORE1_REQUESTS: AtomicU32 = AtomicU32::new(0);
/// Replies core0 has received from core1.  Equal to `CORE1_REQUESTS` when
/// core1 is idle.
static CORE1_RESPONSES: AtomicU32 = AtomicU32::new(0);
/// A reset has been decided: nothing feeds the watchdog any more.
static RESET_PENDING: AtomicBool = AtomicBool::new(false);

/// Debug builds (`debug` feature): set by the DEBUG APDU's watchdog test
/// hook; core0 spins without yielding once it has sent the reply.
#[cfg(feature = "debug")]
pub static DEBUG_WEDGE_CORE0: AtomicBool = AtomicBool::new(false);

/// Core0 is about to hand core1 a request (call before the channel send, so
/// a core1 that never takes it is caught too).
pub fn note_core1_request() {
    CORE1_REQUESTS.fetch_add(1, Ordering::SeqCst);
}

/// Core0 has received core1's reply to a request.
pub fn note_core1_response() {
    CORE1_RESPONSES.fetch_add(1, Ordering::SeqCst);
}

/// Whether a reset has been decided (feeding has stopped for good).
pub fn reset_pending() -> bool {
    RESET_PENDING.load(Ordering::SeqCst)
}

/// Long-running work is advancing: bump the core1 heartbeat and, on core0,
/// feed the hardware watchdog.  Cheap enough for every sector operation.
pub fn progress() {
    crate::WATCHDOG_HEARTBEAT.fetch_add(1, Ordering::Relaxed);
    #[cfg(target_arch = "arm")]
    if on_core0() {
        feed();
    }
}

// ─── Feeding policy (pure, host-tested) ──────────────────────────────────────

/// A snapshot of what core1 has been doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Core1Activity {
    /// Requests handed to core1 so far.
    pub requests: u32,
    /// Replies received from core1 so far.
    pub responses: u32,
    /// `WATCHDOG_HEARTBEAT`.
    pub heartbeat: u32,
    /// A `WatchdogSuppressGuard` deadline is in force (RSA keygen).
    pub suppressed: bool,
}

impl Core1Activity {
    /// Read the live counters.
    pub fn sample() -> Self {
        Core1Activity {
            requests: CORE1_REQUESTS.load(Ordering::SeqCst),
            responses: CORE1_RESPONSES.load(Ordering::SeqCst),
            heartbeat: crate::WATCHDOG_HEARTBEAT.load(Ordering::Relaxed),
            suppressed: crate::watchdog_suppressed(),
        }
    }
}

/// Core1's state as seen by core0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Core1Health {
    /// No request outstanding.
    Idle,
    /// A request is outstanding and core1 moved within `CORE1_STALL_MS`.
    Working,
    /// A request is outstanding under a stall-detection suppression.
    Suppressed,
    /// A request is outstanding and nothing moved for `CORE1_STALL_MS`.
    Stalled,
}

/// Tracks when core1 last made progress.
#[derive(Clone, Copy, Debug)]
pub struct Core1Monitor {
    last: (u32, u32, u32),
    last_progress_ms: u64,
}

impl Core1Monitor {
    /// Start watching at `now_ms`, from `activity`.
    pub fn new(now_ms: u64, activity: Core1Activity) -> Self {
        Core1Monitor {
            last: (activity.requests, activity.responses, activity.heartbeat),
            last_progress_ms: now_ms,
        }
    }

    /// Update with a new snapshot and classify core1.
    ///
    /// Any movement — a new request, a reply, a heartbeat — counts as
    /// progress, so a stream of short APDUs that never touch the RNG or
    /// flash is not mistaken for a stall.
    pub fn observe(&mut self, now_ms: u64, a: Core1Activity) -> Core1Health {
        let token = (a.requests, a.responses, a.heartbeat);
        let moved = token != self.last;
        self.last = token;
        if a.requests == a.responses {
            self.last_progress_ms = now_ms;
            return Core1Health::Idle;
        }
        if a.suppressed {
            self.last_progress_ms = now_ms;
            return Core1Health::Suppressed;
        }
        if moved {
            self.last_progress_ms = now_ms;
            return Core1Health::Working;
        }
        if now_ms.saturating_sub(self.last_progress_ms) >= CORE1_STALL_MS {
            Core1Health::Stalled
        } else {
            Core1Health::Working
        }
    }
}

/// Whether the feeder may feed the hardware watchdog.
pub fn should_feed(health: Core1Health, reset_pending: bool) -> bool {
    !reset_pending && health != Core1Health::Stalled
}

// ─── Reset causes and the boot report (pure, host-tested) ────────────────────

/// Why firmware decided to reset (stored in `WATCHDOG.SCRATCH0`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ResetCause {
    /// The CCID stall detector gave up on core1 (6F00 sent, then reset).
    Core1Stall = 1,
    /// The feeder saw core1 stalled outside an APDU wait (e.g. the USB
    /// disconnect drain) and stopped feeding.
    FeederCore1Stall = 2,
    /// The TRNG failed (`rng::fill_or_reset`).
    RngFailure = 3,
    /// A boot-time security check failed.
    BootCheck = 4,
    /// Debug builds: deliberate test reset.
    DebugTest = 5,
}

impl ResetCause {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => ResetCause::Core1Stall,
            2 => ResetCause::FeederCore1Stall,
            3 => ResetCause::RngFailure,
            4 => ResetCause::BootCheck,
            5 => ResetCause::DebugTest,
            _ => return None,
        })
    }

    /// Short human-readable name for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            ResetCause::Core1Stall => "core1 stall (CCID detector)",
            ResetCause::FeederCore1Stall => "core1 stall (feeder)",
            ResetCause::RngFailure => "TRNG failure",
            ResetCause::BootCheck => "boot security check",
            ResetCause::DebugTest => "debug test",
        }
    }
}

const SCRATCH_MAGIC: u32 = 0x5744_0000; // "WD"
const SCRATCH_MAGIC_MASK: u32 = 0xFFFF_0000;

/// `SCRATCH0` value recording `cause`.
pub const fn encode_cause(cause: ResetCause) -> u32 {
    SCRATCH_MAGIC | cause as u32
}

/// The cause recorded in a `SCRATCH0` value, if any.
pub fn decode_cause(scratch: u32) -> Option<ResetCause> {
    if scratch & SCRATCH_MAGIC_MASK != SCRATCH_MAGIC {
        return None;
    }
    ResetCause::from_u8(scratch as u8)
}

/// How the previous run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LastReset {
    /// Not a watchdog reset (power-on, brown-out, RUN pin, debugger).
    Other,
    /// The watchdog timed out: nothing fed it.  `cause` is set when the
    /// firmware had stopped feeding on purpose; `None` means core0 itself
    /// was stuck (or a fault left the feeder unable to run).
    Timeout(Option<ResetCause>),
    /// Firmware triggered the watchdog deliberately.
    Forced(Option<ResetCause>),
}

/// Classify the previous reset from `WATCHDOG.REASON` and `SCRATCH0`.
pub fn classify(reason_timer: bool, reason_force: bool, scratch0: u32) -> LastReset {
    let cause = decode_cause(scratch0);
    if reason_force {
        LastReset::Forced(cause)
    } else if reason_timer {
        LastReset::Timeout(cause)
    } else {
        LastReset::Other
    }
}

/// One-line description of `last` for the boot log.
pub fn describe(last: LastReset) -> &'static str {
    match last {
        LastReset::Other => "power-on / RUN pin / debugger (not the watchdog)",
        LastReset::Timeout(None) => "WATCHDOG TIMEOUT: core0 stopped feeding (hang or fault)",
        LastReset::Timeout(Some(ResetCause::FeederCore1Stall)) => {
            "WATCHDOG TIMEOUT: core1 stuck on a request (feeder stopped)"
        }
        LastReset::Timeout(Some(_)) => "WATCHDOG TIMEOUT after a firmware reset decision",
        LastReset::Forced(Some(ResetCause::Core1Stall)) => {
            "WATCHDOG RESET: core1 stuck during an APDU (6F00 sent)"
        }
        LastReset::Forced(Some(ResetCause::FeederCore1Stall)) => {
            "WATCHDOG RESET: core1 stuck on a request"
        }
        LastReset::Forced(Some(ResetCause::RngFailure)) => "WATCHDOG RESET: TRNG failure",
        LastReset::Forced(Some(ResetCause::BootCheck)) => {
            "WATCHDOG RESET: boot security check failed"
        }
        LastReset::Forced(Some(ResetCause::DebugTest)) => "WATCHDOG RESET: debug test",
        LastReset::Forced(None) => "WATCHDOG RESET: forced (cause not recorded)",
    }
}

/// Watchdog resets since the last other reset (`SCRATCH1`).
pub fn next_reset_count(previous: u32, last: LastReset) -> u32 {
    match last {
        LastReset::Other => 0,
        _ => previous.saturating_add(1),
    }
}

/// What [`boot_report`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootReport {
    /// How the previous run ended.
    pub last: LastReset,
    /// Consecutive watchdog resets (0 after any other reset).
    pub wdt_resets: u32,
    /// Raw `POWMAN.CHIP_RESET` (which reset domain fired).
    pub chip_reset: u32,
    /// The last [`crumb`] each core left before the reset (core0, core1).
    pub crumbs: (u32, u32),
}

/// Diagnostic breadcrumb: where this core is (`SCRATCH2` for core0,
/// `SCRATCH3` for core1, and the last [`CRUMB_DEPTH`] in [`CRUMB_RING`]).
/// They survive a watchdog reset and the next boot logs them (`reset:
/// crumbs`, `crumbs0` / `crumbs1`, oldest first), so a hang or a fault on
/// a board without a debugger still shows its place.
///
/// Codes (`0xAABB_xxxx`; `xxxx` is a detail):
///
/// | Code | Where |
/// |---|---|
/// | `0110` / `0111`+INS / `0112` | core0 CCID loop: wait for an APDU / got one / handed to core1 |
/// | `0113`, `0120` / `0121` | core0 waiting for core1; time extension sent / done |
/// | `0114` / `0115` / `0116` | core0 sending the response / sent / USB disconnect |
/// | `0130` / `0131`+op / `0132` | core0 flash service: idle / running op (`flash_op_code`) / done |
/// | `0140`–`0144` | core0 display task: show / shown / loop / LED / LED done |
/// | `0150` | core0 watchdog feeder |
/// | `0210` / `0211`+INS / `0214` / `0215` / `0216` | core1: wait / got APDU / USB reset reload / dispatch / done |
/// | `0220`+op / `0221` | core1 waiting for core0 on a flash op / answered |
/// | `0230`+block / `0231`+block / `0232`+block / `0233` | SD read / write / erase-write / done |
/// | `FA17`, then PC, LR | HardFault |
/// | `FA18`+IRQ | unhandled exception or interrupt |
/// | `FA19`+line, then the file name's address | panic (never its message) |
/// | `FA1D` | defmt panic |
#[inline(always)]
pub fn crumb(code: u32) {
    #[cfg(target_arch = "arm")]
    {
        use embassy_rp::pac;
        let core = pac::SIO.cpuid().read() as usize & 1;
        if core == 0 {
            pac::WATCHDOG.scratch2().write_value(code);
        } else {
            pac::WATCHDOG.scratch3().write_value(code);
        }
        // SAFETY: each core writes only its own row; RAM in .uninit
        // survives the watchdog reset and is read once at boot.
        unsafe {
            let ring = &mut *core::ptr::addr_of_mut!(CRUMB_RING);
            let i = ring.next[core] as usize % CRUMB_DEPTH;
            ring.codes[core][i] = code;
            ring.next[core] = ring.next[core].wrapping_add(1);
        }
    }
    #[cfg(not(target_arch = "arm"))]
    let _ = code;
}

/// Breadcrumbs kept per core in [`CRUMB_RING`].
pub const CRUMB_DEPTH: usize = 16;

/// The last [`CRUMB_DEPTH`] breadcrumbs of each core, in RAM the reset
/// does not clear (`.uninit`); `magic` tells a filled ring from garbage.
#[repr(C)]
pub struct CrumbRing {
    magic: u32,
    next: [u32; 2],
    codes: [[u32; CRUMB_DEPTH]; 2],
}

const CRUMB_MAGIC: u32 = 0xC0DE_C0DE;

#[cfg(target_arch = "arm")]
#[link_section = ".uninit.crumbs"]
static mut CRUMB_RING: CrumbRing = CrumbRing {
    magic: 0,
    next: [0; 2],
    codes: [[0; CRUMB_DEPTH]; 2],
};

/// The previous run's breadcrumb history, oldest first, per core (`None`
/// after a power-on, when the RAM held garbage), then start a new one.
/// Core0, at boot, before core1 runs.
#[cfg(target_arch = "arm")]
pub fn take_crumb_history() -> Option<[[u32; CRUMB_DEPTH]; 2]> {
    // SAFETY: core1 is not running yet.
    let ring = unsafe { &mut *core::ptr::addr_of_mut!(CRUMB_RING) };
    let out = (ring.magic == CRUMB_MAGIC).then(|| {
        let mut h = [[0u32; CRUMB_DEPTH]; 2];
        for (core, row) in h.iter_mut().enumerate() {
            let next = ring.next[core] as usize;
            for (k, slot) in row.iter_mut().enumerate() {
                *slot = ring.codes[core][(next + k) % CRUMB_DEPTH];
            }
        }
        h
    });
    ring.magic = CRUMB_MAGIC;
    ring.next = [0; 2];
    ring.codes = [[0; CRUMB_DEPTH]; 2];
    out
}

// ─── Hardware access (ARM only) ──────────────────────────────────────────────

#[cfg(target_arch = "arm")]
fn on_core0() -> bool {
    embassy_rp::pac::SIO.cpuid().read() == 0
}

/// `PSM.WDSEL` value: reset everything except ROSC and XOSC (Pico SDK
/// `watchdog_enable`).  Built from the RP2350 field setters so the bit
/// layout can't drift.
#[cfg(target_arch = "arm")]
fn wdsel_all() -> embassy_rp::pac::psm::regs::Wdsel {
    let mut w = embassy_rp::pac::psm::regs::Wdsel(0);
    w.set_proc_cold(true);
    w.set_otp(true);
    w.set_resets(true);
    w.set_clocks(true);
    w.set_psm_ready(true);
    w.set_busfabric(true);
    w.set_rom(true);
    w.set_bootram(true);
    w.set_sram0(true);
    w.set_sram1(true);
    w.set_sram2(true);
    w.set_sram3(true);
    w.set_sram4(true);
    w.set_sram5(true);
    w.set_sram6(true);
    w.set_sram7(true);
    w.set_sram8(true);
    w.set_sram9(true);
    w.set_xip(true);
    w.set_sio(true);
    w.set_accessctrl(true);
    w.set_proc0(true);
    w.set_proc1(true);
    w
}

/// Find out why the last reset happened, update the scratch registers, and
/// arm the watchdog.  Call once on core0, right after `embassy_rp::init`
/// (which starts the 1 µs watchdog tick); the caller logs the report.
#[cfg(target_arch = "arm")]
pub fn boot_init() -> BootReport {
    use embassy_rp::pac;
    let wd = pac::WATCHDOG;
    let reason = wd.reason().read();
    let last = classify(reason.timer(), reason.force(), wd.scratch0().read());
    let wdt_resets = next_reset_count(wd.scratch1().read(), last);
    let crumbs = (wd.scratch2().read(), wd.scratch3().read());
    wd.scratch2().write_value(0);
    wd.scratch3().write_value(0);
    wd.scratch0().write_value(0);
    wd.scratch1().write_value(wdt_resets);
    let chip_reset = pac::POWMAN.chip_reset().read().0;
    arm();
    BootReport {
        last,
        wdt_resets,
        chip_reset,
        crumbs,
    }
}

/// Arm the watchdog with [`HW_TIMEOUT_MS`], pausing while debugged.
#[cfg(target_arch = "arm")]
fn arm() {
    use embassy_rp::pac;
    let wd = pac::WATCHDOG;
    wd.ctrl().modify(|w| w.set_enable(false));
    pac::PSM.wdsel().write_value(wdsel_all());
    // A stale bootrom reboot magic (probe-rs writes one to enter BOOTSEL)
    // must not turn our watchdog reset into a reboot elsewhere.
    wd.scratch4().write_value(0);
    wd.load()
        .write_value(pac::watchdog::regs::Load(HW_TIMEOUT_MS * 1_000));
    wd.ctrl().modify(|w| {
        w.set_pause_dbg0(true);
        w.set_pause_dbg1(true);
        w.set_pause_jtag(true);
        w.set_enable(true);
    });
}

/// Reload the countdown, unless a reset has been decided.
#[cfg(target_arch = "arm")]
pub fn feed() {
    if reset_pending() {
        return;
    }
    embassy_rp::pac::WATCHDOG
        .load()
        .write_value(embassy_rp::pac::watchdog::regs::Load(HW_TIMEOUT_MS * 1_000));
}

/// Stop feeding for good and record why; the watchdog fires within
/// [`HW_TIMEOUT_MS`].  The first recorded cause wins.
#[cfg(target_arch = "arm")]
pub fn starve(cause: ResetCause) {
    if !RESET_PENDING.swap(true, Ordering::SeqCst) {
        embassy_rp::pac::WATCHDOG
            .scratch0()
            .write_value(encode_cause(cause));
    }
}

/// Reset the whole chip now through the watchdog (both cores, USB, all
/// peripherals).  Safe from either core; no logging.
#[cfg(target_arch = "arm")]
pub fn reset_now(cause: ResetCause) -> ! {
    use embassy_rp::pac;
    // The trigger is the actual reset: record its cause even if feeding had
    // already been stopped for another reason.
    RESET_PENDING.store(true, Ordering::SeqCst);
    pac::WATCHDOG.scratch0().write_value(encode_cause(cause));
    pac::PSM.wdsel().write_value(wdsel_all());
    pac::WATCHDOG.ctrl().modify(|w| {
        w.set_pause_dbg0(false);
        w.set_pause_dbg1(false);
        w.set_pause_jtag(false);
        w.set_enable(true);
        w.set_trigger(true);
    });
    // The trigger takes effect within a few cycles; this is a fallback.
    cortex_m::peripheral::SCB::sys_reset()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn act(requests: u32, responses: u32, heartbeat: u32) -> Core1Activity {
        Core1Activity {
            requests,
            responses,
            heartbeat,
            suppressed: false,
        }
    }

    #[test]
    fn timeout_within_hardware_limit_with_margin() {
        assert!(HW_TIMEOUT_MS * 1_000 <= HW_MAX_TIMEOUT_US);
        assert!(FEED_INTERVAL_MS * 4 <= HW_TIMEOUT_MS as u64);
        assert_eq!(CORE1_STALL_MS, 30_000);
    }

    #[test]
    fn idle_core1_always_feeds() {
        let mut m = Core1Monitor::new(0, act(5, 5, 0));
        for t in (0..120_000).step_by(1_000) {
            let h = m.observe(t, act(5, 5, 0));
            assert_eq!(h, Core1Health::Idle);
            assert!(should_feed(h, false));
        }
    }

    #[test]
    fn busy_without_progress_stalls_after_window() {
        let mut m = Core1Monitor::new(0, act(0, 0, 7));
        // Request handed over at t=1 s.
        assert_eq!(m.observe(1_000, act(1, 0, 7)), Core1Health::Working);
        assert_eq!(m.observe(30_999, act(1, 0, 7)), Core1Health::Working);
        let h = m.observe(31_000, act(1, 0, 7));
        assert_eq!(h, Core1Health::Stalled);
        assert!(!should_feed(h, false));
    }

    #[test]
    fn heartbeat_keeps_busy_core1_alive() {
        let mut m = Core1Monitor::new(0, act(1, 0, 0));
        let mut hb = 0;
        for t in (1_000..600_000).step_by(1_000) {
            if t % 20_000 == 0 {
                hb += 1;
            }
            let h = m.observe(t, act(1, 0, hb));
            assert_ne!(h, Core1Health::Stalled, "t={t}");
        }
    }

    #[test]
    fn stream_of_short_requests_is_not_a_stall() {
        // Sampled while busy every time, heartbeat never moves, but
        // requests and replies keep advancing.
        let mut m = Core1Monitor::new(0, act(0, 0, 0));
        for i in 1..200u32 {
            let h = m.observe(u64::from(i) * 1_000, act(i, i - 1, 0));
            assert_eq!(h, Core1Health::Working);
        }
    }

    #[test]
    fn suppression_feeds_and_restarts_the_window() {
        let mut m = Core1Monitor::new(0, act(1, 0, 0));
        let mut sup = act(1, 0, 0);
        sup.suppressed = true;
        for t in (1_000..3_600_000).step_by(1_000) {
            let h = m.observe(t, sup);
            assert_eq!(h, Core1Health::Suppressed);
            assert!(should_feed(h, false));
        }
        // Suppression ends: a fresh 30 s window starts.
        assert_eq!(m.observe(3_620_000, act(1, 0, 0)), Core1Health::Working);
        assert_eq!(m.observe(3_629_000, act(1, 0, 0)), Core1Health::Stalled);
    }

    #[test]
    fn reply_ends_the_stall_clock() {
        let mut m = Core1Monitor::new(0, act(1, 0, 0));
        assert_eq!(m.observe(29_000, act(1, 0, 0)), Core1Health::Working);
        assert_eq!(m.observe(30_000, act(1, 1, 0)), Core1Health::Idle);
        // Next request starts a new window.
        assert_eq!(m.observe(31_000, act(2, 1, 0)), Core1Health::Working);
        assert_eq!(m.observe(60_000, act(2, 1, 0)), Core1Health::Working);
        assert_eq!(m.observe(61_000, act(2, 1, 0)), Core1Health::Stalled);
    }

    #[test]
    fn counters_wrap() {
        let mut m = Core1Monitor::new(0, act(u32::MAX, u32::MAX, u32::MAX));
        assert_eq!(m.observe(1_000, act(0, u32::MAX, 0)), Core1Health::Working);
        assert_eq!(m.observe(2_000, act(0, 0, 0)), Core1Health::Idle);
    }

    #[test]
    fn pending_reset_never_feeds() {
        for h in [
            Core1Health::Idle,
            Core1Health::Working,
            Core1Health::Suppressed,
            Core1Health::Stalled,
        ] {
            assert!(!should_feed(h, true));
        }
    }

    #[test]
    fn cause_roundtrip_and_garbage() {
        for c in [
            ResetCause::Core1Stall,
            ResetCause::FeederCore1Stall,
            ResetCause::RngFailure,
            ResetCause::BootCheck,
            ResetCause::DebugTest,
        ] {
            assert_eq!(decode_cause(encode_cause(c)), Some(c));
        }
        assert_eq!(decode_cause(0), None);
        assert_eq!(decode_cause(0xFFFF_FFFF), None);
        assert_eq!(decode_cause(SCRATCH_MAGIC | 0x99), None);
        assert_eq!(decode_cause(0x1234_0001), None);
    }

    #[test]
    fn classify_reset() {
        let s = encode_cause(ResetCause::Core1Stall);
        assert_eq!(classify(false, false, s), LastReset::Other);
        assert_eq!(classify(true, false, 0), LastReset::Timeout(None));
        assert_eq!(
            classify(true, false, encode_cause(ResetCause::FeederCore1Stall)),
            LastReset::Timeout(Some(ResetCause::FeederCore1Stall))
        );
        assert_eq!(
            classify(false, true, s),
            LastReset::Forced(Some(ResetCause::Core1Stall))
        );
    }

    #[test]
    fn every_reset_is_described() {
        let mut all = [LastReset::Other; 13];
        let causes = [
            None,
            Some(ResetCause::Core1Stall),
            Some(ResetCause::FeederCore1Stall),
            Some(ResetCause::RngFailure),
            Some(ResetCause::BootCheck),
            Some(ResetCause::DebugTest),
        ];
        for (i, c) in causes.iter().enumerate() {
            all[1 + i] = LastReset::Timeout(*c);
            all[7 + i] = LastReset::Forced(*c);
        }
        for l in all {
            assert!(!describe(l).is_empty());
        }
        assert!(describe(LastReset::Timeout(None)).contains("core0"));
    }

    #[test]
    fn reset_count() {
        assert_eq!(next_reset_count(7, LastReset::Other), 0);
        assert_eq!(next_reset_count(0, LastReset::Timeout(None)), 1);
        assert_eq!(next_reset_count(3, LastReset::Forced(None)), 4);
        assert_eq!(
            next_reset_count(u32::MAX, LastReset::Forced(None)),
            u32::MAX
        );
    }
}
