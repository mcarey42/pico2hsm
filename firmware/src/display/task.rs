//! The display task (core0, ARM only).
//!
//! It owns the panel (SPI bus, DC/CS/RST/BL and, on Waveshare, the
//! WS2812).  The CCID loop never renders: it stores a few atomics and
//! signals [`DISPLAY_KICK`].  The task wakes on a kick, on a 1 Hz tick
//! (uptime, ages) and on the controller's own deadline (WORKING after
//! 300 ms, the progress bar), and redraws only the bands that changed.
//!
//! Every await between bands is a DMA transfer, and one band renders in
//! well under a millisecond, so the executor — and the watchdog feeder —
//! keeps running.

use core::sync::atomic::Ordering;

use embassy_futures::select::select3;
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, signal::Signal};
use embassy_time::{Duration, Instant, Ticker, Timer};

use super::driver::{Panel, ScreenDriver};
use super::model::{Controller, Inputs, StaticInfo};
use crate::display_snapshot::{self, Snapshot};

/// Something the display should look at changed (APDU start / end, USB
/// state).  Core0 only: core1 never touches it (it must not take the
/// critical-section spinlock core0's USB stack uses).
pub static DISPLAY_KICK: Signal<CriticalSectionRawMutex, ()> = Signal::new();

/// Wake the display task.
pub fn kick() {
    DISPLAY_KICK.signal(());
}

/// Core0 uptime in ms.
pub fn now_ms() -> u64 {
    Instant::now().as_millis()
}

fn sample(last: &mut Option<Snapshot>) -> Inputs {
    let now = now_ms();
    if let Some(s) = display_snapshot::read() {
        *last = Some(s);
    }
    let start = display_snapshot::APDU_STARTED_MS.load(Ordering::Acquire);
    Inputs {
        now_ms: now,
        snap: *last,
        sas: display_snapshot::sas_read(),
        usb_configured: display_snapshot::USB_CONFIGURED.load(Ordering::Acquire),
        session_epoch: crate::SESSION_EPOCH.load(Ordering::SeqCst),
        busy_ms: (start != 0).then(|| (now as u32).wrapping_sub(start)),
    }
}

/// Run the display forever.
pub async fn run<P: Panel>(mut drv: ScreenDriver<'_, P>, info: StaticInfo) -> ! {
    let mut ctl = Controller::new(info, now_ms());
    let mut ticker = Ticker::every(Duration::from_secs(1));
    let mut last = None;
    loop {
        crate::watchdog::crumb(0x0142_0000);
        let inputs = sample(&mut last);
        let frame = ctl.step(&inputs);
        if frame.sleep {
            drv.sleep().await;
        } else {
            drv.wake().await;
            crate::watchdog::crumb(0x0140_0000);
            drv.show(&frame.screen).await;
            crate::watchdog::crumb(0x0141_0000);
        }
        crate::watchdog::crumb(0x0143_0000);
        drv.led(frame.led, frame.sleep).await;
        crate::watchdog::crumb(0x0144_0000);
        let deadline = frame.deadline_ms.map_or(
            Instant::now() + Duration::from_secs(3600),
            Instant::from_millis,
        );
        select3(DISPLAY_KICK.wait(), ticker.next(), Timer::at(deadline)).await;
    }
}
