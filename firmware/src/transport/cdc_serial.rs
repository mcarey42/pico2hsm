//! USB CDC-ACM serial log transport.
//!
//! Provides a lightweight ring-buffered log channel that any firmware code can
//! write to with [`cdc_log!`] / [`cdc_warn!`] / [`cdc_error!`].  A dedicated
//! drain task on core0 pushes buffered lines out over the CDC-ACM serial port
//! (`/dev/ttyACMx` on Linux).
//!
//! # Usage
//! ```
//! cdc_log!("SD card: {} bytes", capacity);
//! cdc_warn!("Write failed on sector {}", sector_idx);
//! ```
//!
//! Lines are prefixed with `[I]`, `[W]`, or `[E]` and terminated with `\r\n`.
//! If the channel is full the message is silently dropped (never blocks).
//!
//! # Integration
//! 1. Call [`CdcSerialState::new()`] to create the state.
//! 2. Pass it to [`setup_cdc`] alongside the `UsbBuilder` to add the CDC-ACM
//!    interface.
//! 3. In the main loop, call `cdc.write_packet(...)` / use [`drain_one`] to
//!    flush one buffered line per loop iteration.

#[cfg(target_arch = "arm")]
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, channel::Channel};
#[cfg(target_arch = "arm")]
use heapless::Vec;

/// Maximum length of one log line (bytes, including prefix + `\r\n`).
pub const LOG_LINE_MAX: usize = 128;
/// Number of log lines that can be buffered before drops occur.
const LOG_QUEUE_DEPTH: usize = 16;

/// Cross-core, non-blocking log channel.
///
/// `try_send` is called by the [`cdc_log!`] family of macros (safe from any
/// core or interrupt context).  Core0 drains it via [`drain_one`].
#[cfg(target_arch = "arm")]
pub static CDC_LOG_CHANNEL: Channel<
    CriticalSectionRawMutex,
    Vec<u8, LOG_LINE_MAX>,
    LOG_QUEUE_DEPTH,
> = Channel::new();

// ─── Public logging macros ───────────────────────────────────────────────────

/// Log an info-level message over USB CDC serial.
///
/// Formats the message with `[I] ` prefix, truncates to [`LOG_LINE_MAX`] bytes,
/// and non-blockingly enqueues it.  Silently drops if the queue is full.
#[cfg(target_arch = "arm")]
#[macro_export]
macro_rules! cdc_log {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let mut line: heapless::Vec<u8, { $crate::transport::cdc_serial::LOG_LINE_MAX }> =
            heapless::Vec::new();
        let mut s = heapless::String::<{ $crate::transport::cdc_serial::LOG_LINE_MAX }>::new();
        let _ = core::write!(s, "[I] {}\r\n", format_args!($($arg)*));
        let _ = line.extend_from_slice(s.as_bytes());
        let _ = $crate::transport::cdc_serial::CDC_LOG_CHANNEL.try_send(line);
    }};
}

/// Log a warning-level message over USB CDC serial.
#[cfg(target_arch = "arm")]
#[macro_export]
macro_rules! cdc_warn {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let mut line: heapless::Vec<u8, { $crate::transport::cdc_serial::LOG_LINE_MAX }> =
            heapless::Vec::new();
        let mut s = heapless::String::<{ $crate::transport::cdc_serial::LOG_LINE_MAX }>::new();
        let _ = core::write!(s, "[W] {}\r\n", format_args!($($arg)*));
        let _ = line.extend_from_slice(s.as_bytes());
        let _ = $crate::transport::cdc_serial::CDC_LOG_CHANNEL.try_send(line);
    }};
}

/// Log an error-level message over USB CDC serial.
#[cfg(target_arch = "arm")]
#[macro_export]
macro_rules! cdc_error {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let mut line: heapless::Vec<u8, { $crate::transport::cdc_serial::LOG_LINE_MAX }> =
            heapless::Vec::new();
        let mut s = heapless::String::<{ $crate::transport::cdc_serial::LOG_LINE_MAX }>::new();
        let _ = core::write!(s, "[E] {}\r\n", format_args!($($arg)*));
        let _ = line.extend_from_slice(s.as_bytes());
        let _ = $crate::transport::cdc_serial::CDC_LOG_CHANNEL.try_send(line);
    }};
}

// No-op stubs for host (x86_64) builds.
#[cfg(not(target_arch = "arm"))]
#[macro_export]
macro_rules! cdc_log {
    ($($arg:tt)*) => {{}};
}
#[cfg(not(target_arch = "arm"))]
#[macro_export]
macro_rules! cdc_warn {
    ($($arg:tt)*) => {{}};
}
#[cfg(not(target_arch = "arm"))]
#[macro_export]
macro_rules! cdc_error {
    ($($arg:tt)*) => {{}};
}

// ─── CDC-ACM setup helper ────────────────────────────────────────────────────

/// Re-export so board functions don't need to import embassy_usb directly.
#[cfg(target_arch = "arm")]
pub use embassy_usb::class::cdc_acm::{CdcAcmClass, State as CdcAcmState};

/// Drain at most one buffered log line into the CDC-ACM sender.
///
/// Call this from the core0 main loop each iteration.  Returns immediately
/// if the channel is empty or if no host terminal is connected (DTR not set).
/// Drops the line rather than blocking so the CCID loop is never stalled by
/// an unread serial port.
#[cfg(target_arch = "arm")]
pub async fn drain_one<'d, D: embassy_usb::driver::Driver<'d>>(
    sender: &mut embassy_usb::class::cdc_acm::Sender<'d, D>,
) {
    // Non-blocking peek: if nothing queued, return immediately.
    let line = match CDC_LOG_CHANNEL.try_receive() {
        Ok(line) => line,
        Err(_) => return,
    };

    // Drop the line if no host terminal has the port open (DTR not asserted).
    // write_packet().await blocks until the host reads; without this check the
    // CCID loop stalls whenever /dev/ttyACMx is not being read.
    if !sender.dtr() {
        return;
    }

    // Send in ≤63-byte chunks (never exact max_packet_size to avoid ZLP ambiguity).
    // DTR only says a terminal has the port open, not that it is reading: a
    // stalled reader would block write_packet — and the CCID loop with it —
    // forever, so each chunk gets a deadline and the rest of the line is
    // dropped on timeout.
    use embassy_futures::select::{select, Either};
    let mut sent = 0usize;
    while sent < line.len() {
        let end = core::cmp::min(sent + 63, line.len());
        match select(
            sender.write_packet(&line[sent..end]),
            embassy_time::Timer::after_millis(50),
        )
        .await
        {
            Either::First(Ok(())) => sent = end,
            // USB disconnected, or the host is not reading: drop the rest.
            Either::First(Err(_)) | Either::Second(()) => break,
        }
    }
}
