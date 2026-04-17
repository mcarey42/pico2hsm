//! Board-aware serial debug macros via UART1 PAC-direct writes.
//!
//! # Overview
//! Provides `serial_println!`, `serial_print!`, and `serial_fmt!` macros that
//! work from **any** module in the firmware crate — including async blocks and
//! core1 code — without requiring a `&mut Uart` handle.
//!
//! # Feature gating
//! - When the `uart-debug` feature is active (implied by probe-less boards like
//!   rp2350_geek, waveshare_rp2350_lcd, rp2350_one), the macros write directly
//!   to UART1 via PAC registers (synchronous, spin-wait on TX FIFO).
//! - When `uart-debug` is NOT active (e.g. `pico2_4m` which has a debug probe),
//!   the macros are no-ops.
//!
//! # Prerequisite
//! **UART1 must be initialised before calling these macros.** Each board's run
//! function in `main.rs` must configure UART1 (GPIO4=TX, GPIO5=RX, 115200 8N1)
//! early in its boot sequence. Calling these macros before UART1 init will
//! produce garbage output or spin forever.
//!
//! # Board tags
//! Each message is prefixed with a short board identifier:
//! - `[GEEK]` — rp2350_geek_16m / rp2350_geek_sdcard
//! - `[LCD]`  — waveshare_rp2350_lcd_16m / waveshare_rp2350_lcd_sdcard
//! - `[ONE]`  — rp2350_one_4m
//! - `[PICO]` — pico2_4m (only if uart-debug were manually enabled)

/// Write raw bytes to the debug UART via PAC registers (spin-wait on TX FIFO).
///
/// This is safe to call from either core and from async or sync contexts.
/// It does NOT require an embassy Uart handle — it accesses the hardware
/// directly via the PAC singleton.
///
/// - Waveshare RP2350-LCD boards use **UART0** (GPIO0=TX, GPIO1=RX).
/// - All other boards (Geek, One) use **UART1** (GPIO4=TX, GPIO5=RX).
#[cfg(all(target_arch = "arm", feature = "uart-debug"))]
#[inline(never)]
pub fn uart1_write_bytes(msg: &[u8]) {
    unsafe {
        #[cfg(any(
            feature = "waveshare_rp2350_lcd_16m",
            feature = "waveshare_rp2350_lcd_sdcard"
        ))]
        let uart = embassy_rp::pac::UART0;
        #[cfg(not(any(
            feature = "waveshare_rp2350_lcd_16m",
            feature = "waveshare_rp2350_lcd_sdcard"
        )))]
        let uart = embassy_rp::pac::UART1;
        for &b in msg {
            while uart.uartfr().read().txff() {}
            uart.uartdr().write(|w| w.set_data(b));
        }
    }
}

/// Board tag string, selected at compile time by the active board feature.
#[cfg(feature = "uart-debug")]
pub const BOARD_TAG: &[u8] = {
    #[cfg(any(feature = "rp2350_geek_16m", feature = "rp2350_geek_sdcard"))]
    {
        b"[GEEK] "
    }
    #[cfg(any(
        feature = "waveshare_rp2350_lcd_16m",
        feature = "waveshare_rp2350_lcd_sdcard"
    ))]
    {
        b"[LCD] "
    }
    #[cfg(feature = "rp2350_one_4m")]
    {
        b"[ONE] "
    }
    #[cfg(feature = "pico2_4m")]
    {
        b"[PICO] "
    }
};

/// Write a literal string with board tag prefix and `\r\n` suffix to UART1.
///
/// Usage: `serial_println!("message here")`
///
/// When `uart-debug` is not active, this is a no-op.
#[cfg(all(target_arch = "arm", feature = "uart-debug"))]
#[macro_export]
macro_rules! serial_println {
    ($msg:literal) => {{
        $crate::serial_debug::uart1_write_bytes($crate::serial_debug::BOARD_TAG);
        $crate::serial_debug::uart1_write_bytes($msg.as_bytes());
        $crate::serial_debug::uart1_write_bytes(b"\r\n");
    }};
}

/// Write a literal string with board tag prefix (no newline) to UART1.
///
/// Usage: `serial_print!("partial message")`
///
/// When `uart-debug` is not active, this is a no-op.
#[cfg(all(target_arch = "arm", feature = "uart-debug"))]
#[macro_export]
macro_rules! serial_print {
    ($msg:literal) => {{
        $crate::serial_debug::uart1_write_bytes($crate::serial_debug::BOARD_TAG);
        $crate::serial_debug::uart1_write_bytes($msg.as_bytes());
    }};
}

/// Write formatted output with board tag prefix and `\r\n` suffix to UART1.
///
/// Usage: `serial_fmt!("key={} val={}", key, val)`
///
/// Uses a 256-byte `heapless::String` buffer internally. Output is silently
/// truncated if the formatted string exceeds 256 bytes.
///
/// When `uart-debug` is not active, this is a no-op.
#[cfg(all(target_arch = "arm", feature = "uart-debug"))]
#[macro_export]
macro_rules! serial_fmt {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let mut _buf = heapless::String::<256>::new();
        let _ = core::write!(_buf, "{}", core::format_args!($($arg)*));
        $crate::serial_debug::uart1_write_bytes($crate::serial_debug::BOARD_TAG);
        $crate::serial_debug::uart1_write_bytes(_buf.as_bytes());
        $crate::serial_debug::uart1_write_bytes(b"\r\n");
    }};
}

// ── No-op stubs when uart-debug is disabled or not on ARM ────────────────────

#[cfg(not(all(target_arch = "arm", feature = "uart-debug")))]
#[macro_export]
macro_rules! serial_println {
    ($($arg:tt)*) => {{}};
}

#[cfg(not(all(target_arch = "arm", feature = "uart-debug")))]
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {{}};
}

#[cfg(not(all(target_arch = "arm", feature = "uart-debug")))]
#[macro_export]
macro_rules! serial_fmt {
    ($($arg:tt)*) => {{}};
}
