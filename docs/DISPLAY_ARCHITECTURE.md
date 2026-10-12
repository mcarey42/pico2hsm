# Display Update Architecture

## Overview

The display pipeline decouples the APDU loop from display rendering so that
SPI writes to the ST7789 never add latency to a CCID command response.

The APDU loop (a plain `async` block inside `run_geek_board`) posts a
`DisplayUpdate` message into a static `Channel` and immediately continues.
A separate Embassy task on core0 (`display_task`) drains that channel,
maintains the full `DisplayState`, drives the SPI bus, and manages the
screensaver timer.  Nothing crosses to core1; the display task is pure core0.

```
USB host
   │  CCID bulk-OUT
   ▼
ccid.recv_apdu()          ← core0, CCID loop
   │
   ├─ DISPLAY_CHANNEL.try_send(DisplayUpdate::ApduActivity)   // non-blocking
   ├─ APDU_CHANNEL.send(apdu_bytes).await                     // to core1
   │
   │        core1 dispatcher_task (crypto) ─────────────────────────────┐
   │                                                                     │
   ◄─ RESP_CHANNEL.receive().await ◄────────────────────────────────────┘
   │
   ├─ DISPLAY_CHANNEL.try_send(DisplayUpdate::SetLastOp(op))  // non-blocking
   ├─ DISPLAY_CHANNEL.try_send(DisplayUpdate::SetStatus(s))   // non-blocking
   │
   └─ ccid.send_response(...)
```

The display task runs as a third future joined alongside `usb.run()` and
`ccid_fut`, or spawned as a separate Embassy task. Either composition works;
the spawned-task approach is preferred because it avoids widening the join
tuple and keeps `run_geek_board` readable. See Section 6 for the task
skeleton.

---

## 1. `DisplayState` Struct

`DisplayState` is the complete model for one rendered frame. The display task
owns the single authoritative instance and mutates it in response to
`DisplayUpdate` messages.

```rust
/// Timestamp in seconds since boot, derived from `embassy_time::Instant`.
type BootSecs = u32;

/// Classification of the last completed HSM operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastOperation {
    Sign,
    KeyGen,
    Ecdh,
    Decrypt,
    Verify,
    ChangePin,
    Initialize,
    Other,
}

/// Everything needed to render one display frame.
#[derive(Debug, Clone, Copy)]
pub struct DisplayState {
    /// Overall HSM status — maps to a status-bar colour.
    pub status: LedStatus,

    /// Number of key objects currently stored.
    pub key_count: u8,

    /// `true` while the keystore is healthy.  (No firmware path clears it
    /// in 1.x; the RAID-mirror health it once meant is gone.)
    pub storage_ok: bool,

    /// `true` when a PIN session is active (VERIFY succeeded, not yet timed out).
    pub authenticated: bool,

    /// Last completed operation and the boot-second at which it completed.
    /// Cleared to `None` after `LAST_OP_DISPLAY_SECS` seconds have elapsed.
    pub last_op: Option<(LastOperation, BootSecs)>,

    /// Persistent error message.  Set on any unrecoverable error; cleared
    /// when the next successful operation arrives.
    pub error_msg: Option<&'static str>,

    /// Seconds elapsed since firmware boot (wraps at ~136 years).
    pub uptime_secs: BootSecs,
}

impl DisplayState {
    pub const fn new() -> Self {
        Self {
            status: LedStatus::Off,
            key_count: 0,
            storage_ok: true,
            authenticated: false,
            last_op: None,
            error_msg: None,
            uptime_secs: 0,
        }
    }
}
```

Key design choices:

- All fields are `Copy` — no heap, no `heapless::Vec`. The struct is 24 bytes
  on a 32-bit target and passes cheaply through the channel.
- `last_op` carries a timestamp rather than a countdown so the display task can
  recompute the remaining TTL relative to the current `uptime_secs` on every
  render pass, without needing a separate timer future.
- `error_msg` is `&'static str` — error strings are compile-time literals;
  there is no need for a heap-allocated string.

---

## 2. `DisplayUpdate` Enum

Messages posted by the APDU loop. The channel capacity (Section 4) is 8;
if the channel is full `try_send` silently drops the update. This is
acceptable because the display is informational — a dropped status update
causes a one-frame stale display, never a protocol error.

```rust
/// Message posted by the APDU loop to the display task.
#[derive(Debug, Clone, Copy)]
pub enum DisplayUpdate {
    /// Overall HSM status changed (Busy/Ready/Error/WaitingForPin/…).
    SetStatus(LedStatus),

    /// Number of stored keys changed (after GenerateKey or DeleteKey).
    SetKeyCount(u8),

    /// Last completed operation (posted after RESP_CHANNEL.receive() returns).
    SetLastOp(LastOperation),

    /// A persistent error message to show until the next successful op.
    SetError(&'static str),

    /// Clear the persistent error (posted on any successful operation).
    ClearError,

    /// Any APDU arrived — resets screensaver timer, wakes display.
    /// Posted by the CCID loop immediately on recv_apdu() Ok(_).
    ApduActivity,

    /// Storage health changed.
    SetStorageHealth(bool),

    /// PIN session state changed.
    SetAuthenticated(bool),

    /// Periodic uptime tick posted by a 1-second timer task or inline in the
    /// CCID loop.  Drives uptime_secs and triggers screensaver countdown.
    Tick(u32),
}
```

`SetError` and `ClearError` are separate variants rather than
`SetError(Option<…>)` to make call-sites read clearly:

```rust
// On success:
let _ = DISPLAY_CHANNEL.try_send(DisplayUpdate::ClearError);
// On error:
let _ = DISPLAY_CHANNEL.try_send(DisplayUpdate::SetError("flash write failed"));
```

---

## 3. `DisplayChannel` Static

```rust
use embassy_sync::channel::Channel;
// Spinlock 28 is unreserved in this firmware (29=APDU, 30=RESP, 31=defmt RTT).
use embassy_rp::spinlock_mutex::SpinlockRawMutex;

/// Core0 APDU loop → Core0 display task.
/// Capacity 8: absorbs a burst of updates for one APDU round-trip
/// (ApduActivity + SetStatus(Busy) + SetLastOp + SetStatus(Ready) + ClearError
/// = 5 messages max per APDU) without dropping.
pub static DISPLAY_CHANNEL: Channel<SpinlockRawMutex<28>, DisplayUpdate, 8> = Channel::new();
```

Why a `SpinlockRawMutex` rather than `CriticalSectionRawMutex`? Both
producers (the CCID async block) and the consumer (display task) run on core0,
so a `CriticalSectionRawMutex` would also work and is marginally cheaper.
However, using a numbered spinlock keeps the concurrency model explicit and
consistent with the existing `APDU_CHANNEL` / `RESP_CHANNEL` pattern, making
it easier to audit which spinlocks each core can hold simultaneously.

Spinlock assignment:

| Spinlock | Owner |
|---|---|
| 29 | `APDU_CHANNEL` (core0 → core1) |
| 30 | `RESP_CHANNEL` (core1 → core0) |
| 31 | defmt RTT (embassy-rp critical_section) — **do not use on core1** |
| 28 | `DISPLAY_CHANNEL` (core0 → core0) — new |

---

## 4. Integration Points in `main.rs`

The APDU loop is duplicated across four board runners
(`run_geek_board`, `run_one_board`, `run_pico2_board`,
`run_waveshare_lcd_board`). The integration pattern is identical in each.
This section uses `run_geek_board` as the reference; the diff for the other
three runners is structurally identical.

Only the Geek board currently has an LCD. The display task should be compiled
only when the `rp2350_geek_*` features are active (or in future when any
other board feature enables a display). Guard the spawn with
`#[cfg(any(feature = "rp2350_geek_16m", ...))]`.

### 4a. Before the CCID loop — spawn the display task

Insert after the line `board.led().set_status(LedStatus::Ready);` (line 567
in the current file) and before `let usb_fut = usb.run();` (line 599):

```rust
// ── CHECKPOINT 6b — spawn display task (Geek board only) ──────────────
#[cfg(any(
    feature = "rp2350_geek_16m",
    feature = "rp2350_geek_sdcard",
))]
spawner.spawn(display_task()).expect("display task");
```

`spawner` is the `Spawner` argument of `#[embassy_executor::main]`.
`run_geek_board` must gain a `spawner: Spawner` parameter:

```rust
// Before:
async fn run_geek_board(p: embassy_rp::Peripherals) {

// After:
async fn run_geek_board(p: embassy_rp::Peripherals, spawner: embassy_executor::Spawner) {
```

And the call-site in `main()` changes from:

```rust
run_geek_board(p).await;
```

to:

```rust
run_geek_board(p, _spawner).await;
```

(`_spawner` is already the parameter name of `main`.)

Apply the same `spawner` parameter addition to the other board runners that
will use a display task in the future. For runners without a display it is a
no-op — the parameter is simply unused.

### 4b. Inside the CCID loop — posting updates

The five insertion points within the `ccid_fut` async block are:

```rust
// (1) Immediately after recv_apdu() returns Ok — wake screensaver, mark busy.
Ok(apdu_bytes) => {
    let _ = DISPLAY_CHANNEL.try_send(DisplayUpdate::ApduActivity);  // NEW
    let _ = DISPLAY_CHANNEL.try_send(DisplayUpdate::SetStatus(LedStatus::Busy)); // NEW
    board.led().set_status(LedStatus::Busy);   // existing — keep for non-LCD boards
    let _ = APDU_CHANNEL.send(apdu_bytes).await;

    // ... existing time-extension loop ...

    // (2) After RESP_CHANNEL.receive() returns and before send_response — post result.
    // The APDU loop does not currently know the operation type; a future
    // enhancement can decode INS from the saved apdu_bytes.  For now, post
    // a generic SetLastOp. Full INS decoding is described in Section 9.
    let _ = DISPLAY_CHANNEL.try_send(DisplayUpdate::SetLastOp(LastOperation::Other)); // NEW

    match ccid.send_response(&response).await {
        Ok(()) => {
            // (3) Successful response delivered.
            let _ = DISPLAY_CHANNEL.try_send(DisplayUpdate::ClearError);              // NEW
            let _ = DISPLAY_CHANNEL.try_send(DisplayUpdate::SetStatus(LedStatus::Ready)); // NEW
            board.led().set_status(LedStatus::Ready); // existing
        }
        Err(CcidError::UsbDisconnected) => { ... }
        Err(_) => {}
    }
}
// (4) On recv_apdu error / USB disconnect — return to Ready.
Err(CcidError::UsbDisconnected) => {
    ...
    let _ = DISPLAY_CHANNEL.try_send(DisplayUpdate::SetStatus(LedStatus::Ready)); // NEW
    board.led().set_status(LedStatus::Ready);  // existing
    break;
}
```

Note: `try_send` is used (never `.await`) so the CCID loop never yields to
the display task while holding a position in the APDU pipeline. If the channel
is full (capacity 8), the update is silently dropped; the display shows the
previous state for one more frame.

### 4c. Uptime ticks

A one-second tick can be produced in two ways:

**Option A — inline tick in the CCID loop (simpler).**
Not viable: the CCID loop blocks on `recv_apdu()` indefinitely; it cannot
independently fire a 1-second timer.

**Option B — separate tick task (recommended).**
A tiny core0 task posts `DisplayUpdate::Tick(secs)` every second:

```rust
#[embassy_executor::task]
async fn uptime_tick_task() {
    let mut secs: u32 = 0;
    loop {
        embassy_time::Timer::after_secs(1).await;
        secs = secs.wrapping_add(1);
        let _ = DISPLAY_CHANNEL.try_send(DisplayUpdate::Tick(secs));
    }
}
```

Spawn alongside the display task:

```rust
spawner.spawn(uptime_tick_task()).expect("uptime tick task");
```

---

## 5. Display Task Skeleton

```rust
/// How long to show a last-op label before reverting to the main status view.
const LAST_OP_DISPLAY_SECS: u32 = 3;

/// Screensaver activates after this many seconds of APDU inactivity.
const SCREENSAVER_TIMEOUT_SECS: u32 = 300; // 5 minutes

#[cfg(any(
    feature = "rp2350_geek_16m",
    feature = "rp2350_geek_sdcard",
))]
#[embassy_executor::task]
async fn display_task() {
    use embassy_time::{Duration, Instant, Timer};
    use pico2hsm_firmware::board::rp2350_geek::{
        LCD_HEIGHT, LCD_WIDTH, ScreenLayout, St7789StatusDisplay,
    };
    use pico2hsm_firmware::display::render;

    // --- Hardware init ---
    // St7789StatusDisplay::new() steals the SPI1 + LCD GPIO pins.
    // This is safe because display_task() is spawned after run_geek_board()
    // has already consumed the SPI1 peripheral into Rp2350GeekBoard, which
    // means the St7789StatusDisplay::new() call here should be the *second*
    // owner.  To avoid the double-steal, the preferred refactor is to move
    // St7789StatusDisplay construction entirely into display_task() and
    // remove it from Rp2350GeekBoard — see Section 8 (Refactor Notes).
    // Until that refactor, display_task() receives the constructed
    // St7789StatusDisplay via a StaticCell:
    //
    //   static DISPLAY_CELL: StaticCell<St7789StatusDisplay> = StaticCell::new();
    //
    // run_geek_board() calls DISPLAY_CELL.init(St7789StatusDisplay::new(spi1))
    // before spawning this task, which transfers ownership cleanly.
    let display: &'static mut St7789StatusDisplay = DISPLAY_CELL.wait().await;

    let layout = ScreenLayout::for_st7789_geek(); // 240×135, pre-computed font zones

    let mut state = DisplayState::new();
    let mut screensaver = ScreensaverState::Active;
    let mut last_activity_secs: u32 = 0;

    loop {
        // Drain all pending messages before rendering (batching).
        // Use a short timeout so the screensaver timer still fires even when
        // there is no APDU activity.
        let deadline = Instant::now() + Duration::from_millis(100);
        loop {
            match embassy_futures::select::select(
                DISPLAY_CHANNEL.receive(),
                Timer::at(deadline),
            ).await {
                embassy_futures::select::Either::First(msg) => {
                    apply_update(&mut state, msg, &mut last_activity_secs, &mut screensaver);
                }
                embassy_futures::select::Either::Second(_) => break,
            }
        }

        // Advance screensaver state machine.
        let idle_secs = state.uptime_secs.saturating_sub(last_activity_secs);
        match screensaver {
            ScreensaverState::Active => {
                if idle_secs >= SCREENSAVER_TIMEOUT_SECS {
                    screensaver = ScreensaverState::Sleeping;
                    display.backlight_off();
                }
            }
            ScreensaverState::Sleeping => {
                // Display stays blank; we still drain the channel but skip render.
            }
        }

        // Expire last_op label if TTL elapsed.
        if let Some((_, op_secs)) = state.last_op {
            if state.uptime_secs.saturating_sub(op_secs) >= LAST_OP_DISPLAY_SECS {
                state.last_op = None;
            }
        }

        // Render only when awake.
        if screensaver == ScreensaverState::Active {
            render(display, &state, &layout);
        }
    }
}

/// Apply one `DisplayUpdate` message to `DisplayState`.
fn apply_update(
    state: &mut DisplayState,
    msg: DisplayUpdate,
    last_activity_secs: &mut u32,
    screensaver: &mut ScreensaverState,
) {
    match msg {
        DisplayUpdate::SetStatus(s) => state.status = s,
        DisplayUpdate::SetKeyCount(n) => state.key_count = n,
        DisplayUpdate::SetLastOp(op) => state.last_op = Some((op, state.uptime_secs)),
        DisplayUpdate::SetError(e) => state.error_msg = Some(e),
        DisplayUpdate::ClearError => state.error_msg = None,
        DisplayUpdate::SetStorageHealth(ok) => state.storage_ok = ok,
        DisplayUpdate::SetAuthenticated(a) => state.authenticated = a,
        DisplayUpdate::ApduActivity => {
            *last_activity_secs = state.uptime_secs;
            if *screensaver == ScreensaverState::Sleeping {
                *screensaver = ScreensaverState::Active;
                // Caller (display_task loop) will turn backlight on before
                // the next render call.
            }
        }
        DisplayUpdate::Tick(secs) => state.uptime_secs = secs,
    }
}
```

Key decisions:

- The task polls the channel with a 100 ms deadline rather than blocking
  indefinitely. This ensures the screensaver timer fires within 100 ms of its
  deadline even if no APDU arrives.
- Multiple messages are batched per 100 ms window so a burst of five updates
  from one APDU round-trip results in one SPI frame write, not five.
- `apply_update` is a pure function separated from the task body so it can be
  unit-tested on x86_64 without any `embassy_executor` context.

---

## 6. Screensaver State Machine

```
                 boot
                  │
                  ▼
          ┌───────────────┐
          │    Active     │◄──────────────────────────┐
          │               │  ApduActivity message      │
          │  backlight ON │  (any APDU arrival)        │
          └───────┬───────┘                            │
                  │                                    │
    idle >= 300 s │                                    │
                  ▼                                    │
          ┌───────────────┐                            │
          │   Sleeping    │────────────────────────────┘
          │               │
          │ backlight OFF │
          │  blank screen │
          └───────────────┘
```

State representation:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScreensaverState {
    Active,
    Sleeping,
}
```

Transition rules:

| From | Event | To | Side-effect |
|---|---|---|---|
| `Active` | `idle_secs >= SCREENSAVER_TIMEOUT_SECS` | `Sleeping` | `display.backlight_off()` |
| `Sleeping` | `DisplayUpdate::ApduActivity` received | `Active` | `display.backlight_on()` then full render |
| `Active` | any `DisplayUpdate` other than `ApduActivity` | `Active` | accumulate, render on next 100 ms tick |
| `Sleeping` | any `DisplayUpdate` other than `ApduActivity` | `Sleeping` | accumulate state, skip render |

`backlight_off()` and `backlight_on()` are new methods on `St7789StatusDisplay`
that toggle the `BL` pin without issuing any SPI commands:

```rust
// To add to St7789StatusDisplay:
pub fn backlight_off(&mut self) { self.bl.set_low(); }
pub fn backlight_on(&mut self)  { self.bl.set_high(); }
```

---

## 7. `ScreenLayout` Struct

`ScreenLayout` pre-computes all pixel coordinates and font sizes for a given
display resolution so that `render()` contains no arithmetic and is easy to
review.

```rust
/// Pre-computed layout parameters for one display size.
///
/// Produced once at startup by `ScreenLayout::for_st7789_geek()` (or a
/// future `for_waveshare_lcd()`) and passed by reference to every `render()`.
#[derive(Debug, Clone, Copy)]
pub struct ScreenLayout {
    /// Pixel width of the display (e.g., 240).
    pub width: u16,
    /// Pixel height of the display (e.g., 135).
    pub height: u16,

    // ── Status bar (top strip) ────────────────────────────────────────────────
    /// Y coordinate of the bottom edge of the status bar.
    pub status_bar_height: u16,
    /// Background colour of the status bar (RGB565), overridden per `LedStatus`.
    pub status_bar_bg: u16,

    // ── Main content zone ─────────────────────────────────────────────────────
    /// Y start of the main content area (below status bar).
    pub content_y: u16,
    /// Height of the main content area in pixels.
    pub content_height: u16,

    // ── Font sizes (pixel height of one text glyph row) ──────────────────────
    /// Large font — used for key-count and last-op label.
    pub font_large_h: u16,
    /// Small font — used for status text, uptime, storage line.
    pub font_small_h: u16,

    // ── Text zone origins (x, y top-left of each rendered text block) ─────────
    /// Top-left of the key-count text.
    pub key_count_origin: (u16, u16),
    /// Top-left of the authenticated indicator.
    pub auth_origin: (u16, u16),
    /// Top-left of the storage health indicator.
    pub storage_origin: (u16, u16),
    /// Top-left of the last-op label (shown for LAST_OP_DISPLAY_SECS seconds).
    pub last_op_origin: (u16, u16),
    /// Top-left of the error message text.
    pub error_origin: (u16, u16),
    /// Top-left of the uptime counter.
    pub uptime_origin: (u16, u16),
}

impl ScreenLayout {
    /// Layout for the 240×135 ST7789 on the RP2350-Geek.
    pub const fn for_st7789_geek() -> Self {
        Self {
            width: 240,
            height: 135,
            status_bar_height: 24,
            status_bar_bg: 0x0000,
            content_y: 24,
            content_height: 111,
            font_large_h: 28,
            font_small_h: 14,
            key_count_origin:  (8,   28),
            auth_origin:       (160, 28),
            storage_origin:    (160, 50),
            last_op_origin:    (8,   70),
            error_origin:      (8,   96),
            uptime_origin:     (8,  118),
        }
    }

    /// Layout for the 172×320 ST7789V3 on the Waveshare RP2350-LCD-1.47-B
    /// (landscape: 320×172 logical after MADCTL rotation).
    pub const fn for_waveshare_lcd_1_47() -> Self {
        Self {
            width: 320,
            height: 172,
            status_bar_height: 30,
            status_bar_bg: 0x0000,
            content_y: 30,
            content_height: 142,
            font_large_h: 32,
            font_small_h: 16,
            key_count_origin:  (8,   36),
            auth_origin:       (220, 36),
            storage_origin:    (220, 60),
            last_op_origin:    (8,   90),
            error_origin:      (8,  124),
            uptime_origin:     (8,  155),
        }
    }
}
```

---

## 8. `render()` Function Signature

```rust
/// Render the complete display frame.
///
/// Called by the display task after batching updates.  Writes to the
/// display via the `DrawTarget` impl on `St7789StatusDisplay`.
///
/// `display` — mutable reference to the display driver (owns the SPI bus).
/// `state`   — current `DisplayState` (read-only; all fields are `Copy`).
/// `layout`  — pre-computed pixel geometry for this display size.
pub fn render<D>(
    display: &mut D,
    state: &DisplayState,
    layout: &ScreenLayout,
) where
    D: embedded_graphics::draw_target::DrawTarget<Color = embedded_graphics::pixelcolor::Rgb565>,
{
    use embedded_graphics::{
        mono_font::{ascii::FONT_9X18, ascii::FONT_6X10, MonoTextStyle},
        prelude::*,
        primitives::{PrimitiveStyleBuilder, Rectangle},
        text::Text,
    };

    // 1. Status bar — full-width rectangle coloured by LedStatus.
    let bar_color = led_status_to_rgb565(state.status);
    let bar_style = PrimitiveStyleBuilder::new()
        .fill_color(Rgb565::new(/* ... unpack bar_color ... */))
        .build();
    Rectangle::new(Point::zero(), Size::new(layout.width.into(), layout.status_bar_height.into()))
        .into_styled(bar_style)
        .draw(display)
        .ok();

    // 2. Key count label.
    // 3. Auth indicator ("PIN" badge or blank).
    // 4. Storage health indicator.
    // 5. Last-op label (only when state.last_op.is_some()).
    // 6. Error message (only when state.error_msg.is_some()).
    // 7. Uptime counter.
}
```

The `DrawTarget` bound means `render()` compiles and runs on x86_64 against
a `MockDisplay` from the `embedded-graphics-simulator` crate, enabling
full-frame snapshot tests without physical hardware.

---

## 9. Sequence Diagram

```
Host        USB CCID     core0 CCID loop    DISPLAY_CHANNEL    display_task      ST7789 SPI
 |               |               |                  |                |               |
 |──APDU──►      |               |                  |                |               |
 |          ──recv_apdu──►       |                  |                |               |
 |               |      try_send(ApduActivity)──►   |                |               |
 |               |      try_send(SetStatus(Busy))──►|                |               |
 |               |      APDU_CHANNEL.send().await   |                |               |
 |               |               |  [core1 crypto]  |                |               |
 |               |          (100 ms poll deadline fires)             |               |
 |               |               |                  |──drain msgs──► |               |
 |               |               |                  |                |──render()──── |
 |               |               |                  |                |  fill status  |
 |               |               |                  |                |  bar + zones  |
 |               |               |                  |                | ─────────────►|
 |               |    RESP_CHANNEL.receive().await   |                |               |
 |               |               |                  |                |               |
 |               |      try_send(SetLastOp(op))──►  |                |               |
 |               |      try_send(ClearError)────►   |                |               |
 |               |      try_send(SetStatus(Ready))─►|                |               |
 |               |      send_response()             |                |               |
 |◄──response──  |               |                  |                |               |
 |               |          (100 ms poll fires)      |                |               |
 |               |               |                  |──drain msgs──► |               |
 |               |               |                  |                |──render()─────|
 |               |               |                  |                |  Ready state  |
 |               |               |                  |                | ─────────────►|
```

Notes on the timeline:

- The 100 ms render window means the display update lags the APDU response by
  at most 100 ms. This is imperceptible to a human operator.
- The `try_send` calls are non-blocking and do not appear in the timing path
  between `recv_apdu` and `send_response`. The entire APDU latency budget is
  unchanged.
- `render()` occurs in a different Embassy task and therefore interleaves with
  `usb.run()` at `await` points inside `render()` (i.e., at each SPI DMA
  transfer if the SPI is switched to async mode). For the initial
  implementation using blocking SPI, `render()` is a single long synchronous
  burst; switching to async SPI is a follow-on optimisation.

---

## 10. `StaticCell` Ownership Transfer

The `St7789StatusDisplay` must be constructed exactly once and transferred from
`run_geek_board` to `display_task` without cloning. The pattern:

```rust
// In main.rs (module level):
#[cfg(any(feature = "rp2350_geek_16m", ...))]
static DISPLAY_CELL: StaticCell<St7789StatusDisplay> = StaticCell::new();

// In run_geek_board(), after Rp2350GeekBoard::new() — before spawning:
// Extract display from board struct (requires pub field or into_parts() method):
let (display, spi0_bus) = board.into_parts(); // refactor needed; see below
DISPLAY_CELL.init(display);

// In display_task():
let display: &'static mut St7789StatusDisplay = DISPLAY_CELL.wait().await;
```

The `into_parts()` refactor on `Rp2350GeekBoard` is required because:

1. `display_task` needs sole ownership of `St7789StatusDisplay` (and therefore
   the SPI1 bus and the four LCD GPIOs).
2. The CCID loop only needs to call `board.led().set_status()` for non-LCD
   boards — on the Geek board all status updates go through `DISPLAY_CHANNEL`
   instead, so the CCID loop can drop its reference to the display entirely.

Until the refactor is done, a simpler interim approach is to keep the
`St7789StatusDisplay` inside `Rp2350GeekBoard` and have the display task
access it via a `&'static Mutex<SpinlockRawMutex<28>, St7789StatusDisplay>`.
This avoids the ownership change at the cost of one spinlock acquisition per
render.

---

## 11. File Layout

New and modified files for the implementation:

```
firmware/src/
├── main.rs                          — add DISPLAY_CELL, spawn display_task + uptime_tick_task
├── board/
│   ├── mod.rs                       — no changes needed
│   └── rp2350_geek.rs               — add backlight_off/on, ScreenLayout, into_parts()
└── display/
    ├── mod.rs                       — pub use render, DisplayState, DisplayUpdate, DISPLAY_CHANNEL
    ├── state.rs                     — DisplayState, LastOperation, DisplayUpdate
    ├── channel.rs                   — DISPLAY_CHANNEL static, uptime_tick_task
    ├── render.rs                    — render<D: DrawTarget>(), led_status_to_rgb565()
    └── screensaver.rs               — ScreensaverState, apply_update()
```

`display/` is a new sub-module of the `pico2hsm_firmware` library crate
(`firmware/src/lib.rs` will need `pub mod display;`).  The display task itself
lives in `main.rs` (binary crate) because it references the `DISPLAY_CELL`
and `DISPLAY_CHANNEL` statics that must have `'static` lifetime rooted at the
binary crate.

---

## 12. RAM Budget

| Item | Size | Notes |
|---|---|---|
| `DisplayState` | 24 B | On stack inside `display_task` |
| `ScreensaverState` | 1 B | On stack |
| `DISPLAY_CHANNEL` (8 × `DisplayUpdate`) | ~96 B | BSS, static |
| `DISPLAY_CELL` (`St7789StatusDisplay`) | ~64 B | BSS, static (SPI + 4 GPIO pins) |
| `display_task` future | ~200 B | Embassy task pool |
| `uptime_tick_task` future | ~16 B | Embassy task pool |

Total addition: approximately 400 bytes BSS, negligible stack. Well within the
RAM headroom reported in `CLAUDE.md` (current BSS ~210 KB, limit ~520 KB SRAM).

---

## 13. Dependency Requirements

Add to `firmware/Cargo.toml` under `[dependencies]` (feature-gated):

```toml
[dependencies]
embedded-graphics = { version = "0.8", optional = true }

[features]
# Enable when any display-equipped board is active.
display = ["embedded-graphics"]
rp2350_geek_16m       = ["display", ...]
rp2350_geek_sdcard    = ["display", ...]
waveshare_rp2350_lcd_16m = ["display", ...]
```

`embedded-graphics` is a pure-Rust, `no_std` crate with zero unsafe code and
no heap dependency. It adds approximately 8 KB to flash in a typical
embedded-graphics application using `MonoFont` text rendering.
