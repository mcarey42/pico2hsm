# Display Architecture

How the status display on the LCD boards gets its data and draws it.
Boards: RP2350-Geek (ST7789, 240×135, SPI1) and Waveshare RP2350-LCD-1.47
(ST7789V3, 320×172, SPI0, plus a WS2812B LED).  The pixel layout is in
`DISPLAY_LAYOUT.md`.

Code:

| Path | What |
|---|---|
| `pico2hsm-core/src/op.rs` | `classify_op`: the one table mapping an APDU of any applet to an operation category; `OpResult::of_sw` |
| `firmware/src/display_snapshot.rs` | Core1 → core0 snapshot (seqlock), SAS mailbox, core0 input atomics |
| `firmware/src/apdu/dispatcher.rs` | `display_begin` / `display_end` / `display_snapshot` (core1 side) |
| `firmware/src/display/model.rs` | `Controller::step`: inputs → `Screen` (status priority, auth staleness, screensaver, SAS expiry) |
| `firmware/src/display/view.rs` | The view model (`Screen` and its parts, all `Copy + PartialEq`) |
| `firmware/src/display/layout.rs` | Pixel layouts for both panels |
| `firmware/src/display/render.rs` | `render(&Screen, &Layout, target)` |
| `firmware/src/display/band.rs` | `Rgb444Band` draw target (16-row band, span fills), `Scale2` |
| `firmware/src/display/driver.rs` | `Panel` trait, `ScreenDriver` (dirty bands, partial updates) |
| `firmware/src/display/task.rs` | The display task loop (ARM only) |
| `firmware/src/display/tests.rs` | Host render harness (golden hashes, text fit, previews) |
| `firmware/src/board/rp2350_geek.rs`, `waveshare_rp2350_lcd.rs` | The two `Panel`s (controller init, band writes, sleep/wake, LED) |

Everything except `task.rs` and the board panels compiles and is tested on
the host.

---

## 1. Data flow

```text
 core1 (sync dispatcher_loop)                 core0 (Embassy executor)
 ────────────────────────────                 ─────────────────────────
                                              CCID loop: recv APDU
                                                 send_to_core1(apdu)
                                                 APDU_STARTED_MS = now
                                                 DISPLAY_KICK.signal()
 display_begin(apdu) ─ tracked op? ─┐
   SNAP.write(W0..W4) [in progress] │
 dispatch_into(..., RESP_BOX)       │         display task wakes:
 display_end(response, store)       │           step(inputs) → Screen
 SNAP.write(W0..W4) [outcome]       │           dirty bands → render → DMA
 post_response() → RESP_READY       │
                                              await_core1_response
                                              APDU_STARTED_MS = 0
                                              DISPLAY_KICK.signal()
                                              send response to host
```

Core0 never derives state from APDU bytes.  The only truth is core1's
snapshot; core0 adds what only it knows (USB configured, how long the APDU
in flight has run, the session epoch, its own clock).

## 2. The snapshot (`display_snapshot::SNAP`)

A seqlock over six `AtomicU32` words.  Writer: `seq += 1` (odd), Release
fence, store the words (Relaxed), `seq += 1` (even, Release).  Reader:
Acquire load of `seq`, read the words, Acquire fence, re-read `seq`; retry
if it was odd or changed; give up after 64 tries and keep the previous
copy.  One writer: core0 at boot (`publish_boot_snapshot`, before core1
starts), then core1 only.  No lock is ever held across cores.

| Word | Bits | Field |
|---|---|---|
| W0 session | 0–7 | reserved (0; the epoch is in W5) |
| | 8–9 | active applet: 0 none, 1 HSM, 2 PIV, 3 PGP |
| | 10–16 | auth: HSM_USER, HSM_SO, PIV_PIN, PIV_MGMT, PGP_PW1_81, PGP_PW1_82, PGP_PW3 |
| | 17–18 | one-shot: PIV_9C_ARMED (`pin_always_ok`), PGP_SIG_SINGLE (C4 = 00 and PW1-81 armed) |
| | 19–22 / 23–26 | `pri_left` / `pri_max`: active applet's primary PIN (saturated at 15) |
| | 27–29 | blocked: one bit per applet's primary credential |
| W1 activity | 0–7 | `op_seq` (wraps) |
| | 8–12 | `op` (`OpCode`) |
| | 13–14 | state: 0 idle, 1 in progress, 2 done |
| | 15–16 | result: 0 ok (9000, 61xx), 1 refused, 2 error |
| | 17–20 / 21–28 | `algo` / `key_ref` (shown in debug builds only) |
| | 29–30 | policy hint: 1 PIV 9C PIN-always spent, 2 PGP single-signature PW1 spent |
| W2 inventory | 0–7 / 8–11 / 12–13 | user keys: SC-HSM / PIV / OpenPGP |
| | 14–15 | domain: 0 none, 1 DKEK without a member certificate, 2 member, 3 revoked |
| | 16–21 | member-list entries |
| W3 health | 0–15 | first two bytes of the domain ID |
| | 16–21 | `KS_INIT_FAILED`, `SMK_MISSING`, `STORE_WRITE_FAILED` (sticky until a write succeeds), `SD_MISSING` (the last SD card access failed), reserved, `PROVISIONED` |
| W4 | 0–15 | status word of the last tracked operation (debug detail) |
| W5 | 0–31 | `epoch`: the full `SESSION_EPOCH` the snapshot was built for |

W4 and W5 are additions to the 4-word layout of the design spec: the raw
SW does not fit in W1's spare bits, and the epoch must be compared in full
(the spec's low byte aliases after 256 silent card power cycles, which
would let a stale snapshot's authentication show as live).

Health bit 4 was `MIRROR_DEGRADED` (and a DEGRADED status word).  No
display board has a mirrored store (only the LED-only RP2350-One runs
RAID-1), so it could never be set; the bit, the status word and its screen
were removed.

Pack/unpack is unit-tested (`display_snapshot::tests`).

### Publish points (all in `dispatcher_loop`, core1)

1. **Before dispatch**, only for a tracked operation: W1 `state=1`, `op`,
   `op_seq += 1`.
2. **After dispatch, before `blocking_send`**: everything, with the
   outcome.  The host cannot see the response before the display can.
3. **After `clear_session()`** (a new host session): auth bits zero, the
   new `epoch`.
4. **After a reset / reload** (empty APDU), and **at boot** from core0.

### Where the values come from

`Dispatcher::display_snapshot()` reads live RAM state only:

- Auth: SC-HSM `pin_verified` / `so_pin_verified`, PIV `pin_verified` /
  `mgmt_key_authenticated`, OpenPGP `pw1_verified_sign` /
  `pw1_verified_other` / `pw3_verified`.
- Retries: the applets' RAM counters (`pin_retry_count`,
  `pin_state.pin_retries_remaining`, `pw1_retries`).  Every
  `with_persisted_attempt` keeps them equal to the retry-counter log, so
  no flash is read per publish.  The SC-HSM user-PIN maximum is the log's
  `allowance`, cached at boot and after INITIALIZE / RESET RETRY COUNTER.
- Keys: SC-HSM `key_index` without files (type 16) and refs 0xFC–0xFF;
  PIV `key_index`; OpenPGP slots with a key type.
- Domain: `state.domain`, and the member list (count, this device's entry
  and its status) re-read from the store at boot and after the commands
  that change it (INITIALIZE, KEY DOMAIN, the EXTRAS domain sub-commands).
- Health: boot facts from core0 (`set_boot_health`), `STORE_WRITE_FAILED`
  set on SW 6581 and cleared by the next successful write operation,
  `PROVISIONED` re-read after a 9000 to INS F0–F2.  `SD_MISSING` mirrors
  `display_snapshot::SD_FAULT`, which `SdCardFlash` sets on every failed
  card read / write / erase and clears on the next one that succeeds (on
  the SD boards that I/O runs on core1, so the publish after the command
  carries it).  A pulled card is noticed at the next card access — there is
  no idle polling — and, since the card is not re-initialised at runtime
  (its pairing is checked only at boot), a re-inserted card stays MISSING
  until the next boot.

### Operation classification

`pico2hsm_core::op::classify_op(applet, ins, p1, p2, data)`:

| Op | Mapping |
|---|---|
| Sign | HSM 0x68; PIV 0x87 on 9A/9C/9E with a challenge (tag 81) in the 7C template; PGP 0x2A 9E9A |
| Decrypt | HSM 0x62 with an RSA algorithm (P2 0x21/0x22); PIV 0x87 on 9D with tag 81 |
| Derive | HSM 0x62 with an ECDH algorithm or DERIVE_ASYM (P1=01, P2=00); PIV 0x87 on 9D with tag 85 |
| Auth | PGP 0x88 |
| Decipher | PGP 0x2A 8086 |
| KeyGen | HSM 0x46 / 0x48; PIV 0x47; PGP 0x47 with P1=0x80 (P1=0x81 only reads the key) |
| Import | HSM 0x74 |
| Delete | HSM 0xE4 |
| Verify | 0x20 with a PIN (an empty body is a status query, P1=FF a logout: both Other) |
| ChangePin / Unblock / Initialize | 0x24 / 0x2C / 0x50 |
| Enroll | HSM EXTRAS 0x54 with P1 0x37 / 0x3D / 0x45 |
| Other | everything else (SELECT, GET DATA, READ BINARY, GET RESPONSE, ...) |

Note: the design spec mapped "HSM 0x62 with P2=0x00" to Decrypt; in this
firmware P2=0x00 is DERIVE_ASYM and DECIPHER always carries an algorithm
byte, so the table above follows the handlers.

`Other` never changes the last operation.  A chained command (CLA bit
0x10) counts once, as the operation its first block announced
(`OpTracker`); a GET RESPONSE that continues a tracked operation's 61xx
answer keeps the op and its `op_seq` and records its own SW and result
(the final status of the operation: a GET RESPONSE that fails turns the
op into FAILED / REFUSED).  Only a GET RESPONSE straight after the 61xx
counts; any other command in between ends the sequence.  61xx is success.  SW classes: ok = 9000 / 61xx;
error = 64xx / 65xx / 6Fxx (the device failed); refused = everything else
(wrong PIN, security status, wrong data — the host's request was refused).

## 3. Core0 inputs

| Input | Written by | Meaning |
|---|---|---|
| `display_snapshot::USB_CONFIGURED` | `UsbSessionHandler` | a host configured USB |
| `display_snapshot::APDU_STARTED_MS` | CCID loop | uptime (ms, low 32 bits, never 0) when the APDU in flight went to core1; 0 idle |
| `SESSION_EPOCH` | USB handler, CCID power on/off, an abandoned bulk-IN write | the current host session (all 32 bits are compared) |
| `display::task::DISPLAY_KICK` | CCID loop, USB handler, every `bump_session_epoch` | `Signal<CriticalSectionRawMutex, ()>`: look again |

`bump_session_epoch` kicks the display itself, so a card power-off drops
the authentication on screen at once, not at the next 1 Hz tick.

The CCID loop hands the APDU to core1 *first*, then sets the start time and
kicks.  It never renders.  Core1 never signals `DISPLAY_KICK` (that would
take the critical-section spinlock core0's USB stack uses); the 300 ms
WORKING deadline and the kick after the response cover it.

## 4. The display task (`display::task::run`)

`run_geek_board` / `run_waveshare_lcd_board` initialise the panel, draw the
boot splash through the storage, key-load and USB steps, then join three
futures on core0: `usb.run()`, the CCID loop, and `display::task::run`
(which owns the panel: SPI bus, DC/CS/RST/BL, and the WS2812 on Waveshare).

```text
loop {
    inputs = sample()                       // snapshot, SAS mailbox, atomics, clock
    frame  = controller.step(&inputs)       // Screen, sleep?, LED, deadline
    if frame.sleep { panel sleep } else { wake if asleep; driver.show(screen) }
    driver.led(frame.led, dim = frame.sleep)  // written only on change
    select3(DISPLAY_KICK.wait(), Ticker 1 Hz, Timer::at(deadline))
}
```

Deadlines: `APDU start + 300 ms` (WORKING appears only then), every 250 ms
while WORKING (progress bar), every second while a SAS is pending, the end
of a notice.

### Controller rules (`display::model`)

- **No snapshot yet** (never published): a neutral boot-splash screen,
  `Starting...`, LED off — never READY, never authentication.  In practice
  core0 publishes the boot snapshot before the task starts, so this is the
  fail-closed default only.
- **Status** (highest first): ERROR (`STORE_WRITE_FAILED`,
  `KS_INIT_FAILED` or `SD_MISSING`), LOCKED (active applet's primary
  credential blocked), WORKING (APDU in flight ≥ 300 ms), NO HOST (USB not
  configured), READY.  Health fails closed: READY needs no failure bit.
  With `SD_MISSING` the footer says `SD MISSING` and the activity note
  `SD card missing` (unless a failed write's `Last change NOT saved`
  takes precedence).
- **Authentication** is shown only if `W5.epoch == SESSION_EPOCH` (all 32
  bits) and USB is configured; otherwise the applet chip shows `--`, the PIN tile
  "no applet", and no ADMIN chip.  A logout, a card power-off and a USB
  reset all show "not authenticated" (audit S2-misc).
- **ADMIN chip** whenever SO-PIN, PIV management key or PW3 is live in any
  applet.
- **Last operation** stays on screen with its age (seen-at time on core0)
  and fades: TEXT under 10 s, TEXT2 under 60 s, DIM after.  It outlives its
  session: once the session has ended (epoch moved on, or USB down) it is
  drawn DIM without the policy hint, while authentication and ADMIN clear
  as above.  "Idle" only before the first operation since boot.
- **Footer**: every variant (normal, reset warning, dev board) carries the
  storage health, drawn at the right of the strip.
- **Full-screen errors**: E20 while `SMK_MISSING`; E12 while
  `NEEDS_FORMAT` (a 1.x keystore after the 2.0 upgrade; cleared when
  FORMAT STORE succeeds); E11 while
  `KS_INIT_FAILED` and the host has not yet run an operation (afterwards an
  ERROR band).  E10 is drawn by the boot code (no SD card) before it waits
  for the watchdog.
- **Screensaver**: after 300 s without any change (snapshot, SAS, USB,
  APDU activity), only on READY / NO HOST without ADMIN: backlight off,
  DISPOFF, SLPIN.  Any change wakes it: SLPOUT, 120 ms, DISPON, full
  redraw, and only then the backlight (`Panel::backlight_on`), so the
  pre-sleep GRAM is never visible.  The LED stays on, dimmed.  Never
  asleep with ERROR, LOCKED, WORKING, ADMIN, a SAS or a notice up.
- **SAS**: see §6.

## 5. Rendering and RAM

There is no framebuffer.  The screen is drawn 16 full-width rows at a time
into a band buffer (`DISPLAY_BAND`, a `ConstStaticCell`):

| Board | Band buffer | Old framebuffer |
|---|---|---|
| Waveshare 320×172 | 320 × 16 × 1.5 = 7 680 B | 82 560 B |
| Geek 240×135 | 240 × 16 × 1.5 = 5 760 B | 48 600 B |

For each band, `render()` runs the whole screen against `Rgb444Band`, which
drops rows outside the band; `Painter` skips every element whose box misses
the band, so a band costs about its share of the screen (well under 1 ms).
Each band goes out as one CASET/RASET window and one DMA transfer.
Full-width bands mean every row starts on a pixel pair: no
read-modify-write across band edges.

`Rgb444Band::fill_solid` is a span fill: at most one leading and one
trailing odd pixel are written individually, the middle is a repeated
12-byte pattern copied with `copy_from_slice` (a couple of cycles per pixel
instead of ~25).

**Partial updates.** `ScreenDriver` keeps the last `Screen` it sent.
`dirty_bands(prev, next)` compares region by region (status band, each
tile, activity, footer; splash step line; SAS countdown; error/notice
footer) and only the bands touching changed rows are re-rendered.  The
1 Hz uptime tick touches the footer only (two bands on Waveshare, about
15 KB of SPI).  The host tests check that every partial update produces
exactly the frame a full redraw would.

Commands shorter than 300 ms cause no READY/WORKING repaint at all — only
the activity line (and possibly a tile) after they complete.

**Watchdog.** The task awaits a DMA transfer between bands and does no
synchronous work longer than one band render; controller init uses
`embassy_time` delays on both boards, so the executor and the watchdog
feeder keep running throughout.

### Measured `.bss` (release, all applets + RSA + curve25519)

| Board | before | after | change |
|---|---|---|---|
| Waveshare LCD 16MB | 363 352 B | 285 240 B | −78 112 B |
| Waveshare LCD SDCard | 355 880 B | 277 768 B | −78 112 B |
| RP2350-Geek 16MB | 329 376 B | 283 296 B | −46 080 B |
| RP2350-Geek SDCard | 321 904 B | 275 816 B | −46 088 B |

The snapshot, SAS mailbox, input atomics and kick signal cost under 200 B
of `.bss` (the review fixes — the 32-bit epoch word, the SAS epoch,
`SD_FAULT`, the GET RESPONSE flag — added 76–84 B on the display boards).
Core1: `dispatcher_loop` grew by 8 B (debug build); the new
`display_end → refresh_display_facts → member::count → fetch_key` branch is
far shallower than the dispatch path (~89 KB of 128 KB, unchanged).

## 6. SAS mailbox (enrollment short authentication string)

`display_snapshot::SAS_MAILBOX` is a four-word seqlock: `gen`, `digits`
(0..10^8), `meta` = role (1 bit: sponsor / joiner), `peer_fp` (16 bits, the
first two bytes of SHA-256 of the peer public key), state (3 bits: none,
pending, enrolled, cancelled, expired), and `epoch`: the full
`SESSION_EPOCH` the code was published in.

Core1 API: `sas_publish(digits, role, peer_fp, epoch)` (a new `gen`; a new
code replaces the old one; `epoch` is the session core1 serves) and `sas_clear(state)` (only acts on a pending code).
`sas_clear` is already called on `clear_session()`, on SELECT of a
different applet, on a successful INITIALIZE and when ENROLL_PEER_PUBKEY
(EXTRAS 0x3D) pins a new peer.

The display task shows the framed SAS screen (the SAS colour #D4F is
reserved for it) whenever the state is pending **and** the code belongs to
the live session: USB configured and the mailbox `epoch` equal to the
current `SESSION_EPOCH`.  Core1 clears the mailbox only at the next APDU of
a new session, so between a card power-off / USB reset and that APDU the
task treats a pending code as cancelled (a CANCELLED notice, never the old
digits): the SAS never outlives its session (spec §4.7).  It starts a 120 s deadline
from the first `gen` it sees, overrides the screensaver and the home
screen, and once the deadline passes shows "CODE EXPIRED" — never the stale
code.  Enrolled / cancelled / expired transitions show a 10 s notice.

**On `main`, nothing calls `sas_publish`.**  The trigger is the follow-up
(design spec §2.6 P2b, on `feat/p2-enrollment`): the device computes the
SAS itself from `device_member_pub()`, the pinned peer and nonces drawn by
each device's TRNG behind a commit/reveal (`SAS_BEGIN` 0x4B, `SAS_PEER`
0x4C, `SAS_REVEAL` 0x4D).  A device must never show a SAS without device
nonces — see `CLUSTER_PLAN_V3.md` §5.2.

## 7. Security rules

1. On-screen text is firmware-static.  No host-supplied bytes are rendered
   (no labels, DOs, names, APDU data); numbers come from firmware state
   (counts, fingerprints, SAS digits computed on the device).
2. The SAS colour and framed SAS layout are reserved for a pending SAS set
   by core1 (a host test asserts no other screen contains the colour).
3. Authentication is shown only from core1's snapshot, for the current
   session with USB configured.  Stale means not authenticated.
4. Admin authorisation is the most visible element (ADMIN chip).
5. Health fails closed; defaults are "not provisioned" and "no auth".
6. Production and debug builds differ (`cfg(any(debug_assertions, feature =
   "debug"))` = `display::DETAIL`): debug adds the per-applet key split, the
   algorithm / key ref / SW on the activity line, and the panel border on
   the boot splash.  PIN lengths, slot names, labels, nonces and keys are
   never shown.
7. The SAS never outlives its session: it is shown only while the
   mailbox epoch is the current `SESSION_EPOCH` and USB is configured.
8. The screensaver never hides LOCKED, ERROR, ADMIN or a pending SAS.

## 8. Host render harness

`cargo test -p pico2hsm-firmware --lib --no-default-features --features
pico2_4m --target x86_64-unknown-linux-gnu display::` runs:

- golden FNV-1a hashes of every screen and state at both resolutions (the
  failure message prints the new table after an intended change);
- a text-fit check (no string outside its box);
- partial-update ≡ full-redraw for every pair of screens;
- the 1 Hz footer tick sends at most two bands;
- PPM images in `target/display-snapshots/<res>/`, and PNGs (1:1 and 3×
  in `3x/`) in `$DISPLAY_PREVIEW_DIR/<res>/` when that variable is set.
