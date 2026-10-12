# pico2hsm — Display Layout

Pixel layout of every screen on the two LCD boards.  The coordinates are
the ones in `firmware/src/display/layout.rs` (`WAVESHARE_320X172`,
`GEEK_240X135`); data flow and rules are in `DISPLAY_ARCHITECTURE.md`.
Previews of every screen at both resolutions come out of the host render
harness (`DISPLAY_PREVIEW_DIR=... cargo test ... display::`).

All coordinates are logical: (0,0) is the top-left visible pixel.
Controller offsets live in the board drivers:

| Board | Panel | MADCTL | Visible window |
|---|---|---|---|
| Waveshare RP2350-LCD-1.47 | ST7789V3, 320 × 172 landscape | 0xA0 (MY + MV) | CASET 0–319, RASET 34–205 |
| RP2350-Geek | ST7789, 240 × 135 landscape | 0x70 (MX + MV + ML, RGB order) | CASET 52–291, RASET 40–174 (unverified, see `BOARD_RP2350_GEEK.md`) |

Both run COLMOD RGB444 (two pixels in three bytes) with INVON.

## 1. Palette (RGB444) and type

| Group | Tokens |
|---|---|
| Backgrounds | BG #000, PANEL #111, PANEL2 #222, RULE #333 |
| Text | TEXT #EEE, TEXT2 #AAA, DIM #888 |
| Status | OK #3D5, WARN #FB2, ERR #F44, BUSY #4AF, INFO #6CF, CYAN #2DD |
| Reserved | SAS #D4F — only the pending-SAS screen |

The palette is defined in RGB444 directly (`display/color.rs`), so no two
tokens collapse after truncation (the old RGB565 palette mapped the header
and the cells to the same #111 and "teal" to green).  Black text on OK,
WARN, INFO and CYAN fills; white on ERR and BUSY.  CYAN is NO HOST's
alone, so it never reads as WORKING's blue (INFO is the PIN tile's `OK`).  Every status colour is paired
with a word: colour is never the only signal.

| Use | Waveshare | Geek |
|---|---|---|
| Status word | 10x20 double-struck (bold, no extra font data) | 9x18 bold |
| Tile value | 9x18 bold | 9x18 bold |
| Labels, body | 6x13 | 6x13 (tile labels and sub-lines 6x10) |
| Footer | 6x13 DIM | 6x10 TEXT2 (the 6x10 is tiny on the 1.14" panel) |
| SAS digits | 20x40 (10x20 drawn ×2) | 18x36 (9x18 drawn ×2) |

All embedded-graphics mono fonts (ASCII), in flash.

## 2. Home screen (the only steady-state screen)

### Waveshare 320 × 172

```text
y   0 ┌─▌READY─────────────────────────[ADMIN][ PIV ]┐  band 0–33: PANEL, 6 px status bar,
      │                                               │  status word 10x20 bold @ (14,7),
 34   ├───────────────────────────────────────────────┤  admin chip 186–252, applet chip 260–316 (y 5–28)
 36   │ PIN          │ KEYS          │ DOMAIN         │  tiles 104×62 @ x 2 / 108 / 214, y 36–97
      │ OK           │ 6             │ 3F9A           │  label 6x13 (+6,+4), value 9x18B (+6,+20),
      │ 3/3 left     │ H4 P1 G1      │ 3 members      │  sub-line 6x13 (+6,+44)
100   │ Sign                                          │  activity 2–317 × 100–143, PANEL2
      │ 4s ago  P-256 #9A 9000                        │  line 1 9x18 (+8,+3), line 2 6x13 (+8,+23)
138   │ ▂▂▂▂▂▂▂██████▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂ │  progress bar 10–309 × 138–141 (WORKING only)
150   │ up 2d 04:11  fw 1.0.1  rst: core1      QMI ok │  footer 0–319 × 150–171, 6x13 DIM
172   └───────────────────────────────────────────────┘
```

### Geek 240 × 135

Band 0–25 (4 px bar, status 9x18 bold @ (8,4), admin chip 146–190, applet
chip 196–236, y 4–21, 6x13); tiles 77 × 46 at x 2 / 81 / 160, y 28–73
(label 6x10 +4,+3; value 9x18 bold +4,+14; sub-line 6x10 +4,+33);
activity 2–236 × 76–111 (two 6x13 lines at +3 / +17, 3 px progress bar at
y 107); footer 0–239 × 120–134 (6x10, TEXT2).  Short forms: `3/3`, `H4P1G1`,
`SIG1`, `fw1.0.1`.  The footer drops its `rst:` note if it would not fit.

### Status word (also the band bar and the LED)

| Priority | Word | Colour | When |
|---|---|---|---|
| 1 | ERROR | ERR | keystore init failed, the last write failed (sticky until a write succeeds), or the SD card stopped answering |
| 2 | LOCKED | ERR | the active applet's primary credential is blocked |
| 3 | WORKING | BUSY | an operation has run for more than 300 ms |
| 4 | NO HOST | CYAN | USB not configured |
| 5 | READY | OK | otherwise |

Before core1 has published any snapshot the display shows the boot splash
with `Starting...` (fail closed: never READY).

### Chips

- **Applet chip**: 1 px RULE border, `HSM` / `PIV` / `PGP` in TEXT, or `--`
  in DIM (none selected, or the session is stale).
- **ADMIN chip**: WARN fill, black `ADMIN`, while SO-PIN, the PIV
  management key or PW3 is live in *any* applet.

### Tiles

| Tile | Value | Sub-line |
|---|---|---|
| PIN (active applet's primary: SC-HSM user PIN, PIV PIN, OpenPGP PW1) | `OK` INFO when verified, `--` DIM when not, `BLOCK` white on an ERR tile when blocked | `n/max left` — TEXT2 at ≥ 2, WARN at 1, ERR at 0; with a one-shot armed (PIV 9C PIN-always, OpenPGP single-signature mode) `n/max SIG x1`; `no applet` DIM when none |
| KEYS | user keys, all applets | debug: `H4 P1 G1` (SC-HSM / PIV / OpenPGP); production: `keys` |
| DOMAIN | first two bytes of the domain ID, hex | `N members`; `self` WARN (DKEK without a member certificate); `REVOKED` ERR; `--` / `no domain` DIM |

### Activity

- `Idle` (DIM): no operation since boot.
- `Working: Sign` + elapsed `m:ss` right-aligned + an indeterminate bar
  (40 px BUSY segment, 8 px per 250 ms step): an operation running for more
  than 300 ms.
- `Sign` / `Sign REFUSED` (WARN) / `Sign FAILED` (ERR), then the age
  (`4s ago`).  The text fades TEXT → TEXT2 after 10 s → DIM after 60 s; it
  is never removed, not even when the host session ends (pcscd ends
  sessions between commands): once its session has ended (card power-off,
  USB down) the whole line is DIM and the policy hint goes.  It shows no
  more than production already shows.  Debug builds add `algorithm #keyref SW`.  Policy
  hints replace the debug detail: `PIN-always: re-verify next` (PIV 9C),
  `PW1 single-use spent` (OpenPGP).
- Notes replace the age line in ERR: `Last change NOT saved` (E12, a write
  failed), `SD card missing`, `Keystore unreadable`, `Unblock: PUK or SO-PIN` / `Unblock: PIV
  PUK` / `Unblock: PW3 or reset code` (E40, LOCKED).

### Footer

`up 2d 04:11  fw 1.0.1  rst: core1` on the left and the storage token at
the right, in DIM (TEXT2 on the Geek).  Uptime is `HH:MM:SS` under a day,
`Nd HH:MM` under 1000 days, then `Nd`.  Storage: `QMI ok`, `SD ok`, or in
ERR `QMI FAIL` / `SD FAIL` / `SD MISSING`.  `rst:` names a non-power-on
reset for 24 h after boot.  During the first 60 s after such a reset the
footer is a WARN strip: `Last reset: core1 stall x2`.  An unprovisioned
device running on the development storage key shows a WARN strip
`DEV - UNPROVISIONED  up …`.  Every strip keeps the storage token at its
right (on a WARN strip in a dark PANEL chip), so neither strip hides
storage health; the optional tail (`rst:`, ` x2`, `up …`) is dropped
first when the text would run into it.

## 3. Boot splash

| Element | Waveshare | Geek |
|---|---|---|
| `pico2hsm` | 10x20, centred, y 40 | 9x18, y 20 |
| `fw 1.0.1  <board>` | 6x13 DIM, y 66 | 6x10, y 42 |
| step: `Storage...`, `Keys (6)...`, `USB...`, `Starting...` (no snapshot yet) | 9x18 TEXT2, y 100 | 6x13, y 70 |
| `Last reset: …` (not after a power-on) | 6x13 WARN, y 130 | y 100 |

Each step redraws only its band.  Debug builds draw a 1 px TEXT2 border at
the panel edge: all four edges must be visible (window offset check).

## 4. Full-screen errors

Waveshare: band 0–35 (PANEL, 6 px ERR bar, code 10x20 ERR at (14,8), title
10x20 TEXT at x 64); two action lines 9x18 TEXT2 from y 48 (pitch 24);
detail 6x13 DIM at y 128; footer 150–171.  Geek: band 0–27 (9x18 bold,
title at x 44); action lines 6x13 from y 38 (pitch 16); detail at y 100;
footer 122–134.

| Code | Title | Action | When |
|---|---|---|---|
| E10 | NO SD CARD | Insert microSD card. / Retrying (try N). | SD card init fails at boot; drawn before the device waits for the watchdog (N = watchdog resets in a row + 1) |
| E11 | STORAGE UNREADABLE | Keys not loaded. / Run pico2hsm-tool diag. | keystore init failed; until the host runs an operation, then an ERROR band |
| E20 | NOT PROVISIONED | Keys cannot be stored. / See PROVISIONING.md. | no storage master key (release build, unprovisioned OTP) |
| E31 | RNG FAILURE | Hardware RNG failed self-test. / Device halted. | rendered by the harness; not yet wired (the TRNG failure path resets without the display) |

E12 (a write failed) and E40 (PIN blocked) are not full-screen: they are
ERROR / LOCKED in the band with a note on the activity line.

## 5. Notices (10 s, enrollment outcome)

Same template as the errors, without a code; the title word takes the
level colour: `ENROLLED` (OK bar and title, `7E21 into 3F9A`),
`CANCELLED` (WARN), `CODE EXPIRED` (WARN, `Not confirmed in 120 s.` /
`Restart enrollment on host.`).  CANCELLED also shows when a pending code's
session ends (card power-off, USB reset).

## 6. SAS comparison screen

Waveshare: 3 px SAS frame; `ENROLL - COMPARE CODE` 9x18 bold centred at
y 7; digits `1234 5678` in 20x40 glyphs at y 40–80, centred, 20 px between
the groups; `This device: SPONSOR  peer 04AA` 6x13 TEXT2 at y 92;
`Same code on both devices? Continue on host.` / `Different? Abort and
revoke.` 6x13 TEXT at y 114 / 131; countdown bar (SAS colour, 4 px) at
y 156, x 10–309, shrinking over 120 s.

Geek: 2 px frame; `COMPARE CODE` at y 4; digits 18x36 at y 28 (18 px gap);
role and peer at y 72; `Same code? Continue on host.` / `Different? Abort
and revoke.` at y 90 / 104; countdown bar at y 126.

There is no button: the screen only *detects* a man-in-the-middle; on a
mismatch the operator aborts on the host and revokes.

## 7. LED (Waveshare WS2812B)

Green READY, blue WORKING, cyan NO HOST, yellow notices, red
ERROR / LOCKED / error screens, magenta while a SAS is pending.  Level 8 per
channel, 2 while the screen sleeps.  Written only when the colour changes.
