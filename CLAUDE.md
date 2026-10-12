# pico2hsm — Claude Code Guide

## Build, flash, and debug

Use the debug script to flash firmware and stream RTT logs:

```sh
./build-all-debug.sh pico2_4m
```

Building with `cargo` directly is fine for compile checks, size analysis
(`arm-none-eabi-nm -S --size-sort`, `objdump`), and host tests. Always pass
`--no-default-features --features <board>,...` (see "Feature flags and default
features" below), and set `DEFMT_LOG=trace` if the build will be flashed and you
need full log output. Flash only via the script, which handles signing.

```sh
# From the repo root, -p is required (the workspace includes host-only test crates).
cargo build -p pico2hsm-firmware --no-default-features --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519
# ELF: target/thumbv8m.main-none-eabihf/debug/pico2hsm
```

Valid board arguments: `pico2_4m`, `rp2350_one_4m`, `rp2350_geek_16m`, `rp2350_geek_sdcard`, `waveshare_rp2350_lcd_16m`, `waveshare_rp2350_lcd_sdcard`.

This script:
- Builds with `DEFMT_LOG=trace` (required for defmt log output to survive optimisation)
- Uses the debug profile so `#[cfg(debug_assertions)]` sentinels are active
- Includes `applet-piv` and `applet-openpgp` features (required for PIV/OpenPGP integration tests)
- **Signs the ELF with `picotool seal --hash --sign` if `ec_firmware_signing_key.pem` is present**
  - Signed output → `dist/pico2hsm-<feat>-debug-signed.elf`
  - OTP configuration → `dist/pico2hsm-<feat>-debug-otp.json`
  - If no key is present, flashes unsigned (warns but continues)
  - **About `ec_firmware_signing_key.pem`**: each user of this project generates
    and holds their own secp256k1 key. It is the root of trust for that user's
    HSM fleet — **not** a project-wide test key. The filename is gitignored;
    the `dist/` signed artifacts are gitignored; no key material is ever
    committed. See `docs/PROVISIONING.md` Option A / Option B for generation.
- Flashes via `probe-rs run --chip RP235x` (uses signed ELF if signing occurred)
- Streams RTT output to the terminal until Ctrl+C

The connected hardware is a **Raspberry Pi Pico 2 (pico2_4m feature)** with a Debugprobe (CMSIS-DAP) on the SWD port.

To run the integration test suite against the flashed device:

```sh
./run_tests.sh
```

Start `build-all-debug.sh` in the background first (it blocks on RTT streaming), then wait ~5 s for USB re-enumeration before running `run_tests.sh`.

If multiple pico2hsm devices are connected, select the device under test by its USB serial (the RP2350 chip ID, part of the reader name): `PICO2HSM_READER=<serial> ./run_tests.sh`. Two-device tests take the second device from `PICO2HSM_PEER_READER=<serial>` (default: the first other reader). Run `opensc-tool --list-readers` to see the names. Both are resolved on every connection; `OPENSC_DEFAULT_READER=N` (an index) still works, but indexes shift whenever a board re-enumerates (a flash, a probe-rs reset), so a run selected by index can move to another board half-way.

- **OpenSC tools ignore `OPENSC_DEFAULT_READER`.** Only pyscard honours it. When it or `PICO2HSM_READER` is set, `tests/hw/conftest.py` puts the shims in `tests/hw/helpers/bin` first on PATH; they add `-r N` (`opensc-tool`, `sc-hsm-tool`) or `--slot-description` (`pkcs11-tool`). A bare `opensc-tool` in a shell still talks to reader 0.
- **gpg picks the device by OpenPGP serial.** GnuPG 2.4's scdaemon ignores `reader-port`, and its current card is per connection, so `scd switchcard` can't steer a later `gpg --card-status`. The tests use `gpg-card list <serial>` (or one `gpg-connect-agent` session: `scd switchcard`, `scd learn`), where the serial is the device's OpenPGP AID; bytes 10–13 come from the chip ID, so every board differs. Firmware before that gave every board AID serial `00000001` (and USB serial `0001`); the gpg checks then skip unless the device under test is reader 0.
- **probe-rs resets** need `PROBE_RS_PROBE=2e8a:000c:<serial>` when several probes are attached (`probe-rs list`). Without it the reset tests skip.

If `probe-rs` reports "interface is busy (errno 16)", a previous probe-rs process is still holding the USB device:

```sh
pkill -9 -f "probe-rs"
```

## Architecture overview

**Concurrency model** (RP2350 dual-core):
- **Core0** — Embassy async executor: USB device driver + CCID transport loop, plus the hardware-watchdog feeder task. Sends APDUs to core1 via `APDU_CHANNEL` and waits for responses on `RESP_CHANNEL`.  A `flash_service` future (joined with USB and CCID in every board runner) runs core1's `FlashOp`s whenever they come — during an APDU and between APDUs.
- **Core1** — Synchronous `dispatcher_loop()`: no Embassy executor.  Between APDUs `next_apdu()` runs the RSA key pool's idle work in slices (`rsa_pool::background`, ≤ 20 ms, ending as soon as `APDU_CHANNEL` is non-empty); with nothing to do it sleeps via ARM `wfe` (Wait For Event) and is woken by core0 via `sev` (Send Event) after each channel send.  Calls `blocking_receive()`/`blocking_send()` on the shared channels using `try_receive()`/`try_send()`.

**RSA key pool** (`rsa` feature; `firmware/src/rsa_pool.rs`, `storage/rsa_pool.rs`,
`crypto/rsa_keygen.rs`): pre-generated RSA-2048/3072/4096 keys in 12 sectors of
internal flash at `0x1F0000` (every board), encrypted under the storage key;
SC-HSM GENERATE KEY PAIR takes one (slot marked taken on flash first) or
generates live with the sliced generator.  Config / clock / sequence are
value records in the retry-counter log.  The generator state (~9 KB) is a
static (`rsa_pool::ENGINE`), never on the stack.

Both channels use RP2350 hardware spinlocks (29 and 30) for SMP-safe cross-core signalling.
Core0 issues `cortex_m::asm::sev()` after every `APDU_CHANNEL.send()` and `FLASH_RESP.send()` to wake core1 from WFE.

**CDC serial logger**: Core0 runs a `drain_one()` task that forwards buffered log lines to `/dev/ttyACMx`. `drain_one()` checks DTR before writing; if no terminal has `/dev/ttyACMx` open, the line is dropped silently (no CCID stall).

**APDU dispatch chain** (all on core1, synchronous):
```
dispatcher_loop()
  └─ Dispatcher::dispatch()          [apdu/dispatcher.rs]
       ├─ SELECT AID → activates one of:
       │     ScHsm  (always present)
       │     Piv    (#[cfg(feature = "applet-piv")])
       │     OpenPgp (#[cfg(feature = "applet-openpgp")])
       └─ all other INS → active protocol's process_apdu()
            └─ ScHsm::dispatch() → <command>::handle()   [protocol/sc_hsm/commands/]
```

## Multi-applet feature flag architecture

The device supports multiple smartcard applets on one firmware, selected at compile time via
Cargo features.  A client (OpenSC, GnuPG, macOS CryptoTokenKit) picks an applet by sending
`SELECT AID`; the Dispatcher activates the matching protocol for all subsequent APDUs.

**Applet feature flags:**

| Feature flag | Applet | AID |
|---|---|---|
| *(always on)* | SC-HSM | `E8 2B 06 01 04 01 81 C3 1F 02 01` |
| `applet-piv` | PIV (NIST SP 800-73-4) | `A0 00 00 03 08 00 00 10 00 01 00` |
| `applet-openpgp` | OpenPGP Card 3.4 | `D2 76 00 01 24 01 ...` |
| `applet-openpgp-curve25519` | adds Ed25519 + X25519 to OpenPGP | *(implies applet-openpgp)* |

These compose freely with the board feature flags, e.g.:

```sh
# SC-HSM + PIV on Pico 2:
cargo build --release --no-default-features --features pico2_4m,applet-piv

# All three applets + Ed25519:
cargo build --release --no-default-features \
    --features pico2_4m,applet-piv,applet-openpgp,applet-openpgp-curve25519
```

**Flash / RAM budget (release, all applets + RSA + curve25519, v1.0.1 after the
display redesign; `arm-none-eabi-size -A`):**

| Board | .text | .bss | .bss before the redesign |
|---|---|---|---|
| Pico 2 4MB | 510 KB | 297.4 KB | — |
| RP2350-One 4MB | 515 KB | 297.6 KB | — |
| RP2350-Geek 16MB | 532 KB | 276.6 KB | 321.7 KB |
| RP2350-Geek SDCard | 535 KB | 269.3 KB | 314.4 KB |
| Waveshare LCD 16MB | 534 KB | 278.5 KB | 354.8 KB |
| Waveshare LCD SDCard | 537 KB | 271.2 KB | 347.5 KB |

Flash is not a concern.  RAM is the metric to watch; the 128 KB core1 stack
dominates.  The display boards no longer hold a framebuffer (48 KB Geek,
83 KB Waveshare): they render through a 16-row band buffer (5.6 KB / 7.5 KB),
which freed ~45 KB on the Geek and ~76 KB on the Waveshare boards (Waveshare
LCD 16MB: ~39 KB → ~115 KB free SRAM).

**Storage namespace — implemented:**

All three applets share one flash keystore.  Ownership is encoded in the `KeyId` u32
via the `applet_id` byte (bits 23–16); SC-HSM `INITIALIZE` calls
`wipe_by_owner(AppletId::ScHsm)` and leaves PIV and OpenPGP keys untouched.

`KeyId` u32 encoding (in `pico2hsm-core/src/key.rs`):
```
bits 31–24: partition_id  (u8)  — 0 = default partition
bits 23–16: applet_id     (u8)  — 0=SC-HSM, 1=PIV, 2=OpenPGP, 0x10=domain records
bits 15–8:  reserved            — always 0
bits  7–0:  proto_ref     (u8)  — protocol-level key reference
```

Constructors: `KeyId::sc_hsm(partition, key_ref)`, `KeyId::piv(key_ref)`,
`KeyId::openpgp(slot)`.  Flash magic `"P2K4"` is the current format (with `key_flags` byte); `"P2K2"` and
`"P2K3"` are recognized as legacy and surfaced as incompatible (re-INITIALIZE
required after firmware update from older builds).

**Still required before PIV/OpenPGP command handlers:**
Per-applet PIN slots in flash.  SC-HSM already has a PIN slot; PIV needs its own;
OpenPGP needs PW1 + PW3.  A `PinSlot` enum is planned but not yet implemented.

## Reference documentation

The `docs/` directory contains generated reference documents:

| File | Contents |
|---|---|
| `SC_HSM_APDU_REFERENCE.md` | All 28 SC-HSM commands — INS bytes, TLV tags, algo IDs, pico2hsm deviations |
| `PIV_APDU_REFERENCE.md` | Full NIST SP 800-73-4 command set, 3DES GENERAL AUTHENTICATE, key slots |
| `OPENPGP_APDU_REFERENCE.md` | OpenPGP Card 3.4 — PSO:CDS/DECIPHER, Ed25519/X25519 algo attrs, PW1/PW3 |
| `BOARD_RP2350_ONE.md` | GPIO pinout, WS2812B PIO timing |
| `BOARD_RP2350_GEEK.md` | ST7789 pin table, init sequence, SD card wiring |
| `BOARD_WAVESHARE_LCD_1_47.md` | ST7789V3 + WS2812B, SD card topology |
| `SD_CARD_WIRING.md` | Per-board SD card wiring tables, embedded-sdmmc integration notes |
| `BUILD_CONFIGURATIONS.md` | All feature flag combinations with exact cargo commands, flash/RAM budget |

## Board peripheral implementation

Each board's LED/display driver is fully implemented (not stubbed):

**rp2350_one — WS2812B on GPIO16 (PIO0/SM0)**
- `Ws2812Led::new()` steals `PIO0` and `PIN_16` via `unsafe { steal() }`.
  `main.rs` must **not** claim `p.PIO0` or `p.PIN_16` — they are exclusively
  owned by the LED driver after board init.
- Clock divider is written via `PAC::PIO0.sm(0).clkdiv()` directly (avoids
  `fixed` crate dep); int=18, frac=192 at 150 MHz → 8 MHz PIO clock.
- Write is synchronous (spin-wait on TX FIFO); no DMA or async required.

**Display boards (Geek, Waveshare LCD)** — see `docs/DISPLAY_ARCHITECTURE.md`.
- Core1 publishes a seqlocked snapshot (`display_snapshot::SNAP`) before
  each response; core0's display task (`display::task::run`, joined with
  USB and the CCID loop) renders it.  The CCID loop never renders and never
  guesses state from APDU bytes; it stores `APDU_STARTED_MS` and signals
  `DISPLAY_KICK`.  Core1 must never signal `DISPLAY_KICK`.
- No framebuffer: 16-row band buffer (`DISPLAY_BAND`, 7.5 KB / 5.6 KB),
  dirty bands only.  The render code is host-tested
  (`firmware/src/display/tests.rs`: golden hashes, text fit, previews via
  `DISPLAY_PREVIEW_DIR`).  After a visual change, review the previews and
  paste the new golden table the failing test prints.

**rp2350_geek — ST7789 240×135 on SPI1 (GPIO8/9/10/11/12/25)**
- `Rp2350GeekBoard::new(spi1)` steals DC=GPIO8, CS=GPIO9, RST=GPIO12,
  BL=GPIO25 via `AnyPin::steal()`.  `main.rs` must not claim those four pins.
- `St7789StatusDisplay` is the display `Panel`: async `init()`
  (`embassy_time` delays), band writes, sleep/wake.  MADCTL 0x70 = MX+MV+ML.
- Window offsets CASET 52 / RASET 40 are unverified (possibly portrait
  offsets): do not change them without checking on a Geek (debug builds draw
  a 1 px border on the boot splash).

**waveshare_rp2350_lcd — ST7789V3 320×172 landscape on SPI0 + WS2812B on GPIO22**
- `WavesharePanel` (LCD + LED) is the display `Panel`; async `init()`.
- MADCTL=0xA0 (MY+MV): landscape 320×172, 180°-corrected from broken 0x60 attempt.
- RASET 34–205 (not 0–171): physical GRAM columns 34–205 map to landscape height.
- WS2812: the `Grb` driver orders the bytes; pass `RGB8 {r, g, b}` unswapped.
- SPI on both LCDs: 40 MHz requested = 37.5 MHz.  Never request more.

## Security invariants

Established by the October 2026 audit (`docs/AUDIT_2026-10.md`); keep them
when changing the code.

- **Credential retries are spent on flash before comparing.** VERIFY / CHANGE
  PIN / PUK / re-INITIALIZE (SC-HSM), VERIFY / CHANGE / RESET (PIV), VERIFY /
  CHANGE (OpenPGP) all go through `with_persisted_attempt`; only APDUs the
  handler would actually compare count (`spent_by` mirrors the handler's
  pre-checks). New credential checks must use the same wrapper.
- **Storage errors fail closed.** `Core1KeyStore` is synchronous, so
  `save_key` / `erase_key` / `wipe_*` results are real. Never `let _ =` them
  in a handler: report 6581 and keep RAM consistent with flash.
- **OTP layout lives in `security/otp_layout.rs`** (compile-time overlap
  checks). Never hard-code OTP rows elsewhere; never write row 0x110.
- **Reserved SC-HSM key refs 0xFC–0xFF** (legacy peer record, migrated at
  boot to the single-use pinned peer; DKEK; device key; PIN record) are
  refused by every user key command (`targets_reserved_slot`).
- **Domain records** (cluster plan V3: object-ID sidecars, member
  certificates, the pinned peer) use applet byte 0x10 (`AppletId::Domain`,
  `firmware/src/domain/`). SC-HSM INITIALIZE wipes them with its keys; PIV
  and OpenPGP resets never touch them. The Lamport change counter lives in
  the retry-counter log and is advanced before the change it numbers.
- **The DKEK** is persisted at 0xFD, only replaced by an authenticated,
  SO-PIN, enrolled-peer exchange, never overwritten while set.
- **A member certificate is only issued for an operator-verified key**
  (ISSUE_MEMBER_CERT, 0x54/45, SO-PIN). That key is the peer this device
  sent its DKEK to in this card session (`exchanged_peer`, session state),
  or the currently pinned peer. Either is spent by the certificate. Never
  an arbitrary key. `exchanged_peer` also ends at SELECT, at a new pin and
  at a new SOURCE run.
- **Imported Lamport values are capped** (`member::LAMPORT_CEILING`, 2^62).
  Anything that raises `lamport_seen` from outside the device must be
  bounded, or one signed object could exhaust the persisted counter for
  good.
- **Revocation is permanent per member key** (owner decision 8, plan §12).
  Issue and import refuse a revoked member ID (6984), whatever the
  certificate's Lamport value. Member-list entries are never removed
  before P5. Imports need no PIN: the device checks the domain signature.
  Note that INITIALIZE generates the device (member) key from the TRNG.
- **Secrets are wiped in place.** Zeroize before moving or dropping; use
  `security::zeroize::key_buf` for fixed key buffers; `mem::replace` /
  assigning `None` does not wipe the old bytes.
- **On-screen text is firmware-static.** The display never renders
  host-supplied bytes (labels, DOs, names, APDU data); only firmware strings
  and numbers from firmware state (counts, fingerprints, SAS digits computed
  on the device).  Authentication is shown only from core1's snapshot for
  the current `SESSION_EPOCH` with USB configured (stale = not
  authenticated).  The SAS colour #D4F is reserved for a pending SAS.

## Known pitfalls

### Core1 stack overflow

**Symptom**: APDU is received and logged by core0 (`APDU XX XX XX XX len=N`), time extensions fire every 1.5 s, but the command never completes; after ~30 s core0 sends 6F00 and resets the chip through the hardware watchdog (next boot logs `reset: WATCHDOG RESET: core1 stuck during an APDU`).

**Cause**: core1 runs the whole dispatch chain on its own 128 KB stack (`CORE1_STACK` in `firmware/src/main.rs`). Large stack temporaries — `Vec<u8, 4096>` response buffers, `KeyObject`s (~3 KB), 4 KB flash sector buffers, PKCS#1 DER buffers — add up across `dispatcher_loop → Dispatcher::dispatch_with_store → <protocol>::process_apdu_with_store → route_with_store → handler → store`. MSPLIM is set at the stack base, so an overflow faults (UsageFault) instead of silently corrupting memory, but core1 still stops. (The protocol *state*, e.g. `ScHsmState`, lives in BSS via `DISPATCHER_CELL`, not on this stack.)

**Measured** (2026-10, debug, pico2_4m and SD boards, worst path): dispatcher_loop 20.6 KB → dispatch_with_store 8.2 KB → Piv::process_apdu_with_store 11.2 KB → route 7.1 KB → PIV put_data::handle_with_store 20.6 KB → save_key / fetch_key chain ~20 KB ≈ **89 KB of 128 KB**. Before the synchronous `Core1KeyStore` (which removed a queue of by-value `KeyObject`s) it was ~123 KB.  RSA GENERATE from the key pool: … → route_handler 4.1 KB → generate_keypair::handle 9.1 KB → Engine::take_pooled 6.3 KB → PoolRegion::get_key 12.1 KB → KeyObject::decrypt chain ~9.8 KB ≈ **86 KB**; the idle-time pool slice ≈ 31 KB.  The display snapshot (2026-10, display redesign) added 8 B to dispatcher_loop (20,576 B); its `display_end → refresh_display_facts (0.6 KB) → member::count (9.0 KB) → fetch_key` branch stays far below the dispatch path.

**Re-measure** after adding large locals or a deeper call path:
```sh
cargo build -p pico2hsm-firmware --no-default-features --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519
arm-none-eabi-objdump -d --no-show-raw-insn -C target/thumbv8m.main-none-eabihf/debug/pico2hsm \
  | grep -A6 '<pico2hsm::dispatcher_loop>:' | grep 'sub.*sp'   # frame size per function
```
Keep heavy buffers off the stack (`Zeroizing` helpers like `security::zeroize::key_buf` keep secrets wiped but still use stack), and never queue `KeyObject`s by value.

**Core1 synchronous loop**: Core1 no longer runs an Embassy executor — it uses a
synchronous `dispatcher_loop()` with `wfe`/`sev` for cooperative sleep/wake.
This eliminated ~61 KB of async state machine BSS overhead, giving core0 ~188 KB
of stack space (ample for the ~67 KB debug-build poll frame).

### Hardware watchdog

`firmware/src/watchdog.rs`; armed in `main()` right after `embassy_rp::init`
(8 s, paused while a debugger halts either core).  Only core0 feeds: the
`watchdog_feeder` task every 1 s while core1 is idle, making progress
(heartbeat or request/reply counters moved within 30 s) or under
`WatchdogSuppressGuard`; and `watchdog::progress()` in every flash/SD sector
write/erase and key load, for blocking storage work on core0.

- Code on core0 that blocks the executor for more than a few seconds must
  call `watchdog::progress()` as it goes (or the chip resets ~8 s in).
- Core1 work longer than 30 s must bump `WATCHDOG_HEARTBEAT` (RNG calls and
  storage ops do) or hold a `WatchdogSuppressGuard`.  RSA keygen no longer
  needs the guard: the sliced generator bumps the heartbeat every unit.
- Send work to core1 only via `send_to_core1()`, and count each reply
  (`note_core1_response`), or the feeder's busy/idle accounting drifts.
- Reset with `watchdog::reset_now(cause)`, not `SCB::sys_reset()` (on
  RP2350 only a processor warm reset); don't use
  `embassy_rp::watchdog::Watchdog::start` (RP2040 `PSM.WDSEL` layout, leaves
  both cores out on RP2350).
- The boot log's first lines say why the last reset happened.  A watchdog
  reset also restarts the debug logic, so the probe-rs RTT stream may stop:
  re-run `build-all-debug.sh`.  If probe-rs exits while RTT is in blocking
  mode and core0 stalls on a full RTT buffer, the watchdog now reboots the
  board instead of it hanging.
- `debug`-feature test hooks (SC-HSM selected): `80 FE 10 00` wedges core1,
  `80 FE 11 00` wedges core0 after replying, `80 FE 12 00` resets now.

### CCID timeout on long operations (P-384 / P-521 / K-256 sign)

**Symptom**: pcscd drops the connection mid-operation with "IFD_COMMUNICATION_ERROR"; sign tests fail without reaching the crypto result.

**Cause**: pcscd's default XfrBlock timeout is ~2.5 s. P-384/P-521 ECDSA on a Cortex-M33 without hardware ECC takes longer than that.

**Fix**: Core0 sends a `RDR_to_PC_DataBlock` time-extension message (bStatus=0x80, bError=0x01) every 1.5 s while waiting for core1 to finish. Implemented in `firmware/src/transport/ccid.rs` (`send_time_extension`) and called from the select-loop in `run_pico2_board` / `run_one_board` / `run_geek_board` in `main.rs`.

### Feature flags and default features

`Cargo.toml` sets `default = ["rp2350_one_4m", "rsa", "applet-piv", "applet-openpgp-curve25519"]`. Using `--features X` adds to the defaults, which causes multiple conflicting board features to be active simultaneously and will fail to compile. Always use `--no-default-features` when specifying a non-default board:

```sh
cargo check --no-default-features --features rp2350_geek_16m
```

The debug script handles this correctly automatically.

### defmt log levels

`DEFMT_LOG=trace` must be set **at compile time** for trace/debug log output to survive optimisation. The `build-all-debug.sh` script sets this. If RTT output seems sparse or missing levels, rebuild via the script rather than with a bare `cargo build`.
