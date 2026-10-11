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

If multiple pico2hsm devices are connected, use `OPENSC_DEFAULT_READER=N ./run_tests.sh` to target a specific reader (e.g. `N=1` for the second reader). Run `opensc-tool --list-readers` to see which index is which.

If `probe-rs` reports "interface is busy (errno 16)", a previous probe-rs process is still holding the USB device:

```sh
pkill -9 -f "probe-rs"
```

## Architecture overview

**Concurrency model** (RP2350 dual-core):
- **Core0** — Embassy async executor: USB device driver + CCID transport loop, plus the hardware-watchdog feeder task. Sends APDUs to core1 via `APDU_CHANNEL` and waits for responses on `RESP_CHANNEL`.
- **Core1** — Synchronous `dispatcher_loop()`: no Embassy executor.  Sleeps via ARM `wfe` (Wait For Event) while idle; woken by core0 via `sev` (Send Event) after each channel send.  Calls `blocking_receive()`/`blocking_send()` on the shared channels using `try_receive()`/`try_send()`.

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

**Flash / RAM budget (release, all applets + RSA + curve25519, v0.9.9):**

| Board | Flash | RAM | SRAM % |
|---|---|---|---|
| Pico 2 4MB | 522 KB | 398 KB | 77% |
| RP2350-One 4MB | 529 KB | 398 KB | 77% |
| RP2350-Geek 16MB/SDCard | 539 KB | 450 KB | 87% |
| Waveshare LCD 16MB | 539 KB | 449 KB | 87% |
| Waveshare LCD SDCard | 542 KB | 442 KB | 85% |

Flash is not a concern.  RAM is the metric to watch; the 128 KB core1 stack and the
display framebuffers (48 KB Geek, 83 KB Waveshare LCD, RGB444) dominate on display boards.
Non-display boards have ~90 KB free SRAM; Waveshare LCD 16MB has ~39 KB free.

**Storage namespace — implemented:**

All three applets share one flash keystore.  Ownership is encoded in the `KeyId` u32
via the `applet_id` byte (bits 23–16); SC-HSM `INITIALIZE` calls
`wipe_by_owner(AppletId::ScHsm)` and leaves PIV and OpenPGP keys untouched.

`KeyId` u32 encoding (in `pico2hsm-core/src/key.rs`):
```
bits 31–24: partition_id  (u8)  — 0 = default partition
bits 23–16: applet_id     (u8)  — 0=SC-HSM, 1=PIV, 2=OpenPGP
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

**rp2350_geek — ST7789 240×135 on SPI1 (GPIO8/9/10/11/12/25)**
- `St7789StatusDisplay::new(spi1)` steals DC=GPIO8, CS=GPIO9, RST=GPIO12,
  BL=GPIO25 via `AnyPin::steal()`.  `main.rs` must not claim those four pins.
- Fills entire screen with a solid RGB444 colour per `LedStatus` variant.
- Delays use `cortex_m::asm::delay` (cycle-counted; no embassy-time needed).

**waveshare_rp2350_lcd — ST7789V3 320×172 landscape on SPI0 + WS2812B on GPIO22**
- LCD driven via async `init_lcd()` / `update_status_display()` free functions.
- MADCTL=0xA0 (MY+MV): landscape 320×172, 180°-corrected from broken 0x60 attempt.
- RASET 34–205 (not 0–171): physical GRAM columns 34–205 map to landscape height.
- Full 320×172 RGB444 framebuffer (83 KB in BSS); `ScreenLayout::waveshare_320x172()`.
- Both LCD colour and WS2812B GRB are set simultaneously via `status_to_colors()`.

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
- **Reserved SC-HSM key refs 0xFC–0xFF** (peer record, DKEK, device key, PIN
  record) are refused by every user key command (`targets_reserved_slot`).
- **The DKEK** is persisted at 0xFD, only replaced by an authenticated,
  SO-PIN, enrolled-peer exchange, never overwritten while set.
- **Secrets are wiped in place.** Zeroize before moving or dropping; use
  `security::zeroize::key_buf` for fixed key buffers; `mem::replace` /
  assigning `None` does not wipe the old bytes.

## Known pitfalls

### Core1 stack overflow

**Symptom**: APDU is received and logged by core0 (`APDU XX XX XX XX len=N`), time extensions fire every 1.5 s, but the command never completes; after ~30 s core0 sends 6F00 and resets the chip through the hardware watchdog (next boot logs `reset: WATCHDOG RESET: core1 stuck during an APDU`).

**Cause**: core1 runs the whole dispatch chain on its own 128 KB stack (`CORE1_STACK` in `firmware/src/main.rs`). Large stack temporaries — `Vec<u8, 4096>` response buffers, `KeyObject`s (~3 KB), 4 KB flash sector buffers, PKCS#1 DER buffers — add up across `dispatcher_loop → Dispatcher::dispatch_with_store → <protocol>::process_apdu_with_store → route_with_store → handler → store`. MSPLIM is set at the stack base, so an overflow faults (UsageFault) instead of silently corrupting memory, but core1 still stops. (The protocol *state*, e.g. `ScHsmState`, lives in BSS via `DISPATCHER_CELL`, not on this stack.)

**Measured** (2026-10, debug, pico2_4m and SD boards, worst path): dispatcher_loop 20.6 KB → dispatch_with_store 8.2 KB → Piv::process_apdu_with_store 11.2 KB → route 7.1 KB → PIV put_data::handle_with_store 20.6 KB → save_key / fetch_key chain ~20 KB ≈ **89 KB of 128 KB**. Before the synchronous `Core1KeyStore` (which removed a queue of by-value `KeyObject`s) it was ~123 KB.

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
  storage ops do) or hold a `WatchdogSuppressGuard`.
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
