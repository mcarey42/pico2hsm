# pico2hsm — Claude Code Guide

## Build, flash, and debug

Always use the debug script to build and flash firmware. Do not run `cargo build` directly.

```sh
./build-all-debug.sh pico2_4m
```

Valid board arguments for the Pico 2: `pico2_4m` (bare board).

This script:
- Builds with `DEFMT_LOG=trace` (required for defmt log output to survive optimisation)
- Uses the debug profile so `#[cfg(debug_assertions)]` sentinels are active
- Includes `applet-piv` and `applet-openpgp` features (required for PIV/OpenPGP integration tests)
- **Signs the ELF with `picotool seal --hash --sign` if `ec_firmware_signing_key.pem` is present**
  - Signed output → `dist/pico2hsm-<feat>-debug-signed.elf`
  - OTP configuration → `dist/pico2hsm-<feat>-debug-otp.json`
  - If no key is present, flashes unsigned (warns but continues)
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
- **Core0** — Embassy async executor: USB device driver + CCID transport loop. Sends APDUs to core1 via `APDU_CHANNEL` and waits for responses on `RESP_CHANNEL`.
- **Core1** — Embassy async executor: `dispatcher_task()` receives APDUs, calls the synchronous `Dispatcher::dispatch()` chain, sends responses back.

Both channels use RP2350 hardware spinlocks (29 and 30) for SMP-safe cross-core signalling.

**CDC serial logger**: Core0 runs a `drain_one()` task that forwards buffered log lines to `/dev/ttyACMx`. `drain_one()` checks DTR before writing; if no terminal has `/dev/ttyACMx` open, the line is dropped silently (no CCID stall).

**APDU dispatch chain** (all on core1, synchronous):
```
dispatcher_task()
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

**Flash / RAM budget (release, pico2_4m):**
- Current SC-HSM only: 366 KB flash / 377 KB RAM (18% / 73% of device limits)
- + PIV (3DES new, all curves already in): +18–27 KB flash / +2 KB RAM
- + OpenPGP NIST-ECC only: +10–15 KB flash / +2 KB RAM
- + `applet-openpgp-curve25519` (curve25519-dalek, entirely new): +45–60 KB flash / 0 KB RAM
- Worst case all three + curve25519: ~476 KB flash (23%) / ~383 KB RAM (74%)

Flash is not a concern.  RAM is the metric to watch; the 128 KB core1 stack and the
SC-HSM key caches dominate; applet state structs are small by comparison.
Current BSS budget (waveshare_rp2350_lcd_16m, all applets): ~308 KB / 520 KB (59%).

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
`KeyId::openpgp(slot)`.  Flash magic `"P2K2"` surfaces old pre-u32 data as
incompatible (re-INITIALIZE required after firmware update from older builds).

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
- Fills entire screen with a solid RGB565 colour per `LedStatus` variant.
- Delays use `cortex_m::asm::delay` (cycle-counted; no embassy-time needed).

**waveshare_rp2350_lcd — ST7789V3 320×172 landscape on SPI0 + WS2812B on GPIO22**
- LCD driven via async `init_lcd()` / `update_status_display()` free functions.
- MADCTL=0xA0 (MY+MV): landscape 320×172, 180°-corrected from broken 0x60 attempt.
- RASET 34–205 (not 0–171): physical GRAM columns 34–205 map to landscape height.
- Full 320×172 RGB565 framebuffer (110 KB in BSS); `ScreenLayout::waveshare_320x172()`.
- Both LCD colour and WS2812B GRB are set simultaneously via `status_to_colors()`.

## Known pitfalls

### Core1 stack overflow (silent hang)

**Symptom**: APDU is received and logged by core0 (`APDU XX XX XX XX len=N`), time extensions fire every 1.5 s, but no log lines from the command handler ever appear — not even the first `defmt::info!` at the top of the function. The command never completes.

**Cause**: `ScHsmState` holds `ef_files: Vec<EfEntry, 16>` where each `EfEntry` contains `Vec<u8, 2048>` inline — 32 KB of fixed EF storage alone. Combined with multiple `Vec<u8, 4096>` response buffers allocated as stack temporaries across the `Dispatcher → ScHsm::process_apdu → ScHsm::dispatch → handle()` call chain (~12–16 KB), the total easily exceeds the core1 stack limit. On Cortex-M33 without MPU guard pages this is a **silent** overflow: no panic, no fault, core1 just runs garbage.

**Fix**: Set `CORE1_STACK` in `firmware/src/main.rs` to 128 KB.  Measured peak usage
is ~65 KB (38 KB ScHsmState inline storage + 16 KB dispatch-chain temporaries),
giving ~2× headroom:
```rust
// 128 KB — ~2× measured peak of ~65 KB.  Do not reduce below 96 KB.
static mut CORE1_STACK: Stack<131072> = Stack::new();
```

**Rule of thumb**: Any time a new large static allocation is added to `ScHsmState` (keys, files, buffers), re-evaluate core1 stack headroom. The RP2350 has 520 KB SRAM total; current BSS is ~308 KB (waveshare_rp2350_lcd_16m with all applets), so headroom remains if needed.

### CCID timeout on long operations (P-384 / P-521 / K-256 sign)

**Symptom**: pcscd drops the connection mid-operation with "IFD_COMMUNICATION_ERROR"; sign tests fail without reaching the crypto result.

**Cause**: pcscd's default XfrBlock timeout is ~2.5 s. P-384/P-521 ECDSA on a Cortex-M33 without hardware ECC takes longer than that.

**Fix**: Core0 sends a `RDR_to_PC_DataBlock` time-extension message (bStatus=0x80, bError=0x01) every 1.5 s while waiting for core1 to finish. Implemented in `firmware/src/transport/ccid.rs` (`send_time_extension`) and called from the select-loop in `run_pico2_board` / `run_one_board` / `run_geek_board` in `main.rs`.

### Feature flags and default features

`Cargo.toml` sets `default = ["rp2350_one_4m"]`. Using `--features X` adds to the defaults, which causes multiple conflicting board features to be active simultaneously and will fail to compile. Always use `--no-default-features` when specifying a non-default board:

```sh
cargo check --no-default-features --features rp2350_geek_16m
```

The debug script handles this correctly automatically.

### defmt log levels

`DEFMT_LOG=trace` must be set **at compile time** for trace/debug log output to survive optimisation. The `build-all-debug.sh` script sets this. If RTT output seems sparse or missing levels, rebuild via the script rather than with a bare `cargo build`.
