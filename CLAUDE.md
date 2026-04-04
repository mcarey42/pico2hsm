# pico2hsm — Claude Code Guide

## Build, flash, and debug

Always use the debug script to build and flash firmware. Do not run `cargo build` directly.

```sh
./build-all-debug.sh pico2_4m
```

This script:
- Builds with `DEFMT_LOG=trace` (required for defmt log output to survive optimisation)
- Uses the debug profile so `#[cfg(debug_assertions)]` sentinels are active
- Flashes via `probe-rs run --chip RP235x`
- Streams RTT output to the terminal until Ctrl+C

The connected hardware is a **Raspberry Pi Pico 2 (pico2_4m feature)** with a Debugprobe (CMSIS-DAP) on the SWD port.

To run the integration test suite against the flashed device:

```sh
./run_tests.sh
```

Start `build-all-debug.sh` in the background first (it blocks on RTT streaming), then wait ~5 s for USB re-enumeration before running `run_tests.sh`.

If `probe-rs` reports "interface is busy (errno 16)", a previous probe-rs process is still holding the USB device:

```sh
pkill -9 -f "probe-rs"
```

## Architecture overview

**Concurrency model** (RP2350 dual-core):
- **Core0** — Embassy async executor: USB device driver + CCID transport loop. Sends APDUs to core1 via `APDU_CHANNEL` and waits for responses on `RESP_CHANNEL`.
- **Core1** — Embassy async executor: `dispatcher_task()` receives APDUs, calls the synchronous `Dispatcher::dispatch()` chain, sends responses back.

Both channels use RP2350 hardware spinlocks (29 and 30) for SMP-safe cross-core signalling.

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

**Storage namespace — design constraint for any new applet:**

All three applets share one flash keystore.  Each `KeyObject` must carry an `owner` tag
so that SC-HSM `INITIALIZE` only wipes SC-HSM-owned slots, not PIV or OpenPGP keys.
Reserved key ID ranges (to be enforced in `storage/keystore.rs`):

| Key ID range | Owner |
|---|---|
| `0x01–0x7F` | SC-HSM |
| `0x80–0x8F` | PIV (9A→0x80, 9C→0x81, 9D→0x82, 9E→0x83, retired→0x84–0x8F) |
| `0x90–0x92` | OpenPGP (SIG→0x90, DEC→0x91, AUTH→0x92) |

PIN storage in flash likewise needs per-applet slots.  **This namespace design must be
implemented before any PIV or OpenPGP command handler is written.**

## Known pitfalls

### Core1 stack overflow (silent hang)

**Symptom**: APDU is received and logged by core0 (`APDU XX XX XX XX len=N`), time extensions fire every 1.5 s, but no log lines from the command handler ever appear — not even the first `defmt::info!` at the top of the function. The command never completes.

**Cause**: `ScHsmState` holds `ef_files: Vec<EfEntry, 16>` where each `EfEntry` contains `Vec<u8, 2048>` inline — 32 KB of fixed EF storage alone. Combined with multiple `Vec<u8, 4096>` response buffers allocated as stack temporaries across the `Dispatcher → ScHsm::process_apdu → ScHsm::dispatch → handle()` call chain (~12–16 KB), the total easily exceeds the core1 stack limit. On Cortex-M33 without MPU guard pages this is a **silent** overflow: no panic, no fault, core1 just runs garbage.

**Fix**: Increase `CORE1_STACK` in `firmware/src/main.rs`:
```rust
// Was Stack<65536> — not enough once EF storage + response bufs are counted
static mut CORE1_STACK: Stack<131072> = Stack::new();
```

**Rule of thumb**: Any time a new large static allocation is added to `ScHsmState` (keys, files, buffers), re-evaluate core1 stack headroom. The RP2350 has 520 KB SRAM total; current BSS is ~210 KB, so there is headroom to grow further if needed.

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
