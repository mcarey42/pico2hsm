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
       └─ ScHsm::process_apdu()      [protocol/sc_hsm/mod.rs]
            └─ ScHsm::dispatch()
                 └─ <command>::handle()   [protocol/sc_hsm/commands/]
```

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
