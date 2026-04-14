# Waveshare RP2350-One — Hardware Reference

This document is the definitive hardware reference for the Waveshare RP2350-One
board as used in the pico2hsm firmware.  Pin assignments, bus topology, WS2812B
LED driver details, external SD card recommendations, and build instructions for
all firmware variants are covered.

---

## 1. Board Overview

| Attribute              | Value                                                         |
|------------------------|---------------------------------------------------------------|
| MCU                    | RP2350A (Cortex-M33 × 2 + Hazard3 RISC-V × 2, up to 150 MHz)|
| SRAM                   | 520 KB on-chip                                                |
| Flash — 4 MB variant   | 4 MB QSPI NOR flash (W25Q32JV or equivalent)                 |
| Flash — 16 MB variant  | 16 MB QSPI NOR flash (W25Q128JV or equivalent)               |
| Form factor            | USB-A dongle with castellated edge pads                       |
| USB connector          | PCB Type-A male (plug directly into host port)                |
| Status LED             | Single WS2812B RGB LED on GPIO 16                             |
| GPIO count             | 29 total (20 via edge pinout; 9 via solder castellations)     |
| SD card slot           | None built-in (external SPI module required)                  |
| SPI buses in firmware  | SPI0 (keystore flash, 40 MHz) + SPI1 (RAID-1 mirror, 40 MHz) |
| PIO state machines     | 12 total; PIO0 SM0 claimed by WS2812B driver                  |
| ADC channels           | 4 × 12-bit                                                    |
| PWM channels           | 16 controllable                                               |
| Power supply           | 5 V via USB VBUS; 3.3 V regulated on-board                    |
| I/O voltage            | 3.3 V (not 5 V tolerant)                                      |

The RP2350-One is a compact USB-A dongle-style development board.  Its PCB
Type-A male connector allows it to plug directly into any USB-A host port
without a cable.  The castellated edge pads allow it to be reflow-soldered onto
a carrier PCB.

The RP2350A die integrates two ARM Cortex-M33 cores and two Hazard3 RISC-V
cores; only the two Cortex-M33 cores are used by this firmware.  Core0 runs the
Embassy async USB/CCID transport loop; Core1 runs the synchronous APDU
dispatcher.

Two flash size variants are supported:

| Variant           | Feature flag      | Flash size | Flash size (hex) |
|-------------------|-------------------|------------|------------------|
| RP2350-One 4 MB   | `rp2350_one_4m`   | 4 MB       | 0x00400000       |

`rp2350_one_4m` is the **default** Cargo feature.

**Product page:** https://www.waveshare.com/rp2350-one.htm  
**Waveshare Wiki:** https://www.waveshare.com/wiki/RP2350-One

---

## 2. Full GPIO Pinout

The RP2350A exposes GPIO 0–29 (30 pins total).  The table below lists every
GPIO, its decimal number, its hex number, the RP2350A hardware alternate
functions, and its assignment in the pico2hsm `rp2350_one` firmware build.

| GPIO (dec) | GPIO (hex) | RP2350A alternate functions              | pico2hsm assignment                              |
|------------|-----------|------------------------------------------|--------------------------------------------------|
|  0         | 0x00       | UART0 TX / SPI0 RX / I2C0 SDA           | — (free)                                         |
|  1         | 0x01       | UART0 RX / SPI0 CSn / I2C0 SCL          | — (free)                                         |
|  2         | 0x02       | SPI0 SCK / I2C1 SDA                     | — (free)                                         |
|  3         | 0x03       | SPI0 MOSI / I2C1 SCL                    | — (free)                                         |
|  4         | 0x04       | SPI0 MISO / UART1 TX                    | — (free)                                         |
|  5         | 0x05       | SPI0 CSn / UART1 RX                     | — (free)                                         |
|  6         | 0x06       | SPI0 SCK / UART1 CTS                    | — (free)                                         |
|  7         | 0x07       | SPI0 MOSI / UART1 RTS                   | — (free)                                         |
|  8         | 0x08       | SPI1 RX / I2C0 SDA                      | — (free)                                         |
|  9         | 0x09       | SPI1 CSn / I2C0 SCL                     | **SPI1 CS[0]** — mirror flash chip 0             |
| 10         | 0x0A       | SPI1 SCK / I2C1 SDA                     | **SPI1 SCK**   — mirror flash bus clock          |
| 11         | 0x0B       | SPI1 MOSI / I2C1 SCL                    | **SPI1 MOSI**  — mirror flash data out           |
| 12         | 0x0C       | SPI1 MISO / UART0 TX                    | **SPI1 MISO**  — mirror flash data in            |
| 13         | 0x0D       | SPI1 CSn / UART0 RX                     | **SPI1 CS[1]** — mirror flash chip 1             |
| 14         | 0x0E       | SPI1 CSn / UART0 CTS                    | **SPI1 CS[2]** — mirror flash chip 2             |
| 15         | 0x0F       | SPI1 CSn / UART0 RTS                    | **SPI1 CS[3]** — mirror flash chip 3             |
| 16         | 0x10       | SPI0 RX / PIO0                          | **WS2812B DIN** (PIO0 SM0 side-set output)       |
| 17         | 0x11       | SPI0 CSn                                | **SPI0 CS[0]** — keystore flash chip 0           |
| 18         | 0x12       | SPI0 SCK                                | **SPI0 SCK**   — keystore flash bus clock        |
| 19         | 0x13       | SPI0 MOSI                               | **SPI0 MOSI**  — keystore flash data out         |
| 20         | 0x14       | SPI0 MISO                               | **SPI0 MISO**  — keystore flash data in          |
| 21         | 0x15       | SPI0 CSn                                | **SPI0 CS[1]** — keystore flash chip 1           |
| 22         | 0x16       | SPI0 CSn                                | **SPI0 CS[2]** — keystore flash chip 2           |
| 23         | 0x17       | (USB D+ on-chip routing / GPIO)         | — (not broken out on this board)                 |
| 24         | 0x18       | (USB D− on-chip routing / GPIO)         | — (not broken out on this board)                 |
| 25         | 0x19       | SPI1 CSn / I2C0 SDA                     | — (free)                                         |
| 26         | 0x1A       | SPI0 CSn / ADC0                         | **SPI0 CS[3]** — keystore flash chip 3           |
| 27         | 0x1B       | ADC1 / I2C1 SDA                         | — (free)                                         |
| 28         | 0x1C       | ADC2 / I2C1 SCL                         | — (free)                                         |
| 29         | 0x1D       | ADC3 / VBUS sense                       | — (VBUS sensing; not a general-purpose output)   |

**Notes:**
- GPIO 16 is driven exclusively by PIO0 SM0 after `Ws2812Led::new()` runs.
  It must not be configured as a regular GPIO output or claimed by any other
  peripheral in the same firmware build.
- GPIO 26 is also ADC channel 0.  If ADC use is needed, SPI0 CS[3] must be
  reassigned to another free GPIO and `SPI0_CS` updated in
  `firmware/src/board/rp2350_one.rs`.
- GPIOs 0–3 and 8 are fully free and available for UART, I2C, or GPIO
  expansion.

---

## 3. WS2812B LED

### 3.1 Circuit

The RP2350-One has a single WS2812B RGB LED connected to GPIO 16.  The LED
data input is driven directly from GPIO 16 with no level shifter required:
the RP2350A output is 3.3 V, and the WS2812B Vih threshold at 3.3 V supply
is 0.7 × 3.3 V = 2.31 V, which is satisfied.

```
GPIO 16 (RP2350A) ──────────────────────> DIN (WS2812B)
3.3 V supply       ─── 100 nF bypass ──> VCC (WS2812B)
GND                ────────────────────> GND (WS2812B)
```

### 3.2 PIO Resource Allocation

| Resource      | Assignment                                                    |
|---------------|---------------------------------------------------------------|
| PIO block     | PIO0                                                          |
| State machine | SM0 (index 0)                                                 |
| GPIO          | GPIO 16 (configured as PIO0 side-set output)                  |
| DMA           | Not used — single pixel fits in TX FIFO; synchronous push     |
| Interrupt     | PIO0_IRQ_0 enabled by `Pio::new()`; no `inte()` bits set;     |
|               | interrupt never fires in practice (sync push, not async)      |

PIO0 and GPIO 16 are **stolen** via `unsafe { PIO0::steal(); PIN_16::steal() }`
inside `Ws2812Led::new()`, which is called from `Rp2350OneBoard::new()`.  In
`run_one_board()` in `main.rs`, `p.PIO0` and `p.PIN_16` are deliberately left
unclaimed in the Embassy peripherals struct so the steal is safe.

The `Common<PIO0>` and `LoadedProgram<PIO0>` handles are stored in
`StaticCell`s so their destructors never run and PIO0 instruction memory
remains valid for the firmware lifetime.

### 3.3 PIO Program

The WS2812B bit-bang program is assembled inline in
`firmware/src/board/rp2350_one.rs` (adapted from
`embassy_rp::pio_programs::ws2812`).  It uses side-set mode: the side-set bit
directly controls GPIO 16 at instruction granularity for cycle-accurate timing.

Timing constants used in the assembler: T1=2, T2=5, T3=3 cycles per bit phase.

```
; WS2812B PIO program — T1=2, T2=5, T3=3 cycles/phase
; side-set bit = output level on GPIO 16

                          side 0  ; set PINDIRS = output (run once at start)
wrap_target:
    OUT X, 1     [T3-1]   side 0  ; stop phase:  de-assert; shift next bit into X
    JMP X==0 do_zero [T1-1] side 1 ; start phase: assert;   branch if data bit = 0
    JMP wrap_target [T2-1] side 1  ; data=1:      stay high through T2; loop
do_zero:
    NOP          [T2-1]   side 0  ; data=0:      go low through T2
wrap_source:
```

### 3.4 Bit Timing

PIO clock = 150 MHz system clock ÷ 18.75 = **8.0 MHz** (250 ns per cycle).

| Symbol              | PIO cycles | Duration     | WS2812B specification    |
|---------------------|-----------|--------------|--------------------------|
| T0H (zero, high)    | 2          | **250 ns**   | 220–380 ns (within spec) |
| T0L (zero, low)     | 8          | **1 000 ns** | 580–1 000 ns (within spec)|
| T1H (one, high)     | 7          | **875 ns**   | 580–1 000 ns (within spec)|
| T1L (one, low)      | 3          | **375 ns**   | 220–420 ns (within spec) |
| Bit period          | 10         | **1 250 ns** | = 800 kHz                |

The clock divider is computed at runtime from `clk_sys_freq()` using
`fixed::types::U24F8` arithmetic:

```
divider = (sys_clk_khz) / (FREQ_HZ / 1_000 × CYCLES_PER_BIT)
        = (150_000 kHz) / (800 kHz × 10)
        = 18.75
```

### 3.5 Reset Period

After each pixel write the driver waits for the WS2812B latch reset:

| Constant           | Value            | Derivation                              |
|--------------------|------------------|-----------------------------------------|
| `RESET_US`         | 100 µs           | ≥ 50 µs spec minimum + 50 µs margin    |
| `RESET_CYCLES`     | 15 000           | 150 MHz × 100 µs = 15 000 CPU cycles   |

`cortex_m::asm::delay(15_000)` busy-waits exactly 15 000 CPU cycles.

### 3.6 GRB Wire Colour Order

The WS2812B uses **GRB** byte order on the wire (Green byte first, then Red,
then Blue).  The PIO TX FIFO word is packed as:

```
bit 31                       bit 0
 ┌────────┬────────┬────────┬────────┐
 │ Green  │  Red   │  Blue  │  0x00  │
 │[31:24] │[23:16] │[15:8]  │[7:0]   │
 └────────┴────────┴────────┴────────┘
```

In Rust:
```rust
let grb: u32 = (u32::from(color.g) << 24)
             | (u32::from(color.r) << 16)
             | (u32::from(color.b) <<  8);
```

The PIO shift register is configured left-shift, auto-fill, threshold=24, so
only bits [31:8] (the 24 colour bits) are transmitted; the low byte is ignored.

### 3.7 Status Colour Mapping

| `LedStatus`     | R (dec) | G (dec) | B (dec) | Hex packed (GRB) | Appearance      |
|-----------------|---------|---------|---------|------------------|-----------------|
| `Off`           |   0     |   0     |   0     | `0x00000000`     | Off             |
| `Ready`         |   0     |  32     |   0     | `0x20000000`     | Dim green       |
| `Busy`          |   0     |   0     |  32     | `0x00002000`     | Dim blue        |
| `Error`         |  32     |   0     |   0     | `0x00200000`     | Dim red         |
| `Degraded`      |  16     |  16     |   0     | `0x10100000`     | Yellow (dim)    |
| `Resyncing`     |   0     |  16     |  16     | `0x10001000`     | Cyan (dim)      |
| `WaitingForPin` |   0     |   0     |  64     | `0x00004000`     | Bright blue     |

Values are 8-bit (0–255).  All colours are kept well below full brightness to
reduce power draw from the USB 100 mA default budget and avoid glare.

### 3.8 Synchronous Write Implementation

`LedController::set_status()` calls `Ws2812Led::set_color()`, which is fully
synchronous (no `async`, no DMA):

1. Pack `(r, g, b)` into a `u32` in GRB order at bits [31:8].
2. Spin on `StateMachineTx::full()` until the TX FIFO has space
   (almost always immediate; SM drains the previous word in ~30 µs).
3. Push the packed GRB word to SM0's TX FIFO — PIO shifts 24 bits out at
   800 kHz over approximately 30 µs.
4. Call `cortex_m::asm::delay(RESET_CYCLES)` — busy-waits 100 µs at 150 MHz
   for the WS2812B reset period.

Total blocking time per LED update: **~130 µs** (30 µs transmit + 100 µs reset).

---

## 4. SPI0 Bus — Keystore Flash

SPI0 is the primary keystore flash bus.  Up to four W25Q-series or IS25-series
SPI NOR flash chips can be wired in parallel with independent software-driven
chip-select lines.

| Signal  | GPIO (dec) | GPIO (hex) | Direction | Note                          |
|---------|------------|-----------|-----------|-------------------------------|
| SCK     | 18         | 0x12       | Output    | SPI0 clock                    |
| MOSI    | 19         | 0x13       | Output    | SPI0 data out (controller→flash) |
| MISO    | 20         | 0x14       | Input     | SPI0 data in  (flash→controller) |
| CS[0]   | 17         | 0x11       | Output    | Keystore chip 0, active-low   |
| CS[1]   | 21         | 0x15       | Output    | Keystore chip 1, active-low   |
| CS[2]   | 22         | 0x16       | Output    | Keystore chip 2, active-low   |
| CS[3]   | 26         | 0x1A       | Output    | Keystore chip 3, active-low   |

**Bus frequency:** 40 MHz (`SPI_FREQ_HZ = 40_000_000`)  
**SPI mode:** Mode 0 — CPOL=0 (idle low), CPHA=0 (capture on first transition)  
**Embassy type alias:** `Rp2350OneSpi0 = Spi<'static, SPI0, Blocking>`

Source constants (`firmware/src/board/rp2350_one.rs`):

```rust
pub const SPI0_SCK:  u8    = 18;
pub const SPI0_MOSI: u8    = 19;
pub const SPI0_MISO: u8    = 20;
pub const SPI0_CS:   [u8; 4] = [17, 21, 22, 26];
```

The storage layer drives the CS GPIOs as plain register-write outputs,
asserting exactly one chip select before each SPI transaction and de-asserting
immediately after.  All unselected CS lines are held high (inactive).

---

## 5. SPI1 Bus — RAID-1 Mirror Flash

SPI1 is dedicated to the RAID-1 mirror flash array.  Unlike the RP2350-Geek
board where SPI1 is shared with an LCD, on the RP2350-One SPI1 carries only
flash traffic.  Up to four chips can be attached with independent CS lines.

| Signal  | GPIO (dec) | GPIO (hex) | Direction | Note                          |
|---------|------------|-----------|-----------|-------------------------------|
| SCK     | 10         | 0x0A       | Output    | SPI1 clock                    |
| MOSI    | 11         | 0x0B       | Output    | SPI1 data out                 |
| MISO    | 12         | 0x0C       | Input     | SPI1 data in                  |
| CS[0]   |  9         | 0x09       | Output    | Mirror flash chip 0, active-low |
| CS[1]   | 13         | 0x0D       | Output    | Mirror flash chip 1, active-low |
| CS[2]   | 14         | 0x0E       | Output    | Mirror flash chip 2, active-low |
| CS[3]   | 15         | 0x0F       | Output    | Mirror flash chip 3, active-low |

**Bus frequency:** 40 MHz  
**SPI mode:** Mode 0 — CPOL=0, CPHA=0  
**Embassy type alias:** `Rp2350OneSpi1 = Spi<'static, SPI1, Blocking>`

Source constants (`firmware/src/board/rp2350_one.rs`):

```rust
pub const SPI1_SCK:  u8    = 10;
pub const SPI1_MOSI: u8    = 11;
pub const SPI1_MISO: u8    = 12;
pub const SPI1_CS:   [u8; 4] = [9, 13, 14, 15];
```

### Current Status (v0.3.0)

As of v0.3.0, the SPI buses are constructed in `run_one_board()` and stored in
`Rp2350OneBoard` but not yet forwarded to the `SpiFlash` storage layer.  The
keystore runs in degraded mode (no physical chips attached).  This is a known
TODO pending a board struct refactor — the GPIO topology above is the intended
final wiring.  See the TODO comment in `firmware/src/main.rs` →
`run_one_board()` for the full explanation.

---

## 6. Feature Flags

### 6.1 Board Variant Flags

| Feature flag              | Flash  | RAID-1 SPI1 | Notes                    |
|---------------------------|--------|-------------|--------------------------|
| `rp2350_one_4m`           | 4 MB   | yes         | **Default** in Cargo.toml |

Always pass `--no-default-features` when selecting a non-default board flag to
prevent conflicting features from being simultaneously active (see `CLAUDE.md`
§ "Feature flags and default features").

### 6.2 Applet Feature Flags (composable with any board flag)

| Feature flag                 | Applet / capability added              |
|------------------------------|----------------------------------------|
| *(always active)*            | SC-HSM (AID `E8 2B 06 01 04 01 81 C3 1F 02 01`) |
| `applet-piv`                 | PIV NIST SP 800-73-4 (AID `A0 00 00 03 08 00 00 10 00 01 00`) |
| `applet-openpgp`             | OpenPGP Card 3.4 NIST ECC              |
| `applet-openpgp-curve25519`  | Adds Ed25519 + X25519 to OpenPGP       |
| `rsa`                        | RSA-2048 and RSA-4096 keygen + sign    |

### 6.3 Flash / RAM Budget (release, rp2350_one_4m)

| Configuration                          | Flash    | RAM      |
|----------------------------------------|----------|----------|
| SC-HSM only (default)                  | ~366 KB  | ~377 KB  |
| + PIV                                  | ~384 KB  | ~379 KB  |
| + OpenPGP (NIST ECC only)              | ~376 KB  | ~379 KB  |
| + OpenPGP + Curve25519 (dalek)         | ~421 KB  | ~379 KB  |
| All three applets + Curve25519         | ~450 KB  | ~383 KB  |

Flash device limit (4 MB variant): 4 096 KB.  RAM limit: 520 KB.  Current
usage is well within both limits.  RAM is the metric to watch as the RP2350
has a fixed 520 KB SRAM; flash is not a concern.

---

## 7. Build Commands

### 7.1 Release Builds

```sh
# SC-HSM only, 4 MB flash (default — no flags required)
cargo build --release

# SC-HSM only, 4 MB flash (explicit)
cargo build --release --no-default-features --features rp2350_one_4m

# SC-HSM + PIV, 4 MB
cargo build --release --no-default-features --features rp2350_one_4m,applet-piv

# SC-HSM + OpenPGP (NIST ECC), 4 MB
cargo build --release --no-default-features \
    --features rp2350_one_4m,applet-openpgp

# SC-HSM + OpenPGP + Ed25519/X25519, 4 MB
cargo build --release --no-default-features \
    --features rp2350_one_4m,applet-openpgp,applet-openpgp-curve25519

# All three applets + Ed25519/X25519, 4 MB
cargo build --release --no-default-features \
    --features rp2350_one_4m,applet-piv,applet-openpgp,applet-openpgp-curve25519

# With RSA support (RSA-2048 + RSA-4096)
cargo build --release --no-default-features --features rp2350_one_4m,rsa
```

### 7.2 Debug Build and Flash (hardware required)

The `build-all-debug.sh` script sets `DEFMT_LOG=trace` at compile time, builds
with the debug profile, flashes via `probe-rs run --chip RP235x`, and streams
RTT defmt output to the terminal until Ctrl+C.

```sh
./build-all-debug.sh pico2_4m
```

The connected hardware must be a Waveshare RP2350-One with a CMSIS-DAP
Debugprobe (or equivalent) on the SWD port.

If probe-rs reports `interface is busy (errno 16)`, kill the previous
probe-rs process:

```sh
pkill -9 -f "probe-rs"
```

### 7.3 Running Integration Tests

Start the debug build in one terminal, wait for USB re-enumeration, then run
the test suite in a second terminal:

```sh
# Terminal 1: flash and stream RTT (blocks)
./build-all-debug.sh pico2_4m

# Terminal 2 (after ~5 s for USB re-enumeration): run all tests
./run_tests.sh
```

---

## 8. Implementation Notes

### 8.1 GPIO Ownership After Init

`run_one_board()` in `firmware/src/main.rs` claims peripherals in this order:

| Resource    | Claimed by                                            |
|-------------|-------------------------------------------------------|
| SPI0        | `Spi::new_blocking(p.SPI0, p.PIN_18, p.PIN_19, p.PIN_20, ...)` |
| SPI1        | `Spi::new_blocking(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, ...)` |
| USB         | `UsbDriver::new(p.USB, Irqs)`                         |
| CORE1       | `spawn_core1(p.CORE1, ...)`                           |
| TRNG        | `security::otp::derive_smk()`                         |
| PIO0        | `Ws2812Led::new()` — **stolen** inside board init     |
| GPIO 16     | `Ws2812Led::new()` — **stolen** inside board init     |

The CS GPIO lines (9, 13, 14, 15, 17, 21, 22, 26) are driven via direct
register writes by the storage layer; they do not go through the Embassy
`Output<PIN_N>` ownership model.

### 8.2 SPI Mode 0 Configuration

Both SPI buses are configured identically:

```rust
spi_cfg.phase    = Phase::CaptureOnFirstTransition;  // CPHA = 0
spi_cfg.polarity = Polarity::IdleLow;                // CPOL = 0
spi_cfg.frequency = SPI_FREQ_HZ;                    // 40_000_000 Hz
```

Mode 0 (CPOL=0, CPHA=0) is compatible with all standard W25Q-series and
IS25-series SPI NOR flash chips.

### 8.3 Core1 Stack Headroom

The RP2350-One uses the same 128 KB Core1 stack as all other board variants
(`static mut CORE1_STACK: Stack<131072>` in `firmware/src/main.rs`).
See `CLAUDE.md` § "Core1 stack overflow (silent hang)" for the rationale.
The RP2350 has 520 KB SRAM; current BSS usage is approximately 210 KB, leaving
headroom for further growth.

### 8.4 PIO0_IRQ_0 and the Interrupt Vector

`Pio::new()` (called inside `Ws2812Led::new()`) enables PIO0_IRQ_0 in the
NVIC.  No `bind_interrupts!` entry is registered for PIO0 in `main.rs` because
the WS2812B driver uses synchronous `StateMachineTx::push()` and never calls
`wait_push()`.  No PIO0 interrupt bits (`inte()`) are ever set, so the
interrupt never fires.  If it did, the cortex-m-rt `DefaultHandler` would be
used as the fallback — a benign no-op.

### 8.5 defmt on Core1

Core1 must not call `defmt` macros.  Spinlock 31 is used internally by the
defmt RTT transport, and if Core1 holds Spinlock 31 while Core0 is inside the
USB ISR (which also tries to acquire Spinlock 31 to flush RTT), a deadlock
results.  All `defmt::info!` / `defmt::warn!` calls inside Core1 task code
will cause a silent hang.  See memory file `core1_defmt_deadlock.md` for full
details.
