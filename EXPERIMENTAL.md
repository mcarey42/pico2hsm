# pico2hsm — Experimental RP2350 Overclock Branch

This branch (`experiment/overclock-400mhz`) explores running the pico2hsm
firmware at non-default RP2350 system clocks. The branch name is
historical — the working production overclock target settled at
**300 MHz @ V1_15 core voltage**; 400 MHz was attempted and ruled out.

> ⚠ This is an experimental branch. The 300 MHz target has been validated
> against the full integration suite on two boards (Raspberry Pi Pico 2 4MB
> and Waveshare RP2350-One 4MB), but **embassy-rp 0.10's `system_freq()` API
> is documented by upstream as "experimental and may not work as expected
> or even damage the chip" on RP235x silicon.** Run on your own hardware,
> with adequate cooling, at your own risk.

---

## TL;DR

| Configuration | Boots | Full integration suite (rp2350-one production) | RSA-2048 keygen |
|---|---|---|---|
| **150 MHz stock** | ✓ | (baseline) | ~887 s (debug build, opt=3 RSA) |
| **200 MHz @ V1_10** | ✓ | (validation point only) | — |
| **300 MHz @ V1_15** | ✓ | **314/4/23/6 (passed/failed/skipped/xpassed)** | **701 s (release, opt=z)** |
| 400 MHz @ V1_25, V1_30 | ✗ silent hang | — | — |

Recommended target: **`experiment-overclock-300`** (300 MHz @ V1_15) — repeatable,
with documented headroom on voltage and on QSPI flash bus speed.

---

## What the experiment changed

Configuring a non-default `clk_sys` on RP2350 turns out to require **four**
specific firmware corrections, none of which embassy-rp 0.10's
`ClockConfig::system_freq()` makes on its own. All four are gated behind
the experiment-overclock-* cargo features in `firmware/src/main.rs`
around line 464:

1. **Explicit QMI flash divider write** before `embassy_rp::init()`.
   `embassy_rp::pac::QMI.mem(0).timing()` set to `CLKDIV=4, RXDELAY=2,
   COOLDOWN=1`. This keeps the QSPI bus at `clk_sys / 4` regardless of the
   bootrom's default — 50 MHz @ 200 MHz, 75 MHz @ 300 MHz, 100 MHz @ 400 MHz,
   all comfortably under the W25Q32's 133 MHz QSPI spec.

2. **Dummy XIP read + DSB + ISB** between the QMI write and `init()`.
   Per RP2350 datasheet §12.14.6, the divisor change has not propagated
   through the QMI clock domain until something forces it; the next
   instruction fetch after the PLL retune reads garbage otherwise. This
   is the same pattern documented in pico-sdk's `boot2_w25q080.S` and the
   `eightycc/b61813c0...` overclock gist.

3. **Override `core_voltage`** above embassy-rp's hardcoded V1_10. The
   `system_freq()` body keeps V1_10 for *every* RP235x target (the comment
   says "no official manufacturer endorsement"). Empirically:

   | clk_sys | Minimum stable voltage | Used in this branch |
   |---|---|---|
   | 200 MHz | V1_10 (1.10 V) | V1_10 |
   | 300 MHz | V1_15 (1.15 V) | V1_15 |
   | 400 MHz | (V1_25 fails, V1_30 fails — see below) | V1_30 |

4. **Override `peri_clk_src = PeriClkSrc::PllUsb`** so `clk_peri` stays at
   48 MHz independent of `clk_sys`. embassy-rp leaves `peri_clk_src=Sys`,
   meaning UART/SPI/I2C peripherals would otherwise run at the new
   `clk_sys` (well over typical peripheral spec). pico-sdk's
   `set_sys_clock_pll()` does the same `clk_peri → pll_usb` repointing on
   every clk_sys change.

The full sequence is in `firmware/src/main.rs` lines ~464–510.

---

## Measured results

### Three runs compared

| Run | Profile | Hardware | clk_sys | Wall-clock | Outcome (P/F/S/Xp) |
|---|---|---|---|---|---|
| **150 MHz baseline** | dev (opt-level=1, RSA crate opt=3) | Pico 2 4MB | 150 MHz | 1960 s | 119 / 150 / 76 / 0 |
| **300 MHz debug** | dev (opt-level=1, RSA crate opt=3) | Pico 2 4MB | 300 MHz | **999 s** | 124 / 162 / 59 / 0 |
| **300 MHz production** | release (opt-level="z") | RP2350-One 4MB + heatsink | 300 MHz | 2158 s | **314 / 4 / 23 / 6** |

### Per-test apples-to-apples speedup (119 tests passing in *all* three runs)

Comparing only tests that passed in every run, on the same workload:

| Subset | 150 MHz dev | 300 MHz dev | 300 MHz release | dev/dev speedup | dev→release notes |
|---|---|---|---|---|---|
| Total CPU subset | 1801 s | 727 s | 1435 s | **2.48×** | release `opt-level="z"` for crypto reverses some of the dev `opt=3` win |
| RSA-2048 keygen | 887 s | 286 s | 701 s | **3.11×** | dev profile has `[profile.dev.package.rsa] opt=3` — release has only opt=z |
| ECDSA P-256 keygen | 55 s | 28 s | 43 s | 1.99× | clock-ratio limited |
| ECDSA P-384 sign | 26 s | 13 s | 27 s | 2.04× | dev/dev |
| INITIALIZE (full reset) | 15.5 s | 7.8 s | 11.4 s | 1.98× | bootrom + key derivation |

### What the production rp2350-one run reveals

The **rp2350-one release build at 300 MHz is the most informative single run** in
this experiment. Beyond the speedup numbers, it shows what the firmware actually
does end-to-end with all applets active on real silicon:

- **314 tests passed** (vs only 119 on debug-profile builds) — release-profile
  firmware activates the PIV and OpenPGP applet code paths that fail-fast on
  debug builds because of the `piv_openpgp_gotchas.md` issues.
- **4 failures only** — all pre-existing, not overclock regressions:
  - `test_06_rsa_keygen::test_rsa_public_key_exported[rsa4096]` — RSA-4096 public-key export
  - `test_09_cluster_apdu::TestGetKeyManifest::test_44_bytes_per_key_after_keygen`
  - `test_11_dkek_roundtrip::TestDkekWrapUnwrapRoundtrip::test_dkek_wrap_unwrap_roundtrip`
  - `test_11_dkek_roundtrip::TestDkekDifferentSharesIncompatible::test_dkek_different_shares_incompatible`
- **6 xpassed (xfail tests that unexpectedly succeeded)** — all OpenPGP Curve25519:
  - Ed25519 keygen + sign (returns 64 bytes, verifies)
  - X25519 keygen + decipher (returns expected shared secret)

The xpassed Curve25519 results are unrelated to the overclock — they reflect
fixes that landed since the xfail markers were written. They're called out here
because the production overclock build is the first time they were seen passing.

---

## Why 400 MHz did not work

Despite a four-hypothesis investigation across two boards and multiple
configurations, 400 MHz failed to boot on this silicon. The failure mode
is consistent and reproducible:

1. probe-rs flash succeeds (~40 s)
2. Chip executes the new firmware
3. **No defmt RTT output appears** (RTT control block read pointer is
   uninitialized garbage like `0x35a97bfb`)
4. **No USB CCID enumeration**
5. **probe-rs SWD attach fails** ("ARM specific error / timeout")
6. Recovery requires physical BOOTSEL (hold BOOTSEL + power-cycle)

Hypotheses tested and ruled out:

| Hypothesis | Tested by | Outcome |
|---|---|---|
| QSPI flash bus overspeed | Explicit QMI CLKDIV=4 (100 MHz QSPI, in spec for W25Q32) | Failure unchanged |
| Insufficient core voltage | V1_25, V1_30 | Failure unchanged |
| `clk_peri` overspeed breaking USB driver | Override `peri_clk_src = PllUsb` (48 MHz) | Failure unchanged |
| PLL/QMI sequencing race | dummy XIP read + DSB + ISB barriers | Failure unchanged |

Remaining suspects (not investigated due to lack of post-hang
diagnostics — SWD doesn't attach in the hung state):

- **Per-chip silicon variance.** Pimoroni's "500 MHz easy at stock voltage"
  datapoint was on a specific Pico 2 board; per-chip ROs vary.
- **embassy-rp 0.10 internal driver that doesn't sustain 400 MHz.** Possibly
  resolvable with embassy-rp 0.11 or future versions. The crate documentation
  explicitly disclaims RP235x non-default clocks.
- **PLL_SYS lock instability** at the (refdiv, fbdiv, postdiv1, postdiv2)
  parameters that embassy-rp's `find_pll_params()` selects for 400 MHz.
  A manual PLL configuration via PAC-direct register writes — bypassing
  `system_freq()` entirely — is the next investigation step but was not
  attempted on this branch.

The full 4-board / 4-voltage / 4-config matrix attempted is documented
in this session's commit history.

---

## Longevity and reliability considerations

### Thermal envelope

- **300 MHz @ V1_15 with 1 cm² passive heatsink**: surface temperature stayed
  at room-temperature-touch (~80 °F / 27 °C) throughout the full integration
  suite, including the ~12-min RSA-4096 keygen. The Cortex-M33 junction
  temperature at this point is well under the 105 °C max with substantial
  margin. **No active cooling is required at this target.**
- **400 MHz**: not measurable — chip never ran a sustained workload. Forum
  consensus suggests 400 MHz at V1_25–V1_30 dissipates roughly 4× a stock
  Pico 2 (peak ~1 W vs ~0.25 W), which would push surface temperature past
  100 °F / 38 °C even with a 1 cm² sink. Active airflow recommended if 400 MHz
  ever becomes reachable on a future embassy-rp version.

### Voltage stress and silicon longevity

- V1_15 (1.15 V vs stock 1.10 V) is +50 mV — well within the documented RP2350
  VREG range. Manufacturer datasheet specifies 0.55–1.30 V VREG output as
  legal; V1_15 is in the lower-mid of that range. Negligible electromigration
  / oxide-stress impact at this delta over a typical 5–10 year HSM service
  life.
- The 400 MHz attempts at V1_25/V1_30 would have been higher-stress
  configurations; not relevant since they don't boot.

### Flash bus integrity

- QSPI bus at 75 MHz @ 300 MHz `clk_sys` (CLKDIV=4) is a `0.56× margin` under
  the W25Q32's 133 MHz spec. RXDELAY=2 is the bootrom default; no read
  errors observed in 35-minute integration runs (which exercise XIP heavily
  on every `cargo build` reset).
- For boards with **different flash chips** (e.g., the Waveshare RP2350-Geek
  variants use W25Q128 16 MB), the 133 MHz spec is the same; the CLKDIV=4
  recipe transfers as-is. **Boards with PSRAM** (none currently in the
  pico2hsm matrix) would also need their `QMI.mem(1).timing()` adjusted —
  not handled by this branch.

### Test coverage

- The `experiment-overclock-300` feature has **only been validated on
  Raspberry Pi Pico 2 4MB and Waveshare RP2350-One 4MB**. The other four
  board variants (`rp2350_geek_16m`, `rp2350_geek_sdcard`,
  `waveshare_rp2350_lcd_16m`, `waveshare_rp2350_lcd_sdcard`) have signed
  production binaries built in `dist/` but have not been booted at 300 MHz.
  Display boards with SPI-driven LCDs may require additional validation —
  the SPI peripheral baud-rate dividers compute correctly off the new
  `clk_peri` source but absolute SCK frequencies should be re-confirmed.

### Bricking risk and recovery

- A failed overclock attempt on RP2350 **cannot be recovered via SWD/probe-rs**
  if the chip's clocks are far enough off-spec to make ARM debug unresponsive.
  The only escape is **physical BOOTSEL** — hold the BOOTSEL button while
  power-cycling.
- For deployed pico2hsm devices in tamper-evident enclosures (the typical HSM
  use case), this means an aggressive overclock could permanently brick a
  device the user can't physically open. **The 300 MHz target is conservative
  enough that no failure has been observed**, but the risk envelope is real.
  A production runbook should document BOOTSEL recovery as a required
  capability before enabling overclock on field-deployed hardware.

---

## How to use this branch

### Build and flash

```sh
# Debug build + flash via probe-rs (RTT visible during boot):
OVERCLOCK_300=1 ./build-all-debug.sh pico2_4m

# Debug build + flash via picotool (BOOTSEL mode, no RTT):
OVERCLOCK_300=1 BOOTSEL=1 ./build-all-debug.sh pico2_4m

# Production build for all 6 board variants, signed:
OVERCLOCK_300=1 ./build-all.sh --arm-only
# Outputs: dist/pico2hsm-<board>-signed.elf (and matching -otp.json)
```

The `OVERCLOCK_200` and `OVERCLOCK_400` variants exist for diagnostic
purposes but are not recommended for production:

- `OVERCLOCK_200`: PAC-validation point — useful only for verifying the QMI
  write and barrier sequence are correct on a new embassy-rp version.
- `OVERCLOCK_400`: does not boot. Documented for reference; do not use.

### Recovering a bricked device

If an experiment-overclock-* firmware fails to boot:

1. Hold the BOOTSEL button on the RP2350 board.
2. While holding BOOTSEL, power-cycle (unplug and replug, or tap RUN/RESET).
3. Release BOOTSEL. `lsusb` should show `2e8a:000f Raspberry Pi RP2350 Boot`.
4. Reflash a known-good firmware via `picotool load <elf> -t elf -x`.

This recovery path works regardless of how badly the broken firmware misconfigured
the chip — it bypasses the application code entirely and runs the bootrom from
ROM.

---

## Future work

If anyone wants to push past 300 MHz on this branch, the lowest-risk next
investigations are:

1. **Bypass `embassy_rp::clocks::ClockConfig::system_freq()` entirely.** Drop
   to PAC-direct PLL_SYS register writes with explicit refdiv/fbdiv/postdiv
   parameters. This rules out whether `find_pll_params()` selects a
   non-stable parameter set at 400 MHz.
2. **Try embassy-rp 0.11+** (not released as of this branch). The 0.10 docs
   acknowledge RP235x clocks are experimental.
3. **Try a different RP2350 silicon batch.** Pico 2 boards manufactured in
   different lots may have different ring-oscillator characteristics.
4. **Add temperature monitoring** via the on-die ADC's temperature sensor
   so a higher overclock target could be auto-fallback-scaled at runtime.
5. **For display/PSRAM boards** (`rp2350_geek_*`, `waveshare_rp2350_lcd_*`),
   add `QMI.mem(1).timing()` configuration alongside the existing `mem(0)`
   write. PSRAM has its own divider and timing requirements per the
   `eightycc/b61813c0...` gist.

---

## References

Investigation in this branch drew on:

- [RP2350 datasheet (QMI register definitions, §12.14)](https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf)
- [RP2350 forum: "rp2350 changing flash clock rate"](https://forums.raspberrypi.com/viewtopic.php?t=375081) — `M0_TIMING.CLKDIV` + dummy-access rule
- [RP2350 forum: 700 MHz overclock thread](https://forums.raspberrypi.com/viewtopic.php?t=375975) — RXDELAY rule of thumb at SCK > 100 MHz
- [eightycc gist — Overclock RP2350 with PSRAM](https://gist.github.com/eightycc/b61813c05899281ce7d2a2f86490be3b) — PSRAM `M1_TIMING` recipe
- [DogThoughts — Automatic RP2350 Overclocking](https://www.dogthoughts.link/posts/rp2350_gofast/)
- [Pimoroni — Overclocking the Pico 2](https://learn.pimoroni.com/article/overclocking-the-pico-2)
- [pico-sdk issue #1903 — boot_stage2 not run on RP2350](https://github.com/raspberrypi/pico-sdk/issues/1903)
- [pico-sdk issue #841 — clk_peri reverts to 48 MHz on clk_sys change](https://github.com/raspberrypi/pico-sdk/issues/841)
- [pico-sdk runtime_init_clocks.c](https://github.com/raspberrypi/pico-sdk/blob/master/src/rp2_common/pico_runtime_init/runtime_init_clocks.c)
- [embassy-rs/embassy issue #3241 — RP235x support](https://github.com/embassy-rs/embassy/issues/3241)
- embassy-rp 0.10 source: `clocks.rs:486–529` (`system_freq`), `clocks.rs:969–1313` (`init`), `clocks.rs:137` (`PeriClkSrc`), `clocks.rs:175–183` (`CoreVoltage` for RP235x)
