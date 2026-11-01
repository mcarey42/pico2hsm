# ESP32 port evaluation

Status: research, 2026-10-31. **Conclusion: not ready to port today.** Revisit
when the conditions in §7 are met. Context: issue #24 (platform interface).

This records what three research passes found: the ESP32 chips' USB and
security hardware (Espressif datasheets, ESP-IDF docs, security
advisories), the Rust `no_std` ecosystem (esp-hal source at commit 41b8816,
2026-10-30; espflash 4.7.0), and pico2hsm's own hardware coupling (main at
6ab2b84). **[V]** marks facts checked against a primary source; **[I]**
marks inferences.

## 1. The deciding requirement: a custom USB device

pico2hsm is a USB smartcard: a CCID interface (bulk OUT, bulk IN,
interrupt IN; `firmware/src/transport/ccid.rs`) and a CDC-ACM log
interface (interrupt IN, bulk IN, bulk OUT). That needs a general-purpose
USB device controller.

Espressif's USB-Serial/JTAG controller is "a fixed-function USB device
that is implemented entirely in hardware" and "cannot be reconfigured to
perform any function other than a serial port and JTAG debugging" **[V]**
([ESP-IDF docs](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/api-guides/usb-serial-jtag-console.html)).

| Chip | USB device controller | CCID possible |
|---|---|---|
| ESP32-S3 | OTG Full Speed (DWC2): EP0 + 6 endpoints, at most 5 IN incl. EP0; shares its PHY with USB-Serial/JTAG | Yes, using **every** endpoint (no headroom) |
| ESP32-P4 | OTG High Speed (EP0 + 15, 8 IN) + OTG FS + USB-Serial/JTAG | Yes, with room |
| ESP32-S2 | OTG FS, same limits as S3 | Yes, at the limit |
| ESP32-C6, C5, H2, C3 | USB-Serial/JTAG only | **No** |
| ESP32 (classic) | none | **No** |

The C6 (an early candidate) is therefore out, along with every C-series
and H-series part. The S2 also has only 320 KB SRAM, likely too small for
pico2hsm's current footprint **[I]**.

## 2. S3 and P4 compared

| | ESP32-S3 | ESP32-P4 |
|---|---|---|
| CPU | 2× Xtensa LX7, 240 MHz | 2× RISC-V, 400 MHz (+ LP core) |
| SRAM | 512 KB | 768 KB |
| Flash | in-package variants (FN8, FH4R2, …) | always external (PSRAM in package) |
| Secure boot v2 | RSA-3072-PSS, 3 key digests, revocation | RSA-3072, ECDSA P-256/P-384 (**ECDSA broken, AR2026-006**: use RSA) |
| Glitch detector | **none** | yes |
| Root-key protection | HMAC (eFuse key, never readable), RSA Digital Signature | HMAC, RSA/ECDSA Digital Signature, **Key Manager** (SRAM-PUF; rev ≥ v3.0) |
| Crypto accelerators | SHA, AES, RSA; **no ECC** | AES (anti-DPA, GCM), ECC P-192/256/384 with a constant-time mode, RSA to 4096, SHA to SHA-512 |
| Radio | Wi-Fi 4, BLE 5 | **none** |
| Boards | cheap USB-A dongles (Waveshare ESP32-S3-GEEK ≈ $10, the counterpart of our RP2350-Geek; LilyGO T-Dongle-S3; Waveshare ESP32-S3-LCD-1.47) | large boards only (ESP32-P4-Nano, Function-EV-Board); no dongle |

Sources: datasheets and ESP-IDF security/HMAC/Key Manager pages for each
chip **[V]**; board listings as cited in the research.

## 3. Security findings that shape any port

- **Secure boot keys.** ESP32 secure boot v2 verifies RSA-3072 (S3) or
  RSA/ECDSA P-256/P-384 (P4), not secp256k1. pico2hsm's boot keys
  (`ec_firmware_signing_key-bootkey0/1.pem`) cannot sign ESP32 firmware:
  an ESP32 fleet needs its own root of trust and provisioning runbook.
- **AR2026-006 (2026-07)** **[V]**: the ROM ECDSA secure-boot check
  accepts invalid signatures (no r/s range check) on P4 (≤ v3.2), C5, H2,
  C61, S31. No fix; RSA secure boot is unaffected.
- **AR2026-005 (2026-06)** **[V]**: voltage fault injection plus DFA
  recovers AES-128 keys from the S3's general-purpose AES engine. The S3
  (like S2, C3, C6, ESP32) has no glitch detector. Consequence for a port:
  keep key wrapping in software AES, not the S3 AES engine **[I]**.
- **AR2026-001** **[V]**: power analysis defeats the C5's XTS-AES
  countermeasure; "may be theoretically applicable" to P4.
- **AR2023-007** **[V]**: C3/C6 secure boot and flash encryption bypassed
  (CPA + fault injection + ROM overflow). CPA is theoretically applicable to
  every XTS-AES chip, S2/S3 included.
- **Classic ESP32** **[V]**: revisions 0/1 broken (CVE-2019-17391,
  CVE-2019-15894); revision v3 broken again (CVE-2023-35818 EMFI;
  AR2022-003).
- **S2/S3**: no published fault-injection bypass of secure boot was found;
  absence of a published attack on a chip without a glitch detector is not
  evidence of resistance.
- **RNG** **[V]**: on S3 the RNG is truly random only while the radio runs
  or the SAR ADC entropy source is enabled; on P4 (no radio) the ADC source
  must stay on. A port must keep it enabled and keep pico2hsm's own
  conditioning and health checks.
- **Storage master key** **[V]**: burn an eFuse key with purpose HMAC_UP,
  read-protect it, derive `K = HMAC(eFuse key, label)`; software sees only
  the derived key. Unlike RP2350 OTP (read once, then soft-locked per boot),
  the HMAC unit stays usable for the whole boot; no per-boot lock was found.
- **S3 details** **[V]**: eFuse KEY5 cannot be used for flash encryption
  (erratum); USB-OTG download mode needs its own disable fuse
  (DIS_USB_OTG_DOWNLOAD_MODE, AR2022-004); anti-rollback covers the app,
  not the bootloader.
- **Package**: Espressif advisories recommend SiP parts with flash
  terminated in the package (S3FN8 / S3FH4R2); the P4's external flash
  cannot follow that advice.

## 4. Rust `no_std` readiness

Versions: esp-hal 1.2.2 (2026-09-18), esp-rtos 0.4.0, esp-storage 0.10.0
(being replaced by `esp_hal::flash` on main), esp-bootloader-esp-idf
0.6.0, espflash 4.7.0, Xtensa compiler fork v1.99.0.0, espup 0.19.0
**[V]**. Only GPIO/UART/I2C/SPI/basic RNG are stable; USB OTG, crypto,
flash, eFuse, the second core and esp-rtos require the `unstable` feature
(breaking changes between minor releases).

| Need | S3 | P4 |
|---|---|---|
| Toolchain | Xtensa compiler fork via espup | upstream `riscv32imafc` target |
| Executor / second core | esp-rtos, `start_second_core` / `CpuControl` (open esp-rtos issue #6411 on S3) | same; multicore since esp-hal 1.2.0 |
| USB device | OTG FS via `embassy-usb-synopsys-otg`; takes the PHY, so no on-board USB-JTAG debugging | OTG FS and HS since 1.2.0; HS keeps USB-JTAG debugging |
| True RNG | `TrngSource::new(RNG, ADC1)` | same |
| HMAC with eFuse key | partial, no hardware test | not supported |
| Digital Signature / ECDSA | not supported (esp-hal #884) | not supported (#5444) |
| AES / SHA / RSA / ECC | partial | RSA, ECC partial; AES/SHA not supported |
| eFuse | read-only API; burning is host-side `espefuse` | same |
| Flash from firmware | works; the other core is stalled during each erase | same |
| Secure boot v2 | ESP-IDF-built bootloader + `espsecure` signing; espflash cannot sign (espflash #191) | same flow, not yet demonstrated |
| OTA / rollback | esp-bootloader-esp-idf: OtaUpdater, image states, secure_version | same |

No public Rust CCID, OpenPGP or FIDO project on ESP32 was found.

## 5. What a port would change in pico2hsm

From the coupling inventory (main 6ab2b84):

- **Already portable:** `pico2hsm-core` (no hardware); the CCID/CDC
  transport (generic over `embassy_usb::Driver`); the Storage V2 engines
  behind `StoreFlash` / `CounterFlash`; the display renderer behind
  `Panel`; the watchdog policy (`Core1Monitor`, host-tested).
- **Missing seams** (263 inline `cfg(target_arch = "arm")` lines in 33
  files): entropy (five duplicated host fake-RNG helpers), chip identity
  (USB serial, OpenPGP AID, PIV GUID), security/provisioning state,
  watchdog and reset diagnostics, current core, boot slot / update.
- **Hardest parts:**
  1. The execution model. About 1,500 lines of `main.rs` exist because
     RP2350 flash writes must run on core0 (hardware spinlocks, `wfe`/`sev`,
     `FlashOp` routing). ESP32 flash erases stall the other core instead,
     so the routing is redone, not ported.
  2. The OTP security model (readable IKM with a per-boot soft lock, chaff,
     raw flag row, latched CRIT1, Secure-only partitions) becomes eFuse +
     HMAC + flash encryption, with new capability semantics and a new
     cryptographic root (no migration; acceptable for a new platform).
  3. Boot and update: IMAGE_DEF / try-before-you-buy / `explicit_buy`
     become the ESP-IDF bootloader's OTA rollback, and
     `tools/provision-device.py` needs an `espefuse`/`espsecure`
     counterpart.
- **Stale code to retire regardless:** the `Board` trait (SPI keystore
  chips, RAID-1), `FlashChip`, the 1.x RAID/WAL types in
  `pico2hsm-core/src/storage.rs`, the unused TRNG driver path in
  `crypto/rng.rs`, legacy OTP readers with no callers.

## 6. Assessment

- **ESP32-S3** is the shortest credible path (mature OTG path, dual core
  matching the current split, cheap dongles), but it is a security
  downgrade from RP2350 A4: no glitch detector, a fault attack on its AES
  engine, no ECC hardware, a radio on the die, a forked compiler in the
  trusted build chain, and every needed API unstable.
- **ESP32-P4** has the best hardware (glitch detector, PUF Key Manager,
  constant-time ECC, HS USB, no radio) but immature silicon availability
  (rev ≥ v3.0 only), no esp-hal drivers for its crypto and key blocks, and
  no dongle-sized board.
- **RP2350 A4** remains the stronger target for pico2hsm today.

## 7. Revisit when

1. The platform seams from issue #24 (steps 2–3) exist, so a port is a
   bounded backend rather than a fork of `main.rs`.
2. For P4: esp-hal supports its AES, SHA, HMAC and Key Manager, rev v3.x
   parts are easy to buy, and a small USB-device board exists.
3. For S3: esp-hal's HMAC (with eFuse keys) and USB OTG leave `unstable`
   or have hardware tests, and the secure-boot signing flow works without
   ESP-IDF tooling.
4. Or a newer part (e.g. ESP32-S31: RISC-V, dual core, HS USB) reaches
   esp-hal support.
