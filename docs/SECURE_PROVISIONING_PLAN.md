# pico2hsm — Secure Provisioning Plan

## 1. Overview

pico2hsm is a cryptographic HSM running on the RP2350 (Raspberry Pi Pico 2). The
threat model for this provisioning plan is a physical attacker with unrestricted access
to the board after deployment: the attacker can apply a debugger, probe test points,
swap components, and attempt voltage or clock glitch attacks to extract key material
from flash or registers. The goals addressed here are: (1) signed code execution so
that only firmware built and signed by the device owner will run; (2) permanent debug
port lockout so that a post-deployment attacker cannot attach a debugger; (3) a
per-device encryption key stored in OTP that seeds the Storage Master Key (SMK),
ensuring that cloning the flash image onto another device yields no usable key
material; and (4) hardware glitch detection that resets the processor on supply
voltage tampering. Side-channel attacks (power analysis, EM emanation, timing) are
explicitly out of scope for this phase.

---

## 2. OTP Layout for pico2hsm

The RP2350 has 4096 OTP rows. Rows 0x000–0x0FF are reserved for silicon and ROM
configuration. The user-accessible range is approximately 0x100–0xFFF, though some
rows in the lower range (pages 0–3, rows 0x00–0x3F) contain hardware-significant
fuses that the ROM reads during boot (secure boot enable, JTAG disable, glitch
detector). The pico2hsm firmware uses ECC-protected words (16 bits of payload
stored with 8 bits of Hamming ECC per row) for key material, and raw 24-bit words
for flag registers.

### OTP Row Allocation

| Row address | Name | Content | When programmed | Lock after? | Confidence |
|---|---|---|---|---|---|
| `0x00–0x17` | Silicon/ROM reserved | RP2350 silicon identifiers, RANDID, calibration | Factory | N/A — already locked | CONFIRMED (pico-sdk otp_data.h) |
| `0x18` | NUM_GPIOS | Number of main user GPIOs (48 QFN80, 30 QFN60) | Factory | N/A | CONFIRMED (pico-sdk otp_data.h) — **NOT CRIT0** |
| `0x38–0x3F` | CRIT0 (RBIT-8) | ARM_DISABLE (bit 0), RISCV_DISABLE (bit 1). **Not** secure boot or JTAG. | Provisioning | Yes — write-lock | CONFIRMED (pico-sdk, rp-pac 7.0.0) |
| `0x40–0x47` | CRIT1 (RBIT-8) | SECURE_BOOT_ENABLE (bit 0), SECURE_DEBUG_DISABLE (bit 1), DEBUG_DISABLE (bit 2), GLITCH_DETECTOR_ENABLE (bit 4), GLITCH_DETECTOR_SENS (bits 5-6) | Provisioning | Yes — write-lock | CONFIRMED (pico-sdk, rp-pac 7.0.0, rp2350_hacking_challenge) |
| `0x48–0x4A` | BOOT_FLAGS0 (RBIT-3) | Boot path control flags (NOT secure boot enable) | Provisioning | Yes — write-lock | CONFIRMED (pico-sdk, rp-pac 7.0.0) |
| `0x4B–0x4D` | BOOT_FLAGS1 (RBIT-3) | KEY_INVALID flags for boot key slots | Provisioning | Yes — write-lock | CONFIRMED (pico-sdk, rp-pac 7.0.0) |
| `0x80–0x8F` | BOOTKEY0 (ECC) | SHA-256 hash of secp256k1 boot signing public key (32 bytes = 16 ECC rows) | Key provisioning | Yes — write-lock | CONFIRMED (pico-sdk, rp-pac 7.0.0) |
| `0x100–0x11F` | pico2hsm storage key material (32 ECC rows = 64 bytes) | IKM for HKDF-SHA256 that derives the Storage Master Key (SMK). Per-device random bytes written once at provisioning. | Factory provisioning | Yes — read-lock + write-lock | CONFIRMED (defined in `security/otp.rs` `OTP_STORAGE_KEY_ROW_START = 0x100`) |
| `0x110` | pico2hsm boot flags | bit 0 = JTAG_DISABLED (user-land record); bit 1 = PRODUCTION_MODE; bit 2 = PROVISIONED | After production mode set | Yes — write-lock after setting | CONFIRMED (defined in `security/otp.rs` `OTP_BOOT_FLAGS_ROW = 0x110`) |
| `0x120–0x12F` | Device identity key (16 ECC rows = 32 bytes) | Static Ed25519 device identity key for Noise_XX authentication (pico2hsm DKEK exchange protocol) | Factory provisioning | Yes — read-lock + write-lock | CONFIRMED (defined in `security/otp.rs` `OTP_DEVICE_ID_KEY_ROW_START = 0x120`) |
| `0x130–0x137` | Device serial / unique ID (8 ECC rows = 16 bytes) | Per-device serial number used as HKDF `info` parameter in SMK derivation; provides key diversity across identical boards | Factory provisioning | Yes — write-lock (can remain readable) | ESTIMATED — row range chosen to fit in page 1; TBD by TRM |
| `0x140–0x14F` | (Reserved for future expansion) | Spare rows for additional per-device data | — | — | TBD |

### Notes on Row Addressing Scheme

The RP2350 uses a two-level addressing scheme in its ROM API: the `otp_access`
ROM function takes a row number (0–4095) and an operation code. The
`embassy_rp::otp` module wraps this for ECC and raw access. The CRIT1 rows
(0x40–0x47, RBIT-8) and BOOT_FLAGS0 (0x48–0x4A, RBIT-3) are read by the ROM
during the boot sequence — they must be programmed before the device is
sealed.  CRIT1 and CRIT0 use RBIT-8 redundancy (8 identical copies); always
use `picotool otp set OTP_DATA_CRIT1.*` which writes all 8 copies
automatically.  Do NOT write individual rows with `write_raw_word()`.

---

## 3. Secure Boot Implementation Plan

### 3.1 How RP2350 Secure Boot Works

The RP2350 ROM implements a two-stage boot process. In the second stage, if
`SECURE_BOOT_ENABLE` is set in **CRIT1** (OTP rows `0x40–0x47`, RBIT-8, bit 0),
the ROM reads a boot manifest at the start of the firmware image in flash. The
manifest contains a **secp256k1** signature (not Ed25519) over a SHA-256 hash of
the firmware binary. The ROM verifies this signature against a hash of the public
signing key that was burned into OTP BOOTKEY0 (rows `0x80–0x8F`) during
provisioning. If verification fails, the ROM halts — it does not attempt to
execute any firmware code.

This means secure boot protection is entirely hardware-enforced by the ROM, before
any firmware code runs. The `security/boot.rs` `is_secure_boot_enabled()` function
reads CRIT1 row `0x40` bit 0 to confirm this bit is set at runtime, but that is a
software check layered on top of the hardware guarantee.

### 3.2 Step-by-Step Implementation Plan

**Step 1 — Key generation (offline, one-time per operator)**

Generate a **secp256k1** signing key pair on an air-gapped machine. The private key
must never leave that machine and should be stored in an HSM or on encrypted
offline media. Only the public key needs to be available during provisioning.

Tool: `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1` or the
Raspberry Pi SDK (if available). The public key must be exported as a raw 32-byte
file (no PEM wrapper) for the OTP programming step.

**Step 2 — Burn the public key hash into OTP rows 0x20–0x2F (ESTIMATED range)**

The RP2350 ROM does not store the raw public key in OTP — it stores the SHA-256
hash of the public key (32 bytes = 16 ECC-protected OTP rows). Compute:

```
boot_key_hash = SHA-256(ed25519_public_key_bytes)
```

Write each pair of bytes as one ECC word using `otp::write_ecc_word()`. The exact
rows are defined in the RP2350 TRM §5.6.6 — confirmed as being in OTP page 0
but the precise row range must be verified against the TRM before production use
(currently ESTIMATED as `0x20–0x2F`).

**Step 3 — Sign the firmware image**

The Raspberry Pi SDK provides a signing tool (`picotool sign` or equivalent) that:
1. Takes the compiled ELF/UF2 firmware binary
2. Computes the image hash
3. Signs it with the offline Ed25519 private key
4. Embeds the signature and manifest into the binary at the correct offset

The resulting signed binary is a drop-in replacement for the unsigned binary.
Probe-rs can flash it normally. The ROM's manifest parser expects a specific layout
at the image header — using the official SDK signing tool is mandatory; hand-crafting
the manifest is error-prone.

**Step 4 — Set SECURE_BOOT_ENABLE in CRIT1 (OTP rows 0x40–0x47)**

```bash
picotool otp set OTP_DATA_CRIT1.SECURE_BOOT_ENABLE 1
```

This is the point of no return for secure boot. After this bit is set:
- Unsigned firmware will not run
- Old (unsigned) firmware already in flash will stop working
- The device can only be recovered by flashing a correctly signed image

This step must happen after the signed firmware has been successfully flashed and
verified to boot. Use `picotool otp set` (not raw row writes) — CRIT1 uses RBIT-8
redundancy and all 8 copies must be written.

**Step 5 — Verify at runtime**

The existing `is_secure_boot_enabled()` function in `security/boot.rs` reads CRIT1
row `0x40` bit 0 and can be used as a runtime assertion:

```
assert!(security::boot::is_secure_boot_enabled(), "Secure boot not active — refuse to operate")
```

This assertion should be placed in `security_checks()` for production builds,
so that a device where the fuse was not correctly burned refuses to process APDUs.

**Relation to existing `security/boot.rs`**

`security/boot.rs` already has:
- `is_secure_boot_enabled()` — reads and returns the fuse state (implemented)
- `security_checks()` — calls JTAG disable and debugger detect (implemented)
- `check_debugger_attached()` — reads DHCSR (implemented)

The missing piece is a hard assertion in `security_checks()` that calls
`is_secure_boot_enabled()` and halts if not set when `PRODUCTION_MODE` is active.

---

## 4. JTAG / Debug Disable Plan

### 4.1 Hardware Fuse Location

The RP2350 hardware JTAG disable fuse is **CRIT1.DEBUG_DISABLE** (bit 2 of CRIT1,
OTP rows `0x40–0x47`, RBIT-8 redundancy). Verified against pico-sdk `otp_data.h`,
rp-pac 7.0.0, and the Raspberry Pi `rp2350_hacking_challenge/lock_chip.sh`.

**Important corrections from previous versions of this document:**
- CRIT0 (rows 0x38–0x3F) only contains ARM_DISABLE and RISCV_DISABLE — it has
  nothing to do with JTAG or secure boot.
- Row 0x18 is NUM_GPIOS, not CRIT0.
- SECURE_BOOT_ENABLE, DEBUG_DISABLE, GLITCH_DETECTOR, and SECURE_DEBUG_DISABLE
  are all in CRIT1 (rows 0x40–0x47).

The firmware's `disable_jtag_permanent()` function in `security/boot.rs` sets
bit 0 of OTP row `0x110` — this is the **pico2hsm user-land bookkeeping flag**,
not the hardware JTAG fuse.

### 4.2 Timing in Provisioning Sequence

JTAG disable must happen **after** all firmware flashing and OTP programming is
complete. Once the hardware JTAG fuse is blown:
- No debugger (SWD/JTAG) can connect to the RP2350
- probe-rs, OpenOCD, and any SWD-based tool will fail to connect
- The debug probe is physically useless from that point on

The recommended sequence is:
1. Flash signed firmware
2. Program all OTP key rows
3. `picotool otp set OTP_DATA_CRIT1.SECURE_BOOT_ENABLE 1`
4. Set PRODUCTION_MODE (pico2hsm OTP row 0x110 via firmware APDU)
5. **`picotool otp set OTP_DATA_CRIT1.DEBUG_DISABLE 1`** — point of no return
6. `picotool otp set OTP_DATA_CRIT1.SECURE_DEBUG_DISABLE 1`
7. `picotool otp set OTP_DATA_CRIT1.GLITCH_DETECTOR_ENABLE 1`
8. `picotool otp set OTP_DATA_CRIT1.GLITCH_DETECTOR_SENS 3`
9. Firmware sets bookkeeping flag (row 0x110 bit 0) at next boot

### 4.3 Point of No Return

**Once CRIT1.DEBUG_DISABLE is set, there is no recovery path.**
The RP2350 ROM will reject all SWD/JTAG connections on all subsequent boots. This
cannot be undone by any software operation. If the device has a bug at this point,
the only option is to discard the unit.

### 4.4 CRIT1 RBIT-8 Redundancy

CRIT1 uses RBIT-8: the value is stored in 8 identical copies (rows 0x40–0x47).
The ROM does a majority vote across all copies. **Always use `picotool otp set
OTP_DATA_CRIT1.*` for CRIT1 writes** — picotool writes all 8 copies automatically.
`embassy_rp::otp::write_raw_word()` writes exactly one row, which is insufficient
for reliable RBIT-8 programming.

The firmware does NOT write CRIT1 at runtime. The INS=0xF3 provisioning APDU is
disabled (returns SW 6D00) because single-row writes cannot reliably program
RBIT-8 fields. The firmware only sets the bookkeeping flag in row 0x110.

---

## 5. Device Encryption Key Plan

### 5.1 OTP Rows for Per-Device Key Material

The storage key material occupies OTP rows `0x100–0x11F` (32 ECC rows, 64 bytes).
This is defined in `security/otp.rs` as `OTP_STORAGE_KEY_ROW_START = 0x100` with
`OTP_STORAGE_KEY_LEN = 64`. These rows are in the user-accessible OTP range
(page 4 onward) and are not read by the RP2350 ROM — they are exclusively used
by the pico2hsm firmware.

A device serial / unique ID is planned at rows `0x130–0x137` (16 bytes; ESTIMATED
row range — see Section 2). This serial provides key diversity in the HKDF
derivation so that two devices with identical storage key material IKM still
produce different SMKs.

### 5.2 How It Feeds into `derive_smk()`

The current `derive_smk()` function in `security/otp.rs` (line 365) uses:

```
SMK = HKDF-SHA256(IKM = root_secret, salt = "pico2hsm-smk", info = <empty>)
```

The TODO comment at line 364 notes that the device serial is missing from the
`info` parameter. This is PUNCHOUT item 5e. The intended target is:

```
SMK = HKDF-SHA256(IKM = otp_storage_key_material_64bytes,
                  salt = b"pico2hsm-smk",
                  info = device_serial_16bytes)
```

The `info` parameter binds the SMK to a specific device serial number. Without it,
any two devices with the same IKM burned into their OTP produce the same SMK,
which means cloning the IKM rows would also clone the key protection.

Note: `derive_smk()` currently calls `read_root_secret()` (legacy layout at rows
`0x20–0x3F`) rather than `read_storage_key_material()` (the correct layout at
`0x100–0x11F`). This inconsistency needs to be resolved before production use.

### 5.3 Key Diversity Strategy

Each device must receive unique IKM during factory provisioning. The recommended
strategy:

1. Generate 64 bytes of cryptographically random data per device using a CSPRNG
   on the provisioning host (e.g., `openssl rand 64`).
2. Write the 64 bytes to OTP rows `0x100–0x11F` using ECC writes.
3. Generate 16 bytes of device serial (can be a monotonic counter + random salt,
   or a UUID) and write to rows `0x130–0x137`.
4. After programming, read back both blocks and verify via ECC read — OTP
   programming errors are possible; a verification read confirms the writes.

With this scheme:
- Each device has a unique 64-byte IKM → unique SMK
- Cloning the flash image onto a different device fails to decrypt stored keys
  because the SMK derived from the different device's OTP will not match
- The device serial in `info` provides an additional binding so that a partial
  OTP clone (IKM only, not serial) still produces a different SMK

### 5.4 Factory Provisioning Flow

The production programmer (a script run on a provisioning workstation connected
to the device via SWD probe) must:

1. Connect to the device via probe-rs / picotool
2. Generate 64 bytes of random IKM
3. Write IKM to OTP rows `0x100–0x11F` via `otp::write_ecc_word()`
4. Generate a device serial (16 bytes)
5. Write serial to OTP rows `0x130–0x137`
6. Write the boot signing public key hash to BOOTKEY0 (rows `0x80–0x8F`)
7. Write PRODUCTION_MODE + PROVISIONED flags to row `0x110`
8. `picotool otp set OTP_DATA_CRIT1.SECURE_BOOT_ENABLE 1`
9. `picotool otp set OTP_DATA_CRIT1.DEBUG_DISABLE 1` (point of no return)
10. `picotool otp set OTP_DATA_CRIT1.GLITCH_DETECTOR_ENABLE 1`
11. `picotool otp set OTP_DATA_CRIT1.GLITCH_DETECTOR_SENS 3`
12. Read back all programmed rows to verify (critical — OTP write errors are silent)
13. Record device serial and provisioning timestamp in production database

---

## 6. Glitch Detection Plan

### 6.1 POWMAN VREG Register Fields

The RP2350 Power Management (POWMAN) block contains a voltage regulator (VREG)
with an integrated voltage glitch detector. The relevant register fields are in
the `POWMAN.VREG` register (RP2350 datasheet §7.6.4):

| Field | Bits | Description |
|---|---|---|
| `GLITCH_DETECT_DISABLE` | bit 0 | 0 = detector enabled, 1 = detector disabled (default: 1 on power-on) |
| `GLITCH_DETECT_SENS` | bits [31:16] | Sensitivity control: 0 = off, 1 = low, 2 = medium, 3 = high/max |

Note: The `anti_glitch.rs` comment at line 157 reverses the bit ordering slightly —
the datasheet description above should be treated as authoritative. The
exact register layout (including whether SENS occupies bits [31:16] or a narrower
field) must be confirmed against the TRM before implementation.

When a voltage glitch is detected (voltage drops below the threshold set by SENS),
POWMAN triggers an immediate system reset. The firmware does not get a chance to
react — the hardware reset happens autonomously.

There is also an OTP-level glitch detector enable: **CRIT1** bit 4 (GLITCH_DETECTOR_ENABLE)
and bits 5–6 (GLITCH_DETECTOR_SENS). These configure the detector to be active from
the moment the ROM runs, before firmware starts. The POWMAN VREG software configuration
is an additional control that the firmware can apply at runtime.

### 6.2 Sensitivity Levels and False-Positive Risk

Higher sensitivity detects smaller voltage perturbations but increases the risk of
spurious resets on boards with noisy power supplies:

| SENS level | Typical glitch threshold | False-positive risk |
|---|---|---|
| 0 | Disabled | None |
| 1 | ~100 mV deviation | Low |
| 2 | ~50 mV deviation | Medium |
| 3 | ~20 mV deviation | High on battery/USB supplies |

For pico2hsm deployed on a Raspberry Pi Pico 2 powered from USB, SENS=2 is
recommended as a starting point. SENS=3 may cause false resets when USB host
power drops during enumeration. This should be validated empirically on target
hardware before locking in.

### 6.3 Implementation Plan for `arm_glitch_detector()`

The `arm_glitch_detector()` function in `security/anti_glitch.rs` (line 152) is
currently a documented no-op. The stub already contains the correct PAC code:

```rust
unsafe {
    let powman = embassy_rp::pac::POWMAN;
    powman.vreg().modify(|w| {
        w.set_glitch_detect_disable(false); // 0 = enabled
        w.set_glitch_detect_sens(2);        // medium sensitivity
    });
}
```

This cannot be compiled yet because `rp_pac` (the PAC crate used by embassy-rp)
does not expose `glitch_detect_disable` and `glitch_detect_sens` field accessors
on the `VREG` register as of embassy-rp 0.10 (PUNCHOUT item 5b).

**Path to implementation:**
1. Check the current `rp-pac` version in `Cargo.lock` for any recent additions
2. If still missing, use a direct register write via `core::ptr::write_volatile`
   to the POWMAN VREG register address (can be found in the RP2350 TRM memory map
   or by inspecting the PAC-generated address constants)
3. Once `rp_pac` exposes the field accessors, replace the raw pointer write with
   the idiomatic PAC call

For OTP-level glitch detector (CRIT1 bits 4–6), the provisioning tool should set
these during factory programming so the detector is active from first ROM execution,
before firmware even starts. This provides protection during the boot sequence
itself.

### 6.4 Response Policy

The hardware glitch detector response (automatic reset on detection) is already
handled by POWMAN hardware — no firmware code needed for that path.

For the software double-check path (`double_check()` returning `Mismatch`), the
recommended response policy is:

1. **PIN verification mismatch** — increment the failed-attempt counter in flash
   (to prevent reset-and-retry attacks), then reset via `cortex_m::peripheral::SCB::sys_reset()`
2. **Crypto operation mismatch** — zeroize all in-memory key material via the
   existing `Zeroize` implementations on `KeyObject`, then reset
3. **Stack canary failure** — immediate reset without any flash operations
   (stack corruption means nothing can be trusted)

The existing `double_check()` function in `anti_glitch.rs` is correctly implemented
with a compiler fence. Call sites in PIN verification and ECDSA signing are the
highest-priority locations to add double-check patterns.

---

## 7. Provisioning Sequence (Ordered)

The following steps must be executed in this exact order. Each step is numbered;
steps marked **[IRREVERSIBLE]** cannot be undone.

1. **Build signed firmware**
   - Compile release firmware for the target board feature flag
   - Sign the ELF with the offline Ed25519 signing key using the SDK signing tool
   - Output: signed UF2/ELF binary
   - Tool: `picotool sign` or equivalent SDK tool
   - Point of no return: none (can rebuild at any time)

2. **Flash signed firmware**
   - Flash the signed binary via probe-rs or picotool
   - Verify the device boots successfully (RTT log shows "boot OK")
   - Tool: `probe-rs run --chip RP235x` or `picotool load <elf> -t elf -x`
   - Point of no return: none (can reflash before OTP is locked)

3. **Generate per-device IKM and serial**
   - On provisioning host: `openssl rand 64 > device_ikm.bin`
   - On provisioning host: `openssl rand 16 > device_serial.bin`
   - Record device_serial.bin in the production database alongside board ID
   - Point of no return: none

4. **Write storage key IKM to OTP rows 0x100–0x11F** [IRREVERSIBLE for those rows]
   - Write 64 bytes as 32 ECC words via `otp::write_ecc_word()`
   - Read back immediately and verify all 32 words match
   - Tool: provisioning firmware image, or `picotool otp set` (if supported)
   - Point of no return: the 64 bytes are now permanently fused (cannot be overwritten
     to different values; can only set additional bits from 0 to 1)

5. **Write device serial to OTP rows 0x130–0x137** [IRREVERSIBLE for those rows]
   - Write 16 bytes as 8 ECC words
   - Read back and verify
   - Point of no return: same as step 4

6. **Write boot signing public key hash to BOOTKEY0 (OTP rows 0x80–0x8F)** [IRREVERSIBLE]
   - Compute `SHA-256(secp256k1_public_key_bytes)`
   - Write as 16 ECC words (or use `picotool otp load` with OTP JSON from `picotool seal`)
   - Read back and verify
   - Point of no return: signing key is now bound to this device

7. **Set PRODUCTION_MODE flag in pico2hsm boot flags row (OTP row 0x110)** [IRREVERSIBLE]
   - Call `Otp::set_production_mode()` via a provisioning APDU or provisioning firmware
   - This sets bits 1 (PRODUCTION_MODE) and 2 (PROVISIONED) simultaneously
   - After this step, the firmware will reject debug APDUs and will require signed operation
   - Tool: provisioning firmware APDU or direct OTP write
   - Point of no return: production mode cannot be unset

8. **Enable secure boot in CRIT1 (OTP rows 0x40–0x47, bit 0)** [IRREVERSIBLE]
   - `picotool otp set OTP_DATA_CRIT1.SECURE_BOOT_ENABLE 1`
   - picotool writes all 8 RBIT-8 copies automatically
   - Reboot the device and confirm it still boots correctly (firmware is signed)
   - **Critical point of no return: unsigned firmware will never run again on this device**
   - If the device fails to boot after this step (e.g. bad signature), the device is bricked

9. **Lock key material OTP rows (0x100–0x12F) against further reads and writes**
   - Set read-lock and write-lock permission bits on rows 0x100–0x12F
   - This prevents an attacker who compromises the firmware from reading the raw IKM
   - Implemented via PAC write to OTP SW_LOCK registers in `security/otp.rs`
   - [IRREVERSIBLE per boot session; permanent locks require OTP lock page writes]

10. **Disable JTAG via CRIT1 (OTP rows 0x40–0x47, bit 2)** [IRREVERSIBLE — POINT OF NO RETURN]
    - `picotool otp set OTP_DATA_CRIT1.DEBUG_DISABLE 1`
    - `picotool otp set OTP_DATA_CRIT1.SECURE_DEBUG_DISABLE 1`
    - `picotool otp set OTP_DATA_CRIT1.GLITCH_DETECTOR_ENABLE 1`
    - `picotool otp set OTP_DATA_CRIT1.GLITCH_DETECTOR_SENS 3`
    - Reboot and confirm SWD connection is refused (probe-rs should fail to connect)
    - Tool: picotool only — firmware does NOT write CRIT1 (RBIT-8 requires all 8 copies)
    - **This is the final, absolute point of no return. After this step, no debugger
      can ever connect to this device again.**

11. **Set pico2hsm JTAG_DISABLED bookkeeping flag (OTP row 0x110 bit 0)** [IRREVERSIBLE]
    - Records that hardware JTAG lockdown was performed
    - The firmware's `disable_jtag_permanent()` / `security_checks()` uses this to
      confirm the device is in the expected post-provisioning state
    - Tool: provisioning firmware APDU or direct OTP write

12. **Final verification**
    - Power cycle the device
    - Confirm USB enumeration (device appears as CCID reader)
    - Run `run_tests.sh` to verify all integration tests pass
    - Record provisioning completion in the production database

---

## 8. Embassy-rp API Gaps

The following table summarizes what the provisioning and security implementation
requires versus what embassy-rp 0.10 currently exposes.

| Requirement | Current Status | Gap / Workaround |
|---|---|---|
| `otp::write_ecc_word(row, value)` | Implemented in embassy-rp | No gap — API exists and is used |
| `otp::read_ecc_word(row)` | Implemented in embassy-rp | No gap — API exists and is used |
| `otp::write_raw_word(row, value)` | Implemented in embassy-rp | No gap — used for flag rows |
| `otp::read_raw_word(row)` | Implemented in embassy-rp | No gap — used for flag and BOOT_FLAGS0 reads |
| OTP row read-lock API | **MISSING** (PUNCHOUT 5c) | `lock_read()` in `otp.rs` is a no-op stub. Workaround: direct PAC write to OTP_DATA_RAW permission registers, or call ROM `otp_access` with lock flag directly. |
| OTP row write-lock API | **MISSING** (PUNCHOUT 5c) | Same as read-lock. |
| POWMAN VREG `GLITCH_DETECT_DISABLE` field | **MISSING** (PUNCHOUT 5b) | `rp_pac` does not expose this field on the VREG register type. Workaround: `core::ptr::write_volatile` to the POWMAN VREG register address from the TRM memory map. |
| POWMAN VREG `GLITCH_DETECT_SENS` field | **MISSING** (PUNCHOUT 5b) | Same as above. |
| CRIT0/CRIT1 write via high-level API | **MISSING** | No embassy-rp wrapper. Must use ROM `otp_access` directly via `embassy_rp::pac` or a provisioning tool. Not needed in runtime firmware (only in provisioning tool). |
| Boot signing key hash programming | **MISSING** | No embassy-rp helper for programming the ROM-specific boot key hash rows. Must be done via `picotool otp` or direct ROM `otp_access`. |
| `OTP` peripheral singleton type | **MISSING** (anticipated gap) | `embassy_rp::otp` uses free functions, no peripheral token. `Otp::new()` in `otp.rs` takes no arguments as a workaround. When embassy-rp adds an `Otp` singleton, the constructor signature will need updating. |

---

## 9. Open Questions

Items resolved during v1.0.0-rc4 OTP audit (triple-checked against pico-sdk
`otp_data.h`, rp-pac 7.0.0, and rp2350_hacking_challenge `lock_chip.sh`):

- ~~**JTAG disable bit position:**~~ **RESOLVED.** JTAG disable is CRIT1 bit 2
  (DEBUG_DISABLE) at rows 0x40–0x47 (RBIT-8). CRIT0 (rows 0x38–0x3F) only
  contains ARM_DISABLE and RISCV_DISABLE. Row 0x18 is NUM_GPIOS.

- ~~**Boot signing key hash row range:**~~ **RESOLVED.** BOOTKEY0 is at rows
  0x80–0x8F (ECC). Contains SHA-256 of secp256k1 signing public key (not Ed25519).

- ~~**SECURE_BOOT_ENABLE location:**~~ **RESOLVED.** CRIT1 bit 0 at rows
  0x40–0x47 (RBIT-8). NOT in BOOT_FLAGS0.

Still open:

- **POWMAN VREG register address:** The memory-mapped address for the glitch
  detector arming register. Currently using PAC-derived address.

- **OTP lock permission register layout:** Per-row permission bits for
  `lock_read()` / `lock_write()` — requires PAC OTP_DATA_RAW access not yet
  exposed by embassy-rp.

- **Glitch detector sensitivity for USB-powered board:** SENS=3 is configured
  but not empirically tested for false-positive resets during USB enumeration
  or high-load crypto operations.

- **OTP write-verify requirement:** The RP2350 OTP programming circuit can
  occasionally fail to blow a fuse. The TRM §5.6.1 may specify a recommended
  verify-after-write procedure. All OTP writes in the provisioning sequence must
  include a read-back verification step.
