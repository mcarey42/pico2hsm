# pico2hsm — Production Provisioning Guide

Complete step-by-step guide for provisioning a pico2hsm device from bare
hardware to a production-locked state using **picotool** and standard CLI
tools. No custom provisioning hardware is required.

Last updated: 2026-04-16 (v1.0.0-rc4)

---

## Overview

Provisioning transforms a blank RP2350 board into a production HSM by:

1. Generating a firmware signing key (once per organization)
2. Building and signing the firmware
3. Flashing the signed firmware
4. Writing per-device key material to OTP (one-time programmable fuses)
5. Enabling secure boot (irreversible)
6. Disabling JTAG/SWD debug access (irreversible)

After provisioning, only firmware signed with your private key will boot,
and the device's flash-encrypted key material cannot be extracted even with
physical access to the board.

**Key constraint:** The RP2350 bootrom uses **secp256k1** for signature
verification — not P-256, not Ed25519. Using any other curve produces
`"Signature verification failed"` from picotool.

---

## Supported Boards

The provisioning process is identical across all boards:

| Board | Feature flag | Flash |
|-------|-------------|-------|
| Raspberry Pi Pico 2 | `pico2_4m` | 4 MB |
| Waveshare RP2350-One | `rp2350_one_4m` | 4 MB |
| Waveshare RP2350-Geek | `rp2350_geek_16m` | 16 MB |
| Waveshare RP2350-Geek (SD) | `rp2350_geek_sdcard` | 16 MB + SD |
| Waveshare RP2350-LCD-1.47-B | `waveshare_rp2350_lcd_16m` | 16 MB |
| Waveshare RP2350-LCD-1.47-B (SD) | `waveshare_rp2350_lcd_sdcard` | 16 MB + SD |

OTP layout, secure boot, and JTAG disable are handled identically by the
RP2350 ROM regardless of board variant.

---

## Prerequisites

### Tools

```bash
# picotool — firmware signing, OTP programming, BOOTSEL flashing
# Requires picotool >= 2.1
sudo apt install picotool    # Debian/Ubuntu
brew install picotool        # macOS

# probe-rs — SWD flashing (alternative to BOOTSEL)
cargo install probe-rs-tools

# OpenSSL — key generation
which openssl

# Rust toolchain
rustup target add thumbv8m.main-none-eabihf
```

### Hardware

- One of the supported RP2350 boards listed above
- USB cable for BOOTSEL flashing
- (Optional) CMSIS-DAP debug probe for SWD flashing

---

## Phase 1: Generate Signing Key (One-Time)

This is done **once per organization or device family**. The private key
should be generated on an air-gapped machine and never leave it.

### Option A: Use the included script

```bash
./generate_firmware_signing_keys.sh
```

This generates:
- `ec_firmware_signing_key.pem` — secp256k1 private key (PKCS#8 PEM)
- `ec_firmware_signing_key.pub` — corresponding public key

### Option B: Manual generation

```bash
# Generate secp256k1 private key
openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:secp256k1 \
    -out ec_firmware_signing_key.pem
chmod 600 ec_firmware_signing_key.pem

# Extract public key
openssl pkey -in ec_firmware_signing_key.pem \
    -pubout -out ec_firmware_signing_key.pub
```

### Record the fingerprint

```bash
openssl pkey -pubin -in ec_firmware_signing_key.pub -outform DER 2>/dev/null \
    | openssl dgst -sha256 -hex | sed 's/^.* //'
```

Store this fingerprint in your production records. It identifies the key
that will be permanently bound to every device you provision.

### Key security

- **Private key** → encrypted offline storage (HSM, LUKS volume, vault)
- **Public key** → safe to distribute to build machines
- **Losing the private key = permanent inability to update provisioned devices**
- There is no recovery mechanism. OTP is permanent.

---

## Phase 2: Build Release Firmware

Choose the feature flag for your target board:

```bash
# Example: Raspberry Pi Pico 2
cargo build --release \
    --manifest-path firmware/Cargo.toml \
    --no-default-features \
    --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519
```

Or build all variants at once:

```bash
./build-all.sh --arm-only
```

The release ELF is at:
`target/thumbv8m.main-none-eabihf/release/pico2hsm`

---

## Phase 3: Sign Firmware

The `picotool seal` command signs the ELF and produces an OTP configuration
JSON for programming the boot key hash:

```bash
mkdir -p dist

picotool seal --hash --sign \
    target/thumbv8m.main-none-eabihf/release/pico2hsm -t elf \
    dist/pico2hsm-signed.elf -t elf \
    ec_firmware_signing_key.pem \
    dist/pico2hsm-otp.json
```

This produces two files:

| File | Purpose |
|------|---------|
| `dist/pico2hsm-signed.elf` | Firmware with embedded signature manifest |
| `dist/pico2hsm-otp.json` | OTP values for secure boot (public key hash, boot flags) |

The `build-all-debug.sh` script performs this automatically when
`ec_firmware_signing_key.pem` is present in the repo root.

---

## Phase 4: Flash Firmware

### Option A: BOOTSEL mode (no debug probe needed)

1. Hold BOOTSEL while plugging in USB (or hold BOOTSEL and press RESET)
2. The board appears as a USB mass storage device (`RPI-RP2`)

```bash
# Flash the signed ELF directly:
picotool load dist/pico2hsm-signed.elf -t elf -x
```

The `-x` flag reboots the device after flashing.

### Option B: SWD via debug probe

```bash
probe-rs download --verify --format elf \
    dist/pico2hsm-signed.elf --chip RP235x
```

### Verify boot

After flashing, the device should enumerate as a USB CCID reader:

```bash
opensc-tool --list-readers
# Expected: "pico2hsm SC-HSM (0001) 00 00"
```

---

## Phase 5: Provision OTP

### OTP layout

The pico2hsm firmware uses these OTP regions (defined, with compile-time
overlap checks, in `firmware/src/security/otp_layout.rs`):

```
Page 4 — secrets, read-locked by the firmware after boot
Rows 0x100–0x11F : Storage key IKM (64 bytes, 32 ECC words)
                   Input Keying Material for HKDF-SHA256 → Storage Master Key
Rows 0x120–0x12F : Device identity key (32 bytes, 16 ECC words)
                   Static key for Noise_XX device authentication
Page 5
Row  0x140       : Boot flags (raw 24-bit word)
                   bit 0 — JTAG disabled (irreversible)
                   bit 1 — production mode (irreversible)
                   bit 2 — device provisioned
```

> **Layout change (2026-10):** firmware before this change put the boot
> flags at row 0x110, which is *inside* the storage-key IKM rows. Writing a
> flag there corrupts the IKM (and a random IKM bit could read as
> "production mode"). Never write row 0x110. A device whose row 0x110 was
> written under the old layout must be treated as having an unknown storage
> key: re-provisioning is impossible (OTP is permanent), so retire it.

**Unprovisioned devices:** with blank IKM rows the derived storage key is a
fixed, public value: **nothing stored on such a board is protected**.  Anyone
with the board's flash or SD card can read every key, the DKEK and any domain
key.  Use unprovisioned boards for development only. Debug builds (and release builds with the
`insecure-dev-keystore` feature) accept this for development and log a
warning at boot; release builds disable the keystore entirely until the IKM
is written, so INITIALIZE and key generation fail rather than store keys
under a public key.

The RP2350 ROM uses these additional rows (programmed via `picotool otp set`
or `picotool otp load`).  Row numbers verified against pico-sdk `otp_data.h`
and rp-pac 7.0.0:

```
Rows 0x38–0x3F  : CRIT0 (RBIT-8) — ARM_DISABLE, RISCV_DISABLE only
Rows 0x40–0x47  : CRIT1 (RBIT-8) — SECURE_BOOT_ENABLE, DEBUG_DISABLE,
                   SECURE_DEBUG_DISABLE, GLITCH_DETECTOR_ENABLE/SENS
Rows 0x48–0x4A  : BOOT_FLAGS0 (RBIT-3) — boot path control
Rows 0x4B–0x4D  : BOOT_FLAGS1 (RBIT-3) — KEY_INVALID flags
Rows 0x80–0x8F  : BOOTKEY0 (ECC) — SHA-256 hash of secp256k1 signing public key
```

**RBIT-8**: CRIT0 and CRIT1 each store 8 identical copies.  The ROM does a
majority vote across all copies.  Always use `picotool otp set OTP_DATA_CRIT1.*`
(which writes all 8 copies) — do NOT write individual rows manually.

### Step 1: Generate per-device key material

Each device needs unique random IKM (Input Keying Material). This is the
seed for the Storage Master Key that encrypts all keys in flash.

```bash
# Generate 64 bytes of random IKM
openssl rand 64 > device-001-ikm.bin

# Record the hex for your production database
xxd -p -c 64 device-001-ikm.bin
```

### Step 2: Write IKM to OTP

> **Warning: provisioning loses every key already on the board.** The
> storage key is derived from the IKM, so once the IKM is written, the
> keystore written before (under the public development key) can no
> longer be opened. Export anything you need first (DKEK-wrapped key
> export, or keep the keys on a domain peer), then re-INITIALIZE after
> provisioning and import it again. OTP writes are permanent; this step
> cannot be undone.

The IKM must be written to OTP rows 0x100–0x11F as ECC-protected words.
This can be done via:

**Option A: Provisioning APDU** (through the running firmware)

The firmware's `Otp::write_storage_key_material()` function writes the IKM
to OTP. This is called via a provisioning APDU sequence that requires
SO-PIN authentication. The exact APDU depends on the provisioning command
set.

**Option B: picotool OTP write** (in BOOTSEL mode)

```bash
# Write IKM bytes to ECC rows 0x100–0x11F
# picotool otp set requires the device to be in BOOTSEL mode
picotool otp set 0x100 --ecc --input-file device-001-ikm.bin
```

### Step 3: Verify OTP was written correctly

```bash
picotool otp get 0x100 0x11F --ecc
```

Compare the output byte-by-byte with your IKM file. OTP fuses can
(rarely) fail to blow — if any byte mismatches, **discard the device**.

### Step 4: Program the boot signing key hash

Load the OTP JSON produced by `picotool seal` in Phase 3:

```bash
picotool otp load dist/pico2hsm-otp.json
```

This burns:
- **Boot key hash** (BOOTKEY0, rows 0x80–0x8F): SHA-256 of your secp256k1 public key
- **Boot flags**: key-valid flag

---

## Phase 6: Enable Secure Boot (Point of No Return)

**Once secure boot is enabled, only firmware signed with your private key
will ever boot on this device.** Ensure the signed firmware boots correctly
before proceeding.

### Pre-check

1. Reboot the device and verify it enumerates as a CCID reader
2. Run the integration test suite to confirm functionality
3. Verify OTP key hash matches your intended public key fingerprint

### Enable secure boot

SECURE_BOOT_ENABLE is bit 0 of **CRIT1** (OTP rows 0x40–0x47, RBIT-8).
It is NOT in BOOT_FLAGS0 (row 0x48) or CRIT0 (row 0x38).

Use picotool's field-name syntax — this automatically writes all 8
RBIT-8 copies:

```bash
# Enable secure boot (CRIT1 bit 0, all 8 copies):
picotool otp set OTP_DATA_CRIT1.SECURE_BOOT_ENABLE 1
```

Do NOT write raw row numbers for CRIT1 — `picotool otp set 0x40 0x01`
would only write 1 of 8 copies, which is unreliable.

### Set production mode flag

```bash
# Via firmware APDU (Otp::set_production_mode()):
# This sets bits 1+2 of the boot flags row 0x140 (PRODUCTION_MODE + PROVISIONED)
# Requires SO-PIN authentication
```

### Verify secure boot works

```bash
# Reboot and verify the device still boots:
picotool reboot
sleep 3
opensc-tool --list-readers
```

If the device does not enumerate, the signed firmware has a defect or the
wrong key hash was burned. If JTAG is still enabled, you can recover via
SWD. If JTAG is already disabled, the device is bricked.

---

## Phase 7: Disable JTAG (Absolute Point of No Return)

**This is irreversible.** Once executed, no debugger can ever connect to
this device. If the firmware has a defect, the device cannot be recovered.

### Pre-check (mandatory)

Before disabling JTAG, verify **all** of the following:

- [ ] Signed firmware boots correctly (multiple power cycles)
- [ ] USB CCID enumeration works
- [ ] Integration tests pass
- [ ] OTP key material is written and verified
- [ ] Secure boot is enabled and verified
- [ ] Production mode flag is set

### Disable JTAG

The hardware JTAG disable fuse is **CRIT1.DEBUG_DISABLE** (bit 2, OTP
rows 0x40–0x47, RBIT-8).  The pico2hsm firmware also records a user-land
bookkeeping flag in boot flags row 0x140, bit 0.

```bash
# Hardware JTAG disable (ROM-enforced, all 8 RBIT-8 copies):
picotool otp set OTP_DATA_CRIT1.DEBUG_DISABLE 1

# Also disable secure debug access:
picotool otp set OTP_DATA_CRIT1.SECURE_DEBUG_DISABLE 1

# Enable glitch detector at maximum sensitivity:
picotool otp set OTP_DATA_CRIT1.GLITCH_DETECTOR_ENABLE 1
picotool otp set OTP_DATA_CRIT1.GLITCH_DETECTOR_SENS 3

# pico2hsm user-land flag (set automatically by firmware at next boot
# when production mode is active):
# Row 0x140 bit 0 = JTAG_DISABLED (bookkeeping only)
```

**Important**: CRIT1 fields (DEBUG_DISABLE, SECURE_BOOT_ENABLE, etc.)
use RBIT-8 redundancy — always use `picotool otp set OTP_DATA_CRIT1.*`
field-name syntax, never raw row writes.

### Verify SWD is disabled

```bash
picotool reboot
sleep 3

# This should fail:
probe-rs list
# Expected: no RP2350 device detected
```

---

## Phase 8: OTP Row Locking

### Software locks (per-boot session)

On a provisioned device the firmware derives the storage master key at boot
and then sets OTP page 4's SW_LOCK to inaccessible for both Secure and
Non-secure access (`otp::boot_storage_master_key`). For the rest of that
boot neither SWD nor any firmware code can read the IKM or the device
identity key. GET PROVISIONING STATUS reports this as `otp_rows_locked`.
SW_LOCK resets on every power cycle, so it does **not** protect against
reading the OTP from BOOTSEL (`picotool otp get`) before the firmware runs.

```
OTP page 4 (rows 0x100–0x13F): pico2hsm secrets
  - Storage key IKM (0x100–0x11F)
  - Device identity key (0x120–0x12F)
OTP page 5 (rows 0x140–0x17F): boot flags (0x140) — not locked
```

### Permanent OTP locks — NOT YET VALIDATED

Protecting the IKM from BOOTSEL/picotool reads requires burning page 4's
permanent lock rows (OTP_DATA_PAGE4_LOCK0 / PAGE4_LOCK1; see the RP2350
datasheet's OTP chapter for the LOCK_S / LOCK_NS / LOCK_BL fields). The
firmware does not do this, and the exact field values have **not** been
validated on hardware: a wrong value can lock the firmware itself out of its
own key (bricking the keystore) or leave the bootloader path open. Validate
on a sacrificial board before adding it to this procedure. Until then, a
device is only protected against BOOTSEL OTP reads by being physically
secured.

---

## Production Records

For each provisioned device, record:

```
Device Serial:        <unique identifier>
Board Type:           <feature flag used>
Firmware Version:     v1.0.0
Signing Key Hash:     <SHA-256 fingerprint from Phase 1>
IKM (64 bytes):       <hex dump — store encrypted>
Provisioning Date:    <ISO 8601 timestamp>
Secure Boot:          ENABLED / DISABLED
JTAG:                 ENABLED / DISABLED
Production Mode:      ENABLED / DISABLED
```

**Backup IKM records** in encrypted storage at geographically separated
locations. The IKM is needed if you ever need to migrate key material
(which is not currently supported but may be in future firmware versions).

---

## Recovery and Failure Scenarios

### Before JTAG disable: full recovery possible

```bash
# Full flash erase via SWD:
probe-rs erase --chip RP235x

# Or via BOOTSEL:
picotool load dist/pico2hsm-signed.elf -t elf -x
```

### After JTAG disable: no recovery

Once JTAG is disabled, the RP2350 bootrom refuses all debug connections.
There is no:
- Hardware debugger bypass
- Fuse unblowing mechanism
- Bootloader recovery mode

A device bricked after JTAG disable must be physically discarded.

### Wrong key hash burned + secure boot enabled

If the wrong public key hash was written to OTP before enabling secure
boot, the device will only boot firmware signed with the wrong key. If you
still have JTAG access, reflash via SWD. If JTAG is disabled, the device
is bricked.

**Prevention:** Always verify the OTP key hash matches your intended
fingerprint before enabling secure boot.

### OTP write failure

RP2350 OTP fuses can rarely fail to blow. Always read back and verify
every OTP write. If any byte mismatches, discard the device — partial OTP
writes cannot be corrected.

---

## Provisioning Checklist

```
PHASE 1 — KEY GENERATION (air-gapped machine, once)
  [ ] Generate secp256k1 key pair
  [ ] Record SHA-256 fingerprint
  [ ] Store private key in offline vault
  [ ] Distribute public key to build machines

PHASE 2–3 — BUILD & SIGN (build machine)
  [ ] Build release firmware for target board
  [ ] Sign with picotool seal
  [ ] Verify dist/pico2hsm-signed.elf and dist/pico2hsm-otp.json exist

PHASE 4 — FLASH
  [ ] Flash signed firmware via BOOTSEL or SWD
  [ ] Verify USB CCID enumeration
  [ ] Run smoke test (SELECT AID, VERIFY PIN)

PHASE 5 — OTP PROVISIONING
  [ ] Generate per-device IKM (64 bytes random)
  [ ] Write IKM to OTP rows 0x100–0x11F
  [ ] Verify IKM readback matches
  [ ] Load OTP JSON (boot key hash + flags)
  [ ] Verify boot key hash in OTP

PHASE 6 — SECURE BOOT (irreversible)
  [ ] picotool otp set OTP_DATA_CRIT1.SECURE_BOOT_ENABLE 1
  [ ] Reboot and verify device still boots
  [ ] Run full integration test suite

PHASE 7 — PRODUCTION MODE
  [ ] Set PRODUCTION_MODE via firmware APDU
  [ ] Verify boot flags (OTP row 0x140)

PHASE 8 — JTAG DISABLE (irreversible)
  [ ] Final verification: all tests pass
  [ ] Final verification: multiple power cycles succeed
  [ ] picotool otp set OTP_DATA_CRIT1.DEBUG_DISABLE 1
  [ ] picotool otp set OTP_DATA_CRIT1.SECURE_DEBUG_DISABLE 1
  [ ] picotool otp set OTP_DATA_CRIT1.GLITCH_DETECTOR_ENABLE 1
  [ ] picotool otp set OTP_DATA_CRIT1.GLITCH_DETECTOR_SENS 3
  [ ] Verify probe-rs cannot connect
  [ ] Reboot — firmware sets pico2hsm bookkeeping flag (row 0x140 bit 0)

PHASE 9 — RECORDS
  [ ] Record device serial, IKM, dates in production database
  [ ] Encrypt and backup provisioning records
```

---

## References

- [RP2350 Datasheet](https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf) — OTP layout (§5.4), secure boot (§5.6), CRIT1 (§5.6.4)
- [pico-sdk otp_data.h](https://github.com/raspberrypi/pico-sdk/blob/develop/src/rp2350/hardware_regs/include/hardware/regs/otp_data.h) — authoritative OTP row definitions
- [rp2350_hacking_challenge lock_chip.sh](https://github.com/raspberrypi/rp2350_hacking_challenge) — known-working picotool provisioning commands
- [picotool](https://github.com/raspberrypi/picotool) — firmware signing, OTP programming (handles RBIT-8 automatically)
- `firmware/src/security/otp.rs` — pico2hsm OTP row constants and access functions
- `firmware/src/security/boot.rs` — secure boot status checks
- `generate_firmware_signing_keys.sh` — key generation script
- `docs/SECURE_PROVISIONING_PLAN.md` — detailed design rationale and threat model
