# pico2hsm Testing Procedure — RC2 Release Validation

This document describes the complete testing procedure for validating a pico2hsm
release candidate. It covers firmware unit tests, hardware integration tests,
multi-applet validation, and security-specific checks.

---

## Prerequisites

- One or more pico2hsm devices (Pico 2 4MB, RP2350-One, RP2350-Geek, or Waveshare LCD), each with its partition table installed (`docs/FLASH_LAYOUT_2_0.md` §4)
- Debugprobe (CMSIS-DAP) for SWD flashing (or BOOTSEL mode with `picotool`)
- Linux host with: `pcscd`, `opensc`, `opensc-tool`, `pkcs15-tool`, `pkcs11-tool`
- Python 3.10+ with `pip`
- Rust toolchain with `thumbv8m.main-none-eabihf` target
- `probe-rs` for debug flashing, or `picotool` for BOOTSEL flashing

---

## Phase 1: Firmware Unit Tests

These run on the host (x86_64), not on hardware. They validate all pure-logic
paths including crypto, TLV parsing, APDU dispatch, DKEK wrap/unwrap, and PIN
handling.

```sh
cd firmware
cargo test --target x86_64-unknown-linux-gnu --no-default-features \
    --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519
```

**Expected:** All tests pass. Zero failures. (CI also runs the library tests
for every board, with and without `rsa`.)

Check for specific security-critical tests:
```sh
cargo test --target x86_64-unknown-linux-gnu --no-default-features \
    --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519 2>&1 \
  | grep -E "test_reinit_wrong_sopin|test_challenge_cache|debug_module_gated"
```

**Expected:** All three present and passing:
- `test_reinit_wrong_sopin_rejected` — constant-time SO-PIN comparison
- `test_challenge_cache_full_rotation` — replay cache ring buffer
- `debug_module_gated` — debug module excluded from non-`debug` builds

---

## Phase 2: Build All Board Variants

Verify that all 7 board variants compile in both debug and release profiles.

```sh
./build-all.sh          # Release builds of 6 variants (rp2350_one_16m is not in its list)

# The seventh release build, and the debug builds (build-all-debug.sh
# always flashes, so build them with cargo):
cargo build --release -p pico2hsm-firmware --no-default-features \
    --features rp2350_one_16m,rsa,applet-piv,applet-openpgp-curve25519
for b in pico2_4m rp2350_one_4m rp2350_one_16m rp2350_geek_16m rp2350_geek_sdcard \
         waveshare_rp2350_lcd_16m waveshare_rp2350_lcd_sdcard; do
  cargo build -p pico2hsm-firmware --no-default-features \
      --features $b,rsa,applet-piv,applet-openpgp-curve25519 || echo "FAIL $b"
done
```

**Expected:** All 14 builds succeed (7 release + 7 debug). Check that no
variant has a linker error or feature-flag conflict.

### RAM budget check

After release builds, check static RAM (`.data` + `.bss` + `.uninit`)
against the 520 KB SRAM; core0's stack gets the rest:

```sh
for elf in dist/pico2hsm-*.elf; do
  echo "=== $(basename $elf) ==="
  arm-none-eabi-size -A "$elf" | awk '/^\.(data|bss|uninit) /{r+=$2} END{printf "  static RAM=%d KB\n", r/1024}'
done
```

**Expected:** Well under 520 KB for all variants. Measured 2026-10-15: the
worst case is `rp2350_one_16m` at ~254 KB (49%; `docs/BUILD_CONFIGURATIONS.md`).

---

## Phase 3: Hardware Integration Tests

Flash debug firmware to a device, then run the full integration test suite.

### 3.1 Flash and boot

```sh
# Terminal 1: build, flash, and stream RTT
./build-all-debug.sh pico2_4m

# Wait ~5 seconds for USB re-enumeration

# Terminal 2: verify device is visible
opensc-tool --list-readers
```

**Expected:** At least one reader shows `pico2hsm SC-HSM`.

### 3.2 Run full test suite

```sh
./run_tests.sh
```

**Expected:** every test passes or skips with a stated reason. Known acceptable results:
- `xfail` on secp256k1 ECDH (OpenSC limitation, not a firmware bug)
- `skip` on tests requiring second device or specific board features

### 3.3 Run without RSA (faster iteration)

```sh
./run_tests.sh --no-rsa
```

**Expected:** Same pass rate, minus RSA keygen/sign/decrypt tests. Runs in ~2
minutes instead of ~45 minutes.

### 3.4 Run specific test modules

```sh
# Basic ops: keygen, sign, ECDH
./run_tests.sh -k "test_01 or test_02 or test_03"

# PIV applet
./run_tests.sh -k "test_piv"

# OpenPGP applet
./run_tests.sh -k "test_openpgp"

# DKEK exchange (two devices) and wrap/unwrap
./run_tests.sh -k "test_10 or test_11"

# PIN lifecycle
./run_tests.sh -k "test_12"

# Security state isolation
./run_tests.sh -k "test_13"

# Persistence across resets, the 2.0 layout, store recovery
./run_tests.sh -k "test_14 or test_22 or test_21"
```

The file list is `tests/hw/test_*.py`; `test_21_store_recovery.py` needs a
`debug` build (`EXTRA_FEATURES=debug ./build-all-debug.sh <board>`).

---

## Phase 4: Multi-Applet Validation

The device supports SC-HSM, PIV, and OpenPGP applets simultaneously. Validate
that applet selection works correctly and keys are isolated by namespace.

### 4.1 SC-HSM (default applet)

```sh
# List keys
pkcs15-tool -D

# Generate EC P-256 key
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
  --keypairgen --key-type EC:prime256v1 --id 01 --label "test-p256" \
  --login --pin 648219
```

### 4.2 PIV (if built with applet-piv)

```sh
# Select PIV applet
opensc-tool -s "00 A4 04 00 0B A0 00 00 03 08 00 00 10 00 01 00"

# Read PIV discovery object
opensc-tool -s "00 CB 3F FF 05 5C 03 7E 20 00"
```

### 4.3 OpenPGP (if built with applet-openpgp)

```sh
# Select OpenPGP applet
opensc-tool -s "00 A4 04 00 06 D2 76 00 01 24 01"

# Read application related data
opensc-tool -s "00 CA 00 6E 00"
```

### 4.4 Applet isolation

After operations on PIV/OpenPGP, re-select SC-HSM and verify keys are intact:

```sh
# Re-select SC-HSM
opensc-tool -s "00 A4 04 00 0B E8 2B 06 01 04 01 81 C3 1F 02 01"

# Verify SC-HSM keys still present
pkcs15-tool -D
```

---

## Phase 5: Security-Specific Checks

### 5.1 NO_EXPORT flag enforcement

Generate a key with NO_EXPORT, then attempt export:

```sh
# Tested in test_14 (the flag survives a reset) and test_16 (EXPORT KEY
# without the PIN)
./run_tests.sh -k "test_no_export_flag_persists or test_export_key_without_pin"
```

### 5.2 PIN retry counter

Verify that wrong PINs decrement the retry counter and that lockout works:

```sh
./run_tests.sh -k "test_12"
```

### 5.3 Security state reset on SELECT AID

Verify that authentication state is cleared when switching applets:

```sh
./run_tests.sh -k "test_13"
```

### 5.4 Debug module excluded from release

Verify that release builds do not include debug_dump functionality:

```sh
# The debug dump (SC-HSM INS 0xFE) is compiled only with the `debug` feature
cargo test --target x86_64-unknown-linux-gnu --no-default-features \
  --features pico2_4m debug_module_gated 2>&1 | grep -i "ok\|FAILED"
```

---

## Phase 6: Python Daemon Smoke Test

### 6.1 Package installable

```sh
cd tools/python
pip install -e .
python -c "from pico2hsm import daemon, dkek, tls; print('OK')"
```

### 6.2 TLS identity generation

```sh
python3 -c "
from pathlib import Path
from pico2hsm.tls import ensure_daemon_identity
import tempfile
d = Path(tempfile.mkdtemp())
cert, key = ensure_daemon_identity(d)
print(f'cert={cert} exists={cert.exists()}')
print(f'key={key} exists={key.exists()}')
# Verify it's ECDSA P-256
from cryptography import x509
c = x509.load_pem_x509_certificate(cert.read_bytes())
print(f'algo={c.signature_algorithm_oid._name}')
print(f'subject={c.subject}')
"
```

**Expected:**
```
algo=ecdsa-with-SHA256
subject=<Name(CN=pico2hsm-daemon)>
```

---

## Phase 7: Cargo Audit

```sh
cargo audit
```

**Expected:** No known vulnerabilities in dependencies. Advisory warnings for
unmaintained crates are acceptable if no alternative exists.

---

## Test Result Summary Template

| Phase | Result | Notes |
|-------|--------|-------|
| 1. Unit tests | PASS / FAIL | _count_ tests |
| 2. All variants build | PASS / FAIL | 7 release + 7 debug |
| 3. HW integration | PASS / FAIL | _count_ pass / _count_ skip / _count_ xfail |
| 4. Multi-applet | PASS / FAIL | SC-HSM + PIV + OpenPGP |
| 5. Security checks | PASS / FAIL | NO_EXPORT, PIN, state reset, debug gate |
| 6. Python daemon | PASS / FAIL | install + TLS identity |
| 7. Cargo audit | PASS / FAIL | advisory count |

---

## Next: Phase 2 Pentest

After RC2 public testing, the next security milestone is an external pentest
covering:

1. **Black-box APDU fuzzing** — Send malformed, truncated, and oversized APDUs
   to exercise all INS handlers. Verify no hangs, panics, or unexpected SW codes.
2. **Side-channel analysis** — Validate constant-time PIN comparison and PKCS#7
   padding on real hardware using timing measurements or power analysis.
3. **TLS configuration review** — Verify daemon TLS in CA-authenticated mode
   with real CA infrastructure.
4. **Provisioning subsystem** — Test the secure boot chain, OTP locking and
   the debug-access choice on production hardware (`docs/PROVISIONING.md`).

See `docs/SECURITY_SUMMARY.md` for the complete resolved issues list and
recommendations.
