# pico2hsm Test Plan and Specification

## Overview

pico2hsm is a SmartCard-HSM 2 compatible Hardware Security Module implemented in Rust
for the RP2350 microcontroller. It presents itself over USB CCID and is compatible with
OpenSC, pkcs11-tool, and any PKCS#11 application.

This document defines what the device **must** do, and how to verify each capability.

---

## Test Environment

### Hardware
- Raspberry Pi Pico 2 (or any supported board), with its partition table installed
- USB connection to Linux host
- A debug build (`./build-all-debug.sh <board>`) or a provisioned board: a
  release build on blank OTP has its keystore disabled

### Host Software
- `opensc` (provides `sc-hsm-tool`, `pkcs11-tool`, `opensc-tool`)
- `pcscd` (PC/SC daemon)
- `pcsc_scan` (ATR scanner)
- `openssl` (signature verification)
- `cargo test --target x86_64-unknown-linux-gnu` (unit/integration tests, §11)
- `pytest` (`tests/hw/`, run through `./run_tests.sh`)

### Device State Conventions
- **Factory fresh** — never initialized, all storage blank
- **Initialized** — INITIALIZE completed, User PIN set
- **Authenticated** — VERIFY PIN succeeded in current session

### Default Test Credentials
| Credential | Value |
|---|---|
| User PIN | `648219` |
| SO-PIN | `3537363231383830` (hex, 8 bytes) |
| Device Label | `pico2hsm-test` |
| Init code | `57621880` (decimal) |

---

## 1. USB Enumeration and Transport

### 1.1 USB CCID Enumeration

**Spec:** Device must enumerate as a USB CCID smart card reader with the correct
vendor/product identifiers and class descriptors.

**Test:**
```bash
lsusb | grep -i "smart\|ccid\|pico"
```
**Pass:** Device appears in lsusb output. `pcscd` starts without errors.

---

### 1.2 ATR Verification

**Spec:** The Answer-to-Reset must be exactly:
```
3B FE 18 00 00 81 31 FE 45 80 31 81 54 48 53 4D 31 73 80 21 40 81 07 FA
```
This is the SmartCard-HSM 2 ATR that causes OpenSC to bind the `sc-hsm` driver.

**Test:**
```bash
pcsc_scan
```
**Pass:** ATR shown matches the 24-byte sequence above.

---

### 1.3 CCID Bulk Transfer Framing

**Spec:** All CCID messages (header + payload) must be sent as a single USB bulk write.
A short packet (< max packet size) signals end-of-transfer.

**Test:** Verified implicitly by all APDU tests succeeding without framing errors.

---

## 2. Application Identification

### 2.1 SELECT SC-HSM AID

**Spec:** SELECT with the SC-HSM AID (`E8 2B 06 01 04 01 81 C3 1F 02 01`) must succeed
with `90 00` and return FCI containing:
- Tag `6F` wrapping:
  - Tag `84` — AID (11 bytes)
  - Tag `A5` → Tag `9F6E` — SC-HSM version `02 00 00 00`

**Test:**
```bash
opensc-tool --send-apdu 00A4040007E82B060104018B
opensc-tool --list-readers
sc-hsm-tool --reader 0
```
**Pass:** No error; OpenSC reports SC-HSM driver bound.

---

### 2.2 Unknown AID Rejected

**Spec:** SELECT with an unrecognized AID must return `6A 82` (File Not Found).

**Test:**
```bash
opensc-tool --send-apdu 00A40400050102030405
```
**Pass:** Response is `6A 82`.

---

## 3. Device Initialization

### 3.1 First-Time INITIALIZE

**Spec:** On a factory-fresh device, INITIALIZE (INS=0x50) must:
- Accept any SO-PIN and init code (first-time has no prior credentials)
- Set the device label
- Set User PIN and SO-PIN
- Set PIN retry limits
- Return `90 00`
- Leave device in initialized state (SELECT FCI updated, VERIFY now functional)

**Test:**
```bash
sc-hsm-tool --initialize \
  --label pico2hsm-test \
  --so-pin 3537363231383830 \
  --pin 648219
```
**Pass:** `sc-hsm-tool` exits 0; device is ready for VERIFY.

---

### 3.2 Re-INITIALIZE with Correct SO-PIN

**Spec:** Re-initialization must require the current SO-PIN embedded in the INITIALIZE
command data. A correct SO-PIN wipes the device and re-initializes it. An incorrect
SO-PIN must return `63 Cx` (verification failed, x remaining attempts).

**Test (correct SO-PIN):**
```bash
sc-hsm-tool --initialize \
  --label pico2hsm-test \
  --so-pin 3537363231383830 \
  --pin 648219
```
**Pass:** Returns `90 00`, device reset to fresh initialized state.

**Test (wrong SO-PIN):**
```bash
sc-hsm-tool --initialize \
  --label pico2hsm-test \
  --so-pin FFFFFFFFFFFFFFFF \
  --pin 648219
```
**Pass:** Returns `63 Cx` and state unchanged.

---

### 3.3 INITIALIZE Idempotency

**Spec:** Running INITIALIZE twice with the same parameters must succeed both times
(second run is a re-initialization, not an error).

**Test:** Run `sc-hsm-tool --initialize` twice. Both must exit 0.

---

## 4. PIN Management

### 4.1 VERIFY User PIN (Correct)

**Spec:** VERIFY (INS=0x20) with the correct User PIN must return `90 00` and grant
user-level access for the duration of the logical channel session.

**Test:**
```bash
pkcs11-tool --login --pin 648219 --list-objects
```
**Pass:** Lists objects (or empty list) without authentication error.

---

### 4.2 VERIFY User PIN (Wrong)

**Spec:** VERIFY with incorrect PIN must:
- Return `63 Cx` where x = remaining attempts
- Decrement the retry counter
- Not grant access

**Test:**
```bash
opensc-tool --send-apdu 00200081042222222
```
**Pass:** Response is `63 Cx` with x < initial value.

---

### 4.3 PIN Lockout After Exhausting Retries

**Spec:** After exhausting all PIN retry attempts (default: 3), VERIFY must return
`69 83` (Authentication Method Blocked). The device must remain locked until PUK
authentication or SO-PIN reset retry.

**Test:** Submit wrong PIN 3 times, then attempt a 4th.
**Pass:** 4th attempt returns `69 83`.

---

### 4.4 CHANGE PIN

**Spec:** CHANGE PIN (INS=0x24) must change the User PIN when the current PIN is
verified. New PIN must be accepted on subsequent VERIFY.

**Test:**
```bash
pkcs11-tool --change-pin --login --pin 648219 --new-pin 111222
pkcs11-tool --login --pin 111222 --list-objects
```
**Pass:** Second command succeeds. Reset PIN back to `648219` after test.

---

### 4.5 RESET RETRY (via SO-PIN)

**Spec:** After PIN lockout, RESET RETRY COUNTER (INS=0x2C) with valid SO-PIN must
reset the retry counter and optionally set a new User PIN.

**Test:** Lock the device with wrong PINs, then:
```bash
sc-hsm-tool --unblock-pin --so-pin 3537363231383830 --new-pin 648219
```
**Pass:** VERIFY with new PIN succeeds.

---

## 5. Key Management

### 5.1 Generate ECC P-256 Key Pair

**Spec:** GENERATE KEYPAIR (INS=0x46) with curve P-256 must:
- Generate a valid ECDSA P-256 key pair on-device
- Store the private key in encrypted storage
- Return the public key as an uncompressed point (04 || X || Y, 65 bytes) in a `7F49` TLV
- Return `90 00`

**Test:**
```bash
pkcs11-tool --login --pin 648219 \
  --keypairgen --key-type EC:prime256v1 \
  --id 01 --label "test-p256"
```
**Pass:** Exits 0; key appears in `pkcs11-tool --list-objects`.

---

### 5.2 Generate ECC P-384 Key Pair

**Spec:** GENERATE KEYPAIR with curve P-384 must produce a valid 384-bit key pair.
Public key is 97 bytes (04 || X || Y).

**Test:**
```bash
pkcs11-tool --login --pin 648219 \
  --keypairgen --key-type EC:secp384r1 \
  --id 02 --label "test-p384"
```
**Pass:** Exits 0; key appears in object list.

---

### 5.3 Generate ECC P-521 Key Pair

**Spec:** GENERATE KEYPAIR with curve P-521 must produce a valid 521-bit key pair.
Public key is 133 bytes (04 || X || Y).

**Test:**
```bash
pkcs11-tool --login --pin 648219 \
  --keypairgen --key-type EC:secp521r1 \
  --id 03 --label "test-p521"
```
**Pass:** Exits 0; key appears in object list.

---

### 5.4 Generate AES Symmetric Key

**Spec:** GENERATE KEY (INS=0x48) must generate and store an AES-256 secret key.
The key must be stored encrypted and retrievable (for wrap/unwrap) but not exportable
in plaintext without DKEK authorization.

**Test:**
```bash
pkcs11-tool --login --pin 648219 \
  --keygen --key-type AES:32 \
  --id 10 --label "test-aes256"
```
**Pass:** Exits 0; key appears in object list as `Secret Key`.

---

### 5.5 Key Persistence Across Reset

**Spec:** Keys generated must survive a device power cycle (USB reconnect). All key
objects must still be present and usable after re-enumeration.

**Test:**
1. Generate a P-256 key pair
2. Physically disconnect and reconnect the device
3. Enumerate keys

```bash
pkcs11-tool --login --pin 648219 --list-objects
```
**Pass:** Previously generated key is still present.

---

### 5.6 Delete Key

**Spec:** DELETE FILE (INS=0xE4) targeting a key object must remove the key from
storage. Subsequent operations referencing that key ID must return `6A 82`.

**Test:**
```bash
pkcs11-tool --login --pin 648219 --delete-object --type privkey --id 01
pkcs11-tool --login --pin 648219 --list-objects
```
**Pass:** Key with id 01 no longer appears.

---

### 5.7 LIST KEYS

**Spec:** LIST KEYS (INS=0x58, P2=0x00) must return a list of all key object IDs
currently stored in the device.

**Test:**
```bash
sc-hsm-tool --list-objects --pin 648219
```
**Pass:** All generated keys appear; deleted keys do not.

---

## 6. Cryptographic Operations

### 6.1 ECDSA P-256 Sign and Verify

**Spec:** COMPUTE DIGITAL SIGNATURE (INS=0x68) with a P-256 key and ECDSA algorithm
must produce a valid DER-encoded ECDSA signature that verifies against the public key.

**Test:**
```bash
# Sign a 32-byte SHA-256 digest
echo -n "test message for signing" | sha256sum | xxd -r -p > /tmp/digest.bin
pkcs11-tool --login --pin 648219 \
  --sign --id 01 --mechanism ECDSA \
  --input-file /tmp/digest.bin \
  --output-file /tmp/sig.bin

# Extract public key and verify
pkcs11-tool --login --pin 648219 \
  --read-object --type pubkey --id 01 \
  --output-file /tmp/pubkey.der
openssl dgst -sha256 -verify /tmp/pubkey.der \
  -signature /tmp/sig.bin \
  <(echo -n "test message for signing")
```
**Pass:** `openssl dgst` outputs `Verified OK`.

---

### 6.2 ECDSA P-384 Sign and Verify

**Spec:** Same as 6.1 but with P-384 key and SHA-384 digest (48 bytes).

**Test:** Same procedure with key id 02 and `sha384sum`.
**Pass:** `openssl dgst -sha384` outputs `Verified OK`.

---

### 6.3 ECDSA P-521 Sign and Verify

**Spec:** Same as 6.1 but with P-521 key and SHA-512 digest (64 bytes).

**Test:** Same procedure with key id 03 and `sha512sum`.
**Pass:** `openssl dgst -sha512` outputs `Verified OK`.

---

### 6.4 ECDH Key Agreement (Decrypt / Derive)

**Spec:** DECRYPT (INS=0x62, P1=0x00) with ECDH algorithm must perform Diffie-Hellman
key agreement given an ephemeral peer public key, producing a shared secret.

**Test:**
```bash
# Generate ephemeral P-256 key pair on host
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out /tmp/ephem.pem
openssl pkey -in /tmp/ephem.pem -pubout -out /tmp/ephem_pub.pem

# Convert to raw 65-byte uncompressed point for PKCS#11 CKM_ECDH1_DERIVE
pkcs11-tool --login --pin 648219 \
  --derive --id 01 --mechanism ECDH1-DERIVE \
  --input-file /tmp/ephem_pub.der
```
**Pass:** Returns 32-byte shared secret without error.

---

### 6.5 AES-CBC Encrypt and Decrypt

**Spec:** CIPHER SYM (INS=0x78) with an AES key must encrypt data in CBC mode and
decrypt it back to the original plaintext.

**Test:**
```bash
pkcs11-tool --login --pin 648219 \
  --encrypt --id 10 --mechanism AES-CBC \
  --input-file /tmp/plaintext.bin \
  --output-file /tmp/ciphertext.bin

pkcs11-tool --login --pin 648219 \
  --decrypt --id 10 --mechanism AES-CBC \
  --input-file /tmp/ciphertext.bin \
  --output-file /tmp/decrypted.bin

diff /tmp/plaintext.bin /tmp/decrypted.bin
```
**Pass:** `diff` shows no differences.

---

### 6.6 GET CHALLENGE (Random)

**Spec:** GET CHALLENGE (INS=0x84) must return 8 bytes of random data from the TRNG.
Repeated calls must return statistically distinct values.

**Test:**
```bash
opensc-tool --send-apdu 0084000008
opensc-tool --send-apdu 0084000008
opensc-tool --send-apdu 0084000008
```
**Pass:** Three responses are all different (probability of collision is 1/2^64).

---

### 6.7 BIP32 / SLIP-0010 HD Key Derivation

**Spec:** BIP/SLIP (INS=0x60) must derive a child key from a parent key following
BIP32 or SLIP-0010 derivation. Derived keys must be deterministic for the same
derivation path.

**Test:**
1. Import a known BIP32 seed as a raw key
2. Derive child key at path `m/44'/0'/0'/0/0`
3. Verify derived public key matches known reference vector

**Pass:** Derived public key matches BIP32 test vector.

---

## 7. File System Operations

### 7.1 READ BINARY — PKCS#15 Files

**Spec:** READ BINARY (INS=0xB0) must return correct contents for standard PKCS#15
files including:
- `EF.DIR` (AID directory)
- `EF.ATR` (ATR data)
- `EF.TokenInfo` (SC-HSM token information)
- `EF.OD` (object directory)

**Test:**
```bash
opensc-tool --list-files
sc-hsm-tool --reader 0 --info
```
**Pass:** Files are readable; token info shows correct label and serial.

---

### 7.2 WRITE DATA / UPDATE BINARY

**Spec:** WRITE DATA (INS=0xD7) must store opaque data files (e.g., certificates,
`EF.C.DevAut`). Subsequent READ BINARY must return exactly the written data.

**Test:** This is exercised by `sc-hsm-tool --initialize` which writes `EF.C.DevAut`.
**Pass:** `sc-hsm-tool --info` can read back device certificate data after initialize.

---

### 7.3 DELETE FILE

**Spec:** DELETE FILE (INS=0xE4) must remove a file. Subsequent READ BINARY or SELECT
of that file must return `6A 82`.

**Test:** Covered by key deletion test (5.6).

---

## 8. DKEK (Device Key Encryption Key)

### 8.1 DKEK Import via the DKEK exchange

**Spec:** The DKEK exchange (EXTRAS INS=0x54, P1=0x35–0x38; P-256 ECDH, HKDF,
AES-256-GCM — a simplified Noise-like protocol, not Noise_XX) must move a
DKEK from one device to an enrolled peer, with the SO-PIN, and never
overwrite a DKEK that is already set.

**Test:** `tests/hw/test_10_cluster_dkek_exchange.py` (two devices) and
`tests/hw/test_11_dkek_roundtrip.py`; the `hsm-tool` CLI lives in the
separate `pico2hsm-tool` repository.

---

### 8.2 Key Export Under DKEK

**Spec:** EXPORT KEY (INS=0x34) must export a key object wrapped under the DKEK,
such that it can be imported into another device with the same DKEK.

**Test:**
```bash
sc-hsm-tool --wrap-key --pin 648219 --key-reference 1 \
  --output-file wrapped_key.bin
```
**Pass:** `wrapped_key.bin` is written; file is non-empty.

---

### 8.3 Key Import Under DKEK

**Spec:** IMPORT KEY (INS=0x58, P2=0x93) must import a DKEK-wrapped key and make it
usable for signing/decryption operations.

**Test:**
```bash
sc-hsm-tool --unwrap-key --pin 648219 --key-reference 5 \
  --input-file wrapped_key.bin
pkcs11-tool --login --pin 648219 --list-objects
```
**Pass:** Imported key appears in key list; can be used for signing.

---

## 9. Security Properties

### 9.1 Storage Encryption at Rest

**Spec:** All key material stored in flash must be encrypted with AES-256-GCM using
a Storage Master Key (SMK) derived from OTP-resident root secret. Recovering a flash
dump without the OTP key must yield only ciphertext.

**Verification:** Offline / code review — confirmed by architecture (see `security/otp.rs`
`derive_smk`, `storage/keystore_v2.rs`, `storage/store_v2.rs`, `security/key_management.rs`).

---

### 9.2 PIN Retry Counter Decremented Before Comparison

**Spec:** The retry counter must be decremented (and flushed to storage) **before** the
PIN comparison is performed. This prevents timing attacks from power-cycling the device
mid-comparison to avoid counter decrement.

**Verification:** Code review — every credential check goes through
`with_persisted_attempt` (SC-HSM, PIV, OpenPGP), which spends the attempt in
the counter log (`storage/retry_counter.rs`) before the comparison.

---

### 9.3 Constant-Time PIN Comparison

**Spec:** PIN comparison must use `subtle::ConstantTimeEq` (or equivalent) to prevent
timing side-channel attacks.

**Verification:** Code review — grep for `ct_eq` or `ConstantTimeEq` in `security/pin.rs`.

---

### 9.4 Secret Key Zeroization

**Spec:** All types holding secret key material must implement `ZeroizeOnDrop`. When a
key object is dropped, its memory must be zeroed.

**Verification:** Code review — `security/zeroize.rs` + grep for `ZeroizeOnDrop` on
key structs.

---

### 9.5 Operations Require Authentication

**Spec:** SIGN, DECRYPT, GENERATE KEYPAIR, GENERATE KEY, EXPORT KEY, and IMPORT KEY
must all return `69 82` (Security Status Not Satisfied) if called before a successful
VERIFY.

**Test:**
```bash
# Without prior VERIFY:
pkcs11-tool --keypairgen --key-type EC:prime256v1 --id 99 --label "no-auth"
```
**Pass:** Returns `69 82` or equivalent PKCS#11 error.

---

### 9.6 JTAG Disabled After Provisioning

**Spec:** Where the owner chose to disable debug in provisioning stage 9
(`CRIT1.DEBUG_DISABLE`, `docs/PROVISIONING.md` §6; leaving debug enabled or
key-protected are the other options), the device must not respond on the
SWD port. In production mode the firmware itself halts at boot when a
debugger is attached.

**Verification:** Hardware probe — SWD attach returns error after provisioning.
(Note: This test is irreversible. Only perform on a production device, not a dev unit.)

---

## 10. Storage Durability

### 10.1 Power Loss During a Keystore Write

**Spec:** If power is interrupted during a write, the Storage V2 journal must
mount on the next boot in a consistent state: either the old or the new
object, never a corrupt one, and the anchor in the counter log must still
match (`docs/STORAGE_V2.md` §6, §9).

**Test:** host fault-injection tests in `firmware/src/storage/store_v2_tests.rs`
(a write cut at every step, then a remount). The SD power-pull campaign on
hardware is still to do (`docs/STORAGE_V2.md`, phase 7).

**Pass:** Every cut remounts; either old state or new state is present.

---

### 10.2 Refused Store and Recovery

**Spec:** A store whose journal is behind its anchor, or whose binding does
not verify, is refused rather than mounted; STORE STATUS, OPEN DEGRADED,
ACCEPT STORE and FORMAT STORE recover it (`docs/KEYSTORE_RECOVERY.md`).

**Test:** `tests/hw/test_21_store_recovery.py` (needs a `debug` build:
`80 FE 13` moves the anchor ahead) and the host tests in
`firmware/src/protocol/sc_hsm/store_recovery_tests.rs`.

---

## 11. Unit and Integration Tests (cargo test)

These tests run on x86_64 and do not require hardware. `.cargo/config.toml`
defaults to the thumbv8m target, so every command needs
`--target x86_64-unknown-linux-gnu` and a board feature, e.g.:

```bash
cargo test --manifest-path firmware/Cargo.toml --test crypto_tests \
    --no-default-features --features pico2_4m,rsa,applet-piv,applet-openpgp-curve25519 \
    --target x86_64-unknown-linux-gnu
```

The library's own unit tests (`--lib`) are the bulk of the host tests;
CI runs them for every board (`.github/workflows/build.yml`).

### 11.1 Crypto Algorithm Correctness

```bash
cargo test --manifest-path firmware/Cargo.toml --test crypto_tests <features, --target as above>
```

**Must pass:**
- ECDSA P-256/384/521 sign/verify round-trips
- ECDH shared-secret agreement
- AES-GCM encrypt/decrypt with known test vectors
- AES-CBC round-trip
- ChaCha20-Poly1305 round-trip
- HKDF-SHA256 against RFC 5869 test vectors
- PBKDF2-HMAC-SHA256 against RFC 6070 test vectors
- SHA-256/384/512 against NIST test vectors
- BIP32 child key derivation against BIP32 test vectors
- SLIP-0010 derivation against SLIP-0010 test vectors

---

### 11.2 APDU Dispatcher

```bash
cargo test --manifest-path firmware/Cargo.toml --test apdu_integration <features, --target as above>
```

**Must pass:**
- SELECT AID routes to SC-HSM protocol handler
- Unknown AID returns `6A 82`
- Case 1/2/3/4 APDU parsing round-trips
- Malformed APDU (truncated header) returns `6700`

---

### 11.3 PIN Logic

```bash
cargo test --manifest-path firmware/Cargo.toml --test pin_tests <features, --target as above>
```

**Must pass:**
- Correct PIN returns success, retry counter unchanged
- Wrong PIN decrements counter, returns `63 Cx`
- Counter exhaustion returns `69 83`
- Counter reset via PUK restores access

---

### 11.4 Key Management

```bash
cargo test --manifest-path firmware/Cargo.toml --test key_management_tests <features, --target as above>
```

**Must pass:**
- Key serialization/deserialization round-trip
- Key type validation rejects invalid types
- Key storage slot allocation and retrieval

---

### 11.5 DKEK Tests

```bash
cargo test --manifest-path firmware/Cargo.toml --test dkek_tests <features, --target as above>
```

**Must pass:**
- DKEK exchange handshake completes (both sides simulated; P-256 ECDH, not Noise_XX)
- DKEK key wrap/unwrap is reversible
- Wrong DKEK yields authentication error on unwrap

---

## 12. OpenSC End-to-End Compatibility

### 12.1 Full sc-hsm-tool Initialize Flow

```bash
sc-hsm-tool --initialize --label pico2hsm-test \
  --so-pin 3537363231383830 --pin 648219
sc-hsm-tool --info
```
**Pass:** Both commands exit 0.

---

### 12.2 pkcs11-tool Full Key Lifecycle

```bash
# Generate
pkcs11-tool --login --pin 648219 \
  --keypairgen --key-type EC:prime256v1 --id 01 --label key01

# List
pkcs11-tool --login --pin 648219 --list-objects

# Sign
echo "hello" | sha256sum | xxd -r -p > /tmp/h.bin
pkcs11-tool --login --pin 648219 --sign --id 01 \
  --mechanism ECDSA --input-file /tmp/h.bin --output-file /tmp/s.bin

# Verify (extract public key first)
pkcs11-tool --login --pin 648219 \
  --read-object --type pubkey --id 01 --output-file /tmp/pub.der
openssl dgst -sha256 -verify /tmp/pub.der -signature /tmp/s.bin \
  <(echo "hello")

# Delete
pkcs11-tool --login --pin 648219 --delete-object --type privkey --id 01
```
**Pass:** All steps exit 0; `openssl dgst` reports `Verified OK`.

---

## 13. PIV Applet (NIST SP 800-73-4)

Requires `applet-piv` feature. Tests are in `tests/hw/test_piv_*.py`.

### 13.1 PIV SELECT

**Spec:** SELECT with PIV AID (`A0 00 00 03 08 00 00 10 00 01 00`) must return
SW=9000 with valid FCI. Security state (PIN verified, mgmt key authenticated)
must reset on each SELECT per NIST SP 800-73-4 §3.1.2.

**Test:** `tests/hw/test_piv_00_select.py` — hardware-validated 2026-04-05.

---

### 13.2 PIV GET DATA

**Spec:** GET DATA (INS=0xCB) for standard data objects (CHUID, CCC, X.509
certificate slots) must return correct TLV-encoded responses.

**Test:** `tests/hw/test_piv_00_select.py` (slot listing through PKCS#11) and `tests/hw/test_piv_04_large_object.py` (certificate objects up to the maximum size, PUT/GET DATA) — hardware-validated 2026-04-05.

---

### 13.3 PIV PIN Management

**Spec:** VERIFY (INS=0x20), CHANGE REFERENCE DATA (INS=0x24), RESET RETRY
COUNTER (INS=0x2C) must behave per NIST SP 800-73-4. PIN is flash-persistent
(survives power cycle).

**Test:** `tests/hw/test_piv_01_verify.py`, `tests/hw/test_piv_05_pin_policy.py` — hardware-validated 2026-04-05.

---

### 13.4 PIV GENERAL AUTHENTICATE

**Spec:** GENERAL AUTHENTICATE (INS=0x87) with key ref 9A and P-256 algorithm
must produce a valid DER-encoded ECDSA signature. Calling without prior VERIFY
must return SW=6982.

**Test:** `tests/hw/test_piv_03_auth.py` — hardware-validated 2026-04-05.

---

### 13.5 PIV GENERATE KEY PAIR

**Spec:** GENERATE KEY PAIR (INS=0x47) must return EC public key wrapped in
`7C → 7F49 → 86` TLV per NIST SP 800-73-4 Part 2 Table 3.3-1. Keys are
flash-persistent.

**Test:** `tests/hw/test_piv_02_keygen.py` — hardware-validated 2026-04-05.

---

## 14. OpenPGP Applet (OpenPGP Card 3.4)

Requires `applet-openpgp` feature. Tests are in `tests/hw/test_openpgp_*.py`.

### 14.1 OpenPGP SELECT

**Spec:** SELECT with OpenPGP AID must return correct DOs (6F, 6E, C4, C6).
Security state must reset on each SELECT.

**Test:** `tests/hw/test_openpgp_00_select.py` — hardware-validated 2026-04-05.

---

### 14.2 OpenPGP PIN Management

**Spec:** VERIFY (PW1 modes 82/81 and PW3), CHANGE REFERENCE DATA — PW1 and
PW3 are flash-persistent. PW1 retry counter is RAM-only (resets on power cycle)
per OpenPGP Card 3.4 spec.

**Test:** `tests/hw/test_openpgp_01_verify.py`, `tests/hw/test_openpgp_05_pw1_status.py` — hardware-validated 2026-04-05.

---

### 14.3 OpenPGP Key Generation

**Spec:** GENERATE KEY PAIR for SIG/DEC/AUTH slots must return `7F49 → 86`
uncompressed EC point. Keys are flash-persistent.

**Test:** `tests/hw/test_openpgp_02_keygen.py` — hardware-validated 2026-04-05.

---

### 14.4 OpenPGP PSO:CDS (Sign)

**Spec:** PSO:CDS must return raw r‖s bytes (not DER) for ECDSA as per OpenPGP
Card 3.4 spec. P-256 = 64 bytes, P-384 = 96 bytes.

**Test:** `tests/hw/test_openpgp_03_sign.py` — hardware-validated 2026-04-05.

---

### 14.5 OpenPGP PSO:DECIPHER and INTERNAL AUTHENTICATE

**Spec:** PSO:DECIPHER performs ECDH key agreement. INTERNAL AUTHENTICATE signs
with the AUTH slot key.

**Test:** X25519 PSO:DECIPHER in `tests/hw/test_openpgp_04_curve25519.py`
(with Ed25519 PSO:CDS). There is no automated hardware test of NIST-curve
PSO:DECIPHER or of INTERNAL AUTHENTICATE; the 2026-04-05 validation of
those was manual.

---

## Status Tracker

### SC-HSM (hardware-validated 2026-04-05)

| # | Test | Status |
|---|------|--------|
| 1.1 | USB CCID Enumeration | PASS |
| 1.2 | ATR Verification | PASS |
| 1.3 | CCID Bulk Transfer Framing | PASS |
| 2.1 | SELECT SC-HSM AID | PASS |
| 2.2 | Unknown AID Rejected | PASS |
| 3.1 | First-Time INITIALIZE | PASS |
| 3.2 | Re-INITIALIZE with Correct SO-PIN | PASS |
| 3.3 | INITIALIZE Idempotency | PASS |
| 4.1 | VERIFY User PIN (Correct) | PASS |
| 4.2 | VERIFY User PIN (Wrong) | PASS |
| 4.3 | PIN Lockout | PASS |
| 4.4 | CHANGE PIN | PASS |
| 4.5 | RESET RETRY | PASS |
| 5.1 | Generate P-256 Key Pair | PASS |
| 5.2 | Generate P-384 Key Pair | PASS |
| 5.3 | Generate P-521 Key Pair | PASS |
| 5.4 | Generate AES Key | PASS |
| 5.5 | Key Persistence Across Reset | PASS |
| 5.6 | Delete Key | PASS |
| 5.7 | LIST KEYS | PASS |
| 6.1 | ECDSA P-256 Sign/Verify | PASS |
| 6.2 | ECDSA P-384 Sign/Verify | PASS |
| 6.3 | ECDSA P-521 Sign/Verify | PASS |
| 6.4 | ECDH Key Agreement (ECDH1-DERIVE) | PASS |
| 6.4a | ECDH1-COFACTOR-DERIVE | N/A — cofactor h=1 for all curves; tests use ECDH1-DERIVE |
| 6.5 | AES-CBC Encrypt/Decrypt | PASS |
| 6.6 | GET CHALLENGE (Random) | PASS |
| 6.7 | BIP32/SLIP-0010 Derivation | PASS |
| 7.1 | READ BINARY PKCS#15 Files | PASS |
| 7.2 | WRITE DATA / UPDATE BINARY | PASS |
| 7.3 | DELETE FILE | PASS |
| 8.1 | DKEK Import via the DKEK exchange | - |
| 8.2 | Key Export Under DKEK | - |
| 8.3 | Key Import Under DKEK | - |
| 9.1 | Storage Encryption at Rest | CODE REVIEW |
| 9.2 | PIN Counter Decremented First | CODE REVIEW |
| 9.3 | Constant-Time PIN Comparison | CODE REVIEW |
| 9.4 | Secret Key Zeroization (PIN hash) | PASS |
| 9.5 | Operations Require Authentication | PASS |
| 9.6 | JTAG Disabled | HARDWARE ONLY |
| 10.1 | Power loss during a keystore write | HOST (fault injection); hardware campaign to do |
| 10.2 | Refused store and recovery | `test_21_store_recovery.py` |
| 11.1 | Crypto Unit Tests | PASS |
| 11.2 | APDU Dispatcher Tests | PASS |
| 11.3 | PIN Logic Tests | PASS |
| 11.4 | Key Management Tests | PASS |
| 11.5 | DKEK Tests | PASS |
| 12.1 | sc-hsm-tool Initialize E2E | PASS |
| 12.2 | pkcs11-tool Key Lifecycle | PASS |

### PIV applet (hardware-validated 2026-04-05)

| # | Test | Status |
|---|------|--------|
| 13.1 | SELECT PIV AID / FCI / security state reset | PASS |
| 13.2 | GET DATA (CHUID, CCC, certs) | PASS |
| 13.3 | VERIFY / CHANGE REF DATA / RESET RETRY (flash-persistent) | PASS |
| 13.4 | GENERAL AUTHENTICATE P-256 sign + DER verify | PASS |
| 13.4a | GENERAL AUTHENTICATE without PIN → SW=6982 | PASS |
| 13.5 | GENERATE KEY PAIR P-256/P-384 (7C→7F49→86 format) | PASS |

### OpenPGP applet (hardware-validated 2026-04-05)

| # | Test | Status |
|---|------|--------|
| 14.1 | SELECT OpenPGP AID / DOs (6F/6E/C4/C6) | PASS |
| 14.2 | VERIFY PW1/PW3 / CHANGE REF DATA (flash-persistent) | PASS |
| 14.3 | GENERATE KEY PAIR SIG/DEC/AUTH slots (flash-persistent) | PASS |
| 14.4 | PSO:CDS raw r‖s signature verify | PASS |
| 14.5 | PSO:DECIPHER ECDH key agreement | PASS |
| 14.6 | INTERNAL AUTHENTICATE | PASS |
