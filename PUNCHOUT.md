# pico2hsm — Known Issues and Roadmap

Items identified during development, mechanism audits, and pre-release security review.
Each item carries a severity and a target milestone.

Last updated: 2026-04-13 (v1.0.0-rc2: M3 fuzz test written, Brainpool status corrected, provisioning design complete)

---

## Closed items

| Item | Description | Closed |
|---|---|---|
| 1 | Display: key_count, authenticated, last_op not wired | v0.9.0 |
| 2 | DKEK fully stubbed (share import, wrap, unwrap, Noise exchange) | v0.9.5 |
| 5 | ECDH P-256 xfail markers left from OpenSC 0.25-rc1 regression | v0.9.5 |
| H4 | PKCS#7 padding validation in dkek.unwrap() not constant-time | v0.9.5 |
| H6 | RSA DKEK wrap buffer too small for RSA-4096 | v0.9.5 |
| C3 | test_11 DKEK wrap/unwrap round-trip — hardware validated | v0.9.5+ |
| C4 | PIN lifecycle hardware tests (test_12_pin_lifecycle.py) | v0.9.5+ |
| C5 | Security-state isolation test (test_13_security_state.py) | v0.9.5+ |
| C6 | CI firmware unit test failures no longer suppressed | v0.9.5+ |
| C7 | CONTRIBUTING.md and SECURITY.md created | v0.9.5+ |
| M1 | GET_GENERATION V1 now returns real generation counter | v0.9.5+ |
| M2 | V1 Noise exchange (P1=0x31-0x33) returns SW_INS_NOT_SUPPORTED | v0.9.5+ |
| M5 | cargo audit added to CI | v0.9.5+ |
| 4a | OTP row locking wired (sw_lock INACCESSIBLE) | v0.9.5+ |
| 4c | Periodic CSPRNG reseed every 1000 calls | v0.9.5+ |
| L1 | PIN hashed with PBKDF2-HMAC-SHA256 + salt | v0.9.5+ |
| L5 | rust-version = "1.75" added to Cargo.toml | v0.9.5+ |
| C1 | V2 Noise peer enrollment (P1=0x3D) + SO-PIN gate + flash persistence | v0.9.9-rc2 |
| C2 | dkek.py TLS — auto-generated P-256 identity, CERT_NONE eliminated | v0.9.9-rc2 |
| H7 | Core1 watchdog — RNG heartbeat + 4.5s stall detection | v0.9.9-rc2 |
| H1 | Export key NO_EXPORT flag — fully resolved incl. flash (P2K4) | v0.9.5+ |
| L3 | Python version standardized to 3.10+ across all docs | v0.9.9-rc2 |
| L4 | Config file name standardized to daemon.yaml | v0.9.9-rc2 |
| L6 | macOS opensc-pkcs11 path shows both Intel and Apple Silicon | v0.9.9-rc2 |
| M3 | Malformed/hostile APDU fuzz test (81 cases) | v1.0.0-rc2 |

---

## CRITICAL — Must fix before public v1.0

### ~~C1. V2 NOISE mutual authentication — enrollment missing~~ — RESOLVED

**Fixed (v0.9.9-rc2):** Added `ENROLL_PEER_PUBKEY` command (P1=0x3D, SO-PIN gated).

- `handle_enroll_peer_pubkey()` in extras.rs: validates 65-byte P-256 pubkey via
  `VerifyingKey::from_sec1_bytes()`, stores in `state.noise_enrolled_peer_pubkey`,
  permanently locks out unauthenticated exchanges.
- Flash persistence: peer pubkey stored as `KeyId::sc_hsm(0, 0xFC)` Generic key
  object; loaded at boot in `dispatcher.rs`; cleared by INITIALIZE.
- Re-enrollment with SO-PIN supported (HSM replacement scenario).
- 6 unit tests + Python hardware integration test (`test_15_enroll_peer_pubkey.py`).
- The existing ECDSA verification code in P1=0x36 and P1=0x38 is now reachable.

---

### ~~C2. Python daemon TCP listener sends sync traffic in plaintext~~ — RESOLVED

**Fixed (v0.9.9-rc2):** `dkek.py` `_wrap_tls_server` and `_wrap_tls_client` now use
`tls.create_server_context()` / `tls.create_client_context()` with auto-generated P-256
ECDSA daemon identity via `ensure_daemon_identity()`. The `CERT_NONE` fallback paths are
eliminated — TLS with a real certificate is always used. Anonymous mode (encryption-only,
no peer auth) is still the default for standalone exchanges; CA-authenticated mode (mTLS)
is used when `ca_cert` is configured. Daemon listener TLS wiring is a deployment config
concern documented in SETUP_NETWORK_SYNC.md.

---

### ~~C3. test_11 (DKEK wrap/unwrap round-trip)~~ — RESOLVED

Moved to Closed items table. Hardware test exists and passes.

---

### ~~C4. No hardware tests for PIN lifecycle commands~~ — RESOLVED

Moved to Closed items table. `tests/hw/test_12_pin_lifecycle.py` exists.

---

### ~~C5. No hardware test for security-state isolation across SELECT AID~~ — RESOLVED

Moved to Closed items table. `tests/hw/test_13_security_state.py` exists.

---

### ~~C6. CI silently suppresses firmware unit test failures~~ — RESOLVED

Moved to Closed items table. CI now runs `cargo test` without `|| true`, using `--target x86_64-unknown-linux-gnu`.

---

### ~~C7. No CONTRIBUTING.md or security disclosure policy~~ -- RESOLVED

Moved to Closed items table. Both `CONTRIBUTING.md` and `SECURITY.md` exist in the repo root.

---

## HIGH — Should fix before v1.0

### ~~H1. Export key does not enforce NO-EXPORT flag~~ — RESOLVED

Moved to Closed items table. Flash format migrated to P2K4 (21-byte header with `key_flags`
byte at offset 20). `KeyObject` serialization/deserialization handles P2K2/P2K3/P2K4 blobs
with backward compatibility (older blobs default to `key_flags=0`).

---

### H2. ~~INITIALIZE SO-PIN comparison is not constant-time~~ — RESOLVED

**File:** `firmware/src/protocol/sc_hsm/commands/initialize.rs:91`

**Fixed 2026-04-08:** Replaced `provided_hash != stored_hash` (short-circuit `[u8; 32]` comparison)
with `!bool::from(provided_hash.ct_eq(&stored_hash))` using `subtle::ConstantTimeEq`, matching the
pattern already used in `verify.rs`. Added `use subtle::ConstantTimeEq;` import (line 13) and two
unit tests (`test_reinit_wrong_sopin_rejected`, `test_reinit_correct_sopin_accepted`).

---

### H3. V2 challenge replay cache rotation is broken after 16 entries — FIXED

**File:** `firmware/src/protocol/sc_hsm/commands/extras.rs` (`check_and_add_challenge`)

**Status (2026-04-08):** Fixed. Added `exchange_challenge_cache_write_idx: u8` to `ScHsmState`
as a separate ring-buffer write pointer that increments unconditionally via `wrapping_add(1)`.
The write slot is `write_idx % 16`, independent of the count (which is capped at 16 for the
read-scan). Two unit tests added: `test_challenge_cache_full_rotation` (verifies correct
eviction after 19 inserts) and `test_challenge_cache_deduplication_works` (verifies replay
detection survives full rotation and eviction).

---

### H4. ~~PKCS#7 padding validation in `dkek.unwrap()` is not constant-time~~ — RESOLVED

**File:** `firmware/src/security/dkek.rs`

**Fixed 2026-04-08:** Replaced the short-circuit early-return padding validation loop with a
constant-time accumulator using `subtle::Choice`. The new implementation iterates a fixed 16
positions, masks out-of-range indices, and accumulates mismatches into a `bad` accumulator
without branching on padding content. Added `test_unwrap_bad_padding_rejected_constant_time`
and `test_unwrap_forged_padding_value_rejected` unit tests.

---

### H5. ~~`debug_dump` module declaration is not feature-gated~~ — RESOLVED

**File:** `firmware/src/protocol/sc_hsm/commands/mod.rs:16-17`

**Fixed 2026-04-08:** Added `#[cfg(feature = "debug")]` to the `pub mod debug_dump;` declaration
in `commands/mod.rs`. Removed redundant per-item `#[cfg(feature = "debug")]` attrs inside
`debug_dump.rs` (the module-level gate is sufficient). Added compile-time assertion test
(`debug_gate_tests::debug_module_gated`) that runs when `debug` feature is absent. Dispatch
table reference at `sc_hsm/mod.rs:438-439` was already correctly gated.

---

### H6. ~~RSA DKEK wrap buffer too small for RSA-4096~~ — RESOLVED

**File:** `firmware/src/security/dkek.rs`

**Fixed 2026-04-08:** Increased all internal DKEK wrap/unwrap buffers from 160 bytes (P-521
only) to 2400 bytes to accommodate RSA-4096 PKCS#1 DER private keys (~2350 bytes). Buffers
changed: `wrap()` plaintext Vec (160 -> 2400), `wrap()` ct_buf array (160 -> 2400), `wrap()`
output Vec (2080 -> 2448), `unwrap()` pt_buf array (160 -> 2400), `unwrap()` returned key
material Vec (2048 -> 2400). All buffers are stack-local (only alive during the wrap/unwrap
call), so no BSS impact. Added `test_wrap_unwrap_large_rsa_key` unit test exercising a
2348-byte key round-trip.

---

### ~~H7. Core1 has no watchdog — infinite crypto loop requires power cycle~~ — RESOLVED

**Fixed (v0.9.9-rc2):** Heartbeat-based watchdog via `WATCHDOG_HEARTBEAT` AtomicU32.
`FwRng::fill_bytes()` increments the heartbeat on every call, providing automatic
liveness signaling during RSA keygen (thousands of RNG calls), ECDSA sign, and
all crypto. Core0 checks heartbeat progress every 1.5s; after 3 consecutive stalls
(4.5s with no RNG activity), returns SW 6F00. Safe for RSA-4096 (~16 min).

---

## MEDIUM — Address before v1.0 or document as limitation

### ~~M1. GET_GENERATION V1 returns placeholder zeros~~ — RESOLVED

Moved to Closed items table. `handle_get_generation` now returns
`(state.generation as u32).to_be_bytes()` (line 117 of extras.rs).

---

### ~~M2. V1 Noise exchange (P1=0x31-0x33) should be removed~~ — RESOLVED

Moved to Closed items table. V1 handlers (P1=0x31/0x32/0x33) now return `SW_INS_NOT_SUPPORTED`
(extras.rs line 67).

---

### ~~M3. No hardware test for malformed/hostile APDUs~~ — RESOLVED

**Fixed (v1.0.0-rc2):** `tests/hw/test_16_fuzz_malformed.py` — 81 parametrized test cases
covering structural malformation, truncated TLV, wrong CLA/INS, oversized payloads, empty
data, protocol violations (commands before SELECT/PIN), boundary lengths, and rapid-fire
burst stress tests. Each case sends a malformed APDU sandwiched between SELECT commands
and asserts the device stays alive. Designed for use with a debug probe attached for
Cortex-M33 fault register analysis (CFSR/MMFAR/BFAR) if a hang is detected.

---

### ~~M4. CI does not build or test the Python daemon~~ — DEFERRED

Deferred. CI runner has no hardware HSM devices, so integration tests cannot
run in CI. The Python package is validated manually during the RC testing
procedure (see `docs/TESTING_PROCEDURE.md` Phase 6).

---

### ~~M5. No `cargo audit` in CI~~ — RESOLVED

Moved to Closed items table. `cargo audit` step exists in `.github/workflows/build.yml` (line 88).

---

## LOW / INFO — Polish items

### ~~L1. PIN hashed without salt~~ — RESOLVED

Moved to Closed items table. PINs now use PBKDF2-HMAC-SHA256 with 10K rounds and a 16-byte
random salt (per PUNCHOUT_PRODUCTION.md P1-1).

---

### ~~L2. Python daemon identity certificate uses RSA-2048~~ — RESOLVED

**File:** `tools/python/pico2hsm/tls.py:378`

Already uses P-256 ECDSA (`ec.generate_private_key(ec.SECP256R1())`). The description
was stale — moved to resolved.

---

### ~~L3. Python version inconsistency across docs~~ -- RESOLVED

**Fixed (v0.9.9-rc2):** All docs now say Python 3.10+. `install.sh` version check updated
from 3.9+ to 3.10+.

---

### ~~L4. `install.sh` installs `daemon.yaml` but docs reference `config.yaml`~~ -- RESOLVED

**Fixed (v0.9.9-rc2):** Standardized on `daemon.yaml` everywhere. Updated all `--config`
examples in SETUP_LOCAL_CLUSTER.md, SETUP_NETWORK_SYNC.md, PYTHON_DAEMON.md,
MIRRORED_CLUSTER_SETUP.md, VERIFICATION.md, and install.sh.

---

### ~~L5. Rust MSRV not declared~~ — RESOLVED

Moved to Closed items table. `rust-version = "1.75"` is set in `Cargo.toml` (line 12).

---

### ~~L6. macOS opensc-pkcs11 path in SINGLE_DEVICE_SETUP.md may be wrong~~ -- RESOLVED

**Fixed (v0.9.9-rc2):** SINGLE_DEVICE_SETUP.md now shows both Intel (`/usr/local/lib/`)
and Apple Silicon (`/opt/homebrew/lib/`) paths, plus the auto-detect form
`$(brew --prefix)/lib/opensc-pkcs11.so`.

---

## Still open from previous audit

### 3. Brainpool curves — Blocked on upstream crate

`EcPrivateBrainpoolP256/P384/P512` return `CryptoError::UnsupportedAlgorithm`.

**Status (2026-04-13 feasibility study):**

The PUNCHOUT reference to RustCrypto/elliptic-curves#1114 was stale (that was a LICENSE PR).
The actual blockers are:

1. **`bp256`/`bp384` crates** exist on RustCrypto master with full arithmetic (`CurveArithmetic`,
   ECDSA, ECDH) but target `elliptic-curve 0.14.0-rc` — incompatible with our 0.13.8 stack.
   No stable 0.14 release yet; maintainer says EC crates "will be some of the last to get releases."
2. **`bp512` does not exist** — not upstream, not in any crate anywhere. Would need to be
   written from scratch using fiat-crypto generated field arithmetic (~3-4 weeks).
3. Brainpool random primes are 1.6-2.7x slower than equivalent NIST curves on Cortex-M33
   (no Montgomery reduction shortcuts). BP512r1 sign: ~5-8 seconds.
4. Flash impact: +55-75 KB for all three curves (not a concern on 4 MB flash).

**Plan:**
- **Wait for `elliptic-curve 0.14` stable.** Migrate the full ECC stack (p256, p384, p521,
  k256, ecdsa, elliptic-curve) from 0.13→0.14. Add bp256+bp384 as dependencies (zero local
  crypto code). Then write bp512 locally (~2 weeks with the other two as reference).
- **If urgent before 0.14:** BearSSL FFI is the fastest path (~2-3 weeks for all three curves)
  but adds C toolchain dependency and audit surface. Only pursue if there's a concrete
  customer/compliance requirement (German/EU BSI TR-03110 PKI).

---

### 4. Security hardening — Remaining stubs

**~~4a. OTP row locking not wired~~** — RESOLVED. `lock_read()` and `lock_write()` now
program `OTP.sw_lock(page)` to `INACCESSIBLE` / write-protect via real PAC registers.
Moved to Closed items table.

**4b. CRIT0 / JTAG disable — WRONG ROW AND WRONG REGISTER (upgraded to HIGH)**

**Severity:** HIGH (pre-production)

Two bugs confirmed by SVD/PAC analysis (2026-04-11):

1. **Wrong row:** `CRIT0_ROW = 0x18` writes to `randid2` (private random number), not CRIT0.
2. **Wrong register:** The target bits (DEBUG_DISABLE, GLITCH_DETECTOR_ENABLE,
   GLITCH_DETECTOR_SENS) are in **CRIT1** (row 0x40), not CRIT0 (row 0x38).

Value `0x74` is correct for CRIT1 bit layout. Affected files:
- `provisioning.rs:294` — `CRIT0_ROW = 0x18` → should be `CRIT1_ROW = 0x40`
- `boot.rs:269` — `RP2350_CRIT0_ROW = 0x18` → should be `RP2350_CRIT1_ROW = 0x40`
- `docs/SECURE_PROVISIONING_PLAN.md` — references "CRIT0 row 0x18"

**Additional concern:** CRIT1 uses RBIT-8 redundancy (rows 0x40-0x47). Must verify
whether `embassy_rp::otp::write_raw_word` handles 8-way redundancy or if all 8 copies
need explicit writes. Do NOT fix until RBIT-8 handling is confirmed on hardware.

**~~4c. Periodic CSPRNG reseed not wired~~** — RESOLVED. `fill_random()` now reseeds
every `RESEED_INTERVAL` (1,000) calls via an atomic counter. Moved to Closed items table.

---

## Deferred items

### Multi-partition keystore

Fully deferred (2026-04-06). RAM ceiling (~338 KB committed of 520 KB total), no hardware
isolation between partitions, no standard tooling path, and 254 keys/session is not a binding
real-world constraint. See full rationale in git history.

### PKCS#15 applet

Low priority. SC-HSM → PKCS#11, PIV, and OpenPGP already cover all common client paths.
Revisit only if legacy enterprise middleware (Windows CNG without OpenSC) is a concrete need.
