# pico2hsm — Known Issues and Roadmap

Items identified during development, mechanism audits, and pre-release security review.
Each item carries a severity and a target milestone.

Last updated: 2026-04-11 (audit pass — closed resolved items, updated descriptions)

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
| C1-partial | V2 Noise ECDSA verification code exists (commit 4628651) — enrollment mechanism missing | — |
| C2 | dkek.py TLS — auto-generated P-256 identity, CERT_NONE eliminated | v0.9.9-rc2 |
| H1 | Export key NO_EXPORT flag — fully resolved incl. flash (P2K4) | v0.9.5+ |
| L3 | Python version standardized to 3.10+ across all docs | v0.9.9-rc2 |
| L4 | Config file name standardized to daemon.yaml | v0.9.9-rc2 |
| L6 | macOS opensc-pkcs11 path shows both Intel and Apple Silicon | v0.9.9-rc2 |

---

## CRITICAL — Must fix before public v1.0

### C1. V2 NOISE mutual authentication — verification code exists, enrollment missing

**Severity:** CRITICAL
**File:** `firmware/src/protocol/sc_hsm/commands/extras.rs:199, 434, 549`
**File:** `firmware/src/protocol/sc_hsm/mod.rs:343, 398`

**Status (2026-04-11):** Partially fixed. Commit 4628651 added ECDSA signature
verification in `handle_noise_source_respond` (P1=0x36, line 199) and
`handle_noise_finalize_recv_v2` (P1=0x38, line 434) using `PrehashVerifier`.
However, `noise_enrolled_peer_pubkey` is initialized to `None` (line 398) and
**is never set to `Some()`** — no enrollment command populates it.

The `if let Some(ref peer_pubkey)` branch is dead code. All exchanges fall through
to the unauthenticated path. After the first successful exchange, line 549-550
sets `dkek_unauthenticated_allowed = false`, which paradoxically blocks all
subsequent V2 exchanges (safe failure — denies rather than allows).

**Fix (estimated ~80 lines):**
1. Add `handle_enroll_peer_pubkey` (new P1 code, e.g. 0x3A) that receives a
   65-byte P-256 pubkey, validates it via `VerifyingKey::from_sec1_bytes()`,
   and stores it in `state.noise_enrolled_peer_pubkey`.
2. Persist the enrolled peer pubkey to flash so it survives power cycles.
3. Add unit tests + Python integration test.

**Workaround (RC2):** V1 Noise exchange (P1=0x31-0x33) is disabled. The daemon
uses its own TLS-encrypted TCP transport for DKEK sync, not the V2 on-device
Noise protocol. V2 Noise is only relevant for direct device-to-device exchange
without a host daemon. For RC2 testing, this is non-blocking.

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

### H7. Core1 has no watchdog — infinite crypto loop requires power cycle

**Severity:** HIGH
**File:** `firmware/src/main.rs` (time extension loop)

Core0 sends CCID time-extension messages every 1.5s while waiting for Core1.
If Core1 enters an infinite loop (e.g., degenerate RSA prime candidate), Core0
sends extensions indefinitely. The host eventually times out (~30-60s), but the
device never recovers without a power cycle.

**Fix:** Add a maximum time-extension count (~30 = 45s) after which Core0
returns an error SW and resets Core1 state. Alternatively, configure the RP2350
hardware watchdog on Core1.

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

### M3. No hardware test for malformed/hostile APDUs — POST-RC2

A security device must not hang, panic, or return unexpected SW codes when receiving truncated
data, wrong CLA bytes, or oversized payloads. Deferred to post-RC2 work.

**Fix:** Add a parametrized `test_malformed_apdu_rejected_gracefully` test (full pseudocode
in 2026-04-08 review board report). Minimum cases: truncated GENERATE KEYPAIR TLV, wrong CLA,
oversized SIGN data, empty VERIFY PIN, oversized EXTRAS payload.

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

`EcPrivateBrainpoolP256/P384/P512` return `CryptoError::UnsupportedAlgorithm`. Blocked on
RustCrypto/elliptic-curves#1114 (`bp-curves` no_std + `elliptic-curve 0.13` compatibility).
No firmware work possible until upstream ships. Monitor the tracking issue.

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
