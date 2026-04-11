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
| C1 | V2 Noise mutual auth — ECDSA verification + downgrade protection | v0.9.5+ |
| C2 | dkek.py TLS — auto-generated P-256 identity, CERT_NONE eliminated | v0.9.9-rc2 |
| H1 | Export key NO_EXPORT flag — fully resolved incl. flash (P2K4) | v0.9.5+ |

---

## CRITICAL — Must fix before public v1.0 (ALL RESOLVED)

### ~~C1. V2 NOISE mutual authentication is a no-op~~ — RESOLVED

**Fixed (commit 4628651):** Both `handle_noise_source_respond` (P1=0x36) and
`handle_noise_finalize_recv_v2` (P1=0x38) now verify ECDSA signatures against
`noise_enrolled_peer_pubkey` via `PrehashVerifier`. Downgrade protection: when a
peer is enrolled, `dkek_unauthenticated_allowed=false` blocks unsigned exchanges.
Bootstrapping (TOFU) mode only permitted when no peer is enrolled AND the flag allows it.

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

## MEDIUM — Address before v1.0 or document as limitation

### ~~M1. GET_GENERATION V1 returns placeholder zeros~~ — RESOLVED

Moved to Closed items table. `handle_get_generation` now returns
`(state.generation as u32).to_be_bytes()` (line 117 of extras.rs).

---

### ~~M2. V1 Noise exchange (P1=0x31-0x33) should be removed~~ — RESOLVED

Moved to Closed items table. V1 handlers (P1=0x31/0x32/0x33) now return `SW_INS_NOT_SUPPORTED`
(extras.rs line 67).

---

### M3. No hardware test for malformed/hostile APDUs

A security device must not hang, panic, or return unexpected SW codes when receiving truncated
data, wrong CLA bytes, or oversized payloads.

**Fix:** Add a parametrized `test_malformed_apdu_rejected_gracefully` test (full pseudocode
in 2026-04-08 review board report). Minimum cases: truncated GENERATE KEYPAIR TLV, wrong CLA,
oversized SIGN data, empty VERIFY PIN, oversized EXTRAS payload.

---

### M4. CI does not build or test the Python daemon

The GitHub Actions workflow builds firmware and runs Rust unit tests but never installs or imports
the Python daemon package. A broken `setup.py`, missing `__init__.py`, or import error would not
be caught before release.

**Fix:** Add a CI step:
```yaml
- run: pip install -e tools/python && python -m pytest tools/python/tests/ -x -q
```

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

### L3. Python version inconsistency across docs

`SETUP_LOCAL_CLUSTER.md` says Python 3.9+; `SETUP_NETWORK_SYNC.md` says Python 3.10+.

**Fix:** Standardize on 3.10+ (f-string `=` syntax used in daemon.py requires 3.8+; actual
minimum is 3.9 for `zoneinfo`; 3.10 is a safe, supported, and widely available target).
Update all docs to say Python 3.10+.

---

### L4. `install.sh` installs `daemon.yaml` but docs reference `config.yaml`

**File:** `install.sh` installs the example config as `/etc/pico2hsm/daemon.yaml`; setup guides
use `config.yaml` in examples. Pick one name and apply consistently.

---

### ~~L5. Rust MSRV not declared~~ — RESOLVED

Moved to Closed items table. `rust-version = "1.75"` is set in `Cargo.toml` (line 12).

---

### L6. macOS opensc-pkcs11 path in SINGLE_DEVICE_SETUP.md may be wrong

Homebrew on Apple Silicon installs to `/opt/homebrew/lib/`, not `/usr/local/lib/`.
The doc should show both paths or use `$(brew --prefix)/lib/opensc-pkcs11.so`.

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

**4b. CRIT0 / JTAG disable — confirm bit positions before using on production hardware**
`INS=0xF3` (PROV_WRITE_CRIT0) writes `CRIT0 = 0x74`. Verify exact bit positions against
RP2350 TRM S5.1 with `picotool otp get` on a sacrificial board before deploying on production.

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
