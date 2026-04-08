# pico2hsm — Known Issues and Roadmap

Items identified during development, mechanism audits, and pre-release security review.
Each item carries a severity and a target milestone.

Last updated: 2026-04-08 (v0.9.5 review board)

---

## Closed items

| Item | Description | Closed |
|---|---|---|
| 1 | Display: key_count, authenticated, last_op not wired | v0.9.0 |
| 2 | DKEK fully stubbed (share import, wrap, unwrap, Noise exchange) | v0.9.5 |
| 5 | ECDH P-256 xfail markers left from OpenSC 0.25-rc1 regression | v0.9.5 |

---

## CRITICAL — Must fix before public v1.0

### C1. V2 NOISE mutual authentication is a no-op

**Severity:** CRITICAL
**File:** `firmware/src/protocol/sc_hsm/commands/extras.rs:313-315, 519-521`

`handle_noise_source_respond` (P1=0x36) and `handle_noise_finalize_recv_v2` (P1=0x38) receive
ECDSA signatures (`Sig_T`, `Sig_S`) from the peer device but discard them with `let _ = sig_t;`
and a `// TODO(V2): verify Sig_T against enrolled peer pubkey` comment.

**Impact:** The V2 "mutual-auth" DKEK exchange provides zero authentication. Any device that
can perform P-256 ECDH can impersonate a peer and inject or receive DKEK material. The exchange
degrades to unauthenticated ephemeral ECDH, which is vulnerable to active MITM.

**Fix:** Implement signature verification against enrolled peer public keys in the V2 finalize
handlers before shipping. If V2 is not ready for v1.0, the P1=0x35/0x36/0x37/0x38 handlers
must return `SW_INS_NOT_SUPPORTED` and the V2 commands must be removed from user-facing docs.

---

### C2. Python daemon TCP listener sends sync traffic in plaintext

**Severity:** CRITICAL (network deployments) / HIGH (local-only)
**File:** `tools/python/pico2hsm/daemon.py:100-119`

The TCP listener accepts connections and processes DKEK sync messages (manifests, key blobs,
state hashes) with no TLS wrapping. The `tls.py` module and `_wrap_tls_server`/`_wrap_tls_client`
helpers in `dkek.py` exist but are not wired into the daemon's main listener. An attacker on the
local network can observe and tamper with sync traffic.

**Additional:** `dkek.py:355-369` — both `_wrap_tls_server` and `_wrap_tls_client` set
`ctx.verify_mode = ssl.CERT_NONE` and `ctx.check_hostname = False`, so even when TLS is used
in standalone exchange mode, it provides no peer authentication.

**Fix:**
1. Wrap accepted `conn` with an mTLS context from `tls.py` immediately after `accept()`.
2. Replace `CERT_NONE` in `_wrap_tls_server`/`_wrap_tls_client` with `create_mtls_server_context`
   / `create_mtls_client_context` from `tls.py` which correctly set `CERT_REQUIRED`.

---

### C3. test_11 (DKEK wrap/unwrap round-trip) will fail on hardware

**Severity:** CRITICAL (misleading test suite)
**File:** `tests/hw/test_11_dkek_roundtrip.py`

`sc-hsm-tool --wrap-key` sends `INS=0x72` (EXPORT KEY) and `--unwrap-key` sends `INS=0x74`
(IMPORT KEY). Both commands are implemented in the dispatch table but the underlying DKEK wrap/
unwrap has not been validated end-to-end on hardware with actual key material. The test exists
without a passing record.

**Fix:** Run test_11 on hardware with both devices. If it fails, mark the failing assertions
`pytest.mark.xfail(reason="DKEK wrap/unwrap: hardware validation pending", strict=True)` rather
than leaving a permanently red test. Remove xfail markers once the test passes.

---

### C4. No hardware tests for PIN lifecycle commands

**Severity:** HIGH (functional safety)
**Missing tests:**
- `CHANGE REFERENCE DATA` (INS=0x24) — users cannot safely change PINs without this test
- `RESET RETRY COUNTER` (INS=0x2C) — device can be bricked if PIN lockout cannot be reset
- PIN lockout behavior (retry counter decrement, lockout at 0, counter persists across power loss)
- `GET CHALLENGE` (INS=0x84) — basic entropy sanity (non-zero, non-constant across calls)

**Fix:** Add `tests/hw/test_12_pin_lifecycle.py` covering the four scenarios above. Pseudocode
for each test is in the 2026-04-08 review board report.

---

### C5. No hardware test for security-state isolation across SELECT AID

**Severity:** HIGH (security correctness)

Firmware resets `pin_verified`, `so_pin_verified`, and all session state on every `SELECT AID`.
This is the foundation of multi-applet security. No hardware test verifies that a re-SELECT
after successful VERIFY PIN actually clears auth state and forces re-authentication.

**Fix:** Add `test_select_resets_security_state` to the PIN lifecycle test file:
1. VERIFY PIN → operation requiring auth → assert SW=9000
2. SELECT AID again (no VERIFY)
3. Same operation → assert SW=6982

---

### C6. CI silently suppresses firmware unit test failures

**Severity:** HIGH (CI integrity)
**File:** `.github/workflows/build.yml` line 51

```yaml
cargo test -p pico2hsm-firmware --lib ... 2>/dev/null || true
```

`|| true` means any unit test regression in the firmware library is invisible in CI. The
20 source files with `#[cfg(test)]` modules (verify, puk_auth, bip_slip, cipher_sym, extras,
derive_asym, key_domain, etc.) all pass silently even if broken.

**Fix:** Remove `2>/dev/null || true`. If tests currently fail in CI due to the ARM default
target, add `--target x86_64-unknown-linux-gnu` (already required for local dev).

---

### C7. No CONTRIBUTING.md or security disclosure policy

**Severity:** HIGH (public repo readiness)

There is no contributor guide explaining the hardware-in-the-loop test requirement, the
no-default-features build discipline, or how to report security vulnerabilities privately.
For a security-sensitive embedded project, absence of a disclosure policy before public release
is a significant gap.

**Fix:** Create `CONTRIBUTING.md` (outline in 2026-04-08 docs review) and add a `SECURITY.md`
with a responsible disclosure contact (GitHub private security advisory or a dedicated email).

---

## HIGH — Should fix before v1.0

### H1. Export key does not enforce NO-EXPORT flag

**File:** `firmware/src/protocol/sc_hsm/commands/export_key.rs:26-87`

The file header states "Keys marked with NO-EXPORT flag are rejected" but the `handle()` function
never reads any export flag. All keys are wrappable regardless of their generation policy.

**Fix:** Read a `key_flags` / `exportable` field from the key's metadata blob and return
`SW_CONDITIONS_NOT_SATISFIED` if the key is marked non-exportable.

---

### H2. INITIALIZE SO-PIN comparison is not constant-time

**File:** `firmware/src/protocol/sc_hsm/commands/initialize.rs:90`

Re-initialization compares the provided SO-PIN hash with the stored hash using `!=` on `[u8; 32]`,
which short-circuits on the first differing byte. `verify.rs` correctly uses `subtle::ConstantTimeEq`.

**Fix:**
```rust
use subtle::ConstantTimeEq;
if !bool::from(provided_hash.ct_eq(&stored_hash)) { ... }
```

---

### H3. V2 challenge replay cache rotation is broken after 16 entries

**File:** `firmware/src/protocol/sc_hsm/commands/extras.rs:847-863`

After 16 challenges, `exchange_challenge_cache_count` is capped at 16 but new entries always
write to slot 0 (index `count % 16 = 0`), overwriting the oldest entry. After the 17th exchange,
the first challenge can be replayed without detection.

**Fix:** Add a separate `exchange_challenge_cache_write_idx: u8` field; write to
`write_idx % 16` and increment unconditionally. Read-scan still iterates the full 16 slots.

---

### H4. PKCS#7 padding validation in `dkek.unwrap()` is not constant-time

**File:** `firmware/src/security/dkek.rs:679-688`

The padding check loop short-circuits on the first mismatched byte, potentially leaking
information about the decrypted DKEK plaintext structure via timing.

**Fix:** Replace with a constant-time accumulator:
```rust
let mut bad = subtle::Choice::from(0u8);
for &b in &plaintext[pt_len - pad_len..] {
    bad |= subtle::Choice::from((b as usize != pad_len) as u8);
}
if bool::from(bad) { return Err(DkekError::Crypto); }
```

---

### H5. `debug_dump` module declaration is not feature-gated

**File:** `firmware/src/protocol/sc_hsm/commands/mod.rs:16`

`pub mod debug_dump;` is declared without `#[cfg(feature = "debug")]`, only the internals
are gated. A future contributor adding code to that module could inadvertently ship it in
release builds.

**Fix:** Add `#[cfg(feature = "debug")]` to the module declaration line.

---

### H6. RSA DKEK wrap buffer too small for RSA-4096

**File:** `firmware/src/security/dkek.rs:599-601`

Internal wrap plaintext buffer is `heapless::Vec<u8, 160>` (sized for P-521 at 132 bytes).
RSA-4096 PKCS#1 DER private keys are up to ~2350 bytes. Attempting RSA-4096 DKEK export
silently returns `DkekError::EncryptFailure`.

**Fix:** Either increase the plaintext buffer to `heapless::Vec<u8, 2400>` (matching the
export_key buffer), or explicitly gate RSA key export with a size check that returns
`SW_CONDITIONS_NOT_SATISFIED` with a clear error.

---

## MEDIUM — Address before v1.0 or document as limitation

### M1. GET_GENERATION V1 returns placeholder zeros

**File:** `firmware/src/protocol/sc_hsm/commands/extras.rs:229-233`

`handle_get_generation` (P1=0x34) returns `[0u8; 4]` rather than the actual generation counter.
The V2 variant (P1=0x3C) is correct. Any tooling still using the V1 generation query will skip
necessary sync cycles.

**Fix:** Return the low 32 bits of `state.generation`, or remove the handler and force callers
to use P1=0x3C.

---

### M2. V1 Noise exchange (P1=0x31–0x33) should be removed

V1 provides unauthenticated ephemeral ECDH with no static key binding and is documented as
deprecated. Shipping it alongside V2 (which is also currently broken per C1) creates a
downgrade attack surface.

**Fix:** Remove V1 exchange commands (`P1=0x31`, `0x32`, `0x33`) from the dispatch table for v1.0.
Both protocol versions can be re-introduced together when V2 signature verification is complete.

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

### M5. No `cargo audit` in CI

For a security-sensitive project, dependency vulnerabilities should be caught automatically.

**Fix:** Add `cargo install cargo-audit && cargo audit` as a CI step. Add an `audit.toml`
if any findings need to be ignored with justification.

---

## LOW / INFO — Polish items

### L1. PIN hashed without salt

**File:** `firmware/src/protocol/sc_hsm/commands/initialize.rs:48-56`

PINs are stored as plain `SHA-256(pin)` without a per-device salt. An attacker with flash access
can run a dictionary attack without per-device cost.

**Status:** Acknowledged limitation. The real SC-HSM uses a hardware secure element; pico2hsm's
threat model explicitly excludes physical flash-extraction attackers (see SECURE_PROVISIONING_PLAN.md).
A future improvement would add a per-device salt from OTP and a PBKDF2 stretch.

---

### L2. Python daemon identity certificate uses RSA-2048

**File:** `tools/python/pico2hsm/tls.py:144`

The auto-generated daemon TLS identity uses RSA-2048, inconsistent with the project's
EC-first approach.

**Fix:** Switch to `ec.generate_private_key(ec.SECP256R1())`.

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

### L5. Rust MSRV not declared

`README.md` says "Rust stable (1.75+)" but no `rust-version` key in `Cargo.toml` enforces this.

**Fix:** Add `rust-version = "1.75"` to the workspace `Cargo.toml`.

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

**4a. OTP row locking not wired** (`security/otp.rs`)
`Otp::lock_read()` and `Otp::lock_write()` return safe sentinel errors but do not perform
actual RP2350 OTP row locking. Blocking for deployments that require row-level tamper evidence.
Fix: wire PAC `OTP_DATA_RAW` permission bits or ROM `otp_access` with a lock flag.

**4b. CRIT0 / JTAG disable — confirm bit positions before using on production hardware**
`INS=0xF3` (PROV_WRITE_CRIT0) writes `CRIT0 = 0x74`. Verify exact bit positions against
RP2350 TRM §5.1 with `picotool otp get` on a sacrificial board before deploying on production.

**4c. Periodic CSPRNG reseed not wired**
`reseed()` is called once at core1 startup. Periodic reseeding (every N operations) is not
yet implemented. See `firmware/src/crypto/rng.rs` TODO comment.

---

## Deferred items

### Multi-partition keystore

Fully deferred (2026-04-06). RAM ceiling (~338 KB committed of 520 KB total), no hardware
isolation between partitions, no standard tooling path, and 254 keys/session is not a binding
real-world constraint. See full rationale in git history.

### PKCS#15 applet

Low priority. SC-HSM → PKCS#11, PIV, and OpenPGP already cover all common client paths.
Revisit only if legacy enterprise middleware (Windows CNG without OpenSC) is a concrete need.
