# pico2hsm Security Summary — v0.9.9-rc2

Prepared: 2026-04-11
Scope: Full source code review, APDU robustness assessment, cryptographic mechanism audit,
Python daemon transport security, and provisioning subsystem review.

---

## Executive Summary

All CRITICAL severity issues are now resolved, including C1 (V2 Noise peer enrollment
added with SO-PIN gate and flash persistence). One HIGH item was identified and resolved
in the same release: H7 (Core1 watchdog via RNG heartbeat). All HIGH severity issues
are resolved. The firmware implements
defense-in-depth across cryptographic operations, PIN handling, key storage, and inter-device
communication. Two MEDIUM items remain open (fuzz testing, Python CI) along with cosmetic LOW
items.

---

## Resolved Security Items

### CRITICAL (all resolved)

| ID | Issue | Fix |
|----|-------|-----|
| C1 | V2 Noise mutual auth signatures discarded | **RESOLVED** — Added `ENROLL_PEER_PUBKEY` (P1=0x3D, SO-PIN gated). Peer pubkey persisted to flash at `KeyId::sc_hsm(0, 0xFC)`. Re-enrollment supported for HSM replacement. ECDSA verification branches now reachable. |
| C2 | Daemon TCP listener sends sync traffic in plaintext | `dkek.py` uses `ensure_daemon_identity()` for auto-generated P-256 ECDSA certs; `CERT_NONE` fallback eliminated |
| C3 | No DKEK wrap/unwrap round-trip test | `test_11_dkek.py` hardware test exists and passes |
| C4 | No PIN lifecycle hardware tests | `test_12_pin_lifecycle.py` covers full PIN lifecycle |
| C5 | No security-state isolation test | `test_13_security_state.py` verifies SELECT AID resets |
| C6 | CI suppresses firmware unit test failures | `cargo test` runs without `\|\| true` |
| C7 | No security disclosure policy | `CONTRIBUTING.md` and `SECURITY.md` in repo root |

### HIGH (all resolved)

| ID | Issue | Fix |
|----|-------|-----|
| H1 | Export key ignores NO_EXPORT flag | P2K4 flash format with `key_flags` byte at offset 20; enforced in export path |
| H2 | INITIALIZE SO-PIN comparison not constant-time | `subtle::ConstantTimeEq` via `ct_eq()` |
| H3 | V2 challenge replay cache rotation broken after 16 entries | Separate `exchange_challenge_cache_write_idx` ring-buffer write pointer |
| H4 | PKCS#7 padding validation not constant-time | Fixed-iteration accumulator using `subtle::Choice` |
| H5 | `debug_dump` module not feature-gated | `#[cfg(feature = "debug")]` on module declaration |
| H6 | RSA DKEK wrap buffer too small for RSA-4096 | Buffers increased to 2400 bytes (stack-local, no BSS impact) |

---

## Cryptographic Mechanism Audit

### PIN handling
- PINs hashed with PBKDF2-HMAC-SHA256, 10,000 rounds, 16-byte random salt
- PIN comparison uses constant-time `ct_eq()` (subtle crate)
- SO-PIN re-initialization comparison also constant-time
- PIN retry counter enforced in hardware (flash-backed, survives power loss)

### Key storage
- Flash format P2K4: 21-byte header with magic, key type, algorithm, and `key_flags` byte
- Backward compatibility: P2K2/P2K3 blobs read with `key_flags=0` default
- NO_EXPORT flag enforced at export path — cannot be bypassed via APDU
- Per-applet storage namespace via `KeyId` u32 encoding (applet_id in bits 23-16)
- SC-HSM INITIALIZE wipes only SC-HSM keys; PIV/OpenPGP keys preserved

### DKEK exchange
- V1 Noise commands (P1=0x31-0x33) disabled — return `SW_INS_NOT_SUPPORTED`
- V2 Noise protocol: P-256 ECDH ephemeral + AES-256-GCM with HKDF-SHA256 session key
- V2 mutual authentication: ECDSA signature verification against enrolled peer pubkeys
- Anti-downgrade: `dkek_unauthenticated_allowed=false` blocks unsigned exchanges after enrollment
- Challenge replay cache: 8-entry ring buffer with correct rotation (wrapping write pointer)

### CSPRNG
- `fill_random()` reseeds every 1,000 calls via atomic counter
- Hardware TRNG (RP2350 ROSC/ring oscillator) feeds seed material

### TLS transport (Python daemon)
- P-256 ECDSA self-signed X.509 identity auto-generated via `ensure_daemon_identity()`
- `create_server_context()` / `create_client_context()` from `tls.py`
- Anonymous mode (default): TLS 1.2+ encryption, `CERT_NONE` (no peer verification)
- CA-authenticated mode: `CERT_REQUIRED`, CA bundle loaded, hostname verification for clients
- Peer cert expiry warnings at configurable threshold (default 90 days)

---

## APDU Robustness

### Dispatch chain
- All APDUs received on Core0 (USB/CCID), forwarded to Core1 via `APDU_CHANNEL`
- Dispatcher validates CLA, INS, P1, P2 before routing to command handlers
- Unknown INS returns `SW_INS_NOT_SUPPORTED` (0x6D00)
- Wrong CLA returns `SW_CLA_NOT_SUPPORTED` (0x6E00)
- Data length validation in every command handler (explicit size checks)

### Timeout handling
- CCID time-extension messages sent every 1.5s during long operations (RSA keygen, P-521 sign)
- Prevents pcscd timeout (default 2.5s XfrBlock timeout)

### Memory safety
- Core1 stack: 163,840 bytes (160 KB) — ~2.5x measured peak of ~65 KB
- `Dispatcher::init_in_place()` prevents Core0 stack overflow from 82 KB struct
- All `heapless::Vec` operations checked (no panicking `unwrap()` on push)
- Flash write buffers are stack-local (dropped after use, no persistent BSS overhead)

### Known limitation
- **M3 (open):** No automated fuzz test for malformed/hostile APDUs. Manual testing has not
  revealed hangs or panics, but a parametrized test covering truncated TLV, wrong CLA,
  oversized payloads, empty VERIFY PIN, and oversized EXTRAS payload should be added.

---

## Open Items (non-blocking for RC2)

| Severity | ID | Description | Action |
|----------|----|-------------|--------|
| ~~CRITICAL~~ | ~~C1~~ | ~~V2 Noise enrollment missing~~ | Resolved v0.9.9-rc2 — P1=0x3D enrollment + flash persistence |
| ~~HIGH~~ | ~~H7~~ | ~~Core1 has no watchdog~~ | Resolved v0.9.9-rc2 — RNG heartbeat + 4.5s stall detection |
| MEDIUM | M3 | No hardware test for malformed/hostile APDUs | Add parametrized fuzz test |
| MEDIUM | M4 | CI does not build or test Python daemon | Add `pip install -e tools/python && pytest` CI step |
| ~~LOW~~ | ~~L3~~ | ~~Python version inconsistency (3.9+ vs 3.10+)~~ | Resolved v0.9.9-rc2 |
| ~~LOW~~ | ~~L4~~ | ~~`install.sh` uses `daemon.yaml`, docs use `config.yaml`~~ | Resolved v0.9.9-rc2 |
| ~~LOW~~ | ~~L6~~ | ~~macOS opensc-pkcs11 path may be wrong for Apple Silicon~~ | Resolved v0.9.9-rc2 |
| INFO | 4b | CRIT0/JTAG disable bit positions unverified on production boards | Verify with `picotool otp get` on sacrificial board |
| BLOCKED | 3 | Brainpool curves blocked on upstream `bp-curves` crate | Monitor RustCrypto/elliptic-curves#1114 |

---

## Recommendations

1. **Phase 2 pentest** — Engage an external reviewer to perform black-box APDU fuzzing and
   side-channel analysis (timing, power). The firmware's constant-time paths (PIN, PKCS#7
   padding) should be validated on real hardware with an oscilloscope or ChipWhisperer.

2. **M3 fuzz test** — Before v1.0, add the parametrized `test_malformed_apdu_rejected_gracefully`
   test. This is the last medium-severity security gap.

3. **M4 Python CI** — Low effort, high value. A broken `setup.py` would silently break the
   daemon for users who follow the install guide.

4. **CA-authenticated TLS deployment guide** — The anonymous TLS default protects against
   passive eavesdropping but not active MITM. Document the CA setup path for production
   network deployments in `SETUP_NETWORK_SYNC.md`.
