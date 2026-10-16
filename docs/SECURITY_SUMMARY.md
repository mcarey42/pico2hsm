# pico2hsm Security Summary — v0.9.9-rc2

> **Historical snapshot (2026-04-11).** It describes v0.9.9-rc2. Since
> then the October 2026 audit ([AUDIT_2026-10.md](AUDIT_2026-10.md)) and
> Storage V2 changed several of the mechanisms below: keys live in the
> Storage V2 journaled store (`P2K4`/`P2KP` blobs inside V2 objects;
> [STORAGE_V2.md](STORAGE_V2.md)); retry counters are in the counter log
> and spent before every comparison; the enrolled peer at `0xFC` is
> migrated at boot to a single-use pinned peer; the OTP boot flags are at
> row `0x140`. Use the audit and `CLAUDE.md` (Security invariants) for the
> current state.

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

### RSA key pool (pre-generated RSA keys, 2026-10)

RSA keygen on the Cortex-M33 takes tens of seconds to minutes, so the
firmware (with `rsa`) pre-generates RSA-2048/3072/4096 keys while idle and
SC-HSM GENERATE KEY PAIR hands out a pooled key.  Code:
`firmware/src/rsa_pool.rs` (policy), `storage/rsa_pool.rs` (flash slots),
`crypto/rsa_keygen.rs` (generator); APDUs: `SC_HSM_APDU_REFERENCE.md`,
"RSA key pool".

**The time-shift property.**  A pooled key exists before anyone asks for
it.  Whoever obtains the pool region *and* the device storage key at time
T learns keys that may be issued later — keys their owner believes were
created after T.  (Without the storage key the region holds only
AES-256-GCM ciphertext, like the keystore.)  Mitigations:

- **Storage-key encryption.**  Each pooled key is a `KeyObject` blob
  encrypted under the storage master key exactly like a stored key; the
  slot, size, sequence number and birth time are in the authenticated
  header (GCM AAD) and checked against the slot, so a blob copied to
  another slot, or a header edited in place to claim another size, a
  younger age or another sequence number, does not yield a key.
- **Rotation and age-out (default on).**  A pooled key older than the
  maximum age (default 4 hours of powered-on time) is erased and replaced
  in idle time, and GENERATE never issues one past that age.  A flash image
  therefore holds keys that are likely retired before anyone uses them.
  GENERATE takes the *newest* key.  Age is measured in powered-on minutes
  (persisted pool clock, no RTC): time unplugged does not count, so a key
  can sit in an unplugged device's flash for longer than the maximum age.
- **Configuration (SO-PIN).**  RSA_POOL_CONFIG turns rotation off, changes
  the maximum age (1 hour to 1 year — the floor bounds flash wear: each
  slot is erased about once per maximum age, ≥ 11 years of continuous
  power to 100 000 cycles at 1 hour) or the depth per size, or turns the
  pool off; off erases every pooled key, and GENERATE then always
  generates live.  Readable without a PIN (RSA_POOL_STATUS).
- **INITIALIZE erases the pool** (trust reset).
- **Issue order.**  The slot is marked taken on flash (program-without-
  erase) and read back *before* the key leaves the pool; a power cut can
  waste a key, never issue it twice.  The slot is then erased at once, so
  no ciphertext remains whose TAKEN mark an attacker could undo by
  rewriting the sector from the same image (restoring an *older* image is
  the rollback class S-15, out of scope).  The issued key is then stored
  and numbered like any generated key.
- **Fail closed.**  An unreadable or invalid pool configuration counts as
  *off*; a pool clock that cannot be read or persisted holds the pool off
  for the boot (ages could no longer be trusted after a reboot).  Either
  way the pool is emptied, GENERATE generates live, and RSA_POOL_STATUS
  sets health bit 3.  Repeated flash failures stop the background work
  (health bit 2).  A key that fails its pairwise test or the `rsa` crate's
  validation is never pooled or issued (a pooled one is erased).
- **No remnants.**  The generator's state (candidates, primes, exponents,
  CRT values, temporaries) is zeroized after every key — pooled, issued
  live, discarded, failed — and on every internal restart; big-number
  temporaries are wiped by the arithmetic routines; decrypted pool
  objects and issued pairs wipe on drop.  Retired, rotated, issued and
  torn slots are erased.

**Key quality.**  FIPS 186-5 A.1.3 random probable primes: a fresh DRBG
candidate per attempt, top two bits set, `gcd(p−1, e) = gcd(q−1, e) = 1`
(`e = 65537`), `|p − q| > 2^(nlen/2−100)`, trial division by the odd primes
below 2^14, Miller-Rabin to base 2, then FIPS 186-5 Table B.1's rounds
with DRBG bases for the stricter error column (5 / 4 / 4 rounds for
1024 / 1536 / 2048-bit primes: error ≤ 2^-112 / 2^-128 / 2^-144), then the
B.3.3 Lucas test (base 2 + Lucas = Baillie-PSW; no composite is known to
pass it).  `d = e⁻¹ mod lcm(p−1, q−1)` with `d > 2^(nlen/2)`; dP, dQ, qInv
checked by multiplying back; a pairwise-consistency test (CRT signature of
a random message, verified with `(n, e)`) before a key is pooled or
issued; and at issue the key is parsed and validated again by the `rsa`
crate (an independent big-integer implementation).  The previous keygen
(`rsa` crate) did more Miller-Rabin rounds (21) but on incremental
candidates, with no `|p − q|` bound, `d` modulo φ(n) and no pairwise test.
Generation starts only after the boot TRNG reseed succeeded, and draws
from the same DRBG as every other key (`crypto::rng`).

**Side channels.**  Everything computed on the accepted primes and the
private key is constant-time: no secret-dependent branch, memory index or
`UDIV`/`SDIV` (data-dependent on the M33).  That covers Montgomery
arithmetic (`UMAAL`), the windowed exponentiations (Miller-Rabin, qInv,
the pairwise CRT signature), the Miller-Rabin squaring loop (a fixed 64
squarings, the outcome in a mask, so `ν2(p−1)` is not visible), the Lucas
chain, trial division and `p mod e` (multiplication by a reciprocal),
`gcd(p−1, q−1)` (fixed-count binary GCD), d / dP / dQ (reciprocal
division, Fermat inverse modulo `e`), and the `|p − q|` and `d` size
checks.  Not constant-time, and why that is acceptable: *where* a rejected
candidate fails (it is discarded); Miller-Rabin base redraws (≤ 25 % each,
a statistical hint about the top bits); the Lucas `D` search (a bit or two
of quadratic-residue information about `p` modulo small numbers); the DER
lengths of d, dP, dQ, qInv (inherent to PKCS#1).  Details:
`firmware/src/crypto/rsa_keygen.rs`, "Side channels".  Generation runs
between APDUs, where a host sees only its effect on response times.

**Availability.**  Idle work runs in slices of at most 20 ms that end
before the next unit of work (≤ ~7 ms of computation on the M33) once an
APDU is waiting; the longest wait an APDU can see is one flash sector
erase of the pool (typically ~45 ms, at most 400 ms by the flash
datasheets).  Live keygen inside an APDU keeps the stall detector's
heartbeat moving instead of suppressing it.

### TLS transport (Python daemon)
- P-256 ECDSA self-signed X.509 identity auto-generated via `ensure_daemon_identity()`
- `create_server_context()` / `create_client_context()` from `tls.py`
- Anonymous mode (default): TLS 1.2+ encryption, `CERT_NONE` (no peer verification)
- CA-authenticated mode: `CERT_REQUIRED`, CA bundle loaded, hostname verification for clients
- Peer cert expiry warnings at configurable threshold (default 90 days)

---

## APDU Robustness

### Dispatch chain
- All APDUs received on Core0 (USB/CCID), forwarded to Core1 via the `APDU_BOX` mailbox (wiped after use)
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
| INFO | 4b | ~~CRIT1/JTAG disable bit positions verified~~ | Resolved — triple-checked against pico-sdk `otp_data.h`, rp-pac 7.0.0, rp2350_hacking_challenge; CRIT1 rows 0x40–0x47 (RBIT-8) |
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
