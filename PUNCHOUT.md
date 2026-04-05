# pico2hsm — Punchout List

Items identified by mechanism audit (2026-04-03).  Each section describes what
is advertised by `pkcs11-tool -M` / the opensc sc-hsm driver and the current
state of the firmware and test suite.

---

## 0. Display — Key count not updating on screen

**Current state:**
`display_state.key_count` is initialised to 0 at boot and never updated.  The
CCID loop in `run_geek_board` does not inspect `apdu_bytes[1]` (INS), so it
cannot detect when a `GENERATE KEY PAIR` (INS=0x46) or `DELETE FILE`
(INS=0xE4) completes.

**What needs to happen:**
- After `RESP_CHANNEL.receive()` returns, peek at the saved INS byte.
- On INS=0x46 (GENERATE KEY) with SW=0x9000: increment `display_state.key_count`.
- On INS=0xE4 (DELETE FILE) with SW=0x9000: decrement `display_state.key_count`
  (saturating at 0).
- Alternatively, expose a `Dispatcher::key_count() -> u8` accessor and call it
  after any mutating command — this is more robust than tracking increments.
- Also update `display_state.authenticated` on VERIFY (INS=0x20) success/failure.
- Also update `display_state.last_op` with the correct `LastOperation` variant
  (currently always left as `None` — the INS→LastOperation mapping is trivial).

---

## 1. DKEK — Key backup/restore is fully stubbed

**Current state:**
Three layers are all unimplemented:

- `firmware/src/dkek/mod.rs`: `load_share()` increments a counter but does not
  XOR the share into accumulated key material; `wrap()` and `unwrap()` return
  `HsmError::NotSupported`.
- `firmware/src/dkek/exchange.rs`: The `NoiseSession` struct (Noise_XX_25519
  handshake) has stubs for `new_initiator()`, `new_responder()`,
  `handshake_step()`, `send_share()`, and `receive_share()`.  The module comment
  notes these are waiting on `snow` crate stable `no_std` support (upstream
  tracking issue snow-lang/snow#305).
- `firmware/src/security/dkek.rs`: Same upstream note.
- `protocol/sc_hsm/commands/key_domain.rs`: Create domain, delete domain, import
  DKEK share, and assign key to domain all return `SW_INS_NOT_SUPPORTED`.
- `protocol/sc_hsm/commands/export_key.rs`: Returns `SW_INS_NOT_SUPPORTED`.
- `protocol/sc_hsm/commands/import_key.rs`: Returns `SW_INS_NOT_SUPPORTED`.

**What needs to happen:**
- Track `snow` crate `no_std` stabilization; once available, implement
  `NoiseSession` for encrypted share exchange between two HSM devices.
- Implement `DkekState::load_share()`: XOR each 32-byte share into accumulated
  key material; when `shares_loaded == shares_required`, mark DKEK established.
- Implement `DkekState::wrap()`: AES-256-CBC encrypt + CMAC tag over the
  plaintext private key DER.
- Implement `DkekState::unwrap()`: CMAC verify then AES-256-CBC decrypt.
- Wire the key domain commands: allocate/delete domain IDs in flash, associate
  key IDs with domain IDs.
- Wire EXPORT KEY: wrap the private key under the DKEK and return the blob.
- Wire IMPORT KEY: unwrap the blob under the DKEK and store to flash.
- Add integration tests covering the full share-import → export-key →
  re-initialize → import-key round-trip.

---


## 3. Brainpool curves — Blocked on upstream crate

**Current state:**
`asymmetric.rs:26` tracks RustCrypto/elliptic-curves issue #1114.
`EcPrivateBrainpoolP256`, `EcPrivateBrainpoolP384`, and `EcPrivateBrainpoolP512`
all return `CryptoError::UnsupportedAlgorithm` from keygen, sign, verify, and
ECDH.  The `bp-curves` crate does not yet expose `CurveArithmetic` in a `no_std`
context compatible with `elliptic-curve 0.13`.

**What needs to happen:**
- Monitor RustCrypto/elliptic-curves#1114 and the `bp-curves` crate for upstream
  progress.
- When `bp-curves` ships the required trait implementations, add Brainpool to the
  keygen, sign, verify, and ECDH match arms in `asymmetric.rs` following the
  existing P-256/P-384/P-521 pattern.
- Add integration tests for Brainpool P-256, P-384, P-512.
- No firmware work is possible until the upstream crate ships.

---


## 5. Security hardening — Several stubs awaiting hardware/crate API

**5a. PIN hash not zeroized (`commands/initialize.rs:46`)** — RESOLVED
`hash_pin()` now calls `result.zeroize()` (via `zeroize::Zeroize`) on the
`GenericArray<u8, U32>` returned by `h.finalize()` immediately after
`copy_from_slice`, clearing the intermediate hash copy from the stack.
`generic-array` 0.14 implements `Zeroize` for `GenericArray<u8, N>` and is
already in the dependency graph with the `zeroize` feature enabled.

**5b. Anti-glitch detector not armed (`security/anti_glitch.rs:153`)**
`arm_glitch_detector()` is a no-op stub.  The POWMAN VREG register fields
`GLITCH_DETECT_DISABLE` and `GLITCH_DETECT_SENS` are documented in the RP2350
TRM but not yet exposed by `embassy-rp` / `rp-pac`.  Software double-checks
(`double_check()`) are the current primary countermeasure.  Track the
`embassy-rp` / `rp-pac` crates for POWMAN VREG support.

**5c. OTP lock operations stubbed (`security/otp.rs:311, 326`)**
`Otp::lock_read()` and `Otp::lock_write()` return `Ok(())` without doing anything
because `embassy-rp 0.10` does not expose a lock API.  Fix requires PAC access to
OTP_DATA_RAW permission bits or the ROM `otp_access` function with a lock flag.
Currently non-fatal: provisioning proceeds but OTP rows are not read- or
write-locked after programming.

**5d. JTAG disable incomplete — CRIT0 row never written (`security/otp.rs:222`)** — PRE-PRODUCTION BLOCKER
`disable_jtag_permanent()` only sets the pico2hsm user-land bookkeeping flag at
OTP row `0x110` bit 0.  The actual hardware JTAG lockdown requires writing CRIT0
(OTP row `0x18`); this is never done anywhere in the firmware.  Per
`docs/SECURE_PROVISIONING_PLAN.md` §4, CRIT0 must be written by the factory
provisioning tool only (not by runtime firmware), after all other OTP rows are
confirmed correct.  Exact CRIT0 JTAG-disable bit position is ESTIMATED — confirm
against RP2350 TRM §5.1 "OTP Boot Flags" before burning.

**5e. SMK reads wrong OTP rows — all devices share same key (`security/otp.rs:364`)** — PRE-PRODUCTION BLOCKER
`derive_smk()` calls `read_root_secret()` which reads legacy rows `0x20–0x3F`.
Those rows overlap with the boot signing public key hash range and are NOT the
per-device key material.  The correct IKM source is `read_storage_key_material()`
at rows `0x100–0x11F` (per-device random bytes written at factory).  Until fixed,
all devices programmed with the same firmware derive the same SMK, making flash
encryption trivially bypassed.  Fix: replace the `read_root_secret()` call in
`derive_smk()` with `read_storage_key_material()` and add the device serial from
OTP as the HKDF `info` parameter (original intent of the TODO comment).

**5f. CSPRNG reseed wired (`crypto/rng.rs`)** — RESOLVED (core functionality)
`reseed()` now reads a fresh 32-byte key and 12-byte nonce from the hardware TRNG
via direct PAC register access and installs a new `ChaCha20` instance in a global
`CSPRNG` cell.  `fill_random()` draws from the ChaCha20 keystream when the CSPRNG
is seeded, falling back to direct PAC TRNG reads before the first `reseed()` call.
A shared `pac_fill_bytes()` helper is used by both paths.  `reseed()` is called
once from the core1 dispatcher task at startup (before the first APDU).  Provides
forward secrecy: a future CSPRNG state compromise does not reveal earlier outputs.

**Remaining (not blocking):** The embassy-rp interrupt-bound `Trng` peripheral
singleton is not yet integrated; the `Rng` struct (`rng.rs`) still uses the PAC
fallback.  Periodic re-seeding (e.g. every N operations) is not yet wired.  See
`rng.rs` TODO comment.

---


## 7. PIV and OpenPGP applets — IMPLEMENTED (2026-04-05)

Both applets are fully implemented and hardware-validated.  The Dispatcher
routes by AID to all three protocols at runtime.

**Architecture:** Cargo feature flags (`applet-piv`, `applet-openpgp`,
`applet-openpgp-curve25519`) — all three applets coexist in one binary.
See CLAUDE.md §"Multi-applet feature flag architecture" for build commands
and flash/RAM budget.

**7a. Storage namespace** — DONE

- `KeyId` is a `u32` with partition/applet/proto_ref encoding
- `AppletId` enum (`ScHsm=0`, `Piv=1`, `OpenPgp=2`) with per-applet key ID constructors
- `KeyStore::wipe_by_owner(AppletId)` — `INITIALIZE` only wipes SC-HSM keys
- Flash magic `"P2K2"` — pre-u32 keystore data detected and rejected at boot
- Per-applet PIN slots implemented: `PinSlot::Piv`, `PinSlot::OpenPgpPw1`, `PinSlot::OpenPgpPw3`
- Key ID scheme: `bits 31–24: partition_id | bits 23–16: applet_id | bits 7–0: proto_ref`

**7b. PIV (`applet-piv` feature)** — IMPLEMENTED, hardware-validated

Commands implemented: SELECT (FCI tag 61), GET DATA, VERIFY (PIN/PUK),
CHANGE REFERENCE DATA, RESET RETRY COUNTER, GENERAL AUTHENTICATE (3DES
management key + EC witness/challenge), GENERATE KEY PAIR (P-256, P-384).

Key slots: 9A (PIV Auth), 9C (Digital Sig), 9D (Key Mgmt), 9E (Card Auth).
Retired slots 82–95 not yet implemented.

PIN state: RAM-only (no flash persistence yet — resets to defaults on power cycle).
Default PIN: `123456`, default PUK: `12345678`, default management key: 24-byte 3DES default.

Passing integration tests (after `probe-rs reset`): all `test_piv_*` xpass.

**7c. OpenPGP (`applet-openpgp` feature)** — IMPLEMENTED, hardware-validated

Commands implemented: SELECT (DO 6F, 6E, C4, C6), GET DATA (all standard DOs),
VERIFY (PW1 mode 81/82, PW3), CHANGE REFERENCE DATA, PSO:CDS (ECDSA sign),
PSO:DECIPHER (ECDH), INTERNAL AUTHENTICATE, GENERATE KEY PAIR (P-256, P-384,
P-521), GET CHALLENGE.

Key slots: SIG (0x90), DEC (0x91), AUTH (0x92).

PIN state: RAM-only (no flash persistence yet).
Default PW1: `123456`, default PW3: `12345678`.

Note: Test ordering sensitivity — OpenPGP PW1 retry counter is in RAM and
shared across the test session.  Run `probe-rs reset --chip RP235x` before
the test suite to ensure a clean counter state.  Confirmed XPASS in isolation.

**7d. Ed25519 / X25519 (`applet-openpgp-curve25519` feature)** — TODO

Adds `curve25519-dalek` (~45–60 KB release flash) for EdDSA signing and
X25519 key agreement — the modern OpenPGP key defaults preferred by GnuPG.
Gated behind its own sub-flag; NIST-ECC-only builds don't pay the cost.

---

## 8. Multi-partition key store — thousands of keys via separate AID instances

**Motivation:**
A single SC-HSM AID session can address at most 254 keys (1-byte protocol key
reference).  The partition architecture breaks through this limit by presenting
each partition as a separate AID instance; clients SELECT the desired partition AID
before operating on its keys.  With u32 internal key IDs (item 7a), the storage
layer can hold thousands of keys limited only by flash capacity.

**Design:**
- Each partition registers a distinct AID: last byte encodes partition index.
  Partition 0 = existing AID (backward compatible).
  Partition N = `E8 2B 06 01 04 01 81 C3 1F 02 [N+1]`.
- u32 key ID `partition_id << 24 | applet_id << 16 | proto_ref` unambiguously
  identifies every key in flash across all partitions.
- Each partition has its own independent PIN, session state, and key namespace.
- Dispatcher already does AID-based routing — adding partitions is a new entry
  per partition in the routing table, not a new code path.

**Management APDUs (vendor extension, gated on partition 0 + SO-PIN):**
- `INS=0xD0` CREATE PARTITION — allocate partition, set SO-PIN
- `INS=0xD1` DELETE PARTITION — wipe all partition keys
- `INS=0xD2` LIST PARTITIONS — return count + AID bytes for active partitions
- `INS=0xD3` PARTITION STATS — key count, auth attempts, storage used (TLV response)

**PKCS#11 integration:**
- Custom PKCS#11 provider enumerates partitions via `LIST PARTITIONS` on connect,
  then presents each as a separate PKCS#11 slot/token.
- Standard OpenSC / pkcs11-tool will see only partition 0 (existing AID).

**Capacity (pico2_4m, 2 MB keystore region):**
- EC key: ~200 bytes → ~10,000 EC keys total
- RSA-2048: ~1.5 KB → ~1,300 RSA-2048 keys total
- 40 partitions × 254 keys = 10,160 addressable slots

**Prerequisites:**
- Item 7a (u32 key IDs + AppletId owner field) — must land first.
- Item 7a PIN-slot design extended to per-partition PIN storage.

**What needs to happen:**
- Extend `Dispatcher` to instantiate up to N `ScHsm` instances, one per partition.
- Register N AIDs (one per partition) in the AID routing table.
- Add `wipe_by_partition(partition_id: u8)` to `KeyStore` trait.
- Implement the four management APDUs behind SO-PIN gate on partition 0.
- Design partition metadata storage (active partitions list, per-partition label/flags).
- Write integration tests covering multi-partition round-trip.

---

## 9. ECDH cofactor derive — `ECDH1-COFACTOR-DERIVE` returns `CKR_GENERAL_ERROR`

**Current state:**
Integration tests `test_ecdh_returns_correct_length`, `test_ecdh_cross_check`, and
`test_ecdh_different_peers_give_different_secrets` all fail for P-256 when the test
harness requests mechanism `ECDH1-COFACTOR-DERIVE` (0x1051).  The firmware returns
`CKR_GENERAL_ERROR`; the standard `ECDH1-DERIVE` (0x1050) path is not exercised by
these tests and is believed to work.

**Root cause (to confirm):**
Mechanism `ECDH1-COFACTOR-DERIVE` multiplies the shared point by the curve cofactor
(h=1 for P-256, so it is mathematically identical to plain ECDH on this curve).
The OpenSC sc-hsm driver likely maps this mechanism to a different INS byte or a
different `algo_ref` than plain ECDH.  The firmware dispatch in
`protocol/sc_hsm/commands/ecdh.rs` (or equivalent) may not recognise the cofactor
algo ID and falls through to a generic error.

**What needs to happen:**
- Trace the ECDH1-COFACTOR-DERIVE APDU on hardware to identify the `algo_ref` byte
  the driver sends.
- Add the cofactor algo_ref as an alias for the standard ECDH handler in the dispatch
  match arm (for P-256/P-384/P-521 cofactor h=1, the result is identical).
- Add the three ECDH tests to the passing baseline.

---

## 10. PKCS#15 applet — Low priority, revisit if deployment need surfaces

**Background:**
PKCS#15 (ISO/IEC 7816-15) is a data-format standard defining how keys, certificates,
and PINs are laid out on a smart card filesystem.  A generic PKCS#15 driver (OpenSC,
Windows Base Smart Card CSP) can operate any conformant card without a card-specific
module.

**Why deferred:**
pico2hsm already exposes crypto through SC-HSM → `opensc-pkcs11.so`, PIV (native OS
drivers), and OpenPGP (GnuPG).  PKCS#15 would duplicate the PKCS#11 surface area for
most use cases.  The primary scenario where it adds value is legacy enterprise middleware
or Windows CNG without OpenSC installed.

**Design sketch (for when this is revisited):**
- Feature flag: `applet-pkcs15`
- AID: `A0 00 00 00 63 50 4B 43 53 2D 31 35` (standard PKCS#15 AID)
- Implement a read-only EF filesystem view (`EF.DIR`, `EF.ODF`, `EF.PrKDF`, `EF.CDF`)
  that mirrors keys already stored by SC-HSM on partition 0.
- No new key storage — PKCS#15 is a presentation layer over the existing keystore.
- PUT DATA / write commands optional; read-only is sufficient for most middleware.

**Prerequisites:**
- Item 7a (u32 key IDs + applet owner field) — must land first so PKCS#15 can
  enumerate only SC-HSM-owned keys.
- Item 7b (PIV) and 7c (OpenPGP) should land first; PKCS#15 is lower priority than both.
