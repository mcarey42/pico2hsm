# pico2hsm — Punchout List

Open items identified during mechanism and security audits.  Deferred items
are at the bottom.

---

## 1. Display — Key count not updating on screen

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

## 2. DKEK — Key backup/restore is fully stubbed

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

## 4. Security hardening — Remaining stubs

**4a. OTP row locking not yet wired (`security/otp.rs`)**
`Otp::lock_read()` and `Otp::lock_write()` return `Err(StorageError::WriteError)`
as a safe sentinel (changed from the previous silent `Ok(())`) but do not perform
actual OTP hardware row locking.  Real locking requires PAC access to
`OTP_DATA_RAW` permission bits or the ROM `otp_access` function with a lock flag.
Until wired: provisioning writes the correct key material to OTP rows but those
rows remain erasable / re-writable by an attacker with physical access and a
flash programmer.  Blocking for production deployments that require row-level
tamper evidence.

**4b. CRIT0 / JTAG disable — provisioning APDU exists, tooling confirmation pending**
`INS=0xF3` (PROV_WRITE_CRIT0) writes `CRIT0 = 0x74` (bit 2 = debug_disable/JTAG,
bit 4 = glitch_detector_enable, bits 5–6 = sensitivity 3).  This is an
irreversible OTP write and is gated behind SO-PIN authentication and confirmed
production mode.  Before any device is deployed:
- Confirm the exact CRIT0 bit positions against RP2350 TRM §5.1 "OTP Boot Flags"
  using `picotool otp get`.
- Run the provisioning sequence on a sacrificial board and verify JTAG is
  disabled and glitch detector fires as expected.
- Only then run on production devices.

**4c. Periodic CSPRNG reseed not wired**
`reseed()` is called once at core1 startup.  Periodic re-seeding (e.g. every
N operations) is not yet wired.  Forward secrecy is bounded by the initial seed
interval.  See `firmware/src/crypto/rng.rs` TODO comment.

---

## 5. ECDH cofactor derive — `ECDH1-COFACTOR-DERIVE` returns `CKR_GENERAL_ERROR`

**Current state:**
Integration tests `test_ecdh_returns_correct_length`, `test_ecdh_cross_check`, and
`test_ecdh_different_peers_give_different_secrets` all fail for P-256 when the test
harness requests mechanism `ECDH1-COFACTOR-DERIVE` (0x1051).  The firmware returns
`CKR_GENERAL_ERROR`; the standard `ECDH1-DERIVE` (0x1050) path is not exercised by
these tests and is believed to work.  These tests are marked `xfail` in the suite.

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
- Add the three ECDH tests to the passing baseline and remove the `xfail` markers.

---

## Deferred: Multi-partition key store

**Status: FULLY DEFERRED — revisit only if a concrete multi-tenant deployment need
surfaces on more capable hardware.**

**Why deferred (2026-04-06):**

1. **RAM ceiling** — each `ScHsmState` instance costs ~32 KB RAM (inline
   `Vec<u8, 2048>` EF storage × 16 entries).  The RP2350 has 520 KB SRAM total
   with ~338 KB already committed (BSS + core1 stack).  ~5 additional ScHsm
   instances exhaust remaining RAM, so meaningful partition counts are impossible
   without a hardware change.

2. **No physical isolation** — RP2350 provides no hardware enforcement between
   logical partitions.  All partitions share the same flash, core, and RAM; this
   renders the security model equivalent to software namespacing, not true HSM
   partitioning.  Tamper-evident isolation requires dedicated silicon (e.g. Arm
   TrustZone SE or a discrete secure element).

3. **No standard tooling path** — accessing any partition beyond partition 0
   requires a custom PKCS#11 provider.  Standard OpenSC, pkcs11-tool, macOS
   CryptoTokenKit, and Windows CNG see only partition 0.

4. **254 keys/session is not a binding constraint in practice** — realistic
   workloads (personal crypto, small PKI, lab testing) top out well below 254.

5. **DKEK is still fully stubbed** — shipping a "10,000-key HSM" with no key
   backup/export path is a liability, not a feature.  Item 2 (DKEK) must land first.

6. **Future direction** — if the key-scale use case is ever real, the correct
   path is more capable hardware: FPGA-assisted key generation, a discrete
   secure element with hardware partition isolation, or an RP2350 paired with
   an external crypto accelerator.  Stretching this firmware further on
   Cortex-M33 is not the right lever.

**Flash layout decision (adopted in place of this item):**
All boards use a fixed firmware / keystore split.  For the RP2354 embedded-flash
variant (2 MB total), the canonical split is **1 MB firmware / 1 MB keystore**
(see `boards/rp2354_embedded.x`).  The 254-key addressable limit per session is
documented as a known protocol constraint, not a target for workaround.

---

## Deferred: PKCS#15 applet

**Status: LOW PRIORITY — revisit if legacy enterprise middleware deployment need surfaces.**

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
