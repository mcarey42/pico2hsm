# pico2hsm — Punchout List

Items identified by mechanism audit (2026-04-03).  Each section describes what
is advertised by `pkcs11-tool -M` / the opensc sc-hsm driver and the current
state of the firmware and test suite.

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

## 2. Remaining SC-HSM command stubs

These commands all return `SW_INS_NOT_SUPPORTED`.  They are lower priority than
item 1 but are needed for full SC-HSM compatibility.

**2a. PSO Compute Cryptographic Checksum / Verify (`commands/pso.rs`)**
PSO CDS (0x9E,0x9A) and PSO Decipher (0x80,0x86) are now implemented, delegating
to the same ECDSA/RSA and ECDH/RSA paths as `sign.rs` and `decrypt.rs` but reading
key/algo from MSE state.  Still stubbed:
- `(0x8E, 0x80)` — PSO: Compute Cryptographic Checksum (CMAC/HMAC) — needs item 2d
- `(0x86, 0x80)` — PSO: Verify Cryptographic Checksum — needs item 2d

**2b. Symmetric key generation (`commands/generate_key.rs`)**
INS for GENERATE KEY (symmetric).  Stub calls
`key_management::generate_symmetric_key()`.  Needed for AES key objects.

**2c. Symmetric cipher (`commands/cipher_sym.rs`)**
AES-CBC / AES-GCM encrypt/decrypt.  Stub should dispatch to `crypto::symmetric`
based on the current MSE (Manage Security Environment) state.

**2d. HKDF / PBKDF2 / X9.63 / CMAC / HMAC extras (`commands/extras.rs`)**
Six sub-operations under a single INS, all stubbed:
`HKDF-Extract`, `HKDF-Expand`, `PBKDF2-SHA256`, `X9.63-KDF`, `AES-CMAC`,
`HMAC-SHA256`.  The `crypto/kdf.rs` module has partial implementations; these
commands just need to be wired up.

**2e. BIP-32 / SLIP-10 key derivation (`commands/bip_slip.rs`)**
Stub should call `crypto::kdf::bip32_derive()` or `slip10_derive()`.
Note: the SLIP-10 child key derivation has a known bug (see item 4).

**2f. Asymmetric key derivation (`commands/derive_asym.rs`)**
INS=0x62 / P1=0x01.  Stub should call `crypto::kdf::x963_derive()` or
`hkdf_derive()` with the source key ID and derivation info from the command data.

**2g. Session PIN (`commands/session_pin.rs`)**
Generate a one-time session PIN, store with expiry.

**2h. External auth (`commands/external_auth.rs`)**
Verify a cryptogram over the stored INTERNAL AUTHENTICATE challenge using the
device auth key.  Must clear the challenge after use to prevent replay.

**2i. General auth (`commands/general_auth.rs`)**
Multi-step authentication state machine using the 0x7C TLV template.

**2j. PUK auth and PIN unblock (`commands/puk_auth.rs`)**
Constant-time PUK comparison, retry counter management, and PIN unblock logic.
Currently no PUK is stored.

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

## 4. SLIP-10 child key derivation bug

**Current state:**
`firmware/src/crypto/kdf.rs:828` has a disabled test:
> "slip10_child_key child-key derivation produces a value that diverges from the
> SLIP-0010 reference test vector for m/0'.  Master-key derivation is correct.
> The discrepancy is in `scalar_add_mod` or the HMAC data construction for the
> child step.  Needs investigation and fix before enabling."

The master key derivation unit test passes; only the child step is wrong.  Because
`commands/bip_slip.rs` is also stubbed (item 3e), this bug is not yet
user-visible, but it will block any correct BIP-32 / SLIP-10 operation once that
command is wired up.

**What needs to happen:**
- Re-enable the failing unit test in `kdf.rs` and compare intermediate values
  against a reference implementation (e.g., the Python `slip10` package or the
  reference vectors in the SLIP-0010 spec).
- The most likely culprits are: wrong byte ordering in the HMAC input for hardened
  vs normal child derivation, or an off-by-one in `scalar_add_mod`.
- Fix the implementation until all reference vectors pass.

---

## 5. Security hardening — Several stubs awaiting hardware/crate API

**5a. PIN hash not zeroized (`commands/initialize.rs:46`)**
`hash_pin()` calls `Sha256::new()` / `finalize()` and copies the result, but the
`Sha256` state on the stack is not explicitly zeroized.  The comment says
"replace with proper zeroizing hash call."  Fix: use `sha2::Sha256` via the
`zeroize` crate's `ZeroizeOnDrop` wrapper or call `Zeroize::zeroize()` on the
digest object after copying.

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

**5d. JTAG disable OTP row unverified (`security/otp.rs:222`)**
`disable_jtag_permanent()` uses row `0x110` bit 0 as the JTAG disable fuse, but
the comment notes this is the user-land flag and the hardware JTAG fuse may be at
a different row in OTP page 0.  Cross-reference RP2350 TRM §5.1 "OTP Boot Flags"
to confirm the correct row before this function is called in production
provisioning.

**5e. SMK derivation missing device serial (`security/otp.rs:364`)**
`derive_smk()` (Storage Master Key derivation) has a TODO to pass the device
serial number from OTP as the HKDF `info` parameter.  Currently it likely uses an
empty or default info string, making the SMK the same across all devices with the
same key material.

**5f. CSPRNG reseed hook not wired (`crypto/rng.rs:244`)**
`reseed()` exists as a hook for a future ChaCha20-based CSPRNG but currently does
nothing — the TRNG is used directly for every call.  A CSPRNG would allow
reseeding from TRNG periodically, improving performance for bulk random generation
and providing forward-secrecy properties.  The interrupt binding for the `Rng`
peripheral singleton also needs to be established in `main.rs` and a shared
reference passed to the RNG module (see `rng.rs:38`).

---

## 6. Board bringup — Hardware peripherals not driven

**6a. WS2812 LED on rp2350_one (`board/rp2350_one.rs:88`)**
`Ws2812Led::set_color()` stores the colour value but does not write to the LED.
The comment says "Wire up PIO0 / DMA0 in `init()` and replace the `_current`
field with a real `PioWs2812<PIO0, 0, 1>` handle."  Until fixed, the status LED
on the Pico One board is always off regardless of device state.

**6b. ST7789 LCD on rp2350_geek (`board/rp2350_geek.rs`)**
`init_lcd()` logs a warning and returns; `update_status_display()` is a no-op.
The `LcdDisplay::set_status()` method also does nothing except log via defmt.
Full implementation requires: store SPI + D/C + RST pin handles, implement the
ST7789 hardware reset + init command sequence, and render a status screen using
`embedded-graphics`.  All display-facing code is tagged `// TODO (display agent)`.

---

## 7. PIV and OpenPGP applets

Both protocols have placeholder stubs (`protocol/piv/mod.rs`,
`protocol/openpgp/mod.rs`) that compile and return `SW_INS_NOT_SUPPORTED`.
The Dispatcher (`apdu/dispatcher.rs`) already routes by AID to all three protocols.

**Architecture decision (2026-04-04):** implement as Cargo feature flags
(`applet-piv`, `applet-openpgp`, `applet-openpgp-curve25519`), not separate
firmware targets.  All three applets coexist in one binary and are selected at
runtime by `SELECT AID`.  See CLAUDE.md §"Multi-applet feature flag architecture"
for the full design including flash/RAM budget and feature flag usage.

**7a. Storage namespace — prerequisite for both applets**

This must be done before any command handler is written.  The flash keystore
currently has no concept of applet ownership; SC-HSM `INITIALIZE` would wipe PIV
and OpenPGP keys.

- Add an `owner: AppletId` field to `KeyObject` in `security/key_management.rs`.
- Reserve ID ranges in `storage/keystore.rs`: SC-HSM `0x01–0x7F`, PIV `0x80–0x8F`,
  OpenPGP `0x90–0x92`.
- Change SC-HSM `INITIALIZE` to call `wipe_by_owner(AppletId::ScHsm)` instead of
  `wipe_all()`.
- Add per-applet PIN slots to flash (SC-HSM already has one; PIV needs a second
  for its own PIN; OpenPGP needs PW1 + PW3).

**7b. PIV (`applet-piv` feature)**

3DES dependency is already wired: `des = { version = "0.8.1", ... , optional = true }`
in `Cargo.toml`, pulled in by `applet-piv = ["dep:des"]`.  The `applet-openpgp` and
`applet-openpgp-curve25519` feature stubs are also declared.

3DES usage notes (from research):
- Use `TdesEde3` (EDE, three-key, 24-byte key) — not `TdesEee3` or two-key variants.
- PIV GENERAL AUTHENTICATE challenge/response is **ECB** (single 8-byte block,
  no IV) — the `cbc` crate is not needed for this operation.
- `BlockEncrypt` / `BlockDecrypt` + `KeyInit` from `cipher 0.4` (already in tree).
- Do NOT upgrade to `des 0.9.0-rc.3` — it requires `cipher 0.5`, conflicting with
  all existing cipher crates pinned to `0.4`.

Commands to implement: SELECT, GET DATA, PUT DATA, VERIFY, CHANGE REFERENCE DATA,
RESET RETRY COUNTER, GENERAL AUTHENTICATE, GENERATE KEY PAIR.

Key slots: 9A (PIV Auth), 9C (Digital Sig), 9D (Key Mgmt), 9E (Card Auth),
82–95 (20 retired slots — implement last).

**7c. OpenPGP (`applet-openpgp` feature)**

Base applet (RSA + NIST ECC — all crypto already in): +10–15 KB flash.

Commands to implement: SELECT, GET DATA, PUT DATA, VERIFY (PW1/PW3), CHANGE
REFERENCE DATA, PSO:CDS, PSO:DEC, AUTHENTICATE, GENERATE KEY PAIR, GET CHALLENGE.

Key slots: SIG (0x90), DEC (0x91), AUTH (0x92).

**7d. Ed25519 / X25519 (`applet-openpgp-curve25519` feature)**

Adds `curve25519-dalek` (~45–60 KB release, not currently in binary at all) for
EdDSA signing and X25519 key agreement — the modern OpenPGP key defaults preferred
by GnuPG.  Gate behind its own sub-flag so NIST-ECC-only builds don't pay the cost.
