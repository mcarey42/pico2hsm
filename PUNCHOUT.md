# pico2hsm — Punchout List

Items identified by mechanism audit (2026-04-03).  Each section describes what
is advertised by `pkcs11-tool -M` / the opensc sc-hsm driver and the current
state of the firmware and test suite.

---

## 1. RSA — Stubs only, zero tests

**What is advertised:**
`RSA-PKCS-KEY-PAIR-GEN`, `RSA-PKCS`, `RSA-X-509`, `SHA256/384/512-RSA-PKCS`,
`RSA-PKCS-PSS`, `SHA256/384/512-RSA-PKCS-PSS`, `RSA-PKCS-OAEP`
(all with `hw` flag for keygen/sign/decrypt)

**Current state:**
Every RSA function in `firmware/src/crypto/asymmetric.rs` returns
`CryptoError::UnsupportedAlgorithm`.  The `rsa` crate (v0.9) requires a heap
allocator (`Vec<u32>` internally); the firmware has no global allocator, so the
feature is compiled out.  No RSA tests exist anywhere in the test suite.

**What needs to happen:**
- Decide on an allocator strategy (options documented in `asymmetric.rs:29–41`):
  - Add a small static bump allocator (easiest, ~20–40 KB RAM cost).
  - Switch to a `no_std`-native big-integer RSA crate (e.g. `rsa` fork or
    `micro-rsa`) that does not need `alloc`.
- Implement `generate_rsa_keypair()`, `rsa_sign_pkcs1v15()`, `rsa_sign_pss()`,
  and `rsa_decrypt_oaep()` / `rsa_decrypt_pkcs1v15()` in `asymmetric.rs`.
- Wire RSA key types through the SC-HSM GENERATE KEY PAIR command
  (`generate_keypair.rs`) so that `pkcs11-tool --keypairgen --key-type RSA:2048`
  produces a stored RSA key pair.
- Wire RSA signing through the PSO COMPUTE DIGITAL SIGNATURE command (`sign.rs`)
  for algorithm IDs `0x31` (SHA-256/PKCS#1v1.5), `0x32` (SHA-384), `0x33`
  (SHA-512), `0x34` (PSS).
- Wire RSA decryption through the DECIPHER command (`decrypt.rs`) for algorithm
  ID `0x41`.
- Add integration tests (`test_06_rsa_keygen.py`, `test_07_rsa_sign.py`,
  `test_08_rsa_decrypt.py`) covering at minimum RSA-2048 keygen, PKCS#1v1.5
  sign+verify, PSS sign+verify, and OAEP decrypt.
- Evaluate core1 stack headroom: an RSA-2048 private key DER is ~1.2 KB; RSA-4096
  is ~2.4 KB.  Stack temporaries during RSA ops will be significant — check
  `CORE1_STACK` size before enabling.

---

## 2. ECDH for K-256 (secp256k1) — Protocol gap, crypto code present

**What is advertised:**
`ECDH1-DERIVE` and `ECDH1-COFACTOR-DERIVE` claim `keySize={192,521}`, which
covers the secp256k1 key size (256 bits).

**Current state:**
The crypto layer (`asymmetric.rs:492`) correctly implements
`ecdh_agree_curve::<k256::Secp256k1>` and unit tests pass.  However,
`tests/hw/conftest.py` marks the k256 slot with `"ecdh": False` and
`test_03_ecdh.py` documents that "ECDH1-COFACTOR-DERIVE is not supported for
that curve in the SC-HSM firmware".  The PSO / DERIVE command handler in the
protocol layer apparently does not route K-256 ECDH requests to the crypto
function — the exact failure mode (wrong algorithm ID mapping, missing branch,
or explicit rejection) has not been diagnosed.

**What needs to happen:**
- Investigate the PSO command handler (`pso.rs`) and the MSE SET command
  (`mse.rs`) to find where P-256/P-384/P-521 ECDH is dispatched and confirm
  whether K-256 is missing from the dispatch table or rejected for another
  reason.
- If it is simply a missing branch: add K-256 to the dispatch path, matching
  the existing pattern for the other curves.
- Add an ECDH test fixture for K-256 in `test_03_ecdh.py` (flip `"ecdh": True`
  in conftest once the fix is confirmed working on hardware).
- Update the expected secret-length table in the test (`_SECRET_LEN`) for
  `secp256k1` → 32 bytes.

---

## 3. ECDSA-SHA224 — Implemented, not tested

**What is advertised:**
`ECDSA-SHA224` with `hw` flag (sign/verify for all EC key sizes).

**Current state:**
`firmware/src/protocol/sc_hsm/commands/sign.rs:82` handles algorithm byte
`0x72` (ALGO_EC_SHA224) and dispatches to SHA-224 hashing.  The implementation
appears complete but there is no integration test covering it.  `test_04` covers
SHA-256/384/512; `test_05` covers SHA-1/MD5/RIPEMD-160/GOSTR3411-2012.
SHA-224 falls through the gap between the two files.

**What needs to happen:**
- Add `sha224` to the hash fixture list in `test_04_sign_hashes.py` (or create
  `test_04b` / extend `test_05`) parametrized over all four curves
  (P-256, P-384, P-521, K-256).
- The test should follow the existing cross-hash pattern: sign on-device via
  `pkcs11-tool --mechanism ECDSA-SHA224`, then verify the DER signature
  off-device with `openssl dgst -sha224 -verify`.
- Confirm `openssl` on the test host supports `SHA224withECDSA` (it does on any
  OpenSSL ≥ 1.0.2 build).

---

## 4. Key persistence — Keys are RAM-only, lost on reset

**Current state:**
`protocol/sc_hsm/commands/initialize.rs:155` has a TODO:
> "erase persistent flash keystore, write EF.DevAut, format RAID sectors."

Key pairs generated via GENERATE KEY PAIR are pushed into `ScHsmState.keys` (a
`heapless::Vec` in RAM).  On power-cycle or firmware reset, all generated keys
are gone.  The INITIALIZE command also does not durably write the DKEK share
count or the SO-PIN hash to flash.  The device currently behaves like a session
HSM only.

**What needs to happen:**
- Design a flash storage layout: key slots (key ID → DER private key), PIN/SO-PIN
  hashes, DKEK metadata, device certificate (EF.C.DevAut).
- Implement erase-on-INITIALIZE: wipe all key slots, write fresh SO-PIN hash and
  DKEK share count to flash.
- Implement write-on-GENERATE KEY PAIR: after generating an EC or RSA key pair,
  persist the private key DER to the corresponding flash slot.
- Implement read-on-boot: load key metadata (not necessarily the full private key,
  just IDs and types) into `ScHsmState.keys` from flash so LIST KEYS works after
  reset.
- Evaluate wear-levelling: private-key slots are written once and never
  overwritten (only deleted on INITIALIZE), so raw sector writes are acceptable;
  the PIN hash slot may need a small write-counter.
- Consider the existing `storage/mod.rs` and `security/otp.rs` modules as the
  starting point.

---

## 5. DKEK — Key backup/restore is fully stubbed

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

## 6. Remaining SC-HSM command stubs

These commands all return `SW_INS_NOT_SUPPORTED`.  They are lower priority than
items 4 and 5 but are needed for full SC-HSM compatibility.

**6a. PSO Sign / Decipher / MAC (`commands/pso.rs`)**
The PSO command handler (INS=0x2A) stubs out four operations.  Note: the current
working ECDSA sign path uses a separate INS (probably INS=0x68 via `sign.rs`);
PSO Sign may be a secondary compatibility path required by certain PKCS#11
operations or for RSA.  Needs investigation to determine if/when OpenSC routes
through PSO vs the direct sign command.
- `(0x80, 0x84)` — PSO: Compute Digital Signature → call `key_management::sign()`
- `(0x80, 0x86)` — PSO: Decipher → call `key_management::decrypt()`
- `(0x8E, 0x80)` — PSO: Compute Cryptographic Checksum (CMAC/HMAC)
- `(0x86, 0x80)` — PSO: Verify Cryptographic Checksum

**6b. Symmetric key generation (`commands/generate_key.rs`)**
INS for GENERATE KEY (symmetric).  Stub calls
`key_management::generate_symmetric_key()`.  Needed for AES key objects.

**6c. Symmetric cipher (`commands/cipher_sym.rs`)**
AES-CBC / AES-GCM encrypt/decrypt.  Stub should dispatch to `crypto::symmetric`
based on the current MSE (Manage Security Environment) state.

**6d. HKDF / PBKDF2 / X9.63 / CMAC / HMAC extras (`commands/extras.rs`)**
Six sub-operations under a single INS, all stubbed:
`HKDF-Extract`, `HKDF-Expand`, `PBKDF2-SHA256`, `X9.63-KDF`, `AES-CMAC`,
`HMAC-SHA256`.  The `crypto/kdf.rs` module has partial implementations; these
commands just need to be wired up.

**6e. BIP-32 / SLIP-10 key derivation (`commands/bip_slip.rs`)**
Stub should call `crypto::kdf::bip32_derive()` or `slip10_derive()`.
Note: the SLIP-10 child key derivation has a known bug (see item 8).

**6f. Asymmetric key derivation (`commands/derive_asym.rs`)**
INS=0x62 / P1=0x01.  Stub should call `crypto::kdf::x963_derive()` or
`hkdf_derive()` with the source key ID and derivation info from the command data.

**6g. Session PIN (`commands/session_pin.rs`)**
Generate a one-time session PIN, store with expiry.

**6h. External auth (`commands/external_auth.rs`)**
Verify a cryptogram over the stored INTERNAL AUTHENTICATE challenge using the
device auth key.  Must clear the challenge after use to prevent replay.

**6i. General auth (`commands/general_auth.rs`)**
Multi-step authentication state machine using the 0x7C TLV template.

**6j. PUK auth and PIN unblock (`commands/puk_auth.rs`)**
Constant-time PUK comparison, retry counter management, and PIN unblock logic.
Currently no PUK is stored.

---

## 7. Brainpool curves — Blocked on upstream crate

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

## 8. SLIP-10 child key derivation bug

**Current state:**
`firmware/src/crypto/kdf.rs:828` has a disabled test:
> "slip10_child_key child-key derivation produces a value that diverges from the
> SLIP-0010 reference test vector for m/0'.  Master-key derivation is correct.
> The discrepancy is in `scalar_add_mod` or the HMAC data construction for the
> child step.  Needs investigation and fix before enabling."

The master key derivation unit test passes; only the child step is wrong.  Because
`commands/bip_slip.rs` is also stubbed (item 6e), this bug is not yet
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

## 9. Security hardening — Several stubs awaiting hardware/crate API

**9a. PIN hash not zeroized (`commands/initialize.rs:46`)**
`hash_pin()` calls `Sha256::new()` / `finalize()` and copies the result, but the
`Sha256` state on the stack is not explicitly zeroized.  The comment says
"replace with proper zeroizing hash call."  Fix: use `sha2::Sha256` via the
`zeroize` crate's `ZeroizeOnDrop` wrapper or call `Zeroize::zeroize()` on the
digest object after copying.

**9b. Anti-glitch detector not armed (`security/anti_glitch.rs:153`)**
`arm_glitch_detector()` is a no-op stub.  The POWMAN VREG register fields
`GLITCH_DETECT_DISABLE` and `GLITCH_DETECT_SENS` are documented in the RP2350
TRM but not yet exposed by `embassy-rp` / `rp-pac`.  Software double-checks
(`double_check()`) are the current primary countermeasure.  Track the
`embassy-rp` / `rp-pac` crates for POWMAN VREG support.

**9c. OTP lock operations stubbed (`security/otp.rs:311, 326`)**
`Otp::lock_read()` and `Otp::lock_write()` return `Ok(())` without doing anything
because `embassy-rp 0.10` does not expose a lock API.  Fix requires PAC access to
OTP_DATA_RAW permission bits or the ROM `otp_access` function with a lock flag.
Currently non-fatal: provisioning proceeds but OTP rows are not read- or
write-locked after programming.

**9d. JTAG disable OTP row unverified (`security/otp.rs:222`)**
`disable_jtag_permanent()` uses row `0x110` bit 0 as the JTAG disable fuse, but
the comment notes this is the user-land flag and the hardware JTAG fuse may be at
a different row in OTP page 0.  Cross-reference RP2350 TRM §5.1 "OTP Boot Flags"
to confirm the correct row before this function is called in production
provisioning.

**9e. SMK derivation missing device serial (`security/otp.rs:364`)**
`derive_smk()` (Storage Master Key derivation) has a TODO to pass the device
serial number from OTP as the HKDF `info` parameter.  Currently it likely uses an
empty or default info string, making the SMK the same across all devices with the
same key material.

**9f. CSPRNG reseed hook not wired (`crypto/rng.rs:244`)**
`reseed()` exists as a hook for a future ChaCha20-based CSPRNG but currently does
nothing — the TRNG is used directly for every call.  A CSPRNG would allow
reseeding from TRNG periodically, improving performance for bulk random generation
and providing forward-secrecy properties.  The interrupt binding for the `Rng`
peripheral singleton also needs to be established in `main.rs` and a shared
reference passed to the RNG module (see `rng.rs:38`).

---

## 10. Board bringup — Hardware peripherals not driven

**10a. WS2812 LED on rp2350_one (`board/rp2350_one.rs:88`)**
`Ws2812Led::set_color()` stores the colour value but does not write to the LED.
The comment says "Wire up PIO0 / DMA0 in `init()` and replace the `_current`
field with a real `PioWs2812<PIO0, 0, 1>` handle."  Until fixed, the status LED
on the Pico One board is always off regardless of device state.

**10b. ST7789 LCD on rp2350_geek (`board/rp2350_geek.rs`)**
`init_lcd()` logs a warning and returns; `update_status_display()` is a no-op.
The `LcdDisplay::set_status()` method also does nothing except log via defmt.
Full implementation requires: store SPI + D/C + RST pin handles, implement the
ST7789 hardware reset + init command sequence, and render a status screen using
`embedded-graphics`.  All display-facing code is tagged `// TODO (display agent)`.

---

## 11. Future protocols — PIV and OpenPGP

Both protocols have placeholder module stubs that compile and dispatch to a
`process_apdu()` that returns an empty/error response.  No commands are
implemented.  These are intentionally deferred.

**11a. PIV (`protocol/piv/mod.rs`)**
Standard NIST SP 800-73-4 PIV card protocol.  Used by macOS/Windows login,
YubiKey-compatible tools, and many government/enterprise systems.

**11b. OpenPGP (`protocol/openpgp/mod.rs`)**
OpenPGP card protocol (BSI TR-03110).  Used by GnuPG / gpg-agent for SSH and
email signing.  GnuPG can drive the card via `--card-status` when OpenPGP AID is
selected.
