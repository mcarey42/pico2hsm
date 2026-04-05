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

**2e. BIP-32 / SLIP-10 key derivation (`commands/bip_slip.rs`)**
Stub should call `crypto::kdf::bip32_derive()` or `slip10_derive()`.
The underlying `slip10_child_key` implementation is correct and tested against
all SLIP-0010 test vector 1 paths (m, m/0', m/0'/1, m/0'/1/2').

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

**Key ID scheme — u32 internal key ID:**

The internal key ID is a `u32` with the following layout:

```
bits 31–24: partition_id  (u8)  — 0 = default; extended by item 8
bits 23–16: applet_id     (u8)  — 0=SC-HSM, 1=PIV, 2=OpenPGP
bits 15–8:  reserved            — always 0
bits  7–0:  proto_ref     (u8)  — protocol-level key reference
```

Helper constructors:
- `KeyId::sc_hsm(partition, key_ref)` → `(partition<<24) | key_ref`
- `KeyId::piv(key_ref)` → `(1<<16) | key_ref`
- `KeyId::openpgp(slot)` → `(2<<16) | slot`

For partition 0 SC-HSM keys (current), `KeyId(proto_ref as u32)` — numerically
identical to the old u8 value, just stored as u32 LE in flash.

**Note: flash format change.** Existing stored keys become unreadable — re-INITIALIZE
after firmware update.  Bump `KEY_MAGIC` to `*b"P2K2"` to surface the incompatibility.

**Still required:**
- Add per-applet PIN slots to flash (SC-HSM already has one; PIV needs its own;
  OpenPGP needs PW1 + PW3).

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
- 3DES is **not** added to the SC-HSM service descriptor (no DES3 PKCS#11 mechanisms
  in sc-hsm driver); these functions are PIV-only.

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
