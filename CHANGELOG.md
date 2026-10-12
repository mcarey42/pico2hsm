# Changelog

All notable changes to this project will be documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Security and robustness release from the October 2026 audit
(`docs/AUDIT_2026-10.md` lists every finding with its commit).

### Added — domains, phase P2: enrollment (`docs/CLUSTER_PLAN_V3.md` §11b)
- **ISSUE_MEMBER_CERT (0x54/45, SO-PIN).**  Certifies an enrolling device
  with the domain key.  It only certifies the peer this device sent its
  DKEK to in this card session, or the currently pinned peer; either is
  spent.  The issuing device's own certificate must be active with
  may-sponsor (the default).  The Lamport counter is advanced first.
- **REVOKE_MEMBER (0x54/46, SO-PIN)** returns a 121-byte revocation record
  signed with the domain key.  The entry stays, marked revoked.  A device
  never revokes itself.  **Revocation is permanent** for that member key
  (owner decision 8).
- **IMPORT_MEMBER_CERT (0x54/49) and IMPORT_REVOCATION (0x54/4A), no PIN.**
  The device checks the domain signature and the domain, and refuses
  duplicates and revoked members.  Certificates and revocations are
  ranked, so every member keeps the same ones.  A full list (32 entries,
  revoked included) gets `6A84`.
- **GET_MEMBERS v2** (data `02`): 277-byte entries carrying each revoked
  member's revocation, so hosts can carry revocations between devices.
  DOMAIN_STATUS flags `10` (a served peer awaits its certificate) and `20`
  (this device is revoked).
- Python reference and vectors: revocations and the enrollment short
  authentication string (`firmware/tests/vectors/enrollment_v1.txt`).
  Hardware test `tests/hw/test_19_enrollment.py` (two devices).

### Changed — domains, phase P2
- Member-list entries are stored in version 2 (277 bytes); P1's
  version-1 entries still load.
- The plan's §4.2 is corrected: INITIALIZE generates the device (member)
  key from the TRNG, so a re-initialised device is a new member.

### Added — domains, phase P1 (`docs/CLUSTER_PLAN_V3.md` §11a)
- **Persisted Lamport counter.**  The SC-HSM generation counter is now a
  `u64` on internal flash (a new record kind in the retry-counter log),
  advanced before every key or file change it numbers and never reset —
  not by a reboot, not by INITIALIZE.  A change whose counter cannot be
  written is refused (6581).  `GET_GENERATION` (0x54/34),
  `GET_GENERATION_V2` (0x54/3C) and `GET_STATE_HASH` (0x54/3A) report it.
- **Domain key and DOMAIN_STATUS (0x54/40, no PIN).**  Every device with
  the same DKEK derives the same P-256 domain key (HKDF-SHA256 from the
  DKEK) and reports the same `domain_id`, with the KCV, `Q_domain`, its own
  member ID, the Lamport counter and production/development mode.
  Independent Python reference `tools/python/pico2hsm/domain.py`; vectors
  `firmware/tests/vectors/domain_v1.txt` (shared with `pico2hsm-tool`).
- **Member certificates and list, GET_MEMBERS (0x54/47, no PIN).**  A
  device that completes a DKEK certifies itself with the domain key; up to
  32 certificates are kept.  Members are named by
  `SHA-256(member_pub)[0..16]`, not by a serial number.
- **Global object IDs.**  EC/RSA keys: OpenSC's intrinsic CKA_ID (SHA-1 of
  the X coordinate / modulus); AES keys and standalone files: a random
  16-byte ID in a per-object sidecar, assigned at creation.
  `GET_KEY_MANIFEST` with data `02` lists them.

### Changed — domains, phase P1
- **ENROLL_PEER_PUBKEY (0x54/3D) pins the peer for one DKEK exchange**
  instead of enrolling it permanently in key reference 0xFC; the exchange
  that completes spends the pin.  A 0xFC enrollment from earlier firmware
  becomes the pin at the first boot.
- **GET_KEY_MANIFEST (0x54/39) has no 32-key cap:** paged by P2 (first key
  reference), each page as large as one response allows (GET RESPONSE
  chaining).
- **Synthesised PRKDs carry the intrinsic CKA_ID** (SHA-1 of the public X
  coordinate or modulus) instead of the key reference, for keys that have
  no PRKD written by OpenSC — the CKA_ID no longer depends on the slot.
  PRKDs written by OpenSC (every `pkcs11-tool --keypairgen`) are unchanged.
- **SC-HSM INITIALIZE also erases the domain records** (member list,
  object sidecars, pinned peer), which depend on the DKEK it clears.

### Breaking
- **WRAP / UNWRAP KEY use the SmartCard-HSM (CardContact) key blob** —
  KCV = SHA-256(DKEK)[0..8], AES-256-CBC under SHA-256(DKEK‖00000001) with
  an 8-byte random prefix, AES-CMAC under SHA-256(DKEK‖00000002) — so
  backups move between pico2hsm, real SmartCard-HSMs, pico-hsm and
  `sc-hsm-tool --wrap-key` / `--unwrap-key` files.  EC (P-256, P-384,
  P-521, secp256k1), RSA (written as RSA-CRT; RSA and RSA-CRT read) and AES
  keys; the key's algorithm list travels in the blob's own field.
  Ed25519, X25519, brainpool and BIP32 keys have no CardContact encoding:
  WRAP refuses them with 6A81.  Layout and sources:
  `docs/SC_HSM_APDU_REFERENCE.md` §3.32.
- **The KCV changes** to the CardContact value SHA-256(DKEK)[0..8] (it was
  AES-CMAC(DKEK, 0¹⁶)[0..8]): KEY DOMAIN and `sc-hsm-tool` now show the
  same check value as a SmartCard-HSM loaded with the same shares.
  Compare KCVs only between devices on this firmware.
- **KEY DOMAIN P1=00 response follows OpenSC:** `[shares, missing, KCV]`
  (bytes 0 and 1 were swapped, so `sc-hsm-tool` reported the share count
  wrong), and P1=00 without data now answers the status query
  (`sc-hsm-tool` with no command) instead of 6A80; P2≠0 is 6A86, no DKEK
  configured is 6A88.
- **Deprecated: the pico2hsm wrap formats v2 and v3** (`KCV' || 0x02/0x03
  || IV || CBC || HMAC`).  UNWRAP still imports them for this release; the
  next release drops them.  WRAP no longer writes them: re-wrap backups
  made with earlier firmware (unwrap the old blob, wrap again).  v1 blobs
  (no MAC) stay refused.
- **GENERATE KEY PAIR, P-521:** the order (CVC tag 85) was one byte short;
  it is now the 66-byte order.
- **SC-HSM EF file IDs** are stored under new KeyIds (the full 16-bit FID).
  Certificates written by OpenSC must be re-imported; INITIALIZE regenerates
  the device-key EF 2F02.
- **DKEK exchange (EXTRAS 0x35–0x38)** requires the SO-PIN and an enrolled
  peer on both devices; unauthenticated "bootstrap" mode is removed.
  `hsm-tool dkek-exchange` takes `--so-pin`; the TCP relay framing is `P2H2`.
- **EXTERNAL AUTHENTICATE (INS 0x82) removed** (it accepted the stored
  SO-PIN hash as the key). Returns 6D00.
- **Minimum SC-HSM user PIN length is 6** for VERIFY, CHANGE PIN and RESET
  RETRY (INITIALIZE already required 6).
- **GET_KEY_MANIFEST (EXTRAS 0x39) requires the user PIN.**
- **OTP boot flags moved from row 0x110 to 0x140** (0x110 was inside the
  storage-key rows). Never write row 0x110.
- **Release builds on unprovisioned OTP disable the keystore** instead of
  using a fixed public key (debug builds, or the `insecure-dev-keystore`
  feature, keep the development key with a boot warning).
- **PIV GENERATE KEY PAIR requires the management key** (the PIN alone
  was accepted).
- **Missing or unreadable PIN records load as blocked** (PIV PIN/PUK and
  management key; OpenPGP PW1/PW3) when the applet holds keys, instead of
  falling back to the factory defaults.  The records are now written
  before an applet's first key.  A board that already has PIV keys from
  earlier firmware, without a stored management key, comes up locked out:
  run `ykman piv reset` (APDU `00 FB 00 00`, newly supported, allowed only
  while PIN and PUK are blocked).  OpenPGP TERMINATE is now allowed once
  PW3 is blocked (`gpg --card-edit` → `factory-reset`).
- **Keystore directory is kept as two copies (A/B, sectors 0 and 1)** with a
  sequence number and CRC32, so a power cut during a directory write can no
  longer lose every key.  Existing keystores are read and upgraded on the
  first write; firmware older than this can't read the new format, so
  don't downgrade a board after it has written keys.
- **PIN/PUK retry counters moved to a dedicated counter log** on internal
  flash (`0x1FC000`–`0x200000`, the top 16 KB of the firmware partition,
  on every board including the SD-card ones; see
  `firmware/src/storage/retry_counter.rs`).  The firmware image limit
  shrinks by 16 KB accordingly (`boards/*.x`).  **Migration:** the first
  boot of this firmware copies the counts from the existing PIN records
  (SC-HSM user PIN / SO-PIN / PUK, PIV PIN / PUK, OpenPGP PW1 / PW3) into
  the log, then zeroes them in the records; nothing to do by hand.  If
  that boot can't read a record, every credential loads blocked for that
  boot and the migration runs again on the next one.  **Don't downgrade
  afterwards:** older firmware reads the zeroed records as "every
  credential blocked".  A PIN record without a counter entry (e.g. the
  counter sectors erased on their own) also loads blocked.

- **SC-HSM CIPHER (INS 0x78) AES-CBC no longer pads**: encrypt and
  decrypt work on whole blocks (the host pads), as CardContact's
  `ALGO_AES_CBC_ENCRYPT`/`_DECRYPT`.  Decrypt stripped PKCS#7 and answered
  bad padding with 6985 — a padding oracle.  Other lengths are 6700.
- **SC-HSM DECIPHER P2=0x22 is refused (6D00)**: it ran the raw RSA
  operation of 0x21; card-side unpadding would be a Bleichenbacher oracle.
  OpenSC sends 0x21 only.
- **SC-HSM RSA PKCS#1 v1.5 signature IDs follow the CardContact spec**:
  0x31–0x35 = SHA-1/224/256/384/512 hashed by the card (they were
  SHA-256/384/512 over a host digest, and 0x34 was PSS).  OpenSC uses 0x20.
- **PIV 9D and the retired slots 82–95 no longer sign** (key establishment
  only, ECC CDH with tag 85); 9A/9C/9E no longer accept tag 85
  (SP 800-73-4 / SP 800-78-4).
- **OpenPGP algorithm attributes must match the key role**: C1/C3 ECDSA or
  EdDSA, C2 ECDH; other values (and RSA) are 6A80.
- **Keys with a usage policy use the new object magic `P2KP`**: firmware
  before this release refuses them (keys without a policy stay `P2K4`).
  (Wrap format version 3, which carried the policy, is superseded by the
  CardContact blob above; UNWRAP still reads it this release.)

### Security
- **Per-key usage policy (audit S-10).** SC-HSM keys take the CardContact
  attributes 90 (use counter), 91 (algorithm list) and 92 (key domain) at
  generation and unwrap; every use is checked against the list and spends
  the counter on flash before the operation (6A84 when exhausted, 6985 when
  the algorithm is not allowed); SELECT CCxx reports them; WRAP/UNWRAP
  carry the list (CardContact blob field), keys with a counter are not
  exportable.  PIV
  stores and enforces the Yubico PIN policy (AA) with the SP 800-73-4 slot
  defaults, accepts touch policy only default/never (no button), and "PIN
  always" is used up by the next GENERAL AUTHENTICATE of any slot.
  OpenPGP: PW1 status byte (C4) writable and enforced, signature counter
  (DO 93) persisted before each signature leaves the card.
- PIN / SO-PIN / PUK retry counters (SC-HSM, PIV, OpenPGP) are written to
  flash before the credential is compared; a reset no longer restores
  guesses. Re-INITIALIZE counts against the SO-PIN.
- Credential checks no longer wear out the keystore directory (audit
  R2-4).  A failed attempt now programs one 16-byte record into the
  append-only counter log (no erase), a success one more; PIN records and
  the keystore directory are rewritten only when a credential changes.  A
  4 KB counter sector is erased once per ~248 records, rotating over four
  sectors: roughly 50 million successful VERIFYs before the sectors reach
  100k erase cycles, against ~100k VERIFYs before.  The counters are kept
  as a monotonic failure total plus a snapshot at the last success, so a
  later OTP-backed total can make flash-image rollback reduce, never
  restore, the remaining tries.
- DKEK exchange only encrypts the DKEK to the ephemeral key the enrolled peer
  signed; the DKEK is persisted (it was lost on every reset).
- Reserved key refs 0xFC–0xFF can no longer be used, exported or overwritten
  through user key commands.
- RSA private operations are blinded; the raw path is fault-checked.
- P-521 ECDSA uses hedged RFC 6979 nonces; RNG failures reset the chip.
- OpenPGP: salted PBKDF2 password records, one guess per CHANGE PIN, PSO:CDS
  needs PW1 mode 81, TERMINATE erases flash records.
- PIV: SET MANAGEMENT KEY (Yubico extension); data objects persisted.
- BIP/SLIP derive honours NO_EXPORT and refuses the empty path.
- OTP key page read-locked at boot; failures fail closed.
- Secrets wiped in place: reset, DKEK copies, key buffers, response buffers.

### Added
- SC-HSM GENERATE SYMMETRIC KEY accepts the SmartCard-HSM form (P2 =
  B0/B1/B2, data = key attributes); storage errors are 6581.
- PIV: retired key management slots 82–95; GET METADATA (INS F7); VERIFY
  P1=FF resets the PIN status.
- OpenPGP: PUT DATA C4; GET DATA 7F74 (no button) and 7F74 in 6E.
- **Hardware watchdog armed on every board** (8 s timeout, paused while a
  debugger halts either core).  Core0 feeds it from an executor task only
  while core1 is idle, making progress, or under the RSA-keygen
  suppression; a core1 stuck for 30 s on any path (including the
  USB-disconnect drain) or a hung core0 now resets the whole chip — both
  cores, USB and all peripherals.  Long flash/SD work and key loads feed it
  as they go.  The reason for the previous reset (watchdog timeout,
  deliberate reset with cause, or other) and a consecutive-watchdog-reset
  count are logged at boot (defmt and the CDC log).  Debug builds
  (`debug` feature) add test hooks: DEBUG APDU `80 FE 10/11/12 00` wedges
  core1, wedges core0, or resets through the watchdog.

### Fixed
- USB-disconnect reset deadlock on QMI-flash boards.
- Core1 stack: worst path ~123 KB → ~70 KB of 128 KB.
- Responses with ≥4095 data bytes lost their status word.
- Watchdog abort left core1 running (replies off by one); now resets.
- Deliberate resets (core1 stall, TRNG failure, failed boot check) use the
  watchdog trigger instead of `SYSRESETREQ`, which on RP2350 is only a
  processor warm reset.
- CCID time extensions are sent on time during long flash work.
- Oversized CCID messages no longer desync the bulk pipe.
- Storage write errors are reported instead of ignored.
- IMPORT KEY validates key length (over-long keys hard-faulted core1).
- PIV data objects (certificates, CHUID) survive reset; unique CHUID GUID.
- Core0 MSPLIM covers the RTT buffer.
- CI: clippy gate passes on current stable; PIV/OpenPGP built and tested.
- Builds without `rsa` store certificates and data objects of the same
  size as RSA builds (PIV objects up to 2048 bytes, OpenPGP 7F21 up to
  1024, SC-HSM EFs up to 2400); they were capped at 512 bytes, so EC
  certificates failed closed.  CI builds and tests the applets without
  `rsa` too.

## [1.0.1] - 2026-04-29

First maintenance release of the v1.0 line.  Three coupled SC-HSM bug fixes
plus the test/doc updates that exercise them.  No behaviour change for code
paths that were already passing on v1.0.0.

### Fixed
- **SC-HSM INS=0x62 routing.** `DECIPHER` (P1 = key reference, P2 = algo)
  and the proprietary `DERIVE_ASYM` (P1 = 0x01, P2 = 0x00) were previously
  disambiguated by `P1` alone, which mis-routed a legitimate P-256 ECDH
  `DECIPHER` on slot 1 to `derive_asym` because OpenSC assigns
  `key_ref = 0x01` to the first generated key.  Routing now requires both
  `P1 = 0x01` AND `P2 = 0x00` (DECIPHER's P2 is always a non-zero algo
  code), restoring P-256 ECDH on slot 1.
- **Core1 reset stack overflow risk.** The Core1 dispatcher loop's
  USB-reconnect path used `*dispatcher = Dispatcher::new()`, which
  materialises the ~82 KB `Dispatcher` struct on the Core1 stack before
  copying it into BSS — risking a silent stack overflow on the second
  reconnect in a long test session.  Replaced with a new
  `Dispatcher::reset_in_place()` that rewrites fields through
  `addr_of_mut!`, keeping peak added stack usage to a few hundred bytes.
- **RSA keygen disarms the time-extension stall detector.** Miller-Rabin
  prime-search makes no RNG calls, so `WATCHDOG_HEARTBEAT` stops bumping
  during a long keygen and the stall detector previously tripped.  All
  four board run loops (`pico2_4m`, `rp2350_one_4m`, `rp2350_geek_*`,
  `waveshare_rp2350_lcd_*`) now honour a `WATCHDOG_SUPPRESS` flag — while
  set, `stall_count` resets and CCID time extensions keep flowing until
  keygen completes.

### Changed
- `tests/hw/test_03_ecdh.py` uses `ECDH1-DERIVE` uniformly across all four
  curves now that the firmware INS=0x62 routing fix lets P-256 derivations
  reach the device through plain DERIVE.  Removes the per-curve mechanism
  switch.
- `tests/hw/test_11_dkek_roundtrip.py` `LIST_KEYS` APDU now sends
  `80 58 00 00 00` (Le=0) instead of `80 58 00 FF 00` (P2=0xFF, malformed
  for this command).  Adds diagnostic logging when no `0xCC` slot is found
  so future regressions surface in the test log instead of returning
  `None` silently.

### Documentation
- `docs/SC_HSM_APDU_REFERENCE.md` documents the OpenSC 0.25 sc-hsm-driver
  rejection of `ECDH1-COFACTOR-DERIVE` for P-256 (returns SW=6985 →
  `CKR_GENERAL_ERROR`) so future developers don't waste time chasing the
  symptom.

## [1.0.0] - 2026-04-18

First stable release of the pico2hsm firmware.

### Added
- Multi-applet support: SC-HSM (always on), PIV (NIST SP 800-73-4), and OpenPGP
  Card 3.4 are selectable at compile time and activated at runtime via
  `SELECT AID`. All three applets share one encrypted flash keystore with a
  per-applet `KeyId` namespace.
- OpenPGP Ed25519 and X25519 support behind the `applet-openpgp-curve25519`
  feature flag.
- Secure provisioning workflow: `picotool seal` firmware signing (secp256k1),
  OTP-backed secure boot, JTAG disable, and glitch-detector enable. See
  `docs/PROVISIONING.md`.
- V2 Noise_XX DKEK exchange with peer-public-key enrollment command
  (`P1=0x3D`, SO-PIN gated) and permanent lockout of unauthenticated V1 DKEK
  transfers.
- Core1 liveness watchdog based on the RNG heartbeat; core0 returns SW 6F00
  after 4.5 s with no crypto progress so a stuck key operation no longer
  requires a power cycle.
- Malformed/hostile APDU fuzz test suite (`tests/hw/test_16_fuzz_malformed.py`,
  81 parametrized cases) covering truncated TLV, boundary lengths, wrong
  CLA/INS, oversized payloads, and protocol violations.
- Production runbook (`docs/PROVISIONING.md`), quickstart (`QUICKSTART.md`),
  incident response runbook (`docs/INCIDENT_RESPONSE.md`), support guide
  (`docs/SUPPORT.md`), and contributor and security policies
  (`CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`).

### Changed
- Core1 now runs a synchronous `dispatcher_loop()` using ARM WFE/SEV rather
  than an Embassy executor, reclaiming ~61 KB of BSS previously consumed by
  async state machines.
- Core1 stack increased to 128 KB to prevent silent stack overflow in the
  SC-HSM dispatch chain (measured peak ~65 KB).
- PIN storage hardened: PBKDF2-HMAC-SHA256 with 10,000 rounds and a 16-byte
  random salt replaces the previous unsalted hash.
- TLS sync between paired devices (Python daemon) now always uses a real
  P-256 ECDSA identity; the `CERT_NONE` fallback paths are removed.
- Flash keystore format upgraded to `"P2K4"` (21-byte header with a
  `key_flags` byte); `"P2K2"` and `"P2K3"` blobs are recognized as legacy and
  require re-INITIALIZE after upgrading from older firmware.
- Supported-version policy: `1.0.x` is the current stable series; `0.9.x`
  pre-1.0 development snapshots are no longer maintained.

### Fixed
- Secure boot OTP row constants: CRIT1 is rows `0x40`–`0x47` (RBIT-8), not
  row `0x18` as earlier code mistakenly wrote. SECURE_BOOT_ENABLE is CRIT1
  bit 0; all 8 RBIT-8 copies are now programmed via `picotool otp set
  OTP_DATA_CRIT1.*`.
- Constant-time comparisons for INITIALIZE SO-PIN and for PKCS#7 padding in
  `dkek.unwrap()` (previously short-circuited).
- Challenge replay cache correctly rotates past 16 entries (separate write
  pointer and read count).
- `NO_EXPORT` key flag is now enforced across flash round-trips.
- DKEK wrap/unwrap buffers resized to 2400 bytes to support RSA-4096 keys.
- ECDH P-256 OpenPGP decipher regression and OpenSC 0.25-rc1 interop
  xfails resolved.
- CCID time-extension messages (every 1.5 s) keep pcscd from dropping the
  connection during long ECDSA sign operations (P-384, P-521, K-256).

### Security
- JTAG and secure-debug disable fuses, plus glitch-detector enable, are part
  of the documented provisioning workflow.
- V1 DKEK exchange (unauthenticated ephemeral ECDH, P1=0x31–0x33) returns
  `SW_INS_NOT_SUPPORTED`; only the V2 authenticated path is usable.
- `cargo audit` runs on every CI build.
- `debug_dump` APDU module is feature-gated at the module level; release
  builds cannot expose memory-read debug commands.
- Supported-version table in `SECURITY.md` is the canonical statement of
  which releases receive security fixes.

[Unreleased]: https://github.com/mcarey42/pico2hsm/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/mcarey42/pico2hsm/releases/tag/v1.0.0
