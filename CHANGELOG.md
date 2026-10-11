# Changelog

All notable changes to this project will be documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Security and robustness release from the October 2026 audit
(`docs/AUDIT_2026-10.md` lists every finding with its commit).

### Breaking
- **DKEK-wrapped key blobs use a new authenticated format (v2):**
  `KCV || 0x02 || IV || CBC || HMAC-SHA256-128`. v1 blobs (no MAC) are
  refused; re-export backups made with earlier firmware.
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

### Security
- PIN / SO-PIN / PUK retry counters (SC-HSM, PIV, OpenPGP) are written to
  flash before the credential is compared; a reset no longer restores
  guesses. Re-INITIALIZE counts against the SO-PIN.
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

### Fixed
- USB-disconnect reset deadlock on QMI-flash boards.
- Core1 stack: worst path ~123 KB → ~70 KB of 128 KB.
- Responses with ≥4095 data bytes lost their status word.
- Watchdog abort left core1 running (replies off by one); now resets.
- CCID time extensions are sent on time during long flash work.
- Oversized CCID messages no longer desync the bulk pipe.
- Storage write errors are reported instead of ignored.
- IMPORT KEY validates key length (over-long keys hard-faulted core1).
- PIV data objects (certificates, CHUID) survive reset; unique CHUID GUID.
- Core0 MSPLIM covers the RTT buffer.
- CI: clippy gate passes on current stable; PIV/OpenPGP built and tested.

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
