# Changelog

All notable changes to this project will be documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - YYYY-MM-DD

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
