# RustCrypto 0.14 ECC migration (RUSTSEC-2026-0387) — design

**Status:** draft for owner approval, 2026-11-01.
**Ships as:** firmware 2.2.0; `pico2hsm-tool` follows in its own PR.

## Why

`cargo audit` reports RUSTSEC-2026-0387 (2026-10-23) against `crypto-bigint`
0.5.5. Several operations meant to be constant-time can take secret-dependent
branches depending on compiler and target: subtraction, zero counting,
division and Montgomery multiplication. Only `>= 0.7.6` is patched; 0.5 gets
no fix.

All firmware ECC reaches 0.5.5 through `elliptic-curve` 0.13: P-256, P-384,
P-521 and K-256 ECDSA and ECDH. That covers user keys, the device identity
key, the DKEK exchange, domain member certificates and the enrollment
handshake. Exploitability on the Cortex-M33 is unproven, but an HSM must not
carry a known constant-time defect in its key arithmetic. The firmware CI
audit step is `continue-on-error`, so this showed up only as a warning.

The fix is the RustCrypto 0.14 line, now stable: `p256`/`p384`/`p521`/`k256`
0.14.0, `elliptic-curve` 0.14.3 and `ecdsa` 0.17.0. They resolve to
`crypto-bigint` 0.7.10. A scratch crate with the firmware's exact feature
set builds for `thumbv8m.main-none-eabihf` (rustc 1.97.1).

## Goals

- No `crypto-bigint` < 0.7.6 in any firmware build; `cargo audit` no longer
  reports RUSTSEC-2026-0387.
- Byte-for-byte compatible: keys, the DKEK, domain records and certificates
  stored by 2.1.x load and work unchanged. No keystore format change, no
  re-INITIALIZE.
- Same ECC behaviour on the wire: CVCs, signatures, ECDH results and error
  status words.

## Non-goals

- **`rsa`.** 0.9 does not use `crypto-bigint`. Its Marvin advisory
  (RUSTSEC-2023-0071) is already tracked as residual S-09 in
  `docs/AUDIT_2026-10.md`. 0.10 is still a release candidate. Revisit when
  0.10 is stable.
- **Ed25519 / X25519 (`*-dalek` 2).** These don't use `crypto-bigint` and
  are unaffected.
- **Moving everything else to the new trait generation now.** That covers
  `sha2` 0.11, `hmac`/`hkdf`/`pbkdf2` 0.13, `aes-gcm` and `rand_core` 0.10
  everywhere. `rsa` 0.9 and `dalek` 2 still need the 0.10/0.6 versions, so
  a full move is blocked until they release. Doing the ECC alone fixes the
  advisory with the smallest change.

## Approach

**ECC-only migration, with the old and new trait generations side by side.**

- `p256`/`p384`/`p521`/`k256` 0.13 → 0.14, `elliptic-curve` → 0.14,
  `ecdsa` 0.16 → 0.17. ecdsa 0.17 has no `hazmat` feature; the firmware
  uses `bits2field`, `DigestPrimitive` and the prehash signer/verifier, so
  the right feature (`algorithm`) and the new paths are found at
  implementation time.
- 0.14 brings `rand_core` 0.10, `digest`/`sha2` 0.11, `hmac` 0.13,
  `signature` 3 and `hybrid-array` in place of `generic-array`. These sit
  next to the 0.6/0.10 versions that `rsa`, `dalek`, `aes-gcm`, `hkdf` and
  `pbkdf2` keep using.
- `FwRng` (`protocol/sc_hsm/mod.rs`) implements both the `rand_core` 0.6
  and the 0.10 traits over the same hardware TRNG/CSPRNG. Test RNGs do the
  same where the ECC tests need them. There is no second RNG and no new
  entropy path.
- Code changes are limited to the ECC call sites, about 140 uses in 9 files
  (`crypto/asymmetric.rs`, `crypto/kdf.rs`, `security/dkek.rs`,
  `security/key_blob.rs`, `domain/key.rs`, `domain/member.rs`, sc_hsm
  `mod.rs`/`extras.rs` and tests). Expected API churn:
  - `generic_array::ArrayLength` becomes `hybrid_array`;
  - `ScalarPrimitive` was renamed;
  - `signature` 3 traits;
  - `from_slice` / SEC1 constructors.
  These are exact paths to confirm while porting, not decisions.

## Proving compatibility (before and after)

1. **Known-answer vectors captured from 2.1.1 before any change.** For
   each curve:
   - a fixed scalar → its public point;
   - a fixed prehash → its deterministic RFC 6979 ECDSA signature;
   - ECDH with a fixed peer;
   - a stored key blob → decrypt → sign;
   - a DKEK exchange transcript;
   - a domain member certificate verify.
   The same vectors must pass after the migration. RFC 6979 makes
   signatures deterministic, so any arithmetic or encoding change shows up.
2. **Host suites** on every board configuration, as in CI.
3. **Hardware on the dev Pico 2s.** The full hw suite runs on the debug
   build, including two-device DKEK exchange and enrollment with the peer
   board. A store written by 2.1.1 (dev board, real keys) must keep
   working after the update.
4. **Budgets.**
   - Release flash and RAM per board, compared with 2.1.1.
   - Core1 stack depth re-measured on the worst path (P-521 sign; the
     CLAUDE.md procedure), because `crypto-bigint` 0.7 may change frame
     sizes. The 128 KB core1 stack must keep a margin.
   - Timing of P-384/P-521 sign against 2.1.1. The CCID time extension
     covers it either way, but a large regression gets noted.
5. **`cargo audit`** shows RUSTSEC-2026-0387 gone, and no new
   vulnerability.

## Rollout

1. Firmware PR (`feat/rustcrypto-014`), reviewed and merged.
2. Release 2.2.0, a minor version for the dependency-generation change.
   The CHANGELOG names the advisory.
3. Production boards get the signed 2.2.0 after it passes on the dev
   boards:
   - the One into slot 0;
   - the LCD board into slot B, keeping 2.1.1 in A as the fallback.
4. `pico2hsm-tool`: the same p256 0.13 → 0.14 bump. Host-side only
   (enrollment, signature checks), lower risk, but it clears the same
   advisory. `LATEST_FIRMWARE` → 2.2.0.
5. The CI audit job stays `continue-on-error`, so unrelated PRs aren't
   blocked by a new upstream advisory. Its warnings now also arrive as
   Dependabot alerts, enabled 2026-11-01.

## Risks

- **Size.** Duplicate `sha2`/`digest`/`rand_core` generations add flash.
  Flash is not tight (CLAUDE.md); RAM and core1 stack are what to watch.
- **Silent behaviour change in a rename** (for example scalar reduction or
  point validation). The known-answer vectors and the two-device hardware
  run are there to catch it.
- **The new versions are recent** (crypto-bigint 0.7.10 is 2026-10-26).
  They are the patched line. Pin exact versions in `Cargo.lock` as usual.
