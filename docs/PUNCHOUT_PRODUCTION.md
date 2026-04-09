# pico2hsm Production Readiness Punchout

Generated from three-team review (pentest, code quality, standards compliance) 2026-04-09.
Last updated: 2026-04-09 — all agent fixes landed.

Status key: `[ ]` open · `[~]` in-progress · `[x]` done · `[>]` deferred · `[-]` N/A

---

## P0 — Ship Blockers

| ID | Status | Title | Branch | Notes |
|----|--------|-------|--------|-------|
| P0-1 | [-] | Firmware signing key in repo | — | Non-issue: build-tree artifact, not checked in |
| P0-2 | [x] | JTAG/CRIT0 hardware fuse never written | worktree-agent-a185ced7 | CRIT0 row 0x18 bit 2 now burned via `write_raw_word`; double-burn guard |
| P0-3 | [x] | OTP read-lock is a stub | worktree-agent-a185ced7 | `lock_read()` programs `OTP.sw_lock(page)` to INACCESSIBLE |
| P0-4 | [x] | SMK zero-fallback on unprovisioned devices | worktree-agent-aabccc16 | Production+provisioned → panic; dev → warn + zero fallback |
| P0-5 | [x] | Silent flash-op queue overflow | worktree-agent-aabccc16 | Queue full → `StorageError::WriteError` propagated to APDU handler |

---

## P1 — Security Vulnerabilities

| ID | Status | Title | Branch | Notes |
|----|--------|-------|--------|-------|
| P1-1 | [x] | PIN uses bare SHA-256, not PBKDF2 | worktree-agent-a1df385e | PBKDF2-HMAC-SHA256 10K rounds + 16-byte salt; pin blob 101→149 bytes; re-INITIALIZE required |
| P1-2 | [x] | `double_check()` has zero call sites | worktree-agent-a1df385e | Double-checked PIN verify + EXTERNAL AUTH HMAC; mismatch → SW_SECURITY_STATUS |
| P1-3 | [x] | `is_production_mode_otp()` fails open | worktree-agent-a185ced7 | Returns `Result<bool,()>`; OTP read error → `sys_reset()` |
| P1-4 | [x] | Secure boot not asserted at runtime | worktree-agent-a185ced7 | Production mode + secure boot disabled → `sys_reset()` |
| P1-5 | [x] | EXTERNAL AUTHENTICATE has no retry counter | worktree-agent-a1df385e | `ext_auth_retry_count: u8` (init 5); empty data → 63CX; blocked → 6983 |
| P1-6 | [x] | DKEK unauthenticated mode is permanent | worktree-agent-a1df385e | `dkek_unauthenticated_allowed` flag; false after first unauth exchange |
| P1-7 | [x] | RSA-4096 mapped to RSA-2048 storage type | worktree-agent-aabccc16 | `algo_to_core_key_type()` uses blob length to distinguish; `RsaPrivate4096` variant |

---

## P1 — Interoperability Blockers

| ID | Status | Title | Branch | Notes |
|----|--------|-------|--------|-------|
| I1-1 | [x] | No GET RESPONSE (INS=0xC0) | worktree-agent-aa6445452 + ac39b2e63 + a4ed9ee16 | Implemented per-applet with pending response buffer + SW=61xx chaining |
| I1-2 | [x] | SC-HSM EXPORT KEY wrong INS | worktree-agent-aa6445452 | 0x34 aliased to export; 0x58 conflict with LIST KEYS documented — import stays at 0x74 |
| I1-3 | [x] | PIV slot 9C PIN-always not enforced | worktree-agent-ac39b2e63 | `pin_verified = false` after every successful 9C sign |

---

## P2 — Spec-Mandated Features

| ID | Status | Title | Branch | Notes |
|----|--------|-------|--------|-------|
| P2-1 | [x] | OpenPGP RESET RETRY COUNTER (INS=0x2C) | worktree-agent-a4ed9ee16 | P1=0x00 resets count; P1=0x02 resets + sets new PW1; requires PW3 |
| P2-2 | [x] | OpenPGP TERMINATE DF + ACTIVATE FILE | worktree-agent-a4ed9ee16 | terminate wipes state; activate factory-resets; terminated → SW=6285 for all other cmds |
| P2-3 | [x] | PIV Security Object (5FC106) missing | worktree-agent-ac39b2e63 | Minimal compliant empty mapping `53{BA 00, BB 00, FE 00}` |
| P2-4 | [>] | PIV retired key slots 0x82–0x95 | — | Deferred: 20 slots × key gen + auth = substantial scope |
| P2-5 | [x] | OpenPGP DO 5F50 + DO 7F21 missing | worktree-agent-a4ed9ee16 | url (254B) + cardholder_cert (1024B) in state; GET+PUT DATA wired |
| P2-6 | [x] | OpenPGP Extended Capabilities understated | worktree-agent-a4ed9ee16 | byte 0: 0x44→0x54; cert max 0x0400; special DO max 0x00FE |
| P2-7 | [x] | PIV CHUID FASC-N hardcoded test value | worktree-agent-ac39b2e63 | FIPS 201-2 Appendix B non-federal test FASC-N verified and documented |
| P2-8 | [x] | PIV PIN not constrained to digits 0–9 | worktree-agent-ac39b2e63 | 0x30–0x39 range check in VERIFY + CHANGE REFERENCE DATA |
| P2-9 | [x] | RSA keys absent from SC-HSM PKCS#15 PRKDF | worktree-agent-aa6445452 | RSA keys emitted as `A1` PKCS#15 entries; 0xC4XX dispatch covers RSA; gated `#[cfg(feature="rsa")]` |

---

## P3 — Code Quality & Correctness

| ID | Status | Title | Branch | Notes |
|----|--------|-------|--------|-------|
| P3-1 | [ ] | PIV applet: zero unit tests | — | Follow-on milestone |
| P3-2 | [ ] | OpenPGP applet: zero unit tests | — | Follow-on milestone |
| P3-3 | [ ] | SC-HSM sign/read_binary/mse/decrypt: no unit tests | — | Follow-on milestone |
| P3-4 | [x] | CSPRNG never reseeded after boot | worktree-agent-a2b0e00dc | AtomicU32 counter; reseed every 1,000 `fill_random()` calls |
| P3-5 | [x] | `DispatcherPtr` two-await window | worktree-agent-aabccc16 | SeqCst fence before/after raw-ptr deref; expanded safety comment |
| P3-6 | [ ] | `FRAMEBUF` UnsafeCell aliasing | — | Needs per-board audit; low risk given task-level serialization |
| P3-7 | [>] | Directory sector wear | — | Deferred: requires storage redesign |
| P3-8 | [x] | OpenPGP PSO:DECIPHER `0x04` fallback | worktree-agent-a4ed9ee16 | A6 wrapper required unconditionally; 0x04 bypass removed |
| P3-9 | [x] | SD card init panics on missing card | worktree-agent-aabccc16 | Graceful degraded-mode; USB stays up; key ops fail cleanly |
| P3-10 | [x] | No board feature = silent infinite loop | worktree-agent-aabccc16 | `compile_error!` at compile time |

---

## Summary

| Priority | Total | Done | Open | Deferred | N/A |
|----------|-------|------|------|----------|-----|
| P0 | 5 | 4 | 0 | 0 | 1 |
| P1 (security) | 6 | 6 | 0 | 0 | 0 |
| P1 (interop) | 3 | 3 | 0 | 0 | 0 |
| P2 | 9 | 8 | 0 | 1 | 0 |
| P3 | 10 | 6 | 3 | 1 | 0 |
| **Total** | **33** | **27** | **3** | **2** | **1** |

## Remaining Open Items
- **P3-1/P3-2/P3-3**: Unit tests for PIV, OpenPGP, SC-HSM command handlers — follow-on milestone
- **P3-6**: FRAMEBUF UnsafeCell aliasing audit — low priority; task-level serialization provides practical safety

## Deferred Items
- **P2-4**: PIV retired key slots 0x82–0x95 — substantial scope, next milestone
- **P3-7**: Directory sector wear leveling — requires storage redesign

## Branches to Merge
All fixes live in isolated worktrees. Merge order (minimize conflicts):
1. `worktree-agent-a185ced7` — boot/OTP (security/ only)
2. `worktree-agent-a2b0e00dc` — CSPRNG (crypto/ only)
3. `worktree-agent-aabccc16` — storage/main.rs
4. `worktree-agent-a1df385e` — pin/auth (sc_hsm/commands/ + security/)
5. `worktree-agent-aa6445452` — SC-HSM compliance (sc_hsm/ + dispatcher.rs)
6. `worktree-agent-ac39b2e63` — PIV compliance (piv/ only)
7. `worktree-agent-a4ed9ee16` — OpenPGP compliance (openpgp/ + core apdu.rs)
