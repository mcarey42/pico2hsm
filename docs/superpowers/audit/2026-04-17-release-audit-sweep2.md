# Release Audit Sweep-2 — 2026-04-17

**Auditor run:** Phase 5 (verification diff against Phase 1 audit)
**Commit audited:** `fa79af7554d34c0d2f8b8ee4901e41c704518206`
**Branch:** `release-prep/v1.0.0`
**Prior audit:** `docs/superpowers/audit/2026-04-16-release-audit.md` (commit `cc36a06`)
**Verdict:** **READY** for Phase 6 (CHANGELOG date fill + PR)

---

## Summary

All 30 Phase 1 findings verified **resolved** against their stated
resolution commits. Both supplemental CI-failure findings (python-tests
pyscard build; firmware-lib host-target test flag) verified fixed. No
new findings surfaced during this sweep.

One intentional carve-out remains: `cargo clippy -p pico2hsm-core -- -D
warnings` locally surfaces 36 pedantic-category warnings (style / doc /
cast-precision — no correctness bugs). Both clippy steps in
`.github/workflows/build.yml` carry `continue-on-error: true` with a
`TODO(post-v1.0.0)` comment per the ci-engineer's RETURN entry. This
matches the admin-approved post-v1.0.0 follow-up tracked in the progress
doc; it is not release-blocking.

The workspace is otherwise clean: `cargo fmt --all --check` passes, no
secrets are tracked, workspace members all declare `version.workspace =
true` resolving to `1.0.0`, LICENSE is singular and canonical, and all
OSS-etiquette scaffolding (CHANGELOG, CoC, CODEOWNERS, issue/PR
templates, release workflow, SBOM, SHA256SUMS, THIRD_PARTY_NOTICES,
INCIDENT_RESPONSE, SUPPORT, RELEASE_PROCESS) is present.

---

## Finding-by-finding verification

### Closed (30 of 30)

**CRITICAL**

- **F-C-001** ✅ — `cargo fmt --all --check` exits 0 in worktree. Commit `34b6ce2` applied the 90-file whitespace sweep; subsequent commits (`537b8ce`, `897616c`, etc.) preserve compliance. Security-verifier ACCEPT recorded in progress doc.
- **F-C-002** ✅ — `LICENSE.txt` no longer exists; `LICENSE` remains as canonical MIT (1072 bytes, 2024–2026 copyright). Commit `537b8ce`.
- **F-C-003** ✅ — `CHANGELOG.md` present at repo root (81 lines, Keep a Changelog format) with a `[1.0.0] - YYYY-MM-DD` section whose date is intentionally a placeholder (filled at tag time per `docs/RELEASE_PROCESS.md`). Commit `aa78ee2` + release.yml excerpt pipeline `4fcfddd`.

**HIGH**

- **F-H-001** ✅ — `.github/workflows/release.yml` exists (336 lines); tag-triggered on `v*`; produces per-board UF2 + ELF + .uf2.sha256; emits SHA256SUMS combined file; generates CycloneDX SBOMs per crate; publishes via `softprops/action-gh-release@v2`. Commit `4fcfddd`.
- **F-H-002** ✅ — `docs/RELEASE_PROCESS.md` exists (12429 bytes). Commit `78dcfc1`.
- **F-H-003** ✅ — `examples/` directory exists with top-level README plus 4 sub-examples (`01-opensc-smoke`, `02-pkcs11-keygen`, `03-piv-cli-auth`, `04-gnupg-signing`), each containing `README.md` + executable `run.sh`. Spot-checked `01-opensc-smoke/run.sh` — well-structured, idempotent, documents `OPENSC_DEFAULT_READER` escape hatch. **Hardware validation of `run.sh` scripts remains a tracked post-v1.0.0 follow-up (progress doc item 3); not a Phase 5 blocker.** Commits `7152de5`, `945a192`, `2ca3696`, `b3e8368`, `d796153`.
- **F-H-004** ✅ — Workspace `Cargo.toml` now declares `description`, `repository` (`https://github.com/mcarey42/pico2hsm`), `homepage`, `authors`, `edition`, `rust-version` in `[workspace.package]`; each member inherits. Per-crate `keywords`, `categories`, `readme` populated. Commit `537b8ce`.
- **F-H-005** ✅ — `CODE_OF_CONDUCT.md` present (30 lines, Contributor Covenant 2.1 short-form with canonical URL + attribution). Commit `0655272`.
- **F-H-006** ✅ — `README.md` top carries Build, Release, License (MIT), Rust-Edition badges. Commit `5d6988d`.
- **F-H-007** ✅ — `release.yml` job `sbom:` installs pinned `cargo-sbom 0.9.1` and emits CycloneDX 1.4 JSON per workspace member (`pico2hsm-core`, `firmware`, `pico2hsm-integration-tests`), plus a cargo-tree fallback. Commit `4fcfddd`.
- **F-H-008** ✅ — `.github/ISSUE_TEMPLATE/bug_report.yml` (76 lines; structured form with version/board/OS/repro/logs fields, not-a-security-issue checkbox), `.github/ISSUE_TEMPLATE/feature_request.yml` (38 lines), `.github/pull_request_template.md` (present with testing/checklist/license sections). Commit `3e54cb1`.
- **F-H-009** ✅ — `CONTRIBUTING.md` now has explicit "Contributor licensing" section stating inbound=outbound MIT, no CLA required, no DCO sign-off required. Commit `0655272`.

**MEDIUM**

- **F-M-001** ✅ — Workspace `Cargo.toml:15` declares `repository = "https://github.com/mcarey42/pico2hsm"`, matching README and SECURITY.md. Commit `537b8ce`.
- **F-M-002** ✅ — `build.yml` audit job now caches the `cargo-audit` binary keyed on pinned version `0.21.1`; `continue-on-error: true` is retained but `Report cargo-audit result` step surfaces non-zero exit via `::warning::` + `$GITHUB_STEP_SUMMARY` (not silent). Commit `a28b773`.
- **F-M-003** ✅ — `docs/PROVISIONING.md:7` now reads `Last updated: 2026-04-16 (v1.0.0-rc4)`. Commit `5d6988d`.
- **F-M-004** ✅ — `PUNCHOUT.md:6` reads `Last updated: 2026-04-16 (v1.0.0-rc4: ...)` — matches the newest closed-items entry (`4b | ... | v1.0.0-rc4`). Commit `5d6988d`.
- **F-M-005** ✅ — Workspace root `Cargo.toml:11` declares `version = "1.0.0"`; all three members (`pico2hsm-core`, `firmware`, `tests/integration`) use `version.workspace = true`. Grep for `version = "0.{7,9,1}.0"` in workspace `Cargo.toml` files returns zero matches. Commit `897616c`.
- **F-M-006** ✅ — `SECURITY.md` version table updated: `1.0.x` → "Future stable series -- will be supported on release"; `0.9.x` → "Current pre-release development series". Text is deliberately transition-compatible (valid both before and after tag-time flip) per the docs-engineer's Chunk-A RETURN. Once `v1.0.0` is tagged, the admin will promote `1.0.x` to "Current stable" in Phase 6. Commit `5d6988d`. *(Minor cosmetic note: wording is tag-time-flip-ready; not a blocker.)*
- **F-M-007** ✅ — `docs/INCIDENT_RESPONSE.md` exists (4755 bytes, 107 lines per progress doc), covers signing-key compromise / vulnerability disclosure / corrupt-release scenarios, declares 72-hour best-effort SLA. Commit `3e54cb1`.
- **F-M-008** ✅ — `docs/SUPPORT.md` exists (2212 bytes), channels questions to Discussions/Issues, points to CHANGELOG / APDU references / SECURITY.md. Commit `3e54cb1`.
- **F-M-009** ✅ — `THIRD_PARTY_NOTICES.md` exists (3305 bytes); documents `codespan-reporting` (Apache-2.0) attribution with full Apache-2.0 preamble plus any other non-MIT-OR-Apache deps. Commit `537b8ce`.
- **F-M-010** ✅ — `.github/workflows/build.yml:103-105` installs `cargo-audit` pinned to `--version 0.21.1`; cache key carries the same version so bumping invalidates the cache. Commit `a28b773`.
- **F-M-011** ✅ — `tools/python/pyproject.toml` exists (1451 bytes) with SPDX MIT, version `1.0.0`, Python 3.10-3.12 classifiers, full dependency list. `[project.scripts]` deliberately empty per documented post-v1.0.0 follow-up (item 2). Commit `897616c`.

**LOW**

- **F-L-001** ✅ — `.github/CODEOWNERS` exists with `* @mcarey42`; `CONTRIBUTING.md:11` now references CODEOWNERS as the enforcement mechanism. Commit `0655272`.
- **F-L-002** ✅ — Admin decision: keep `CLAUDE.md` as-is (functional AI-assistant documentation). No file change required. Commit `0c8b77a` for F-L-003 landed alongside.
- **F-L-003** ✅ — `CLAUDE.md` now carries an explicit note explaining that `ec_firmware_signing_key.pem` is each user's own secp256k1 root of trust (not a project-wide test key) with pointer to `docs/PROVISIONING.md` options. Commit `0c8b77a`.
- **F-L-004** ✅ — Each member manifest declares `rust-version.workspace = true`; workspace root sets `rust-version = "1.75"` at `Cargo.toml:12`. Commit `537b8ce`.
- **F-L-005** ✅ — `.github/workflows/build.yml:77-83` wires `cargo clippy -p pico2hsm-core -- -D warnings` and `cargo clippy -p pico2hsm-firmware --target thumbv8m... -- -D warnings`. Both steps carry `continue-on-error: true` with an explicit comment `TODO(post-v1.0.0): address clippy warnings surfaced by new workspace lint policy; then remove continue-on-error.` Local `cargo clippy -p pico2hsm-core -- -D warnings` against the worktree produces 36 pedantic warnings (all style/doc/cast-precision; no correctness errors), confirming that removing the guard is the intended post-v1.0.0 cleanup. Commit `3bc6ca9`.
- **F-L-006** ✅ — `README.md:44` explicitly documents `rp2350_one_4m` as default while noting `pico2_4m` is the primary debug/test target with a `CLAUDE.md` cross-reference. Commit `5d6988d`.
- **F-L-007** ✅ — Workspace `Cargo.toml:19-38` declares `[workspace.lints.rust]` (unsafe_op_in_unsafe_fn, rust_2018_idioms, unused_import_braces, unused_qualifications) and `[workspace.lints.clippy]` (pedantic ramp with standard carve-outs: module_name_repetitions, must_use_candidate, missing_errors_doc, missing_panics_doc, similar_names, too_many_lines, cast_possible_truncation, cast_sign_loss, cast_precision_loss, cast_possible_wrap). All three members carry `[lints] workspace = true`. Commit `897616c`.

### Still open (0)

All 30 findings resolved.

### New findings surfaced during sweep (0)

Spot-checks covered:

- `cargo fmt --all --check` — clean (exit 0).
- Grep for workspace-member version strings `"0.7.0"`, `"0.9.0"`, `"0.1.0"` in `**/Cargo.toml` — zero matches. (`Cargo.lock` still references these for some transitive crates — expected, not a concern.)
- CHANGELOG date placeholder `YYYY-MM-DD` present at `CHANGELOG.md:9` — intentional per `docs/RELEASE_PROCESS.md`.
- `cargo clippy -p pico2hsm-core -- -D warnings` — 36 pedantic warnings (documented, guarded with `continue-on-error: true`, post-v1.0.0 follow-up tracked).
- `.claude/` directory — only contains `agents/` with the 7 tracked agent specs. No `settings.json`, no `settings.local.json`, no stray artefacts.
- `git ls-files | grep -E "\.(pem|key|crt|env)$"` — no secret files tracked. `.gitignore:13-14` correctly excludes `ec_firmware_signing_key.{pem,pub}`.

---

## Supplemental findings verification

- **Supplemental #1 — `python-tests` CI (pyscard build)** ✅ — `.github/workflows/build.yml:145-151` installs `libpcsclite-dev swig pcscd` via `sudo apt-get install` before `pip install -e tools/python/`. Matches the originally-failing symptom (`fatal error: winscard.h: No such file`). Commit `3bc6ca9`.

- **Supplemental #2 — firmware-lib host test CI (invalid libtest flag)** ✅ — `.github/workflows/build.yml:48-57` now runs `cargo test --manifest-path firmware/Cargo.toml --lib --no-default-features --features <matrix> --target x86_64-unknown-linux-gnu`. The invalid `-- --test-output immediate` has been removed; the step header comments confirm failures are no longer masked. Commit `3bc6ca9`.

---

## Positive delta since Phase 1

1. **Workspace metadata unification.** Prior to Phase 3, the three members advertised `0.7.0` / `0.9.0` / `0.1.0` with no shared repository/homepage/authors. Now all metadata flows from `[workspace.package]` via `*.workspace = true`, eliminating drift.
2. **Release pipeline is end-to-end.** `release.yml` produces per-board UF2 + ELF + .uf2.sha256, combines into `SHA256SUMS`, generates per-crate CycloneDX 1.4 SBOMs, extracts the matching `CHANGELOG.md` section via `awk`, and publishes with `softprops/action-gh-release@v2`. Explicit dry-run support via `-ci-test` suffix; expected-boards guard fails the release loudly if any matrix entry is missing.
3. **Clippy policy installed at workspace scope.** `[workspace.lints.clippy] pedantic = "warn"` with thoughtful carve-outs (8 allows) is a permanent quality ratchet that will pay off post-v1.0.0 when the 36/78 pending warnings are cleaned up and the `continue-on-error` guards come off.
4. **Issue/PR templates use structured forms.** `bug_report.yml` is a proper `type: form` with dropdown board selector and not-a-security-issue checkbox — better UX than free-form markdown.
5. **Runbooks cover all three OSS incident classes.** `INCIDENT_RESPONSE.md` handles key compromise / vulnerability disclosure / corrupt artefact in one runbook; `SUPPORT.md` separates question channels from bug channels cleanly.
6. **Documented post-v1.0.0 follow-ups.** The progress doc's "Post-v1.0.0 follow-ups" section now tracks five items (clippy cleanup, pyproject scripts, examples HW validation, CoC dedicated email, Node 24 runner migration), none of which are release-blocking. This is the kind of transparency reviewers look for.

---

## Release readiness statement

**READY** for Phase 6. All 30 Phase 1 findings are verified closed; both
supplemental CI failures are fixed; no new findings surfaced during this
sweep.

Remaining work for Phase 6 (not in Phase 5 scope):

1. **Fill the CHANGELOG date.** `CHANGELOG.md:9` placeholder `YYYY-MM-DD`
   gets replaced with the tag date per `docs/RELEASE_PROCESS.md`.
2. **Optional — post-tag flip** `SECURITY.md` version table so `1.0.x`
   reads "Current stable" and `0.9.x` reads "Legacy / no longer
   maintained" (cosmetic; current text is transition-compatible).
3. **Open the PR** against `main`.
4. **Cut the tag.** `git tag -a v1.0.0 -m "..."` → `git push --tags` →
   `release.yml` fires → GitHub Release with UF2 + SHA256SUMS + SBOMs
   auto-publishes.
5. **Dry-run first.** `docs/RELEASE_PROCESS.md` recommends pushing
   `v1.0.0-ci-test` once to exercise the full pipeline before the real
   tag.

Post-v1.0.0 (not blocking, tracked in progress doc):

- Clean up 114 pedantic clippy warnings; remove `continue-on-error`
  guards.
- Populate `tools/python/pyproject.toml` `[project.scripts]` once
  `pico2hsm/__main__.py` is added.
- Hardware-validate `examples/*/run.sh` against a flashed device.
- Decide on dedicated CoC reporting email.
- Migrate CI runner actions to Node 24 before September 2026.

---

*End of Phase 5 sweep.*
