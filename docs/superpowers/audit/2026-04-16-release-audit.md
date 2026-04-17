# Release Audit — 2026-04-16

**Auditor run:** Phase 1
**Commit audited:** cc36a06c92b688dc45b44af22e85e61c2d60503b (branch `release-prep/v1.0.0`, worktree `/home/mcarey/pico2hsm-release-prep`)
**Counts:** 3 critical, 9 high, 11 medium, 7 low (30 total)

## Summary

Not ready for v1.0.0 tagging. The codebase is functionally close — all canonical docs exist, LICENSE is present, all PUNCHOUT critical/high items are closed, third-party dependencies are uniformly permissive, and the GitHub build workflow already runs matrix builds + clippy + cargo-audit + host tests. However, three categories of gaps actively block a public release:

1. **Release machinery is absent.** No `release.yml`, no `RELEASE_PROCESS.md`, no `CHANGELOG.md`, no SHA256SUMS or SBOM emission. UF2 artifacts attach to tagged releases but nothing else does; a v1.0.0 tag today would produce a half-dressed GitHub release.
2. **Two canonical release-blocker artifacts do not exist.** `examples/` directory is missing entirely. No `CHANGELOG.md`. No runbooks (`docs/RELEASE_PROCESS.md`, `docs/INCIDENT_RESPONSE.md`, `docs/SUPPORT.md`, `CODE_OF_CONDUCT.md`).
3. **`cargo fmt --check` fails on 887 diffs across 89 files** — directly contradicting the CI step that claims to enforce it (`cargo fmt --all -- --check`). This is release-blocking: either CI is not running or recent commits drifted without enforcement, and either way a first-time contributor will hit a failing lint on day one.

The biggest themes are (a) missing release infrastructure (owned by `ci-engineer`), (b) missing OSS-etiquette files/directory scaffolding (owned by `docs-engineer` + `examples-author`), and (c) Cargo metadata thinness + LICENSE duplication (owned by `license-hygienist`).

---

## Findings

### CRITICAL

#### F-C-001: `cargo fmt --check` fails on 89 files, 887 diffs
- **Category:** code-hygiene
- **File(s):** 89 files spanning `firmware/src/**`, `firmware/tests/**`, `firmware/build.rs`, `pico2hsm-core/src/{apdu.rs,key.rs}`, `tests/integration/tests/apdu_parsing.rs`. Full list captured by running `cargo fmt --all -- --check` in the worktree.
- **Evidence:** `cargo fmt --all -- --check` produces 887 `Diff in ...` lines across 89 unique source files. Examples:
  - `firmware/build.rs:44` — `let manifest_dir = std::env::var(...).expect(...)` reformatted.
  - `firmware/src/apdu/dispatcher.rs:20` — `use pico2hsm_core::{apdu::{...}}` import layout.
  - Dozens of diffs inside `firmware/src/protocol/{sc_hsm,piv,openpgp}/commands/`.
  rustfmt version: `rustfmt 1.8.0-stable (e408947bfd 2026-03-25)`. No `rustfmt.toml` or `.rustfmt.toml` in the repo — these are default-rules diffs.
- **Why critical:** `.github/workflows/build.yml:70` runs `cargo fmt --all -- --check` as a lint step that must pass. Either CI is currently broken (the repo is merging with the fmt step failing and someone is overriding), CI is masking the failure, or rustfmt's default rules drifted under a stable toolchain — which is unusual but possible if a recent toolchain update changed formatting. Regardless of cause, a first-time contributor running `cargo fmt` locally will produce a 887-line diff they did not author. Release-blocking for OSS credibility.
- **Proposed owner:** admin (to diagnose root cause before routing; may be code-hygiene work or a CI configuration issue)
- **Cross-ref:** none

#### F-C-002: Duplicate LICENSE files are not byte-identical and contradict each other
- **Category:** licensing
- **File(s):** `LICENSE` (MIT License, "Copyright (c) 2024-2026 Mark Carey", straight quotes, 22 lines), `LICENSE.txt` ("Copyright 2026 Mark Carey", no `MIT License` header, curly/smart quotes, 9 lines, different text flow)
- **Evidence:** `diff LICENSE LICENSE.txt` shows substantially different files — different copyright years (2024-2026 vs 2026), different header ("MIT License" present vs absent), different typography (straight quotes vs smart quotes), different paragraph structure. Both are MIT grants so the license choice is not ambiguous, but the boilerplate differs.
- **Why critical:** Two different "authoritative" license files force downstream consumers and auto-license-detection tools to pick one arbitrarily. `Cargo.toml` members set `license = "MIT"` pointing to neither filename explicitly. This is legally risky (copyright year and holder inconsistency) and cosmetically unacceptable for a v1.0.0 tag.
- **Proposed owner:** license-hygienist
- **Cross-ref:** none (new finding; spec notes this as known)

#### F-C-003: No `CHANGELOG.md` exists; v1.0.0 release notes have no source of truth
- **Category:** docs
- **File(s):** (missing) `CHANGELOG.md`
- **Evidence:** `ls CHANGELOG.md` → file not found. Grep confirms no CHANGELOG artifact anywhere in the repo.
- **Why critical:** OSS convention expects `CHANGELOG.md` at repo root for every tagged release. The `release.yml` workflow the design calls for reads `CHANGELOG.md` to auto-populate the GitHub release body. PUNCHOUT closes dozens of items across v0.9.0 through v1.0.0-rc4 without any structured changelog consolidating them. Release-blocking.
- **Proposed owner:** docs-engineer
- **Cross-ref:** spec "Done" definition explicitly requires CHANGELOG reflects v1.0.0.

### HIGH

#### F-H-001: No `release.yml` workflow; tag-triggered release machinery is absent
- **Category:** ci
- **File(s):** (missing) `.github/workflows/release.yml`. Existing `build.yml` has a partial `build-artifacts` job that attaches UF2s on tag push via `softprops/action-gh-release@v2` but no dedicated release pipeline.
- **Evidence:** `ls .github/workflows/` → only `build.yml`. `build.yml:118-191` attaches UF2 on tag push but emits no SHA256SUMS, no SBOM, no release body template, no CHANGELOG excerpt, no signed-asset handling, and does not fail the release if any board variant fails.
- **Why high:** Spec "Done" definition requires a dry-run release that attaches UF2 + SHA256SUMS + SBOM. Current setup cannot produce that output.
- **Proposed owner:** ci-engineer
- **Cross-ref:** none

#### F-H-002: No `docs/RELEASE_PROCESS.md` runbook
- **Category:** docs
- **File(s):** (missing) `docs/RELEASE_PROCESS.md`
- **Evidence:** Grep for `RELEASE_PROCESS` returns only hits in `docs/superpowers/specs/2026-04-16-release-readiness-design.md` and `plans/2026-04-16-release-readiness-plan.md` (both planning docs).
- **Why high:** Release process is not documented. Operators cutting v1.0.0 or a patch release have no authoritative sequence to follow. Spec explicitly names this as a required deliverable.
- **Proposed owner:** ci-engineer
- **Cross-ref:** F-H-001

#### F-H-003: `examples/` directory does not exist
- **Category:** examples
- **File(s):** (missing) `examples/` (entire directory)
- **Evidence:** `ls examples/` → No such file or directory.
- **Why high:** Spec "Done" definition requires at minimum: OpenSC smoke, pkcs11-tool keygen, PIV CLI auth, GnuPG signing. A first-time user coming from README has no "run this script, see it work" path — they must piece together the QUICKSTART.md snippets manually.
- **Proposed owner:** examples-author
- **Cross-ref:** none

#### F-H-004: Workspace `Cargo.toml` members lack repository / homepage / keywords / categories / readme
- **Category:** metadata
- **File(s):** `Cargo.toml` (workspace root), `pico2hsm-core/Cargo.toml`, `firmware/Cargo.toml`, `tests/integration/Cargo.toml`
- **Evidence:**
  - Workspace root `Cargo.toml` sets only `rust-version = "1.75"` in `[workspace.package]`. No `repository`, `homepage`, `keywords`, `categories`, `readme`, `license`, or `description`.
  - `pico2hsm-core/Cargo.toml` has `description` and `license` but no `repository`, `homepage`, `keywords`, `categories`, or `readme`.
  - `firmware/Cargo.toml` same — `description` and `license` present; everything else missing.
  - `tests/integration/Cargo.toml` same.
- **Why high:** `cargo publish` requires most of these; even without publishing, `crates.io` and `docs.rs` users expect them. OSS norm is to fill all of them. Also, `rust-version` is set at workspace scope but individual members do not opt in via `rust-version.workspace = true`, so per-crate MSRV advertising is absent.
- **Proposed owner:** license-hygienist
- **Cross-ref:** none

#### F-H-005: No `CODE_OF_CONDUCT.md`
- **Category:** docs
- **File(s):** (missing) `CODE_OF_CONDUCT.md`
- **Evidence:** `ls CODE_OF_CONDUCT.md` → file not found.
- **Why high:** OSS community norm (expected by GitHub community health checks; a Contributor Covenant v2.1 file is the usual choice). Absent from all documented locations.
- **Proposed owner:** docs-engineer
- **Cross-ref:** none

#### F-H-006: No status badges in `README.md`
- **Category:** docs
- **File(s):** `README.md`
- **Evidence:** `README.md:1-10` is a plain `# pico2hsm` header and prose — no CI status badge, no license badge, no "MIT" shield.
- **Why high:** OSS convention signals build health and license at a glance. Their absence suggests the project is not yet maintained to public standards.
- **Proposed owner:** docs-engineer
- **Cross-ref:** F-H-001 (badge URL depends on release workflow name)

#### F-H-007: No SBOM emission configured or documented as intentional omission
- **Category:** ci
- **File(s):** `.github/workflows/build.yml` (no cargo-sbom / cyclonedx-bom step); no `cargo-sbom.toml`; no documented omission in `docs/`
- **Evidence:** Grep for `sbom`, `cyclonedx`, `cargo-sbom` in workflows and docs returns no hits. README and BUILDING.md do not mention SBOM.
- **Why high:** Spec "Done" definition lists SBOM attachment as required. Industry OSS expectation is at minimum an SPDX or CycloneDX file per release.
- **Proposed owner:** ci-engineer
- **Cross-ref:** F-H-001

#### F-H-008: No GitHub issue templates or PR template
- **Category:** punchout (repo hygiene)
- **File(s):** (missing) `.github/ISSUE_TEMPLATE/`, `.github/PULL_REQUEST_TEMPLATE.md`
- **Evidence:** `ls .github/` shows only `workflows/`. No `ISSUE_TEMPLATE/` directory, no `PULL_REQUEST_TEMPLATE.md`, no `CODEOWNERS`.
- **Why high:** First-time contributors have no guided bug-report / feature-request / PR flow. Combined with `CONTRIBUTING.md` that references `@mcarey42` for security reviews, a CODEOWNERS file would formalize that expectation. GitHub repo-health signal is negative.
- **Proposed owner:** docs-engineer
- **Cross-ref:** none

#### F-H-009: `CONTRIBUTING.md` lacks explicit DCO / CLA position
- **Category:** docs
- **File(s):** `CONTRIBUTING.md`
- **Evidence:** `CONTRIBUTING.md` covers: submission flow, build discipline, commit style, what-we're-looking-for. Does not state whether contributors must sign off (DCO), whether a CLA is required, or that MIT license inbound = outbound. The absence of an explicit policy is ambiguous.
- **Why high:** Security-sensitive repos typically require a DCO or CLA. For an MIT project the defensible default is "no CLA; inbound=outbound under MIT; no DCO sign-off required" — but it needs to be stated, not left to interpretation.
- **Proposed owner:** docs-engineer
- **Cross-ref:** none

### MEDIUM

#### F-M-001: `README.md` repository URL is `github.com/mcarey42/pico2hsm` but workspace metadata does not declare it
- **Category:** metadata
- **File(s):** `README.md:54`, `QUICKSTART.md:105`, `SECURITY.md:22`. Not declared in any `Cargo.toml`.
- **Evidence:** README and QUICKSTART both point to `https://github.com/mcarey42/pico2hsm`; SECURITY.md points to `https://github.com/mcarey42/pico2hsm/security/advisories`. None of the `Cargo.toml` files mention this URL.
- **Why medium:** Canonical URL is known and consistent across docs but isn't surfaced in package metadata. Picked up by F-H-004; separate finding here to highlight the "known good" value for license-hygienist to use.
- **Proposed owner:** license-hygienist
- **Cross-ref:** F-H-004

#### F-M-002: `cargo audit` step has `continue-on-error: true` and installs unconditionally each run
- **Category:** ci
- **File(s):** `.github/workflows/build.yml:78-91`
- **Evidence:** `build.yml:88-91`:
  ```
  run: |
    cargo install cargo-audit --locked 2>/dev/null || true
    cargo audit
  continue-on-error: true
  ```
- **Why medium:** `continue-on-error: true` means a new upstream RustSec advisory never blocks a PR. Comment justifies this as intentional, but the trade-off should instead be: allow the step to fail, require a follow-up commit adding an ignore entry (documented via `.cargo/audit.toml`). Also `cargo install` runs every CI invocation rather than being cached. Low priority fix but worth noting.
- **Proposed owner:** ci-engineer
- **Cross-ref:** none

#### F-M-003: `docs/PROVISIONING.md` references rc2; date field says "Last updated: 2026-04-14 (v1.0.0-rc2)"
- **Category:** docs
- **File(s):** `docs/PROVISIONING.md:8`
- **Evidence:** `docs/PROVISIONING.md:8` — `Last updated: 2026-04-14 (v1.0.0-rc2)`. Current `main` is at v1.0.0-rc4.
- **Why medium:** Stale version stamp. Not inaccurate, but suggests the doc has not been re-validated against rc4 changes (OTP row corrections, synchronous dispatch loop).
- **Proposed owner:** docs-engineer
- **Cross-ref:** none

#### F-M-004: `PUNCHOUT.md` "Last updated" header says 2026-04-13 and references v1.0.0-rc2
- **Category:** punchout
- **File(s):** `PUNCHOUT.md:5`
- **Evidence:** `PUNCHOUT.md:5` — `Last updated: 2026-04-13 (v1.0.0-rc2: M3 fuzz test written, Brainpool status corrected, provisioning design complete)`. Closed-items table has `4b` marked as closed in `v1.0.0-rc4` but header is stuck at rc2.
- **Why medium:** The PUNCHOUT is used as authoritative release history. Header needs to match newest closed entry.
- **Proposed owner:** docs-engineer (or admin during Phase 6)
- **Cross-ref:** none

#### F-M-005: Workspace member versions are diverged (core=0.7.0, firmware=0.9.0, integration-tests=0.1.0) and none are v1.0.0-rc4
- **Category:** metadata
- **File(s):** `pico2hsm-core/Cargo.toml:3` (`version = "0.7.0"`), `firmware/Cargo.toml:3` (`version = "0.9.0"`), `tests/integration/Cargo.toml:3` (`version = "0.1.0"`)
- **Evidence:** Git log shows `v1.0.0-rc4` commit as most recent on `main`, but no `Cargo.toml` member advertises `1.0.0` or `1.0.0-rc4`.
- **Why medium:** Semver inconsistency is confusing for consumers. Release convention is to bump workspace members to the target release version before tagging. Cutting v1.0.0 from `firmware = 0.9.0` prints a misleading `--version` string.
- **Proposed owner:** admin (decision on per-member version scheme before release) → then license-hygienist (apply bumps)
- **Cross-ref:** none

#### F-M-006: `SECURITY.md` version table lists `0.9.x` as "Legacy development series — no longer maintained" but `firmware/Cargo.toml` version is 0.9.0
- **Category:** docs
- **File(s):** `SECURITY.md:6-9`, `firmware/Cargo.toml:3`
- **Evidence:** SECURITY.md declares `0.9.x` unmaintained; `firmware/Cargo.toml` ships version `0.9.0`. Until F-M-005 is resolved, SECURITY.md contradicts the version the code self-reports.
- **Why medium:** Cross-doc contradiction. Auto-resolves once F-M-005 is fixed.
- **Proposed owner:** docs-engineer
- **Cross-ref:** F-M-005

#### F-M-007: No `docs/INCIDENT_RESPONSE.md` runbook
- **Category:** docs (runbooks)
- **File(s):** (missing) `docs/INCIDENT_RESPONSE.md`
- **Evidence:** Grep for `INCIDENT_RESPONSE` returns zero hits outside the planning doc.
- **Why medium:** For a security-sensitive project, having a documented incident-response playbook (what to do if a signing key is compromised, how to issue an advisory, coordination with downstream) is expected. Not release-blocking but expected by the spec's runbooks checklist.
- **Proposed owner:** docs-engineer
- **Cross-ref:** none

#### F-M-008: No `docs/SUPPORT.md` runbook
- **Category:** docs (runbooks)
- **File(s):** (missing) `docs/SUPPORT.md` or `SUPPORT.md` at root
- **Evidence:** `ls docs/SUPPORT.md` — file not found; same for root.
- **Why medium:** GitHub community health checklist expects a SUPPORT.md documenting where to ask questions (Discussions, Issues, matrix/IRC channel, etc.). Currently `CONTRIBUTING.md:169-170` hand-waves "Open a GitHub Discussion or file an issue" without formalizing the policy.
- **Proposed owner:** docs-engineer
- **Cross-ref:** none

#### F-M-009: No `THIRD_PARTY_NOTICES.md`; `codespan-reporting` is Apache-2.0 only (requires attribution)
- **Category:** licensing
- **File(s):** (missing) `THIRD_PARTY_NOTICES.md`. Dependency surfaced via `cargo license`.
- **Evidence:** `cargo license` (firmware, pico2_4m features, thumbv8m target) shows `Apache-2.0 (1): codespan-reporting`. Apache-2.0 requires a NOTICE-style attribution when redistributing. Everything else in the tree is permissive (`MIT`, `MIT OR Apache`, `BSD-3-Clause`, `MIT OR Apache OR Zlib`, `Unicode-3.0`, `MIT OR Unlicense`). `codespan-reporting` is a transitive build-time dep (via `lalrpop`), so its presence in a published binary is debatable.
- **Why medium:** Strictly speaking Apache-2.0 requires preserving the NOTICE if one is present in the upstream. `codespan-reporting` has no NOTICE file, so attribution obligation is minimal — but a `THIRD_PARTY_NOTICES.md` that enumerates build-time vs runtime deps with their SPDX tags is a cheap OSS due-diligence artifact.
- **Proposed owner:** license-hygienist
- **Cross-ref:** none

#### F-M-010: `cargo audit` CI step does not pin a specific cargo-audit version
- **Category:** ci
- **File(s):** `.github/workflows/build.yml:89`
- **Evidence:** `cargo install cargo-audit --locked` with no version pin. A future breaking change in cargo-audit output format could silently break the step.
- **Why medium:** Reproducibility. Best practice is to pin `--version X.Y.Z`.
- **Proposed owner:** ci-engineer
- **Cross-ref:** F-M-002

#### F-M-011: Python daemon package has no license / version metadata check in CI
- **Category:** ci
- **File(s):** `tools/python/pico2hsm/` (not audited in this pass), `.github/workflows/build.yml:93-108`
- **Evidence:** `python-tests` job runs `pytest` but does not validate `tools/python/pyproject.toml` (if any) has license / author / version metadata aligned with the repo. Not exhaustively audited in this pass.
- **Why medium:** Pre-release hygiene. Admin should decide whether the Python package is published alongside v1.0.0 or deferred.
- **Proposed owner:** admin
- **Cross-ref:** none

### LOW

#### F-L-001: `CONTRIBUTING.md` references `@mcarey42` for security reviews but no CODEOWNERS file enforces it
- **Category:** docs
- **File(s):** `CONTRIBUTING.md:13,151`; (missing) `.github/CODEOWNERS`
- **Evidence:** CONTRIBUTING.md says to "request review from `@mcarey42` explicitly" but a CODEOWNERS would auto-request.
- **Why low:** Process nuance, non-blocking.
- **Proposed owner:** docs-engineer
- **Cross-ref:** F-H-008

#### F-L-002: `CLAUDE.md` leaks into root docs as a public-facing file
- **Category:** docs
- **File(s):** `CLAUDE.md`
- **Evidence:** `CLAUDE.md` is referenced from `CONTRIBUTING.md:11` as the architecture guide. It is a dual-purpose doc — AI-agent context + human architecture guide. Some OSS projects treat `CLAUDE.md` as an internal scratchpad and exclude it from public branches; here it serves a legitimate documentation role.
- **Why low:** Purely cosmetic — some reviewers will question why a Claude-specific file is in the root of a public repo. The in-file note at top of CLAUDE.md already addresses the concern. Could be renamed to `ARCHITECTURE_INTERNAL.md` or `DEVELOPER_GUIDE.md` with a symlink, or kept as-is with an explicit "this is checked in intentionally" disclaimer in the README.
- **Proposed owner:** admin
- **Cross-ref:** none

#### F-L-003: `generate_firmware_signing_keys.sh` and `ec_firmware_signing_key.pem` naming assumes one canonical key path
- **Category:** docs
- **File(s):** `generate_firmware_signing_keys.sh`, `.gitignore`
- **Evidence:** `.gitignore:13-14` ignores `ec_firmware_signing_key.pem` and `.pub`. If a contributor checks out with a slightly different key name, `build-all-debug.sh` will silently flash unsigned. Acceptable given explicit warning, but low-risk.
- **Why low:** Edge case; not a release blocker.
- **Proposed owner:** admin
- **Cross-ref:** none

#### F-L-004: No `rust-version.workspace = true` opt-in on individual member manifests
- **Category:** metadata
- **File(s):** `pico2hsm-core/Cargo.toml`, `firmware/Cargo.toml`, `tests/integration/Cargo.toml`
- **Evidence:** Workspace root declares `rust-version = "1.75"` in `[workspace.package]` but individual members do not pull it in with `rust-version.workspace = true`.
- **Why low:** MSRV is declared at workspace scope but not advertised per-crate. cargo respects workspace MSRV for builds, but tooling (docs.rs, cargo-msrv) reads per-crate metadata.
- **Proposed owner:** license-hygienist
- **Cross-ref:** F-H-004

#### F-L-005: `build.yml` clippy step on firmware target allows warnings (`-A warnings`)
- **Category:** code-hygiene
- **File(s):** `.github/workflows/build.yml:76`
- **Evidence:** `build.yml:76` — `cargo clippy -p pico2hsm-firmware --target thumbv8m.main-none-eabihf -- -A warnings`. `-A warnings` explicitly allows all clippy warnings; only the core crate runs with `-D warnings`.
- **Why low:** Documented deviation (CLAUDE.md doesn't discuss this). Firmware code likely has some Embassy-specific lints that would false-positive, but the full allow is coarser than necessary. Could be tightened to specific `-A clippy::X` lints.
- **Proposed owner:** admin (decision), then ci-engineer
- **Cross-ref:** none

#### F-L-006: `README.md` supported-boards table and Cargo.toml feature flag table both list `waveshare_rp2350_lcd_16m` but README has no explicit mention of `pico2_4m` as "Pico 2 (stock)" even though that is the default debug target
- **Category:** docs
- **File(s):** `README.md:30-37`, `firmware/Cargo.toml:19`
- **Evidence:** README table lists "Raspberry Pi Pico 2" first with 4MB; firmware `default = ["rp2350_one_4m", ...]`. CLAUDE.md states the primary debug target is pico2_4m but README's feature-flag list shows `rp2350_one_4m` as default. Not a contradiction, just under-documented reasoning.
- **Why low:** Cosmetic.
- **Proposed owner:** docs-engineer
- **Cross-ref:** none

#### F-L-007: Workspace `Cargo.toml` does not enable `[workspace.lints]` to enforce clippy across all members
- **Category:** code-hygiene
- **File(s):** `Cargo.toml` (workspace root)
- **Evidence:** No `[workspace.lints]` or `[lints]` table. Each member sets lints independently (or not at all).
- **Why low:** Recent cargo feature (1.74+) that centralizes lint config. Nice-to-have; not blocking.
- **Proposed owner:** admin (scope decision)
- **Cross-ref:** none

---

## Satisfied checklist items (addendum — for Phase 5 diff)

These items were explicitly checked and found to be in good shape. Recorded here so the Phase 5 sweep can confirm they remain so.

### Licensing & legal

- **License identifier matches Cargo.toml on every workspace member.** `firmware/Cargo.toml:6` `license = "MIT"`; `pico2hsm-core/Cargo.toml:6` `license = "MIT"`; `tests/integration/Cargo.toml:6` `license = "MIT"`. All consistent.
- **Third-party dep licenses are permissive / compatible.** `cargo license` output: 190 deps are `Apache-2.0 OR MIT`, 34 are `MIT`, 7 are `MIT OR Unlicense`, 3 are `BSD-3-Clause` (rp-pac, rp2040-boot2, subtle), 2 are `Apache-2.0 OR BSD-2-Clause OR MIT`, 2 are `Apache-2.0 OR BSD-3-Clause OR MIT`, 1 is `Apache-2.0 OR MIT OR Zlib`, 1 is `(Apache-2.0 OR MIT) AND Unicode-3.0`, and only 1 (`codespan-reporting`) is Apache-2.0-only. No GPL/AGPL/SSPL/non-permissive licenses detected. See F-M-009 for the `codespan-reporting` attribution follow-up.
- **No trademark issues in branding.** "pico2hsm" name does not conflict with RP2350/Raspberry Pi trademarks; README describes support for OpenSC/GnuPG/PIV without claiming affiliation.

### Documentation completeness

- **README covers one-sentence pitch, feature table, install, quickstart, supported applets, contributing, license, support.** All sections present (see `README.md:1-144`). Section "Supported Applets" has a detailed matrix.
- **CONTRIBUTING.md exists and covers submission flow, code style, testing expectations.** See `CONTRIBUTING.md:1-171`. Commit-style table, feature-flag discipline section, and PR process are documented.
- **SECURITY.md covers supported versions, vulnerability disclosure process, threat model scope.** See `SECURITY.md:1-46`. Uses GitHub private security advisory. Has a "Known limitations" section distinguishing design decisions from bugs.
- **QUICKSTART.md, BUILDING.md, ARCHITECTURE.md exist and are link-consistent (confirmed by grep).** Cross-referenced links from README to QUICKSTART, BUILDING, ARCHITECTURE all resolve. PROVISIONING.md referenced from QUICKSTART resolves.
- **No references to pre-release code names or scratch notes.** Spot-check of README and docs/ top files shows no internal-only terminology.

### Runbooks

- **`docs/PROVISIONING.md` present and OSS-accessible.** 551 lines, walks through OTP provisioning with picotool. See also F-M-003 for stale version header.

### `Cargo.toml` metadata

- **`description` and `license` present on every member.** `firmware/Cargo.toml:5-6`, `pico2hsm-core/Cargo.toml:5-6`, `tests/integration/Cargo.toml:5-6`.
- **`rust-version = "1.75"` set at workspace scope.** `Cargo.toml:11`. See F-L-004 for per-member opt-in follow-up.

### CI coverage

- **`.github/workflows/build.yml` matrix covers all six boards.** Matrix includes `pico2_4m`, `rp2350_one_4m`, `rp2350_geek_16m`, `rp2350_geek_sdcard`, `waveshare_rp2350_lcd_16m`, `waveshare_rp2350_lcd_sdcard` — same list as `build-all-debug.sh`.
- **No hardcoded tokens in workflows; `GITHUB_TOKEN` scope is implicit.** `softprops/action-gh-release@v2` uses the workflow's default `GITHUB_TOKEN`.
- **`cargo audit` step exists in CI.** `.github/workflows/build.yml:78-91`. See F-M-002 / F-M-010 for tightening follow-ups.
- **Host-side tests run and their failures now fail CI.** `build.yml:42-58` runs `cargo test` without `|| true`; PUNCHOUT C6 (previously CRITICAL) closed.

### Code hygiene

- **`cargo clippy` passes cleanly on `pico2hsm-core`.** `cargo clippy -p pico2hsm-core -- -D warnings` completes with no warnings. See F-L-005 for firmware clippy deviation.
- **`.gitignore` covers target/, dist/, .pem key files, .venv, __pycache__, editor dirs.** `.gitignore:1-14` is clean and explicit.
- **No secrets committed.** `git ls-files` shows no `*.pem`, `*.key`, `*.crt`, `id_rsa`, or `.env` tracked. `ec_firmware_signing_key.pem` exists on disk but is correctly ignored (`git check-ignore` confirmed) and not in the tree.
- **`dist/` and `target/` not committed.** Neither present in the tracked file list; both in `.gitignore`.

### PUNCHOUT.md

- **Every open CRITICAL and HIGH item closed prior to this audit.** All C-items (C1–C7) moved to the Closed table. All H-items (H1–H7) resolved. Only item 3 (Brainpool, deferred on upstream crate) and item 4 (security hardening, subitems resolved) remain open — both documented with clear status.

### GitHub repo hygiene

- **No obsolete workflows referencing deleted paths.** `build.yml` is the only workflow; all paths in it resolve.

---

## Blockers / meta-observations

- **`cargo fmt --check` failure** (F-C-001) is the single most surprising finding. Before dispatching fixers, admin should confirm whether CI is actually green on `main` at commit `a27fbfd` — if CI is green but a local `cargo fmt --check` produces 887 diffs with the same `rustfmt 1.8.0-stable` toolchain CI uses, something is non-trivially wrong.
- **No examples directory** means `examples-author` work is greenfield. No risk of stomping existing content.
- **LICENSE duplication** should be a ~2-minute fix (delete one, ensure the remaining file is the canonical MIT boilerplate with correct copyright holder + years).
- **Spec "Done" requires a dry-run release.** That validation is out of scope for Phase 1 audit but should be treated as the gating criterion for Phase 5 re-audit.
