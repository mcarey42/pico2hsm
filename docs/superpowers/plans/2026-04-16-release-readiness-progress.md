# Release Readiness — Live Progress

**Spec:** `docs/superpowers/specs/2026-04-16-release-readiness-design.md`
**Plan:** `docs/superpowers/plans/2026-04-16-release-readiness-plan.md`
**Branch:** `release-prep/v1.0.0`
**Started:** 2026-04-16

This document is the **source of truth** for where the release-prep effort is. The `release-administrator` updates it before and after every agent dispatch.

---

## Phase status

| Phase | Status | Started | Completed | Notes |
|---|---|---|---|---|
| 0 — Setup | completed | 2026-04-16 | 2026-04-16 | worktree + agents + progress doc seeded |
| 1 — Audit | completed | 2026-04-16 | 2026-04-16 | 30 findings (3 C / 9 H / 11 M / 7 L) |
| 2 — Triage | completed | 2026-04-16 | 2026-04-16 | gate #1 — user approved all 30 findings with auditor's proposed owners |
| 3 — Parallel execution | in_progress | 2026-04-16 | — | F-C-001 admin diagnosis first; then 4-specialist parallel dispatch |
| 4 — Firmware items | pending | — | — | gate #2, on demand only |
| 5 — Verification sweep | pending | — | — | auditor rerun |
| 6 — Finalize | pending | — | — | gate #3, CHANGELOG + PR |

---

## Audit findings tracker

All 30 findings approved by user on 2026-04-16 with auditor's proposed owners.

| ID | Sev | Category | Owner | Decision | Status | Commit |
|---|---|---|---|---|---|---|
| F-C-001 | C | code-hygiene | admin | approved | resolved | 34b6ce2 (verifier ACCEPT) |
| F-C-002 | C | licensing | license-hygienist | approved | resolved | 537b8ce |
| F-C-003 | C | docs | docs-engineer | approved | partial | 4fcfddd (release.yml), aa78ee2 (CHANGELOG partial — date stamp deferred) |
| F-H-001 | H | ci | ci-engineer | approved | resolved | 4fcfddd |
| F-H-002 | H | ci | ci-engineer | approved | resolved | 78dcfc1 |
| F-H-003 | H | examples | examples-author | approved | resolved | 7152de5, 945a192, 2ca3696, b3e8368, d796153 (needs HW validation in Phase 5) |
| F-H-004 | H | metadata | license-hygienist | approved | resolved | 537b8ce |
| F-H-005 | H | docs | docs-engineer | approved | pending | blocked-content-filter; re-dispatch |
| F-H-006 | H | docs | docs-engineer | approved | pending | blocked-content-filter; re-dispatch |
| F-H-007 | H | ci | ci-engineer | approved | resolved | 4fcfddd |
| F-H-008 | H | docs | docs-engineer | approved | pending | blocked-content-filter; re-dispatch |
| F-H-009 | H | docs | docs-engineer | approved | pending | blocked-content-filter; re-dispatch |
| F-M-001 | M | metadata | license-hygienist | approved | resolved | 537b8ce |
| F-M-002 | M | ci | ci-engineer | approved | resolved | a28b773 |
| F-M-003 | M | docs | docs-engineer | approved | pending | blocked-content-filter; re-dispatch |
| F-M-004 | M | docs | docs-engineer | approved | pending | blocked-content-filter; re-dispatch |
| F-M-005 | M | metadata | admin→license-hygienist | approved | pending | needs user decision on version scheme |
| F-M-006 | M | docs | docs-engineer | approved | pending | blocked-content-filter; re-dispatch |
| F-M-007 | M | docs | docs-engineer | approved | pending | blocked-content-filter; re-dispatch |
| F-M-008 | M | docs | docs-engineer | approved | pending | blocked-content-filter; re-dispatch |
| F-M-009 | M | licensing | license-hygienist | approved | resolved | 537b8ce (THIRD_PARTY_NOTICES.md) |
| F-M-010 | M | ci | ci-engineer | approved | resolved | a28b773 |
| F-M-011 | M | ci | admin | approved | pending | admin — deferred |
| F-L-001 | L | docs | docs-engineer | approved | pending | blocked-content-filter; re-dispatch |
| F-L-002 | L | docs | admin | approved | pending | admin — deferred |
| F-L-003 | L | docs | admin | approved | pending | admin — deferred |
| F-L-004 | L | metadata | license-hygienist | approved | resolved | 537b8ce (rust-version.workspace) |
| F-L-005 | L | ci | admin→ci-engineer | approved | pending | admin — deferred |
| F-L-006 | L | docs | docs-engineer | approved | pending | blocked-content-filter; re-dispatch |
| F-L-007 | L | metadata | admin | approved | pending | admin — deferred |

---

## Dispatch log

Chronological record. One entry per `Agent` invocation.

### Example entry format

```
### [YYYY-MM-DD HH:MM] DISPATCH → <agent-name>
**Task:** <one-line summary>
**Context provided:** <findings addressed, files scoped>
**Expected deliverable:** <what admin expects back>

### [YYYY-MM-DD HH:MM] RETURN ← <agent-name>
**Files changed:** <list>
**Findings addressed:** <IDs or "n/a">
**Follow-ups:** <any new items surfaced>
**Verdict (if verifier):** ACCEPT / REJECT
```

### Entries

### [2026-04-16] DISPATCH → release-auditor
**Task:** Phase 1 initial OSS-release readiness audit
**Context provided:** worktree path `/home/mcarey/pico2hsm-release-prep`, canonical docs (spec/plan/progress), auditor system prompt inlined (Mode B — session cwd is main repo, not worktree), full audit checklist
**Expected deliverable:** `docs/superpowers/audit/2026-04-16-release-audit.md` with severity-tagged findings covering every checklist section

### [2026-04-16] DISPATCH → security-verifier
**Task:** Review fmt-only commit 34b6ce2 (resolves F-C-001)
**Context provided:** worktree path, commit SHA, rationale (whitespace-only cargo fmt --all)
**Expected deliverable:** ACCEPT or REJECT verdict
**Note:** Touches firmware/ and pico2hsm-core/ — non-negotiable rule requires verifier ACCEPT before commit counts as F-C-001 resolution.

### [2026-04-16] RETURN ← security-verifier
**Verdict:** **ACCEPT** (for commit 34b6ce2)
**Verification:**
- `cargo check -p pico2hsm-core` clean (host target)
- `cargo check --manifest-path firmware/Cargo.toml --no-default-features --features pico2_4m,applet-piv,applet-openpgp-curve25519 --target thumbv8m.main-none-eabihf` clean
- `cargo clippy -p pico2hsm-core -- -D warnings` clean
- Zero new `unsafe` blocks; zero new `.unwrap()` in core1 / apdu / main paths
- Pure whitespace + line-wrap + import reordering across 90 files
**No blocking concerns.** F-C-001 resolution commit is now verified.

### [2026-04-16] DISPATCH → license-hygienist (parallel)
**Task:** Resolve F-C-002, F-H-004, F-M-001, F-M-009, F-L-004
**Context provided:** worktree path, canonical URL, copyright holder, finding evidence from audit
**Expected deliverable:** LICENSE deduped; `Cargo.toml` members carry full metadata; `THIRD_PARTY_NOTICES.md` new; `rust-version.workspace` enabled
**Explicit exclusions:** F-M-005 (version scheme) — admin decides before bumping versions

### [2026-04-16] DISPATCH → docs-engineer (parallel)
**Task:** Resolve F-C-003, F-H-005, F-H-006, F-H-008, F-H-009, F-M-003, F-M-004, F-M-006, F-M-007, F-M-008, F-L-001, F-L-006
**Context provided:** worktree path, canonical URL, CHANGELOG format convention, finding evidence
**Expected deliverable:** new `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, `docs/INCIDENT_RESPONSE.md`, `docs/SUPPORT.md`, `.github/ISSUE_TEMPLATE/*`, PR template; targeted edits to `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `PUNCHOUT.md`, `docs/PROVISIONING.md`
**Explicit exclusions:** must NOT write `docs/RELEASE_PROCESS.md` (ci-engineer owns); must NOT edit `Cargo.toml` (license-hygienist owns)

### [2026-04-16] DISPATCH → ci-engineer (parallel)
**Task:** Resolve F-H-001, F-H-002, F-H-007, F-M-002, F-M-010
**Context provided:** worktree path, release workflow requirements from spec, finding evidence
**Expected deliverable:** new `.github/workflows/release.yml`, `docs/RELEASE_PROCESS.md`; targeted edits to `.github/workflows/build.yml` for audit step improvements
**Explicit exclusions:** F-L-005 (clippy -A warnings) — admin scope decision pending

### [2026-04-16] DISPATCH → examples-author (parallel)
**Task:** Resolve F-H-003
**Context provided:** worktree path, examples-author agent spec (4-example initial set)
**Expected deliverable:** new `examples/` directory with 4 examples (01-opensc-smoke, 02-pkcs11-keygen, 03-piv-cli-auth, 04-gnupg-signing), each with README + run.sh, plus top-level index

### Supplemental findings surfaced during F-C-001 diagnosis (informational, user decides triage)
While diagnosing why CI wasn't catching fmt drift, observed that recent CI runs on `main` also fail in other jobs, not in the audit:
- `python-tests` → `Python daemon install and unit tests` step fails
- `build (all boards)` → `Rust unit tests (firmware library, host target)` step fails
These have been red since at least `v1.0.0-rc2`. Not in audit scope (auditor did not run CI jobs locally). Flagging to admin for user decision on whether to expand scope.

### [2026-04-16] RETURN ← release-auditor
**Files changed:** `docs/superpowers/audit/2026-04-16-release-audit.md` (new, 341 lines, 28 KB)
**Commit audited:** `cc36a06` (release-prep/v1.0.0, after gitignore carve-out)
**Findings:** 3 critical, 9 high, 11 medium, 7 low — 30 total
**Top CRITICAL themes:**
1. F-C-001 — `cargo fmt --check` fails on 887 diffs across 89 files, contradicting CI
2. F-C-002 — LICENSE and LICENSE.txt both tracked, content differs (year, typography)
3. F-C-003 — No `CHANGELOG.md` + no `release.yml` workflow; release machinery absent
**Proposed owners (from findings):** `ci-engineer` (release infra), `docs-engineer` (OSS scaffolding + runbooks), `examples-author` (examples/ dir), `license-hygienist` (Cargo metadata + LICENSE dedup), `admin` (fmt CI root-cause triage)
**Follow-ups:** Phase 2 triage — user approval required before Phase 3 dispatch. Audit addendum captures positive findings (clean third-party deps, no secrets committed, PUNCHOUT clean, 6-board CI matrix, clippy passes on core) to support Phase 5 diff.

### [2026-04-16] RETURN ← license-hygienist
**Verdict:** SUCCESS
**Commit:** `537b8ce` — "chore(cargo): fill workspace metadata, dedupe LICENSE, add THIRD_PARTY_NOTICES"
**Findings addressed:** F-C-002, F-H-004, F-M-001, F-M-009, F-L-004
**Files changed:** `LICENSE.txt` deleted (dedup to `LICENSE`), `Cargo.toml` workspace metadata filled (description/repository/homepage/keywords/categories/rust-version), `THIRD_PARTY_NOTICES.md` added.
**Explicitly deferred:** F-M-005 (version scheme) — admin owns.

### [2026-04-16] RETURN ← ci-engineer
**Verdict:** SUCCESS
**Commits:** `4fcfddd` (release.yml with UF2 + SHA256SUMS + SBOM + CHANGELOG excerpt), `78dcfc1` (RELEASE_PROCESS.md runbook), `a28b773` (build.yml cache + pin cargo-audit)
**Findings addressed:** F-H-001, F-H-002, F-H-007, F-M-002, F-M-010
**Explicitly deferred:** F-L-005 (clippy `-D warnings`) — admin owns.

### [2026-04-16] RETURN ← examples-author
**Verdict:** SUCCESS
**Commits:** `7152de5` (top-level examples README), `945a192` (01-opensc-smoke), `2ca3696` (02-pkcs11-keygen), `b3e8368` (03-piv-cli-auth), `d796153` (04-gnupg-signing)
**Findings addressed:** F-H-003
**Files:** `examples/` directory with 4 examples, each with README + run.sh (1,044 lines / 9 files total)
**Follow-ups for Phase 5:** Examples require end-to-end hardware validation before release tag. Author flagged that run.sh scripts have not been executed against a flashed device.

### [2026-04-16] RETURN ← docs-engineer
**Verdict:** **FAIL — content-filter block**
**Agent:** dispatched general-purpose (Mode B) with inlined docs-engineer system prompt; agentId `af72dc00987b903f8` completed 16 tool uses over 93.5s before Anthropic API error: "Output blocked by content filtering policy". No commits landed.
**Partial salvage:** untracked `CHANGELOG.md` (81 lines, Keep a Changelog format covering v1.0.0 Added/Changed/Fixed/Security) was recovered from the worktree and committed by admin as `aa78ee2`. F-C-003 is now partial — CHANGELOG exists with placeholder date; release-day date stamp is documented in RELEASE_PROCESS.md.
**Findings still open:** F-H-005, F-H-006, F-H-008, F-H-009, F-M-003, F-M-004, F-M-006, F-M-007, F-M-008, F-L-001, F-L-006 (11 findings).
**Hypothesis:** likely trigger was attempting to paste the full Contributor Covenant 2.1 text into `CODE_OF_CONDUCT.md` (F-H-005). The canonical-URL + short attribution variant is the standard OSS-safe remediation.
**Recovery plan:** re-dispatch in 3 smaller chunks (date-stamp/README edits; runbooks + issue/PR templates; CoC as URL + CONTRIBUTING DCO + reviewer note).

### [2026-04-16] DISPATCH → docs-engineer (Chunk A — metadata/date-stamp/README polish)
**Task:** Resolve F-M-003 (PROVISIONING date), F-M-004 (PUNCHOUT date), F-M-006 (SECURITY version table), F-H-006 (README badges), F-L-006 (README board coverage)
**Context provided:** worktree path, canonical URL `github.com/mcarey42/pico2hsm`, finding evidence, no large boilerplate pastes
**Expected deliverable:** one commit editing `docs/PROVISIONING.md`, `PUNCHOUT.md`, `SECURITY.md`, `README.md` only

### [2026-04-16] DISPATCH → docs-engineer (Chunk B — new runbooks + GitHub templates)
**Task:** Resolve F-M-007 (INCIDENT_RESPONSE), F-M-008 (SUPPORT), F-H-008 (issue/PR templates)
**Context provided:** worktree path, incident-response + support runbook structure from spec
**Expected deliverable:** new `docs/INCIDENT_RESPONSE.md`, `docs/SUPPORT.md`, `.github/ISSUE_TEMPLATE/{bug_report,feature_request}.yml`, `.github/pull_request_template.md`

### [2026-04-16] DISPATCH → docs-engineer (Chunk C — CoC + CONTRIBUTING polish)
**Task:** Resolve F-H-005 (CODE_OF_CONDUCT), F-H-009 (CONTRIBUTING DCO), F-L-001 (CONTRIBUTING reviewer note)
**Context provided:** worktree path, **explicit instruction** to write `CODE_OF_CONDUCT.md` as a short-form reference to Contributor Covenant 2.1 (canonical URL + attribution, NOT inline the full text) to avoid content-filter block
**Expected deliverable:** new `CODE_OF_CONDUCT.md` (short-form), targeted edits to `CONTRIBUTING.md`

---

## Open user approvals

*(none pending — Phase 3 recovery in progress)*

---

## Blockers

*(none)*

---

## Notes for future sessions

If you are picking this up in a new session, read in this order:
1. The spec.
2. This progress doc — check phase status table and the dispatch log tail.
3. If Phase 1 audit exists, read `docs/superpowers/audit/2026-04-16-release-audit.md` next.
4. Resume from the last incomplete phase.
