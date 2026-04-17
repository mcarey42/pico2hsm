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
| F-C-002 | C | licensing | license-hygienist | approved | pending | — |
| F-C-003 | C | docs | docs-engineer | approved | pending | — |
| F-H-001 | H | ci | ci-engineer | approved | pending | — |
| F-H-002 | H | ci | ci-engineer | approved | pending | — |
| F-H-003 | H | examples | examples-author | approved | pending | — |
| F-H-004 | H | metadata | license-hygienist | approved | pending | — |
| F-H-005 | H | docs | docs-engineer | approved | pending | — |
| F-H-006 | H | docs | docs-engineer | approved | pending | — |
| F-H-007 | H | ci | ci-engineer | approved | pending | — |
| F-H-008 | H | docs | docs-engineer | approved | pending | — |
| F-H-009 | H | docs | docs-engineer | approved | pending | — |
| F-M-001 | M | metadata | license-hygienist | approved | pending | — |
| F-M-002 | M | ci | ci-engineer | approved | pending | — |
| F-M-003 | M | docs | docs-engineer | approved | pending | — |
| F-M-004 | M | docs | docs-engineer | approved | pending | — |
| F-M-005 | M | metadata | admin→license-hygienist | approved | pending | — |
| F-M-006 | M | docs | docs-engineer | approved | pending | — |
| F-M-007 | M | docs | docs-engineer | approved | pending | — |
| F-M-008 | M | docs | docs-engineer | approved | pending | — |
| F-M-009 | M | licensing | license-hygienist | approved | pending | — |
| F-M-010 | M | ci | ci-engineer | approved | pending | — |
| F-M-011 | M | ci | admin | approved | pending | — |
| F-L-001 | L | docs | docs-engineer | approved | pending | — |
| F-L-002 | L | docs | admin | approved | pending | — |
| F-L-003 | L | docs | admin | approved | pending | — |
| F-L-004 | L | metadata | license-hygienist | approved | pending | — |
| F-L-005 | L | ci | admin→ci-engineer | approved | pending | — |
| F-L-006 | L | docs | docs-engineer | approved | pending | — |
| F-L-007 | L | metadata | admin | approved | pending | — |

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

---

## Open user approvals

*(none pending)*

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
