# Release Readiness Design — pico2hsm v1.0.0 Prep

**Date:** 2026-04-16
**Status:** Draft, pending user review
**Owner:** release-administrator (this Claude instance)

## Goal

Prepare pico2hsm for its first open-source v1.0.0 release. Conduct a fresh-eyes audit, close all critical/high gaps surfaced by the audit (subject to user triage), produce comprehensive examples and runbooks, validate the CI release pipeline end-to-end via a dry-run, and leave the repo ready to tag `v1.0.0` in a follow-up session.

## Context

- Current state: `v1.0.0-rc4` on `main` (commit `a27fbfd`).
- Existing release infrastructure: `.github/workflows/build.yml` with matrix build across 6 boards, clippy+fmt lint, cargo audit, Python tests, unsigned UF2 artifact emission keyed on version tags.
- Existing documentation: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `QUICKSTART.md`, `BUILDING.md`, `ARCHITECTURE.md`, `TEST_PLAN.md`, `PUNCHOUT.md`, 28 references under `docs/`.
- Hardware-validated applets: SC-HSM, PIV, OpenPGP (including Ed25519/X25519).
- MIT licensed (both `LICENSE` and `LICENSE.txt` present — duplication to resolve).
- A second concurrent Claude instance is active in this workspace. Release-prep work is therefore isolated in a git worktree to prevent file collisions.

## Architecture

### Physical layout

- **Worktree:** `../pico2hsm-release-prep/` on a new branch `release-prep/v1.0.0`. All edits happen there.
- **Agent definitions:** Checked in at `.claude/agents/*.md` within the worktree branch. Merged back to `main` with the release-prep work, so future sessions can invoke them.
- **Design spec:** This document, at `docs/superpowers/specs/2026-04-16-release-readiness-design.md`. Committed on `main` before the worktree is created; the worktree branch inherits it through normal git branching (no copy needed).
- **Progress tracker:** `docs/superpowers/plans/2026-04-16-release-readiness-progress.md` — live scratchpad maintained by the admin across turns.
- **Audit findings:** `docs/superpowers/audit/2026-04-16-release-audit.md` — initial gap list + final verification sweep diff.

### Logical model

```
       ┌──────────────────────────────────────────────┐
       │   User (approvals at defined gates)          │
       └──────────────┬───────────────────────────────┘
                      │
       ┌──────────────▼───────────────┐
       │   release-administrator      │  (this Claude instance)
       │   (triage, dispatch, gate)   │
       └──┬────┬────┬────┬────┬────┬──┘
          │    │    │    │    │    │
        ┌─▼─┐ ┌▼─┐ ┌▼─┐ ┌▼─┐ ┌▼─┐ ┌▼──────────────┐
        │AUD│ │DO│ │CI│ │EX│ │LI│ │security-      │
        │   │ │CS│ │  │ │  │ │C │ │verifier       │
        └───┘ └──┘ └──┘ └──┘ └──┘ └── on demand ───┘
```

- **AUD** = release-auditor (Phase 1 + Phase 5)
- **DOCS / CI / EX / LIC** = parallel specialists (Phase 3)
- **security-verifier** fires only on firmware-adjacent diffs (Phase 4)

### Key constraints

- Agents dispatched via the `Agent` tool are cold per invocation. The admin packages context (worktree path, relevant files, prior findings doc) into every prompt.
- Read-only agents (auditor, security-verifier) are allowed **no** `Write`/`Edit` tools — this is a structural guarantee, not a policy.
- The admin is the only agent that talks to the user. Specialists report to the admin.

## Agent Roster

Seven agents total. Each lives at `.claude/agents/<name>.md` with SDK frontmatter, role description, tool allowlist, input contract, output contract, and prompt template.

### 1. `release-administrator`

- **Role:** Coordinate the entire release-prep effort. Triage audit findings, dispatch specialists, enforce acceptance gates, request user approvals, maintain the progress doc.
- **Tools:** All (Agent, Task\*, Read, Write, Edit, Bash, Grep, Glob).
- **Input:** Approved design doc + session goals.
- **Output:** Orchestration; updates to progress doc; approval requests to user.
- **Note:** This Claude instance acts as the admin in this session. The checked-in `.md` lets future sessions re-spawn the role.

### 2. `release-auditor`

- **Role:** Fresh-eyes audit against an OSS-release checklist. Runs twice: Phase 1 initial gap list, Phase 5 final verification sweep.
- **Tools:** Read, Grep, Glob, Bash. No Write/Edit.
- **Input:** Worktree path + checklist location.
- **Output:** `docs/superpowers/audit/2026-04-16-release-audit.md` — severity-tagged findings (critical/high/medium/low), cross-referenced to `PUNCHOUT.md` items.
- **Checklist covers:** licensing, docs completeness, CI coverage, examples, runbooks, `Cargo.toml` metadata, `CHANGELOG.md`, security disclosure, SBOM, tag/release conventions, code hygiene (clippy/fmt/unused deps), `.gitignore` hygiene (`dist/`, `target/`, secrets), open PUNCHOUT items still relevant.

### 3. `docs-engineer`

- **Role:** Documentation review and authoring. README polish, runbook authoring, cross-doc consistency, dead-link detection.
- **Tools:** Read, Write, Edit, Grep, Glob, Bash.
- **Input:** Specific doc(s) or runbook task from admin.
- **Output:** Direct edits + change summary returned to admin.

### 4. `ci-engineer`

- **Role:** GitHub Actions work. Extend build matrix where needed, author `release.yml`, integrate SHA256SUMS + SBOM artifacts, write the release-process runbook.
- **Tools:** Read, Write, Edit, Grep, Glob, Bash.
- **Input:** Workflow task from admin.
- **Output:** Edits to `.github/workflows/*.yml` + `docs/RELEASE_PROCESS.md`.

### 5. `examples-author`

- **Role:** Scaffold `examples/` directory and author end-user examples. Initial set: OpenSC smoke test, pkcs11-tool key generation, PIV CLI auth, GnuPG signing. Additional examples subject to audit triage.
- **Tools:** Read, Write, Edit, Grep, Glob, Bash.
- **Input:** Example spec from admin.
- **Output:** `examples/<topic>/` per-example directory with runnable scripts + README documenting prerequisites, steps, expected output.

### 6. `license-hygienist`

- **Role:** Resolve `LICENSE` vs `LICENSE.txt` duplication. Fill `Cargo.toml` package metadata on every workspace member (`description`, `license`, `repository`, `homepage`, `keywords`, `categories`, `readme`). Audit third-party dependency licenses. Author `THIRD_PARTY_NOTICES.md` if required.
- **Tools:** Read, Write, Edit, Grep, Glob, Bash (cargo-license, cargo-deny optional).
- **Input:** Scope hand-off from admin.
- **Output:** Direct edits + change summary.

### 7. `security-verifier`

- **Role:** Independent read-only review of any diff that touches `firmware/` or `pico2hsm-core/`. Blocks acceptance if it flags regressions or concerns.
- **Tools:** Read, Grep, Glob, Bash (git diff, cargo check, clippy). **No Write/Edit.**
- **Input:** Diff + proposing agent's rationale + surrounding context.
- **Output:** Verdict (`ACCEPT` or `REJECT` with specific file:line references and reasoning). Admin does not merge a firmware-touching change without `ACCEPT`.

## Workstreams and Sequencing

### Phase 0 — Setup (admin)

- Create worktree at `../pico2hsm-release-prep` on branch `release-prep/v1.0.0`.
- Write all 7 agent `.md` files under `.claude/agents/`.
- Create the progress doc at `docs/superpowers/plans/2026-04-16-release-readiness-progress.md` inside the worktree. (The design spec is already present — inherited from `main`.)
- Commit "chore: seed release-prep worktree + agent roster."

### Phase 1 — Audit (auditor, read-only)

- Admin dispatches `release-auditor` with worktree path + OSS-release checklist.
- Auditor produces `docs/superpowers/audit/2026-04-16-release-audit.md` with severity-tagged findings.

### Phase 2 — Triage (admin ↔ user)

- Admin reads the audit, groups findings by workstream, flags any firmware-touching items.
- **Approval gate #1:** Admin presents the triaged findings to the user as a consolidated list with proposed owner (agent) per item. User approves, prunes, or defers. Firmware-adjacent items are flagged explicitly and require per-item approval.

### Phase 3 — Parallel execution (specialists)

Admin dispatches specialists in parallel on disjoint workstreams:

- `license-hygienist` — LICENSE dedup, `Cargo.toml` metadata, third-party audit.
- `docs-engineer` — Doc polish, runbook authoring (release, provisioning ops, incident response, support).
- `ci-engineer` — `release.yml` authoring, `build.yml` review, SHA256SUMS + SBOM integration, `RELEASE_PROCESS.md` runbook.
- `examples-author` — `examples/` directory scaffold + initial example set.

Each specialist returns artifacts + a change summary. Admin logs each in the progress doc.

### Phase 4 — Firmware-touching items (on demand, serialized)

If triage approved any firmware items:

- Admin dispatches the specialist owning the item to propose the change.
- **Approval gate #2:** `security-verifier` reviews the diff read-only. `ACCEPT` → admin commits. `REJECT` → admin surfaces to user (merge anyway / fix and re-verify / defer).

### Phase 5 — Verification sweep (auditor again, read-only)

- Admin re-dispatches `release-auditor` against the updated worktree.
- Auditor produces a diff versus the Phase 1 findings, saved alongside the original.

### Phase 6 — Finalize (admin ↔ user)

- Admin writes/updates `CHANGELOG.md` for v1.0.0.
- Admin updates `PUNCHOUT.md` to reflect closed items.
- **Approval gate #3:** Admin asks user to review the worktree. User's choice: merge PR vs. direct merge. Tag `v1.0.0` is **not** cut in this session.

### Parallelism guarantee

Phase 3 specialists operate on disjoint files by design:

- `license-hygienist` → `Cargo.toml`, `LICENSE*`, `THIRD_PARTY_NOTICES.md`
- `ci-engineer` → `.github/workflows/*`, `docs/RELEASE_PROCESS.md`
- `examples-author` → `examples/` (new directory)
- `docs-engineer` → existing `*.md` except `RELEASE_PROCESS.md`

If two agents want the same file, the admin serializes.

## Coordination Artifacts

| File | Purpose | Lifetime |
|---|---|---|
| `.claude/agents/*.md` | Durable agent roster | Permanent, merges to main |
| `docs/superpowers/specs/2026-04-16-release-readiness-design.md` | This design | Permanent (decision record) |
| `docs/superpowers/plans/2026-04-16-release-readiness-progress.md` | Live workstream state, open approvals, blockers | Kept after merge |
| `docs/superpowers/audit/2026-04-16-release-audit.md` | Initial audit + final verification diff | Kept after merge |

The progress doc is the admin's persistent memory between turns. Any tool result worth remembering is written there, so context loss mid-session does not lose work.

## User Touchpoints

The user is paged exactly three times, plus per-firmware-item approvals:

1. **After Phase 1 audit** — triaged findings presented; user approves/prunes/defers.
2. **Per firmware-touching item** (if any) — diff + verifier verdict presented; user decides.
3. **After Phase 5 verification sweep** — final state + `CHANGELOG.md` + PR presented; user merges when ready.

Between touchpoints, the admin works silently (tool activity visible, no questions). If the admin encounters ambiguity outside the approved scope, it stops and asks rather than guessing.

## "Done" Definition

Release-prep is complete when all of:

- Phase 5 audit re-run shows **zero critical or high** findings (medium/low may survive with explicit justification).
- `docs/RELEASE_PROCESS.md` exists and describes the full tag-to-GitHub-release flow.
- **Dry-run release validated:** admin pushes a throwaway tag like `v1.0.0-ci-test` to the worktree branch, confirms the release workflow produces UF2s + SHA256SUMS + SBOM as GitHub artifacts, then deletes the tag. This is the "testing configuration only" clause — proves the machinery works without minting `v1.0.0` itself.
- `examples/` directory contains at least these runnable examples, each with its own README: OpenSC smoke test, pkcs11-tool key generation, PIV CLI auth, GnuPG signing. Additional examples subject to audit triage.
- `LICENSE` / `LICENSE.txt` duplication resolved; `Cargo.toml` has full package metadata on every workspace member.
- `CHANGELOG.md` reflects v1.0.0.
- `PUNCHOUT.md` accurately reflects closed vs. open items.
- Worktree branch pushed to GitHub; PR against `main` open and labeled.

## Non-Goals (Explicit)

- **Tagging `v1.0.0`.** That is the user's follow-up after merging this PR.
- **Firmware behavioral changes**, unless the auditor flags something as "grossly broken in the security context" and the user approves per-item. Any such change requires `security-verifier` `ACCEPT` before merge.
- **Refactoring unrelated to an audit finding.** Scope discipline per user instruction.
- **Signing key generation or OTP provisioning.** The project is being prepped for open-source release; real signing is out of scope here.

## Decision Log

Decisions made during brainstorming (2026-04-16):

| # | Question | Decision |
|---|---|---|
| 1 | Agent team interpretation: `.md` files, ephemeral, or both? | **Both** — durable `.md` roster + dispatch live this session |
| 2 | Start from known gaps or fresh audit? | **Fresh audit first**, then execute against approved findings |
| 3 | Coordinate with concurrent Claude instance #1 — how? | **Git worktree** isolation on `release-prep/v1.0.0` branch |
| 4 | Release target: cut v1.0.0 this session, prep for later, or open-ended? | **Prep for v1.0.0** — user tags in follow-up session |
| 5 | Team's authority to make changes? | **Docs/CI/examples/runbooks + hygiene + per-item PUNCHOUT approval**; firmware changes only if "grossly broken security" and require independent `security-verifier` review |

## Out of this document (next step)

Once the user approves this spec, the brainstorming skill hands off to `superpowers:writing-plans` to author a detailed implementation plan — agent `.md` file contents, specific bash commands for worktree setup, exact audit checklist contents, etc.
