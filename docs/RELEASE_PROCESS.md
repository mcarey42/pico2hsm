# pico2hsm Release Process

Operator runbook for cutting a tagged release of pico2hsm. Releases are
tag-triggered: pushing an annotated tag matching `v*` to the upstream remote
fires `.github/workflows/release.yml`, which builds UF2 firmware for all six
supported boards, emits SBOMs, aggregates SHA256SUMS, and publishes a GitHub
Release with all assets attached.

The UF2s shipped in the GitHub Release are **unsigned**. Production signing
(with a per-project EC firmware signing key) is performed offline and is out of
scope for this workflow — see [SECURE_PROVISIONING_PLAN.md](SECURE_PROVISIONING_PLAN.md).

---

## 1. Prerequisites

**Local tools**

- `git` with push access to the project repository
- [`gh`](https://cli.github.com/) CLI, authenticated against GitHub
  (`gh auth status` should show a valid token)
- [`picotool`](https://github.com/raspberrypi/picotool) 2.0.0 or newer (for
  local verification of UF2 content)
- Rust stable toolchain with the `thumbv8m.main-none-eabihf` target (for local
  repro builds if needed):
  ```sh
  rustup target add thumbv8m.main-none-eabihf
  ```
- Optional: `ec_firmware_signing_key.pem` in the repo root if you intend to
  produce a signed build locally for final hardware verification. This key is
  **not** used by CI — CI ships unsigned artifacts.

**GitHub permissions**

- Push rights to the `pico2hsm` repository
- Tag-push rights (some branch-protection rules block direct tag pushes; check
  `Settings > Tags` if push is rejected)
- Permission to create releases (implied by `contents: write` on the
  `release.yml` workflow)

**Access to reference hardware**

- At least one RP2350 board from the supported list, ideally a `pico2_4m`
  (most portable), for the post-release flash verification step.

---

## 2. Pre-release checklist

Work through this list on a clean, up-to-date `main` checkout.

1. **All CI green on `main`.** `gh run list --workflow=build.yml --branch=main
   --limit=5` — every recent run must be `success`. If anything is failing,
   fix on `main` before tagging.

2. **PUNCHOUT.md updated.** The closed-items table should reflect every item
   closed in this release. Bump the "Last updated" line at the top to
   `YYYY-MM-DD (vX.Y.Z: short summary)`.

3. **CHANGELOG.md updated.** Rename the `## [Unreleased]` section to
   `## [X.Y.Z] - YYYY-MM-DD` (Keep-a-Changelog format). Add a fresh empty
   `## [Unreleased]` section above it. The release workflow extracts the
   `## [X.Y.Z]` section verbatim — so keep it self-contained and well-edited.

4. **Version bumps in `Cargo.toml` members.** Each workspace crate
   (`pico2hsm-core`, `firmware`, `tests/integration`) should advertise the
   release version. _The exact scheme — whether all crates move in lockstep or
   stay on independent semver — is owned by admin. See admin before bumping._

5. **Docs review.** Confirm the top-of-file "Last updated" stamps in
   `docs/PROVISIONING.md`, `docs/SECURE_PROVISIONING_PLAN.md`, and
   `SECURITY.md` reference the new version (or at least the correct RC
   lineage).

6. **Local repro build.** Pick one board and verify the release profile
   builds:
   ```sh
   cargo build -p pico2hsm-firmware --release --no-default-features \
       --features pico2_4m,applet-piv,applet-openpgp-curve25519 \
       --target thumbv8m.main-none-eabihf
   ```
   A successful local build is a strong signal that CI will succeed.

7. **Commit and push** all pre-release edits to `main`. Do not tag until the
   push-trigger `build.yml` passes for the last commit.

---

## 3. Tagging and pushing

Releases are cut from annotated tags on `main`. From an up-to-date `main`:

```sh
git checkout main
git pull --ff-only
git tag -a v1.0.0 -m "v1.0.0"
git push origin v1.0.0
```

Do **not** push a lightweight tag (`git tag v1.0.0`). The workflow tolerates it
but annotated tags carry the tagger identity and message, which matters for
provenance.

If you need to abort before CI finishes:

```sh
git push --delete origin v1.0.0
git tag -d v1.0.0
# If a draft release was already created, delete it manually:
gh release delete v1.0.0 --yes
```

---

## 4. CI workflow monitoring

The release workflow takes roughly 15 minutes to complete end-to-end:

- `build-uf2` matrix (6 boards, parallel): ~10 min each, but parallel so the
  slowest board gates. Cold-cache ~12 min, warm-cache ~4 min.
- `sbom`: ~2 min cold, ~30 s warm.
- `release`: ~30 s (pure asset assembly).

Watch the run live:

```sh
gh run watch
```

Or list recent runs and tail one:

```sh
gh run list --workflow=release.yml --limit=5
gh run watch <run-id>
```

Check that the GitHub Release page populated correctly:

```sh
gh release view v1.0.0
gh release view v1.0.0 --web   # opens in browser
```

If anything fails, the release is **not** published (the `release` job runs
only after `build-uf2` and `sbom` both succeed). Fix the underlying cause, push
a follow-up commit, delete the tag (see §3), and re-tag.

---

## 5. Release verification

After the workflow finishes and the GitHub Release appears, verify the assets
before announcing.

### 5.1 Integrity check

Download `SHA256SUMS` and at least one UF2 to a scratch directory, then:

```sh
gh release download v1.0.0 --pattern 'SHA256SUMS'
gh release download v1.0.0 --pattern 'pico2hsm-pico2_4m-unsigned.uf2'
sha256sum -c SHA256SUMS --ignore-missing
# Expected: pico2hsm-pico2_4m-unsigned.uf2: OK
```

Every board listed in `SHA256SUMS` should correspond to an uploaded UF2. If
any line is missing, something in the release job regressed — investigate
before announcing.

### 5.2 SBOM sanity check

The release assets include CycloneDX 1.4 JSON SBOMs (`*.cdx.json`), one per
workspace crate. Spot-check one:

```sh
gh release download v1.0.0 --pattern 'firmware.cdx.json'
jq '.metadata.component.name, .components | length' firmware.cdx.json
# Expected: "firmware"  followed by a component count (typically 80-120).
```

SBOMs can be ingested by standard SCA tooling (Grype, Dependency-Track,
`cyclonedx-cli validate`, etc.).

### 5.3 UF2 flash test on real hardware

Pick one board (the `pico2_4m` is the recommended reference) and flash the
unsigned UF2 via BOOTSEL:

1. Hold `BOOTSEL` on the Pico 2 and plug USB → a `RPI-RP2` mass-storage volume
   appears.
2. Flash:
   ```sh
   picotool load pico2hsm-pico2_4m-unsigned.uf2 -t uf2 -x
   # Or drag-and-drop the .uf2 onto the mass-storage volume.
   ```
3. After re-enumeration, confirm the smartcard reader is visible:
   ```sh
   opensc-tool --list-readers
   opensc-tool --atr
   ```
   Expected ATR is the SC-HSM 2 ATR (see memory note `sc_hsm_atr.md`).

If the device enumerates, an ATR is returned, and `opensc-tool --send-apdu
00A4040B A0000003080000100001` SELECT responds with a reasonable SW, the UF2 is
good.

---

## 6. Post-release

### 6.1 Announce

Draft announcement template (adjust channels as appropriate):

> **pico2hsm v1.0.0 is out.**
>
> - Release: https://github.com/mcarey42/pico2hsm/releases/tag/v1.0.0
> - UF2 firmware for all six supported RP2350 boards (unsigned — sign locally
>   for production).
> - Highlights: [pull key bullets from CHANGELOG].
>
> Thanks to everyone who tested the rc series. Report issues via GitHub Issues.

### 6.2 Maintenance policy

- Update `SECURITY.md`'s "Supported versions" table to reflect the new stable
  line. Typically only the latest minor is supported for security fixes.
- Open a `release-X.Y` branch **only** if a patch release is expected. For the
  initial v1.0.0 cut, no branch is needed until a v1.0.1 is in sight.

### 6.3 Backport policy

Patch releases (`v1.0.1`, `v1.0.2`, …) are cut from `release-1.0` once it
exists. Cherry-pick security and regression fixes only — no feature backports.
Re-tag from the branch following the same process as §3.

---

## 7. Dry-run mode

Before the first real release, always rehearse with a dry-run tag. The
workflow recognises any tag with a `-ci-test` suffix and flags the release
body with a prominent dry-run warning so nobody mistakes it for real.

```sh
# 1. Push a throwaway tag.
git tag -a v1.0.0-ci-test -m "release.yml dry-run"
git push origin v1.0.0-ci-test

# 2. Watch the workflow.
gh run watch

# 3. Once published, inspect the release.
gh release view v1.0.0-ci-test
gh release download v1.0.0-ci-test --pattern 'SHA256SUMS' -O -
gh release download v1.0.0-ci-test --pattern 'pico2hsm-pico2_4m-unsigned.uf2'

# 4. Verify the UNSIGNED warning and DRY-RUN banner appear in the release body.
# Verify every expected asset is present.

# 5. Clean up: delete the GitHub Release AND the tag (both sides).
gh release delete v1.0.0-ci-test --yes
git push --delete origin v1.0.0-ci-test
git tag -d v1.0.0-ci-test
```

Important: `gh release delete` does **not** delete the underlying tag — you
must delete the tag separately on both the remote and the local repo.

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `build-uf2` job fails for one board only | New code broke that board's feature flag | Fix on `main`, re-tag. Use `cargo check --no-default-features --features <board>,applet-piv,applet-openpgp-curve25519` locally to reproduce. |
| UF2 for a board is missing from the release | The `build-uf2` matrix job for that board failed but the `release` job still ran | The release job's "Assemble release directory" step enforces all six boards are present; this should now fail fast. If you see a release published with a missing UF2 anyway, the enforcement regressed — file a bug. |
| `SHA256SUMS` is empty or incomplete | Artifact download step lost a shard | Check the workflow logs under "Download all UF2 artifacts" for download failures. Re-run the workflow with `gh run rerun`. |
| Release body says "No CHANGELOG.md section found for version X.Y.Z" | CHANGELOG header uses a different format than `## [X.Y.Z]` or tag name has a leading `v` that didn't get stripped | The extractor strips a single leading `v` from the tag. Ensure CHANGELOG uses `## [1.0.0] - 2026-04-16` (Keep-a-Changelog) exactly. |
| `cargo install cargo-sbom` fails in the `sbom` job | crates.io outage or toolchain breakage | Re-run the workflow. The cached install path (`~/.cargo/bin/cargo-sbom`) is keyed on version 0.9.1; if the version is bumped, the cache miss forces a fresh install. |
| SBOM JSON is well-formed but missing a crate | Workspace member name drift | Edit the `for crate in ...` loop in `.github/workflows/release.yml` to match `Cargo.toml` `[package].name` for every member. |
| GitHub release publish fails with 403 | `contents: write` permission missing or branch-protection ruleset blocks tag-triggered creation | Check `Settings > Actions > General > Workflow permissions` is at least "Read and write" for this repo. |
| `picotool load` on the flashed device produces "No UF2 file found" | UF2 family mismatch | The UF2 family must be `rp2350-arm-s`. If a new bootrom revision requires a different family, update `release.yml` and `build.yml` together. |

### 8.1 Consuming the SBOMs

The `*.cdx.json` release assets are CycloneDX 1.4 JSON, produced by
`cargo-sbom`. Any standard SCA tool can consume them:

- [`cyclonedx-cli validate`](https://github.com/CycloneDX/cyclonedx-cli) —
  schema validation.
- [Grype](https://github.com/anchore/grype) — vulnerability scan:
  `grype sbom:firmware.cdx.json`.
- [Dependency-Track](https://dependencytrack.org/) — upload via the REST API
  (`/api/v1/bom`).
- `cargo-sbom --help` — full option reference, including other output
  formats (SPDX, CycloneDX XML) if downstream consumers need them.

If `cargo-sbom` ever fails in CI, the workflow still attaches a plain-text
`cargo-tree-firmware-<board>.txt` fallback that lists every transitive
dependency with its SPDX license tag — enough for manual audit.

---

## 9. References

- Release workflow: `.github/workflows/release.yml`
- Build workflow: `.github/workflows/build.yml`
- Secure provisioning (signing): [SECURE_PROVISIONING_PLAN.md](SECURE_PROVISIONING_PLAN.md)
- Production provisioning playbook: [PROVISIONING.md](PROVISIONING.md)
- Board matrix reference: [BUILD_CONFIGURATIONS.md](BUILD_CONFIGURATIONS.md)
- Keep a Changelog: https://keepachangelog.com/en/1.1.0/
- softprops/action-gh-release: https://github.com/softprops/action-gh-release
- cargo-sbom: https://crates.io/crates/cargo-sbom
