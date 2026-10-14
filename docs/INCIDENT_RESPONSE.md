# pico2hsm — Incident Response Runbook

Operational runbook for the project maintainer. This document covers the three
incident classes that require a coordinated response: signing-key compromise,
disclosed firmware vulnerability, and corrupt release artifact.

A single device that refuses its keystore (a swapped or damaged SD card,
lost writes, E11/E12 on the display) is an operator matter, not a project
incident: see [KEYSTORE_RECOVERY.md](KEYSTORE_RECOVERY.md).

Last updated: 2026-04-17

---

## Roles and response time

pico2hsm is a **single-maintainer project** (`@mcarey42`). There is no on-call
rotation. Response is best-effort within **72 hours** of confirmed incident
notification. Reporters and downstream users should assume this SLA and plan
accordingly.

---

## Triggers

Initiate this runbook if any of the following occur:

- `ec_firmware_signing_key.pem` is suspected or confirmed to have leaked.
- A firmware vulnerability is disclosed via GitHub Security Advisories (see
  `SECURITY.md`) or discovered internally.
- A release UF2 or SHA256SUMS file is reported to be corrupt, truncated, or
  mismatched against its signature.
- Any combination of the above (e.g. a key leak that coincides with a
  vulnerability report — handle both tracks in parallel).

---

## Signing-key compromise

Scope: the EC private key in `ec_firmware_signing_key.pem` (or its HSM-backed
equivalent) has leaked, been lost, or is otherwise no longer trustworthy.
Impact: any attacker with the key can sign firmware that will boot on
production-locked devices.

Runbook:

1. **Rotate the signing key.** Generate a new `ec_firmware_signing_key.pem`
   following `docs/PROVISIONING.md` Phase 1. Store the new key under the same
   offline custody procedure as the original. Do not reuse the old key.
2. **Revoke prior release tags.** On GitHub Releases, edit every release signed
   with the compromised key and mark it as "pre-release" or delete the release
   (tags remain; only the release page is affected). Add a banner to each
   release notes body pointing at the replacement version.
3. **Publish a GHSA advisory.** Draft a security advisory at
   `https://github.com/mcarey42/pico2hsm/security/advisories` describing the
   scope of the compromise, affected release range, and mitigation (upgrade to
   the re-signed release below).
4. **Post a pinned issue.** Open a pinned issue titled `Signing key rotation —
   action required` linking to the advisory and the new release.
5. **Ship a re-signed firmware.** Cut the next patch version signed with the
   new key. Follow `docs/RELEASE_PROCESS.md` for the release cut.

Note: **OTP-locked devices provisioned with the old key trust chain cannot be
re-keyed.** This is a fundamental property of RP2350 secure boot; see
`docs/PROVISIONING.md` for the OTP story. Users with locked devices must be
notified that their hardware is now tied to a compromised signer and should be
rotated out of production.

---

## Disclosed firmware vulnerability

Scope: a bug with security impact has been reported via
`https://github.com/mcarey42/pico2hsm/security/advisories` or discovered
internally. Reporter-facing process lives in `SECURITY.md`.

Runbook:

1. **Acknowledge the report** within 72 hours in the GHSA draft. Request a
   reproducer if one was not supplied.
2. **Create a private fix branch** from the advisory's "Temporary private
   fork" feature. Do not push the fix to `main` until disclosure.
3. **Coordinate a disclosure window** with the reporter. Default is 90 days
   (per `SECURITY.md`); shorten for actively-exploited issues, lengthen for
   complex fixes only with reporter agreement.
4. **Land the fix.** Merge the private fork into `main` on disclosure day.
5. **Publish the advisory and patch release** simultaneously. Cut the patch
   version per `docs/RELEASE_PROCESS.md`. The advisory body must include
   affected version range, workaround (if any), and upgrade instructions.

---

## Corrupt release artifact

Scope: a UF2, ELF, or SHA256SUMS file on a GitHub Release is reported to be
corrupt, mismatched, or truncated. This is typically an upload mistake, not a
malicious event, but is handled with the same rigour.

Runbook:

1. **Confirm the corruption.** Recompute the local SHA-256 against the
   expected value in `SHA256SUMS`. If `SHA256SUMS` itself is the problem,
   regenerate it from the known-good build artifacts.
2. **Invalidate the artifact.** Delete the corrupt file from the GitHub
   Release page. Do not reupload under the same filename with different
   contents — recut the release under a new patch version.
3. **Re-cut the release.** `docs/RELEASE_PROCESS.md` is authoritative for the
   full re-cut procedure. At minimum: rebuild all UF2s, regenerate
   `SHA256SUMS`, re-sign artifacts, and upload to a new patch tag.
4. **Announce** the corrupt-artifact notice on the superseded release page
   and in a pinned issue. Link to the replacement release.
