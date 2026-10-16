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

- `ec_firmware_signing_key-bootkey0.pem` is suspected or confirmed to have leaked.
- A firmware vulnerability is disclosed via GitHub Security Advisories (see
  `SECURITY.md`) or discovered internally.
- A release UF2 or SHA256SUMS file is reported to be corrupt, truncated, or
  mismatched against its signature.
- Any combination of the above (e.g. a key leak that coincides with a
  vulnerability report — handle both tracks in parallel).

---

## Signing-key compromise

Scope: one of the two boot keys (`ec_firmware_signing_key-bootkey0.pem`, which
signs releases, or the offline backup `-bootkey1.pem`) has leaked, been lost, or
is otherwise no longer trustworthy.  The project ships no keys: this runbook is
for whoever signs firmware for a fleet of provisioned devices.
Impact: any attacker with the key can sign firmware that will boot on
devices that trust it.

Provisioned devices trust exactly two keys, burned into OTP slots 0 and 1;
slots 2 and 3 are invalidated at provisioning, so **no new key can ever be
added** (`docs/PROVISIONING.md` §1).

Runbook:

1. **If key 0 is compromised, move to key 1.** Build and sign the next release
   with `SIGNING_KEY=ec_firmware_signing_key-bootkey1.pem`, install it on every
   device and confirm it boots.  Then revoke slot 0 on each device
   (`BOOT_FLAGS1.KEY_INVALID` bit 0) so firmware signed with the leaked key no
   longer boots.  Key 1 is now the only key: keep it under the strictest
   custody you have.  **If key 1, or both keys, are compromised,** there is no
   slot left: the devices must be retired (see the note below).
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
5. **Ship the re-signed firmware.** Cut the next patch version signed with key 1.
   Follow `docs/RELEASE_PROCESS.md` for the release cut.

Note: **OTP-locked devices cannot be re-keyed.** This is a fundamental property
of RP2350 secure boot. Devices that trust no uncompromised key (both keys
leaked, or key 1 leaked after slot 0 was revoked) are tied to a compromised
signer: notify their owners and rotate them out of production.

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
