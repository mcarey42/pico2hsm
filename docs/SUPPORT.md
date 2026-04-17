# pico2hsm — Support

How to get help with pico2hsm. Please pick the right channel for your
question — it saves everyone time.

---

## Questions and usage help

Open a GitHub issue with the `question` label:

- https://github.com/mcarey42/pico2hsm/issues/new?labels=question

If GitHub Discussions is enabled on the repository, that is the preferred
channel for open-ended questions. Check the Discussions tab first.

Before asking, please check:

- `README.md` — project overview and quick links.
- `QUICKSTART.md` — first-device walkthrough.
- `docs/SC_HSM_APDU_REFERENCE.md` and sibling APDU references — full command
  semantics.

---

## Bug reports

Open a GitHub issue with the `bug` label using the bug report form:

- https://github.com/mcarey42/pico2hsm/issues/new?template=bug_report.yml

The form is specified in `.github/ISSUE_TEMPLATE/bug_report.yml`. You will be
asked for the pico2hsm version, board variant, host OS + OpenSC version,
reproduction steps, expected and actual behaviour, and RTT/defmt logs if
available.

---

## Feature requests

Open a GitHub issue with the `enhancement` label using the feature request
form:

- https://github.com/mcarey42/pico2hsm/issues/new?template=feature_request.yml

The form is specified in `.github/ISSUE_TEMPLATE/feature_request.yml`. You
will be asked for a problem statement, proposed solution, and alternatives
considered.

---

## Security reports

**Do not file security issues in public issues or discussions.** Use GitHub's
private security advisories feature:

- https://github.com/mcarey42/pico2hsm/security/advisories

Full reporter-facing process, scope, and disclosure policy lives in
`SECURITY.md`.

---

## Response expectations

pico2hsm is a **single-maintainer project**. There is no SLA. Response is
**best-effort within 72 hours** for security reports, and as-available for
everything else. Please be patient — if an issue has not been acknowledged in
two weeks, a polite nudge comment is appropriate.

## Commercial support

None is available. pico2hsm is an unpaid open-source project. If you need a
supported commercial HSM, consider a certified product such as a YubiHSM,
Nitrokey HSM, or Thales Luna series device.
