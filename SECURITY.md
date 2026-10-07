# Security

## Reporting a vulnerability

Please open a private security advisory via GitHub
(`Security` → `Report a vulnerability`) for any suspected vulnerability
in this repository or in the ContentOps pipeline. Do **not** open a
public issue.

GitHub Security Advisories is the only reporting channel. The
advisory thread is the canonical record for triage, remediation, and
coordinated disclosure. Maintainers receive notifications immediately;
see [`MAINTAINERS.md`](MAINTAINERS.md) for who handles security
triage. If you cannot access GitHub Security Advisories, a private
direct message to any maintainer listed in `MAINTAINERS.md` is an
acceptable backup channel.

### Disclosure SLA

We commit to the following response times for vulnerability reports:

| Step | Target |
|---|---|
| Acknowledge receipt | **2 business days** |
| Initial triage + severity assessment | **5 business days** |
| Remediation plan (or "won't fix" with rationale) | **15 business days** |
| Patch released for High / Critical | **30 days from acknowledgement** |
| Patch released for Medium / Low | **90 days from acknowledgement** |
| Public disclosure (coordinated) | **after patch is available** |

We follow standard 90-day coordinated disclosure. Reporters who
follow this process are credited (with consent) in the release notes
and the GHSA advisory.

## Incident history

### 2026-05 — tenant configuration accidentally published

`config/tenant.yml` was committed to a public repository in the
project's distribution history, carrying real Entra ID tenant and
subscription GUIDs. The values were not credentials, but they are
reconnaissance-grade infrastructure identifiers.

**Actions taken**:
- `config/tenant.yml` deleted from the working tree, replaced with
  `config/tenant.yml.example` containing null-GUIDs.
- `config/tenant.yml` and any `config/tenant.*.yml` (other than
  `.example`) added to `.gitignore`.
- CI workflows updated to materialise `config/tenant.yml` from the
  `TENANT_CONFIG_YAML` repository / environment secret at job start.
  See [`docs/operations/tenant-config-modes.md`](docs/operations/tenant-config-modes.md)
  for the full set of supported config-source modes and the recipe
  for switching between them (this repo runs Mode B; private-fork
  adopters typically run Mode A).
- `gitleaks` CI workflow + local pre-commit hook added; the known
  leaked GUIDs are pinned to specific commit SHAs so historical
  commits do not trip CI, but any new commit reintroducing them
  fails the build.
- App Registration credential rotation, federated credential
  subject review, and Azure activity log review for the affected
  subscription are the responsibility of the repository owner and
  were performed out-of-band.

**Lessons learned**: documented in
[`docs/operations/github-actions-setup.md`](docs/operations/github-actions-setup.md)
and [`CONTRIBUTING.md`](CONTRIBUTING.md). Pre-commit and CI gates now
close the recurrence path.

If you cloned the repository before the rotation and still hold a
copy that contains the original GUIDs, please delete it.

## Audit chain — integrity vs authenticity

The `audit/<date>.jsonl` files form a forward hash chain (SHA-256
over canonical JSON; each record carries `prev_hash` plus its own
`record_hash`). The chain provides **integrity** — editing or
reordering a recorded entry is detected by `contentops audit verify`
and the weekly `audit-verify.yml` workflow (which verifies the latest
deploy run's artifact; `audit/` itself is gitignored, never committed).

The chain does **not** provide **authenticity**. An actor who can
rewrite the audit files (e.g. a runner with `contents: write`, or
control of `deploy.yml`) can drop the newest records or re-compute
the entire chain from a tampered state, and `audit verify` on its own
will still pass. Detecting that needs an anchor outside the chain:
compare the chain's head hash (`contentops audit head`) with the
head attested for that run (below). HMAC-
signing the chain with a tenant key was considered and explicitly
declined: the threat model assumes write access to `main` is the
high-trust boundary, enforced by branch protection + CODEOWNERS,
not by cryptographic signing.

### Head-hash attestation (provenance, run-bound)

`deploy.yml` notarises the chain head out-of-band: after a clean
apply it emits `audit-head.json` (`contentops audit head`) and signs
it with a **GitHub Artifact Attestation** (Sigstore keyless via the
run's OIDC identity, recorded in the public Rekor transparency log) in
a separate job that holds only `id-token: write` + `attestations: write`
— the prod apply job's token is unchanged. Verify with `gh attestation
verify audit-head.json --owner KustoKing`.

Scope of this attestation, stated precisely:

- It provides **provenance**: cryptographic proof that *KustoKing CI run
  N produced this chain head*. It does **not** add authenticity against
  an attacker who controls `deploy.yml` execution — such an attacker can
  attest their own tampered chain. The write-to-`main` boundary above is
  still the trust line.
- Because `audit/` is gitignored and **not restored across runs** (the
  runner starts from `ZERO_HASH`), the attested head describes **that
  run's** records, not a cumulative ledger. It detects nothing about
  records from prior runs (they were never present).
- Durability is bounded by GitHub's artifact/attestation retention.

If your threat model needs stronger authenticity (survival of a
compromised runner or retention expiry), sign the head into an external
append-only ledger — the file format supports that without changing the
writer.

## CI trust model for pull requests

Workflows triggered by `pull_request` run **the PR's own code**:
`contentops/`, `requirements.txt` and the workflow file itself as they
are on the PR branch. Branch protection and CODEOWNERS only gate the
*merge*; they do not stop a PR job from running. Consequences:

- **Fork PRs** get no OIDC token and no secrets. Every job that can
  mint an Azure token (`id-token: write`) is also skipped for fork PRs
  by a job-level `head.repo.full_name == github.repository` guard, so
  fork code never runs inside an Azure-credentialed environment.
- **Same-repo PRs** (anyone with write access, or an automated branch
  such as a dependency bump) run inside the job's GitHub Environment:
  - `integration-deploy.yml` → `integration`: applies the PR's content
    to the integration workspace.
  - `drift.yml` (`drift-pr`) and `tuning-impact-preview.yml` →
    `automation`: read the production tenant.
  - `integration.yml` → `integration`, only after the `run-integration`
    label is applied.
  - `validate.yml` (the required PR gate) holds **no** Azure
    credentials.
- `tests/v2/test_workflow_hardening.py` fails CI if a PR-reachable job
  gains `id-token: write` without such a guard, or if a workflow expands
  `inputs.*` / `github.event.*` inside a `run:` script.

The identity behind each environment is therefore exposed to anyone who
can push a branch. Close that gap with GitHub and Azure settings (they
live outside the repository):

1. **Least privilege.** Give `integration` its own App Registration
   whose RBAC is scoped to the integration workspace's resource group
   only — not the production write identity. Keep `automation` on the
   read identity (Sentinel Reader + Log Analytics Reader,
   `CustomDetection.Read.All`); see
   [`docs/operations/authentication-setup.md`](docs/operations/authentication-setup.md).
2. **Approval.** If not every writer is trusted with that identity, add
   required reviewers (with *Prevent self-review*) to the `integration`
   environment so each PR deploy waits for a second person.
3. **Config source.** `config/tenant.yml` is materialised by
   `scripts/materialise_tenant_config.py`: a committed or force-added
   file that differs from the `TENANT_CONFIG_YAML` secret fails the job
   instead of silently retargeting it.

`contentops conformance` (L7, `environment_protection[...]`) checks the
approval half: it WARNs when `integration` has no required reviewer, and
when `automation` has none under `identity_mode: single` (PR code then
runs with the shared write identity). A deliberate single-identity setup
remains supported, so this is a warning, never a failure. The least-
privilege half is L5 (Azure RBAC per identity).

## Dependency scanning

Every pull request and every push to `main` runs
[`pip-audit`](https://pypi.org/project/pip-audit/) against
`requirements.txt` (see `.github/workflows/ci.yml`). The job fails the
build on any unsuppressed advisory.

## Static application security testing (SAST)

Every pull request and every push to `main` runs
[`bandit`](https://bandit.readthedocs.io/) and
[`semgrep`](https://semgrep.dev/) over the `contentops/`, `scripts/`,
and `tests/` trees (see `.github/workflows/sast.yml`). Findings at
`high` severity fail the build; lower findings warn.

## Secret scanning

[`gitleaks`](https://github.com/gitleaks/gitleaks) runs on every push,
every PR, and nightly. The full config lives at `.gitleaks.toml`.
GitHub's built-in secret scanner is also enabled at the repository
level.

## Workflow-failure notifications

Three load-bearing scheduled workflows — `audit-verify.yml` (weekly
chain integrity), `drift.yml` (daily live-tenant drift snapshot),
and `silent-rules.yml` (weekly silent-rule report) — open a
`pipeline-alert`-labelled GitHub issue when their scheduled run
fails. Subsequent failures of the same workflow comment on the
existing issue (dedup by title) rather than creating new ones.

Implementation: `.github/actions/notify-workflow-failure/action.yml`,
called via `if: failure() && github.event_name == 'schedule'` from
each workflow. Uses `GITHUB_TOKEN` — no external webhook channel.
Operators triage via the standard GitHub issue surface; close the
issue once the next scheduled run is green. PR-mode and
`workflow_dispatch` failures do not notify (those are operator-
driven and already visible to whoever ran them).

Recovery guidance per failure mode lives in
[`docs/operations/audit-recovery.md`](docs/operations/audit-recovery.md)
and the per-workflow step summary.

## Software bill of materials

Every tagged release attaches a CycloneDX SBOM under the workflow
artifacts (see `.github/workflows/release.yml`). Downstream
consumers can pin to the SBOM and scan with the tool of their
choice (`grype`, `trivy`, etc.).

## Supply-chain hardening

- All third-party GitHub Actions are pinned by **commit SHA**, not by
  tag, with the human-readable tag retained as a comment. Renovate
  (`.github/renovate.json`) keeps these digests current.
- Runtime dependencies in `requirements.txt` and `pyproject.toml` are
  **pinned to exact versions**. Renovate opens weekly PRs to bump
  them; security advisories are picked up immediately by `pip-audit`.
- Commits to `main` must be GPG- or SSH-signed and verified by
  GitHub. The Developer Certificate of Origin (`Signed-off-by:`
  trailer) is enforced by `.github/workflows/dco.yml`. See
  `CONTRIBUTING.md` for setup.
- Branch protection on `main` requires `pytest`, `cli-smoke`,
  `mitre-attack-coverage`, `production-promotion-check`, `dco`,
  `sast`, and `secret-scan` to pass. Configure via repository
  settings; see `CONTRIBUTING.md`.

## Known advisories

No advisories are currently suppressed. If a future advisory is
determined to be non-exploitable in this codebase, document it here
in the following form and add `--ignore-vuln <id>` to the
`pip-audit` step in `.github/workflows/ci.yml`:

```
- GHSA-xxxx-xxxx-xxxx (package <name> <version>)
  Status: suppressed
  Rationale: <why this advisory does not apply to our usage>
  Reviewed: <YYYY-MM-DD> by <handle>
```
