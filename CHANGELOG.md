# Changelog

All notable changes to **ContentOps powered by SecM8** are recorded
here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versioning follows [Semantic Versioning 2.0](https://semver.org/).

This project uses [Conventional Commits](https://www.conventionalcommits.org/)
for commit messages. Future releases will be generated automatically
from the commit history.

## [Unreleased]

### Security

- **Tenant config moved out of git.** The committed `config/tenant.yml`
  carrying real Azure tenant + subscription GUIDs was deleted from the
  working tree and gitignored. CI workflows now materialise it at job
  start from a `TENANT_CONFIG_YAML` repository secret. Local developers
  copy `config/tenant.yml.example` and fill in their own values. See
  `SECURITY.md` for the rotation history.
- **gitleaks gate** added (`.github/workflows/secret-scan.yml` +
  `.gitleaks.toml` + `.pre-commit-config.yaml`). Push, PR, and nightly
  scans plus a local pre-commit hook. The historical leaked GUIDs are
  pinned to specific commit SHAs in the allowlist so old commits do
  not break CI; new commits cannot reintroduce them.
- **DCO sign-off enforcement** via `.github/workflows/dco.yml`. Every
  commit in a PR must carry a `Signed-off-by:` trailer.

### Added

- `LICENSE` (Apache 2.0).
- `NOTICE` (copyright + attribution-appreciated guidance).
- `TRADEMARK.md` (policy for the `ContentOps` and `SecM8` marks).
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1 by reference).
- `CONTRIBUTORS.md`, `MAINTAINERS.md`.
- `.github/ISSUE_TEMPLATE/` (bug + feature + config).
- `scripts/add_spdx_headers.py` plus SPDX headers on every Python file
  in `pipeline/`, `scripts/`, and `tests/`.

### Changed

- **Lint policy revision: production-status no longer auto-escalates
  META002-005.** Severity for the four authoring-metadata rules
  (`metadata.description`, `metadata.attackDescription`,
  `metadata.references`, `metadata.falsePositives`) is now controlled
  solely by `tenant.policy.scaffoldStrict`. The earlier override —
  which forced these to `error` on any envelope with
  `status: production` regardless of the tenant policy — was removed
  so a tenant carrying a backlog of collected-but-not-yet-enriched
  production rules can drain it incrementally without every PR going
  red. Operators who want the strict gate set
  `policy.scaffoldStrict: true` in `config/tenant.yml`. The current
  backlog (51 production rules without authoring metadata) is tracked
  as **G24** in `docs/reference/gap-assessment.md`.
- `contentops/config.py` raises a helpful `FileNotFoundError` when
  `config/tenant.yml` is missing, pointing at the `.example` template
  and the CI secret.
- `.github/actions/pipeline-setup/action.yml` materialises
  `config/tenant.yml` from the `tenant-config-yaml` input (wired to
  `${{ secrets.TENANT_CONFIG_YAML }}` by callers). Affected callers:
  `deploy.yml`, `drift.yml`, `collect.yml`, `prune.yml`,
  `retry-failed.yml`, `integration.yml`, `silent-rules.yml`,
  `integration-deploy.yml`, `promote-to-integration.yml`.
- `CONTRIBUTING.md` documents the DCO sign-off, the tenant config
  template, and the pre-commit hook setup.

---

## Pre-0.1.0 — historical

The repository carries substantial history under the project's
former name `SIEMContent`. Highlights from the most recent ~50
merges, kept as a coarse reference for downstream readers:

- **Coverage**: derive MITRE coverage from payload (not metadata-only);
  accept ARM-only tactics (PreAttack + ICS/OT). _(PR #153)_
- **Catalog**: code-driven catalog generator + CI drift gate. _(eace16e)_
- **Phase 8** — explicit workspace inputs on `deploy` +
  `integration-deploy`. _(PR #149/150)_
- **Phase 7** — CI quality-gate refinement (smoke tests, pytest-xdist,
  actionlint pinning). _(PR #148)_
- **Phase 6** — KQL lint audit + refresh; `KQL101` (no `| take` /
  `| limit`) ships under `--strict`. _(PR #144)_
- **Sentinel ARM normalization** — `sentinel-roundtrip-diff` diagnostic
  + per-handler `_strip_server_fields`. _(PR #142)_
- **Workspace snippet substitution** — per-workspace KQL overrides.
  _(PR #136/140)_
- **Optional engine gating** — symmetric Sentinel + Defender gating
  from `tenant.yml`. _(PR #134)_
- **Config CLI** — `contentops config validate` /
  `contentops config list-workspaces` + `plan --role/--workspace`.
  _(PR #133)_
- **Asset taxonomy reduction** — six detection-engineering essentials.
  _(PR #129)_

For the full pre-0.1.0 history see `git log` or the GitHub releases
page. From 0.1.0 onwards, this file is the authoritative source.
