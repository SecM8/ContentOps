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

- **`AUTO_PR_TOKEN` escape hatch for org-blocked PR creation.** Org
  policies commonly disable "Allow GitHub Actions to create and approve
  pull requests", which kills all seven PR-opening workflows (`collect`,
  `drift`, `kql-schemas-refresh`, `attack-matrix-refresh`,
  `upstream-watchers`, `lock-unlock`, `emergency-disable`) at the PR
  step. Those workflows now accept an optional `AUTO_PR_TOKEN` secret
  (fine-grained PAT, Contents + Pull requests RW, this repo only) and
  fall back to the built-in `GITHUB_TOKEN` when it's unset — zero
  behaviour change for repos where the toggle is on. Side benefit:
  PAT-opened PRs trigger `on: pull_request` CI, which
  `GITHUB_TOKEN`-opened PRs never do. Documented in the
  `github-actions-setup.md` secrets table + troubleshooting matrix and
  the operationalization-paths org gotcha callout.
- **`identity_mode: single` in `.contentops-conformance.yml`** — first-class
  support for single-App-Registration deployments. The conformance `read`
  leg previously hard-coded least-privilege expectations (require
  `CustomDetection.Read.All`, forbid `ReadWrite.All`, expect no Sentinel
  write), so forks running one shared App Reg for every environment —
  a second App Reg can take months of procurement — failed the weekly
  read leg with no supported way to declare their posture. With
  `identity_mode: single` the read leg keeps verifying the `automation`
  environment's federated credential, RBAC reach, and functional reads,
  but applies the shared-identity grant expectations; the report header
  records `identity=read (single-app)`. Default remains `split` (strict);
  unrecognised values fall back to `split` with a visible warning.
  Documented in `deployment-conformance.md` with the accepted trade-off
  and compensating safeguards spelled out.
- `docs/operations/operationalization-paths.md` — decision guide for
  standing the pipeline up: the five operationalization decisions
  (repo topology, execution model A/B/C, identity, tenant-config
  mode, workspace topology), a workflow maturity ladder (which of
  the GitHub Actions workflows to enable at each stage), and a
  read-only validation matrix per path. Linked from `README.md` and
  the Operator Guide doc index.
- `LICENSE` (Apache 2.0).
- `NOTICE` (copyright + attribution-appreciated guidance).
- `TRADEMARK.md` (policy for the `ContentOps` and `SecM8` marks).
- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1 by reference).
- `CONTRIBUTORS.md`, `MAINTAINERS.md`.
- `.github/ISSUE_TEMPLATE/` (bug + feature + config).
- `scripts/add_spdx_headers.py` plus SPDX headers on every Python file
  in `pipeline/`, `scripts/`, and `tests/`.

### Fixed

- **e2e capability matrix: mocked mode is now hermetic.** Token
  acquisition goes over `requests` (azure-identity/MSAL), which respx
  cannot intercept, so the mocked leg's synthetic `AZURE_CLIENT_SECRET`
  drove a real AAD request, failed, fell back to a credential-less
  `DefaultAzureCredential`, and every Azure-touching command died at
  the auth flow before a single mocked route was exercised. Lenient
  `expect_exit` values masked the degradation until prune's
  fail-closed blind guard (#349) turned it into a hard
  `prune.dry_run` failure on every PR touching the CLI surface. The
  e2e conftest now pre-seeds `contentops.utils.auth`'s credential
  cache with an `AccessToken`-shaped fake in offline + mocked modes,
  so the matrix actually flows through the respx routes + in-memory
  stores (51/51 PASS, and the mocked leg drops from ~60 s to ~2 s —
  the old runtime was credential-chain timeouts).
- **`dco.yml` no longer fails fork upstream-sync PRs.** Commits authored
  by the upstream mirror account arrive on downstream sync branches
  (via the one-time `--allow-unrelated-histories` stitch) without
  `Signed-off-by` trailers — they never passed through the fork's DCO
  gate. The per-commit loop now skips upstream-mirror-authored commits,
  mirroring the existing PR-author bypass for Dependabot/Renovate. The
  rebase the failure hint used to suggest (`git rebase --signoff`) is
  destructive on a sync branch: it rewrites the stitch merge.

### Changed

- **Fork-sync documentation hardened from a real downstream
  onboarding:**
  - `docs/operations/upstream-sync.md` gained §4 "One-time stitch —
    fork with unrelated history": the
    `git merge --signoff --allow-unrelated-histories -X theirs`
    procedure, the true-merge-commit requirement (squash/rebase
    destroys the stitch), the DCO interaction, and the post-stitch
    routine-merge loop. The README's upstream-pull section now lists
    it as the fourth sync workflow.
  - `docs/operations/github-actions-setup.md` gained §6 "Scheduled
    workflows — re-point the repo-slug gate" (eleven workflows gate
    cron runs on the operator slug and silently no-op on forks), a
    fork caveat on the "Require linear history" branch-protection
    recommendation, and two new troubleshooting rows (silent
    schedules, DCO failures on sync PRs). Cross-linked from
    `workflow-schedule.md`, the operationalization-paths maturity
    ladder, and the `dco.yml` row in `workflows.md`.
- `docs/reference/workflows.md` re-aligned with the actual workflow
  inventory: ten previously undocumented workflows added to the index
  (`alerts-report`, `attack-matrix-refresh`, `kql-schemas-refresh`,
  `references-check`, `report`, `rollback`, `spelling`,
  `status-refresh`, `tuning-impact-preview`, `upstream-watchers`),
  the stale "26 workflows" / "33 workflows" counts dropped from the
  index and the Operator Guide, and the category map updated
  (`rollback` is a real workflow now, not CLI-only). The generated
  catalog remains the authoritative list.
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
