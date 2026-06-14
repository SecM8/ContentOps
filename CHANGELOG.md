# Changelog

All notable changes to **ContentOps powered by SecM8** are recorded
here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versioning follows [Semantic Versioning 2.0](https://semver.org/).

This project uses [Conventional Commits](https://www.conventionalcommits.org/)
for commit messages. Future releases will be generated automatically
from the commit history.

## [Unreleased]

### Security

- **Detection-inventory report telemetry scrubbed from git + the public
  mirror.** `report.yml` was committing `reports/latest.{html,json,md}`,
  dated `reports/YYYY-MM-DD.*`, and `reports/unified.html` — which carry
  live per-detection operational telemetry (display names, alert/incident
  counts, TP/FP %, MTTD, MTTR), and `reports/latest.*` was in the
  public-mirror sync allowlist. Those files were removed from the tree and
  `reports/` is now gitignored except `reports/badge.json` (an anonymous
  coverage % that still feeds the README badge). The sync allowlist now
  ships **only** `reports/badge.json`, so the next `public-sync` drops the
  telemetry from the mirror tree. Reports are still produced — download the
  `report.yml` / `alerts-report.yml` run artefact — they're just no longer
  committed. Note: removing from the tree stops future exposure but the
  files remain in git **history** on any repo they were pushed to; a
  history rewrite is required to purge them there.
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

- **`alerts-report` backfill no longer times out.** The time-sliced
  `alerts_v2` fetch makes ~350 throttled requests for a busy 30-day tenant,
  so the fetch + export ran past the job's 15-minute `timeout-minutes` and
  got cancelled mid-run (≈ day 24 of 30, leaving the ledger unwritten). The
  ceiling is raised to 30 minutes — free for the daily cron, which is one
  day and finishes in ~2 min. Operators who want to shrink the slice count
  (and the throttling) can raise the `alerts_v2` `$top` page size from its
  proven-safe default of 500 via the new `CONTENTOPS_ALERTS_PAGE_SIZE`
  Variable, after confirming their tenant's alert total is unchanged (per
  Microsoft's paging guidance an over-large `$top` can be silently capped to
  the API maximum, which would break the time-slice truncation signal — so
  the default stays at the empirically-verified 500 and a higher value is
  opt-in per fork). Wired into `alerts-report.yml`.
- **Graph ↔ Sentinel alert correlation fixed (de-dup / double-count).**
  The same Defender alert lands in both Graph `alerts_v2` (keyed by `id` /
  `providerAlertId`) and the Sentinel `SecurityAlert` table (keyed by
  `VendorOriginalId`), but the merge joined Graph `providerAlertId` against
  Sentinel `SystemAlertId` — a Log-Analytics-internal hash that never equals
  the Graph id. So **every** cross-source alert fell through as
  `0 merged`, was kept twice (Graph-only + Sentinel-only), and the
  Graph→Sentinel MITRE/evidence enrichment matched nothing (`0/N enriched`).
  Harmless while Graph capped at 500; once the paging fix surfaced the full
  ~50k, daily totals inflated ~1.8×. The KQL projection now selects
  `VendorOriginalId`, `from_kql_row` maps it to `provider_alert_id`, and both
  join sites (`merge_alerts`, `enrich_from_graph`) correlate on the vendor's
  original alert id via a shared `_correlation_keys` helper that tries every
  candidate field. A run that still finds zero matches logs a one-line sample
  of both sides' ids so the right key is obvious from the log.
- **Alert sync no longer truncates Graph `alerts_v2` at 500.** The
  enrichment fetch pulled the whole window in one `GET /alerts_v2?$top=500`
  and relied on `@odata.nextLink` to page — but alerts_v2 silently stops
  emitting the continuation token past the first page on large result
  sets, so a 30-day backfill returned exactly 500 alerts, all landing on
  day one (every later day showed `0 from Graph`). The daily cron hid it
  because a single day usually fit under 500. `list_graph_alerts_windowed`
  now paginates by **time** instead of the continuation token — the
  technique UAL/Defender harvesting tools use to beat per-window result
  caps: fetch a slice as one page, and if it comes back full at the cap,
  halve the window and recurse down to a 15-minute floor. `$top` stays at
  the empirically-observed page cap (500) so the "full page = truncated"
  signal can't be fooled by the API ignoring a larger value; a slice still
  saturated at the floor logs a loud WARNING naming the window. Verified
  against a simulated 30-day × 2000/day tenant (60,000 alerts recovered in
  255 slices, zero loss).
- **Automated PRs now carry a DCO sign-off.** The shared `auto-pr`
  composite action passes `signoff: true` to
  `peter-evans/create-pull-request`, so `collect` / `drift` /
  `kql-schemas-refresh` / `attack-matrix-refresh` / `upstream-watchers`
  / `lock-unlock` commits land with a `Signed-off-by` trailer. Until
  now these PRs leaned on the `dco.yml` PR-author bypass, which only
  matches bot logins — fine while PRs were opened by `GITHUB_TOKEN`
  (those never trigger `pull_request` CI, so `dco` never ran). The
  moment a PR is opened with `AUTO_PR_TOKEN`, it is authored by the PAT
  owner (a real account, not bypassed), `dco` runs, and the missing
  trailer fails it. `dco.yml` treats a present-but-author-mismatched
  trailer as a non-fatal warning, so the sign-off turns the check green.
- **First `collect` of a brownfield tenant no longer red-walls the
  promotion gate.** `production-promotion-check.yml` carries a skip for
  `chore(collect|drift):` commits — collected content mirrors
  already-promoted tenant rules, not new human promotions — but the
  skip read `git log -1` on the synthetic merge commit that
  `actions/checkout` produces for `pull_request` events, whose subject
  is `Merge <sha> into <sha>` and never matches the regex. The skip
  therefore never fired; it stayed invisible only because collect PRs
  never triggered `pull_request` CI until the `AUTO_PR_TOKEN` path
  arrived. The gate now reads the PR head-commit subject via
  `$HEAD_SHA`. Without the fix, importing an existing tenant's N
  production rules failed the gate on all N at once.
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
