# Changelog

All notable changes to **ContentOps powered by SecM8** are recorded
here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versioning follows [Semantic Versioning 2.0](https://semver.org/).

This project uses [Conventional Commits](https://www.conventionalcommits.org/)
for commit messages. Future releases will be generated automatically
from the commit history.

## [Unreleased]

### Added

- **Team routine page.** New
  [`docs/operations/team-routine.md`](docs/operations/team-routine.md)
  sets out what a deployment fork needs from its team: a five-minute
  daily look at the drift PR (merge to accept portal changes, or revert
  them in the portal), a weekly sweep of the housekeeping bot PRs and
  the upstream-sync PR (always a merge commit), a "red check -> what to
  do" table for the failures forks have actually hit, and a short
  never-do list. Result: one page to hand a new team member instead of
  a tour of the workflow files. Linked from the Operator Guide.
- **`contentops state adopt` and `state-adopt.yml`.** A tenant deployed
  before ContentOps tracked state showed every rule as `unmanaged`, and
  the only way to fix that was a full redeploy — which re-saves every
  rule (rules can re-run over windows they already covered and raise
  duplicate incidents) and can overwrite template links. `state adopt` runs drift's read-only comparison and
  records each rule that already matches the tenant as managed
  (`status: adopted`), keyed by the local id. Rules that differ are
  listed, never adopted; any listing error aborts before state is
  written; `last_apply_*` and the audit trail are untouched. The
  manual-only `state-adopt.yml` (dry-run by default) runs it in CI and
  pushes the state branch. Result: an existing tenant becomes managed
  without a single write to Azure. See
  [`operations/adopt.md`](docs/operations/adopt.md).

### Changed

- **KQL schema refresh runs weekly, not daily.** `kql-schemas-refresh.yml`
  now fires Mondays at 03:30 UTC (`30 3 * * 1`) instead of every day.
  Table schemas change rarely, and a daily PR is more review than the
  change is worth — one fork accumulated 83 daily schema PRs before
  supersede-close landed. `gh workflow run kql-schemas-refresh.yml`
  still refreshes on demand. Result: at most one schema PR a week.
- **Scheduled workflows are opt-in per deployment, not slug-edited.**
  Eleven cron gates read `github.repository == 'KustoKing/SIEMContent'`,
  so every deployment fork had to rewrite the slug in eleven workflow
  files — and every upstream sync then conflicted on exactly those
  lines. The gate now also passes when the repo variable
  `CONTENTOPS_SCHEDULES` is `true`. Result: forks set one variable
  (`gh variable set CONTENTOPS_SCHEDULES --body true`), take upstream's
  workflow files verbatim, and syncs stop conflicting. Forks that leave
  it unset (the public mirror included) stay silent on cron, so this is
  a no-op for anyone who has not opted in. See
  [`github-actions-setup.md` §6](docs/operations/github-actions-setup.md#6-scheduled-workflows--opt-in-with-contentops_schedules).
- **Bot PRs supersede-close.** `kql-schemas-refresh.yml`, `collect.yml`
  and `upstream-watchers.yml` now close their own older open PRs (matched
  by branch prefix, branch deleted) right after the new one opens, the
  way `drift.yml` already did. Result: one open PR per kind instead of
  one per run — an untended fork had piled up 85 daily schema PRs.

### Fixed

- **Template-link fix wrote `alertRuleTemplateName: null` into every
  custom rule.** ARM returns the field as `null` on rules not built from
  a template; keeping the link now also kept the null, which added a
  meaningless line to ~200 rules on one fork and re-flagged all of them
  as changed in drift. Empty values are dropped; a real link is kept.
  Result: drift after the template-link fix only touches the rules that
  are actually template-bound.
- **Sentinel analytics lost their Content Hub template link.** For
  Scheduled, NRT and MicrosoftSecurityIncidentCreation rules,
  `collect` / `drift` dropped `alertRuleTemplateName` and
  `templateVersion` from the YAML (the code wrongly treated them as
  server-side audit fields), so the next deploy re-saved the rule
  without its template link and the portal stopped offering Content Hub
  updates for it — 18 rules on one deployment fork. Both fields now
  round-trip. A second bug hid behind it: apply strips `displayName`
  from template-bound bodies (the template owns it) but the verify hash
  still included it, so every template-bound rule reported
  `verified=False`. The hash for those rules now uses the template name
  in place of `displayName`, on both the sent and the read-back side;
  Fusion, MLBehaviorAnalytics and ThreatIntelligence are unchanged.
  Existing YAML for template-bound rules shows as "changed" once on the
  next `drift` / `collect` while the two fields are re-added — expected,
  and a one-time event. Result: template-bound rules keep their link
  and verify cleanly.
- **The durable state branch was never pushed, so the status page
  showed every rule as `unmanaged`.** apply / prune / rollback /
  retry-failed write `state/<env>/state.json` and `state sync push`
  pushes that file, but the workflows gated the push on the
  env-less `state/state.json`, which nothing writes — so the push was
  always skipped. `status-refresh.yml` never pulled state either, and
  `status` read `state/state.json` by default. The workflows now gate
  on `state/*/state.json`, `status-refresh.yml` pulls the state branch
  first, and `status deployments` / `status all` default `--env` to
  tenant.yml's `name` like `state sync` does. `state sync push` also
  exits 1 when the network push fails (it used to report
  `pushed_remote=False` and exit 0) and falls back to a bot committer
  identity on runners with no git identity. `undeployed-rules` uses the
  same default as `status`. The integration lane
  (`promote-to-integration.yml`) deliberately still does not push: state
  is keyed by tenant name, not role, so on a single-tenant.yml
  deployment it would mark integration-only rules managed in prod.
  Result: state advances
  after every deploy and the status page reflects it; run
  `state adopt` once to backfill rules deployed before the fix.
- **FP-rate and incident counts were computed over incident rows, not
  incidents.** `SecurityIncident` logs one row per incident update
  (assignment, comment, closure), and the shared telemetry query
  counted raw rows: `incidents_30d` (the FP-rate denominator) was
  inflated by every update, and a false-positive incident counted once
  per row carrying that classification. The query behind `silent-rules`,
  `portfolio --with-telemetry` and the `lifecycle promote`
  `fp_rate_threshold` gate — and the incident count in `tuning preview`
  — now dedupes to the latest row per `IncidentNumber` first, the same
  `arg_max` pattern the alert-join query already used. Result: expect
  FP-rate, incident counts and portfolio numbers to change after
  upgrading — they now count each incident once and are correct; a gate
  verdict near the threshold may flip.
- **`collect` reported success when an asset kind failed to list, and
  `--clear` could wipe that kind.** A handler whose listing raised (a
  403 on one kind, a Graph outage) was printed as a warning and collect
  exited 0, so `collect.yml` opened a PR from a partial snapshot. With
  `--clear` it was worse: local YAML was deleted *before* listing, so
  the failing kind's files were wiped with nothing to replace them.
  Collect now lists first, clears only the kinds that listed
  successfully (which also keeps `--clear --asset K` to kind K), writes
  what it collected, and exits 2 if any kind failed — matching
  `contentops drift`. Result: a failed kind fails the job and its local
  files survive.
- **`lifecycle promote` passed its workspace gates when it could not
  authenticate.** A failed credential, token or workspace-id lookup was
  caught and reported as an `info:` line, leaving `live_test_pass` and
  `fp_rate_threshold` deferred, and `all_passed()` counts deferred gates
  as passed — so an expired `az login` promoted rules to `production`
  with neither gate run. A failed lookup now fails both gates with the
  error as the reason; deferral is reserved for an explicit
  `--no-workspace-query`, which behaves as before. Result: promote exits
  non-zero and writes nothing unless the gates actually ran or the
  operator opted out (or used `--force`).
- **`rollback` bypassed apply's safety gates.** Rollback replayed the
  YAML at the target SHA straight into the handlers: it never checked
  tenant.yml `writeAllowed`, never ran the env-status filter, and PUT
  `{{...}}` snippet placeholders verbatim instead of resolving them from
  `overrides/`. It also read the `localCustomization` lock from the copy
  materialised at that SHA, so a rule locked since then was overwritten.
  Rollback now reuses apply's helpers for the write gate, the env-status
  and disabled-engine filters, and per-asset snippet substitution (plan
  and apply), and reads the lock from the current checkout. Dry-run
  still previews a write-locked workspace. Result: a rollback can only do
  what an `apply` of the same YAML would be allowed to do.
- **Defender apply could create duplicate custom detections.** Apply
  matched live rules by `displayName` only and ignored the Graph id
  collect records in `metadata.arm_name`, so editing a rule's
  `displayName` in YAML POSTed a second rule beside the original. Two
  YAMLs sharing a `displayName` both POSTed in the same run, because the
  name map was not updated after the first create. And the create POST
  went through the shared retry loop, so a 5xx or read timeout after
  Graph had already committed the rule replayed it. Apply now matches by
  `arm_name` first (when that rule still exists), falls back to
  `displayName`, records each created or renamed rule for the rest of the
  run, and `create_rule` retries only faults that prove the request was
  not processed (429, connection never established); GET, PATCH and
  DELETE keep the full retry policy. Result: a rename PATCHes the rule in
  place and one YAML never yields two live rules.
- **`collect` duplicated rules renamed in the portal.** Collect matched
  local files by the slug-derived `id` only, while `drift` matched by
  ARM name first. A portal rename changes the slug, so collect classified
  the rule as new and wrote a second file pointing at the same live rule
  (8 duplicates on one fork). Collect now uses drift's lookup — ARM name
  / Graph id first, then `id` — so a rename is a change to the existing
  file.
- **Portal renames changed a rule's `id` but not its file name.** Handlers
  derive `id` from the displayName, so renaming a rule in the portal made
  the drift re-import write a new `id` into the existing file (matched by
  ARM name), leaving `id` != file name — 8 rules on one fork after a
  prefix rename. The re-import now keeps the local `id`; the rename still
  lands through `displayName`.
- **Drift PRs with portal edits always failed the version-bump gate.**
  A drift re-import kept the operator's `version` (so it never rolls
  back a bump), but `check_version_bump.py` refuses a content change
  under an unchanged version — so every drift PR carrying a real portal
  edit went red. The re-import now patch-bumps (`1.0.6` -> `1.0.7`) when
  the envelope actually changed, using the same comparison as the gate
  (parsed YAML, `version` set aside); cosmetic-only re-imports keep the
  version. Result: drift PRs pass validation without hand-bumping.
- **Deploys that select no assets went red.** A push to `main` touching
  only detection READMEs, samples or templates triggers `deploy.yml`;
  `apply --changed-since` then selects 0 assets and returned before
  writing `--json-report`, so the post-deploy smoke step read the missing
  `apply-report.json` as "apply did not run to completion" and failed the
  run. `apply` now writes an empty report on that path. Result: docs-only
  pushes deploy nothing and stay green.
- **Defender custom detections: `status` and `description` (Graph removed
  `isEnabled` on 2026-10-01).** Graph beta replaced `isEnabled` with a
  `status` enum (`enabled` / `disabled` / `autoDisabled`) and added an
  authorable `description`. Collect copied both into YAML and the strict
  `DefenderPayload` rejected them, so every drift PR touching a Defender
  rule failed with `Extra inputs are not permitted`. The model now accepts
  both, apply sends `status` (never the removed `isEnabled`), deprecated
  envelopes deploy as `status: disabled`, and `autoDisabled` is left
  alone on apply so re-enabling stays a deliberate edit. Legacy
  `isEnabled` YAML still validates and is translated on the way out;
  `description` joins the verify hash only when authored, so older YAML
  keeps verifying against rules with a portal description. Result: drift
  PRs validate again and Defender deploys keep working past the API
  change. Shared logic lives in `contentops/defender/rule_status.py`.
- **Failure alerts filed on the wrong repo.** In a job that adds an
  `upstream` git remote, `gh` resolves `upstream` first, so
  `notify-workflow-failure` searched, labelled and opened its issue on
  `SecM8/ContentOps` and failed with `could not add label:
  'pipeline-alert' not found`. The action now pins
  `GH_REPO: ${{ github.repository }}`, reports label errors as warnings
  instead of discarding them, and retries the issue unlabelled rather
  than losing the alert.
- **`alerts sync --date <old date>` deleted its own export.** The
  retention prune ran after the export and removed any explicitly
  requested day older than `ledgerRetentionDays`. Requested dates are
  now exempt from the prune in that run. The matching test used a
  hard-coded date and started failing once that date aged out of the
  window; it is now relative to today.
- **`deploy.yml` post-deploy verify ran on dry runs.** The step compared
  the boolean `inputs.dry_run` with the string `'true'`, which is always
  unequal. It now uses `!inputs.dry_run`.
- **`test_render_uses_repo_relative_paths` failed on real deployment
  content.** It asserted that no `C:` appeared anywhere in a rendered
  detection page, which trips on KQL such as
  `@"C:\Program Files\..."`. It now checks only the `source` row, which
  is what it is meant to guard.
- **Defender custom detections: no-op unchanged rules instead of force-PATCHing.**
  `apply()` used to PATCH every existing Defender rule on every deploy. With no
  `state/` branch (the deployment-fork norm) that re-pushes all rules, and
  Microsoft's tightened beta `detectionRules` save-validator now 400s the
  *re-save* of rules that run fine but use patterns like `invoke FileProfile()`
  (the query is unchanged; only the API got stricter). The handler now GETs the
  live rule and compares with the same canonicalisation the post-apply verify
  uses (`_strip_server_fields` + `_HASHED_FIELDS`); if content **and** enabled
  state match, it returns `NOOP` and skips the push. Result: collected,
  unchanged rules are never re-pushed (no 400), deploys are idempotent, and
  beta-API writes drop sharply. Enable/disable still pushes (`isEnabled` is not
  in the content hash, so it is checked explicitly).

## [1.0.0] - 2026-06-16

First production release. The package version moves from `0.1.0` to `1.0.0`
now that the pipeline runs against production tenants. From here, the public
CLI surface, `tenant.yml` schema, asset taxonomy, and audit format follow
[Semantic Versioning](https://semver.org/): breaking changes bump the major
and ship with a migration note in this file. The accumulated changes below
are the 1.0.0 baseline.

### Security

- **Detection-inventory report telemetry removed from the public mirror.**
  `reports/latest.*` was in the public-mirror sync allowlist, so the
  detailed report, which carries live per-detection operational telemetry
  (display names, alert/incident counts, TP/FP %, MTTR), was being
  published to `SecM8/ContentOps`. The sync allowlist now ships **only**
  `reports/badge.json` (an anonymous coverage % that still feeds the README
  badge), and `public-sync.yml`'s forbidden-paths check asserts
  `reports/unified.html` + `reports/*-findings.md` never reach the mirror,
  so the next `public-sync` drops the telemetry from the mirror tree. The
  **mirror allowlist is the boundary**: reports themselves remain normal
  versioned content (not gitignored), so a private deployment keeps a
  durable posture history; only the one-way public sync is filtered. Note:
  dropping the files from the mirror stops future exposure, but they remain
  in git **history** on any repo they were already pushed to; a history
  rewrite is required to purge them there.
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

- **Committed report history + `reports.retentionDays` retention.**
  `reports/` is normal versioned content (no longer gitignored), so
  `report.yml` commits the regenerated detection-inventory report on
  push-to-main — a deployment gets a durable, diffable posture history out
  of the box. The new optional `reports:` block in `tenant.yml`
  (`retentionDays`, default 365, range 0..3650; 0 disables) bounds the
  committed dated snapshots: `contentops report` prunes
  `reports/<YYYY-MM-DD>.{html,json}` older than the window each run (CLI
  override `--retention-days`; `report.yml` materialises `tenant.yml` from
  `TENANT_CONFIG_YAML` so the prune fires in CI). Per-detection telemetry
  is kept off the public mirror by the sync allowlist, not gitignore (see
  the Security note above). `config/tenant.yml.example` now documents the
  `alerts:` retention settings (`ledgerRetentionDays` / `rollupRetentionDays`
  + lookbacks) and the new `reports:` block, which the template previously
  omitted. Guide: `docs/operations/durable-reports.md`.
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

- **Source/deployment split — real detections no longer live in the
  source repo.** The operator repo (`→` public mirror) was doubling as a
  tenant deployment, carrying ~155 real per-tenant detection YAMLs plus
  reports. Those are removed: the source now ships only
  `detections/samples/`, `detections/templates/`, the per-kind READMEs,
  and the empty `drift_suppressions.yml`. Real detection content now
  lives in **private deployment forks** (one per tenant), each populated
  by `collect` against its own tenant — so no tenant detection content
  sits in, or syncs from, the public repo. `detections/<kind>/*.yml` are
  **not** gitignored (the reverted PR #183 pattern is not reintroduced);
  the source simply carries none. CLAUDE.md invariant #11 rewritten to
  document the new topology. The `.gitignore` is unchanged — it is the
  *deployment template* every fork inherits via the mirror, so its
  tenant-data-hygiene rules (`config/tenant.yml`, `audit/`, `state/`,
  `alerts-reports/`, the report-telemetry block) must stay or downstream
  forks would leak.
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
