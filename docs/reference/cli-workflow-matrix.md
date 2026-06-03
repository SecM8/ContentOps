# CLI ↔ workflow parity matrix

Every operation reachable from `contentops.cli` has a GitHub Actions
workflow that wraps it (or is documented as local-only). This is the
single source of truth for "what's automatable."

> **Authoritative mapping:** the complete, code-derived CLI↔workflow
> mapping is the "Command traceability (Action → Function → Script →
> Workflow)" matrix in
> [`generated-catalog.md`](generated-catalog.md), which is regenerated
> from code and drift-gated in CI. This page is curated narrative and
> may not list every command.

## Mapping

| CLI command | Workflow file | Trigger | Notes |
|---|---|---|---|
| `contentops plan` | `validate.yml` | PR | Enforces dependency graph + lint at merge gate. The `--against-tenant` flag is local-only (closes G17 — apply-side CREATE/UPDATE/NO-CHANGE/ORPHAN preview against the live workspace). |
| `contentops apply` (prod) | `deploy.yml` | push to main (skipped on `chore(collect\|drift):` and bot commits) + manual | Uses `--changed-since`; `--role prod`; uploads audit JSONL artefact. Subscription resolved from `config/tenant.yml`, not `vars.AZURE_SUBSCRIPTION_ID`. |
| `contentops apply` (integration) | `integration-deploy.yml` | PR on `detections/**` + manual | `--role integration --continue-on-error`. No-ops when no integration workspace exists. Dispatch defaults to dry-run. `--role test` available for dedicated-test workspaces (G21). |
| `contentops drift` | `drift.yml` | daily 06:00 UTC + PR on `detections/**` + manual | Scheduled: auto-PR via peter-evans/create-pull-request@v6. PR mode: informational comment via `gh pr comment` (no auto-PR). |
| `contentops drift-pr-body` | (internal helper) | n/a | Called from `drift.yml` scheduled mode, not exposed as a top-level workflow. |
| `contentops drift-resolve` | _none — purely local_ | n/a | Per-rule reconciliation (`--strategy git\|remote\|merge`). |
| `contentops collect` | `collect.yml` | weekly Mon 06:00 UTC + manual | Supports `role`, `full`, `since`, `workers` inputs; opens PR with snapshot diff. Allowlist auto-sync step runs between collect and tree-change detection. |
| `contentops clean` | _none — purely local_ | n/a | Destructive — wipes local detection YAMLs. Pairs with `collect --clear`. |
| `contentops prune` | `prune.yml` | manual only | Environment-protected; defaults to dry-run; audit artefact uploaded. |
| `contentops bootstrap` | (called from `promote-to-integration.yml`) | manual | Idempotent first-run setup for a new env. |
| `contentops lock` / `contentops unlock` | `lock-unlock.yml` | manual | Mutates YAML on disk → opens a PR for review. |
| `contentops retry-failed` | `retry-failed.yml` | manual | Re-applies failed audit records; dry-run option. |
| `contentops disable` | `emergency-disable.yml` | manual | Gated, breakglass workflow. |
| `contentops enable` | _none — purely local_ | n/a | Inverse of `disable`; selectors mirror `disable` (positional id, `--pattern`, `--cohort`). |
| `contentops portfolio` | `portfolio.yml` | nightly + manual | Renders CSV + JSON; uploaded as artefact. With `--with-telemetry`: F20 columns from LA workspace. |
| `contentops coverage` | `coverage.yml` | PR (paths `detections/`, `contentops/`) + manual | Renders MITRE ATT&CK heatmap; posts sticky PR comment + uploads JSON artefact. `--d3fend` flag (local-only) renders the defensive-axis MITRE D3FEND companion report. |
| `contentops lint` | `validate.yml` | PR + push to main + nightly + manual | Standalone KQL + envelope lint. Runs in the `validate` + `lint-regression` jobs; passes `--strict` on PRs (KQL101 policy rule + optional Kusto.Language wrapper). |
| `contentops test --live` | `integration.yml` | label `run-integration` + manual | Hits the live tenant; gated to avoid accidental prod runs. Full runbook: [`docs/development/live-integration-tests.md`](../development/live-integration-tests.md). |
| `contentops audit verify` | `audit-verify.yml` | weekly Mon 04:00 UTC + on-PR-touching-audit/ + manual | Hash-chain integrity check. |
| `contentops audit query` | _none — purely local_ | n/a | Read-only forensic queries (`latest`, `failures`, `by-actor`, `rollbacks`, `timeline`). |
| `contentops explain` | _none — purely local_ | n/a | Single-rule context: envelope + dependencies + state + recent audit + drift. |
| `contentops silent-rules` | `silent-rules.yml` | weekly Mon 07:00 UTC + manual | Reports rules with zero alerts/incidents in the lookback window (F4). |
| `contentops auto-disabled-rules` | `silent-rules.yml` (same workflow, sequence step) | weekly Mon 07:00 UTC + manual | NVISO Part 7. Surfaces rules Sentinel auto-disabled (`SentinelHealth.Status in ("Disabled","Failure")`) and rules with recent query failures (`LAQueryLogs`). Prerequisite: SentinelHealth diagnostic enabled (probed by `contentops doctor --auth`). |
| `contentops tuning preview` | `tuning-impact-preview.yml` | PR on `detections/drift_suppressions.yml` | NVISO Part 8. Posts/updates a PR comment with 30-day blast-radius for each new suppression entry. Fork-PR safe (`--no-workspace-query` falls back to dashes). |
| `contentops navigator` | _none — purely local / on-demand_ | n/a | Renders MITRE ATT&CK Navigator layer JSON across three axes (repo + deployed + firings). Upload to https://mitre-attack.github.io/attack-navigator/. |
| `contentops detection-docs regenerate / check` | _none — local; CI gate inside the pytest suite_ | n/a | NVISO Part 4. Per-detection markdown pages under `docs/detections/<asset>/<id>.md`. Byte-identical drift gate (test `test_committed_detection_docs_are_in_sync`). |
| `contentops restore` | _none — purely local_ | n/a | DR inverse of `contentops collect`. |
| `contentops snapshot-diff` | _none — purely local_ | n/a | Content-aware diff between two collect archives. |
| `contentops rollback` | _none — purely local_ | n/a | Replays the YAML at SHA against the tenant. Defaults dry-run. |
| `contentops lifecycle promote` | _none — purely local_ | n/a | Promote `experimental` → `production` after gates pass. |
| `contentops state sync` (push/pull/status) | _called from workflows that need state_ | n/a | Orphan-branch `refs/heads/state/<env>` convention. |
| `contentops state show` / `state forget` | _none — purely local_ | n/a | State file inspection / surgical drop. |
| `contentops defender-extensions-probe` | `defender-graph-probe.yml` | weekly Tue 06:00 UTC + manual | Secondary-signal probe of three Defender Graph endpoints (savedQueries / detection-tuning / alert-suppression). Exits 2 (workflow red) when an endpoint GAs. |
| `contentops defender-roundtrip-diff` | _none — purely local_ | n/a | Diagnostic for `verified=False` on a Defender rule. Read-only. |
| `contentops sentinel-roundtrip-diff` | _none — purely local_ | n/a | Sentinel counterpart to `defender-roundtrip-diff`. |
| `contentops new` | _none — purely local_ | n/a | Scaffolds files; no remote interaction. |
| `contentops doctor` | _none — purely local_ | n/a | Diagnostic; runs as a step in CI smoke (`ci.yml`). With `--auth`: hits tenant for token / workspace / SentinelHealth / Graph probes. |
| `contentops test` (no `--live`) | `ci.yml` | PR + push to main | Unit suite. |
| `contentops conformance` | `conformance.yml` | weekly Mon 05:00 UTC + manual | Layered install / tenant / RBAC / Graph / GitHub conformance report (scope `L1..L7`). |
| `contentops report` | `report.yml` | weekly Mon 08:00 UTC + push to main (detection/report paths) + manual | Regenerates the detection inventory / portfolio report and commits the refreshed snapshot. |
| `contentops status configuration` / `deployments` / `all` | `status-refresh.yml` | daily 04:00 UTC + manual | Renders the `docs/status/` dashboard markdown; `all` runs both pages (what the cron invokes). |
| `contentops config validate` / `list-workspaces` | _none — purely local_ | n/a | Read-only tenant-config inspection. Both `--help` paths smoke-tested in `ci.yml`. |
| `contentops catalog regenerate` / `check` | _none — purely local_ | n/a | Regenerates `docs/reference/generated-catalog.md`; `catalog check` is the drift gate in `ci.yml`. |
| `contentops rule-test` | _none — purely local_ | n/a | Retrospective LA-query rule test (F2 live path). |
| `contentops alerts` (`sync` / `rollup` / `health` / `collect` / `report`) | `alerts-report.yml` | daily 07:00 UTC + manual | Maintains the alert ledger and renders rollup + detection-health reports; cron runs `sync` → `rollup` → `health`. |
| _(script)_ `scripts/check_references.py` | `references-check.yml` (full corpus, Saturdays 06:00 UTC) + `validate.yml` (added URLs only, PR-time) | weekly + PR | NVISO Part 3. HEAD-checks URLs in `metadata.references[]` + `runbookUrl`. PR-time variant uses `--diff-base` to walk only added URLs. |
| _(tool)_ `codespell` | `spelling.yml` | PR on prose paths | NVISO Part 3. Catches typos in author-controlled prose. Config: `.codespellrc`. |

## Promote / multi-env workflows

| Workflow | Purpose |
|---|---|
| `promote-to-integration.yml` | Manual `bootstrap` → `collect` (prod) → `rewrite` → `apply` (integration) chain. Confirmation gate `confirm == 'PROMOTE'`. |
| `production-promotion-check.yml` | Asserts no analytic rule is being promoted to `production` without the right metadata flags. |
| `release.yml` | On `v*` tag push: build sdist tarball, render changelog, create GitHub Release. |

## Workflow conventions

Every destructive workflow follows these rules (verified by
`docs/operations/prune.md` and the `lock-unlock.yml` /
`retry-failed.yml` review):

1. **OIDC** for Azure auth; `azure/login@<sha>` pinned by full SHA.
2. **`environment:` input** so the GitHub Environment matches the
   tenant slug — production gets reviewer-gated approval.
3. **Dry-run default** for any workflow that can mutate state.
   `contentops prune` and `promote-to-integration` both default to
   dry-run.
4. **Audit artefact upload** on every workflow that writes records:
   `actions/upload-artifact@<sha>`, 90-day retention.
5. **Structured `$GITHUB_STEP_SUMMARY`** with the inputs used and
   the result.
6. **`concurrency:` group** on env-scoped workflows so two
   simultaneous runs against the same tenant queue rather than race.

## Local-only commands (never automated)

| Command | Why no workflow |
|---|---|
| `contentops new` | File-system scaffold; analyst-driven. |
| `contentops doctor` | Diagnostic-only; embedded in `ci.yml` as a smoke step. |
| `contentops audit query` | Read-only forensic; CI gate is on `audit verify`, not on queries. |
| `contentops explain` | Local context surface; not automatable. |
| `contentops clean` | Destructive local-state operation; analyst-driven. |
| `contentops drift-resolve` | Per-rule reconciliation with strategy choice — requires operator judgment. |
| `contentops defender-roundtrip-diff` | One-off diagnostic for MISMATCH triage. |
| `contentops sentinel-roundtrip-diff` | One-off diagnostic for MISMATCH triage on Sentinel rules. |
| `contentops rollback` | Defaults dry-run; requires operator + `--yes` to actually mutate. |
| `contentops navigator` | Operator-triggered layer generation; output uploaded to the hosted Navigator UI. Could be wired to a scheduled cron if a SOC dashboard wants periodic refreshes. |
| `contentops detection-docs regenerate` | Run alongside `catalog regenerate`; the drift gate inside pytest catches forgotten regens. |

## How to add a new operation

When you add a new CLI subcommand, this matrix is the contract:

1. Decide whether it has a remote side effect.
2. If yes: add a workflow under `.github/workflows/<command>.yml`
   following the conventions above. Pin every action to a SHA.
3. If no: add it to the "Local-only commands" table here with a
   reason.
4. Update this document. CI doesn't enforce the matrix today, but
   keeping it in sync is a code-review expectation.
