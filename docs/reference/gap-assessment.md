# Gap assessment

> Honest review of what the pipeline does NOT yet do. Every gap is
> evidence-backed against `main` as of this PR. Severity reflects
> operational impact, not implementation difficulty.

Read this with [`roadmap.md`](roadmap.md) — every gap below has at
least one proposed feature in the roadmap that closes it.

---

## Severity legend

- **Critical** — pipeline cannot do something it claims to do, or a
  failure mode is unbounded.
- **High** — workaround exists but is slow / risky / hard to do
  under pressure (e.g. during incident response).
- **Medium** — operational papercut. Forces analyst toil; doesn't
  block the workflow.
- **Low** — a clear improvement but not load-bearing today.

## Effort legend

- **S** — under 1 day for a competent engineer who knows the codebase.
- **M** — 1–3 days.
- **L** — more than 3 days; usually because of an external API
  dependency, design ambiguity, or test fixture lift.

---

## Top three (worst gaps, ranked)

1. ~~**G6 — No emergency rollback command.**~~ **Resolved.**
   `contentops rollback <sha>` now materialises `detections/` at SHA
   via `git ls-tree` + `git show`, validates + applies against the
   temp tree, and writes audit records with `message="rollback to
   <sha>"`. Defaults dry-run; honours locks; non-destructive. See
   the row in the full table.

2. ~~**G2 — 46 defender_custom_detection report `changed` in drift,
   uncovered.**~~ **Resolved (twice — drift + apply-verify).** Root
   cause was a server-field stripping divergence between v1 collect
   and v2 handler (`detectorId`, `lastRunDetails`, nested timestamps).
   The drift symptom was fixed by bringing
   `DefenderCustomDetectionHandler.to_envelope` in line with
   `contentops.defender.collect`. A *separate* MISMATCH symptom (every
   Defender rule reported `verified=False` post-apply) was traced
   to the same divergence on the apply-verify side: post-PUT GET
   returned `schedule.nextRunDateTime` which the local body never
   carried. Fixed by extracting `_strip_server_fields` and applying
   it symmetrically at both `to_envelope` (collect) AND apply-verify
   time. The `contentops defender-roundtrip-diff` diagnostic was
   shipped during the investigation and pinned the root cause on
   first run; the regression is now covered by
   `tests/v2/test_apply_verify_defender.py::test_apply_verifies_when_remote_has_server_managed_nested_fields`.

3. **G1 — KQL lint is regex-based, not a real parser. RESOLVED.**
   Closed in layers (see the G1 row in the full table for detail):
   (1) F1's Python policy rules under `--strict` (KQL101 in
   [`contentops/lint/strict_rules.py`](../../contentops/lint/strict_rules.py)
   catches `| take` / `| limit`); (2) Kusto.Language parser
   diagnostics via the C# wrapper at
   [`tools/kql_strict/`](../../tools/kql_strict/), invoked from
   [`contentops/lint/strict.py`](../../contentops/lint/strict.py); and
   (3) F1.1 schema loading so KS-series findings reflect the real
   Sentinel + Defender XDR table surface. Wrapper findings ship at
   `warning` severity by default (`KQL_STRICT_PROMOTE_SEVERITY=1`
   promotes them once the nightly schema baseline is filled in). The
   "undefined column / wrong table" case no longer depends solely on
   the apply-time ARM 400.

**As of 2026-05-22**, G17 and G21 have also been resolved (PR #239),
and G25/G26/G27 (operational gaps from PR #237's NVISO borrowings)
were captured + closed in the same sprint. **As of 2026-05-25**,
G28/G29/G30 (alert-performance tracking, per-detection health
recommendations, and unified multi-audience reporting) have been
resolved by the F21/F22/F23 alert-tracking features. **The only
currently-open engineering gap is G5** (Defender Graph extensions --
blocked on Microsoft GA), plus the **G24** content-authoring backlog
(human writing work, not engineering).

The remaining gaps below are real but lower-priority.

---

## Full gap table

| Gap | Severity | Evidence | Workaround today | Effort |
|---|---|---|---|---|
| **G1** KQL static lint is regex-based, not parser-based — **RESOLVED** | High → resolved | Closed in two layers + schema loading: (1) Python policy rules under `--strict` (KQL101 in [`contentops/lint/strict_rules.py`](../../contentops/lint/strict_rules.py) catches `\| take` / `\| limit`); (2) Kusto.Language parser diagnostics via the C# wrapper at [`tools/kql_strict/`](../../tools/kql_strict/), invoked from [`contentops/lint/strict.py`](../../contentops/lint/strict.py); (3) **F1.1 schema loading**: wrapper now reads [`tools/kql_strict/schemas.json`](../../tools/kql_strict/schemas.json) at startup and builds a `Kusto.Language.GlobalState.WithDatabase(...)` with the committed Sentinel + Defender XDR table surface so KS204 / KS142 reflect real schema-bound issues. The schemas baseline is refreshed nightly from `/v1/workspaces/<id>/metadata` by [`kql-schemas-refresh.yml`](../../.github/workflows/kql-schemas-refresh.yml) (opens a PR on drift) and on-demand via `contentops upstream check-schemas --write`. Wrapper findings ship at `warning` severity by default; setting `KQL_STRICT_PROMOTE_SEVERITY=1` in the lint workflows promotes them to the upstream `Diagnostic.Severity` (typically `error`) — recommended flip after the nightly workflow has filled out the baseline against the live tenant. Wrapper gracefully degrades to no-schema mode if `schemas.json` is missing / malformed. | n/a (resolved) | M actual; closed across PRs #224 + the F1.1 PR. |
| **G2** 46 defender_custom_detection reports CHANGED in drift, never reconciled — **RESOLVED** | High → resolved | `drift-report.json` (2026-05-06): `defender_custom_detection: total=46 changed=46`. Root cause: `DefenderCustomDetectionHandler._SERVER_FIELDS` in [`contentops/handlers/defender_custom_detection.py`](../../contentops/handlers/defender_custom_detection.py) was missing `detectorId` and `lastRunDetails`, and lacked the nested-strip logic v1's [`contentops/defender/collect.py`](../../contentops/defender/collect.py) had for `queryCondition.lastModifiedDateTime` and `schedule.nextRunDateTime`. Local YAMLs were collected via v1 (which strips them); v2 drift kept them, so every rule diffed. Fixed in this PR: extended `_SERVER_FIELDS` + added `_SERVER_NESTED_FIELDS`. Regression covered by `test_defender_to_envelope_strips_g2_server_fields` and `test_defender_drift_clean_after_g2_fix` in [`tests/v2/test_drift_roundtrip.py`](../../tests/v2/test_drift_roundtrip.py). | n/a (resolved) | S (was estimated M; actual fix was 4 lines in `_SERVER_FIELDS` + 6 lines for nested strip + 2 tests). |
| **G3** Marketplace catalog upstream-watcher deferred — **RESOLVED** | Medium → resolved | Closed by `contentops upstream check-marketplace` + the scheduled [`upstream-watchers.yml`](../../.github/workflows/upstream-watchers.yml) workflow (Mondays 07:00 UTC). The CLI diffs Sentinel's `contentPackages` ARM resource against the committed baseline at `manifests/upstream_marketplace.json` and writes `docs/whats-new/<YYYY-MM-DD>.md` when a change is detected; the workflow then opens a PR via `peter-evans/create-pull-request`. Implementation: [`contentops/upstream/marketplace.py`](../../contentops/upstream/marketplace.py) (fetch + normalise), [`contentops/upstream/manifest.py`](../../contentops/upstream/manifest.py) (diff core), [`contentops/cli/commands/upstream.py`](../../contentops/cli/commands/upstream.py) (CLI). Tests under `tests/v2/test_upstream_*.py`. Revives the F7 plumbing that was removed in Phase 1E, scoped tighter (watcher-only; no auto-install). | n/a (resolved) | M actual. |
| **G4** Templates catalog upstream-watcher deferred — **RESOLVED** | Medium → resolved | Closed by `contentops upstream check-templates` + the same [`upstream-watchers.yml`](../../.github/workflows/upstream-watchers.yml) workflow as G3. Reuses the manifest-diff machinery; baseline at `manifests/upstream_templates.json`. Implementation: [`contentops/upstream/templates.py`](../../contentops/upstream/templates.py) (fetch + normalise via `provider.list_resource("alertRuleTemplates")`, the same call `contentops new --search-template` uses for on-demand lookup). | n/a (resolved) | S actual — shared plumbing with G3. |
| **G5** Defender Graph extensions deferred | Medium | [`docs/assets/defender_graph_extensions_deferred.md`](../assets/defender_graph_extensions_deferred.md) explicitly: savedQueries, detection-tuning rules, alert suppression — endpoints not GA. No handler files for these under [`contentops/handlers/`](../../contentops/handlers/). | Manage in portal. | L (gated on Microsoft shipping the endpoints; we own only the re-probe logic). |
| **G6** No emergency rollback command — **RESOLVED** | High → resolved | Closed by F3 in this PR. `contentops rollback <sha>` now materialises `detections/` at SHA via `git ls-tree` + `git show`, validates and applies against a temp tree, and writes audit records with `message="rollback to <sha>"`. Implementation: [`contentops/rollback.py`](../../contentops/rollback.py), CLI in [`contentops/cli/commands/rollback.py`](../../contentops/cli/commands/rollback.py) (`rollback_cmd`), 13 tests in [`tests/v2/test_rollback.py`](../../tests/v2/test_rollback.py). Defaults dry-run; honours `localCustomization: true` locks; non-destructive (assets that exist today but not at SHA are left alone — run `prune` for full reset). | n/a (resolved) | M actual; the design sketch was accurate. |
| **G7** No silent-rule detection — **RESOLVED** | Medium → resolved | Closed by F4. `contentops silent-rules` queries the workspace's `SecurityAlert` + `SecurityIncident` tables and surfaces per-rule counts with a configurable `--since` lookback (default 30d). Implementation: [`contentops/cli/commands/silent_rules.py`](../../contentops/cli/commands/silent_rules.py) (docstring: "Closes G7."), registered in [`contentops/cli/__init__.py`](../../contentops/cli/__init__.py), backed by [`contentops/workspace_kql.py`](../../contentops/workspace_kql.py) — the Log Analytics Query API bootstrap this row's effort estimate flagged as the missing dependency. Scheduled in [`.github/workflows/silent-rules.yml`](../../.github/workflows/silent-rules.yml). Tests: [`tests/v2/test_workspace_kql.py`](../../tests/v2/test_workspace_kql.py) covers the KQL helper; [`tests/v2/test_workflow_state_and_telemetry.py`](../../tests/v2/test_workflow_state_and_telemetry.py) covers the workflow path. | n/a (resolved) | M actual; estimate matched. |
| **G8** No analytic test harness — **RESOLVED (live path)** | Medium → resolved | `contentops rule-test` ships ([`contentops/cli/commands/rule_test.py`](../../contentops/cli/commands/rule_test.py)): it runs the envelope's KQL against historical telemetry via the Log Analytics Query API (the F4 `workspace_kql` helper) and asserts the returned row count falls in an expected band (`--expect-min` / `--expect-max`). This is the **retrospective** path — never the Python KQL evaluator originally proposed. It is now also wired into `lifecycle promote` as the `live_test_pass` gate (see G13). Still open: the offline **CSV-fixture** path. | (resolved for the live path) | S remaining (optional CSV authoring). |
| **G9** No cost/quota awareness — **OUT OF SCOPE** | n/a | Cost in this org is driven by **ingest**, not by detection rules. Detection KQL reads data that's already been paid for at ingest time, so a per-rule "GB scanned" estimate is the wrong abstraction (would mislead operators into tuning detections to lower a bill that won't actually move). The historical cost-heuristic lint rule (and the whole supporting module) was removed for the same reason in PR #234. F5 (`pipeline cost`) is **rejected** — see [`roadmap.md`](roadmap.md#f5--pipeline-cost--rejected). Cost optimisation belongs in a separate ingest-side workflow. | n/a (out of scope) | n/a |
| **G10** No drift-resolution UX — **RESOLVED (partial)** | Medium → resolved | `contentops drift-resolve <id> --strategy {git\|remote}` ships; `--strategy merge` raises `NotImplementedStrategy` by design — operators pick `git` or `remote` per rule. Implementation: [`contentops/drift_resolve.py`](../../contentops/drift_resolve.py); tests in [`tests/v2/test_drift_resolve.py`](../../tests/v2/test_drift_resolve.py). | n/a (resolved) | M actual. |
| **G11** Pipeline-deployed envelopes still carry `id: sentinel-<guid>` — **RESOLVED** | Low → resolved | All 101 envelopes under `detections/sentinel_analytic/` now carry slug-based ids (e.g. `a-user-added-an-account-to-a-privileged-role`) — `grep -c '^id: sentinel-[0-9a-f]\{8\}-' detections/sentinel_analytic/*.yml` returns 0. The slugified-id transition is complete. `metadata.arm_name` preserves the original ARM resource GUID ([`contentops/handlers/sentinel_analytic.py:304`](../../contentops/handlers/sentinel_analytic.py)) so apply and prune still address the right remote resource without leaking provenance into the user-facing envelope id. The `contentops collect --rename-existing` flag at [`contentops/cli/commands/collect.py:82`](../../contentops/cli/commands/collect.py) performed the migration. | n/a (resolved) | S — already complete; no further work needed. |
| **G12** Operational/incident collection has no cap or archival path — **OBSOLETE** | n/a → obsolete | The seven operational asset kinds (incidents, incident tasks, watchlist items, four workspace-manager kinds), their handlers, the `OPERATIONAL_ASSETS` set, and the `--include-operational` opt-in flag were all deleted in the asset-taxonomy reduction (PR #122). Only 6 configuration kinds are managed today; there is no operational-data fan-out path to cap. | n/a (no longer applicable) | n/a |
| **G13** Lifecycle gate is implicit — **RESOLVED** | Medium → resolved | `status: experimental` is the only one that doesn't deploy ([`contentops/handlers/sentinel_analytic.py:117`](../../contentops/handlers/sentinel_analytic.py)). Closed by F8: `contentops lifecycle promote <id>` runs four gates — `status_is_experimental`, `recent_validation` (META001's source of truth), `live_test_pass`, and `fp_rate_threshold`. Both workspace-backed gates are **LIVE** when a workspace is set (`--role` / `--workspace-id` / `PIPELINE_WORKSPACE_ID`) and `--no-workspace-query` is unset: `live_test_pass` executes the rule's KQL via the LA Query API (the `rule-test` path) and `fp_rate_threshold` computes `closed_fp_30d / incidents_30d` against the threshold in [`config/lifecycle.yml`](../../config/lifecycle.yml). Both are **fail-closed** on workspace errors and stay `deferred` offline. Implementation: [`contentops/lifecycle.py`](../../contentops/lifecycle.py); CLI in [`contentops/cli/commands/lifecycle.py`](../../contentops/cli/commands/lifecycle.py); tests in [`tests/v2/test_lifecycle_promote.py`](../../tests/v2/test_lifecycle_promote.py). | Run `contentops lifecycle promote <id>` (or `--force` with reviewer approval recorded out-of-band). | S — done. |
| **G14** No content-coverage gap analysis vs MITRE — **RESOLVED** | Medium → resolved | Closed by F9. `contentops coverage --gaps` enumerates MITRE techniques NOT covered by any detection. Implementation: [`contentops/coverage/gaps.py`](../../contentops/coverage/gaps.py). The default reference is the **full** MITRE ATT&CK Enterprise matrix (222 parents + 475 sub-techniques) at [`contentops/coverage/data/mitre_attack_full.json`](../../contentops/coverage/data/mitre_attack_full.json), refreshed weekly from MITRE's maintained STIX (`mitre-attack/attack-stix-data`) by [`attack-matrix-refresh.yml`](../../.github/workflows/attack-matrix-refresh.yml) via [`scripts/refresh_attack_matrix.py`](../../scripts/refresh_attack_matrix.py); the generator normalises MITRE's non-Sentinel tactic short-names back to canonical `DefenseEvasion`, and [`tests/v2/test_attack_matrix_data.py`](../../tests/v2/test_attack_matrix_data.py) hard-fails CI on canonical-tactic drift. `--matrix-mode curated` selects the smaller high-value shortlist ([`mitre_attack_techniques.json`](../../contentops/coverage/data/mitre_attack_techniques.json)); `--techniques-file FILE` swaps in a custom list. Sub-techniques group under their parent in the markdown render. Tests in [`tests/v2/test_coverage_gaps.py`](../../tests/v2/test_coverage_gaps.py). | n/a (resolved) | S — implementation matched the design sketch; full-matrix default + weekly refresh added in Wave 5. |

## Additional gaps surfaced from reading the code

| Gap | Severity | Evidence | Effort |
|---|---|---|---|
| **G15** State file orphan-branch checkout not wired in any workflow — **RESOLVED** | Medium → resolved | The CLI (`contentops state sync push|pull|status`), module ([`contentops/state_sync.py`](../../contentops/state_sync.py)), and tests ([`tests/v2/test_state_sync.py`](../../tests/v2/test_state_sync.py)) were already in place when this gap was written; the missing piece was workflow-level wiring. Closed by F19 in [`roadmap.md`](roadmap.md): `deploy.yml` (prod), `promote-to-integration.yml` (integration), `prune.yml` and `retry-failed.yml` (per-env) now all call `state sync pull` before their mutation step and `state sync push` after (gated on non-dry-run). `integration-deploy.yml` deliberately skips state sync — it's a PR-time smoke test where per-PR state churn would be noise. | n/a (resolved) |
| **G16** Audit chain has no monotonic timestamp guarantee — **RESOLVED** | Low → resolved | Closed by `_monotonic_timestamp` in [`contentops/audit/writer.py:130`](../../contentops/audit/writer.py). Module docstring (lines 15-34) explicitly cites G16 and explains the contract: within a batch, `_chain_records` advances each timestamp to `max(record.timestamp, prev_timestamp + 1µs)`; across batches, `write_records` seeds the chain with the previous tail's timestamp; `verify_chain` enforces `current_timestamp >= prev_timestamp` so pre-bump records on disk still verify. CLAUDE.md invariant §9 ("Audit trail is hash-chained + monotonic") reflects this. | n/a (resolved) |
| **G17** No automated pre-flight diff against the live tenant on PR — **RESOLVED** | Medium → resolved | Closed by PR #239. `contentops plan --against-tenant` extends the plan command to also call `contentops.core.drift.detect_drift` and overlay an apply-side summary: **CREATE: N · UPDATE: M · NO-CHANGE: K · ORPHAN-IN-TENANT: J**. Drift's framing ("what's in tenant that's not in repo") is translated to apply-side verbs ("what would apply do"). Implementation: [`contentops/cli/commands/apply.py`](../../contentops/cli/commands/apply.py) (`plan_cmd` extended with `--against-tenant` flag + `_print_against_tenant_summary`); tests in [`tests/v2/test_plan_against_tenant.py`](../../tests/v2/test_plan_against_tenant.py) (4 tests). Default OFF so fork PRs / offline runs keep working; remote-list failures degrade to a banner without failing the command. The original PR-time piece was already covered operationally via the `drift-pr` job in `drift.yml`; this commit adds the sharper "apply preview" framing for operators running plan locally before merging. | n/a (resolved) | M actual; matched the design sketch. |
| **G18** No bulk-disable / cohort-disable command — **RESOLVED** | Medium → resolved | `contentops disable` ships with three selectors: positional `rule_id`, `--pattern <glob>` (envelope id glob), and `--cohort <name>` (exact match against `metadata.cohort`). The inverse `contentops enable` mirrors the same three selectors plus `--to {experimental,production,test}` (default `experimental` so re-promotion still goes through F8's gates). Both commands keep a symmetric audit trail in the YAML: disable writes `disableReason: "..."` (or a dated comment), enable strips that marker and writes `enableReason: "..."` (or its own dated comment). Implementation: [`contentops/cli/commands/lifecycle.py`](../../contentops/cli/commands/lifecycle.py) `disable_cmd` / `enable_cmd`. Tests: [`tests/v2/test_disable_pattern.py`](../../tests/v2/test_disable_pattern.py) (12 tests) + [`tests/v2/test_enable_pattern.py`](../../tests/v2/test_enable_pattern.py) (15 tests including a disable→enable round-trip). F14 (`retry-failed --since/--run-id`) covers the *recovery* side of the same papercut; this row covers the *cohort lifecycle* side. | n/a (resolved) | S — three-way selector + inverse + tests. |
| **G19** `metadata.lastValidatedAt` is read but not enforced — **RESOLVED** | Low → resolved | Closed by lint rule **META001** in [`contentops/lint/metadata_rules.py`](../../contentops/lint/metadata_rules.py) (lines 115-171), wired into the runner at [`contentops/lint/runner.py:168`](../../contentops/lint/runner.py). The rule emits a warning for missing `lastValidatedAt`, escalates to error on unparseable, and warns when the field is older than threshold (180 days default, 90 for `status: production`). Under `policy.scaffoldStrict=true` the staleness finding escalates to error so `validate.yml`'s `lint --strict` step blocks the PR. | n/a (resolved) |
| **G20** No telemetry-overlay on the portfolio report — **RESOLVED** | Medium → resolved | Closed by F20. `contentops portfolio --with-telemetry --workspace-id <id> --telemetry-since 30` adds four operational columns (`alerts_30d`, `incidents_30d`, `closed_fp_30d`, `fp_rate`) to the per-rule report. Implementation: [`contentops/cli/commands/portfolio.py`](../../contentops/cli/commands/portfolio.py) lines 21-156, sharing F4's workspace-KQL helper via `telemetry_query()` in [`contentops/workspace_kql.py`](../../contentops/workspace_kql.py) line 157. Tests: [`tests/v2/test_portfolio_telemetry.py`](../../tests/v2/test_portfolio_telemetry.py) (5 tests). Scheduled nightly via [`portfolio.yml`](../../.github/workflows/portfolio.yml); telemetry is opt-in via the `PIPELINE_WORKSPACE_ID` Actions variable so the workflow still runs in inputs-only mode when the variable is unset. The original sketch's fifth column (`est_gb_scanned_per_day`) was dropped because F5 is rejected — cost lever is on ingest, not detections. | n/a (resolved) |
| **G21** `experimental` → `test` lifecycle has no test workspace — **RESOLVED** | Low → resolved | Closed by PR #239. `WorkspaceRole` extended to include `test` ([`contentops/config.py`](../../contentops/config.py)); routing semantics differentiated in [`contentops/core/env_status.py`](../../contentops/core/env_status.py): `_DEDICATED_TEST_ALIASES = {"test"}` accepts only `{TEST, DEPRECATED}` (production envelopes do NOT spill into a dedicated test workspace — test workloads stay isolated from live prod); `_INTEGRATION_ALIASES = {"integration", "staging", "stage"}` keeps the historical `{TEST, PRODUCTION, DEPRECATED}` shared-lower-env behaviour. Every `--role` flag on the 13 affected CLI commands now accepts `test` alongside the three existing values. Tests: [`tests/v2/test_workspace_role_test.py`](../../tests/v2/test_workspace_role_test.py) (4 tests) + updated `tests/v2/test_env_status_filter.py` (split the dedicated-test semantic from integration). Operators who want isolated test deployments configure a workspace with `role: test`; operators who prefer the old shared-lower-env pattern continue to use `role: integration`. | n/a (resolved) | M actual. |
| **G22** No restore-from-export command (inverse of `contentops collect` archive) — **RESOLVED** | Medium → resolved | Closed by F10. `contentops restore <archive.tar.gz>` reads a collect snapshot (with optional `MANIFEST.json`) and restores `detections/<asset_kind>/*.yml` under `--out` (default `detections/`). Refuses to overlay a non-empty target without `--force`. Defends against path-traversal entries. Implementation: [`contentops/restore.py`](../../contentops/restore.py); CLI registered in [`contentops/cli/commands/archive.py`](../../contentops/cli/commands/archive.py) (`restore_cmd`). Tests: [`tests/v2/test_restore.py`](../../tests/v2/test_restore.py). | n/a (resolved) |
| **G23** No content-aware diff between two collect snapshots — **RESOLVED** | Low → resolved | Closed by F12. `contentops snapshot-diff <a.tar.gz> <b.tar.gz>` indexes envelopes by `(asset_kind, envelope_id)` and diffs payloads using the same per-handler hash projection the apply path uses, so file renames + reordering don't surface as noise. Output: per-asset list of created / updated / deleted / unchanged. Implementation: [`contentops/snapshot_diff.py`](../../contentops/snapshot_diff.py); CLI registered in [`contentops/cli/commands/archive.py`](../../contentops/cli/commands/archive.py) (`snapshot_diff_cmd`). Tests: [`tests/v2/test_snapshot_diff.py`](../../tests/v2/test_snapshot_diff.py). Pairs naturally with F10 (`restore`). | n/a (resolved) |
| **G24** Authoring-metadata backlog on collected production rules | Medium | 51 production detection envelopes (every file under `detections/`) lack the META002-005 authoring fields (`metadata.description`, `metadata.attackDescription`, `metadata.references`, `metadata.falsePositives`). Each fires as a WARNING under the lint policy. As of PR #241, `policy.scaffoldStrict` defaults to **False** (lenient) so adopters with a fresh `config/tenant.yml` aren't blocked by the backlog out of the box (see [[feedback_internal_fail_fast_public_smooth]]); the operator's own internal tenant.yml carries `scaffoldStrict: true` to keep the fail-fast posture on authored content. Closing this gap is human content authoring — one paragraph of `description`, one of `attackDescription`, at least one URL in `references`, at least one entry in `falsePositives` per rule. | L (51 rules × 4 fields; can't be synthesised meaningfully). |
| **G25** `auto-disabled-rules` silently returns 0 rows when SentinelHealth diagnostic is off — **RESOLVED** | Low → resolved | Closed by PR #239. `contentops doctor --auth` now runs `_check_sentinel_health()` at [`contentops/devex/doctor.py`](../../contentops/devex/doctor.py) which fires a `SentinelHealth \| take 1` probe against the prod workspace. PASS when rows exist; WARN with a doc link (https://learn.microsoft.com/en-us/azure/sentinel/health-audit) when zero rows are returned, distinguishing "all rules healthy" from "diagnostic not configured" without forcing the operator into the Azure portal. Tests: [`tests/v2/test_doctor_sentinel_health.py`](../../tests/v2/test_doctor_sentinel_health.py) (6 tests). | n/a (resolved) | S — one new check function + 6 tests. |
| **G26** Dead URLs in `references[]` only surfaced by weekly cron, not on the introducing PR — **RESOLVED** | Low → resolved | Closed by PR #239. [`scripts/check_references.py`](../../scripts/check_references.py) learned a `--diff-base REF` flag that walks only URLs newly added by the PR diff (via `git diff --name-only` + per-file before/after URL extraction). Wired into [`.github/workflows/validate.yml`](../../.github/workflows/validate.yml) as a fast PR step; the weekly full HEAD-check in `references-check.yml` stays as the safety net. Tests: [`tests/v2/test_check_references_diff.py`](../../tests/v2/test_check_references_diff.py) (5 tests). | n/a (resolved) | S. |
| **G27** Fork-PR contributors get degraded signal on `drift-pr` / `tuning-preview` / `validate.yml` schema refresh — **RESOLVED (doc)** | n/a → resolved | Closed by PR #239 (documentation). A new section in [`docs/onboarding.md`](../onboarding.md) titled "Contributing from a fork" documents which checks degrade on fork PRs (OIDC token unavailable), which still work (lint, tests, references URL check, structural plan), and the workaround (rebase into the base repo for full signal). Design is correct as-is; the gap was operator awareness. | n/a (resolved) | S — one doc section. |

| **G28** No alert-to-detection performance tracking — **RESOLVED** | Medium → resolved | Closed by F21. `contentops alerts sync` fetches alerts from Graph alerts_v2 (Defender, 30d lookback) and Sentinel ARM incidents (90d lookback) into a PII-free JSONL ledger with watermark-based incremental sync. Graph `detectorId` capture enables reliable alert-to-detection correlation via a four-tier matching strategy (ARM GUID, exact title, alert format prefix, substring containment). Upsert logic handles reclassifications (TP→FP, FP→TP) idempotently. Daily rollup store provides gap filling, idempotent rebuild, and version tracking. Config: `config/tenant.yml` `alerts:` block with `defenderLookbackDays`, `sentinelLookbackDays`, `ledgerRetentionDays`, `rollupRetentionDays`. | n/a (resolved) | M actual. |
| **G29** No per-detection health recommendations — **RESOLVED** | Medium → resolved | Closed by F21. `contentops alerts health` computes per-detection health with six recommendation categories: TUNE (FP rate > 40%), CLASSIFY (>50% unclassified alerts with >5 total alerts), SILENT (0 alerts in period), HEALTHY (TP rate > 80%), REVIEW (metrics outside normal thresholds), EXPECTED_SILENT (detection marked as expected-silent). Includes owner mapping via `config/owners.yml`, version tracking, and expected-vs-actual volume comparison. `--sync-owners` auto-populates the ownership file. | n/a (resolved) | M actual. |
| **G30** No unified multi-audience report — **RESOLVED** | Medium → resolved | Closed by F22. `contentops report --unified` renders a single self-contained HTML report for CEO (posture score), CISO (MITRE heatmap), SOC Manager (owner accountability matrix), Engineers (per-detection health + attention queue), and Hunters (silent/uncovered gaps). Consumes the detection health report, MITRE coverage data, and ownership mapping. | n/a (resolved) | M actual. |

---

## Gaps deliberately NOT pursued

These are not gaps in the same sense — the team has explicitly
chosen not to build them, and the choice is documented:

- **Multi-tenant fan-out.** Single-tenant model is fixed in
  [`CLAUDE.md`](../../CLAUDE.md) and load-bearing in
  [`contentops/config.py`](../../contentops/config.py). Any roadmap
  proposal must preserve it.
- **Replacement for the Sentinel UI for ad-hoc investigation.** The
  pipeline is a *configuration management* tool; live triage and
  investigation stay in the portal.
- **Workspace bootstrapping at scale.** `contentops bootstrap` does
  one workspace; orchestrating many is out of scope.
- **Playbook authoring.** Logic Apps Designer remains the source of
  truth for playbook *internals*; we manage deployment only.

---

## Validation

Every gap above passes the test "if I read the cited file or run
the cited command, the gap is observable." Where the citation is a
*line* rather than a file, the line still exists at the SHA this PR
is opened from. Reviewers: spot-check 3–5 entries against `main`
before approving.
