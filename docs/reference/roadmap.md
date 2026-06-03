# Roadmap

> Proposed features that close gaps from
> [`gap-assessment.md`](gap-assessment.md). Each entry is a design
> sketch, not an implementation plan — expect comments, push back,
> and reordering on review.
>
> **Single-tenant constraint preserved** throughout. None of these
> proposals require fan-out to a second tenant.

---

## Personas

Two role-based lanes drive prioritization. Every feature carries
one or both persona tags so the build queue can be ordered by who
benefits — not just by gap severity.

### Detection Engineer (DE)

The primary author of detection content. Lives in `contentops new`,
`contentops lint`, `contentops plan`, `contentops apply` every day; gets
paged when a deploy fails or drift fires; debugs why their rule
doesn't behave as expected.

Optimizes for:

- **Build/tune/debug speed** — short feedback loops, machine-readable
  output for scripted triage, fast recovery from partial failures.
- **Signal quality** — lint/plan should catch what *actually* breaks
  at apply time; drift should highlight *real* changes, not noise.
- **Triage context on demand** — one command should surface
  "everything I need to know about this rule right now."

### SOC Manager (SM)

Accountable for risk visibility, governance, audit posture, and
team-wide tooling consistency. Lives in `pipeline portfolio`,
`contentops coverage`, `audit/`; reads PR
diffs without writing rules; signs off on production promotions
and explains posture to compliance auditors.

Optimizes for:

- **Risk + compliance visibility** — coverage and exposure data
  rendered without writing KQL.
- **Governance over promotion** — evidence-backed gates between
  experimental → production.
- **Durable, consistent state** — same view across runners, no
  "works on my machine."
- **Auditability** — answers to "who did what, when" should be a
  one-liner, not a forensic project.

---

## Top picks per persona

### Detection Engineer top three

The DE list is ordered "what hurts during build/tune/debug today,
right now."

1. **F1 — `contentops lint --strict` (Kusto.Language).**
   Promotes lint from regex heuristics to a real parser. Catches
   undefined columns, wrong table references, malformed `let`
   blocks — bugs that today only surface as ARM 400 at apply
   time. Closes G1 (High). M effort, blocked on a CI runtime
   decision (.NET install).
2. **F13 — `contentops apply --json-report` ✅ shipped.** A
   structured JSON summary written to disk on every apply:
   per-asset action, status, error, audit pointer, hash-verify
   result. Lets DEs pipe the output through `jq` instead of parsing
   the human summary table. The same JSON becomes the contract that
   workflow steps and downstream tooling read. S effort.
3. **F15 — `contentops drift --suppressions`.** A
   `detections/drift_suppressions.yml` that names known-good
   drift entries with an expiry date, so daily drift PRs surface
   only *new* or *expired-suppression* changes. Closes the muscle
   memory failure where ops learn to ignore drift output. M effort.

### SOC Manager top three

The SM list is ordered "what hurts when explaining posture to a
compliance auditor or signing off on a production promotion."

1. **F18 — `contentops audit query` ✅ shipped.** Built-in CLI for
   the forensic queries that today require `jq` or PowerShell
   one-liners. Surfaces the most common "who/when/what" questions
   from [`audit-trail.md`](audit-trail.md) as named subcommands.
   S/M effort.
2. **F19 — `contentops state sync`.** Wires the orphan-branch
   state-file convention DESIGN §13 promised. Today every
   runner reads its build's local-disk copy; sync makes
   production state durable + visible across runners + auditable
   in git. Closes G15. M effort.
3. **F8 — `contentops lifecycle promote` + F20 portfolio telemetry
   overlay.** Listed together because they're co-dependent: F8
   gates `experimental → production` on evidence; F20 produces
   the evidence (fire-rate, FP-rate, cost). Closes G13 + G20.
   F20 is L effort (depends on workspace KQL access — same
   dependency as F2, F4, F5).

The remaining proposals close lower-severity gaps and are ordered
in the [phased delivery section](#phased-delivery) below.

---

## Phased delivery

The user-directed sequencing for this batch:

| Phase | Theme | Features | Persona(s) | Why this phase |
|-------|-------|----------|------------|----------------|
| **1 — Quick wins** ✅ all shipped | Machine-readable feedback + targeted recovery + first compliance affordance | **F13** (`apply --json-report`), **F14** (`retry-failed --since/--run-id`), **F18** (`audit query`) | DE × 2, SM × 1 | All S effort. No external dependencies. Each turns a multi-step manual loop into a one-liner. |
| **2 — Signal quality** | Make the noise stop, give analysts context | **F15** (`drift --suppressions`), **F16** (`explain <rule-id>`), **F17** (`doctor --fix`) | DE × 3 | M effort each. Compounds with Phase 1: now the JSON output that DEs script against carries less noise and more context. |
| **3 — Manager outcomes** ✅ all shipped | Evidence-backed governance | **F19** (`state sync`) ✅, **F20** (portfolio telemetry overlay) ✅, **F8** (lifecycle gates) ✅ | SM × 3 | F19 + F20 + F8 all shipped. F8 still carries one deferred gate (`live_test_pass`) because F2 itself is parked; the F20 `fp_rate_threshold` gate is live and runs when `PIPELINE_WORKSPACE_ID` is set. |

**Unphased** (now all shipped or partially shipped — see per-feature status banners): F1
(Python policy rules + Kusto.Language semantic wrapper, both wired into lint + validate),
F6 (drift-resolve — `merge` deferred), F7 (revived; watcher-only),
F10 (restore), F11 (Defender extensions probe — secondary signal), F12 (snapshot-diff),
F13 (`apply --json-report`), F14 (`retry-failed --since/--run-id`),
F18 (`audit query`), F19 (`state sync`).

**Removed from the queue:**
- **F2** — deferred to far-future backlog (see the F2 section).
- **F5** — rejected; cost optimisation belongs on the ingest side,
  not the detection side.

### Cluster dependencies

The shared workspace-KQL helper (`contentops.workspace_kql`) already
ships with F4 / F20 — anything new that needs to query a Log
Analytics workspace can build on it directly.

---

## Acceptance criteria by persona

How we'll know the persona-track is working. These are
*outcome* metrics, not feature-shipped checkmarks.

### Detection Engineer

- **Lower MTTR on failed deploys.** From "open a PR, look at the
  audit JSONL, eyeball the failure, hand-craft a retry list" to
  "`contentops retry-failed --run-id <id>`" → measurable in
  median time-to-redeploy after a transient ARM 5xx.
- **Less drift noise.** Daily drift PRs should average <5
  CHANGED entries (down from current ~50, weighted heavily by
  G2 which already shipped). F15 gets us the rest of the way.
- **Faster triage context.** "What does `<rule-id>` do, who owns
  it, what depends on it, when was it last applied?" is one
  command, not a slack thread.

### SOC Manager

- **Clearer risk + coverage visibility.** Quarterly coverage
  evidence is rendered by `contentops coverage --gaps` + the future
  telemetry overlay — without anyone writing KQL by hand. (The
  earlier framework-compliance loop, ``pipeline compliance``, was
  retired in PR #146.)
- **Better promotion governance.** Every `experimental →
  production` flip carries machine-readable evidence (live test
  result, N days at experimental, FP-rate threshold met).
  Audit trail proves it.
- **Stronger auditability.** "Who promoted rule X to production
  on date Y, with what evidence?" is a single `contentops audit
  query` invocation. Today it's a manual `jq` + `git log` join.

---

## Common shape

All commands listed below share a vocabulary already proven by the
existing CLI:

- Default to dry-run; require `--no-dry-run` (or equivalent) to
  mutate.
- Emit machine-readable output via `--json` / `--out-json`.
- Live under [`contentops/cli/commands/`](../../contentops/cli/commands/)
  (one module per command group, e.g. `apply.py`, `drift.py`,
  `lifecycle.py`).
- Always exit 0 if the command itself succeeded; non-zero only for
  hard errors or gating failures.
- Tests under `tests/v2/test_<feature>.py`; live tests (where
  applicable) under `tests/integration/` gated by
  `RUN_LIVE_TESTS=1`.

---

## F1 — `contentops lint --strict` ✅ shipped (Python policy + Kusto.Language wrapper + schema-loaded semantic gating) — DE

> **Status: fully shipped.** `contentops lint --strict` runs two
> layers, in order, with the F1.1 schema-loading follow-up landed:
>
> 1. **Python policy rules.** KQL101 (`| take` / `| limit` forbidden
>    in production rules) from
>    [`contentops/lint/strict_rules.py`](../../contentops/lint/strict_rules.py).
>    Always runs; never depends on .NET. Emits at error severity.
> 2. **Kusto.Language semantic checks.** C# wrapper at
>    [`tools/kql_strict/`](../../tools/kql_strict/) compiled to
>    `tools/kql_strict.dll`. Invoked by
>    [`contentops/lint/strict.py:run_strict`](../../contentops/lint/strict.py)
>    via `dotnet kql_strict.dll < file.kql`. Emits diagnostics in the
>    `<rule_id>\t<severity>\t<line>\t<message>` shape; upstream codes
>    (e.g. `KS204`, `KS142`) preserved.
>
> **F1.1 schema loading.** The wrapper now reads
> [`tools/kql_strict/schemas.json`](../../tools/kql_strict/schemas.json)
> at startup (copied next to the DLL by the csproj's `<Content>` item)
> and builds a `Kusto.Language.GlobalState.WithDatabase(...)` with the
> baked Sentinel + Defender XDR table surface. Findings ship at
> `warning` severity by default; set `KQL_STRICT_PROMOTE_SEVERITY=1`
> in the lint workflow env to promote findings to the upstream
> `Diagnostic.Severity` (recommended flip after the nightly workflow
> has filled out the baseline against the live tenant — until then,
> the hand-curated starter baseline may have gaps that would
> otherwise gate the lint pipeline on schema-resolution false
> positives).
>
> Schema refresh paths (covered in
> [`tools/kql_strict/README.md`](../../tools/kql_strict/README.md)):
> nightly cron via
> [`kql-schemas-refresh.yml`](../../.github/workflows/kql-schemas-refresh.yml),
> on-demand `gh workflow run`, or manual
> `contentops upstream check-schemas --write` locally. The source of
> truth is the LA Query API `/v1/workspaces/<id>/metadata` endpoint
> — single fetch returns both Sentinel built-ins and Defender XDR
> pseudo-tables (surfaced via the M365 Defender connector).
>
> If `schemas.json` is missing / empty / malformed the wrapper logs a
> stderr advisory and gracefully degrades to no-schema mode +
> warning-only severity — an absent or corrupt schema can't take the
> lint pipeline down.
>
> [`validate.yml`](../../.github/workflows/validate.yml) (both its
> load-bearing PR `validate` job and the `lint-regression` job that
> runs the lint on push-to-main / nightly / dispatch) runs
> `dotnet publish tools/kql_strict` before the lint step. Local devs
> run [`scripts/build_kql_strict.sh`](../../scripts/build_kql_strict.sh)
> (or `.ps1` on Windows) once and strict mode works end-to-end.
> Tests in [`tests/v2/test_lint_strict_dotnet.py`](../../tests/v2/test_lint_strict_dotnet.py)
> exercise both the schema-loaded path AND the no-schema fallback;
> they auto-skip when the wrapper isn't installed locally.

### Problem

The lint at [`contentops/lint/kql.py`](../../contentops/lint/kql.py) is
ten regex-based heuristics. They catch obvious authoring bugs but
not column-name typos, undefined `let` references, or wrong table
joins. Those bugs only surface as ARM 400 at apply time — exactly
the failure mode PAYLOAD001 was added to prevent for one specific
case.

### Proposed shape

A `--strict` opt-in to the existing `contentops lint` command (no new
top-level command). When `--strict` is passed, the runner shells
out to a small wrapper that loads `Kusto.Language.dll` (Microsoft's
parser, available as a NuGet package) and reports parse errors
with line numbers. The wrapper is kept in the repo so it can be
audited; .NET runtime requirement is documented in `contentops doctor`.

```
contentops lint [--strict]
```

Output reuses the existing `LintFinding` shape (`KQL000` reserved
for parser errors).

### Tests

- `tests/v2/test_lint_strict.py` — fixtures with known-bad KQL
  (undefined column, malformed `let`, mismatched paren in a
  comment); `--strict` produces deterministic findings.
- `tests/integration/test_lint_strict_live.py` — optional, gated
  on the .NET runtime being available.

### Closes

G1 (High).

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F1 | `contentops lint --strict` (KQL101 + Kusto.Language) | G1 | M | L | none |

---

## F2 — `pipeline rule test <id>` — DE (primary), SM (governance evidence)

> **Status: deferred (far-future backlog).** No active work planned.
> If/when revisited, the two viable directions are:
>
> 1. **CSV-fixture test** — author hand-curated CSVs as test data,
>    evaluate KQL against them. Lower fidelity than a real engine
>    but bounded scope; no Azure auth.
> 2. **Retrospective via Sentinel / Defender API** — submit the KQL
>    as a normal Log Analytics query (or Defender advanced-hunting
>    query) over a historical window with `| count` appended.
>    Reuses the `contentops.workspace_kql` helper from F4. Higher
>    fidelity, requires read-only API access.
>
> The original synthetic-mode proposal (Python KQL evaluator) is
> explicitly **not** the path forward — research-grade and the cost
> doesn't justify the fidelity gap. Keep the rest of this section
> for context only.

### Problem

There is no way to evaluate a rule's KQL against any data before
deploying it. Analysts test in the portal with live data, which
means catastrophic rules (10× normal alert volume, FP storms) only
manifest after deploy.

### Proposed shape

```
pipeline rule test <envelope_id> --synthetic [--fixture FILE.csv]
pipeline rule test <envelope_id> --against-historical --workspace <ws> --since 7d
```

Two evaluation modes:

- **Synthetic** — KQL evaluated against an in-process Python KQL
  engine seeded by a CSV fixture. The fixture path is recorded in
  `metadata.testFixturePath` so future runs are reproducible.
  Lower fidelity (not all KQL operators are implementable in
  Python) but fast, deterministic, no Azure auth.
- **Against-historical** — submit the KQL as a normal LA query
  with `| count` appended; surface row count + sample. Requires a
  Log Analytics Reader role; no write capability needed. Higher
  fidelity, slower, hits live workspace.

Output: count, sample row, runtime.

### Tests

- `tests/v2/test_rule_test_synthetic.py` — three rules, three
  fixtures, expected counts.
- `tests/integration/test_rule_test_historical.py` — gated on a
  workspace with at least one known-stable table.

### Closes

G8 (Medium). Indirectly: G13 (live test pass becomes a promotion
gate input), G7 (workspace KQL execution path becomes reusable for
silent-rule detection), G20 (telemetry overlay).

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F2 | `pipeline rule test <id>` | G8 | L | H (KQL Python evaluator is research-quality) | F1 (clean parse tree useful) |

---

## F3 — `contentops rollback <sha>` ✅ shipped — DE (primary), SM (incident response)

> **Status: shipped.** Implemented as `contentops rollback <sha>` (the
> `--to <sha>` syntax was simplified to a positional argument).
> Implementation: [`contentops/rollback.py`](../../contentops/rollback.py),
> CLI in [`contentops/cli/commands/rollback.py`](../../contentops/cli/commands/rollback.py)
> (`rollback_cmd`). Tests: [`tests/v2/test_rollback.py`](../../tests/v2/test_rollback.py)
> (13 tests). Closes G6.
>

### Problem

Reverting today is a multi-step `git revert + apply`. During an
incident, that's three commands too many. Rollback should be one
command and a confirmation prompt.

### Proposed shape

```
contentops rollback prod --to <sha>                      # interactive (default)
contentops rollback prod --to <sha> --asset sentinel_analytic
contentops rollback prod --to <sha> --yes                # skip the prompt
contentops rollback prod --to <sha> --dry-run            # diff only
```

Behaviour:

1. Resolve `<sha>` (full or short).
2. Check out `detections/` at that SHA into a temp tree.
3. Compute a plan: every asset whose state at `<sha>` differs from
   current state is a candidate to roll back.
4. Show the plan + per-asset action (`UPDATE`, `DISABLE`, `DELETE`).
5. Confirm (or `--yes`).
6. Apply the plan against the tenant.
7. Write audit records with `action="rollback"` and a synthetic
   `message="rollback to <sha>"`.

Per-asset scoping (`--asset`) is mandatory in practice — never roll
back the whole repo unless the operator types it out.

### Tests

- `tests/v2/test_rollback.py` — end-to-end with a fake state +
  fake handlers, three rules, one rolled back.
- `tests/integration/test_rollback_live.py` — create rule, mutate,
  rollback, verify rule body matches the older shape.

### Closes

G6 (High).

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F3 | `contentops rollback` | G6 | M | L (read-only on disk; same write path as `apply`) | none |

---

## F4 — `contentops silent-rules --workspace --since 30d` — SM

### Problem

Rules that haven't fired in N days sit forever. There's no tooling
to flag them. A rule that hasn't fired could be (a) tuned out of
existence by an upstream change in the data shape, (b) intentional
(waiting for an attack pattern that hasn't recurred), (c) broken
(KQL evaluates to zero rows). The pipeline can't distinguish them,
but it *can* surface the candidates.

### Proposed shape

```
contentops silent-rules --workspace <name> --since 30d [--out CSV]
```

For every `sentinel_analytic` rule, query the workspace:

```kql
SecurityAlert
| where AlertName == "<rule.displayName>"
| where TimeGenerated > ago(30d)
| count
```

(or `SecurityIncident` when applicable). Emit a CSV with columns:
`rule_id`, `displayName`, `last_modified`, `alerts_30d`,
`incidents_30d`, `tactic`, `owner`. Sort by alerts_30d ascending.

No deletion — surface only. Operators triage the list.

### Tests

- `tests/v2/test_silent_rules.py` — mock workspace responses; CSV
  shape stable.

### Closes

G7 (Medium).

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F4 | `contentops silent-rules` | G7 | M | L | F2 (workspace-KQL helper) |

---

## F5 — `pipeline cost` — REJECTED

> **Status: rejected. Not building.**
>
> Detection rules don't drive cost in this environment — **ingest
> does**. Estimating "GB scanned per detection run" frames the
> problem wrong: the detection only reads what was already
> ingested, and the bill was already paid at ingest time. A tool
> that reports per-rule scan estimates would mislead operators
> into thinking they can reduce spend by tuning queries, when
> the lever is actually on the data-collection side (table
> selection, transform-DCRs, Basic-Logs tier choice, etc.).
>
> Cost optimisation in this org belongs in a separate
> ingest-side workflow, not in the detection-pipeline CLI.
>
> The original proposal is preserved below as historical context.

<details>
<summary>Original proposal (rejected — see banner above)</summary>

A heuristic cost rule (`union *`, wide time windows, `materialize`
without `where`) doesn't know how many bytes a table ingests per
day, and so cannot tell you that `union T1, T2` against two tables
totalling 800 GB/day is dangerous and `union T3, T4` against two
tables totalling 80 MB/day is fine. The historical KQL011 cost-
estimator was removed for this reason.

```
pipeline cost [--workspace <name>] [--top N]
```

For every analytic / hunting rule: identify the base tables
referenced, look up table size via `Usage`, estimate scanned
bytes per day, sort descending, flag the top N. CSV per-rule
output with `rule_id`, `displayName`, `queryPeriod`,
`frequency`, `tables`, `est_gb_scanned_per_day`, `flagged`.

</details>

---

## F6 — `contentops drift resolve <id> --strategy {git|remote|merge}` ✅ shipped (partial — `merge` deferred) — DE

> **Status: shipped (partial).** `contentops drift-resolve` (kebab-case,
> not subcommand) implements `--strategy git` (no-op; remote loses on
> next apply) and `--strategy remote` (write the remote envelope into
> local YAML). `--strategy merge` raises `NotImplementedStrategy` with
> a clear "use git+remote" guidance message — the 3-way merge editor
> is deferred. Implementation: [`contentops/drift_resolve.py`](../../contentops/drift_resolve.py),
> CLI in [`contentops/cli/commands/drift.py`](../../contentops/cli/commands/drift.py)
> (`drift_resolve_cmd`). Tests: [`tests/v2/test_drift_resolve.py`](../../tests/v2/test_drift_resolve.py).
> Closes G10 in surface-sufficient form.

### Problem

`contentops drift --write` is all-or-nothing. There's no per-rule
"take the remote version" / "take the git version" / "open a
3-way merge editor" workflow.

### Proposed shape

```
contentops drift resolve <envelope_id> --strategy git       # remote loses; PUT git's version
contentops drift resolve <envelope_id> --strategy remote    # git loses; write remote into YAML
contentops drift resolve <envelope_id> --strategy merge     # opens $EDITOR with a 3-way diff
```

Behaviour for `merge`: write a temp file with conflict markers
(local YAML / remote YAML / common ancestor), launch `$EDITOR`,
parse the result, validate, write back to disk. The handler then
applies it as a normal `contentops apply`.

### Tests

- `tests/v2/test_drift_resolve.py` — cover all three strategies
  with mocked editor.

### Closes

G10 (Medium).

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F6 | `contentops drift resolve` | G10 | M | L | none |

---

## F7 — Marketplace + Templates catalog watcher ✅ shipped (revived; watcher-only) — DE + SM

> **Status: shipped.** Originally removed in Phase 1E
> (`refactor/cli-marketplace-check-removal`) because the CLI shipped
> without a cron workflow and was untested. Revived here scoped
> tighter: pure watcher (no auto-install), tested at multiple
> layers, and wired to the scheduled
> [`upstream-watchers.yml`](../../.github/workflows/upstream-watchers.yml)
> from day one.
>
> Two subcommands under the new `contentops upstream` group:
>
> * `contentops upstream check-marketplace` — diffs Sentinel
>   `contentPackages` against `manifests/upstream_marketplace.json`.
> * `contentops upstream check-templates` — diffs
>   `alertRuleTemplates` against `manifests/upstream_templates.json`.
>
> Both write `docs/whats-new/<YYYY-MM-DD>.md` on a non-empty diff.
> The workflow runs both with `--write` weekly (Mondays 07:00 UTC)
> and opens a PR via `peter-evans/create-pull-request` when
> `git status --porcelain` shows any change. Closes G3 + G4.
> Implementation: [`contentops/upstream/`](../../contentops/upstream/)
> (`manifest.py` + `marketplace.py` + `templates.py` + `whatsnew.py`)
> + [`contentops/cli/commands/upstream.py`](../../contentops/cli/commands/upstream.py).
> Tests: `tests/v2/test_upstream_*.py`.

### Problem

DESIGN §19.2 + §19.3 promised cron-driven PRs when Microsoft
ships new Solution / Alert Rule Template versions. They don't
exist. The pipeline lets analysts *find* templates manually
(`contentops new --search-template`) but doesn't *push* the news.

### Proposed shape

A new workflow `marketplace-catalog.yml` running weekly. It runs:

```
pipeline upstream check-marketplace
```

which lists `alertRuleTemplates` and `contentPackages` from the
target workspace's Sentinel API, diffs against a checked-in
manifest at `state/marketplace_manifest.json`, and:

- on new template version: opens a PR adding a row to a `WHATSNEW.md`.
- on existing template version drift: opens a PR with the diff.

Operators triage the WHATSNEW.md and decide whether to install /
adopt.

### Tests

- `tests/v2/test_marketplace_check.py` — frozen Microsoft response,
  manifest before/after, expected PR body.

### Closes

G3 (Medium), G4 (Medium).

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F7 | Marketplace + template watcher | G3, G4 | M | L | none |

---

## F8 — `contentops lifecycle promote <id>` ✅ shipped (F20 gate live; F2 gate still deferred) — SM (primary), DE (workflow integration)

> **Status: shipped.** `contentops lifecycle promote <rule-id>` runs
> four gates and writes `status: production` + a `lifecycle.promotedAt`
> / `lifecycle.promotedBy` stamp when they pass. Implementation:
> [`contentops/lifecycle.py`](../../contentops/lifecycle.py),
> CLI in [`contentops/cli/commands/lifecycle.py`](../../contentops/cli/commands/lifecycle.py)
> (`lifecycle_promote_cmd`). Threshold lives in
> [`config/lifecycle.yml`](../../config/lifecycle.yml) and is loaded via
> `load_lifecycle_config()`. Tests:
> [`tests/v2/test_lifecycle_promote.py`](../../tests/v2/test_lifecycle_promote.py).
> Closes G13 to the extent it can close without F2.
>
> **Gate map (current):**
> * `status_is_experimental` ✅ live.
> * `recent_validation` ✅ live — same source of truth as G19's
>   META001 lint enforcement.
> * `live_test_pass` 🗄️ **deferred** — depends on F2, which is
>   parked in the far-future backlog (see F2 section).
> * `fp_rate_threshold` ✅ live when `--workspace-id` (or
>   `PIPELINE_WORKSPACE_ID` env var) is set, AND
>   `--no-workspace-query` is unset. Queries F20's
>   `telemetry_query()` against the LA workspace, looks up the
>   rule by `payload.displayName`, computes
>   `closed_fp_30d / incidents_30d`, and compares against the
>   config threshold (default `0.5`). Workspace failures are
>   **fail-closed** — `passed=False` so a transient LA outage
>   blocks promotion until the operator investigates (escape
>   hatch: `--force` or `--no-workspace-query`).

### Problem

`status: experimental` doesn't deploy; everything else does. There
is no automated criterion for "ready to promote
`experimental → production`."

### Shape

```
contentops lifecycle promote <envelope_id> \
    [--workspace-id <id>] [--telemetry-since 30] \
    [--no-workspace-query] [--force] [--dry-run]
```

Checks (threshold tunable via `config/lifecycle.yml`):

1. Status must currently be `experimental`.
2. `metadata.lastValidatedAt` within `--max-validation-age-days`
   (default 30).
3. Live test (F2) — **deferred**; passes silently until F2 ships.
4. FP-rate at or below `fp_rate_threshold` over the
   `--telemetry-since` window (default 30 days). Only evaluated
   when `--workspace-id` is set and `--no-workspace-query` is
   unset; otherwise stays deferred so offline / dry-run paths keep
   working.
5. Reviewer approval — PR-time, not CLI-gateable; honour by
   PR comment / audit-trail message convention.

If gates pass, the command flips `status` to `production` and writes
a `lifecycle.promotedAt` / `lifecycle.promotedBy` block.
Otherwise, prints the failing gate with a hint.

### Tests

- [`tests/v2/test_lifecycle_promote.py`](../../tests/v2/test_lifecycle_promote.py)
  — direct gate unit tests (under/over threshold, no incidents,
  rule not in telemetry, fail-closed on workspace error,
  deferred when no workspace), config loader behaviour, plus
  CLI integration paths for the new `--workspace-id`,
  `--telemetry-since`, `--no-workspace-query` flags.

### Closes

G13 (Medium) to the extent it can close without F2. G13 only fully
closes when the F2 synthetic-test gate ships.

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F8 | `contentops lifecycle promote` | G13 (partial — F2 gate still deferred) | M (actual) | L | F4 / F20 (workspace KQL helper) |

---

## F9 — `contentops coverage --gaps` ✅ shipped — SM (primary), DE (authoring feedback)

> **Status: shipped.** Implemented as a flag on the existing
> `coverage` command (`contentops coverage --gaps`) rather than a
> subcommand, to avoid breaking the `coverage.yml` workflow.
> Implementation: [`contentops/coverage/gaps.py`](../../contentops/coverage/gaps.py).
> Bundled reference list at [`contentops/coverage/data/mitre_attack_techniques.json`](../../contentops/coverage/data/mitre_attack_techniques.json)
> (~70 curated high-value techniques across all 14 tactics).
> `--techniques-file FILE` accepts a fuller MITRE STIX-derived list
> or a custom threat-model. Tests: [`tests/v2/test_coverage_gaps.py`](../../tests/v2/test_coverage_gaps.py)
> (14 tests). Closes G14.
>

### Problem

The MITRE coverage report ([`contentops/coverage/report.py`](../../contentops/coverage/report.py))
shows what we *have*. It doesn't show what we're *missing*.

### Proposed shape

```
contentops coverage gaps [--threat-model FILE] [--out CSV]
```

Loads the full MITRE ATT&CK technique list (vendored or downloaded
from MITRE's STIX bundle), computes the set difference against
techniques referenced by any rule in `detections/`, sorts by tactic
and surfaces the empty cells.

If `--threat-model` is passed, restricts the coverage check to a
subset of techniques the threat model says we care about (e.g.
"this org sees mostly cloud-resident attackers, only T1078, T1098,
T1486 etc.")

### Tests

- `tests/v2/test_coverage_gaps.py` — tiny technique list, three
  rules, expected gap set.

### Closes

G14 (Medium).

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F9 | `contentops coverage gaps` | G14 | S | L | none |

---

## F10 — `pipeline restore <archive>` ✅ shipped — SM

> **Status: shipped.** `pipeline restore <archive>` reads a
> `.tar.gz` / `.tgz` of collect output (and optional MANIFEST.json)
> and restores `detections/<asset_kind>/*.yml` under `--out`
> (default `detections/`). Refuses to overlay a non-empty target
> without `--force`. Defends against path-traversal entries.
> Implementation: [`contentops/restore.py`](../../contentops/restore.py),
> CLI in [`contentops/cli/commands/archive.py`](../../contentops/cli/commands/archive.py)
> (`restore_cmd`). Tests: [`tests/v2/test_restore.py`](../../tests/v2/test_restore.py).
> Closes G22.

### Problem

`contentops collect` produces a snapshot. There's no inverse —
`pipeline restore <snapshot.tar.gz>` would reconstruct
`detections/` from the snapshot for DR.

### Proposed shape

```
pipeline restore <archive.tar.gz> [--out DIR]
```

Reads the MANIFEST shipped by collect/export, validates each
envelope file's checksum, writes them to `--out` (default
`detections/`). Idempotent. Refuses to overwrite a non-empty
target without `--force`.

### Tests

- `tests/v2/test_restore.py` — collect → tar → restore →
  drift-check shows zero diff.

### Closes

G22 (Medium).

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F10 | `pipeline restore` | G22 | M | L | none (collect/export already manifest-driven) |

---

## F11 — Defender Graph extensions revival ✅ shipped (probe only) — DE

> **Status: shipped (probe only).** `pipeline
> defender-extensions-probe` hits the three Microsoft Graph
> endpoints (savedQueries / detection-tuning-rules /
> alert-suppression) and reports `available=true/false` for each.
> Implementation: [`contentops/defender_extensions_probe.py`](../../contentops/defender_extensions_probe.py),
> CLI in [`contentops/cli/commands/diagnostics.py`](../../contentops/cli/commands/diagnostics.py)
> (`defender_extensions_probe_cmd`). Tests: [`tests/v2/test_defender_extensions_probe.py`](../../tests/v2/test_defender_extensions_probe.py).
> **Important corroboration note:** the probe is a *secondary*
> signal, not a primary GA-discovery channel — Microsoft's
> announcement on Microsoft Learn / a Build session is the
> primary trigger. The probe corroborates and is useful for
> catching silent revivals, but a "still false" reading does not
> rule out GA. When an endpoint goes GA: author the corresponding
> handler under [`contentops/handlers/`](../../contentops/handlers/)
> following the existing protocol. Closes G5 in probe form;
> handler authoring remains the deferred follow-up.

### Problem

[`docs/assets/defender_graph_extensions_deferred.md`](../assets/defender_graph_extensions_deferred.md)
documents three Graph surfaces (savedQueries, detection-tuning
rules, alert suppression) that we don't manage because the
endpoints aren't GA.

### Proposed shape

A scheduled `defender-extensions-probe.yml` workflow. Quarterly:

1. Hit each known endpoint URL with a HEAD/OPTIONS request.
2. If 200 / 405 (i.e. the endpoint exists), open an issue tagged
   `roadmap-defender-extensions` with the response.
3. Behind an env flag `PROBE_DEFENDER_EXTENSIONS=1` so we know
   exactly when Microsoft ships them.

When an endpoint goes GA, we author the corresponding handler
under [`contentops/handlers/`](../../contentops/handlers/) following
the existing protocol.

### Tests

- `tests/v2/test_defender_extensions_probe.py` — mocked HTTP,
  flag on/off behaviours.

### Closes

G5 (Medium).

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F11 | Defender extensions probe | G5 | S now (probe), L later (handlers) | L (no actions taken without humans) | none |

---

## F12 — `contentops diff <export-a> <export-b>` ✅ shipped (as `snapshot-diff`) — SM

> **Status: shipped.** Shipped as `pipeline snapshot-diff
> <a.tar.gz> <b.tar.gz>` (the `contentops diff` name was kept for
> the legacy v1 command pending retirement). Content-aware diff
> between two collect archives — indexes envelopes by
> `(asset_kind, envelope_id)` so renames don't surface as
> changes. Implementation: [`contentops/snapshot_diff.py`](../../contentops/snapshot_diff.py),
> CLI in [`contentops/cli/commands/archive.py`](../../contentops/cli/commands/archive.py)
> (`snapshot_diff_cmd`). Tests: [`tests/v2/test_snapshot_diff.py`](../../tests/v2/test_snapshot_diff.py).
> Pairs with F10 (`pipeline restore`). Closes G23.

### Problem

Comparing two collect snapshots is `git diff`, which surfaces every
file rename and reordering as noise. Pre-promotion review (prod ↔
integration) wants a content-aware diff.

### Proposed shape

```
contentops diff <snapshot-a.tar.gz> <snapshot-b.tar.gz> [--asset K] [--format md|json]
```

Walks both archives, indexes envelopes by `(asset, envelope_id)`,
diffs payloads using the same per-handler hash projection logic
the apply path uses. Output: per-asset list of created / updated /
deleted / unchanged.

### Tests

- `tests/v2/test_diff_snapshots.py` — two synthetic archives,
  expected diff output.

### Closes

G23 (Low).

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F12 | `contentops diff` | G23 | M | L | F10 (manifest format) |

---

# Persona-driven additions (F13–F20)

These came out of the persona-track restructure. F13–F17 are
**Detection Engineer** features; F18–F20 are **SOC Manager**
features. F13 / F14 / F18 are Phase 1; F15 / F16 / F17 are Phase 2;
F19 / F20 (and the existing F8) are Phase 3. See
[Phased delivery](#phased-delivery) above.

---

## F13 — `contentops apply --json-report` ✅ shipped — DE

> **Status: shipped.** `apply --json-report PATH` (or `-` for stdout)
> writes a structured outcome document built by
> [`contentops/apply_report.py`](../../contentops/apply_report.py).
> Schema matches the design sketch with one additive field
> (`dry_run`). The report is written *after* the audit chain is
> appended so each result row carries an
> `audit_pointer = "<relative path>#L<line>"` into the chained
> record. Tests in
> [`tests/v2/test_apply_json_report.py`](../../tests/v2/test_apply_json_report.py).

### Problem

`contentops apply` prints a human-readable summary table and writes
audit JSONL. There is no structured *outcome* document for a single
apply run that scripts can consume — workflow steps that need to
react to per-asset failures end up parsing the audit file or
re-greppping the log. This is the same papercut the existing
`contentops prune --json` flag already solved for prune output (see
[`contentops/cli/commands/prune.py`](../../contentops/cli/commands/prune.py),
`prune_cmd`'s `as_json` block).

### Proposed shape

```
contentops apply --json-report apply-report.json
contentops apply --json-report -      # write to stdout
```

JSON document:

```jsonc
{
  "tenant": "production",
  "started_at": "2026-05-07T08:14:00Z",
  "finished_at": "2026-05-07T08:14:32Z",
  "duration_s": 32.1,
  "sha": "<full git sha>",
  "actor": "github-actor-or-USER",
  "workflow_run": "9123456789",
  "results": [
    {
      "asset": "sentinel_analytic",
      "id": "brute-force-ssh-001",
      "action": "update",
      "status": "success",
      "verified": true,
      "audit_pointer": "audit/2026-05-07.jsonl#L142",
      "detail": null,
      "error": null
    },
    ...
  ],
  "totals": {
    "total": 100, "success": 98, "failed": 1, "skipped": 1,
    "verified": 98, "unverified": 0
  }
}
```

`audit_pointer` is the relative path + 1-indexed line number of the
matching audit record so downstream tooling can jump straight to
the chained record.

### Tests

- `tests/v2/test_apply_json_report.py` — apply with mocked
  handlers, assert structure stable, totals add up,
  `audit_pointer` matches the actual line number written.

### Closes

Doesn't close a numbered gap — fills the missing structured-output
contract for the most-run command. Pairs naturally with F14 (the
`--json-report` becomes the input to `retry-failed --run-id`).

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F13 | `contentops apply --json-report` | (productivity) | S | L | none |

---

## F14 — `contentops retry-failed --since/--run-id` ✅ shipped — DE

> **Status: shipped.** Both flags live on `retry-failed` in
> [`contentops/cli/commands/lifecycle.py`](../../contentops/cli/commands/lifecycle.py),
> mutually exclusive. `--since` accepts duration shorthand (`1h`,
> `30m`, `7d`) and ISO 8601 timestamps via
> [`contentops.audit_filter.parse_since`](../../contentops/audit_filter.py).
> Reader is non-mutating (CLAUDE.md invariant 9). Tests in
> [`tests/v2/test_retry_failed_since.py`](../../tests/v2/test_retry_failed_since.py).

### Problem

`contentops retry-failed` today reads the *latest* `audit/*.jsonl`
file and re-applies anything with `status=failed`. Two real-world
shapes break this:

1. The latest audit file might be a *successful* later run that
   masks the partial failure two runs ago.
2. A workflow may want to retry one specific run-id (the
   `GITHUB_RUN_ID` from the audit record) without touching
   anything else.

### Proposed shape

```
contentops retry-failed                             # current behaviour (latest file)
contentops retry-failed --run-id 9123456789         # exact run-id from audit
contentops retry-failed --since 1h                  # last hour of audit records
contentops retry-failed --since 2026-05-07T08:00Z   # since ISO timestamp
```

`--since` and `--run-id` are mutually exclusive. Either narrows the
audit window before extracting the failed (asset, id) pairs.

### Tests

- `tests/v2/test_retry_failed_since.py` — fixtures with three
  audit files spanning multiple runs; assert `--since 1h` and
  `--run-id <id>` each pick the right subset.

### Closes

Operational papercut where "failed yesterday, fine today" was
silently invisible to retry today: F14 gives DEs a
narrowly-scoped retry window when only some rules failed. The
bulk-disable side of G18 was closed separately by
`contentops disable --cohort` + `contentops enable` (see the
gap-assessment G18 row); G18 is now fully resolved.

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F14 | `contentops retry-failed --since/--run-id` | (productivity) | S | L | none |

---

## F15 — `contentops drift --suppressions` — DE

### Problem

The daily drift PR is the canonical signal "the live tenant has
drifted from git." But not every drift is actionable. A
known-good portal-side tweak (e.g. an analyst tuned a threshold
last week and we agreed the tenant wins for now) shows up every
single day until either the YAML is updated or the tweak is
reverted. Teams learn to ignore the wall of CHANGED entries —
exactly the muscle memory we don't want.

### Proposed shape

A new file `detections/drift_suppressions.yml`:

```yaml
schema_version: "1.0"
suppressions:
  - asset: sentinel_analytic
    id: brute-force-ssh-001
    reason: "Threshold tuned in portal pending data review (tracked in Linear ENG-7421)"
    expires: 2026-06-01
  - asset: sentinel_analytic
    id: o365-mailbox-anomaly
    reason: "Pending team decision on tactic mapping"
    expires: 2026-05-21
```

`contentops drift` reads the file (no flag — always honours
suppressions), and:

- Suppressed entries are *omitted from the changed list* but
  still printed in the summary as `suppressed: 2`.
- An entry past its `expires` date is *not* suppressed — it
  re-surfaces in the changed list with a `[suppression-expired]`
  tag in the PR body.
- A suppression for an asset that isn't actually changed is
  flagged as `[suppression-unused]` so dead entries get cleaned
  up.

`contentops drift --suppressions=ignore` opt-out for forensic runs.

### Tests

- `tests/v2/test_drift_suppressions.py` — three drift scenarios
  (active suppression hides, expired surfaces with tag, unused
  flags as such).
- Schema test: malformed suppressions YAML rejected at load
  time, not silently swallowed.

### Closes

The "drift fatigue" failure mode that's the operational risk
behind G2's high severity (now resolved at the data-shape level
but the noise pattern recurs whenever portal tuning is
intentional). Specifically reduces daily drift PR size for SOCs
that do legitimate portal-side tuning.

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F15 | `contentops drift --suppressions` | (signal quality) | M | L | none |

---

## F16 — `contentops explain <rule-id>` — DE

### Problem

When a DE is paged about a misbehaving rule (or a SOC analyst
asks "what does this rule do?"), the answer requires walking
through five places: the YAML file, `metadata.owner`,
`detections/dependencies.yml`, the latest `audit/*.jsonl` for
recent applies, and `state/state.json` for last-applied SHA.
There is no single command that surfaces "everything I need to
know about this rule right now."

### Proposed shape

```
contentops explain <rule-id>
contentops explain <rule-id> --format json
```

Output (markdown, default):

```
## brute-force-ssh-001  (sentinel_analytic, status: production)

Owner:      secops@example.com
Runbook:    https://runbooks.example.com/brute-force-ssh-001
Severity:   medium  •  Tactics: CredentialAccess  •  Techniques: T1110
Path:       detections/sentinel_analytic/brute-force-ssh-001.yml

### Dependencies
  needs tables: SecurityEvent
  needs watchlists: (none)
  needs parsers: (none)

### State
  last applied: 2026-05-06T22:14:33Z by github-actions
  last sha:     8356ae9b
  remote name:  abcd-... (preserved on metadata.arm_name)
  locked:       false

### Recent audit (5 most recent)
  2026-05-06 22:14:33  update  success     8356ae9
  2026-05-04 19:02:07  update  success     93f2136
  2026-05-01 14:33:12  update  failed      dfb08f0   ETag conflict — resolved on retry
  ...

### Drift status
  in-sync as of 2026-05-07 06:00 (drift.yml)
```

### Tests

- `tests/v2/test_explain.py` — synthetic envelope + state +
  audit; assert each section renders the right field.
- CLI test for `--format json` — structure stable.

### Closes

Operational papercut. Doesn't map to a numbered gap but it's the
single biggest "context-switch cost" issue DEs hit during triage.

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F16 | `contentops explain <rule-id>` | (signal quality) | M | L | none |

---

## F17 — `contentops doctor --fix` — DE

### Problem

`contentops doctor` today is read-only: it surfaces what's wrong
and you fix it manually. For a new DE doing first-time setup
(see [`docs/onboarding.md`](../onboarding.md)), the loop is:
read failure, look up fix, apply fix, re-run doctor, repeat.
Most failures are mechanical and *safe to automate*: missing
`.env`, malformed YAML in `config/tenant.yml`, missing
`detections/` subdirs.

### Proposed shape

```
contentops doctor --fix              # interactive (prompt before each mutation)
contentops doctor --fix --yes        # autofix all safe items
contentops doctor --fix --dry-run    # show what would be fixed
```

Each fix is opt-in by *check*:

| Check that fails | Safe autofix |
|---|---|
| `.env` missing | Copy `.env.example` → `.env`, prompt for values |
| `detections/` missing subdirs | `mkdir -p` the standard layout |
| `config/tenant.yml` malformed | Print first parse error + offset; refuse to mutate |
| `python_deps` missing | Run `pip install -e .[dev]` if `pyproject.toml` is present |
| `git` missing from PATH | Print install instruction; refuse to mutate |
| `auth_env` partially set | List missing vars; refuse to mutate (secret material) |
| `detections_parse` fails | Run `contentops lint` and surface findings; refuse to mutate |

Mutations stay narrow: anything touching credentials or YAML
content is **explicitly out of scope** — autofix never types a
secret or hand-edits a rule.

### Tests

- `tests/v2/test_doctor_fix.py` — each safe fix in isolation,
  plus the "refuse to mutate" cases (malformed config, missing
  auth env vars).

### Closes

Operational papercut for onboarding. Pairs with
[`docs/onboarding.md`](../onboarding.md) — the day-1 setup loop
collapses from "fix → re-run → fix → re-run" into one or two
commands.

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F17 | `contentops doctor --fix` | (onboarding velocity) | M | M (must not over-reach into credential or rule content) | none |

---

## F18 — `contentops audit query` ✅ shipped — SM

> **Status: shipped.** Five subcommands (`latest`, `failures`,
> `by-actor`, `rollbacks`, `timeline`) under
> [`contentops/cli/commands/audit.py`](../../contentops/cli/commands/audit.py)
> with `--format {table|json|csv}` and `--out PATH`. Reader logic in
> [`contentops/audit_query.py`](../../contentops/audit_query.py) is
> non-mutating (CLAUDE.md invariant 9). Tests in
> [`tests/v2/test_audit_query.py`](../../tests/v2/test_audit_query.py).

### Problem

[`audit-trail.md`](audit-trail.md) ships the canonical "who/when/
what" queries as `jq` and PowerShell one-liners. They work but
require an SM to know jq, type the right field name, and trust
their `*.jsonl` glob. The standard forensic queries (latest
success per id, failures since date, applies by actor in
window) should be a named subcommand each.

### Proposed shape

```
contentops audit query latest <rule-id>             # latest record per id
contentops audit query failures --since 7d          # failures in window
contentops audit query by-actor <actor> --since 30d
contentops audit query rollbacks --since 30d        # records with rollback marker (F3)
contentops audit query timeline <rule-id>           # all records for one id, in order
contentops audit query --format {table|json|csv}
```

Implementation: thin wrapper over the existing `audit/*.jsonl`
files; reads the chain in date order, filters, prints. No new
schema. Output formats reuse the table/JSON/CSV idioms from
existing `portfolio` / `compliance` commands.

### Tests

- `tests/v2/test_audit_query.py` — synthetic chain across two
  days, assert each subcommand surfaces the right records.
- CSV/JSON shape stable across schema_version.

### Closes

Closes the "compliance reporting requires `jq` literacy" papercut
implicit in [`audit-trail.md`](audit-trail.md). Removes a real
adoption barrier for SMs who don't write KQL or shell.

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F18 | `contentops audit query` | (operational visibility) | S/M | L | none |

---

## F19 — `contentops state sync` ✅ shipped — SM

> **Status: shipped.** CLI surface (`state sync push|pull|status`) is
> live in [`contentops/cli/commands/state.py`](../../contentops/cli/commands/state.py);
> git-plumbing module is
> [`contentops/state_sync.py`](../../contentops/state_sync.py) (hash-object
> + mktree + commit-tree + force-push against `refs/heads/state/<env>`,
> non-mutating read path). Workflow wiring landed across `deploy.yml`,
> `promote-to-integration.yml`, `prune.yml`, and `retry-failed.yml` —
> each calls `state sync pull` before its mutation step and
> `state sync push` after (gated on non-dry-run). `integration-deploy.yml`
> deliberately skips: PR-time smoke runs would generate noisy per-PR
> state churn. Closes gap-assessment G15. Tests in
> [`tests/v2/test_state_sync.py`](../../tests/v2/test_state_sync.py).

### Problem

DESIGN §13 promised the state file lives on an orphan branch
`state/<env>` so its history is auditable but doesn't pollute
main. Today's reality (per
[`gap-assessment.md`](gap-assessment.md) G15): every runner reads
its build's local-disk copy of `state/state.json`. There's no
durable, cross-runner state — two parallel applies on different
runners produce divergent state files, and CI's clean checkout
loses the state every time.

### Proposed shape

```
contentops state sync push          # commit state to state/<env> orphan branch
contentops state sync pull          # checkout state/<env>, restore into state/
contentops state sync status        # show divergence vs the orphan branch
contentops state sync --env <slug>  # explicit env (defaults to tenant.yml's name)
```

Behaviour:

1. `pull` runs at the start of every workflow that needs state
   (apply, drift, prune). If the orphan branch doesn't exist
   yet, treat as empty — non-fatal.
2. `push` runs at the end of the same workflows after
   successful state mutation. Atomic: stages the new file,
   commits with `[state] <env> <sha> <timestamp>`, force-pushes
   to the orphan ref.
3. Concurrency: workflow `concurrency:` group on `state/<env>`
   ensures two simultaneous applies queue rather than race.

### Tests

- `tests/v2/test_state_sync.py` — fake remote, assert push/pull
  round-trips, status reports divergence, env-slug honoured.
- Integration test: simulate two-runner scenario in a temp repo;
  one pushes, the other pulls, assert state matches.

### Closes

G15 (Medium).

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F19 | `contentops state sync` | G15 | M | M (force-push to orphan branch needs careful concurrency design) | none |

---

## F20 — Portfolio telemetry overlay ✅ shipped (4 of 4 columns; cost column dropped — F5 rejected) — SM

> **Status: shipped.** `contentops portfolio --with-telemetry
> --workspace-id <id> --telemetry-since 30` adds four operational
> columns to the per-detection report: `alerts_30d`, `incidents_30d`,
> `closed_fp_30d`, and derived `fp_rate`. Implementation:
> [`contentops/cli/commands/portfolio.py`](../../contentops/cli/commands/portfolio.py)
> (lines 21-156), backed by `telemetry_query()` in
> [`contentops/workspace_kql.py`](../../contentops/workspace_kql.py)
> (line 157, deliberately shares the F4 silent-rules KQL).
> Tests: [`tests/v2/test_portfolio_telemetry.py`](../../tests/v2/test_portfolio_telemetry.py)
> (5 tests — column population, fp_rate rounding, graceful
> degradation on KQL + auth failures, telemetry-off baseline).
> Scheduled via the nightly [`portfolio.yml`](../../.github/workflows/portfolio.yml)
> workflow; telemetry is opt-in via the `PIPELINE_WORKSPACE_ID`
> Actions variable so the workflow still runs in inputs-only mode
> when the variable is unset. Closes G20.
>
> **Cost column dropped.** The original sketch promised a fifth
> column, `est_gb_scanned_per_day`, derived from F5's table-size
> estimator. F5 was rejected (cost lever in this org is ingest,
> not detections — see the F5 section), so the cost column was
> never implemented. The roadmap text below reflects the four
> shipped columns.

### Problem

The portfolio report ([`contentops/portfolio/report.py`](../../contentops/portfolio/report.py))
shows authoring inputs only — tactic, technique, severity,
owner, status. SMs deciding which rules deserve tuning
investment need *operational signal*: how often does each rule
fire and what's its FP rate? Today this is manual KQL in the
portal. G20 explicitly defers it to "Wave 5"; this is the Wave 5
deliverable.

### Shape

An opt-in workspace-KQL pass on `pipeline portfolio`:

```
contentops portfolio --with-telemetry --workspace-id <id> --telemetry-since 30
```

Adds columns:

- `alerts_30d` — `SecurityAlert | summarize count() by AlertName`
- `incidents_30d` — `SecurityIncident | summarize count() by Title`
- `closed_fp_30d` — `SecurityIncident | countif(Classification == "FalsePositive")`
- `fp_rate` — derived: `closed_fp_30d / incidents_30d` (None when
  `incidents_30d == 0`; rounded to 3dp)

When `--with-telemetry` is omitted, the existing inputs-only
portfolio is unchanged.

### Tests

- [`tests/v2/test_portfolio_telemetry.py`](../../tests/v2/test_portfolio_telemetry.py)
  — mock workspace responses; assert column population stable for
  matched rules, blank cells for unmatched rules, graceful
  degradation on KQL / auth failures.

### Closes

G20 (Medium). Indirectly: G7 (silent rules become visible via
`alerts_30d == 0`), G13 (FP-rate becomes a promotion gate input —
wired up under F8).

| ID | Feature | Closes gap | Effort | Risk | Depends on |
|----|---------|-----------|--------|------|------------|
| F20 | Portfolio telemetry overlay | G20 | M (actual) | L (workspace KQL helper already shipped under F4) | F4 (workspace KQL helper) |

---

# Alert tracking features (F21–F23)

These features close the alert-performance visibility gap —
surfacing per-detection health, ownership accountability, and
multi-audience reporting from a single PII-free data pipeline.

---

## F21 — `contentops alerts sync` + `contentops alerts health` ✅ shipped — SM + DE

> **Status: shipped.** Two new command groups under `contentops alerts`:
>
> * `contentops alerts sync` — PII-free alert ledger with smart
>   lookback (30d Defender / 90d Sentinel), watermark-based
>   incremental sync, upsert reclassification handling, and
>   `--backfill` for full refetch. Graph `detectorId` capture
>   enables reliable alert-to-detection correlation.
> * `contentops alerts health` — per-detection health report with
>   six recommendation categories: **TUNE** (FP rate > 40%),
>   **CLASSIFY** (>50% unclassified, >5 alerts), **SILENT** (0
>   alerts in period), **HEALTHY** (TP rate > 80%), **REVIEW**
>   (metrics outside normal thresholds), **EXPECTED_SILENT**
>   (detection marked as expected-silent). Includes owner mapping
>   via `config/owners.yml`, version tracking, and expected-vs-actual
>   volume comparison.
>
> The daily rollup store (`contentops/alerts/daily_store.py`)
> provides gap filling, idempotent rebuild, and version tracking.
>
> `config/tenant.yml` gains an `alerts:` block for opt-in enablement
> with `defenderLookbackDays`, `sentinelLookbackDays`,
> `ledgerRetentionDays`, and `rollupRetentionDays`.
>
> `--sync-owners` auto-creates/updates `config/owners.yml` with all
> detection IDs found in the ledger.

| ID | Feature | Persona | Status | Closes | Effort |
|----|---------|---------|--------|--------|--------|
| F21 | `contentops alerts sync` + `contentops alerts health` | SM + DE | ✅ shipped | G28, G29 | M |

---

## F22 — `contentops report --unified` ✅ shipped — SM

> **Status: shipped.** `contentops report --unified` renders a single
> HTML report (`reports/unified.html`) for all audiences:
>
> * **CEO** — posture score (single number)
> * **CISO** — MITRE heatmap + risk summary
> * **SOC Manager** — owner accountability matrix + attention queue
> * **Engineers** — per-detection health table + recommendation queue
> * **Hunters** — silent/uncovered technique gaps
>
> The renderer consumes the detection health report from F21, the
> MITRE coverage data, and the ownership mapping to produce a
> self-contained HTML file with no external dependencies.

| ID | Feature | Persona | Status | Closes | Effort |
|----|---------|---------|--------|--------|--------|
| F22 | `contentops report --unified` | SM | ✅ shipped | G30 | M |

---

## F23 — `config/owners.yml` ownership mapping ✅ shipped — SM + DE

> **Status: shipped.** `config/owners.yml` maps detection IDs to
> owners (email, team, or alias). Auto-synced via
> `contentops alerts health --sync-owners` which adds any detection
> IDs found in the alert ledger that are not yet mapped. The file
> is consumed by the health report (F21) and the unified report
> (F22) for owner accountability views.

| ID | Feature | Persona | Status | Closes | Effort |
|----|---------|---------|--------|--------|--------|
| F23 | `config/owners.yml` ownership mapping | SM + DE | ✅ shipped | (accountability) | S |

---

## Summary table

| ID | Feature | Persona | Phase | Status | Closes gap | Severity | Effort | Risk | Depends on |
|----|---------|---------|-------|--------|-----------|----------|--------|------|------------|
| F1  | `contentops lint --strict` (KQL101 + Kusto.Language wrapper) | DE | unphased | ✅ shipped (both layers; CI installs .NET 8) | G1 | High → resolved | M | L | none |
| F2  | `pipeline rule test <id>` | DE+SM | n/a | 🗄️ deferred (backlog) | G8 | Medium | L | H | F1 |
| F3  | `contentops rollback` | DE+SM | n/a | ✅ shipped | G6 | High | M | L | none |
| F4  | `contentops silent-rules` | SM | n/a | ✅ shipped | G7 | Medium | M | L | (workspace KQL helper) |
| F5  | `pipeline cost` | SM+DE | n/a | ❌ rejected | G9 | — | — | — | (cost lever is on ingest, not detections) |
| F6  | `contentops drift-resolve` | DE | unphased | ✅ shipped (`merge` deferred) | G10 | Medium | M | L | none |
| F7  | Marketplace + template watcher | DE+SM | unphased | ✅ shipped (revived; watcher-only, scheduled) | G3, G4 | Medium | M | L | none |
| F8  | `contentops lifecycle promote` | SM+DE | **3** | ✅ shipped (F20 fp_rate_threshold gate live; F2 live_test_pass gate still deferred) | G13 (partial) | Medium | M (actual) | L | F4 / F20 |
| F9  | `contentops coverage --gaps` | SM+DE | n/a | ✅ shipped | G14 | Medium | S | L | none |
| F10 | `pipeline restore` | SM | unphased | ✅ shipped | G22 | Medium | M | L | none |
| F11 | Defender extensions probe | DE | unphased | ✅ shipped (probe; secondary signal) | G5 | Medium | S+L | L | none |
| F12 | `pipeline snapshot-diff` | SM | unphased | ✅ shipped | G23 | Low | M | L | F10 |
| F13 | `contentops apply --json-report` | DE | **1** | ✅ shipped | (productivity) | — | S | L | none |
| F14 | `contentops retry-failed --since/--run-id` | DE | **1** | ✅ shipped | (productivity) | — | S | L | none |
| F15 | `contentops drift --suppressions` | DE | **2** | ✅ shipped ([`contentops/drift_suppressions.py`](../../contentops/drift_suppressions.py)) | (signal quality) | — | M | L | none |
| F16 | `contentops explain <rule-id>` | DE | **2** | ✅ shipped ([`commands/diagnostics.py:451`](../../contentops/cli/commands/diagnostics.py)) | (signal quality) | — | M | L | none |
| F17 | `contentops doctor --fix` | DE | **2** | ✅ shipped ([`commands/doctor.py:55`](../../contentops/cli/commands/doctor.py)) | (onboarding velocity) | — | M | M | none |
| F18 | `contentops audit query` | SM | **1** | ✅ shipped | (operational visibility) | — | S/M | L | none |
| F19 | `contentops state sync` | SM | **3** | ✅ shipped | G15 | Medium | M | M | none |
| F20 | Portfolio telemetry overlay | SM | **3** | ✅ shipped (4 of 4 columns; cost column dropped — F5 rejected) | G20 | Medium | M | L | F4 (workspace KQL helper) |
| F21 | `contentops alerts sync` + `contentops alerts health` | SM+DE | n/a | ✅ shipped | G28, G29 | — | M | L | none |
| F22 | `contentops report --unified` | SM | n/a | ✅ shipped | G30 | — | M | L | F21 |
| F23 | `config/owners.yml` ownership mapping | SM+DE | n/a | ✅ shipped | (accountability) | — | S | L | none |

### Sprint cluster shipped 2026-05-22 (PRs #237 / #239 / #240 / #241)

Four PRs landed in close sequence after the original F1–F20 phasing
exhausted. They're tracked as the **NVISO + gap-closeout + navigator**
cluster — see also [`feature-catalog.md`](feature-catalog.md#recently-shipped-2026-05-22-sprint-cluster).

| ID | Feature | Persona | Status | Closes | Source |
|---|---|---|---|---|---|
| **N1** | `contentops detection-docs regenerate \| check` | DE+SM | ✅ shipped | NVISO Part 4 | PR #237 |
| **N2** | `contentops auto-disabled-rules` | SM | ✅ shipped | NVISO Part 7 | PR #237 |
| **N3** | `contentops tuning preview` | DE | ✅ shipped | NVISO Part 8 | PR #237 |
| **N4** | URL link-rot + codespell CI | DE | ✅ shipped | NVISO Part 3 | PR #237 |
| **S1** | `contentops plan --against-tenant` | DE+SM | ✅ shipped | G17 | PR #239 |
| **S2** | Dedicated `role: test` workspace | SM | ✅ shipped | G21 | PR #239 |
| **S3** | `contentops coverage --d3fend` (MITRE D3FEND) | SM | ✅ shipped | (new axis) | PR #239 |
| **S4** | Operational gap closeouts (doctor SentinelHealth probe; PR-time URL check; fork-PR onboarding note) | DE | ✅ shipped | G25, G26, G27 | PR #239 |
| **M1** | `contentops navigator` (MITRE ATT&CK Navigator layer) | SM | ✅ shipped | (new capability) | PR #240 |
| **P1** | `policy.scaffoldStrict` default → False (lenient) | (cross-cutting) | ✅ shipped | adopter friction | PR #241 |

### Recommended landing order (historical)

All Phase 1–3 features above have shipped as of 2026-05-22. The
ordering below is preserved as a historical note for posterity:

- **Phase 1 (S effort × 3, no dependencies):** F13 → F14 → F18 ✅
- **Phase 2 (M effort × 3, no dependencies):** F15 → F16 → F17 ✅
- **Phase 3 (M / L / L, share workspace-KQL dependency):** F19 →
  F20 → F8 ✅ (F8's `live_test_pass` gate still deferred until F2)

The unphased baseline (F1, F3, F6, F7, F9, F10, F11, F12) all
shipped. Of the original 20 F-features, **only F2 (rule test, deferred)
and F5 (cost, rejected) remain unshipped by design.**
