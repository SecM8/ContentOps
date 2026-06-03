# Operator Guide

> The single canonical entry point for everyone who touches this
> repo. Read this first; it links to the rest.

---

## What is this pipeline?

A **detection-as-code** system for Microsoft Sentinel and Microsoft
Defender XDR. Single tenant. Git is the source of truth.

- Analysts author detection rules as YAML under `detections/`.
- Pull requests run `validate` + `lint` + `plan` (no Azure auth).
- Merge to `main` runs `apply` against the production tenant
  (deploy.yml).
- A daily `drift` workflow watches for portal-side changes and
  opens a PR if the tenant has drifted from git.
- An append-only **hash-chained** audit trail records every write.

Everything works through one CLI: **`contentops`**. Both
`contentops <cmd>` (the console script) and `python -m contentops <cmd>`
work after `pip install -e .`.

Architectural detail: [`reference/architecture.md`](reference/architecture.md).
Tenant configuration setup: [`operations/tenant-config-modes.md`](operations/tenant-config-modes.md).
Workflows index: [`reference/workflows.md`](reference/workflows.md) —
which of the 33 GitHub Actions workflows fires when.
Terminology: [`glossary.md`](glossary.md) — every term that recurs
in CLI output and PR comments, on one page.
When something breaks in CI or production, start at
[`../SECURITY.md`](../SECURITY.md) for the incident-response history
and rotation procedure.

---

## Daily flow

```
   Analyst                 GitHub                Tenant
   ───────                 ──────                ──────
                                                      
   edit YAML  ─────► PR (validate.yml,                
                          coverage.yml)               
                                                      
                          merge to main ─────► deploy.yml
                                               (apply)
                                                  │
                                                  ▼
                                              audit/
                                              state/
                                                      
   drift?     ◄────  drift.yml (daily) ────  list_remote()
              opens PR with detected drift   compare to git
```

Happy path: the analyst writes YAML, the reviewer reviews the
diff, merge auto-deploys, drift PR confirms in-sync the next
morning. Failures gate at PR time (lint/plan errors) or on apply
(per-asset failure → audit `status: failed`, batch exits 1).

### Alert tracking (daily, automated)

The `alerts-report.yml` workflow runs daily at 07:00 UTC:

1. **Sync** — fetches new alerts into the PII-free ledger
2. **Rollup** — computes yesterday's classification breakdown
3. **Health** — maps alerts to detections, computes recommendations

```bash
# Manual equivalent:
contentops alerts sync
contentops alerts rollup --date yesterday
contentops alerts health --period 30d --out-md alerts-reports/health.md
contentops report --unified
```

Recommendations:
- **TUNE** — FP rate > 40%, needs query/exclusion tuning
- **CLASSIFY** — >50% alerts unclassified by analysts
- **SILENT** — 0 alerts in period, check data source health
- **HEALTHY** — TP rate > 80%, performing well
- **REVIEW** — metrics outside normal thresholds, needs investigation
- **EXPECTED_SILENT** — detection marked as expected-silent (e.g. canary rules)

Ownership: edit `config/owners.yml` to assign detection owners.
Run `contentops alerts health --sync-owners` to auto-add new detections.

---

## Five things you'll do in your first week

All commands assume a working `.env` (tenant ID, client
credentials, subscription, workspace) per
[`development/local-testing.md`](development/local-testing.md).

### 1. Verify your setup

```
contentops doctor
```

Checks: Python 3.12+, deps, `.env`, auth env vars, `config/tenant.yml`,
`detections/` parse, git on PATH. Add `--auth` to test token
acquisition; add `--matrix` to also smoke-test every handler's
`list_remote()` against the live tenant.

Implementation: [`contentops/devex/doctor.py`](../contentops/devex/doctor.py).

### 2. Scaffold a new rule

```
contentops new sentinel_analytic <kebab-id>
```

Writes a valid envelope under `detections/sentinel_analytic/<id>.yml`
and lints it round-trip. Or, to start from a Microsoft-shipped
template:

```
contentops new --search-template "brute force"
contentops new --from-template <template-guid> --id <kebab-id>
```

Doc: [`assets/cli_new_from_template.md`](assets/cli_new_from_template.md).

### 3. See what your PR would do

```
contentops plan --asset sentinel_analytic
```

Read-only. Runs every handler's `validate()` + `plan()`. Shows the
intended action per asset (`update`, `disable`, `skip`) and any
validation errors. Same code path the PR's `validate.yml` runs.

Use `--changed-since origin/main` to limit to assets your branch
touched.

### 4. Push to the tenant

You don't push manually — merge to `main` triggers `deploy.yml`
which runs `contentops apply --changed-since <prev SHA>`. To
preview locally without writing:

```
contentops apply --dry-run --asset sentinel_analytic
```

Real apply (rare; production deploys go through CI):

```
contentops apply --asset sentinel_analytic --no-audit   # dev workflow only
```

Don't apply against production from a feature branch. Don't pass
`--no-audit` in CI. The deploy.yml workflow handles the rest.

### 5. Read the drift report

```
contentops drift --asset sentinel_analytic
```

Compares remote tenant ↔ local YAML. Reports `new` / `changed` /
`in-sync` per asset. Add `--write` to materialise changed
envelopes onto disk; add `--report drift.json` for the
machine-readable form `drift.yml` consumes.

The daily `drift.yml` workflow opens a PR every morning if drift
is detected. Triage that PR; merge it if the portal change is
intentional, revert it if not.

Doc: [`operations/collect.md`](operations/collect.md).

---

## Suppressing known-good drift

When a portal-side tweak is *intentional* (e.g. an analyst tuned a
threshold and the team agreed the tenant wins for now), it would
otherwise show as `CHANGED` in every daily drift PR forever — and the
team learns to ignore the wall of CHANGED entries. List it in
`detections/drift_suppressions.yml` to hide it until a fixed expiry:

```yaml
schema_version: "1.0"
suppressions:
  - asset: sentinel_analytic
    id: brute-force-ssh-001
    reason: "Threshold tuned in portal pending data review (ENG-7421)"
    expires: 2026-06-01
```

`contentops drift` honors the file by default:

- **Active** suppression → entry hidden from the changed list, counted
  as `suppressed: N` in the summary and the auto-PR.
- **Expired** (past `expires`) → entry re-surfaces in the changed list,
  and the auto-PR lists it under **Expired suppressions** — renew the
  entry or resolve the drift.
- **Unused** (matches no drift) → flagged under **Unused suppressions**
  so dead entries get cleaned up.

Every entry needs a `reason` (validated — an empty reason is rejected)
so a future analyst can tell why the tenant was allowed to win. Run a
forensic, suppression-blind report with
`contentops drift --suppressions=ignore`.

Doc: [`reference/feature-catalog.md`](reference/feature-catalog.md).

---

## When something breaks — decision tree

### Red CI on a PR

| Workflow red | Likely cause | Fix |
|---|---|---|
| `validate.yml` | Pydantic schema error, missing metadata block, dependency-graph violation | Read the error; usually one envelope. Run `contentops plan` locally. |
| `validate.yml` (lint step) | KQL bracket mismatch, `union *`, `templateVersion` without `alertRuleTemplateName`, etc. | Run `contentops lint --severity error` locally. Lint rule reference in [`reference/feature-catalog.md`](reference/feature-catalog.md#lint-rules). |
| `coverage.yml` | Posts a comment; never gates on its own. | n/a — just a heads-up. |
| `ci.yml` | Unit test failure, pip-audit vulnerability | Run `pytest -q --ignore=tests/integration` locally. |

### ARM / Graph 400 at apply time

Most common: **`templateVersion` is set without `alertRuleTemplateName`**.
The PAYLOAD001 lint rule catches this at PR time, but if you bypass
lint or hand-edit a YAML, apply will 400. The apply-time scrub at
[`contentops/handlers/sentinel_analytic.py:160`](../contentops/handlers/sentinel_analytic.py)
silently drops the field; remove it from YAML to stay quiet. Full
post-mortem: [`archive/incidents/broken-analytics-2026-05-06.md`](archive/incidents/broken-analytics-2026-05-06.md).

Other 400s usually mean the API contract changed; check the audit
record's `message` field, then look up the failing handler under
[`contentops/handlers/`](../contentops/handlers/).

### Drift PR opened — is it real?

Open the PR. The body lists each `new` / `changed` envelope with
its `metadata.owner`. Then:

- If a known portal change matches it (someone tuned a threshold,
  imported a Solution): merge the PR. Drift PR ⇄ portal-state
  capture is the intended round-trip.
- If you don't recognise the change: investigate before merging.
  Use `git log -- <file>` for prior history; check the audit
  trail (`jq -c 'select(.id=="<id>")' audit/*.jsonl`).

Long-form: [`operations/collect.md`](operations/collect.md).

### Drift says CHANGED but I didn't edit anything

```
contentops drift --diff
```

For each CHANGED entry, prints the field-level deltas under the
same canonical-JSON projection drift uses. Useful when a handler
reports drift on rules nobody touched — the diff shows whether a
server-managed field is leaking through, a normalization
divergence is at play, or someone really did edit the rule.

For a `verified=False` MISMATCH after an apply, use the
roundtrip-diff diagnostic for the affected engine:

```
contentops defender-roundtrip-diff <envelope-id>
contentops sentinel-roundtrip-diff <envelope-id>
```

Both load the local envelope, fetch the live remote, and report
which `_HASHED_FIELDS` paths differ — read-only, no tenant writes.
Pass `--raw` to see the literal API response when you suspect
Microsoft has added a new server-managed field the stripper
doesn't yet know about. Exit codes: `0` = clean, `1` =
invocation error (envelope or remote not found), `2` = at least
one field differs.

The Sentinel diagnostic dispatches by asset kind (`sentinel_analytic`,
`sentinel_hunting`, `sentinel_parser`, `sentinel_watchlist`) to the
right handler's hash projection. `sentinel_data_connector` is not
currently supported by this command (connectors hash via a
`_projection()` helper rather than the `_HASHED_FIELDS` shape);
for connector mismatches, read the apply summary directly.

### `apply` failed, batch exit 1

```
contentops retry-failed
```

Reads the latest `audit/*.jsonl`, finds entries with
`status:failed`, re-applies just those. Default dry-run. Useful
after a transient ARM 5xx burst or rate limit.

Implementation: [`contentops/cli/commands/lifecycle.py`](../contentops/cli/commands/lifecycle.py) (`retry_failed_cmd`).

### Locked rule won't deploy

A rule with top-level `localCustomization: true` is the lock flag.
`apply` skips it without `--force-overwrite`. Either:

```
contentops unlock <rule-id>           # remove the lock, then apply normally
contentops apply --force-overwrite    # apply through the lock (rare)
```

Doc: [`assets/cli_lock_retry.md`](assets/cli_lock_retry.md).

### Integration PR with one broken rule, but I want the rest to merge

`integration-deploy.yml` runs `contentops apply --role integration --continue-on-error`. The `--continue-on-error` flag turns per-rule apply failures into warnings instead of a non-zero exit — the workflow still summarises the failed rules in the PR comment and the audit chain still records them, but a single broken envelope doesn't block the rest of the batch (or your merge).

The flag is **only** wired into the integration path. `deploy.yml` (push-to-main, prod role) deliberately leaves it off and fails loud on any per-rule failure — you don't ship a broken rule to prod just because nine other rules in the same merge are fine.

When you see "X rules failed, exit 0" on an integration PR:

1. Read the apply summary in the PR comment — each failure has the rule id and the API error.
2. Fix the offending envelope locally and re-push; the next `integration-deploy.yml` run re-applies just the changed file (`--changed-since` against PR base).
3. If you can't fix it before merge but the rule isn't critical, mark `status: experimental` so production-promotion-check flags it as a non-prod rule rather than letting it sneak into the prod batch.

CLI reference: `contentops apply --help`. Workflow: [`.github/workflows/integration-deploy.yml`](../.github/workflows/integration-deploy.yml).

### Audit chain break

```
contentops audit verify
```

Reports the file:line where the chain broke. Investigate before
"fixing." Usually means someone hand-edited a record (don't), or
two `apply` runs raced (the deploy workflow uses
`concurrency.cancel-in-progress: false` to prevent this).

Recovery + interpretation: [`reference/audit-trail.md`](reference/audit-trail.md).
Full step-by-step recovery runbook: [`operations/audit-recovery.md`](operations/audit-recovery.md).

### Need to silence one rule fast

```
contentops disable <rule-id> --reason "<text>"
```

Sets `status: deprecated` in YAML. Doesn't commit — the workflow
opens a PR for review. Or trigger
[`emergency-disable.yml`](../.github/workflows/emergency-disable.yml)
from the GitHub UI; the workflow needs `confirm=DISABLE` to
proceed.

Doc: [`emergency-disable-workflow.md`](emergency-disable-workflow.md).

### Local tree is stale — pull a fresh copy from the tenant

```
contentops collect --clear --role prod
```

Wipes `detections/<asset_kind>/*.yml` (preserves `templates/` and
`samples/`), then collects fresh from the tenant. Equivalent to
`contentops clean --yes && contentops collect --role prod`. Use
when local state has drifted or you want a clean re-pull rather
than an additive merge.

Long-form: [`operations/collect.md`](operations/collect.md).

### My tenant has more than one Sentinel workspace

```
contentops doctor                              # lists every workspace
contentops apply --role integration --dry-run  # target by role
contentops apply --workspace law-sentinel-int  # target by exact name
```

A tenant with more than one workspace requires `--role` or
`--workspace`. Defender XDR is tenant-scoped — there is no
integration Defender — so `--role integration` skips Defender
content silently. Long-form: [`operations/multi-workspace.md`](operations/multi-workspace.md).

---

## Runbooks — top failure modes, decision trees

The four highest-impact failure modes the operator will hit in the
field. Each tree assumes the operator is on the affected branch
(`git switch main` first if not) and has a working `.env`.

### Runbook 1 — `audit verify` reports a chain break

**Symptom:** `contentops audit verify` exits 1 with
`prev_hash_mismatch` or `record_hash_invalid` at a specific
`audit/<file>.jsonl#L<n>`.

```
1.  contentops audit verify --root .
    └─► note the file:line of the first break.
2.  Open the offending audit/<file>.jsonl at that line in your editor.
3.  Decide what kind of break it is:

    a) The line was hand-edited (or a tool reformatted the file)?
       └─► STOP. The hash chain is the durable record. Restoring is a
           git revert against the audit/ commit that introduced the
           edit; do NOT try to re-compute hashes by hand.
           See: docs/reference/audit-trail.md > "Recovery".

    b) Two ``apply`` runs raced and both wrote into the same JSONL?
       └─► The deploy workflow uses ``concurrency: cancel-in-progress: false``,
           so this should not be possible from CI. If it happened
           locally, drop the duplicate suffix lines, re-verify, commit.

    c) Records appear out of timestamp order but hashes are intact?
       └─► Not a break -- the chain is order-by-prev_hash, not
           order-by-timestamp. ``audit verify`` will pass; the
           ``timestamp`` field is informational. (Tracked as G16.)
```

Reference: [`reference/audit-trail.md`](reference/audit-trail.md),
[`contentops/audit/writer.py`](../contentops/audit/writer.py).

### Runbook 2 — A rule stopped firing in a workspace

**Symptom:** SOC analyst reports zero alerts from a rule that used
to alert. No deploy in flight; rule status is `production` in git.

```
1.  contentops explain <rule-id>
    └─► confirms: envelope status, last apply SHA, last apply time,
        latest audit record, current drift status. If any of those
        is wrong, that's your lead.

2.  contentops silent-rules --since 30
    └─► one-shot list of rules with zero SecurityAlert hits in the
        lookback window. If your rule is on the list, it's a *real*
        silent rule, not a deploy/drift problem.

3.  contentops drift --asset sentinel_analytic --diff
    └─► look for the rule in the CHANGED list. If a portal-side
        edit demoted the rule (e.g. ``enabled: false`` flipped),
        the diff shows the field. Resolve via either:

        contentops drift-resolve <id> --strategy git     # local wins; re-apply
        contentops drift-resolve <id> --strategy remote  # accept the portal edit

4.  Look at the live KQL by running it in the portal advanced-hunting
    blade. If it returns 0 rows there too, the rule is silent because
    the underlying telemetry stopped flowing -- not a pipeline issue.
```

References: [`contentops/cli/commands/diagnostics.py`](../contentops/cli/commands/diagnostics.py)
(explain), [`contentops/cli/commands/silent_rules.py`](../contentops/cli/commands/silent_rules.py),
[`contentops/cli/commands/drift.py`](../contentops/cli/commands/drift.py).

### Runbook 3 — Post-apply hash mismatch (`verified=False`)

**Symptom:** A merge-to-main deploy lands; `apply` reports
``status: success`` but ``verified: false`` for one or more assets.
The audit record carries it as ``status: failed``; the workflow
exit-codes 1.

```
1.  contentops audit query failures --since 1h
    └─► confirms which (asset, id) pairs flipped to verified=False.

2.  For Defender custom detections:
        contentops defender-roundtrip-diff <envelope-id>
    For Sentinel rules:
        contentops sentinel-roundtrip-diff <envelope-id>

    └─► both load the local envelope, fetch the live remote, and
        report which _HASHED_FIELDS paths differ.

3.  Read the diff:

    a) Server-managed field that the stripper doesn't yet know about
       (new ARM/Graph addition)?
       └─► ``--raw`` mode confirms it (skips the strip). File a
           handler patch to extend ``_strip_server_fields``; until
           merged, ``--force-overwrite`` re-applies cleanly.

    b) The local envelope has stale data the API normalised away
       (e.g. trailing whitespace, alternate quoting)?
       └─► re-run ``contentops collect`` for the affected asset and
           commit the canonicalised envelope.

    c) The local envelope is genuinely wrong (operator typo)?
       └─► fix the YAML, ``contentops apply --asset <kind>``.
```

Reference: [`reference/audit-trail.md`](reference/audit-trail.md),
[`contentops/handlers/_verify.py`](../contentops/handlers/_verify.py).

### Runbook 4 — Drift PR shows entries the operator didn't make

**Symptom:** The morning `drift.yml` auto-PR has rows the team did
not edit (in the portal or in git).

```
1.  Open the auto-PR. Each entry has a ``metadata.owner`` line --
    map to a person.

2.  contentops drift --diff --asset <kind>
    └─► field-level diff per CHANGED entry. Three common patterns:

    a) ``enabled`` or ``severity`` flipped?
       └─► someone tuned the rule in the portal. Confirm with the
           owner; either accept (merge the PR) or revert in the portal.

    b) ``serializedData`` (workbook), ``definition`` (playbook), or
       ``query`` changed in trivial ways (whitespace / quoting)?
       └─► API normalisation drift, not a real edit. The handler
           strip is not catching this projection. File a follow-up;
           accept the PR for now.

    c) NEW entries appearing for asset kinds you don't manage?
       └─► someone created the resource in the portal. Decide:
           import it (merge the PR), or delete it from the portal
           and let the next drift PR clear.

3.  contentops drift-resolve <id> --strategy {git|remote}
    └─► per-rule reconciliation when the bulk merge is wrong for a
        specific row. ``--strategy merge`` is reserved (raises
        NotImplementedStrategy by design -- pick git or remote).
```

Reference: [`operations/collect.md`](operations/collect.md),
[`contentops/cli/commands/drift.py`](../contentops/cli/commands/drift.py),
[`contentops/drift_resolve.py`](../contentops/drift_resolve.py).

---

## Authoring a new detection from scratch

The 8-step playbook from KQL idea → production rule.

```
1.  Draft the KQL in the Sentinel / Defender portal advanced-hunting
    blade. Iterate against real telemetry until the result set is
    actionable. Aim for < 20 rows / day at production volume.

2.  Decide the asset kind:
      sentinel_analytic           - scheduled or NRT alert
      sentinel_hunting            - investigative query, no alert
      defender_custom_detection   - cross-engine MDE rule
      sentinel_parser             - reusable function for other queries
      sentinel_watchlist          - reference data
      sentinel_data_connector     - backend ingest binding

    ``contentops new`` scaffolds the first five. sentinel_data_connector
    is collected from the tenant (``contentops collect``), not authored
    from a template, so there is no ``new`` template for it.

3.  Scaffold the envelope:

      contentops new <asset-kind> <kebab-id>

    Edit the rendered YAML: paste the KQL into ``payload.query``,
    set ``payload.displayName``, fill ``metadata.severity``,
    ``metadata.tactics`` / ``techniques``, ``metadata.owner``,
    ``metadata.fpHandling`` (a one-line operator note for the
    triage team), ``metadata.expectedAlertsPerDay`` (best estimate).

4.  Lint locally:

      contentops lint --asset <kind> --strict

    Fix every error. Common surprises:
      KQL001  unbalanced bracket - check your inline JSON
      KQL002  unterminated string - look for missing close-quote
      KQL004  project * - project explicit columns instead
      KQL007  union *  - replace with explicit table list
      KQL101  | take / | limit  - use ``top N by`` for bounded results
      PAYLOAD001  templateVersion without alertRuleTemplateName
      PAYLOAD002  displayName slug > 80 chars (advisory)

5.  Plan locally:

      contentops plan --path detections/<kind>/<id>.yml

    Confirms validate() + plan() pass. No API calls.

6.  Open the PR. ``validate.yml`` + ``coverage.yml``
    run; ``integration-deploy.yml`` deploys the rule to your
    integration workspace if one is configured. Watch the PR
    comments for the integration apply summary -- if the rule
    breaks at the API, you find out before merge.

7.  Merge. ``deploy.yml`` runs ``apply --role prod --changed-since
    <prev-SHA>`` and writes one audit record per asset. Watch the
    workflow tail for ``verified=true`` on your rule; an unverified
    rule fails the deploy.

8.  Drift watch. Tomorrow's ``drift.yml`` PR should show your rule
    as ``in-sync``. If it shows up as ``changed``, work Runbook 4
    above before assuming the rule is broken.
```

Tip: every command above is in the generated catalog at
[`reference/generated-catalog.md`](reference/generated-catalog.md)
(drift-pinned by CI; refresh with ``contentops catalog regenerate``).

### Promoting to `status: production` (including mid-incident hotfixes)

The playbook above authors at `status: experimental`. To flip a rule to
`production`, run:

```
contentops lifecycle promote <rule-id>
```

It runs the promotion gates and writes the `lifecycle.promotedAt` /
`lifecycle.promotedBy` stamp. **A direct YAML edit of `status:
production` — even a fast incident hotfix — fails the
`production-promotion-check` (red ✗ on the PR)** because it carries no
fresh stamp (the script hard-exits 1; see the workflow row in
[`reference/feature-catalog.md`](reference/feature-catalog.md)). The fix
is always to promote through the CLI so the stamp is written. If a gate
would otherwise block a genuine emergency, use `contentops lifecycle
promote <rule-id> --force` and record the reviewer approval out-of-band —
do **not** hand-edit `status` to dodge the check.

---

## `metadata.runbookUrl` convention

`RuleMetadata.runbookUrl` is an optional URL field on every detection
envelope ([`contentops/core/metadata.py`](../contentops/core/metadata.py)).
The pipeline does not enforce a runbook -- it is operator-team
policy. The convention below makes the field useful when SOC
analysts open the alert.

**When to set it.** Required for any rule with `metadata.severity`
of `medium` or higher (per team policy). Optional for `info` and
`low` -- but encouraged whenever the triage step is non-obvious.

**What a runbook should contain (minimum useful).**

1. **Symptom** -- one sentence: what the alert means in plain
   English. ("Account X attempted N failed sign-ins from a single
   IP within M minutes.")
2. **Decision tree** -- 3-5 branches: is this a known service
   account / known scanner / new geography / privileged role?
   Each branch ends in an action.
3. **Escalation criteria** -- when this leaves Tier 1 and goes to
   IR. Include severity ramp triggers ("if MFA is also failing → IR").
4. **Rollback / contain procedure** -- the one-shot CLI/portal
   action to lock the account, kill the session, etc.
5. **Tuning guidance** -- if the rule keeps producing FPs from a
   specific source, the runbook author should update
   `metadata.fpHandling` instead of hand-fixing it case-by-case.

**Naming convention for URLs.**

* **Internal team wiki** (Confluence, Notion, GitHub Pages):
  `https://wiki.example.com/runbooks/<rule-id>`. The
  `<rule-id>` is the envelope id (kebab-case slug). One runbook
  per rule, named after the rule -- avoids "which runbook does
  this alert mean?"
* **External vendor** (Microsoft, MITRE):
  use the vendor URL directly. Permitted but discouraged -- vendor
  URLs are not under the team's edit control.
* **GitHub link** to a markdown file in this repo (under e.g.
  `docs/runbooks/<rule-id>.md`):
  `https://github.com/<your-org>/<your-repo>/blob/main/docs/runbooks/<rule-id>.md`.
  Acceptable when the runbook is short enough to live in git; the
  path stays stable across renames as long as the markdown file
  follows the rule slug.

**Auditability.**

The runbookUrl appears in every drift PR row + every audit record's
envelope summary. SOC managers reviewing
[`reference/feature-catalog.md`](reference/feature-catalog.md) for
governance evidence can grep for missing or stale runbook URLs.

---

## Doc index

### Get started

- [`onboarding.md`](onboarding.md) — Day-1 setup for analysts.
- [`operations/authentication-setup.md`](operations/authentication-setup.md) — **first-timer primer** for Azure App Registration + OIDC federated credentials. Read before onboarding if it's your first Azure pipeline.
- [`development/local-testing.md`](development/local-testing.md) — `.env`, RBAC, pre-flight checks.
- [`development/live-integration-tests.md`](development/live-integration-tests.md) — live Azure validation commands for PowerShell and bash.

### Daily reference

- [`reference/generated-catalog.md`](reference/generated-catalog.md) — **generated**, drift-pinned in CI: every Click command, asset, lint rule, handler, workflow, test file. Refresh via `contentops catalog regenerate`.
- [`reference/feature-catalog.md`](reference/feature-catalog.md) — curated narrative: every shipped feature with workflow + tests + per-feature doc.
- [`reference/asset-coverage.md`](reference/asset-coverage.md) — per-asset endpoint, RBAC, hash projection, live-test status.
- [`reference/cli-workflow-matrix.md`](reference/cli-workflow-matrix.md) — CLI ↔ workflow mapping.
- [`reference/test-catalog.md`](reference/test-catalog.md) — every test file, what it covers, how to run it.
- [`reference/audit-trail.md`](reference/audit-trail.md) — JSONL schema, query examples, retention policy.

### Architecture + design

- [`reference/architecture.md`](reference/architecture.md) — handler protocol, envelope schema, audit + state, end-to-end flow.
- [`reference/envelope-schema.md`](reference/envelope-schema.md) — canonical reference for every envelope/metadata field, lint rules guarding each, and the FalconFriday worked example.
- [`../DESIGN.md`](../DESIGN.md) — full design doc (1100+ lines). Long.

### Operations

- [`operations/authentication-setup.md`](operations/authentication-setup.md) — Azure App Registration + OIDC walkthrough. First-timer-friendly; TL;DR up top for the experienced.
- [`operations/tenant-config-modes.md`](operations/tenant-config-modes.md) — the three supported `tenant.yml` layouts (committed / secret / vars+secrets) and the `policy.scaffoldStrict` flag.
- [`operations/collect.md`](operations/collect.md) — pulling live state (`--clear`, `--role`).
- [`operations/multi-workspace.md`](operations/multi-workspace.md) — single tenant, N Sentinel workspaces; OIDC federated credentials; per-role CLI selection.
- [`operations/prune.md`](operations/prune.md) — deletion-as-code.
- [`operations/prod-to-int-mirror.md`](operations/prod-to-int-mirror.md) — wipe + collect + apply workflow to mirror prod into integration; tombstone window guidance and retry-failed recovery.
- [`emergency-disable-workflow.md`](emergency-disable-workflow.md) — break-glass single-rule disable.

### Per-asset

- [`assets/README.md`](assets/README.md) — index of per-asset deep-dives.
- [`assets/sentinel_alert_rules.md`](assets/sentinel_alert_rules.md), [`assets/sentinel_extras.md`](assets/sentinel_extras.md), [`assets/sentinel_watchlist_sas.md`](assets/sentinel_watchlist_sas.md) — Sentinel kinds.
- [`assets/defender_graph_extensions_deferred.md`](assets/defender_graph_extensions_deferred.md) — Defender Graph endpoints not yet GA.

### Alert tracking

- [`onboarding.md#day-2--alert-tracking-optional`](onboarding.md#day-2--alert-tracking-optional) — setup guide for alert sync, health, and unified reporting.

### Strategy

- [`reference/gap-assessment.md`](reference/gap-assessment.md) — what the pipeline does NOT do (yet). Honest.
- [`reference/roadmap.md`](reference/roadmap.md) — proposed features. Discussion document.

### Top-level

- [`../README.md`](../README.md) — 1-paragraph what+why.
- [`../CONTRIBUTING.md`](../CONTRIBUTING.md) — how to PR.
- [`../SECURITY.md`](../SECURITY.md) — how to report vulnerabilities.
- [`../CLAUDE.md`](../CLAUDE.md) — project context for AI assistants.

---

## Vocabulary cheat sheet

(Full definitions in [`reference/architecture.md`](reference/architecture.md#vocabulary).)

- **Envelope** — the YAML wrapper around an API payload (id,
  version, asset, status, metadata).
- **Asset kind** — typed enum naming what the envelope represents
  (e.g. `sentinel_analytic`).
- **Handler** — class that knows validate / plan / apply / delete
  for one asset kind.
- **Provider** — thin HTTP wrapper around ARM or Graph.
- **Drift** — read-only compare of remote tenant ↔ local YAML.
- **`metadata.runbookUrl`** — optional URL on every envelope; SOC
  analyst's link target when the alert fires. Convention:
  required for `severity ≥ medium`, see "metadata.runbookUrl
  convention" above.

---

## Don't-do-this list

The full list with reasons is in [`onboarding.md`](onboarding.md#dont-do-this).
TL;DR:

- Don't force-push to `main`.
- Don't run `contentops apply` against production from a feature
  branch.
- Don't commit `.env`.
- Don't edit a rule directly in the portal without a follow-up
  drift PR.
- Don't pass `--no-audit` or `--skip-deps-check` in CI.
- Don't hand-edit `audit/*.jsonl`.
