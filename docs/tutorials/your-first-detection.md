# Your first detection — end-to-end tutorial

> **Audience:** an analyst or detection engineer who has installed
> ContentOps and configured `config/tenant.yml`. If you haven't done
> that yet, work through [`docs/quickstart.md`](../quickstart.md)
> first — it covers clone, venv, credentials, and `doctor`.

By the end of this tutorial you will have:

1. Scaffolded a Sentinel analytic rule envelope from scratch.
2. Linted it and fixed any issues.
3. Run a pre-flight plan against the live tenant.
4. Deployed it to your integration workspace.
5. Verified it in the Azure portal.
6. Optionally promoted it to production.

Estimated time: **20–30 minutes** for the first run; ~5 minutes for
subsequent rules once the muscle memory is there.

> **Prerequisite check.** Before you start, confirm `contentops
> doctor --matrix` is fully green. If anything is FAIL or WARN,
> work through [`troubleshooting.md`](../troubleshooting.md) first
> — most blockers are auth / config issues with quick fixes.

---

## Step 1 — pick what you're detecting

Don't write a rule because you can. Start with a question:

> "What attacker behaviour do I want an alert for that I'm
> currently NOT alerting on?"

For this tutorial we'll detect **a user adding themselves to a
high-privileged Azure AD role** — a Defense Evasion / Privilege
Escalation tell. The MITRE technique is `T1098.003` (Account
Manipulation: Additional Cloud Roles).

> If you already know what you want to detect, substitute your own
> idea throughout. The mechanics are identical.

Check that nothing in your current corpus already covers it:

```powershell
contentops coverage --gaps | grep -i "T1098"
```

If `T1098.003` shows in the *covered* list, somebody beat you to it
— pick another technique. Otherwise, continue.

---

## Step 2 — scaffold the envelope

`contentops new` generates a syntactically-valid envelope with the
right shape for the asset kind. You'll fill in the content:

```powershell
contentops new sentinel_analytic detect-self-elevation-to-privileged-role `
  --name "User self-elevation to privileged AAD role"
```

> The **id** (`detect-self-elevation-to-privileged-role`) is the
> kebab-case slug that identifies the envelope across the codebase
> and the audit trail. Keep it short, unique, and stable — renaming
> later is a coordinated change.

The command writes to
`detections/sentinel_analytic/detect-self-elevation-to-privileged-role.yml`.
Open it in your editor:

```powershell
notepad detections\sentinel_analytic\detect-self-elevation-to-privileged-role.yml
```

You'll see a Pydantic-validated template. The fields you must
fill in are:

```yaml
id: detect-self-elevation-to-privileged-role
version: 0.1.0
asset: sentinel_analytic
status: experimental        # start here; promote later
lifecycleStage: engineering # optional, for dashboards

metadata:
  owner: you@example.com
  runbookUrl: https://runbooks.example.com/<your-runbook-slug>
  severity: high
  tactics: [PrivilegeEscalation, DefenseEvasion]
  techniques: [T1098.003]
  defensiveTechniques: [D3-UBA]   # User Behavior Analysis (optional)
  expectedAlertsPerDay: 0
  fpHandling: |
    Common false positives: a Global Administrator legitimately
    assigning a role to themselves during an audited break-glass
    procedure. Cross-reference the actor against the
    `entraprivilegedgroups` watchlist before triaging.

  # Optional but recommended:
  description: |
    Detects when a user assigns themselves to a high-privileged
    Azure AD role (Global Administrator, Privileged Role
    Administrator, Application Administrator, etc.) without an
    approval workflow.
  attackDescription: |
    Adversaries who compromise an account with role-assignment
    privileges (often via OAuth consent or session hijack) will
    promote themselves to broader access before pivoting. This is
    a high-signal sign of an insider threat or a fully-realised
    cloud account takeover.
  references:
    - https://attack.mitre.org/techniques/T1098/003/
    - https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning
  falsePositives:
    - Global Administrators legitimately self-assigning during a
      documented break-glass procedure.
    - Approved Privileged Identity Management (PIM) elevation
      events that didn't go through the activation portal.
  blindSpots:
    - Roles assigned via PIM directly (these don't appear in
      AuditLogs as "Add role assignment" events).
    - Roles assigned by a service principal acting on behalf of the
      user.
  responseActions:
    - Review the user's last 24h sign-in IPs for impossible-travel
      anomalies.
    - Check for prior `Add app role assignment to service principal`
      events from the same actor.
    - If the role is Global Admin, treat as a P1 and engage the
      incident response runbook.

payload:
  displayName: User self-elevation to privileged AAD role
  enabled: true
  severity: High
  query: |
    AuditLogs
    | where OperationName == "Add member to role"
    | where Result == "success"
    | extend Actor = tostring(InitiatedBy.user.userPrincipalName)
    | extend Target = tostring(parse_json(TargetResources)[0].userPrincipalName)
    | extend RoleName = tostring(parse_json(TargetResources)[0].modifiedProperties[1].newValue)
    | where Actor == Target
    | where RoleName has_any (
        "Global Administrator",
        "Privileged Role Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Privileged Authentication Administrator"
      )
    | project TimeGenerated, Actor, RoleName, Result, CorrelationId
  queryFrequency: PT5M
  queryPeriod: PT5M
  triggerOperator: GreaterThan
  triggerThreshold: 0
  suppressionDuration: PT1H
  suppressionEnabled: false
  tactics: [PrivilegeEscalation, DefenseEvasion]
  techniques: [T1098.003]
  subTechniques: []
  entityMappings:
    - entityType: Account
      fieldMappings:
        - identifier: FullName
          columnName: Actor
  incidentConfiguration:
    createIncident: true
    groupingConfiguration:
      enabled: false
      reopenClosedIncident: false
      lookbackDuration: PT5H
      matchingMethod: AllEntities
```

A few notes for the curious:

- **`status: experimental`** keeps the rule out of production
  workspaces (env-status gate). You promote later.
- **`expectedAlertsPerDay: 0`** is the operator's signal that this
  rule should be rare; values > 5 trigger META009 noise warnings
  when paired with high severity.
- **`techniques`** is parsed by `contentops coverage` for the
  ATT&CK heatmap; **`defensiveTechniques`** feeds
  `contentops coverage --d3fend`.
- **`falsePositives`** + **`blindSpots`** + **`responseActions`**
  feed the `docs/detections/` per-rule page that
  `contentops detection-docs regenerate` produces.

---

## Step 3 — lint

```powershell
contentops lint --strict --path detections
```

Read the output. With the metadata block above filled in, you
should see at most a few warnings (e.g. PAYLOAD002 if your
displayName slug exceeds 80 chars). Address each:

- **KQL errors** → fix the query.
- **PAYLOAD warnings** → adjust as suggested.
- **META warnings** → fill the missing metadata field (your
  envelope was authored fully, so you shouldn't see META002–005;
  if you do, you missed a paragraph).

> If you see hundreds of META errors on rules you didn't touch,
> that's the G24 backlog showing through. See
> [`troubleshooting.md`](../troubleshooting.md#600-meta002005-errors-on-a-fresh-tenantyml)
> for the `scaffoldStrict` knob.

Run lint until it's clean for *your* rule (other warnings are
pre-existing backlog).

---

## Step 4 — plan against the tenant

The static plan tells you the rule parses and would deploy:

```powershell
contentops plan --asset sentinel_analytic --changed-since main
```

But the *live preview* — what apply will actually do — uses the
`--against-tenant` overlay:

```powershell
contentops plan --against-tenant --role integration --changed-since main
```

You should see:

```
Against-tenant overlay (closes G17):
  CREATE: 1   UPDATE: 0   NO-CHANGE: ...   ORPHAN-IN-TENANT: 0
```

Your new rule is the CREATE. If you see UPDATE instead, the id
already exists in the integration workspace — pick a unique id.

---

## Step 5 — apply to integration

Start with a dry run to be sure:

```powershell
contentops apply --role integration --dry-run --changed-since main
```

Read the per-rule summary. If your rule shows `dry-run` and no
other rules show errors, you're good. Real deploy:

```powershell
contentops apply --role integration --changed-since main
```

Expected output:

```
  create: detect-self-elevation-to-privileged-role
  ...
Apply summary:
  ...
  detect-self-elevation-to-privileged-role  sentinel_analytic  create  success  ok
```

`success` means the PUT succeeded; `ok` (the `verified` column)
means the round-trip hash matched (no server-side surprise
mutation). If you see `MISMATCH`, run
`contentops sentinel-roundtrip-diff <id>` to see which fields the
server changed.

The deploy wrote a record to `audit/<today>.jsonl`:

```powershell
contentops audit query latest --since 5m
```

Your rule should appear with `action: create`, `status: success`.

---

## Step 6 — verify in the Azure portal

Go to the Azure Sentinel portal → Analytics → Active rules. Search
for "User self-elevation to privileged AAD role". You should see:

- The rule listed with status **Enabled**
- Severity **High**
- The query you authored (read-only in the portal — edits would
  show up as drift on the next scheduled `drift.yml` run)
- Tactics / Techniques tags matching what you put in
  `payload.tactics` / `payload.techniques`

If the rule isn't there after 60 seconds, see
[`troubleshooting.md`](../troubleshooting.md#integration-deploy-succeeded-but-rules-dont-appear-in-the-portal).

---

## Step 7 — wait for the first signal (optional)

Your rule is now running every 5 minutes against the last 5
minutes of `AuditLogs`. If a test event fires (e.g. you assign
yourself a privileged role in a dev tenant), you'll see:

- A new `SecurityAlert` row appear within ~6 minutes.
- A `SecurityIncident` row when grouped (depending on your
  configuration).

You can sanity-check coverage:

```powershell
contentops navigator --since 30 --out my-coverage.json
# Upload my-coverage.json to https://mitre-attack.github.io/attack-navigator/
```

Your new technique tile (T1098.003) should now be highlighted in
the Navigator UI.

---

## Step 8 — commit and PR

```powershell
git checkout -b feat/detect-self-elevation
git add detections/sentinel_analytic/detect-self-elevation-to-privileged-role.yml
contentops detection-docs regenerate    # generates docs/detections/sentinel_analytic/<id>.md
git add docs/detections/
git commit --signoff -m "feat(detect): self-elevation to privileged AAD role (T1098.003)"
git push -u origin feat/detect-self-elevation
gh pr create --title "feat(detect): self-elevation to privileged AAD role"
```

When the PR opens:

- `validate.yml` runs strict lint + version-bump check + URL
  link-rot check (on the URLs you added).
- `coverage.yml` posts a sticky comment showing your new technique
  in the heatmap.
- `drift-pr` (in `drift.yml`) runs a read-only drift report; for a
  brand-new rule it should show your envelope as "new in repo"
  relative to integration (which is what integration-deploy
  already created).
- `integration-deploy.yml` runs apply against integration with
  `--continue-on-error` (so other people's broken PRs don't block
  yours).

After review and merge:

- `deploy.yml` fires on the push to main, applies your rule to
  prod, writes the audit record, and pushes the updated
  `state/state.json` to the orphan-branch ref.

---

## Step 9 — promote to production

When your rule has been firing reliably in integration for a week
or two and the FP rate is acceptable, promote it to `status:
production`:

```powershell
contentops lifecycle promote detect-self-elevation-to-privileged-role
```

This runs four gates:

| Gate | What it checks |
|---|---|
| `status_is_experimental` | The current status is `experimental` (you can't promote a `deprecated` rule directly). |
| `recent_validation` | `metadata.lastValidatedAt` is within 30 days (you need to have eyeballed the rule recently). |
| `live_test_pass` | DEFERRED (F2 — Python KQL evaluator parked); always passes. |
| `fp_rate_threshold` | If `--workspace-id` is set, computes `closed_fp_30d / incidents_30d`; fails the gate if above `config/lifecycle.yml`'s threshold (default 0.5). |

If all gates pass, the command flips `status: experimental` → `status:
production` in your YAML and stamps `lifecycle.promotedAt` /
`lifecycle.promotedBy`. Commit + PR + merge as usual.

> Use `--force` only with reviewer approval recorded out-of-band
> (PR comment, audit log message). The gates exist for a reason.

---

## You're done.

You've authored, deployed, verified, and promoted a real detection.

Next steps for getting fluent:

- Read [`docs/OPERATOR_GUIDE.md`](../OPERATOR_GUIDE.md) for the
  day-to-day operations flow and the deep-dive runbooks.
- Skim [`docs/reference/envelope-schema.md`](../reference/envelope-schema.md)
  to learn the full envelope surface (cohorts, lifecycle stages,
  Section T metadata, etc.).
- Look at existing rules under `detections/sentinel_analytic/` to
  borrow patterns for your next detection.

If you got stuck anywhere in this tutorial, please file an issue —
or, better, open a PR fixing the gap. Detection content is the
work; the tooling is supposed to get out of your way.
