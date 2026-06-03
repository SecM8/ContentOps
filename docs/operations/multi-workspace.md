# Multi-workspace operator guide

> Part of **ContentOps powered by SecM8**. Companion to
> [DESIGN §6](../../DESIGN.md#6-multi-environment-model-v3--single-tenant-multi-workspace).
> Read that first for the model. This doc covers the day-to-day
> operations: how to add a workspace, how to target one from the CLI,
> and what each workflow expects.
>
> Where this guide quotes literal Azure OIDC federated-credential
> values (e.g. the `Repository: <your-repo>` field below), those
> strings are part of the Azure App Registration contract and must
> match the repository's GitHub name verbatim — for the public
> reference deployment that's `ContentOps`; for your fork it's
> whatever you named the repo on GitHub.

## Do I need this page?

**Read this if:** you want more than one Sentinel workspace — for
example a `dev` sandbox, an `integration` workspace for PR validation,
and a `prod` workspace where alerts actually fire.

**Skip this if:** you have one Sentinel workspace (or are
Defender-only). `contentops apply --role prod` will target it
automatically, and the workflows default to prod when no `--role`
flag is given. Come back here when you decide to add a second
workspace.

If you haven't created the App Registration yet, do
[`authentication-setup.md`](authentication-setup.md) first — every
workspace you add must trust the same App Registration.

## TL;DR — the mental model

* **One tenant = one Entra ID tenant.** Configured in `config/tenant.yml`.
* **A tenant has 0–1 Defender XDR.** Defender is tenant-scoped.
* **A tenant has 0–N Sentinel workspaces.** Each workspace is tagged
  with a `role`: `prod`, `integration`, or `dev`.
* **Identity is in env vars, not in `tenant.yml`.** Local: `.env`.
  CI: GitHub Actions Variables (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`)
  + OIDC federated credentials.

## Adding an integration workspace

1. **Create the workspace in Azure** in any subscription within the
   same Entra ID tenant. The pipeline is single-tenant by design — every
   Sentinel workspace listed in `tenant.yml` MUST live in the same
   Entra ID tenant as the App Registration. (An integration workspace in
   a different Entra ID tenant would break the OIDC trust boundary; the
   federated credential is scoped to one issuer/audience per app
   registration.)
2. **Grant the App Registration permission.** The same App Registration
   used for prod can target the integration workspace; assign
   `Microsoft Sentinel Contributor` (and `Log Analytics Contributor`)
   on the integration RG. Full role list +
   `az role assignment create` examples in
   [`authentication-setup.md` step 2](authentication-setup.md#step-2-grant-the-app-registration-its-permissions).
3. **Add the OIDC federated credential** for the new environment. Walk
   through
   [`authentication-setup.md` step 3](authentication-setup.md#step-3-add-an-oidc-federated-credential-for-ci)
   with **GitHub environment name** = `integration` (instead of
   `production`). Same App Registration; new federated credential
   row.
4. **Append the workspace to `config/tenant.yml`:**

   ```yaml
   tenant:
     name: production-tenant
     tenantId: "..."
     defender:
       enabled: true
     sentinelWorkspaces:
       - role: prod
         subscriptionId: "..."
         resourceGroup: rg-sentinel
         workspaceName: law-sentinel
         location: westeurope
       - role: integration             # ← new
         subscriptionId: "..."
         resourceGroup: rg-sentinel-int
         workspaceName: law-sentinel-int
         location: westeurope
   ```

5. **Verify locally:**

   ```bash
   contentops doctor                                # tenant_yml check should list both
   contentops config list-workspaces                # both workspaces appear in the table
   contentops plan --role integration               # should select law-sentinel-int
   contentops apply --role integration --dry-run    # should select law-sentinel-int
   ```

6. **Push.** The next PR with `detections/**` changes will trigger
   `integration-deploy.yml` and apply to the integration workspace.

## CLI cheat sheet

| Want to... | Command |
|---|---|
| Validate `tenant.yml` parses + summarise engines | `contentops config validate` |
| Fail-fast on an empty tenant (CI gate) | `contentops config validate --strict` |
| List configured Sentinel workspaces (table / JSON / CSV) | `contentops config list-workspaces [--format json\|csv]` |
| Plan against a specific role | `contentops plan --role integration` |
| Plan against a workspace by exact name | `contentops plan --workspace law-sentinel-int` |
| Apply changed detections to every prod workspace | `contentops apply --role prod --changed-since main` |
| Apply to integration only | `contentops apply --role integration --dry-run` |
| Target one specific workspace by name | `contentops apply --workspace law-sentinel-int` |
| Drift-check against a specific workspace | `contentops drift --role prod` (or `--workspace <name>`) |
| Test a rule against a sandbox workspace | Add a `role: dev` workspace, then `--role dev` |
| Inspect everything (including auth + handlers) | `contentops doctor` (shows the active tenant + every Sentinel workspace) |

### Inspecting config

`contentops config validate` parses `tenant.yml` (env-aware via `PIPELINE_ENV`) and prints a one-line engine summary:

```
tenant=production-tenant, sentinel_workspaces=2 [prod:law-sentinel, integration:law-sentinel-int], defender=enabled
```

It exits 1 on parse / schema errors (legacy single-workspace shape, duplicate workspace names, missing required fields). It exits 0 on a valid-but-degenerate config (zero workspaces AND Defender disabled), printing a `WARN` line — pass `--strict` to make CI fail-fast on that case.

`contentops config list-workspaces` prints the configured Sentinel workspaces. `--format json` / `--format csv` give scriptable output. A Defender-only tenant (zero workspaces) prints "no Sentinel workspaces configured" — that is a valid configuration, not an error.

## Workflow flow

| Trigger | Workflow | Role used | What happens |
|---|---|---|---|
| PR with changes to `detections/**` | `integration-deploy.yml` | `integration` | Deploys changed YAML to integration workspaces. **Skips silently** if no integration workspace exists in `tenant.yml`. |
| Push to `main` with changes to `detections/**` | `deploy.yml` | `prod` | Deploys changed YAML to prod workspace(s). |
| Manual prod-→-integration snapshot | `promote-to-integration.yml` | n/a (uses `--env`) | Snapshots prod and applies to a **separate** integration tenant (`config/tenant.integration.yml`). **Skips gracefully** (exit 0) when no separate integration tenant is configured — redundant with `integration-deploy.yml` for single-`tenant.yml` setups. |

### No integration workspace? Nothing fails.

A tenant is **not required** to have a `role: integration` workspace. When one is
absent, the pipeline **skips gracefully** rather than failing:

* `integration-deploy.yml` detects the missing workspace and skips (green).
* `contentops drift` / `collect` / `prune` / `rollback` / `plan` / `apply`
  with `--role integration` print `no Sentinel workspace with role=integration
  — skipping` and exit 0. The skip is scoped to `integration` only — a missing
  `prod` workspace still hard-fails, as it should.
* `promote-to-integration.yml` skips when no separate integration tenant
  (`TENANT_CONFIG_INTEGRATION_YAML` / `config/tenant.integration.yml`) exists.

> **Future:** instead of a separate integration workspace, deploy `status: test`
> content to the **prod** workspace with **incident creation disabled** (shadow
> mode) — a single-workspace way to validate detections live before they create
> incidents. Not yet implemented.

### CD workflow workspace selection

The `deploy.yml` and `integration-deploy.yml` workflows accept an
optional **`workspace`** `workflow_dispatch` input. Set it to a
specific workspace name (matching `workspaceName` in `tenant.yml`)
to target one workspace explicitly when a role matches more than
one:

* **Empty (default)** — the workflow uses `--role prod` /
  `--role integration` and iterates every matched workspace.
* **Set to a name** — the workflow drops the `--role` flag and
  passes `--workspace <name>` instead. The CLI's
  `--role`/`--workspace` mutex enforces exactly one selector at
  a time.

Use cases:
* Target one specific prod workspace for a hotfix (e.g.
  `deploy.yml` with `workspace: law-prod-eu` when only the EU
  workspace needs the change).
* Validate against one specific integration workspace before
  promoting (e.g. `integration-deploy.yml` with
  `workspace: law-int-staging` when there are multiple
  integration workspaces).

Push-to-`main` runs of `deploy.yml` (the auto-trigger path) always
iterate every prod workspace — the input is `workflow_dispatch`
only. Pull-request runs of `integration-deploy.yml` also always
iterate every integration workspace; the workspace input is
ignored on the PR-trigger path.

`promote-to-integration.yml` does NOT yet accept a `workspace`
input — its bootstrap step reads `tenant.integration.yml` in the
v2 single-workspace schema. Adding multi-workspace support there
requires migrating that config file to the v3 schema first;
tracked as a separate workstream.

## Engine selection — both Sentinel and Defender are optional

A tenant may configure either engine, both, or neither. The runtime
gates handler registration on the engine config so a tenant only pays
for engines it actually deploys to.

| # | Sentinel workspaces | Defender | Behaviour |
|---|---|---|---|
| 1 | 0 | enabled | **Defender-only tenant.** Sentinel handlers don't register; Sentinel envelopes in `detections/` are filtered with an info line. `--role` / `--workspace` are no-ops with an "ignored" message. `defender-extensions-probe` runs normally. |
| 2 | ≥ 1 | disabled / absent | **Sentinel-only tenant.** Defender handler doesn't register; Defender envelopes in `detections/` are filtered with an info line. `defender-extensions-probe` exits 0 with a skip message. |
| 3 | ≥ 1 | enabled | **Both engines.** Default; nothing is filtered or skipped. |
| 4 | 0 | disabled / absent | **Empty tenant.** Schema-valid but operationally degenerate. `config validate` warns; `config validate --strict` exits 1. |

Switch between configurations by editing `config/tenant.yml`:

```yaml
# Defender-only:
tenant:
  name: defender-only
  tenantId: ...
  defender:
    enabled: true
  sentinelWorkspaces: []
```

```yaml
# Sentinel-only (Defender explicitly disabled):
tenant:
  name: sentinel-only
  tenantId: ...
  defender:
    enabled: false
  sentinelWorkspaces:
    - role: prod
      ...
```

```yaml
# Sentinel-only (Defender block omitted entirely; equivalent):
tenant:
  name: sentinel-only
  tenantId: ...
  sentinelWorkspaces:
    - role: prod
      ...
```

Defender XDR is tenant-level — there is **no integration Defender
XDR**. `apply --role integration` skips Defender content with a
`[defender:prod-only]` note in the env-status filter output even
when the tenant has Defender enabled.

## Per-workspace KQL snippets (`overrides/`)

A detection's KQL can embed placeholders of the form
`{{folder/file.yml}}` (`\` accepted on Windows; the resolver
normalises to `/` internally). At plan / apply time the substitution
engine picks one of three outcomes per placeholder:

1. **`overrides/<workspaceName>/<path>` exists** — its `content` is
   spliced in.
2. **Workspace-specific missing, `overrides/<path>` exists** — the
   generic `content` is spliced in.
3. **Both missing** — the **entire line** containing the placeholder
   is dropped.

The same snippet file may be referenced by many rules — that's the
point. One `common/domainadmins.yml` referenced by every "domain
admin activity" rule; one workspace-specific
`law-prod/001/excludedusers.yml` overriding the generic
`001/excludedusers.yml` only for the prod workspace.

### Disk layout

```
overrides/
├── common/
│   └── domainadmins.yml             # generic; shared across workspaces and rules
├── 001/
│   └── excludedusers.yml            # generic; shared across workspaces, "001" cohort
├── law-prod/                        # mirrors any subset of the generic tree
│   └── 001/
│       └── excludedusers.yml        # workspace-specific override
└── law-int/
    └── common/
        └── domainadmins.yml         # workspace-specific override
```

### Snippet file format

```yaml
# overrides/001/excludedusers.yml
description: "Comma separated array of users excluded from the rule"
content: |-
  "alice@corp", "bob@corp", "service-acct@corp"
```

* `content` (required, string) — the literal text spliced where the
  placeholder appears. Use a `|-` block scalar for multi-line snippets.
* `description` (optional, string) — operator-facing documentation.
  Never substituted.

CRLF in `content` is normalised to LF before substitution so Windows
and *nix authors produce identical deploy bytes.

### Two placeholders on the same line

`KQLOVERRIDE003` allows multiple `{{...}}` placeholders on a single
line as long as nothing else (besides whitespace and a trailing
`//` comment) is on that line. **If any one placeholder fails to
resolve on both tiers, the whole line is dropped — including the
sibling placeholders that DID resolve.** That's an intentional
consequence of the line-removal fallback being line-level, not
token-level. Operators who want partial-resolution semantics should
put each placeholder on its own line.

### Audit trail (workspace + snippet_digest)

Every audit record written by `apply` carries two extra fields when
multi-workspace deploys are in play:

* `workspace` — the Sentinel workspace name the record describes
  (`null` when the apply ran without a `--role` / `--workspace`
  selector, or for tenant-scoped Defender records).
* `snippet_digest` — SHA-256 of the substituted KQL fields, hex-
  encoded. `null` when no substitution happened. Lets post-incident
  replay distinguish two records that share `(asset, id)` but were
  deployed with different snippet bodies to different workspaces.

The hash chain extends across the schema bump cleanly — `audit
verify` recomputes per-record hashes from the on-disk JSON dict, so
records written before these fields existed continue to verify
without modification.

### Hard rule: placeholder must be alone on its line (`KQLOVERRIDE003`)

The both-missing fallback (rule 3 above) drops the entire line
containing the placeholder. To make that fallback safe for
surrounding KQL, the placeholder MUST be the only non-whitespace
token on its line. The `lint --strict` rule `KQLOVERRIDE003`
enforces this.

**Bad:**

```kql
SecurityEvent
| where User in ({{001/excludedusers.yml}})    // ✗ KQLOVERRIDE003
| where EventID == 4625
```

If the override file is missing on both paths, the entire `| where
User in (...)` line is removed — but the surrounding `| where
EventID == 4625` line stays, leaving syntactically valid KQL. That
only works because the placeholder is on its own line:

**Good:**

```kql
SecurityEvent
| where EventID == 4625
| where User in (
    {{001/excludedusers.yml}}
)
```

A trailing `// ...` line comment is tolerated:

```kql
{{001/excludedusers.yml}}  // exclusion list, see overrides/001/
```

### Other lint rules

* `KQLOVERRIDE001` — placeholder must match exactly
  `{{folder/file.yml}}` (no surrounding spaces, `.yml` required).
* `KQLOVERRIDE002` — the path must be relative, with no `..`
  segments and no leading `/` or `\`. Defends against path traversal.
* `KQLOVERRIDE004` — every file under `overrides/**/*.yml` must
  parse as YAML and contain a `content:` (string) key.

### Defender envelopes

Defender XDR is tenant-scoped (one deploy per tenant per `apply`
run). Snippet substitution for Defender custom detections uses
**generic-only** lookup — even when a workspace-specific override
file exists for the same path, only `overrides/<path>` is consulted.
Defender placeholders that resolve from neither tier still get the
line-removal fallback.

### Worked example

`detections/sentinel_analytic/failed-logins-non-svc.yml`:

```yaml
id: failed-logins-non-svc
asset: sentinel_analytic
status: production
payload:
  kind: Scheduled
  displayName: Failed logins (non-service accounts)
  severity: Medium
  query: |-
    SecurityEvent
    | where EventID == 4625
    | where Account !in (
        {{001/excludedusers.yml}}
    )
    | summarize count() by Account, bin(TimeGenerated, 1h)
  queryFrequency: PT1H
  queryPeriod: PT1H
  triggerOperator: GreaterThan
  triggerThreshold: 10
```

`overrides/001/excludedusers.yml` (generic — applies to every
workspace by default):

```yaml
description: "Service accounts excluded from failed-login alerting"
content: |-
  "svc-backup@corp", "svc-monitor@corp"
```

`overrides/law-prod/001/excludedusers.yml` (prod-specific — adds the
prod-only break-glass account):

```yaml
description: "Prod adds the break-glass account"
content: |-
  "svc-backup@corp", "svc-monitor@corp", "breakglass-prod@corp"
```

`contentops apply --role prod` substitutes the prod list; `--role
integration` falls back to the generic list. If both files were
deleted, the entire `Account !in (...)` line would be dropped, and
the rule would alert on every failed login.

### Operating notes

* `contentops plan --role <r>` iterates per workspace too; useful for
  sanity-checking that the substituted bodies look right before
  deploying.
* `state.json` is keyed on `(asset_kind, envelope_id)` only — it
  reflects the **last applied workspace** for any given rule, not the
  per-workspace truth. If two workspaces produce different bodies
  for the same rule, the state file shows whichever ran last. This
  is documented limitation; per-workspace state granularity is
  follow-up work. **Confirmed safe**: cross-phase reviews verified no
  active correctness break — `drift` and `prune` compare local YAML
  vs the live remote directly (not via `state.json`), so the
  workspace dimension being absent here is an observability gap, not
  a drift-vs-prune-vs-rollback decision input. The
  `AuditRecord.workspace` field is the
  authoritative per-workspace audit dimension; query it via
  `contentops audit query --workspace <name>` when you need
  post-incident attribution. See PR #138 / cross-phase review for
  the verdict.

## GitHub Actions configuration (one-time)

The repo-level GitHub Variables (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`)
and the OIDC federated credentials are set up once per App
Registration — same for single-workspace and multi-workspace tenants.
See
[`authentication-setup.md` step 4](authentication-setup.md#step-4-local-dev-client-secret-vs-ci-oidc).

For each Sentinel workspace you add, repeat **only step 3**
(federated credential with the matching `environment:` name) — the
Variables don't change.

## Local dev

Local dev uses the same `.env`-based client-secret flow regardless of
workspace count. Walkthrough in
[`authentication-setup.md` "Local: client secret"](authentication-setup.md#local-client-secret).

The same App Registration can target every workspace defined in
`tenant.yml` provided you've granted it `Microsoft Sentinel
Contributor` on each workspace's resource group.

## Failure modes and how to recognise them

| Symptom | Cause | Fix |
|---|---|---|
| `error: tenant has N Sentinel workspaces; specify --role or --workspace` | Multiple workspaces, no selector | Add `--role prod` or `--workspace <name>` |
| `[apply] no Sentinel workspace with role=integration — skipping` | Integration workspace not configured | Add it to `tenant.yml` (see "Adding an integration workspace") |
| `Login failed with Error: ... Not all values are present` | GitHub Variables `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` not set | Configure them in repo Settings → Variables |
| `tenant.yml: legacy single-workspace schema detected` | Old `sentinel:` block | Run `python scripts/migrate_tenant_config.py config/tenant.yml` |

<!-- The "Future: multi-tenant" forward-reference that previously
lived here was removed in the cross-phase review follow-up. The
pipeline is single-tenant by explicit design (see CLAUDE.md and
DESIGN §6); the OIDC + DefaultAzureCredential model couples
authentication to one Entra ID tenant per process. Multi-tenant is not
in any active or backlog roadmap; surfacing it as a near-future
path here invites OIDC mis-configurations the pipeline cannot
support. If multi-tenant ever lands as a real workstream, the
design is open enough to accommodate it (per-env tenant.yml files
selected via PIPELINE_ENV), but that's a separate, currently-
hypothetical workstream rather than operator guidance. -->
