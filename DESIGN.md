# Detection-as-Code Platform — Design

> Manages detection content for Microsoft Sentinel and Microsoft
> Defender XDR from a single GitHub Enterprise repository, driven by
> GitHub Actions, with Git as the source of truth.

> **Scope: this document is a contract with future-self, not a
> capability statement.** It describes the full ContentOps vision.
> What ships today is a subset:
>
> - **Implemented**: §1, §2 rows 1 (sentinel_analytic), 3
>   (defender_custom_detection), 4 (sentinel_hunting), 5
>   (sentinel_watchlist), 9 (sentinel_data_connector), plus
>   sentinel_parser. §4, §6 (single-workspace today, multi-workspace
>   iteration partial), §7 plan/apply, §8 drift + prune, §10 identity,
>   §13 state, §16 observability (basic), §20 partial linter set.
> - **Roadmap (in the contract, not yet built)**: §2 rows 2 (NRT), 6
>   (workbooks), 7 (automation rules), 8 (playbooks), 10 (Content Hub
>   solutions), §11 lifecycle gating, §12 promotion-tier workflows,
>   §19 upstream-sync workflows, §21 full CI matrix.
> - **Authoritative on what's actually shipped**: see
>   [`docs/reference/gap-assessment.md`](docs/reference/gap-assessment.md)
>   and [`docs/reference/generated-catalog.md`](docs/reference/generated-catalog.md).
>
> When this doc and the gap-assessment disagree, the gap-assessment
> wins.

---

## 0. Read this first — the critical question

**Microsoft already ships a "Repositories" feature in Sentinel** that natively
connects a GitHub or Azure DevOps repo to a workspace and deploys analytic
rules, automation rules, hunting queries, parsers, playbooks, and workbooks
via a managed runner with "smart deployments" (skip-if-unchanged).

Before building anything, justify *why we are not just using that*. Honest
answers — any one of these is a valid reason:

| Limitation of native Repositories                                 | Our requirement                              |
|-------------------------------------------------------------------|----------------------------------------------|
| Workspace-scoped, one repo ↔ one workspace. No multi-tenant fan-out. | We want one repo, many envs (dev/test/prod). |
| **Does not manage Defender XDR custom detections at all.**        | We want unified Sentinel + Defender XDR.     |
| **Does not manage data connectors, Content Hub solutions, or watchlists.** | We want full CRUD over those.                |
| Deletion is not handled — orphans accumulate forever.             | We want explicit drift detection + prune.    |
| ARM/Bicep only. No abstraction layer. Reviewers diff giant JSON.  | We want lean YAML for analysts to PR.        |
| No environment promotion model (no dev → prod gating).            | We want enterprise change control.           |
| No PR-time validation of KQL or schema beyond ARM template parse. | We want strict pre-merge validation.         |

**If none of those are blocking for you, stop reading and use Sentinel
Repositories.** Building a custom platform is only justified by those gaps.

The rest of this document assumes you are building the custom platform.

---

## 1. Goals and non-goals

### Goals
- Single GitHub Enterprise repo manages detection content for one or more
  Sentinel workspaces and one Defender XDR tenant.
- Lean, human-authored YAML for everything analysts touch (analytics rules,
  custom detections, watchlists, automation rules).
- Pass-through ARM/JSON for things humans don't author (workbooks, playbook
  logic apps).
- Declarative state for "knobs" (data connectors enabled, solutions
  installed).
- Full lifecycle: create / update / disable / delete, with drift detection.
- Multi-environment promotion (dev → test → prod) with environment-level
  approvals.
- Auditable deploys: every change traceable to a commit, PR, and reviewer.

### Non-goals
- Replacing the Sentinel UI for ad-hoc investigation.
- Managing Log Analytics workspace creation, tables, retention, or DCRs (use
  separate IaC repo).
- Managing RBAC role assignments (separate IaC repo / privileged identity).
- Managing the App Registration that the pipeline uses (chicken-and-egg —
  bootstrap manually or with a separate one-time IaC).
- Replacing playbook authoring (Logic Apps Designer stays the source of truth
  for playbook *internals*; we only manage deployment).

---

## 2. Surface area — what we manage and how

| # | Asset                       | Platform   | API / resource                                                               | Source format         | Notes                                                                                          |
|---|-----------------------------|------------|------------------------------------------------------------------------------|-----------------------|------------------------------------------------------------------------------------------------|
| 1 | Analytic rules (Scheduled)  | Sentinel   | `Microsoft.SecurityInsights/alertRules` (ARM `2025-07-01-preview`)           | YAML (lean envelope)  | Already in v1.                                                                                 |
| 2 | Analytic rules (NRT)        | Sentinel   | same, `kind: NRT`                                                            | YAML                  | Already in v1.                                                                                 |
| 3 | Custom detections           | Defender XDR | Graph **beta** `/security/rules/detectionRules`                              | YAML                  | Already in v1. Tenant-wide, ~100-rule limit by default.                                        |
| 4 | Hunting queries             | Sentinel   | `savedSearches` on the LA workspace (`Microsoft.OperationalInsights`)        | YAML                  | Cheap to manage; pure KQL.                                                                     |
| 5 | Watchlists                  | Sentinel   | `Microsoft.SecurityInsights/watchlists` + `watchlistItems`                   | YAML metadata + CSV   | Bulk path: PUT watchlist with `rawContent` (small) or SAS-URI to CSV blob (large >3.8 MB).     |
| 6 | Workbooks                   | Sentinel   | `Microsoft.Insights/workbooks` (ARM `2023-06-01`, `kind: shared`)            | JSON file (`serializedData`) + small YAML manifest | Authored in UI, exported as ARM. Not human-diffable.                                           |
| 7 | Automation rules            | Sentinel   | `Microsoft.SecurityInsights/automationRules`                                 | YAML                  | Order matters (`order` field).                                                                 |
| 8 | Playbooks (Logic Apps)      | Sentinel   | `Microsoft.Logic/workflows` (Consumption) or `Microsoft.Web/sites` (Standard) | ARM JSON              | Often in a separate RG with separate RBAC. Authored in Designer.                                |
| 9 | Data connectors             | Sentinel   | `Microsoft.SecurityInsights/dataConnectors` (legacy) and `dataConnectorDefinitions` (CCP) | YAML state file       | Many connectors require manual UI consent — **partial automation only**.                       |
| 10 | Content Hub solutions       | Sentinel   | `Microsoft.SecurityInsights/contentPackages` (ARM `2025-09-01`)              | YAML state file       | Lists which solutions+versions are installed in each workspace.                                |
| 11 | Threat intel indicators     | Sentinel/Defender | Graph `/security/threatIntelligence/...` or Sentinel TI ingest API     | (out of scope v2)     | Recommend dedicated TI platform (MISP/Sentinel TI), not Git.                                   |

Things deliberately **not** managed via Git in v2: incidents, bookmarks,
entities, MTH huntings (live state, not config), workspace settings (UEBA,
diagnostic settings — separate IaC).

---

## 3. Repository layout

```
SIEMContent/                          # GitHub Enterprise repo
├── README.md
├── DESIGN.md
├── pyproject.toml
├── requirements.txt
│
├── content/                          # All deployable content (renamed from detections/)
│   ├── analytics/                    # (1)(2) Sentinel scheduled + NRT
│   │   └── *.yml
│   ├── detections/                   # (3) Defender XDR custom detections
│   │   └── *.yml
│   ├── hunting/                      # (4) Sentinel saved KQL hunting queries
│   │   └── *.yml
│   ├── watchlists/                   # (5)
│   │   ├── tor-exit-nodes/
│   │   │   ├── watchlist.yml         # metadata
│   │   │   └── items.csv             # data
│   │   └── ...
│   ├── workbooks/                    # (6)
│   │   ├── identity-overview/
│   │   │   ├── workbook.yml          # metadata (displayName, category, etc.)
│   │   │   └── workbook.json         # exported serializedData
│   │   └── ...
│   ├── automation/                   # (7) automation rules
│   │   └── *.yml
│   ├── playbooks/                    # (8) ARM templates
│   │   ├── isolate-device/
│   │   │   ├── playbook.yml          # metadata + parameter values
│   │   │   └── azuredeploy.json      # ARM template (from Designer export)
│   │   └── ...
│   ├── connectors/                   # (9) declarative state
│   │   └── connectors.yml            # one file lists desired enabled/disabled
│   └── solutions/                    # (10) declarative state
│       └── solutions.yml             # one file lists installed packages + versions
│
├── environments/                     # Per-environment configuration
│   ├── dev.yml
│   ├── test.yml
│   └── prod.yml
│
├── pipeline/                         # Python package (extends current)
│   ├── cli.py
│   ├── config.py                     # loads environments/*.yml
│   ├── models/                       # split per asset type
│   │   ├── analytics.py
│   │   ├── detections.py
│   │   ├── hunting.py
│   │   ├── watchlists.py
│   │   ├── workbooks.py
│   │   ├── automation.py
│   │   ├── playbooks.py
│   │   ├── connectors.py
│   │   └── solutions.py
│   ├── providers/                    # one per backend API
│   │   ├── arm.py                    # generic ARM PUT/GET/DELETE
│   │   ├── graph.py                  # generic Graph beta wrapper
│   │   ├── sentinel.py               # Sentinel-specific helpers (composes ARM)
│   │   └── defender.py               # Defender-specific helpers (composes Graph)
│   ├── handlers/                     # one per asset type — implements plan/apply/collect
│   │   ├── analytics.py
│   │   ├── detections.py
│   │   ├── ...
│   ├── core/
│   │   ├── auth.py                   # DefaultAzureCredential, scope helpers
│   │   ├── diff.py                   # git diff + content-hash diff
│   │   ├── plan.py                   # produce a typed Plan{create,update,delete,skip}
│   │   ├── apply.py                  # execute a Plan
│   │   ├── state.py                  # local + remote state correlation
│   │   ├── yaml_io.py                # block scalar dumper, envelope load/dump
│   │   └── ids.py                    # slug, hash, GUID derivation rules
│   └── cli/                          # subcommand modules
│       ├── validate.py
│       ├── plan.py
│       ├── apply.py
│       ├── collect.py
│       ├── diff.py
│       ├── prune.py
│       └── lint.py
│
├── tests/
│   ├── unit/
│   ├── integration/                  # against a sandbox tenant
│   └── fixtures/
│
└── .github/
    ├── copilot-instructions.md
    ├── CODEOWNERS                    # require security team review
    └── workflows/
        ├── validate.yml              # PR: schema + KQL lint + plan against dev
        ├── deploy-dev.yml            # push to main → deploy to dev
        ├── promote-test.yml          # tag v*-rc.* → deploy to test (env approval)
        ├── promote-prod.yml          # tag v*  → deploy to prod (env approval)
        ├── collect.yml               # nightly → drift report PR
        └── prune.yml                 # manual → delete orphans (env approval)
```

---

## 4. The universal envelope

Every YAML asset shares the same envelope and adds a single typed payload
block. This is the contract that lets one validator/loader handle all asset
types.

```yaml
# Required envelope
id:        <kebab-slug>     # unique within asset type, e.g. "brute-force-ssh-001"
version:   "1.2.0"          # semver, bumped manually or by CI
asset:     analytic | detection | hunting | watchlist | workbook | automation | playbook | connector | solution
status:    experimental | test | production | deprecated
owner:     "team-soc"       # CODEOWNERS group; used in audit logs
references:                 # optional — links to docs, MITRE, ticketing
  - "https://attack.mitre.org/techniques/T1110/"

# Exactly one of these blocks, matching `asset`
analytic:   { ... }
detection:  { ... }
hunting:    { ... }
# etc.
```

Pipeline guarantees:
- `id` is unique within asset type (validator).
- For human-authored YAML, `id` is the deterministic remote ARM resource name
  (so an upsert by id works across replays).
- For collected envelopes, `id` is the slugified `displayName` (lowercase,
  non-alphanumerics → `-`, capped at 80 chars). The original ARM resource
  name lives on under `metadata.arm_name`. `apply` resolves the remote
  resource using `metadata.arm_name` first and falls back to `id` when
  absent (matches v1 behaviour for legacy envelopes).
- If two envelopes of the same asset kind would slug to the same `id`, both
  get suffixed with `-<arm8>` (first 8 alphanumeric chars of the ARM name)
  so neither steps on the other. The non-colliding case stays bare.
- For Defender (Graph generates its own GUID), the Graph id is `metadata.arm_name`;
  upsert is by `displayName` (already true in v1).

### Filename convention

Collected envelopes are written to
`<path>/<asset_kind>/<slug>.yml`. The slug matches the envelope `id`.
Human-readable filenames let analysts find a rule by its title in `git ls`
output and PRs.

`contentops collect --rename-existing` walks the existing on-disk tree once
and renames any envelope whose filename does not already match its slug.
Idempotent. Off by default — opt in once after this contract lands so the
`detections/sentinel/` legacy tree follows the same convention.

### Operational vs. configuration

Sentinel exposes two kinds of remote state under the same API:

- **Configuration** — declarative content the team owns. Detection rules,
  hunting queries, watchlists, parsers, automation rules, workbooks, data
  connectors, summary rules. Round-trips cleanly through `collect → drift`.
- **Operational** — runtime state. Incidents, incident tasks, watchlist
  items, workspace manager assignments/configurations/groups/members. New
  items appear continuously, so including them creates permanent apparent
  drift.

Operational kinds are skipped by default in `contentops collect` and
`contentops drift`. Pass `--include-operational` to opt in. The set is
defined in `contentops.core.drift.OPERATIONAL_ASSETS`. See
[docs/operations/collect.md](docs/operations/collect.md) for guidance.

### Log-level policy

CLI subcommands (`collect`, `apply`, `drift`, `prune`) run at a default
verbosity that demotes the chatty SDK loggers (`azure.identity`,
`azure.core`, `httpx`, `urllib3`, `msal`) to `WARNING`. The top-level
`pipeline` logger stays at `INFO` so per-asset progress lines still
surface. Pass `-v` to promote the SDK loggers to `INFO` (~10× output)
or `-vv` for `DEBUG` (~30× output). Default output for `collect` is
~25 lines: tenant banner + summary table.

---

## 5. Per-asset deep dive

### 5.1 Analytic rules and custom detections
- Authored as lean YAML envelopes under `detections/sentinel_analytic/`
  and `detections/defender_custom_detection/`.
- Use the universal envelope shape (`asset`, `id`, `version`,
  `status`, `metadata`, `payload`).
- Optional `dryRunQuery: true` flag — the pipeline calls Sentinel's
  KQL validation API in PR builds (preview, rate-limited; treat as
  advisory not blocking).

### 5.2 Hunting queries
ARM resource: `Microsoft.OperationalInsights/workspaces/savedSearches`.
```yaml
id: hunting-anomalous-svc-account-001
version: "1.0.0"
asset: hunting
status: production
hunting:
  displayName: "Anomalous service account logon"
  category: "Hunting Queries"
  query: |
    SecurityEvent | where ...
  tactics: [CredentialAccess]
  techniques: [T1078]
```
Caveat: hunting queries collide on `name` (the ARM segment). Use
`hash(displayName)` for the resource name to avoid collisions across files.

### 5.3 Watchlists
Two failure modes the design must address explicitly:
1. **Size**: `rawContent` (inline CSV) is fine ≤ ~3.8 MB. Above that, you
   must upload to a SAS-protected blob and PUT with `sasUri`. Pipeline picks
   automatically based on file size.
2. **Item churn**: PUT-replace replaces the whole list (no row diff). For
   high-frequency append-only feeds (TI IPs, etc.), this is fine. For lists
   analysts edit by hand in the portal, **this pipeline will overwrite their
   changes** — call this out loudly in onboarding. Either:
   - declare watchlists as Git-only (portal edits forbidden), OR
   - exclude specific watchlists via `managed: false` and let collect surface
     them as drift.

```yaml
id: tor-exit-nodes
version: "2025.04.25"     # date-versioned for feeds
asset: watchlist
status: production
watchlist:
  displayName: "Tor Exit Nodes"
  description: "Daily refresh from torproject.org"
  itemsSearchKey: "IPAddress"   # column used to JOIN in KQL
  source: "items.csv"           # relative to YAML file
  contentType: text/csv
  numberOfLinesToSkip: 0
```

### 5.4 Workbooks
Workbooks are the worst offender for "JSON in JSON" — the entire workbook is
a string-encoded JSON blob inside `properties.serializedData`. PR diffs are
unreviewable. Mitigations:
1. Store the workbook as **two files**: small YAML manifest + pretty-printed
   `workbook.json`. Pipeline serializes `workbook.json` into the ARM body at
   deploy time.
2. Pre-commit hook auto-formats `workbook.json` with stable key ordering so
   diffs are minimal.
3. Workbook `name` (ARM segment) **must be a GUID**. Pipeline derives it
   deterministically from `id` (UUIDv5 with a fixed namespace) so the same
   `id` always produces the same GUID across environments.
4. `sourceId` must be the workspace resource ID — pipeline injects from
   environment config.

### 5.5 Automation rules
ARM `Microsoft.SecurityInsights/automationRules`. Key gotcha: `order` is a
required integer, must be unique across active rules in the workspace.
Validator enforces uniqueness within the repo; collect pulls remote orders
into the diff to prevent unintentional reordering.

### 5.6 Playbooks (Logic Apps)
This is where the design must be **most conservative**:
- Playbooks are typically authored visually in the Logic Apps Designer. Hand-
  editing the ARM JSON is painful. The pipeline does **not** try to be the
  authoring tool.
- Workflow: develop in a sandbox, "Export template" from the portal,
  parameterize connections, commit `azuredeploy.json` and a YAML manifest.
- Playbooks live in their own resource group with their own RBAC. The
  pipeline needs `Logic App Contributor` on that RG **and** the Microsoft
  Sentinel service account needs `Microsoft Sentinel Automation Contributor`
  on it (one-time bootstrap, document in README).
- Connections (e.g., to Microsoft Teams) **cannot** be fully OIDC-deployed —
  most connectors require an interactive consent the first time. Document
  which connectors are needed and require manual consent post-deploy.

YAML manifest:
```yaml
id: isolate-device
version: "1.4.0"
asset: playbook
status: production
playbook:
  resourceGroup: "rg-sentinel-playbooks"
  template: "azuredeploy.json"
  parameters:
    PlaybookName: "Isolate-Device"
    UserName:
      reference: "@parameters('UserName')"  # passthrough; resolved at deploy
  connections:                              # documented, not deployed
    - "azuremonitorlogs"
    - "wdatp"
```

### 5.7 Data connectors — **the partially-automatable problem**
There are ~100+ connector kinds. They split roughly into:
- **Fully automatable** (REST API connectors, Entra ID diagnostic-style toggles,
  syslog-AMA via DCR): can PUT `dataConnectors` with credentials in env vars.
- **Requires UI consent** (Office 365, MDE-via-MDC integrations, anything
  with a "Connect" button that triggers OAuth): the API call succeeds but the
  connector remains "not connected" until a human clicks once.
- **Codeless Connector Platform (CCP)**: `dataConnectorDefinitions` +
  `dataConnectors` of kind `RestApiPoller` / `GCP` / `CCP`. Fully scriptable,
  but Microsoft is steering everything new to CCP and the old API surface
  will keep changing.

Design decision: model connectors as **declarative desired state**, not
imperative. One file:

```yaml
# content/connectors/connectors.yml
connectors:
  - kind: AzureActiveDirectory
    enabled: true
    dataTypes:
      signinLogs: { state: enabled }
      auditLogs:  { state: enabled }

  - kind: Office365
    enabled: true
    dataTypes:
      exchange:   { state: enabled }
      sharePoint: { state: enabled }
      teams:      { state: enabled }
    requiresManualConsent: true   # pipeline warns, doesn't fail

  - kind: MicrosoftDefenderAdvancedThreatProtection
    enabled: false
```

`apply` reconciles to desired state. For connectors flagged
`requiresManualConsent`, after PUT the pipeline polls connection status; if
not connected within N minutes, it emits a **warning annotation on the PR**
("manual consent needed in portal") rather than failing the build.

### 5.8 Content Hub solutions
ARM resource: `Microsoft.SecurityInsights/contentPackages` (latest API
version `2025-09-01`). Installs an entire solution (e.g., "Microsoft Entra
ID", "Cloud Identity Threat Protection Essentials") with a specific version.

```yaml
# content/solutions/solutions.yml
solutions:
  - contentId: "azuresentinel.azure-sentinel-solution-azureactivedirectory"
    version:   "3.0.6"
    enabled:   true
  - contentId: "azuresentinel.azure-sentinel-solution-mdc"
    version:   "3.0.3"
    enabled:   true
```

Critical caveat: installing a solution dumps a pile of templates (analytics,
hunting, workbooks, playbooks) **as templates** into the workspace — they
are not active until separately enabled. Don't conflate "solution installed"
with "rules running". The pipeline should:
1. Reconcile installed solutions and versions.
2. **Not** auto-enable templates from solutions (that's what custom rules
   files are for — copy from template, commit, manage explicitly).
3. Surface installed-but-unmanaged content in `collect` as informational.

---

## 6. Multi-environment model — single tenant, multi workspace

The tenant file declares **0 to N Sentinel workspaces** under
`sentinelWorkspaces:`, each tagged with a `role`. Defender XDR is
tenant-level (0 or 1 per Entra ID tenant).

A tenant ↔ Entra ID tenant. Within one Entra ID tenant you can have:

* **0 or 1 Defender XDR instance** (Defender is tenant-scoped — no
  workspace concept; either present or not).
* **0 to N Sentinel workspaces**, in any number of subscriptions. Each
  workspace declares its own subscription / resource group / name and
  carries one of these roles:
  * `prod` — receives content from `main` merges (`deploy.yml`).
  * `integration` — receives content from PR builds (`integration-deploy.yml`).
    Used to catch broken KQL or wrong-column references **before** they
    hit prod. Defender content is **not** deployed to integration —
    Defender is prod-only by design (no integration Defender XDR exists).
  * `dev` — receives `experimental` + `test` + `production` statuses.
    Useful for personal sandboxes; not auto-deployed by any workflow.

```yaml
# config/tenant.yml
tenant:
  name: production-tenant       # human label, for logging
  tenantId: "..."               # Entra ID tenant GUID (must match the
                                # federated credential / .env
                                # AZURE_TENANT_ID — the loader does
                                # not verify, the API call will fail
                                # if they mismatch).

  defender:
    enabled: true               # omit the block entirely for tenants
                                # that don't have Defender XDR.

  sentinelWorkspaces:
    - role: prod
      subscriptionId: "..."
      resourceGroup: "rg-sentinel"
      workspaceName: "law-sentinel"
      location: westeurope

    - role: integration
      subscriptionId: "..."     # may differ from prod's; same Entra ID tenant.
      resourceGroup: "rg-sentinel-int"
      workspaceName: "law-sentinel-int"
      location: westeurope
```

### Selection at CLI invocation time

Workflows / operators select workspaces by **role** (the common case)
or by **name** (when one role has multiple workspaces and only one is
the target). Selection happens at command invocation:

```
contentops apply --role prod                 # every prod workspace
contentops apply --role integration          # every integration workspace
contentops apply --workspace law-sentinel    # exactly one, by name
contentops apply                             # implicit when the tenant
                                           # has exactly one Sentinel
                                           # workspace; error otherwise.
```

Implementation: ``contentops.config.select_workspaces(cfg, role=..., workspace=...)``
resolves a list of ``SentinelWorkspaceConfig``. The CLI orchestrator
exports ``PIPELINE_WORKSPACE_NAME`` per iteration; handler factories
in ``contentops.cli.bootstrap`` read that env var to instantiate clients
against the active workspace. This keeps handlers workspace-scoped
without N-way registry rewiring.

> **Iteration follow-up.** Today `apply_cmd` resolves `--role` to a
> single workspace and errors when N>1 match. Multi-workspace
> iteration (deploy to every `--role prod` workspace independently,
> aggregate exit codes, group output by workspace) is the immediate
> follow-up. The schema and selector are in place; the iteration loop
> is mechanical work that lands in a follow-up PR.

### Status gating per active role

Status gating now keys off the **active workspace's role**, not the
tenant name:

* `dev` → `experimental` + `test` + `production`
* `integration` (was `test`) → `test` + `production`
* `prod` → `production` only (and `deprecated` deploys as disabled)

`deprecated` is never auto-deployed by any role; it lives on the
explicit `deprecate` / `prune` flow.

### Identity is separate

Identity (`AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_CLIENT_SECRET`)
is **never** in `tenant.yml`. It comes from environment variables —
local `.env` or GitHub Actions Variables (not Secrets — these IDs are
public). Auth flows:

* **Local dev** — `.env` populates env vars; `DefaultAzureCredential`
  picks up the `ClientSecretCredential` chain.
* **CI** — `azure/login@v2` uses OIDC federated credentials (no
  client secret in CI). Federated credential subject is bound to
  `repo:KustoKing/SIEMContent:environment:<production|integration>`
  on the App Registration.

GitHub Variables (not Secrets) hold `AZURE_CLIENT_ID` and
`AZURE_TENANT_ID`. No `AZURE_SUBSCRIPTION_ID` variable is needed at
the workflow level — workflows read subscriptions from `tenant.yml`
and pass them to `azure/login`'s `subscription-id` input.

Multi-tenant is explicitly out of scope. One Entra ID tenant per
repo, full stop.

---

## 7. The plan / apply model

Inspired by Terraform; non-negotiable for safety at this scale.

```
contentops plan  --env prod [--asset analytic,detection]
   → reads YAML, fetches remote state, prints typed Plan to stdout + JSON
     to artifact. Does not call any write APIs.

contentops apply --env prod --plan plan.json
   → executes the previously-produced plan. Idempotent on retry.

contentops collect --env prod
   → pulls remote state to YAML in a scratch directory; emits diff as PR.

contentops prune  --env prod --confirm
   → deletes remote items not present locally (gated; prod requires
     2-reviewer approval via GitHub Environment).
```

**Why a separate plan step:** PR builds run `plan` against `prod` and post
the summary as a PR comment. Reviewers see *exactly* what will change before
merging. `apply` then runs in the deploy workflow with the merged plan.

---

## 8. Drift detection and the "delete" problem

Three sources of truth get out of sync:
1. **Git** (what we want).
2. **Remote API** (what's actually deployed).
3. **State file** (what we last successfully deployed — optional but
   recommended; stored as a workflow artifact + checked into a `state/`
   branch, NOT main).

Drift cases:
| Local | Remote | State | Meaning                   | Action                         |
|-------|--------|-------|---------------------------|--------------------------------|
| ✅    | ✅     | ✅    | in sync                   | nothing                        |
| ✅    | ❌     | ❌    | new                       | create                         |
| ✅    | ✅     | ✅(diff) | locally modified         | update                         |
| ✅    | ✅(diff) | ✅  | remote drift              | warn; require explicit re-apply |
| ❌    | ✅     | ✅    | deleted from Git          | mark for prune (separate flow) |
| ❌    | ✅     | ❌    | unmanaged (never ours)    | leave alone, surface in report |

**Default deploy never deletes.** Deletion is a separate `prune` workflow
that requires reviewer approval — silent deletion of a detection rule is a
catastrophic failure mode you do not want to have to explain to an auditor.

### 8.1 `contentops prune` — the deletion-as-code path (Chunk 1, implemented)

The CLI command is `contentops prune` and the workflow is `.github/workflows/prune.yml`.

**Handler contract.** Every handler implements `delete(remote_id) -> ActionResult`.
For write-capable handlers, this calls the appropriate DELETE endpoint
on the remote API. For read-only / collect-only handlers (workspace
manager, source controls, incidents, incident tasks, watchlist items)
the method raises `NotSupportedError`. For singleton handlers
(`sentinel_settings`, `sentinel_onboarding`) it also raises
`NotSupportedError` — those resources represent workspace-wide
capabilities that are toggled via `status: deprecated`, not pruned.

**404 is success.** If the resource is already gone, the prune is a
no-op success — the operation is idempotent. Anything else maps to
`error-<status_code>`.

**Safety rails:**
1. `--dry-run` defaults to true. The CLI lists the orphan plan and
   exits without touching anything.
2. `--yes` is required to actually delete (alongside `--no-dry-run`).
   Two flags, not one — defends against shell-history accidents.
3. `--max-deletes N` (default 25) is fail-closed. Exceeding it is an
   exit-1 error, not a "ok let's keep going" warning.
4. Locked envelopes (top-level `localCustomization: true` on the YAML)
   are NEVER pruned by default. `--include-locked` is required to
   override, and the workflow exposes that as an explicit boolean
   input.
5. `NotSupportedError` from any handler is caught and surfaced as a
   per-asset SKIP — never a batch failure.
6. Every actual deletion writes an `AuditRecord` onto the same JSONL
   chain `apply` uses, so the hash chain spans both create/update
   and delete operations.

**Workflow:** `prune.yml` is `workflow_dispatch` only. Inputs:
`env`, `asset` (optional), `dry_run` (default true), `max_deletes`
(default 25), `include_locked` (default false), `confirm` (must
equal the literal string `CONFIRM` when `dry_run=false`). Uses the
GitHub Environment matching the env input so production prune runs
require reviewer approval. Posts the prune plan as a step summary;
uploads the audit JSONL as an artefact (90-day retention).

**Live-tested:** every write-capable handler has a `tests/integration/`
test that creates a temp resource on the live tenant, deletes it via
`handler.delete()`, and asserts a subsequent GET returns 404.

---

## 9. GitHub Enterprise specifics

This is GitHub Enterprise (likely GHEC, possibly GHES). Practical
implications:

- **OIDC with Azure**: GHEC supports federated credentials to Azure normally.
  GHES requires the GHES instance's OIDC issuer to be reachable by Azure
  (public DNS) and the federated credential subject claim format may differ.
  Verify before designing around OIDC; fall back to a managed-identity-on-
  self-hosted-runner if OIDC isn't viable.
- **Federated credential subject limit**: an Azure App Registration accepts
  at most 20 federated credentials. With multiple environments × branches ×
  workflows you can hit this. Mitigation: use the `repo:org/repo:environment:<env>`
  subject pattern (one credential per environment, not per workflow).
- **GitHub Environments**: required for reviewer-gated deploys. One per
  Azure environment (`dev`, `test`, `prod`); secrets/variables scoped per
  environment.
- **CODEOWNERS** in the security project: split ownership — analysts own
  `content/analytics/` and `content/detections/`; platform team owns
  `content/connectors/`, `content/solutions/`, `pipeline/`, `.github/`.
- **Branch protection on `main`**: required reviews from CODEOWNERS, status
  checks (`validate`, `plan-prod`), no force-push, no admin bypass.
- **GitHub Advanced Security**: enable secret scanning + push protection so
  someone can't commit a workspace key into a sample.

---

## 10. Identity and permissions

| Component                    | Identity                                      | Scope                                                       |
|------------------------------|-----------------------------------------------|-------------------------------------------------------------|
| Pipeline -> Sentinel ARM      | App Reg + OIDC                                | `Microsoft Sentinel Contributor` + `Log Analytics Contributor` on each workspace (LA role covers hunting queries + parsers as `savedSearches`) |
| Pipeline → Workbooks         | same                                          | `Monitoring Contributor` on workbook RG (workbooks live there) |
| Pipeline → Playbooks         | same                                          | `Logic App Contributor` on playbook RG                      |
| Sentinel service → Playbooks | Sentinel managed identity (auto-created)      | `Microsoft Sentinel Automation Contributor` on playbook RG  |
| Pipeline → Defender XDR      | same App Reg, **app permission**              | Graph `CustomDetection.ReadWrite.All` (admin consent)       |
| Pipeline → Content Hub       | same                                          | `Microsoft Sentinel Contributor` already covers it          |
| KQL dry-run validation       | same                                          | `Log Analytics Reader` on workspace                         |

One App Registration per environment is cleaner than one shared App Reg with
multiple subjects — easier to revoke a single env without affecting others,
fits the "blast radius" principle. Trade-off: more App Regs to manage.

---

## 11. Validation pipeline (what `validate` actually does)

PR-time, in order, fail-fast on first hard error:

1. **YAML well-formed**, file extensions correct.
2. **Envelope schema** valid (id pattern, semver version, known asset/status).
3. **Per-asset payload schema** valid (Pydantic models per asset type).
4. **Cross-file invariants**:
   - `id` unique within asset type.
   - Defender `displayName` unique across detection files.
   - Automation rule `order` unique within workspace scope.
   - Watchlist CSV columns match `itemsSearchKey`.
   - Workbook `serializedData` parses as JSON; matches declared `version`.
5. **Reference checks**:
   - Playbook references in automation rules resolve to a known playbook.
   - Connector references in solutions warn if the solution provides a
     connector you've also declared in `content/connectors/` (potential
     conflict).
6. **KQL lint** (advisory, soft-fail):
   - Static parse via `Kusto.Language` (.NET) shelled, or `pykusto`.
   - Optional `dryRunQuery` against workspace (preview API, rate-limited,
     advisory only).
7. **Plan against target env(s)** — requires Azure auth, so runs after
   `azure/login`; if creds unavailable (fork PR), skip with notice.

---

## 12. Workflows

| Workflow            | Trigger                              | Permissions                  | Action                                                |
|---------------------|--------------------------------------|------------------------------|-------------------------------------------------------|
| `validate.yml`      | PR opened/updated                    | `id-token: write`            | steps 1–6 above; plan against `dev`; comment on PR    |
| `deploy-dev.yml`    | push to `main`                       | `id-token: write`            | apply diff to `dev` automatically                     |
| `promote-test.yml`  | tag `v*-rc.*`                        | `id-token: write` + env approval | apply to `test`                                  |
| `promote-prod.yml`  | tag `v*` (no `-rc`)                  | `id-token: write` + env approval | apply to `prod` (2 reviewers required)           |
| `collect.yml`       | nightly cron + manual                | `id-token: write` + `pr: write` | collect each env, open PR with drift              |
| `prune.yml`         | manual `workflow_dispatch`           | `id-token: write` + env approval | delete orphans (env chosen as input)             |
| `kql-lint.yml`      | PR (paths: KQL-bearing files)        | none                         | static KQL parse only (no Azure auth needed)          |
| `solutions-catalog.yml` | daily cron + manual              | `id-token: write` + `pr: write` | upstream PR for new Content Hub versions (§19.2)   |
| `templates-catalog.yml` | weekly cron + manual             | `id-token: write` + `pr: write` | upstream PR for new built-in template versions (§19.3) |
| `models-catalog.yml`    | weekly cron + manual             | `pr: write`                  | upstream PR for ARM/Graph schema diffs (§19.4)        |
| `tables-catalog.yml`    | weekly cron + manual             | `id-token: write` + `pr: write` | upstream PR for new advanced-hunting tables (§19.5)|
| `community-watch.yml`   | weekly cron + manual             | `pr: write`                  | informational PR for Azure-Sentinel community (§19.6) |

The five `*-catalog.yml` / `community-watch.yml` workflows are the
"upstream → repo" PR producers detailed in §19. They share the PR
machinery in §19.7 and run the full validation matrix (§21) on every PR
they open.

Concurrency: every deploy/promote workflow has
`concurrency: { group: deploy-${{ env }}, cancel-in-progress: false }` so
two simultaneous merges don't race.

Self-hosted runners: required if GHES + private Sentinel workspace + no
public ingress. Use ephemeral runners with managed identity instead of OIDC
in that case.

---

## 13. State, idempotency, and resumability

- **All upserts are idempotent** by construction (PUT with deterministic name
  for ARM; displayName-keyed PATCH for Defender).
- **Resumable applies**: `apply` writes a per-item progress JSON; on retry,
  items already marked `success` for that plan ID are skipped.
- **State file** (Chunk 5, implemented): per-env JSON, one file per env,
  conventionally written to a separate `state/<env>` orphan branch on
  CI runs. Local-dev path is `state/state.json`. Used to detect "Git
  removed it but remote still has it → flag for prune". Without
  state, drift / prune still work via the local YAML index (the
  collect-as-truth fallback), but you can't distinguish "removed
  intentionally" from "never managed".

### 13.1 State schema (Chunk 5)

```json
{
  "schema_version": "1.0",
  "env": "prod",
  "last_apply_sha": "abc123...",
  "last_apply_at": "2026-05-06T12:00:00.000000Z",
  "managed_assets": {
    "sentinel_analytic": {
      "brute-force-001": {
        "remote_id": "brute-force-001",
        "last_applied_at": "2026-05-06T12:00:00.000000Z",
        "last_applied_sha": "abc123...",
        "status": "success"
      }
    }
  }
}
```

* ``apply`` updates the file after a successful batch:
  one ``managed_assets[<asset>][<envelope_id>]`` entry per
  non-skipped result, plus the run's ``last_apply_sha`` /
  ``last_apply_at``.
* ``classify_remote(state, asset, envelope_id, in_local)`` returns
  one of ``in-sync``, ``new-local``, ``orphan``, ``unmanaged`` —
  the contract drift / prune use to decide what to do with each
  remote item.
* The state file is *advisory*. A corrupt or missing file falls back
  to "treat everything as unmanaged" (no prune candidates surfaced
  via state, but git-history fallback still works). The pipeline
  never fails because of state.

### 13.2 CLI

| Command | Effect |
|---|---|
| `contentops state show` | Print the per-env state. JSON via `--format json`. |
| `contentops state forget <id> --asset <kind>` | Drop one envelope from state (e.g. after a manual portal cleanup). |
| `contentops apply` | After every successful batch, merges results into state and writes it. Failures and skips are recorded too (failed entries get re-tried by `contentops retry-failed`). |

---

## 14. Secrets, configuration, sensitive data

- Connector credentials (e.g., third-party API keys for CCP connectors): never
  in YAML. Reference by name; pipeline resolves from GitHub environment
  secrets at apply time and POSTs to the connector's `auth` block.
- Watchlist contents: typically not sensitive, but TI feeds can be licensed.
  Use `.gitattributes` `filter` for CSVs that must stay encrypted, or store
  outside the repo and download at deploy time.
- Workspace and tenant IDs: not secrets; commit them in `environments/*.yml`.
- App Registration client IDs: not secrets; commit them.
- Anything referenced by a `${{ secrets.* }}` pattern is mandatory to lock
  via push protection / secret scanning.

---

## 15. Testing strategy

| Layer        | What                                                             | Where                                           |
|--------------|------------------------------------------------------------------|-------------------------------------------------|
| Unit         | Pydantic models, YAML round-trip, ARM body builders, plan diff   | `tests/unit/` (current `tests/` extended)       |
| Contract     | HTTP responses recorded with `respx` per provider                | `tests/unit/providers/`                         |
| Integration  | Real plan + apply against a sandbox tenant, then prune everything | `tests/integration/` (only on schedule + manual) |
| Smoke (CI)   | After each deploy, GET 5 random rules and verify they exist      | inside `deploy-*.yml`                           |

Sandbox tenant is non-negotiable for an enterprise rollout — a separate
Sentinel workspace with isolated RBAC, used by `dev` and integration tests.

---

## 16. Observability

- Every CLI run emits a structured JSON log line per item; workflows upload
  the run log as an artifact (90-day retention).
- A summary table is posted as a PR comment / workflow summary
  (`$GITHUB_STEP_SUMMARY`).
- Optional: ship logs to the very Sentinel workspace they manage (close the
  loop) via Log Ingestion API → custom table `SIEMContentDeploys_CL`. Then
  build an analytic rule: "deploy failure rate > N in 1h".
- Notifications on prod failure: GitHub Issue auto-opened + Teams webhook.

---

## 17. Risks, gotchas, and things I will get wrong

Honest list:

1. **Defender XDR API is `beta`.** Microsoft can and does change beta
   shapes. Pin `User-Agent` so support can identify you, and budget for
   recurring schema fixups. There is no GA detection-rule API as of this
   writing.
2. **Workbook serializedData is a moving target.** Microsoft adds fields to
   the workbook JSON over time; an older committed workbook may "downgrade"
   features when re-applied. Mitigation: collect-then-PR workflow keeps the
   committed JSON close to portal reality.
3. **Solutions auto-update in the portal.** If "Auto-update" is on, the
   pipeline's "installed version: 3.0.6" will fight the portal. Turn auto-
   update **off** for managed solutions, or accept that `collect` will keep
   producing version-bump PRs.
4. **Data connector kinds change.** New connectors (CCP-based) replace old
   ones (e.g., Office365 connector is being replaced). Treat
   `content/connectors/connectors.yml` as a **convention**, not as schema-
   validated; use a permissive Pydantic model with `extra='allow'`.
5. **Microsoft Sentinel is moving from Azure Portal to Defender Portal**
   (deadline 2027-03-31). The ARM API surface stays, but the *semantics*
   around unified incidents, automation, etc., are shifting. Don't tightly
   couple to Azure-portal-only concepts.
6. **`git diff HEAD~1..HEAD` is wrong for squash merges with multiple
   logical changes.** Prefer comparing `main` to the previous successful
   deploy SHA stored in the state file. Falling back to "deploy everything
   in main" is safer than a half-applied subset.
7. **Rate limits**: ARM throttles around 12K req/h per subscription;
   Graph beta is more aggressive. Batch + parallelize cautiously
   (httpx with bounded semaphore, ~5 concurrent).
8. **Logic Apps connections cannot be fully automated.** Some require
   interactive OAuth. The pipeline should clearly document which connectors
   need manual consent and not pretend otherwise.
9. **Two App Regs with the same Graph permission can both manage Defender
   detections.** There is no per-rule ownership tag. If another tool also
   pushes Defender detections, you will fight it. Solve organizationally,
   not technically.
10. **Watchlist updates are not transactional.** Mid-update the watchlist
    can be empty for seconds. KQL detections joining it will miss alerts.
    Schedule watchlist updates outside detection trigger windows.

---

## 18. Phased delivery

| Phase | Scope                                                                                | Why                                       |
|-------|--------------------------------------------------------------------------------------|-------------------------------------------|
| 1     | Refactor v1 to envelope+handlers+providers; add `plan`/`apply`; multi-env config.    | Foundation; nothing new functionally.     |
| 2     | Hunting queries, automation rules, watchlists.                                       | Highest ROI, lowest API risk.             |
| 3     | Workbooks (with two-file layout) and Content Hub solutions.                          | Useful but JSON-heavy; needs UX care.     |
| 4     | Data connectors (CCP first, classic last).                                           | Highest API risk, partial automation.     |
| 5     | Playbooks (deploy-only; authoring stays in Designer).                                | Crosses RG/RBAC boundary; high blast radius. |
| 6     | KQL dry-run validation, drift dashboard workbook, deploy telemetry to Sentinel.      | Polish.                                   |

Each phase is independently shippable; phases 4–5 are optional if Sentinel
Repositories already covers your playbook/workbook flow well enough.

---

## 19. Upstream sync — pipeline-opened PRs

Requirement: when reality upstream changes (live workspace, Microsoft
catalogs, API schemas), the pipeline must open a PR against this repo with
the proposed change. Humans always merge; the pipeline never pushes to
`main` directly.

There are **six** distinct upstream streams. Each is a separate scheduled
workflow with its own label, branch name pattern, and CODEOWNERS routing.
They share one underlying "open-or-update PR" library.

| # | Stream                                  | Workflow                  | Trigger        | Label             | Branch                                    | Owner team      |
|---|-----------------------------------------|---------------------------|----------------|-------------------|-------------------------------------------|-----------------|
| 1 | Live-state drift (portal hand-edits)    | `collect.yml` (§12)       | nightly        | `upstream:drift`     | `upstream/drift/<env>/<date>`             | SOC analysts    |
| 2 | Content Hub solution catalog            | `solutions-catalog.yml`   | daily          | `upstream:solutions` | `upstream/solutions/<contentId>`          | Platform        |
| 3 | Built-in analytic rule templates        | `templates-catalog.yml`   | weekly         | `upstream:templates` | `upstream/templates/<rule-id>`            | SOC analytics   |
| 4 | ARM / Graph API schema (Pydantic)       | `models-catalog.yml`      | weekly         | `upstream:schema`    | `upstream/schema/<api>-<date>`            | Platform        |
| 5 | Advanced hunting / table schema         | `tables-catalog.yml`      | weekly         | `upstream:tables`    | `upstream/tables/<date>`                  | Platform        |
| 6 | Azure-Sentinel community repo (opt-in)  | `community-watch.yml`     | weekly         | `upstream:community` | `upstream/community/<date>`               | SOC analytics   |

### 19.1 Live-state drift  (portal → repo)
Already specified in §12. Strengthen:
- Group changes by asset type and produce **one PR per asset type per env**
  (not one giant PR), to keep CODEOWNERS routing clean.
- For modified items, the PR body contains a 3-way diff: *git HEAD*, *last
  applied state* (§13), *current remote*. This distinguishes "we forgot to
  re-deploy" from "someone hand-edited in the portal".

### 19.2 Content Hub solution catalog
- Source: `GET /providers/Microsoft.SecurityInsights/contentProductPackages`
  (workspace-scoped) and the Marketplace `productPackages` listing.
- Compare each `contentId` in `content/solutions/solutions.yml` against the
  latest published `version`. Open / update a PR bumping the version.
- PR body includes the package's published changelog URL and a list of
  templates the new version adds/removes (so reviewers see if a managed rule
  is impacted).
- Opt-out per solution via `pinVersion: true` in `solutions.yml` (and
  document why — usually "incompatible breaking change in 4.x").

### 19.3 Built-in analytic rule templates
- Source: `GET .../alertRuleTemplates` and `Microsoft.SecurityInsights/contentTemplates`.
- For every analytic rule whose YAML carries `alertRuleTemplateName` and
  `templateVersion`, detect a newer `templateVersion` and open a PR.
- The PR shows the *KQL* and *property* diff between the two template
  versions, plus the diff against the customer's local override. Reviewer
  decides what to keep.
- Never auto-merge — these almost always need analyst judgement (false-
  positive rate, environment-specific thresholds).

### 19.4 API schema / model drift
- Source: snapshot the relevant slices of the
  [`Azure/azure-rest-api-specs`](https://github.com/Azure/azure-rest-api-specs)
  Sentinel swagger and Graph beta `$metadata` into `contentops/schemas/`
  (committed JSON).
- Weekly job re-fetches and diffs.
- For added optional fields → auto-regenerate Pydantic models in a PR with
  matching test fixtures (additive, non-breaking).
- For renamed/removed fields → open a PR with **failing test stubs** and
  TODOs in handler code; never auto-fix. This is how the team discovers
  Microsoft removed something before prod blows up.
- Bumps to `api-version` (preview → GA) require a manual decision; the PR
  proposes the new version but leaves the call sites unchanged.

### 19.5 Advanced hunting / table schema
- Source: Defender XDR advanced hunting schema (via Graph
  `/security/runHuntingQuery` metadata or the public schema doc).
- Diff against `contentops/schemas/defender_tables.json`.
- New columns / tables → PR updates the snapshot. The KQL linter
  (§21 + §22) automatically gains awareness on merge.

### 19.6 Azure-Sentinel community repo
- Source: `Azure/Azure-Sentinel` releases / new files under
  `Detections/`, `Hunting Queries/`.
- Filter by configured MITRE techniques, data sources, and severity.
- PR is **informational only** — lists candidate detections with summaries,
  links, and a copy/paste YAML stub (status `experimental`). Never imports
  KQL into the repo automatically.

### 19.7 Shared PR machinery
All six streams share one library (`contentops/upstream/pr.py`):
- **Stable branch name** per stream + key. Re-runs *force-update* the branch
  rather than stacking PRs (`git push --force-with-lease`).
- **Content-hash dedupe**: if the new branch's tree hash matches the open
  PR's head, the run is a no-op (no comment spam).
- **Title format**: `[upstream:<stream>] <key> <vfrom>→<vto>` (parseable).
- **Body**: structured Markdown — summary table, collapsible per-item
  details, links to upstream sources, instructions for reviewers.
- **Labels**: `auto-generated`, `upstream:<stream>`, plus risk labels
  (`risk:low|medium|high`) computed from diff size.
- **CODEOWNERS auto-request**: derived from path + `.github/upstream-owners.yml`.
- **Bot identity**: a dedicated GitHub App (preferred) or
  `github-actions[bot]` with `pull-requests: write`, `contents: write` on a
  protected branch namespace `upstream/*` — and **no** push permission to
  `main`.
- **Conflict policy**: if a human pushed commits to the upstream branch
  since last run, the bot does NOT force-overwrite — it opens a follow-up
  PR with the new upstream change, against the existing branch, and lets
  the human merge/rebase. Never lose human work silently.
- Every upstream PR runs the full `validate.yml` matrix (§22). No special
  fast-path — these PRs are reviewed like any human PR.

### 19.8 What we deliberately do NOT auto-PR
- Microsoft Sentinel **incidents, alerts, entities** (operational, not config).
- **Workspace-level settings** (UEBA, EntityAnalytics, diagnostic settings —
  separate IaC repo).
- **Connector credentials** rotated upstream (handled via secret rotation,
  not Git).
- **Defender XDR live machine state** (devices, users) — not config.

---

## 20. Alignment matrix — cross-asset invariants

Big systems fail at integration seams. This table is the contract that CI
enforces; each row is a dedicated linter under `contentops/lint/`.

| # | Invariant                                                                                  | Source                                | Target                                                | Enforced in                       | Severity |
|---|--------------------------------------------------------------------------------------------|---------------------------------------|-------------------------------------------------------|-----------------------------------|----------|
| 1 | Every `_GetWatchlist("X")` in any KQL resolves to a `content/watchlists/X/` directory      | analytics + detections + hunting KQL  | `content/watchlists/`                                 | `lint-watchlist-refs`             | error    |
| 2 | Every table referenced in KQL exists in the target workspace (built-in or from connector)  | KQL                                   | LA built-in tables ∪ tables provided by enabled conns | `lint-table-refs`                 | warn     |
| 3 | Every `playbookId` in an automation rule resolves to a `content/playbooks/` entry          | automation YAML                       | `content/playbooks/`                                  | `lint-playbook-refs`              | error    |
| 4 | Solution-provided rule that is locally customized declares matching `alertRuleTemplateName`| analytics YAML                        | `solutions.yml`                                       | `lint-solution-overrides`         | warn     |
| 5 | Analytics rule's `alertRuleTemplateName` + `templateVersion` exists upstream               | analytics YAML                        | live `alertRuleTemplates`                             | `plan` step                       | warn     |
| 6 | Defender `displayName` unique across all detection files                                   | detections YAML                       | each other                                            | already (v1)                      | error    |
| 7 | Workbook `sourceId` resolves to the target env's workspace                                 | workbook YAML                         | `environments/*.yml`                                  | injected at plan time             | error    |
| 8 | Required connector enabled before a detection that depends on it (`requires:` field)       | detection / analytics YAML            | `connectors.yml`                                      | `lint-connector-deps`             | error    |
| 9 | A `production` rule does not reference an `experimental`/`test` playbook                   | rule status                           | playbook status                                       | `lint-status-coherence`           | error    |
| 10 | Automation rule `order` unique within workspace                                           | automation YAML                       | each other                                            | already (§5.5)                    | error    |
| 11 | `id` slug regex consistent across all asset types                                         | every YAML                            | regex                                                 | envelope (§4)                     | error    |
| 12 | Pipeline version pinned in workflows matches `pyproject.toml`                             | `.github/workflows/*`                 | `pyproject.toml`                                      | `lint-self-version`               | error    |
| 13 | Every committed `workbook.json` parses + matches its declared `version`                   | workbook JSON                         | manifest YAML                                         | `lint-workbook-shape`             | error    |
| 14 | Every YAML file referenced by `references:` URL pattern is reachable (HEAD 200)           | envelope `references`                 | the internet                                          | `lint-references` (advisory)      | warn     |
| 15 | Watchlist CSV columns include the declared `itemsSearchKey`                               | watchlist YAML + CSV                  | each other                                            | `lint-watchlist-shape`            | error    |
| 16 | No two analytics rules share `displayName` per workspace (Sentinel UI assumes uniqueness) | analytics YAML                        | each other                                            | `lint-displayname-unique`         | warn     |
| 17 | Hunting query `name` (ARM segment) collisions resolved via deterministic hash             | hunting YAML                          | derivation rule (§5.2)                                | computed at build                 | error    |

Linter output is GitHub-annotation-formatted (`::error file=,line=::`) so
findings render inline on the PR diff.

---

## 21. Try / Build / Test / Review — the full CI matrix

Every PR runs **all** of this. Matrices fan out per asset type and per env so
failures are localized. Required vs. advisory is called out per check.

### 21.1 Try (read-only plan everywhere)

| Job                | What                                                                                  | Required to merge? |
|--------------------|---------------------------------------------------------------------------------------|--------------------|
| `plan-dev`         | Plan against dev. Comments diff on PR.                                                | advisory           |
| `plan-test`        | Plan against test. Comments diff on PR.                                               | advisory           |
| `plan-prod`        | Plan against prod. Comments diff on PR.                                               | **required**       |
| `try-sandbox`      | Apply to throwaway RG `rg-sentinel-pr-${{ pr_number }}`; teardown on PR close. Opt-in via label `try:sandbox`. | advisory  |

A red `plan-prod` blocks merge — that's the safety net for "this PR would
break prod even if it looks fine in dev".

### 21.2 Build (validate + compile)

| Job              | What                                                                                              | Required |
|------------------|---------------------------------------------------------------------------------------------------|----------|
| `build-yaml`     | Schema validation (Pydantic) of every YAML.                                                       | **req**  |
| `build-arm`      | `az deployment group validate` for every workbook + playbook against sandbox RG.                  | **req**  |
| `build-kql`      | Kusto.Language static parse of every KQL block.                                                   | **req**  |
| `build-models`   | Re-run code generators from committed schemas; fail if `git status` non-empty (ensures regen-up-to-date). | **req** |
| `build-docs`     | Regenerate `content/INDEX.md` (catalog, MITRE coverage). Fail on drift.                           | advisory |
| `build-bicep`    | If any file under `content/playbooks/**/*.bicep`, transpile with `bicep build` and validate.      | conditional |

### 21.3 Test (unit + contract + smoke)

| Job                  | What                                                                                          | Where it runs                |
|----------------------|-----------------------------------------------------------------------------------------------|------------------------------|
| `test-unit`          | pytest matrix Python 3.12 / 3.13.                                                             | every PR                     |
| `test-contract`      | respx-replay HTTP fixtures per provider; fail if recorded responses contradict snapshots.     | every PR                     |
| `test-integration`   | Real plan + apply + GET assert + prune against sandbox tenant.                                | nightly + on prod-tag        |
| `test-smoke`         | Post-deploy: GET 5 random items per asset type; assert exists + enabled-as-expected.          | inside `deploy-*.yml`        |
| `test-rollback`      | Apply, then re-apply previous SHA; assert state matches.                                      | nightly                      |
| `test-permissions`   | New SP with documented role set is sufficient to run a full plan+apply.                       | nightly                      |

### 21.4 Review (automated + human gates)

| Job                    | What                                                                                              | Required |
|------------------------|---------------------------------------------------------------------------------------------------|----------|
| `review-codeowners`    | Native GitHub: `.github/CODEOWNERS` requires the right team(s) per touched path.                  | **req**  |
| `review-plan-comment`  | Bot posts plan summary table on PR; updates on each push.                                         | bot      |
| `review-diff-render`   | For workbooks: render before/after JSON to PNG via headless workbook renderer; attach to PR.      | advisory |
| `review-kql-render`    | For KQL: side-by-side syntax-highlighted diff in PR comment.                                      | advisory |
| `review-policy`        | OPA / Conftest policies (e.g., "Severity High ⇒ createIncident=true"; "no `*` in customDetails"). | **req**  |
| `review-checklist`     | PR template enforces analyst checklist (tested in dev, MITRE mapping, FP rate measured, runbook link). | **req** |
| `review-ai`            | Optional Copilot/code-review agent posts inline suggestions.                                      | advisory |

### 21.5 Branch protection on `main`
Required status checks (must all be green to merge):
- `build-yaml`, `build-arm`, `build-kql`, `build-models`, `build-bicep`
- all linters from §20 (errors only)
- `test-unit`, `test-contract`
- `plan-prod`
- `review-codeowners`, `review-policy`, `review-checklist`

Plus: linear history, no force-push, no admin bypass, dismiss stale reviews
on push, signed commits required.

### 21.6 Pre-commit (local mirror of CI)
A `.pre-commit-config.yaml` runs the cheap subset locally:
yaml-lint, json-lint, KQL formatter, schema regen check,
linters #1, #3, #6, #11, #15 from §20. This is the *same code paths* CI
uses (no duplication), invoked via `python -m contentops lint --fast`.

---

## 22. Update-PR lifecycle — concrete example

To make §19 concrete, here is the end-to-end flow for an upstream template
update (stream #3):

1. **Tue 02:00 UTC** — `templates-catalog.yml` runs on schedule
   (`workflow_dispatch` also enabled).
2. Pipeline lists `alertRuleTemplates` from each managed workspace; finds
   template `BruteForceAttack` advanced from `1.4.0` (what we have) to
   `2.1.0` (upstream).
3. Pipeline computes structural diff (KQL, severity, tactics) between the
   two template versions and against our local overrides in
   `content/analytics/aad-brute-force-001.yml`.
4. Pipeline checks branch `upstream/templates/aad-brute-force-001`.
   - If the branch exists and its tree hash equals the freshly-computed
     hash → **no-op** (already proposed, awaiting review).
   - If the branch exists with a different hash and **no human commits**
     since the last bot push → force-update with `--force-with-lease`.
   - If the branch exists with **human commits** → open a *follow-up* PR
     against the existing branch with the new upstream delta. Never
     overwrite human work.
5. Pipeline opens / updates the PR
   `[upstream:templates] aad-brute-force-001 1.4.0→2.1.0` with:
   - structured diff table,
   - rendered KQL side-by-side,
   - link to the upstream template + Microsoft changelog,
   - labels `auto-generated`, `upstream:templates`, `risk:medium`,
   - CODEOWNERS auto-request `@org/soc-analytics`.
6. PR triggers the full §21 matrix:
   - `build-yaml` ✓ — envelope still valid.
   - `build-kql` ✓ — new KQL parses.
   - `lint-table-refs` (warn) — new template references `SecurityEvent`
     which our connector enumeration shows is enabled. Pass.
   - `plan-dev` posts: "1 analytic rule will UPDATE; threshold 5→3,
     query body changed by 14 lines." ✓
   - `plan-prod` ✓ (read-only).
   - `review-policy` ✓ — Severity unchanged (High), createIncident still true.
7. Analyst reviews, possibly tweaks the threshold (their FP-rate data shows
   3 is too noisy; bumps to 4) and pushes a commit to the bot's branch.
8. On the next Tuesday run, pipeline detects upstream still at 2.1.0 → diff
   unchanged → no-op (the human commit is preserved).
9. Analyst merges → `deploy-dev.yml` applies → SOC validates over the week
   → tags `v2026.04.30-rc.1` → `promote-test.yml` (env approval) → tags
   `v2026.04.30` → `promote-prod.yml` (env approval, 2 reviewers).
10. State file (§13) records `aad-brute-force-001` last-applied template
    version is now `2.1.0`. Next `templates-catalog.yml` run sees no diff.

Same loop, parameterized, runs for solutions, schemas, tables, drift, and
community streams. **The pipeline opens PRs; humans merge. Always.**

---

## 23. Open questions (need a human decision)

1. **One repo or many?** I assume one repo (`SIEMContent`) covering all
   asset types and all environments. Alternative: one repo per asset type
   (`siem-analytics`, `siem-playbooks`). One-repo is simpler for promotion
   and CODEOWNERS; many-repo isolates blast radius and makes per-team
   ownership cleaner. **Default: one repo.**
2. **One Defender XDR tenant or many?** v2 assumes one. Multi-tenant
   Defender requires a foreach over tenants and per-tenant App Regs (Graph
   has no cross-tenant app permissions for `CustomDetection.ReadWrite.All`).
3. **Sentinel Repositories side-by-side?** Some teams may want to keep
   workbooks/playbooks in Sentinel Repositories (because the native flow is
   simpler) and only this pipeline for analytics + Defender. This is
   *fine* and possibly the pragmatic answer.
4. **State file: where?** Orphan Git branch (auditable but noisy), Azure
   Storage blob (clean but extra resource), or no state at all (rely on
   collect-as-truth). I lean Azure Storage blob per env.
5. **Versioning of the platform itself**: this repo also hosts the Python
   pipeline. Pin pipeline version per env, or always-latest? Recommended:
   pipeline is versioned with the repo; workflows install from the same
   commit they're triggered by — one fewer thing to drift.
