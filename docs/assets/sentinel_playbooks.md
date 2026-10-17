# Sentinel playbooks (`sentinel_playbook`)

> Handler: [`contentops/handlers/sentinel_playbook.py`](../../contentops/handlers/sentinel_playbook.py)
> · Model: [`sentinel_playbook_models.py`](../../contentops/handlers/sentinel_playbook_models.py)
> · Scaffold: `contentops new sentinel_playbook <id>` (writes the envelope **and** the definition sidecar)

A playbook is a **Consumption Logic App** that Sentinel automation
rules call (and analysts run on demand). ContentOps deploys the
workflow plus one managed-identity **API connection** per connector it
uses, verifies what the playbook's managed identity still needs, and
keeps the whole thing under drift and prune — managed-tag only, so
Logic Apps built outside ContentOps in the same resource group are
never touched.

Playbooks are a **support kind** (`NON_DETECTION_ASSETS`): no KQL, no
ATT&CK, `SupportAssetMetadata`, reduced META lint, excluded from
coverage and the detection report, default mode **`monitor`**.
Standard (single-tenant) Logic Apps are out of scope.

## Files on disk

```
detections/sentinel_playbook/<id>.yml            # envelope
detections/sentinel_playbook/<id>.workflow.json  # definition — designer export, verbatim
```

The envelope points at the sidecar with `definitionFile:`; the loader
inlines it as `payload.definition`, so every handler, lint rule and
drift comparison works on the inlined form, and the writers
(`collect`, `drift --write`, `contentops new`) split it back out as
2-space-indented, key-sorted JSON. Edit the definition in the
designer's **code view** and paste it into the sidecar. A changed
sidecar requires a `version` bump of the `.yml`
(`scripts/check_version_bump.py` maps the two).

```yaml
id: notify-soc-teams-channel
version: 1.0.0
asset: sentinel_playbook
status: production
metadata:
  owner: detection-engineering@example.com
  runbookUrl: https://wiki.example.com/soc/playbooks/notify-soc
  description: Posts a summary of a new incident to the SOC webhook and comments on the incident.
payload:
  state: Enabled                       # Enabled | Disabled
  # location: westeurope               # optional; defaults to the workspace location
  connections:
    - name: azuresentinel              # apiName defaults to name; authMode from the known table
    - name: logs
      apiName: azuremonitorlogs
  roleAssignments:
    - role: Microsoft Sentinel Responder
      scope: workspace                 # workspace | playbookResourceGroup | <full ARM scope id>
  definitionFile: notify-soc-teams-channel.workflow.json
  parameters: {}                       # workflow parameter values, never $connections
```

## API

| | |
|---|---|
| Workflow | `Microsoft.Logic/workflows/<id>` (api `2019-05-01`), `identity: SystemAssigned`, tag `contentops-managed=true` |
| Connections | `Microsoft.Web/connections/<id>-<name>` (api `2016-06-01`), `kind: V1`, tags `contentops-managed=true` + `contentops-playbook=<id>`; `parameterValueType: Alternative` (Sentinel connector) or `parameterValueSet: managedIdentityAuth` |
| Resource group | `playbooksResourceGroup` on the workspace entry in `config/tenant.yml` (defaults to the workspace RG) |
| Discovery | one ARM resources query filtered on the managed tag; no per-workflow GET on untagged Logic Apps |
| ETag | opportunistic (`If-Match` when the GET-before-PUT returned one) |
| Verification | structural projection: location, state, identity type, sorted trigger names, sorted action names, sorted action types, sorted connector names. Logic Apps normalises definitions heavily, so **`verified=True` means "same shape", not "same inputs"** — a changed URL inside an action is not detected. |
| RBAC (deploy identity) | **Logic App Contributor** on the playbook RG (`Microsoft.Logic/workflows/write` + `Microsoft.Web/connections/write`), plus Reader on it for the role checks |

## Apply order and failure behaviour

1. Each declared connection, in order: GET (etag) → PUT → GET-back
   check that `api.id` matches the connector and the auth marker is
   managed identity. **Any failure stops before the workflow PUT**, so
   a half-deployed playbook never references a missing connection.
2. The workflow PUT with `$connections` rewritten to the deployed
   connection ids (the canonical `$connections` parameter declaration
   is injected into the definition when absent).
3. GET-back + projection compare.
4. Role verification (below).

`delete` (prune) removes the workflow and then only the connections
tagged `contentops-playbook=<id>`; untagged connections are never
touched.

## Connections: declared, never pasted

Every connection is managed-identity authenticated. No secrets, no
OAuth consent tokens, no `$connections` values live on disk.

- Known managed-identity connectors and their ARM shape:
  `azuresentinel` (Alternative), `azuremonitorlogs`, `keyvault`,
  `azureblob`, `azurequeues`, `azuretables`, `servicebus`,
  `azureeventgridpublish`, `azureloganalyticsdatacollector`
  (parameterValueSet). Verify a connector's managed-identity support
  in its connector reference before relying on it.
- Connectors that only work with interactive OAuth consent
  (`office365`, `teams`, `sharepointonline`, …) are **rejected at
  validate** — they cannot be deployed from CI.
- A connector outside the known table needs an explicit `authMode`
  and gets PAYLOAD010 (warning) so you verify it in the designer.

## Roles: declared, verified, never assigned

`roleAssignments` lists what the playbook's managed identity needs. On
every successful apply the handler reads the role assignments for the
identity at each declared scope and, for anything missing, puts the
exact command in the result (`extra.missingRoleAssignments` and the
audit message):

```
az role assignment create --assignee-object-id <principalId> \
  --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Responder" --scope <workspace resource id>
```

`contentops conformance` repeats the check so the ask to the customer
can be generated from one command. Assignment stays a human,
Owner-level step; the deploy identity never holds User Access
Administrator. Well-known roles accepted by name: Microsoft Sentinel
Reader / Responder / Contributor, Log Analytics Reader / Contributor,
Reader; any role-definition GUID is also accepted.

For automation rules to *run* the playbook, the **Azure Security
Insights** service principal additionally needs **Microsoft Sentinel
Automation Contributor** on the playbook RG — reported by conformance
as INFO, see [`sentinel_automation_rules.md`](sentinel_automation_rules.md).

## Adopting existing playbooks

Discovery is managed-tag only, so a Logic App built in the portal is
invisible to `collect`, `drift` and `prune` until you adopt it:

```bash
contentops collect --asset sentinel_playbook --adopt <workflow-name> [--adopt <other>]
```

This stamps the `contentops-managed` tag on the named workflow (an
explicit, audited write that is allowed in `monitor` mode because you
named the resource; still gated by `writeAllowed`) and imports it.
Playbooks whose connections are not managed-identity shaped are
skipped with a warning naming the workflow — convert the connection in
the designer first.

## Cost, throttling, verification caveat

Consumption Logic Apps bill per action execution and are subject to
Logic Apps concurrency limits. A playbook attached to a broad
incident-created automation rule can run thousands of times a day;
prefer scoped conditions and `expirationTimeUtc` on the calling rule.
Treat `verified=True` as "the deployed workflow has the triggers,
actions and connectors we sent", not as byte equality — review the
sidecar diff in the PR for what the actions actually do.

## Lint

| Rule | Severity | Catches |
|---|---|---|
| PAYLOAD010 | warning | connection for a connector outside the known managed-identity table |
| PAYLOAD012 | warning | uses the `azuresentinel` connector but declares no `roleAssignments` |
| validate | error | OAuth-only connector, undeclared `$connections` reference in the definition, `$connections` in `parameters`, duplicate connection names, envelope id > 64 chars |

Management modes are the same as for automation rules (default
`monitor`); see
[`docs/operations/upgrading-to-support-assets.md`](../operations/upgrading-to-support-assets.md).
