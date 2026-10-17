# Sentinel automation rules (`sentinel_automation_rule`)

> Handler: [`contentops/handlers/sentinel_automation_rule.py`](../../contentops/handlers/sentinel_automation_rule.py)
> · Model: [`sentinel_automation_rule_models.py`](../../contentops/handlers/sentinel_automation_rule_models.py)
> · Scaffold: `contentops new sentinel_automation_rule <id>`

Automation rules are Microsoft Sentinel's response and noise-control
layer: when an incident (or alert) is created or updated and matches
the rule's conditions, the rule changes incident properties, adds
tasks, or runs a playbook. **Incident suppression is just an automation
rule** whose action closes the incident with a classification; it is
not a separate kind.

Automation rules are a **support kind** (`NON_DETECTION_ASSETS`): they
carry no KQL and no ATT&CK mapping, use the lighter
`SupportAssetMetadata` block, run a reduced META lint set
(META001 / META002 / META008), and are excluded from coverage and the
detection report. Their default management mode is **`monitor`** —
see [Management modes](#management-modes).

## API

| | |
|---|---|
| Resource | `Microsoft.SecurityInsights/automationRules/{guid}` under the workspace |
| api-version | `2025-09-01` (stable; pinned as `AUTOMATION_API_VERSION`, used by apply and collect) |
| ARM name | `metadata.arm_name` when collected; otherwise `uuid5(NAMESPACE_URL, envelope.id)` — stable, idempotent |
| ETag | yes (`If-Match` on PUT, 412 surfaces as a per-asset failure) |
| Verification | projection hash: display name, order, trigger flags, expiry presence, action count + sorted action types, sorted playbook resource ids (lower-cased), sorted condition keys. **Not** detected: a changed action parameter (e.g. the severity a ModifyProperties action sets). |
| RBAC | `Microsoft.SecurityInsights/automationRules/write` (Microsoft Sentinel Contributor). To *run* playbooks, the **Azure Security Insights** service principal needs **Microsoft Sentinel Automation Contributor** (`f4c81013-99ee-4d62-a7ee-b3f1f648599a`) on the playbook resource group — a one-time Owner-level grant the pipeline reports in `conformance` but never performs. |

## Envelope

```yaml
id: suppress-admin-role-additions-iam-migration
version: 1.0.0
asset: sentinel_automation_rule
status: production
metadata:
  owner: detection-engineering@example.com
  runbookUrl: https://wiki.example.com/soc/suppressions/iam-migration
  description: Auto-closes incidents from the privileged-role rule when the actor is the IAM migration account. Remove when PRJ-123 closes.
payload:
  displayName: "Suppress: privileged role additions by IAM migration account (PRJ-123)"
  order: 5                              # 1..1000, assigned by you
  triggeringLogic:
    isEnabled: true
    triggersOn: Incidents               # Incidents | Alerts
    triggersWhen: Created               # Created | Updated
    expirationTimeUtc: "2026-12-31T23:59:59Z"
    conditions:
      - conditionType: Property
        conditionProperties:
          propertyName: IncidentRelatedAnalyticRuleIds
          operator: Contains
          propertyValues: ["analytic:a-user-added-an-account-to-a-privileged-role"]
      - conditionType: Property
        conditionProperties: {propertyName: AccountName, operator: Equals, propertyValues: ["svc-iam-migration"]}
  actions:
    - order: 1
      actionType: ModifyProperties
      actionConfiguration:
        status: Closed
        classification: BenignPositive
        classificationReason: SuspiciousButExpected
        classificationComment: "IAM migration PRJ-123, approved CAB-456"
    # - order: 2
    #   actionType: RunPlaybook
    #   actionConfiguration: {playbook: notify-soc-teams-channel}
```

The payload mirrors the ARM `properties` block one-to-one. Condition
types are the five ARM types (`Boolean`, `Property`, `PropertyArray`,
`PropertyArrayChanged`, `PropertyChanged`); `conditionProperties` is
passed through.

### Reference by envelope id, never by GUID

Two pieces of sugar keep subscription and tenant GUIDs out of
`detections/`:

| Where | Write | Resolved at apply to |
|---|---|---|
| `RunPlaybook` action | `playbook: <sentinel_playbook id>` | `/subscriptions/<sub>/resourceGroups/<playbooksResourceGroup>/providers/Microsoft.Logic/workflows/<id>` + `tenantId` |
| `IncidentRelatedAnalyticRuleIds` / `AlertAnalyticRuleIds` value | `analytic:<sentinel_analytic id>` | `<workspace>/providers/Microsoft.SecurityInsights/alertRules/<that envelope's arm_name>` |

`collect` reverses both when the id falls inside the configured
workspace / playbook resource group; foreign ids stay raw. gitleaks
(`azure-guid-in-support-asset-envelope`) fails CI on a real GUID in
this directory. Dangling references are errors at lint time
(PAYLOAD007) and at plan time (dependency check), so apply never sends
a rule ARM would reject with 400.

## Validation and lint

| Check | Where | Severity |
|---|---|---|
| `displayName` ≤ 500, `order` 1..1000, unique action `order`, `expirationTimeUtc` parses | model | validate error |
| `triggersOn: Alerts` ⇒ `triggersWhen: Created` and only `RunPlaybook` actions | model | validate error |
| `RunPlaybook` has exactly one of `playbook` / `logicAppResourceId` | model | validate error |
| `status: Closed` ⇔ `classification` set | model | validate error |
| **Close action with zero conditions** (would auto-close every incident) | model + PAYLOAD014 | validate error / lint error |
| Close action not scoped to analytics / custom-detection rules | PAYLOAD014 | warning |
| `playbook:` / `analytic:` reference to a missing envelope | PAYLOAD007 + dependency check | error |
| `expirationTimeUtc` in the past | PAYLOAD008 | warning (apply skips; collect imports as `deprecated`) |
| Duplicate `order` on the same trigger | PAYLOAD009 | warning (ARM accepts duplicates and runs them in an unspecified sequence) |

## Operational notes

- **Deploy order.** Playbooks apply first, every existing kind next,
  automation rules last (`APPLY_ORDER_BY_ASSET`), so a rule's
  playbook and analytics references exist remotely before the PUT.
  `apply --asset sentinel_automation_rule` on a brand-new playbook can
  still race; ARM's 400 surfaces as `error-400`.
- **`order` is git-owned.** Dragging rules in the portal renumbers
  many rules; drift reports that on purpose because execution
  sequence is security-relevant.
- **Expired rules.** ARM rejects a PUT whose expiry has passed. Apply
  skips them with a clear detail; collect imports them as
  `status: deprecated` so the active set stays honest and `prune` can
  remove them behind its gates.
- **Defender portal.** Once the workspace is onboarded to the Defender
  portal, incident-created rules also fire for Defender XDR incidents;
  alert-created rules fire only for Sentinel analytics alerts.
- **Blast radius.** A close rule is silence, not noise. Keep every
  suppression scoped to specific analytics rules, give it an expiry,
  and say why in `classificationComment` and `metadata.description`.

## Management modes

`assetModes` in `config/tenant.yml` (per workspace) — default
**`monitor`** for this kind, in code, so an upgraded fork whose tenant
secret pre-dates the kind starts by watching:

| Mode | collect / drift / lint | apply | prune |
|---|---|---|---|
| `monitor` (default) | normal | per-asset skip (`status: monitor`, audited as skipped) | refuses the kind |
| `managed` | normal | normal | behind `purgeAllowed` / `maxDelete`, and never for a kind with zero local envelopes unless `--allow-empty-kind` |

See [`docs/operations/upgrading-to-support-assets.md`](../operations/upgrading-to-support-assets.md)
for the opt-in ladder and
[`sentinel_playbooks.md`](sentinel_playbooks.md) for the playbooks these
rules call.
