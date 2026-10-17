# `detections/sentinel_automation_rule/`

Microsoft Sentinel **automation rules** — including the "suppression"
rules that auto-close noisy incidents — as code. One
`detections/sentinel_automation_rule/<id>.yml` per rule.

- ARM resource: `Microsoft.SecurityInsights/automationRules/{guid}`
  (api-version `2025-09-01`). Authored rules get a stable
  `uuid5(envelope id)` GUID; collected rules keep their portal GUID in
  `metadata.arm_name`.
- Scaffold: `contentops new sentinel_automation_rule <id>`.
- Reference other resources by **envelope id**, never by ARM id:
  `playbook: <sentinel_playbook id>` in a `RunPlaybook` action and
  `analytic:<sentinel_analytic id>` in an `IncidentRelatedAnalyticRuleIds`
  / `AlertAnalyticRuleIds` condition. The handler resolves them at apply
  time; `collect` reverses them. gitleaks rejects subscription / tenant
  GUIDs in this directory.
- A close action (`status: Closed`) **must** have at least one condition
  (PAYLOAD014 + handler validate), should be scoped to analytics rules,
  and should carry `expirationTimeUtc`. Expired rules import as
  `status: deprecated`; apply skips them.
- `order` is yours to assign (1..1000); PAYLOAD009 warns on duplicates
  per trigger. Drift reports portal reorders.
- Default management mode is **monitor** (`assetModes` in
  `config/tenant.yml`): collect / drift / lint only until you opt in.

Full reference: [`docs/assets/sentinel_automation_rules.md`](../../docs/assets/sentinel_automation_rules.md).
