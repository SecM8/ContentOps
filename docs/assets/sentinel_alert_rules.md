# Sentinel alert rules — every kind

Handler:   `contentops.handlers.sentinel_analytic.SentinelAnalyticHandler`
Asset:     `sentinel_analytic`
Endpoint:  `Microsoft.SecurityInsights/alertRules` (ARM `2025-07-01-preview`)

The single handler dispatches by `kind` for every alert rule the
Sentinel ARM API exposes. The Pydantic dispatcher is
`contentops.models.validate_sentinel_payload`.

## Supported kinds

| `kind`                              | What it is                                                                          | Authoring model                          |
|-------------------------------------|-------------------------------------------------------------------------------------|------------------------------------------|
| `Scheduled`                         | KQL-driven analytic rule, runs on a fixed cadence.                                  | Full payload — analyst-authored.         |
| `NRT`                               | Near-real-time KQL rule. Same shape as Scheduled minus `query{Frequency,Period}` and the trigger fields. | Full payload — analyst-authored.         |
| `MicrosoftSecurityIncidentCreation` | Promotes alerts from a connected MS security product (MDC, Defender for Identity, etc.) into Sentinel incidents. Filterable by severity, displayName whitelist / blacklist. | Filter-only.                              |
| `Fusion`                            | Microsoft-shipped multi-source correlation. Customer toggles enable / disable + per-source-subtype overlay (`sourceSettings`). | Toggle + overlay.                         |
| `MLBehaviorAnalytics`               | Microsoft-shipped behaviour analytics. Toggle only.                                 | Toggle, identified by `alertRuleTemplateName`. |
| `ThreatIntelligence`                | Microsoft-shipped threat-intel correlation. Toggle only.                            | Toggle, identified by `alertRuleTemplateName`. |

## YAML examples

### Scheduled

```yaml
id: my-scheduled-rule
version: "1.0.0"
asset: sentinel_analytic
status: production
metadata: {owner: team-soc}
payload:
  kind: Scheduled
  displayName: "Suspicious sign-in volume"
  severity: High
  enabled: true
  query: |
    SigninLogs
    | where ResultType != 0
    | summarize count() by IPAddress, UserPrincipalName
    | where count_ > 10
  queryFrequency: PT5M
  queryPeriod: PT1H
  triggerOperator: GreaterThan
  triggerThreshold: 0
  tactics: [InitialAccess]
  techniques: [T1078]
  incidentConfiguration:
    createIncident: true
  eventGroupingSettings:
    aggregationKind: SingleAlert
```

### MicrosoftSecurityIncidentCreation

```yaml
id: mdc-high-only
version: "1.0.0"
asset: sentinel_analytic
status: production
metadata: {owner: team-soc}
payload:
  kind: MicrosoftSecurityIncidentCreation
  displayName: "Microsoft Defender for Cloud — High severity only"
  enabled: true
  # ARM is locked to the legacy product names. "Microsoft Defender for
  # Cloud" (post-rebrand) is rejected as 400 Bad Request — Sentinel
  # surfaces the rebranded product even though we send the legacy name.
  productFilter: "Azure Security Center"
  severitiesFilter: [High]
  displayNamesExcludeFilter:
    - "Suspicious activity in your subscription"
```

### Fusion (toggle + overlay)

```yaml
id: fusion-default
version: "1.0.0"
asset: sentinel_analytic
status: production
metadata: {owner: team-soc}
payload:
  kind: Fusion
  alertRuleTemplateName: f71aba3d-28fb-450b-b192-4e76a83015c8
  enabled: true
  sourceSettings:
    - sourceName: Anomaly
      enabled: true
      sourceSubTypes:
        - sourceSubTypeName: AnomalousAccessToCloudResources
          enabled: false
          severityFilters: {filters: []}
```

### MLBehaviorAnalytics / ThreatIntelligence

```yaml
id: ml-anomalous-rdp
version: "1.0.0"
asset: sentinel_analytic
status: production
metadata: {owner: team-soc}
payload:
  kind: MLBehaviorAnalytics
  alertRuleTemplateName: fa118b98-de46-4e94-87f9-8e6d5060b60b
  enabled: true
```

## Drift round-trip

`SentinelAnalyticHandler.to_envelope` round-trips every kind. Two
`kind`-aware behaviours to know:

* **Scheduled / NRT / MicrosoftSecurityIncidentCreation**: the server-set
  `alertRuleTemplateName` and `templateVersion` are dropped. They are
  audit fields, not the identifier of the rule, and would always force
  a "changed" report.
* **Fusion / MLBehaviorAnalytics / ThreatIntelligence**: `alertRuleTemplateName`
  is *required* to identify the upstream Microsoft template, so it is
  preserved. `sourceSettings` is preserved on Fusion but excluded from
  the post-apply hash projection — ARM frequently echoes back a
  `sourceSettings` overlay we did not send.

## Post-apply hash projection

Per-kind projection keeps the post-apply verification deterministic
without false positives. See
`contentops.handlers.sentinel_analytic._hashed_fields_for_kind`.

| kind                                | Hashed fields                                                                                          |
|-------------------------------------|--------------------------------------------------------------------------------------------------------|
| `Scheduled`                         | displayName, query, severity, tactics, queryFrequency, queryPeriod, triggerOperator, triggerThreshold, enabled |
| `NRT`                               | displayName, query, severity, tactics, enabled                                                          |
| `MicrosoftSecurityIncidentCreation` | displayName, productFilter, severitiesFilter, displayNamesFilter, displayNamesExcludeFilter, enabled    |
| `Fusion` / `MLBehaviorAnalytics` / `ThreatIntelligence` | alertRuleTemplateName, enabled                                                       |

## Known limitations

* `Fusion`, `MLBehaviorAnalytics` and `ThreatIntelligence` only PUT
  successfully when the referenced `alertRuleTemplateName` exists in
  the target workspace. Templates ship with Content Hub solutions —
  install the solution before deploying these rules.
* The 412 ETag conflict path is reported as a per-asset failure, not a
  fatal exception. Re-run `contentops plan` to resolve drift first.
* `displayNamesFilter` and `displayNamesExcludeFilter` are validated to
  be disjoint at the model layer (the API silently accepts overlapping
  filters and produces ambiguous behaviour).
