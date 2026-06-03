# `detections/sentinel_analytic/`

Detection envelopes for the **Microsoft Sentinel analytic rule** asset
kind go here.

Sentinel analytic rules drive the alert pipeline — Scheduled, NRT,
Fusion, MLBA, ThreatIntelligence, and MicrosoftSecurityIncident
creation kinds all live under this asset. Deployed via ARM at
`Microsoft.SecurityInsights/alertRules` (API version
`2025-07-01-preview`).

## Placement

Each rule is one YAML file:

```
detections/sentinel_analytic/<rule-id>.yml
```

The `<rule-id>` is the canonical envelope id (kebab-case slug). Files
under this directory are gitignored — they live on your local clone
and never get committed back to this public pipeline repo.

## Authoring

Scaffold a new rule:

```bash
contentops new sentinel_analytic <rule-id>
```

Or start from a Microsoft Marketplace template:

```bash
contentops new --search-template "brute force"
contentops new --from-template <guid> --id <rule-id>
```

The pipeline's strict mode (`tenant.policy.scaffoldStrict: true`)
requires the META002–005 authoring fields:
`metadata.description`, `metadata.attackDescription`,
`metadata.references`, `metadata.falsePositives`. The
`scripts/list_missing_metadata.py` helper produces a checklist of
rules missing those fields.

## See also

- [`../templates/sentinel-template.yml`](../templates/sentinel-template.yml) — scaffold reference.
- [`../../docs/reference/asset-coverage.md`](../../docs/reference/asset-coverage.md) — endpoint, RBAC, hash projection.
- [`../../docs/reference/envelope-schema.md`](../../docs/reference/envelope-schema.md) — canonical YAML shape.
- [`../../docs/assets/sentinel_alert_rules.md`](../../docs/assets/sentinel_alert_rules.md) — per-kind authoring guide.
