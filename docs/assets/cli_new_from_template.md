# `contentops new --from-template` — scaffold a rule from a Microsoft template

Microsoft Sentinel ships ~500 alert rule templates with each Content
Hub solution. These are read-only ARM resources at
`Microsoft.SecurityInsights/alertRuleTemplates` that carry a working
KQL body, MITRE tactics/techniques, severity, and threshold defaults.

`contentops new --from-template <template-guid>` fetches one of these
templates and writes a v2 envelope that's ready for `contentops plan`
and `contentops apply` — replacing the old "open the portal, screenshot,
manually copy the KQL" loop.

## Discovery

Find the template GUID by substring search against ARM name or
`displayName`:

```
$ contentops new --search-template "brute force"
Found 5 template(s) matching 'brute force':
  a6c435a2-b1a0-466d-b730-9f8af69262e8     Scheduled  Medium    Brute force attack against user credentials (Uses Authentication Normalization)
  3fbc20a4-04c4-464e-8fcb-6667f53e4987     Scheduled  Medium    Brute force attack against a Cloud PC
  e1ce0eab-10d1-4aae-863f-9a383345ba88     Scheduled  Low       SSH - Potential Brute Force
  ...
```

## Scaffolding

```
$ contentops new --from-template a6c435a2-b1a0-466d-b730-9f8af69262e8
wrote detections/sentinel_analytic/brute-force-attack-against-user-credentials-uses-authentication-normalization.yml
lint: clean
```

The envelope id is derived from the template's `displayName` via
slugify. Override with `--id`:

```
$ contentops new --from-template a6c435a2-b1a0-466d-b730-9f8af69262e8 --id brute-force-001
wrote detections/sentinel_analytic/brute-force-001.yml
```

## What the scaffold contains

```yaml
id: brute-force-001
version: 0.1.0
asset: sentinel_analytic
status: experimental                     # always — promote manually
metadata:
  owner: detection-engineering@example.com
  runbookUrl: https://example.com/runbooks/REPLACE-ME
  severity: medium                       # mapped from template severity
  tactics: [CredentialAccess]            # mapped from template tactics
  techniques: [T1110]                    # copied from template
  expectedAlertsPerDay: 1                # placeholder
  fpHandling: 'TODO: review FP rate ...'
payload:
  kind: Scheduled
  displayName: "Brute force attack against user credentials"
  description: "Identifies evidence of brute force activity..."
  enabled: true
  severity: Medium
  query: |                               # full KQL body from template
    let timeRange = 1d;
    ...
  queryFrequency: P1D
  queryPeriod: P1D
  triggerOperator: GreaterThan
  triggerThreshold: 0
  tactics: [CredentialAccess]
  techniques: [T1110]
  alertRuleTemplateName: a6c435a2-b1a0-466d-b730-9f8af69262e8
  templateVersion: "2.0.0"
```

The scaffold is intentionally `status: experimental` — promoting to
`production` is a manual step after the analyst tunes the threshold,
fills in the runbook URL, etc.

## Behaviour by alert kind

| Template kind | Scaffold payload |
|---|---|
| `Scheduled` | Full KQL + scheduling fields (queryFrequency, queryPeriod, triggerOperator, triggerThreshold) + tactics/techniques/entityMappings. |
| `NRT` | Same but no scheduling fields. |
| `MicrosoftSecurityIncidentCreation` | productFilter + displayName + description; toggle-only kind so the scaffold is small. |
| `Fusion` / `MLBehaviorAnalytics` / `ThreatIntelligence` | Toggle-only: `kind` + `alertRuleTemplateName` + `enabled: true`. |

## Limitations

- Templates are **workspace-scoped**: a Microsoft solution must be
  installed on the workspace before its templates appear. If you get
  `alertRuleTemplate ... not found` install the relevant Content Hub
  package first (or use `contentops collect --asset sentinel_content_package`
  to discover what's installed).
- The mapping from template tactics to metadata-block tactics drops
  the wider Sentinel taxonomy (`PreAttack`, `ImpairProcessControl`,
  `InhibitResponseFunction`) — the metadata schema only knows the
  14 standard ATT&CK tactics. Edit the metadata block by hand if the
  template uses one of the Sentinel-only tactics.
