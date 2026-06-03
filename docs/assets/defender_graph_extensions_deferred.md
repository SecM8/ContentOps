# Defender XDR Graph beta extensions — DEFERRED (endpoints don't exist)

> **How to track GA status.** The canonical source is the
> [Microsoft Defender XDR — What's new](https://learn.microsoft.com/en-us/defender-xdr/whats-new)
> page and the
> [Microsoft 365 roadmap](https://www.microsoft.com/microsoft-365/roadmap) —
> read those first. F11 (`contentops defender-extensions-probe`) is a
> secondary canary: it runs HEAD against each endpoint and exits 2
> when one becomes reachable. Treat its `available=true` rows as
> "interesting, verify against the Defender roadmap before acting"
> rather than "Microsoft has GA'd this." HTTP 200 from a half-shipped
> preview looks identical to HTTP 200 from a stable GA endpoint, and
> HTTP 405 (see 2026-05-15 finding below) means the path now exists
> but the verb is rejected — the rollout is in progress, not done.

The master spec called for handlers covering three Defender XDR
extension surfaces:

| Spec ref | Asset | Endpoint claimed by spec |
|---|---|---|
| §4-b | Detection tuning rules | `/security/rules/detectionTuningRules` |
| §4-c | Alert suppression rules | `/security/alerts/v2` (suppression endpoints) |
| §4-d | Defender saved queries | `/security/savedQueries` |

### 2026-05-06 — endpoints don't exist

A live probe of the production tenant's Microsoft Graph beta
(`/beta/security/...`) on **2026-05-06** found:

| Endpoint | Result |
|---|---|
| `/beta/security/savedQueries` | `400 Bad Request — Resource not found for the segment 'savedQueries'` |
| `/beta/security/rules/detectionTuningRules` | `400 Bad Request — Resource not found for the segment 'detectionTuningRules'` |
| `/beta/security/alerts_v2` | `403 Forbidden — Missing application roles. API required roles: SecurityAlert.Read.All, SecurityAlert.ReadWrite.All, SecurityIncident.Read.All, SecurityIncident.ReadWrite.All` |

Two of the three endpoints **do not exist** at the path the spec
listed. The third (`alerts_v2`) exists but the suppression-rule
sub-resource path the spec implies isn't documented; even getting a
listing response requires `SecurityAlert.*` permissions the
pipeline's service principal doesn't currently hold.

### 2026-05-15 — rollout in progress (HTTP 405)

Re-probed during PR #161 (CI run on `chore/o3-p3-backlog`). Path
segments now resolve, but the verb is rejected:

| Endpoint | Status | Detail |
|---|---:|---|
| `/security/savedQueries` | `405` | endpoint live but rejects GET (verb-check needed) |
| `/security/rules/detectionTuningRules` | `405` | endpoint live but rejects GET (verb-check needed) |
| `/security/alertSuppressionRules` | `405` | endpoint live but rejects GET (verb-check needed) |

**Interpretation.** Microsoft has placed the three paths but they are
not yet serving GET responses (probably either accepting POST only for
write-side previews, or rolling out region-by-region). This is the
canonical "partway through GA" signal — **don't author handlers yet**.
Wait for the probe to report HTTP 200 from GET against at least one
endpoint, or for the Defender roadmap / "What's new" page to formally
announce the surface.

The scheduled `.github/workflows/defender-graph-probe.yml` runs every
Tuesday at 06:00 UTC and will surface the next transition.

### 2026-05-23 — still 405; probe tightened to match this rule

Re-probed via manual dispatch (run
[26328263924](https://github.com/KustoKing/SIEMContent/actions/runs/26328263924)).
All three endpoints **still return HTTP 405** — same state as
2026-05-15, no movement in the eight days since. Microsoft Learn
search still returns no Graph CRUD documentation for any of the three
resource paths (only the related audit-record type
[`mS365DSuppressionRuleAuditRecord`](https://learn.microsoft.com/graph/api/resources/security-ms365dsuppressionruleauditrecord?view=graph-rest-beta)
exists, which catalogs portal-side mutations but is not itself a CRUD
surface).

**Probe behaviour fixed at the same time.** The probe used to
classify 405 as `available=true`, which made every weekly run since
2026-05-15 exit 2 — a false positive against the playbook's actual
decision rule ("wait for HTTP 200 from GET"). The probe now treats
405 as `available=false` (with the `endpoint live but rejects GET …
not GA` detail still visible in the report) so the workflow only
exits 2 when there's something genuinely new to act on. Code at
`contentops/defender_extensions_probe.py:_classify`; tests at
`tests/v2/test_defender_extensions_probe.py::test_probe_405_is_NOT_available_but_keeps_verb_note`.

**Permissions update.** The pipeline's App Registration now holds
`CustomDetection.ReadWrite.All` (verified end-to-end via the live
CRUD round-trip at `tests/integration/test_defender_custom_detection_crud.py`,
6-second pass on 2026-05-23) and `ThreatHunting.Read.All` (new). The
runtime is therefore ready the moment any of the three deferred
endpoints transitions to a documented GA-with-CRUD surface and a
matching application permission is published — no further App Reg
work needed for the most likely Defender-XDR shapes.

## Status

These three handlers are **deferred until Microsoft ships the
endpoints** (or until the spec is corrected to point at the real
endpoints, if they exist on a different path). The pipeline's
`DefenderClient` (`contentops/defender/client.py`) is the production
Graph beta client; a new handler would either use it directly (if
the new endpoint sits under `/beta/security/rules/...`) or take a
small refactor to parameterise the base URL. Either way the gating
constraint is the API surface itself, not the pipeline.

## What did get built for Defender XDR

| Asset | Handler | Status |
|---|---|---|
| Custom detection rules | `contentops.handlers.defender_custom_detection` | ✅ Implemented |

That's the only Defender handler in the repo today. It targets
`/beta/security/rules/detectionRules` and has live integration test
coverage at `tests/integration/test_defender_custom_detection_crud.py`.

A second Defender handler — `contentops.handlers.defender_ti_indicator`
(Threat Intelligence indicators against `/security/tiIndicators`) —
was implemented at one point and **removed in commit `2b31f07`**
("refactor: reduce asset taxonomy to 6 detection-engineering
essentials") as part of the asset-taxonomy reduction. Recoverable
from git history at commit `af0c623` if the taxonomy decision is
ever reversed.

## When to revisit

Run the scheduled probe on demand via `gh workflow run defender-graph-probe.yml`
(or wait for the weekly Tuesday 06:00 UTC schedule), or invoke
`contentops defender-extensions-probe` locally once Microsoft
announces the endpoints. If they ship under different names or under
a different RP namespace, adjust the spec reference in this document
and add the corresponding handlers.
