# Asset coverage

> One row per asset kind. Endpoint, RBAC, hash projection, known
> quirks, and live-test status. The taxonomy lives in
> [`contentops/core/asset.py`](../../contentops/core/asset.py); each
> handler under [`contentops/handlers/`](../../contentops/handlers/).

The handler protocol is documented in
[`architecture.md`](architecture.md#the-handler-protocol). For
authoring details on individual asset kinds beyond what fits in this
table, see [`docs/assets/`](../assets/).

The kind enum has **6 values today** — the focused detection-engineering
surface (two strategic detection kinds, four supporting kinds). The
broader Sentinel everything-management surface that earlier versions
of this document described (workbooks, automation, playbooks, hunts,
content packages, TI indicators, workspace-manager kinds, source
control, incidents, settings, onboarding, metadata, summary rules)
was deleted in the asset-taxonomy reduction (PR #122 / #129). See the
"Historical kinds" section at the bottom for what was removed and how
to recover the handlers from git history if you need them.

---

## Quick legend

- **W** = write-capable handler (validate/plan/apply/delete).
- **R** = read-only handler — `apply` returns SKIP; `delete` raises
  `NotSupportedError`. Useful for `collect`/`drift` only.
- **Hash projection** = the field set the post-apply verifier hashes.
  "Field hash" = SHA-256 over a deterministic JSON projection of named
  fields; "Projection hash" = SHA-256 over a derived dict (used when
  the API normalises the body too aggressively for byte-level hashing).
  See [`contentops/handlers/_verify.py`](../../contentops/handlers/_verify.py).
- **CRUD test** = an entry under `tests/integration/` exercises the
  full create/update/delete cycle against a live tenant.

---

## Sentinel — write-capable, drift-capable

| # | Asset kind | Class | API | RBAC | ETag | Hash projection | CRUD test | Notes / quirks |
|---|---|---|---|---|---|---|---|---|
| 1 | `sentinel_analytic` | `SentinelAnalyticHandler` | `Microsoft.SecurityInsights/alertRules` (ARM 2025-07-01-preview) | Microsoft Sentinel Contributor on workspace | yes (If-Match) | Field hash, kind-dependent — Scheduled: `displayName,query,severity,tactics,queryFrequency,queryPeriod,triggerOperator,triggerThreshold,enabled`; NRT: subset; MSI: filter fields; Fusion/MLBA/TI: `alertRuleTemplateName,enabled` | ✓ `tests/integration/test_sentinel_analytic_crud.py`, `test_sentinel_alert_kinds_crud.py` | ARM rejects PUT if `templateVersion` is set without `alertRuleTemplateName`. Caught by PAYLOAD001 lint + plan-time `validate()` + apply-time scrub ([`contentops/handlers/sentinel_analytic.py:100`](../../contentops/handlers/sentinel_analytic.py)). |
| 2 | `sentinel_hunting` | `SentinelHuntingHandler` | LA workspace `savedSearches` (Microsoft.OperationalInsights, category=`Hunting Queries`) | Sentinel Contributor + LA Contributor | yes | Field hash: `displayName,query,category,tags` | ✓ `tests/integration/test_sentinel_extras_crud.py` | No enable/disable — deprecated removal goes via `prune`. |
| 3 | `sentinel_watchlist` | `SentinelWatchlistHandler` | `Microsoft.SecurityInsights/watchlists` + `watchlistItems` | Sentinel Contributor | yes | Field hash + item-count check (W4.5-B): expected vs actual `watchlistItems` rows | ✓ `tests/integration/test_sentinel_extras_crud.py` | Cell-level item equality intentionally not hashed — ARM normalisation makes it unstable ([`contentops/handlers/sentinel_watchlist.py:233`](../../contentops/handlers/sentinel_watchlist.py)). For files >3.8 MB, SAS-URI upload required. |
| 4 | `sentinel_parser` | `SentinelParserHandler` | LA `savedSearches` (category=`Function`) | Sentinel + LA Contributor | yes | Field hash: `displayName,query,category,functionAlias,functionParameters,tags` | ✓ `tests/v2/test_sentinel_extras.py` (apply-verify, no live CRUD) | Same resource family as hunting queries; `category=Function` discriminates. |
| 5 | `sentinel_data_connector` | `SentinelDataConnectorHandler` | `Microsoft.SecurityInsights/dataConnectors` (legacy) + `dataConnectorDefinitions` (CCP) | Sentinel Contributor | yes | Projection hash: `kind,tenantId,enabledDataTypes(sorted-by-name where state=enabled),dataTypeCount` | ✗ deferred — many connector kinds require interactive portal consent | Manual-consent connectors PUT succeeds but reports "disconnected" until a human clicks Connect ([`sentinel_data_connector.py:216`](../../contentops/handlers/sentinel_data_connector.py)). Pydantic model uses `extra='allow'` so new kinds don't break PRs. |

## Defender — write-capable, drift-capable

| # | Asset kind | Class | API | RBAC | ETag | Hash projection | CRUD test | Notes / quirks |
|---|---|---|---|---|---|---|---|---|
| 6 | `defender_custom_detection` | `DefenderCustomDetectionHandler` | Graph beta `/security/rules/detectionRules` | `CustomDetection.ReadWrite.All` (App permission, admin-consented) | no (Graph beta limitation) | Field hash: `displayName,queryCondition.queryText,schedule,actions,alertTemplate.severity,alertTemplate.title,alertTemplate.category` | ✓ `tests/integration/test_defender_custom_detection_crud.py` | Upserts by `displayName` — per-apply name→graph-id map built lazily ([`defender_custom_detection.py:8`](../../contentops/handlers/defender_custom_detection.py)). No If-Match; concurrent edits race. |

---

## Preview / beta API risk

One of the six write-capable handlers uses a Microsoft API surface
that is **not generally available** at the time of writing:

- **`defender_custom_detection`** writes to Microsoft Graph
  **beta** (`/security/rules/detectionRules`). Graph beta endpoints
  are explicitly versioned as preview by Microsoft and may change
  shape, semantics, or availability at any time without notice.

What this means in practice:

- **Schema drift** — a field name change in the Graph beta response
  body would break the field-hash post-apply verifier; the apply
  itself may still succeed but `verified=False` will surface in the
  audit chain. Diagnose with `contentops defender-roundtrip-diff
  <id> --raw` to see the literal API body before
  `_strip_server_fields` runs.
- **No ETag concurrency control** — unlike the Sentinel ARM
  endpoints, Graph beta does not implement `If-Match` for these
  rules. Two concurrent operators editing the same rule race; last
  writer wins. Mitigate by keeping `deploy.yml` concurrency-serial
  (already configured: `cancel-in-progress: false`).
- **Eventual deprecation** — when Microsoft GAs the Defender
  detection-rules API on the v1.0 Graph surface, the handler will
  need updating. The probe at `contentops defender-extensions-probe`
  watches three related Graph endpoints (`savedQueries`,
  `detection-tuning-rules`, `alert-suppression`) and flags
  availability changes.

The other five handlers (`sentinel_analytic`, `sentinel_hunting`,
`sentinel_watchlist`, `sentinel_parser`, `sentinel_data_connector`)
all use ARM REST endpoints under
`Microsoft.SecurityInsights` / `Microsoft.OperationalInsights` at
GA `preview` (`2025-07-01-preview`) or stable
(`2023-09-01` for `savedSearches`) API versions. These are
preview-versioned but stable in semantic — historically Microsoft
has carried preview ARM versions for years with backward-compatible
evolution.

Enterprise reviewers concerned about beta-API exposure should weigh
the operational lift of disabling Defender custom detection
management (set `defender.enabled: false` in `config/tenant.yml`)
against the value of detection-as-code for that engine.

---

## Hash projection — global rules

Across all write-capable handlers, the "hash projection" answers
*"what content do we hash to detect tamper or partial writes?"*. Two
flavours:

- **Field hash** — list of dotted paths into the API response body.
  Hash = SHA-256(canonical_json(extracted_dict)). Used when the API
  preserves the body byte-for-byte. Stable.
- **Projection hash** — handler builds a derived dict (e.g. sorted
  trigger names) and hashes that. Used when the API normalises the
  body so aggressively that a field hash would always mismatch.

Limitations are honest: a projection hash that names only "trigger
names + action types" cannot catch a parameter value flip inside an
action. The handlers that take this trade-off document it inline.

The verifier code is in
[`contentops/handlers/_verify.py`](../../contentops/handlers/_verify.py).
Common helpers
([`_strip_server_fields`](../../contentops/handlers/_verify.py)) remove
server-injected timestamps + `etag` + `provisioningState` before
hashing so the comparison stays stable across PUT/GET round-trips.

---

## Historical kinds (removed in PR #122 / #129)

The asset-taxonomy reduction removed 21 handlers that targeted the
broader Sentinel everything-management surface. The product is
intentionally focused on **detection engineering**, not
configuration-as-code for every Sentinel resource.

If you need to manage these from code, the handlers exist in git
history and can be recovered:

```bash
# List the deletion commits.
git log --diff-filter=D --name-only --pretty=format:'%h %s' -- contentops/handlers/ \
  | head -50

# Recover a single handler from history.
git show <sha>:contentops/handlers/sentinel_workbook.py > contentops/handlers/sentinel_workbook.py
```

The removed kinds were:

**Sentinel (write-capable, drift-capable)** — `sentinel_workbook`,
`sentinel_automation`, `sentinel_playbook`, `sentinel_content_package`,
`sentinel_hunt`, `sentinel_bookmark`, `sentinel_metadata`,
`sentinel_summary_rule`, `sentinel_ti_indicator`

**Sentinel (singleton, delete refused)** — `sentinel_onboarding`,
`sentinel_settings`

**Defender (write-capable)** — `defender_ti_indicator`

**Sentinel (read-only / collect-only)** —
`sentinel_workspace_manager_assignment`,
`sentinel_workspace_manager_configuration`,
`sentinel_workspace_manager_group`,
`sentinel_workspace_manager_member`,
`sentinel_source_control`, `sentinel_incident`,
`sentinel_incident_task`, `sentinel_watchlist_item`

Plus the deprecated `sentinel_solution` (folded into
`sentinel_content_package` before both were removed).

If you re-introduce one of these handlers, register it in
`contentops/core/asset.py`, the handler factory under
`contentops/cli/handler_factories.py`, and the lint coverage check in
`contentops/lint/coverage.py`. Tests must cover both
`tests/v2/` (handler unit tests) and `tests/integration/` (live
tenant CRUD). Add a row to this table in the same PR.

---

## Defender — extensions deferred

These Graph endpoints are *referenced* in design docs but have no
handler yet, because the endpoints are not GA / not exposed in beta.
See [`docs/assets/defender_graph_extensions_deferred.md`](../assets/defender_graph_extensions_deferred.md).

| Surface | Status | Why deferred |
|---|---|---|
| `savedQueries` | deferred | Endpoint not GA; schema unstable. |
| Detection-tuning rules | deferred | No public Graph endpoint for tuning rules. |
| Alert suppression | deferred | Surface managed via portal; no documented Graph endpoint. |

Roadmap proposal F11 (in [`roadmap.md`](roadmap.md)) is to re-probe
these quarterly behind an env flag so we know when Microsoft ships
them.
