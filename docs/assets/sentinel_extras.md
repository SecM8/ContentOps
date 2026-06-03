# Sentinel content-management assets — parsers, hunts, bookmarks, metadata

Four resource types that round out Sentinel's content surface:

| Asset                | Endpoint                                                    | Handler module                            |
|----------------------|-------------------------------------------------------------|-------------------------------------------|
| `sentinel_parser`    | `Microsoft.OperationalInsights/.../savedSearches` (`category=Function`) | `contentops.handlers.sentinel_parser`       |
| `sentinel_hunt`      | `Microsoft.SecurityInsights/hunts` (api `2025-07-01-preview`) | `contentops.handlers.sentinel_hunt`         |
| `sentinel_bookmark`  | `Microsoft.SecurityInsights/bookmarks` (api `2025-07-01-preview`) | `contentops.handlers.sentinel_bookmark`     |
| `sentinel_metadata`  | `Microsoft.SecurityInsights/metadata` (api `2025-07-01-preview`) | `contentops.handlers.sentinel_metadata`     |

Each handler implements the standard `validate / plan / apply /
list_remote / to_envelope` contract; all four are drift-capable and
are wired into the registry via `contentops.cli.handler_factories`.

## Parser (`sentinel_parser`)

A KQL function exposed as a `savedSearch` whose `category` is
`Function`. Other queries can call it via the configured
`functionAlias`. Distinct from a Hunting Query (`category="Hunting
Queries"`) — the category discriminator is what keeps them in
separate drift inventories.

```yaml
id: get-failed-logons
version: "1.0.0"
asset: sentinel_parser
status: production
payload:
  displayName: "GetFailedLogons"
  category: Function
  functionAlias: GetFailedLogons
  functionParameters: ""
  query: |
    let GetFailedLogons = (start:datetime=ago(1h), end:datetime=now()) {
        SecurityEvent
        | where TimeGenerated between (start .. end)
        | where EventID == 4625
    };
    GetFailedLogons
  version: 2
```

Hash projection: `displayName`, `query`, `category`, `functionAlias`,
`functionParameters`, `tags`. Server fields (`etag`, `tenantId`) are
excluded.

## Hunt (`sentinel_hunt`)

Hypothesis-driven investigation tracker. Distinct from a Hunting
*Query* — the query is the primitive, the Hunt is the workflow on top.

```yaml
id: lateral-via-wmi
version: "1.0.0"
asset: sentinel_hunt
status: production
payload:
  displayName: "Hypothesis: lateral movement via WMI"
  description: "Investigate suspicious WMI usage on jump boxes."
  hypothesisStatus: Unknown      # Unknown | Validated | Invalidated
  status: New                    # New | Active | InProgress | Backlog | Approved | Closed | Failed | Succeeded
  attackTactics: [LateralMovement]
  attackTechniques: [T1047]
  labels: [q2-hypothesis]
  owner:
    objectId: "00000000-0000-0000-0000-000000000000"
    ownerType: User
    userPrincipalName: "alice@example.com"
```

Hash projection: `displayName`, `description`, `hypothesisStatus`,
`status`, `attackTactics`, `attackTechniques`, `labels`. Audit fields
(`createdBy`, `createdTimeUtc`) are dropped on round-trip.

**Resource name = GUID.** ARM rejects human slugs for hunt names with
HTTP 400. The handler derives a stable GUID via
`uuid5(NAMESPACE_URL, envelope.id)` so the same `id` always produces
the same remote resource.

## Bookmark (`sentinel_bookmark`)

A KQL query result an analyst pinned for follow-up. Useful for
encoding incident-driven content in git so it survives portal cleanup.

```yaml
id: sus-signin-2026-q2
version: "1.0.0"
asset: sentinel_bookmark
status: production
payload:
  displayName: "Suspicious sign-in pattern"
  query: |
    SigninLogs
    | where ResultType != 0
    | take 50
  notes: "From incident #2026-04-21."
  tactics: [InitialAccess]
  techniques: [T1078]
  labels: [incident-2026-q2]
```

**Resource name = GUID** (same translation pattern as hunts).

## Metadata (`sentinel_metadata`)

Tags content (analytic rule, hunting query, parser, etc.) so the
Content Hub UI shows it as customer-managed rather than a Microsoft-
shipped template.

```yaml
id: brute-force-001-meta
version: "1.0.0"
asset: sentinel_metadata
status: production
payload:
  kind: AnalyticsRule          # required
  parentId: "/subscriptions/.../alertRules/brute-force-001"   # required
  contentId: brute-force-001
  version: 1.0.0
  source:
    kind: LocalWorkspace       # LocalWorkspace | Community | Solution | SourceRepository
    name: detection-as-code
  author:
    name: Detection Engineering
    email: detection-engineering@example.com
```

The drift round-trip filters out `source.kind == Solution` records so
Microsoft-shipped solution metadata doesn't get imported into git.

## Known limitations

* The parser handler hashes `tags` so changes there will appear as
  drift, but hunting-query-style tactics/techniques tags are not
  parsed back into top-level fields the way the hunting handler does.
* The hunt handler does not yet manage `hunts/relations` (relations
  to other hunts) or `hunts/comments`.
* The bookmark handler does not manage `bookmarks/relations`.
* The metadata handler does not bulk-tag rules during analytic
  apply; metadata records authored as their own YAML are deployed
  independently. Auto-tagging-on-apply is deferred until §3-p of the
  master spec is closed.
