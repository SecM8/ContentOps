# `detections/sentinel_hunting/`

Detection envelopes for the **Microsoft Sentinel hunting query** asset
kind go here.

Hunting queries are investigative KQL searches — they do not fire
alerts directly. Stored as Log Analytics `savedSearches` with
`category=Hunting Queries`.

## Placement

Each hunting query is one YAML file:

```
detections/sentinel_hunting/<query-id>.yml
```

The `<query-id>` is the canonical envelope id (kebab-case slug). Files
under this directory are gitignored — they live on your local clone
and never get committed back to this public pipeline repo.

## Authoring

Scaffold:

```bash
contentops new sentinel_hunting <query-id>
```

Hunting queries deprecate via the `prune` path (set
`status: deprecated` and let `contentops prune` remove the remote
savedSearch). There's no per-rule enable/disable.

## See also

- [`../../docs/reference/asset-coverage.md`](../../docs/reference/asset-coverage.md) — endpoint, RBAC, hash projection.
- [`../../docs/reference/envelope-schema.md`](../../docs/reference/envelope-schema.md) — canonical YAML shape.
