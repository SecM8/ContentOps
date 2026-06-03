# `detections/sentinel_parser/`

KQL function (parser) envelopes for **Microsoft Sentinel** go here.

Parsers are reusable KQL functions called by other queries — typically
normalisation helpers that map a raw log table to a canonical schema.
Stored as Log Analytics `savedSearches` with `category=Function` plus a
`functionAlias` field.

## Placement

Each parser is one YAML file:

```
detections/sentinel_parser/<parser-id>.yml
```

The `<parser-id>` is the canonical envelope id (kebab-case slug). Files
under this directory are gitignored — they live on your local clone
and never get committed back to this public pipeline repo.

## Authoring

Scaffold:

```bash
contentops new sentinel_parser <parser-id>
```

Parsers don't fire alerts; lint rules requiring time filters
(`KQL007`) are skipped for this asset kind.

## See also

- [`../../docs/reference/asset-coverage.md`](../../docs/reference/asset-coverage.md) — endpoint, RBAC, hash projection.
- [`../../docs/assets/sentinel_extras.md`](../../docs/assets/sentinel_extras.md) — Sentinel non-analytic asset authoring notes.
