# `detections/` — your content goes here

This directory is where detection envelopes live. The ContentOps
pipeline walks `detections/<asset_kind>/*.yml`, validates each
envelope, lints the KQL, and applies the changes to your Microsoft
Sentinel + Defender XDR tenant on merge.

**Detection YAMLs are intentionally NOT tracked by this repo.** The
ContentOps pipeline is open-source; the actual detections you run in
your tenant are operator-supplied tradecraft. Keep them on your own
clone (or in a separate private repo) and let `.gitignore` keep them
out of public commits.

## What is committed here

| Path | Purpose |
|---|---|
| `README.md` (this file) | Overview. |
| `<asset_kind>/README.md` | One per asset kind — explains placement. |
| `templates/` | Scaffold templates `contentops new` uses. Tracked. |
| `samples/` | Worked example envelopes for reference. Tracked. |

## What is NOT committed (gitignored)

| Path pattern | Why |
|---|---|
| `<asset_kind>/*.yml` | Operator-supplied detection content. Bring your own. |
| `dependencies.yml` | Per-detection prerequisite graph (operator-authored). |
| `drift_suppressions.yml` | Per-tenant allowlist of intentional portal tweaks. |

See [`.gitignore`](../.gitignore) for the exact patterns.

## Workflow for a new operator

1. **Clone this repo.** You'll see this `detections/` directory with
   six asset-kind sub-directories, each carrying a `README.md`.
2. **Add your detection envelopes** as `detections/<asset_kind>/<rule-id>.yml`.
   They're automatically gitignored — you won't accidentally commit
   them when running `git add -A`.
3. **Scaffold new ones** via `contentops new <asset_kind> <rule-id>`
   (uses the tracked `templates/`).
4. **Lint locally** with `contentops lint --strict`.
5. **Apply** through CI (merge to main triggers `deploy.yml`) or
   locally with `contentops apply --role <role>`.

## Workflow for collecting from an existing tenant

If you already have rules deployed in your tenant and want to bootstrap
this repo's local state from them, `contentops collect` pulls every
rule down as YAML. The downloaded YAMLs land in
`detections/<asset_kind>/` and stay gitignored — they live on your
clone only.

```bash
contentops collect --role prod
```

## Six supported asset kinds

The current taxonomy (see [`contentops/core/asset.py`](../contentops/core/asset.py)):

- **`sentinel_analytic`** — Scheduled / NRT / Fusion / MLBA / TI alert rules.
- **`sentinel_hunting`** — Hunting queries (savedSearches, category=Hunting).
- **`sentinel_watchlist`** — Watchlists + watchlist items.
- **`sentinel_parser`** — KQL functions (savedSearches, category=Function).
- **`sentinel_data_connector`** — Data ingest bindings.
- **`defender_custom_detection`** — Microsoft Defender XDR custom rules
  (Graph beta API).

See [`docs/reference/asset-coverage.md`](../docs/reference/asset-coverage.md)
for endpoint + RBAC + hash-projection detail per kind.

## See also

- [`docs/OPERATOR_GUIDE.md`](../docs/OPERATOR_GUIDE.md) — day-to-day operator flow.
- [`docs/reference/envelope-schema.md`](../docs/reference/envelope-schema.md) — canonical YAML shape.
- [`docs/operations/tenant-config-modes.md`](../docs/operations/tenant-config-modes.md) — how to wire up your tenant.
