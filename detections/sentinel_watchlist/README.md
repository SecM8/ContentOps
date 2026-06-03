# `detections/sentinel_watchlist/`

Watchlist envelopes for **Microsoft Sentinel** go here.

Watchlists are reference data used by other detections (allowlists,
known-bad indicators, asset inventories). Deployed via ARM at
`Microsoft.SecurityInsights/watchlists` + `watchlistItems`.

## Placement

Each watchlist is one YAML file:

```
detections/sentinel_watchlist/<watchlist-id>.yml
```

The `<watchlist-id>` becomes both the envelope id and the watchlist
alias on the tenant. Files under this directory are gitignored — they
live on your local clone and never get committed back to this public
pipeline repo.

## Authoring

Scaffold:

```bash
contentops new sentinel_watchlist <watchlist-id>
```

Inline items live under `payload.items`; for watchlists larger than
3.8 MB the pipeline switches to SAS-URI upload (see
[`../../docs/assets/sentinel_watchlist_sas.md`](../../docs/assets/sentinel_watchlist_sas.md)).

## See also

- [`../../docs/reference/asset-coverage.md`](../../docs/reference/asset-coverage.md) — endpoint, RBAC, hash projection.
- [`../../docs/assets/sentinel_watchlist_sas.md`](../../docs/assets/sentinel_watchlist_sas.md) — large-watchlist upload path.
