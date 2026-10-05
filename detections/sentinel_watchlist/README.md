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
alias on the tenant. This source repository ships no tenant watchlist
YAMLs, and these paths are not gitignored. Commit watchlists to your
private deployment repository; do not commit tenant detections to a
public repository.

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
