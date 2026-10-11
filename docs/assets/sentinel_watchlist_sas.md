# Sentinel watchlist — SAS-URI ingestion path

Sentinel watchlists support two ingestion paths, both managed by the
same `sentinel_watchlist` handler:

| Path | Field | Use when |
|---|---|---|
| Inline CSV | `rawContent` | watchlist is < 3.5 MB and authored in git (e.g. high-value-asset list, watchlist-driven exception lists) |
| SAS-protected blob | `sasUri` | watchlist is > 3.5 MB or sourced from an external feed (e.g. millions-of-rows TI list) |

The two are mutually exclusive — exactly one must be set.

## Inline path (existing, unchanged)

```yaml
id: high-value-assets
version: "1.0.0"
asset: sentinel_watchlist
status: production
payload:
  displayName: "High Value Assets"
  itemsSearchKey: AssetName
  contentType: text/csv
  rawContent: |
    AssetName,Tier
    dc01,0
    ceo-laptop,1
```

## SAS-URI path (new in PR-L)

For watchlists too large to commit to git, upload the CSV to an
Azure Storage blob, generate a read-only SAS token, and reference
the URL.

```yaml
id: tor-exit-nodes
version: "1.0.0"
asset: sentinel_watchlist
status: production
payload:
  displayName: "Tor Exit Nodes"
  description: "Daily refresh from torproject.org"
  itemsSearchKey: IPAddress
  contentType: text/csv
  numberOfLinesToSkip: 0
  # The SAS URL is sensitive — never commit a real one. Use env-var
  # substitution at apply time:
  #   sasUri: "${TOR_EXIT_NODES_SAS_URI}"
  sasUri: "${TOR_EXIT_NODES_SAS_URI}"
  labels: [external-feed]
  defaultDuration: P30D
```

## Metadata-only envelopes (items managed out-of-band)

Some watchlists ship with `sasUri: ''` and no `rawContent` — the
envelope only carries the watchlist **definition** (displayName,
columns, alias, defaultDuration), while the **items** are managed
out-of-band by Logic Apps, SOC operators editing in the Sentinel
portal, or external automation. This pattern is by design.

```yaml
id: autoclose
version: 0.1.0
asset: sentinel_watchlist
status: production
payload:
  displayName: AutoClose
  provider: Microsoft
  source: AutoClose.csv
  sourceType: Local
  itemsSearchKey: Title
  watchlistType: watchlist
  defaultDuration: P1DT3H
  sasUri: ''           # <- empty, intentional
  watchlistKind: Regular
  watchlistAlias: AutoClose
  # no rawContent      # <- intentional
```

When you run `contentops apply` against a metadata-only envelope it
reports `skipped (no-content)` — that's the expected outcome, not a
warning. The handler skips the items-upload step because there's no
content to upload. The watchlist's **definition** is still tracked
in git and round-trips cleanly via `contentops collect`; only the
items table is owned elsewhere.

If you ever want to bring item management into the pipeline, populate
`rawContent` (inline CSV, < 3.5 MB) or `sasUri` (cloud blob URL) in
the envelope and re-apply — the handler will start uploading items
on the next run.

## Validation

The model enforces:

- For watchlists that DO upload items, exactly one of `rawContent` /
  `sasUri` is supplied. Metadata-only envelopes (both fields empty)
  are valid and apply with `skipped (no-content)`.
- If `sasUri` is set, the URL must begin `https://` and contain a
  `sig=` query parameter (the SAS signature). A bare URL without
  `sig=` almost certainly means the analyst hasn't actually generated
  a SAS — fail-fast at PR time rather than waiting for ARM to reject.
- `source` is auto-coerced to match the chosen path: `"Local file"`
  for `rawContent`, `"Remote storage"` for `sasUri`.

## Item-count verification

The handler's `_expected_item_count` post-apply check (count rawContent
data rows, GET watchlistItems, assert match) **only runs for inline
watchlists**. For SAS-sourced watchlists, ARM ingests the blob
asynchronously after the PUT returns; counting items right after PUT
would race against ingestion. The handler treats the PUT 200 as
success and skips the count check.

## Secret handling

A SAS URL is a credential. The expected pattern:

1. Store the SAS in a GitHub Actions secret (e.g. `TOR_EXIT_NODES_SAS_URI`).
2. Reference it via `${VAR}` substitution in the YAML.
3. Resolve the env var at apply time before passing to the handler.

The pipeline does **not** currently auto-substitute `${VAR}` patterns —
that's a follow-up. For now, render the YAML with the secret resolved
as part of the deploy workflow, e.g.:

```yaml
# .github/workflows/...
- name: Render watchlist with SAS
  env:
    TOR_EXIT_NODES_SAS_URI: ${{ secrets.TOR_EXIT_NODES_SAS_URI }}
  run: envsubst < detections/sentinel_watchlist/tor-exit-nodes.yml > /tmp/rendered.yml
- name: Apply
  run: contentops apply --path /tmp --asset sentinel_watchlist
```

## Collected watchlists carry no rows

A `contentops collect` run writes every watchlist in the tenant as a
**metadata-only envelope**: display name, alias, provider, source,
search key, description, labels, retention. No `rawContent`, no
`sasUri`, no items. That is what the first collect of any existing
tenant looks like, and it is expected, for two reasons on the API side:

- `rawContent` is an **input-only** property of the ARM watchlist
  resource. Microsoft's schema describes it as "the raw content that
  represents the watchlist items to create": the service parses it into
  items on PUT and does not return it on GET. The handler re-fetches
  each watchlist individually hoping for it (`to_envelope` in
  [`contentops/handlers/sentinel_watchlist.py`](../../contentops/handlers/sentinel_watchlist.py))
  and the service still answers without it.
- The rows live in a separate child resource, `watchlistItems`. Collect
  does not read it; the handler only reads it after an apply, to compare
  the item count with the CSV it just uploaded.

What that means for a collected watchlist:

| Operation | What it covers |
|---|---|
| `apply` | nothing to upload; the handler reports `skipped (no-content)` |
| `drift` | the definition only; rows edited in the portal are invisible |
| `state adopt` / status page | "in-sync" refers to the definition |
| `prune` | the watchlist counts as managed and is never an orphan |

Three ways to work with that boundary:

1. **Keep rows portal-owned** (the default). Nothing to do; tell the
   team drift does not cover watchlist rows.
2. **Bring a list under change control by hand.** Export the rows,
   paste them into `rawContent` as CSV, apply: the handler uploads the
   items and verifies the count on every deploy from then on. Stay
   under 3.5 MB, keep the `itemsSearchKey` column in the header, and
   strip the system columns that `_GetWatchlist()` adds (`SearchKey`,
   `_DTItemId`, `LastUpdatedTimeUTC`, `TenantId`, `WatchlistId`). Lists
   of people (admin accounts, VIPs, leavers) are personal data; decide
   with the data owner before committing them, private repository or
   not.
3. **Collect the rows.** An opt-in collect mode that reads
   `watchlistItems`, rebuilds the CSV sorted by the search key and
   writes it into `rawContent` would make drift cover row changes and
   give every list a backup in git. Not built yet; tracked in
   [`docs/reference/gap-assessment.md`](../reference/gap-assessment.md#full-gap-table).

## Limitations

- ARM rejects SAS URLs without read permission on the blob; verify
  the SAS includes `sp=r`.
- The handler does NOT fetch the blob to peek at the CSV header —
  that would require sharing the SAS with the pipeline runtime as
  well as ARM. `itemsSearchKey` validity is therefore checked
  **server-side at ingestion time** for SAS-sourced watchlists; for
  inline watchlists it's still validated at the model layer.
- Rotating a SAS without re-applying the watchlist is fine — ARM
  caches the ingestion result; the SAS is only consulted on PUT.
