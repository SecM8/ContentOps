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
