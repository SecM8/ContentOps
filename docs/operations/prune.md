# `contentops prune` — delete remote orphans

Closes the deletion-as-code loop: drift surfaces orphans, prune
removes them. Distinct from `apply` (creates/updates) and `drift`
(read-only diff); never auto-runs.

## When to use it

After `contentops drift` reports remote-only assets (orphans), and
after a human has confirmed those assets are genuinely supposed to
be gone — typically:

- An analytic rule was renamed; the old YAML was deleted but the
  remote rule survived.
- A solution was uninstalled in the portal; its templates remain.
- A test bookmark / hunt / watchlist accumulated during dev and
  needs cleanup.

If the orphan represents real customer-authored state someone
forgot to commit, **`contentops collect` is the right answer**, not
prune.

## CLI

```
contentops prune [--path detections] [--asset <kind>]
               [--dry-run | --no-dry-run] [--yes]
               [--max-deletes 25] [--include-locked]
               [--json]
```

Two flags must be set to actually delete:

```
contentops prune --no-dry-run --yes
```

Anything missing one of those falls back to dry-run mode and exits 0
without touching anything.

### Output

Dry-run:

```
Prune plan — 3 orphan(s) found:
  ORPHAN  sentinel_analytic     test-rule-001        remote_id=guid-...
  ORPHAN  sentinel_watchlist    stale-watchlist      remote_id=guid-...
  ORPHAN  sentinel_hunting      abandoned-hunt       remote_id=guid-...

[dry-run] No deletions performed. Pass --no-dry-run --yes to actually delete.
```

After `--no-dry-run --yes`:

```
Prune plan — 3 orphan(s) found:
  ORPHAN  sentinel_analytic     test-rule-001        remote_id=guid-...
  ORPHAN  sentinel_watchlist    stale-watchlist      remote_id=guid-...
  ORPHAN  sentinel_hunting      abandoned-hunt       remote_id=guid-...

  DELETED sentinel_analytic     test-rule-001
  DELETED sentinel_watchlist    stale-watchlist
  DELETED sentinel_hunting      abandoned-hunt
[audit] wrote 3 prune records to audit/2026-05-06.jsonl

Prune summary: 3 deleted, 0 error(s), 0 skipped (locked).
```

JSON mode (`--json`) emits a stable structured payload for piping
into another tool:

```json
{
  "dry_run": false,
  "max_deletes": 25,
  "orphans": [...],
  "skipped_locked": [...],
  "deleted": [...],
  "errors": []
}
```

## Safety rails

| Rail | Behaviour |
|---|---|
| `--dry-run` default true | Plan-only mode unless `--no-dry-run`. |
| `--yes` required | Even with `--no-dry-run`, `--yes` must also be set. Two flags defend against shell-history accidents. |
| `--max-deletes N` | Fail-closed. Default 25. Exceeding the cap aborts (exit 1) before any delete runs. |
| `--include-locked` required for locked envelopes | Top-level `localCustomization: true` on the YAML protects an envelope; pass `--include-locked` to override. |
| Read-only handlers SKIP | `NotSupportedError` is caught and emits a SKIP row, not a batch failure. |
| Singletons SKIP | N/A — the legacy singleton handlers (`sentinel_settings`, `sentinel_onboarding`) were removed in the asset-taxonomy reduction; the current six kinds have no singletons. |
| Audit chain | One AuditRecord per attempted delete, on the same JSONL hash chain that `apply` uses. |

## Workflow

`.github/workflows/prune.yml` is `workflow_dispatch` only:

- `env` — tenant slug (selects `config/tenant.<env>.yml`).
- `asset` — optional filter to a single asset kind.
- `dry_run` — default `true`. Uncheck to actually delete.
- `max_deletes` — default `25`.
- `include_locked` — default `false`.
- `confirm` — must equal `CONFIRM` when `dry_run=false`. The
  workflow exits 1 otherwise.

Uses the GitHub Environment matching `env`, so production prune
requires reviewer approval at the workflow level on top of the CLI
gates.

Posts the prune plan as the workflow run summary. Uploads the
audit JSONL as an artefact (90-day retention).

## Idempotent deletion

The handler's `delete()` treats HTTP 404 as success — re-running
prune over an already-pruned resource is a no-op. This matters for
the "did the workflow really finish?" diagnostic case: re-run, look
at the summary, expect zero orphans.

## What's NOT prune-able

- Legacy singleton/toggle handlers (`sentinel_settings/{EyesOn,
  Anomalies,EntityAnalytics,Ueba}`, `sentinel_onboarding/default`)
  are N/A — they were removed in the asset-taxonomy reduction and
  are not part of the current six kinds.
- Any handler whose `delete()` raises `NotSupportedError` (read-only
  / collect-only kinds).

For these, the CLI emits a SKIP row with the reason; the prune
batch keeps going.
