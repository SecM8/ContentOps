# `contentops collect` — pull every asset from the live tenant

Collects every asset from the live Microsoft Sentinel + Defender XDR
tenant into local YAML, walking every drift-capable handler in the
registry. This is the "pull everything down" entry point for either a
brand-new repo or an audit-style snapshot of the live state.

## Usage

```
contentops collect [--path detections] [--asset <kind>]
```

Both options are optional:
- `--path` — root directory to write YAML into (default `detections/`).
  Created if missing.
- `--asset` — restrict to a single asset kind. Without this flag, all
  registered drift-capable handlers run.

## Output

```
$ contentops collect --path /tmp/snapshot

Collect summary — 250 item(s) inspected across 12 asset kind(s):
  asset                                      new  changed  in-sync
  defender_custom_detection                   46        0        0
  sentinel_analytic                          127        0        0
  sentinel_incident                           50        0        0
  sentinel_metadata                            2        0        0
  sentinel_onboarding                          1        0        0
  sentinel_settings                            4        0        0
  sentinel_watchlist                           5        0        0
  sentinel_watchlist_item                     11        0        0
  sentinel_workspace_manager_*                 4        0        0

Wrote 250 file(s):
  /tmp/snapshot/defender_custom_detection/<id>.yml
  /tmp/snapshot/sentinel_analytic/<id>.yml
  ...
```

Each row in the summary shows how many remote items the handler
returned, broken down by `new` (no local file existed),
`changed` (file existed but content differs), and `in-sync` (already
matches).

## Differences vs `contentops drift --write`

| Capability | `collect` | `drift --write` |
|---|---|---|
| Always writes | ✅ | ✅ |
| Always succeeds | ✅ | ✅ when `--no-exit-on-drift` |
| Creates target dir | ✅ | ❌ (must exist) |
| CI-friendly exit code | exit 0 | exit 2 on drift |
| Default audience | analyst pulling state | scheduled drift workflow |

`drift --write` is gated for the auto-PR workflow (it gets the right
exit codes for the workflow to detect drift and open a PR);
`collect` is the unfiltered "pull everything" path.

## Asset kinds covered

After the collect-and-readonly PR, **24 asset kinds** can be
collected:

- Sentinel: analytic, automation, bookmark, content package, data
  connector, hunt, hunting query, metadata, onboarding, parser,
  playbook (read-only via subscription RP), settings (4 singletons),
  source control (read-only), summary rule, watchlist, watchlist
  item, workbook, workspace manager × 4.
- Sentinel incidents (read-only) and incident tasks (read-only).
- Defender XDR: custom detection rule, TI indicator.

The 9 read-only handlers (workspace manager, incidents, incident
tasks, source controls, watchlist items) refuse to write back via
``apply``, but they participate in `collect` and `drift` like any
other handler.

## Limitations

- Some endpoints return 403 unless the service principal has the
  right scoped role:
  - `sentinel_playbook` needs Logic App Reader on the playbook RG.
  - `defender_ti_indicator` needs Graph
    `ThreatIndicators.Read.All` (admin consent).
  Auth failures are logged and skipped — collect keeps going across
  the rest.
- The collect run can be expensive on a busy tenant (one ARM call
  per asset kind plus pagination plus the watchlist-items fan-out).
  The `contentops drift` retry/backoff logic in
  `SentinelArmProvider.request()` applies to every call.
