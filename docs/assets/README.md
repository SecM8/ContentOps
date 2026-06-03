# Per-asset documentation

Each managed asset kind lives in its own page where one exists:
ARM/Graph endpoint, payload schema (with examples), and known
limitations. This is the spec the handler enforces — new
contributors should read the asset doc before touching the
corresponding handler.

The canonical, code-derived view of the asset taxonomy (six kinds
today, RBAC + hash projection per row) is
[`../reference/asset-coverage.md`](../reference/asset-coverage.md).
This index points at the longer-form per-asset pages.

## Sentinel — write-capable, drift-capable

| Asset kind                | Per-asset doc                                                                                    | Handler module                                |
|---------------------------|--------------------------------------------------------------------------------------------------|-----------------------------------------------|
| `sentinel_analytic`       | [sentinel_alert_rules.md](sentinel_alert_rules.md)                                               | `contentops.handlers.sentinel_analytic`         |
| `sentinel_hunting`        | [sentinel_extras.md](sentinel_extras.md)                                                         | `contentops.handlers.sentinel_hunting`          |
| `sentinel_watchlist`      | [sentinel_watchlist_sas.md](sentinel_watchlist_sas.md)                                           | `contentops.handlers.sentinel_watchlist`        |
| `sentinel_parser`         | [sentinel_extras.md](sentinel_extras.md)                                                         | `contentops.handlers.sentinel_parser`           |
| `sentinel_data_connector` | see [`../reference/asset-coverage.md`](../reference/asset-coverage.md) (no dedicated page yet)   | `contentops.handlers.sentinel_data_connector`   |

## Defender — write-capable, drift-capable

| Asset kind                  | Per-asset doc                                                                                  | Handler module                                  |
|-----------------------------|------------------------------------------------------------------------------------------------|-------------------------------------------------|
| `defender_custom_detection` | see [`../reference/asset-coverage.md`](../reference/asset-coverage.md) (no dedicated page yet) | `contentops.handlers.defender_custom_detection`   |

## CLI extensions

| Capability                                              | Doc                                                  |
|---------------------------------------------------------|------------------------------------------------------|
| `contentops collect`                                    | [cli_collect.md](cli_collect.md)                     |
| `contentops lock` / `unlock` / `retry-failed`           | [cli_lock_retry.md](cli_lock_retry.md)               |
| `contentops new --from-template` / `--search-template`  | [cli_new_from_template.md](cli_new_from_template.md) |

## How drift's auto-PR routes asset owners

The `drift.yml` workflow renders a checkbox list of asset owners
parsed from `envelope.metadata.owner`. The `.github/CODEOWNERS`
patterns map per-asset directories onto reviewer teams so that
opening the PR auto-requests the right people.

## Historical kinds (removed in PR #122 / #129)

The asset-taxonomy reduction removed 21 handlers that targeted the
broader Sentinel everything-management surface (workbooks,
automation, playbooks, hunts, content packages, TI indicators,
workspace-manager kinds, source control, incidents, settings,
onboarding, metadata, summary rules) plus the deferred Defender
Graph extensions (tuning rules, alert suppression, saved queries).
See the
[Historical kinds section in `asset-coverage.md`](../reference/asset-coverage.md#historical-kinds-removed-in-pr-122--129)
for the full list, and `git log --all --diff-filter=D -- contentops/handlers/`
for handler recovery.

`defender_graph_extensions_deferred.md` remains in this directory —
it documents Defender Graph beta endpoints that Microsoft has not yet
GA'd (saved queries, detection tuning rules, alert suppression). The
`contentops defender-extensions-probe` command refers to it.

Per-asset pages for removed handlers were deleted alongside the
handlers; consult git history if you need to recover them
(`git log --all --diff-filter=D -- docs/assets/`).
