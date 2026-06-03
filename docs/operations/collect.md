# `contentops collect` — operations guide

`contentops collect` pulls every asset from the live tenant into local
YAML. This guide covers the operational flags and the
**operational vs. configuration** distinction that drives the
default scope.

## Quick reference

```sh
# Default — configuration assets only, write to detections/
contentops collect

# Snapshot to a different path (round-trip contract test)
contentops collect --path .roundtrip

# Limit to one asset kind
contentops collect --asset sentinel_analytic

# Migrate the existing tree onto the slug naming convention
contentops collect --rename-existing

# Refresh from tenant — wipe local YAMLs first, then collect.
# Useful when local state has drifted or you want a clean ground-truth
# pull rather than an additive merge.
contentops collect --clear --role prod

# Target a specific Sentinel workspace by role (single tenant, multi
# workspace — see docs/operations/multi-workspace.md)
contentops collect --role integration
contentops collect --workspace law-sentinel-int   # by name; mutex with --role
```

## Selecting a workspace (multi-workspace tenants)

A tenant with more than one Sentinel workspace requires a selector:

* `--role prod|integration|dev` — pick the workspace tagged with that
  role in `config/tenant.yml`.
* `--workspace <name>` — pick by exact `workspaceName`. Mutex with
  `--role`.

Single-workspace tenants don't need either flag. Defender XDR is
tenant-scoped and is always collected; pass `--asset
sentinel_analytic` (or similar) if you want to skip it.

## Refresh from tenant: `--clear`

`contentops collect` is **additive** by default — it writes new or
changed envelopes alongside whatever already exists locally. That's
the right behaviour for incremental syncs, but it leaves stale files
behind if the tenant has had content removed since the last collect.

`--clear` wipes the local detection YAMLs **before** the collect runs:

```sh
contentops collect --clear --role prod
```

Mechanically equivalent to running `pipeline clean --yes` and then
`contentops collect`. Behaviour:

* Deletes `detections/<asset_kind>/*.yml` and the legacy v1
  `detections/sentinel/` and `detections/defender/` directories.
* Preserves `detections/templates/` and `detections/samples/`.

Use `pipeline clean` (without collecting) when you want the wipe
without the immediate re-pull — e.g. to inspect what's left or to
re-collect against a different workspace.

<!--
The "Allowlist auto-sync in CI" section that previously sat here
documented ``scripts/check_legacy_detection_allowlist.py
--write-allowlist`` running between the collect + tree-change
steps in ``collect.yml``. The script + the
``config/legacy_detections_allowlist.txt`` file + the workflow
step were all deleted in Phase 1 (PR #125). The doc-side cleanup
landed in PR #147; the workflow step was removed in PR #148; this
operational doc is the last place the allowlist mechanism was
documented as current behaviour. Removed for accuracy.
-->


<!--
The "Operational vs. configuration" section + the
``--include-operational`` flag documented the seven read-only
operational kinds (sentinel_incident, sentinel_incident_task,
sentinel_watchlist_item, sentinel_workspace_manager_*) that were
skipped by default and opted in with ``--include-operational``.
The handlers for those kinds were deleted in the asset-taxonomy
reduction (Phase 1, PR #122) -- only 6 configuration kinds are
managed today (see contentops/core/asset.py). The flag, the
``OPERATIONAL_ASSETS`` set, and the opt-in surface are gone with
them.
-->

## Filename + `metadata.arm_name`

Collected envelopes are written to
`<path>/<asset_kind>/<displayname-slug>.yml`. The slug is derived
from the resource's `displayName` (lowercase; non-alphanumerics
become `-`; capped at 80 chars). The original ARM resource name
lives on under `metadata.arm_name` so `apply` and `prune` can still
address the same remote resource even when the on-disk filename has
changed.

If two resources of the same asset kind slug to the same name (two
analytics both called "Test"), both get suffixed with the first
8 alphanumeric chars of their ARM name (e.g. `test-1840b991`,
`test-20fffe11`). The non-colliding case stays bare (`test`).

`contentops collect --rename-existing` walks the existing on-disk
tree and renames any envelope whose filename does not already
match its slug. Idempotent. Off by default — opt in once after
this contract lands so the `detections/sentinel/` legacy tree
follows the same convention.

## Run output

`contentops collect` prints a tenant banner before any API call and a
fixed-width summary table at the end:

```
contentops collect — production
  subscription   : 00000000-0000-0000-0000-000000000000
  resource_group : rg-sentinel
  workspace      : law-sentinel
  api version    : 2025-07-01-preview (ARM) / beta (Graph)
  path           : detections
  full           : true
  workers        : 8
  since          : (none)

Collect summary (duration 12.3s):
  asset                                         new  changed  in-sync  failed
  defender_custom_detection                       0        0       12       0
  sentinel_analytic                               0        0       97       0
  ...
```

By default the SDK loggers (`azure.identity`, `azure.core`, `httpx`,
`urllib3`) are demoted to `WARNING` so the run output stays
~25–30 lines. Pass `-v` for `INFO` or `-vv` for `DEBUG` to debug
auth / HTTP issues.

## Round-trip contract

After `contentops collect`, running `contentops drift` against the same
path must report zero NEW + zero CHANGED entries:

```sh
contentops collect --path .roundtrip
contentops drift --path .roundtrip --no-exit-on-drift
# Drift report — new: 0, changed: 0, in-sync: <N>
```

This is enforced by
`tests/integration/test_collect_drift_roundtrip.py` against the
live production tenant. If it fails, a handler's `to_envelope` is
not deterministic OR the YAML serialiser is round-tripping
differently (e.g. lost trailing whitespace, alternate quoting).

## See also

* [docs/operations/prune.md](prune.md) — the destructive
  counterpart that deletes orphans found by drift.
* [DESIGN.md](../../DESIGN.md) — filename convention,
  `metadata.arm_name` contract, log-level policy.
