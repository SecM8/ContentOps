# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops collect`` and ``pipeline clean`` commands.

Orchestration only — the mechanics (workspace resolution, the parallel
``list_remote`` fan-out, drift classification, summary bucketing, the
enrich/rename/clean/since helpers) live in :mod:`collect_support`, which
``clean`` also draws ``_clean_local_detections`` from.
"""

from __future__ import annotations

import time
from pathlib import Path

import click

from contentops.cli.handler_factories import register_default_handlers
from contentops.cli.commands._shared import (
    _apply_log_levels,
    _collect_drift_handlers,
    _format_summary_table,
    _print_run_banner,
    _skip_if_integration_role_absent,
)
from contentops.cli.commands.collect_support import (
    _classify_collected_drift,
    _clean_local_detections,
    _enrich_drift_entries,
    _list_remote_parallel,
    _parse_since_or_exit,
    _rename_existing_to_slug,
    _resolve_collect_workspace_or_exit,
    _summarize_collect,
)
from contentops.core.asset import Asset
from contentops.core.drift import write_drift


@click.command("collect")
@click.option(
    "--path", "detections_path",
    type=click.Path(path_type=Path),
    default=Path("detections"),
    help="Root detections directory (created if missing).",
)
@click.option(
    "--asset",
    type=click.Choice([a.value for a in Asset]),
    default=None,
    help="Restrict collection to one asset kind.",
)
@click.option(
    "--full/--no-full", default=True,
    help=(
        "Pull all sub-resources (watchlist items, incident tasks, etc.). "
        "Default true - disable to skip fan-out handlers."
    ),
)
@click.option(
    "--since", "since_iso", default=None,
    help=(
        "ISO 8601 timestamp; client-side filter to items whose "
        "lastUpdated/created timestamp is at or after this value. "
        "Best-effort: handlers without a remote timestamp pass through "
        "everything."
    ),
)
@click.option(
    "--workers", type=int, default=4,
    help=(
        "Parallel handler workers (default 4). Set 1 for serial. "
        "Lowered from 8 in 2026-05 after adopter testing on a Windows "
        "endpoint with Device Guard / Application Control: bursty "
        "parallel subprocess invocations of `az account get-access-"
        "token` (via AzureCliCredential) triggered policy throttling "
        "and many tokens failed to acquire. The token cache amortises "
        "after first acquisition; 4 workers gives most of the "
        "throughput without the startup-burst pathology. Drop to 1 if "
        "you still see AzureCliCredential errors. Related Windows-"
        "adopter workaround for the chain-ordering 401 case (different "
        "symptom, same root cause): set "
        "AZURE_TOKEN_CREDENTIALS=dev to bypass stale SharedTokenCache / "
        "VSCode credentials in the chain."
    ),
)
@click.option(
    "--rename-existing/--no-rename-existing",
    default=False,
    help=(
        "Walk the existing detections/<kind>/ tree and rename any "
        "envelope file whose filename does not match what slugify would "
        "produce. Idempotent. Off by default."
    ),
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default=None,
    help="Target the Sentinel workspace with this role. Defaults to "
         "`prod` when the tenant has more than one Sentinel workspace; "
         "single-workspace tenants pick the only one implicitly. "
         "Defender (tenant-level) is collected regardless. "
         "Mutex with --workspace.",
)
@click.option(
    "--workspace", "workspace_name",
    default=None,
    help="Target the Sentinel workspace with this exact ``workspaceName``. "
         "Mutex with --role.",
)
@click.option(
    "--clear/--no-clear", default=False,
    help="Delete local detection YAMLs (equivalent to `pipeline clean "
         "--yes`) before collecting. Use for a true 'refresh from tenant' "
         "snapshot - without this flag, collect is additive (writes new "
         "or changed envelopes alongside existing files). Default off.",
)
@click.option(
    "--enrich/--no-enrich", default=False,
    help="Bulk-import mode for fork day-1. For every new or changed "
         "envelope: demote status: production -> status: test (so the "
         "production-only META lint escalation does NOT fire until the "
         "operator has enriched the rule), and stub a placeholder "
         "metadata block with TODO markers in the required RuleMetadata "
         "fields. Existing envelopes that already carry a full metadata "
         "block are left alone. Lint will then surface a warning per "
         "missing optional field (description, attackDescription, "
         "references, falsePositives). The forker walks those down as "
         "they enrich each rule and promotes status back to production.",
)
def collect_cmd(
    detections_path: Path,
    asset: str | None,
    full: bool,
    since_iso: str | None,
    workers: int,
    rename_existing: bool,
    role: str | None,
    workspace_name: str | None,
    clear: bool,
    enrich: bool,
) -> None:
    """Collect every asset from the live tenant into local YAML.

    Walks every drift-capable handler, lists everything in the remote
    tenant, and writes new+changed envelopes under
    ``detections/<asset_kind>/<id>.yml``. This is the "pull everything
    down" entry point - distinct from ``contentops drift``, which is
    gated for CI use.

    Behaviour:
    - Per-handler list_remote() runs in a thread pool (--workers).
    - --full drives fan-out collectors that walk per-parent items.
    - --since filters listed items client-side by timestamp; handlers
      without a remote timestamp ignore the flag.
    - The roundtrip contract is enforced by tests:
      collect -> drift returns no NEW or CHANGED entries.
    """
    _apply_log_levels()

    # Resolve the active Sentinel workspace from --role / --workspace
    # before registering handlers (factories in contentops/cli/handler_factories.py
    # read PIPELINE_WORKSPACE_NAME). Defender (tenant-level) is collected
    # regardless of workspace selection.
    if _skip_if_integration_role_absent(role, workspace_name, command="collect"):
        return
    _resolve_collect_workspace_or_exit(role, workspace_name)

    register_default_handlers()
    target_asset = Asset(asset) if asset else None

    detections_path.mkdir(parents=True, exist_ok=True)

    _print_run_banner(
        "collect",
        detections_path,
        extra={
            "full": str(full).lower(),
            "workers": str(max(1, workers)),
            "since": since_iso or "(none)",
            "clear": str(clear).lower(),
        },
    )

    # --clear: empty local detections before collecting. Equivalent
    # to running `contentops clean --yes` ahead of the collect — single
    # command for the refresh-from-tenant use case.
    if clear:
        deleted, dirs_removed = _clean_local_detections(
            detections_path, asset_kinds=None,
        )
        click.echo(
            f"  [--clear] removed {deleted} YAML file(s) across "
            f"{len(dirs_removed)} director{'y' if len(dirs_removed) == 1 else 'ies'}"
        )

    if rename_existing:
        renamed = _rename_existing_to_slug(detections_path)
        click.echo(f"  (--rename-existing: {len(renamed)} file(s) renamed)")

    drift_handlers = _collect_drift_handlers(target_asset)

    if not drift_handlers:
        click.echo("No drift-capable handlers registered.")
        return

    since_dt = _parse_since_or_exit(since_iso)

    started = time.perf_counter()
    handler_results, failed_kinds = _list_remote_parallel(
        drift_handlers, workers=workers,
    )
    report = _classify_collected_drift(
        drift_handlers, handler_results, detections_path, since_dt=since_dt,
    )
    duration = time.perf_counter() - started

    by_asset = _summarize_collect(drift_handlers, report, failed_kinds)
    for line in _format_summary_table(
        by_asset, duration_s=duration, title="Collect summary",
    ):
        click.echo(line)

    if report.has_drift():
        if enrich:
            n_enriched = _enrich_drift_entries(report)
            click.echo(
                f"\n[--enrich] demoted to status: test and stubbed "
                f"placeholder metadata on {n_enriched} envelope(s). "
                f"Fill in description / attackDescription / references / "
                f"falsePositives and promote back to status: production."
            )
        written = write_drift(report, detections_path)
        click.echo(f"\nWrote {len(written)} file(s).")
    else:
        click.echo("\nNo new or changed assets — local YAML is already in sync.")


@click.command("clean")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory.",
)
@click.option(
    "--asset", "asset_filter", multiple=True,
    type=click.Choice([a.value for a in Asset]),
    help="Restrict to specific asset kind(s). Repeatable. Default: all.",
)
@click.option(
    "--yes", "skip_confirm", is_flag=True, default=False,
    help="Skip the destructive-action confirmation prompt.",
)
def clean_cmd(
    detections_path: Path,
    asset_filter: tuple[str, ...],
    skip_confirm: bool,
) -> None:
    """Delete local detection YAMLs (Sentinel + Defender content).

    \b
    Use to prepare for a fresh `contentops collect` against the live
    tenant. Preserves:
      * `detections/templates/`  - `contentops new` scaffolding
      * `detections/samples/`    - fixture data for tests

    Removes:
      * `detections/<asset_kind>/` directories (sentinel_analytic,
        defender_custom_detection, sentinel_watchlist, etc.)

    \b
    Typical refresh flow:
      contentops clean --yes
      contentops collect --role prod

    \b
    Or one-shot:
      contentops collect --clear --role prod
    """
    asset_kinds: set[Asset] | None
    if asset_filter:
        asset_kinds = {Asset(a) for a in asset_filter}
    else:
        asset_kinds = None  # all

    candidates: list[Path] = []
    skip_dirs = {"templates", "samples"}
    for entry in detections_path.iterdir():
        if not entry.is_dir() or entry.name in skip_dirs:
            continue
        try:
            kind = Asset(entry.name)
        except ValueError:
            continue
        if asset_kinds is None or kind in asset_kinds:
            candidates.append(entry)

    file_count = sum(
        len(list(d.glob("*.yml")) + list(d.glob("*.yaml")))
        for d in candidates
    )
    click.echo(
        f"Will delete {file_count} YAML file(s) across "
        f"{len(candidates)} directory/directories under {detections_path}:"
    )
    for d in candidates:
        nfiles = len(list(d.glob("*.yml")) + list(d.glob("*.yaml")))
        click.echo(f"  - {d.name}/ ({nfiles} file(s))")

    if file_count == 0:
        click.echo("Nothing to clean.")
        return

    if not skip_confirm:
        click.confirm("Proceed?", abort=True)

    deleted, dirs_removed = _clean_local_detections(
        detections_path,
        asset_kinds=asset_kinds,
    )
    click.echo(
        f"Deleted {deleted} YAML file(s); removed "
        f"{len(dirs_removed)} empty director{'y' if len(dirs_removed) == 1 else 'ies'}."
    )
