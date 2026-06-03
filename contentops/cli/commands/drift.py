# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``drift``, ``drift-resolve``, ``drift-pr-body`` Click commands."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import click

from contentops.cli.handler_factories import register_default_handlers
from contentops.cli.commands._shared import (
    _apply_log_levels,
    _collect_drift_handlers,
    _print_run_banner,
    _resolve_single_workspace_or_exit,
    _skip_if_integration_role_absent,
)
from contentops.core.asset import Asset
from contentops.core.drift import (
    detect_drift,
    write_drift,
)
from contentops.core.registry import default_registry


@click.command("drift")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory (used for both reading local + writing drift).",
)
@click.option(
    "--asset",
    type=click.Choice([a.value for a in Asset]),
    default=None,
    help="Restrict drift detection to one asset kind.",
)
@click.option(
    "--write/--no-write", default=False,
    help="Write detected drift to disk. Default is report-only.",
)
@click.option(
    "--exit-on-drift/--no-exit-on-drift", default=True,
    help="Exit with non-zero status when drift is detected (CI gating).",
)
@click.option(
    "--report",
    "report_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Also emit a structured JSON report (consumed by the auto-PR workflow).",
)
@click.option(
    "--suppressions",
    type=click.Choice(["honor", "ignore"]),
    default="honor",
    help=(
        "Whether to honor `detections/drift_suppressions.yml`. "
        "Default 'honor' - known-good portal-side tweaks listed in "
        "the suppressions file are removed from the changed list "
        "until they expire. 'ignore' - show every changed entry "
        "regardless (forensic mode)."
    ),
)
@click.option(
    "--diff", "show_diff", is_flag=True, default=False,
    help=(
        "For each CHANGED entry, print the field-level diffs. Useful "
        "for diagnosing why a handler reports drift on rules that "
        "haven't been edited (e.g. G2 - defender_custom_detection "
        "showing CHANGED for every rule on every run)."
    ),
)
@click.option(
    "--role",
    type=click.Choice(["prod", "integration", "dev", "test"]),
    default=None,
    help="Target the Sentinel workspace with this role. Mutex with --workspace. "
         "Multi-workspace tenants must pass one of --role / --workspace; "
         "drift operates on one workspace per run.",
)
@click.option(
    "--workspace", "workspace_name",
    default=None,
    help="Target the Sentinel workspace with this exact ``workspaceName``. "
         "Mutex with --role.",
)
def drift_cmd(detections_path: Path, asset: str | None, write: bool,
              exit_on_drift: bool, report_path: Path | None,
              suppressions: str,
              show_diff: bool, role: str | None,
              workspace_name: str | None) -> None:
    """Detect drift between remote tenant and local YAML.

    For every handler that supports drift (implements `list_remote()` +
    `to_envelope()`), pull the remote inventory and compare against
    local YAML. Optionally write new/changed envelopes to disk so a
    GitHub Actions workflow can open a PR.
    """
    _apply_log_levels()
    # Resolve --role / --workspace before handler registration so the
    # Sentinel ARM provider factories target the right LA workspace.
    if _skip_if_integration_role_absent(role, workspace_name, command="drift"):
        return
    _resolve_single_workspace_or_exit(role, workspace_name)
    register_default_handlers()
    target_asset = Asset(asset) if asset else None

    _print_run_banner(
        "drift",
        detections_path,
        extra={
            "write": str(write).lower(),
        },
    )

    # Load + validate drift_suppressions.yml BEFORE the network calls so
    # a malformed file fails fast without exercising the live tenant.
    sups: list = []
    if suppressions == "honor":
        from contentops.drift_suppressions import (
            SuppressionsError, load_suppressions,
        )
        try:
            sups = load_suppressions(detections_path)
        except SuppressionsError as exc:
            click.echo(f"error: {exc}", err=True)
            sys.exit(2)

    drift_handlers = _collect_drift_handlers(target_asset)

    if not drift_handlers:
        click.echo("No drift-capable handlers registered.")
        return

    started = time.perf_counter()
    try:
        report = detect_drift(drift_handlers, detections_path)
    finally:
        default_registry.close_all()
    duration = time.perf_counter() - started

    # Now apply suppressions (already loaded + validated above).
    suppressed_count = 0
    suppressed_entries: list = []
    expired_keys: set[tuple[str, str]] = set()
    unused_suppressions: list = []
    if suppressions == "honor" and sups:
        from contentops.drift_suppressions import apply_suppressions
        filter_result = apply_suppressions(report, sups)
        report = filter_result.filtered
        suppressed_entries = filter_result.suppressed
        suppressed_count = len(filter_result.suppressed)
        expired_keys = {(s.asset, s.id) for s in filter_result.expired}
        unused_suppressions = filter_result.unused

    summary_extra = f", suppressed: {suppressed_count}" if suppressed_count else ""
    error_extra = f", errors: {len(report.errors)}" if report.has_errors() else ""
    click.echo(
        f"\nDrift report — new: {len(report.new)}, "
        f"changed: {len(report.changed)}, in-sync: {len(report.in_sync)}"
        + error_extra + summary_extra
    )
    for entry in report.errors:
        # An error means we couldn't list remote state for this asset
        # kind — the "changed/new/in-sync" numbers above exclude it
        # entirely. Surface the reason so the operator doesn't read
        # "0 changed" and assume it was actually compared.
        click.echo(
            f"  ERROR    {entry.asset.value:30} (could not list remote: {entry.error})",
            err=True,
        )
    for entry in report.new:
        click.echo(f"  NEW      {entry.asset.value:30} {entry.asset_id}")
    for entry in report.changed:
        tag = ""
        if (entry.asset.value, entry.asset_id) in expired_keys:
            tag = "  [suppression-expired]"
        click.echo(
            f"  CHANGED  {entry.asset.value:30} {entry.asset_id}"
            f"  ({entry.local_path}){tag}"
        )
        if show_diff:
            from contentops.core.discovery import load_asset
            from contentops.core.drift import field_diff
            try:
                local_payload = load_asset(entry.local_path).payload
            except Exception as exc:  # noqa: BLE001
                click.echo(f"    [diff] could not load local YAML: {exc}")
                continue
            remote_payload = (entry.envelope or {}).get("payload", {})
            diffs = field_diff(local_payload, remote_payload)
            if not diffs:
                click.echo(
                    "    [diff] (no field-level diffs surfaced — "
                    "may indicate a normalization gap)"
                )
            for d in diffs:
                if d.kind == "added":
                    click.echo(f"    + {d.key}: {d.remote_repr}")
                elif d.kind == "removed":
                    click.echo(f"    - {d.key}: {d.local_repr}")
                else:
                    click.echo(f"    ~ {d.key}:")
                    click.echo(f"        local : {d.local_repr}")
                    click.echo(f"        remote: {d.remote_repr}")
    if unused_suppressions:
        click.echo(
            f"\n[suppression-unused] {len(unused_suppressions)} entry/entries in "
            "drift_suppressions.yml didn't match any drift today (clean up):"
        )
        for s in unused_suppressions:
            click.echo(f"  {s.asset:30} {s.id}  (expires {s.expires.isoformat()})")

    if write and report.has_drift():
        written = write_drift(report, detections_path)
        click.echo(f"\nWrote {len(written)} file(s):")
        for p in written:
            click.echo(f"  {p}")

    if report_path is not None:
        from contentops.config import load_tenant_config
        try:
            cfg = load_tenant_config()
            tenant_name = cfg.name
            active_name = os.environ.get("PIPELINE_WORKSPACE_NAME")
            if active_name:
                workspace_name = active_name
            elif len(cfg.sentinelWorkspaces) == 1:
                workspace_name = cfg.sentinelWorkspaces[0].workspaceName
            else:
                workspace_name = ""
        except Exception:
            tenant_name = ""
            workspace_name = ""
        report_doc = {
            "tenant": tenant_name,
            "workspace": workspace_name,
            "run_id": os.getenv("GITHUB_RUN_ID") or "",
            "entries": [
                {"asset": e.asset.value, "id": e.asset_id, "kind": e.kind}
                for e in (report.new + report.changed)
            ],
            # Error entries surface separately so downstream consumers
            # (auto-PR workflow, ops dashboards) can distinguish
            # "couldn't check" from "no drift".
            "errors": [
                {"asset": e.asset.value, "error": e.error or ""}
                for e in report.errors
            ],
            # Suppression accounting so the auto-PR body can report what
            # was hidden (and surface expired/unused suppressions that
            # need operator attention). Suppressed entries were already
            # removed from `entries` above.
            "suppressed": [
                {"asset": e.asset.value, "id": e.asset_id}
                for e in suppressed_entries
            ],
            "expired": [
                {"asset": a, "id": i} for (a, i) in sorted(expired_keys)
            ],
            "unused": [
                {"asset": s.asset, "id": s.id, "expires": s.expires.isoformat()}
                for s in unused_suppressions
            ],
        }
        import json as _json
        report_path.write_text(_json.dumps(report_doc, indent=2), encoding="utf-8")
        click.echo(f"[drift] wrote JSON report: {report_path}")

    # Errors always exit non-zero — even when --no-exit-on-drift is
    # passed, an unreachable asset kind is a real failure (we cannot
    # state whether drift exists or not). exit_on_drift still gates the
    # genuine has_drift() path so CI users can ratchet drift gradually.
    if report.has_errors():
        sys.exit(2)
    if exit_on_drift and report.has_drift():
        sys.exit(2)


@click.command("drift-resolve")
@click.argument("asset_id")
@click.option(
    "--strategy",
    type=click.Choice(["git", "remote", "merge"]),
    required=True,
    help=(
        "How to resolve drift for this rule: 'git' (local wins, no "
        "mutation), 'remote' (overwrite local YAML with remote), "
        "'merge' (3-way merge - not yet implemented)."
    ),
)
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory.",
)
@click.option(
    "--asset",
    type=click.Choice([a.value for a in Asset]),
    default=None,
    help=(
        "Hint at which asset kind to look in (speeds up the lookup; "
        "without it every drift-capable handler runs list_remote)."
    ),
)
@click.option("--dry-run", is_flag=True, default=False,
              help="Print the action without writing to disk.")
def drift_resolve_cmd(
    asset_id: str, strategy: str, detections_path: Path,
    asset: str | None, dry_run: bool,
) -> None:
    """Resolve drift for one rule with a chosen strategy.

    Per-rule alternative to `contentops drift --write`, which is
    all-or-nothing. Use this when:

    \b
      * Most drift entries should fall back to git, but a specific
        rule has been intentionally tuned in the portal -
        --strategy remote captures that.
      * Or vice versa: most should keep the portal version, but
        one rule was reverted for cause - --strategy git
        documents that.
    """
    from contentops.drift_resolve import (
        DriftResolveError, NotImplementedStrategy,
        find_entry_for, resolve_git, resolve_merge, resolve_remote,
    )

    register_default_handlers()
    target_asset = Asset(asset) if asset else None
    handlers = _collect_drift_handlers(target_asset)

    if strategy == "git":
        outcome = resolve_git(asset_id)
        click.echo(f"  [{outcome.strategy}]  {outcome.asset_id}: {outcome.detail}")
        default_registry.close_all()
        return

    try:
        entry = find_entry_for(handlers, detections_path, asset_id)
    finally:
        default_registry.close_all()

    if entry is None:
        click.echo(f"error: no drift entry found for {asset_id!r}", err=True)
        sys.exit(1)

    if entry.kind == "in-sync":
        click.echo(f"  {asset_id}: in-sync — no resolution needed")
        return

    try:
        if strategy == "remote":
            outcome = resolve_remote(entry=entry, dry_run=dry_run)
        else:  # merge
            outcome = resolve_merge(entry=entry)
    except NotImplementedStrategy as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(2)
    except DriftResolveError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)

    tag = "[would-write]" if outcome.action == "would-write" else "[wrote]"
    click.echo(f"  {tag}  {outcome.asset_id}: {outcome.detail}")


@click.command("drift-pr-body")
@click.option(
    "--report",
    "report_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Drift JSON report produced by `contentops drift --report`.",
)
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    help="Root detections directory used to look up envelope.metadata.owner.",
)
@click.option(
    "--out",
    type=click.Path(path_type=Path),
    default=None,
    help="Write the body to this path (default: stdout).",
)
@click.option(
    "--labels-out",
    type=click.Path(path_type=Path),
    default=None,
    help="If set, also write the comma-separated label list to this path.",
)
def drift_pr_body_cmd(
    report_path: Path,
    detections_path: Path,
    out: Path | None,
    labels_out: Path | None,
) -> None:
    """Render a Markdown PR body for the auto-drift workflow."""
    import json as _json

    from contentops.upstream.drift_pr import (
        collect_owners,
        labels_for,
        parse_report,
        render_pr_body,
    )

    raw = _json.loads(report_path.read_text(encoding="utf-8"))
    report = parse_report(raw)
    owners = collect_owners(detections_path, [e.id for e in report.entries])
    body = render_pr_body(report, id_to_owner=owners)

    if out is not None:
        out.write_text(body, encoding="utf-8")
        click.echo(f"[drift-pr-body] wrote body: {out}", err=True)
    else:
        click.echo(body)

    if labels_out is not None:
        labels_out.write_text(",".join(labels_for(report)), encoding="utf-8")
        click.echo(f"[drift-pr-body] wrote labels: {labels_out}", err=True)
