# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops alerts`` command group.

Three subcommands:

* ``alerts collect`` -- fetch raw alerts / incidents and write JSON/CSV.
* ``alerts rollup`` -- compute a daily rollup and write MD/JSON/CSV.
* ``alerts report`` -- compute a multi-day trend report.
"""

from __future__ import annotations

import csv
import io
import json
import re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import click

from contentops.cli.commands._shared import _apply_log_levels, _print_run_banner


# ------------------------------------------------------------------
# Duration parser: "24h", "7d", "30d", or ISO 8601 timestamp
# ------------------------------------------------------------------

_DURATION_RE = re.compile(r"^(\d+)([hd])$", re.IGNORECASE)


def _parse_since(value: str) -> datetime:
    """Parse a duration shorthand or ISO 8601 timestamp into a tz-aware datetime."""
    m = _DURATION_RE.match(value.strip())
    if m:
        amount, unit = int(m.group(1)), m.group(2).lower()
        if unit == "h":
            return datetime.now(timezone.utc) - timedelta(hours=amount)
        return datetime.now(timezone.utc) - timedelta(days=amount)
    # Try ISO 8601
    normalised = value.replace("Z", "+00:00") if value.endswith("Z") else value
    try:
        dt = datetime.fromisoformat(normalised)
        # Make tz-aware if naive
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        raise click.BadParameter(
            f"Cannot parse '{value}' as a duration (e.g. 24h, 7d) or ISO 8601 timestamp."
        )


def _parse_date(value: str) -> date:
    """Parse a date string: YYYY-MM-DD, 'yesterday', or 'today'."""
    lower = value.strip().lower()
    if lower == "today":
        return date.today()
    if lower == "yesterday":
        return date.today() - timedelta(days=1)
    try:
        return date.fromisoformat(value.strip())
    except ValueError:
        raise click.BadParameter(
            f"Cannot parse '{value}' as a date. Use YYYY-MM-DD, 'today', or 'yesterday'."
        )


def _parse_period(value: str) -> int:
    """Parse a period string like '7d', '30d', or a bare integer."""
    m = re.match(r"^(\d+)d?$", value.strip(), re.IGNORECASE)
    if m:
        return int(m.group(1))
    raise click.BadParameter(
        f"Cannot parse '{value}' as a period. Use e.g. '7d', '30d', or '7'."
    )


# ------------------------------------------------------------------
# Provider construction helpers
# ------------------------------------------------------------------


def _build_provider() -> Any:
    """Construct a GraphAlertsProvider with optional Sentinel fallback."""
    from contentops.alerts.provider import GraphAlertsProvider
    from contentops.utils.auth import get_credential

    credential = get_credential()
    sentinel_provider = None

    try:
        from contentops.config import load_tenant_config

        cfg = load_tenant_config()
        if cfg.sentinelWorkspaces:
            import os
            from contentops.providers.sentinel_arm import SentinelArmProvider

            ws_name = os.environ.get("PIPELINE_WORKSPACE_NAME")
            if ws_name:
                workspace = cfg.workspace_by_name(ws_name)
            else:
                from contentops.config import select_primary_workspace
                workspace = select_primary_workspace(cfg, role="prod")

            sentinel_provider = SentinelArmProvider(
                workspace, credential=credential,
            )
    except FileNotFoundError:
        pass  # No tenant config -> Graph-only

    workspace_id = None
    if sentinel_provider is not None:
        try:
            from contentops.workspace_kql import resolve_workspace_id
            workspace_id = resolve_workspace_id(credential=credential)
        except Exception:
            pass  # Fall back to ARM incidents if workspace ID unavailable

    return GraphAlertsProvider(
        credential,
        sentinel_provider=sentinel_provider,
        workspace_id=workspace_id,
    )


def _normalize_alerts(raw: list[dict], source: str) -> list[Any]:
    """Normalize raw dicts into NormalizedAlert objects."""
    from contentops.alerts.models import NormalizedAlert

    results = []
    for item in raw:
        try:
            if source == "sentinel":
                results.append(NormalizedAlert.from_sentinel(item))
            else:
                results.append(NormalizedAlert.from_graph(item))
        except Exception as exc:
            click.echo(f"  [warn] skipped alert: {exc}", err=True)
    return results


# ------------------------------------------------------------------
# Click group + subcommands
# ------------------------------------------------------------------

@click.group("alerts")
def alerts_group() -> None:
    """Alert tracking, daily rollup, and trend reporting.

    \b
    Subcommands:
      collect   Fetch raw alerts from Graph / Sentinel
      rollup    Compute a daily classification rollup
      report    Compute a multi-day trend report
    """


@alerts_group.command("collect")
@click.option(
    "--since", "since_str", default="24h",
    help="Time window: duration (24h, 7d, 30d) or ISO 8601 timestamp.",
)
@click.option(
    "--until", "until_str", default=None,
    help="End of time window (ISO 8601). Defaults to now.",
)
@click.option(
    "--service-source", default=None,
    help="Filter by serviceSource (Graph only). E.g. microsoftDefenderForEndpoint.",
)
@click.option(
    "--status", default=None,
    help="Filter by status: new, inProgress, resolved.",
)
@click.option(
    "--classification", default=None,
    help="Filter by classification: truePositive, falsePositive, etc.",
)
@click.option(
    "--out", "out_path", default=None, type=click.Path(path_type=Path),
    help="Output file path (.json or .csv). Omit for stdout JSON.",
)
def collect_cmd(
    since_str: str,
    until_str: str | None,
    service_source: str | None,
    status: str | None,
    classification: str | None,
    out_path: Path | None,
) -> None:
    """Fetch raw alerts from Graph alerts_v2 or Sentinel incidents."""
    _apply_log_levels()

    since = _parse_since(since_str)
    until_dt = _parse_since(until_str) if until_str else None

    _print_run_banner(
        "alerts collect",
        extra={
            "since": since.isoformat(),
            "until": until_dt.isoformat() if until_dt else "(now)",
            "service_source": service_source or "(all)",
        },
    )

    provider = _build_provider()
    try:
        source = provider.detect_source()
        click.echo(f"  source         : {source}")
        click.echo("")

        raw = provider.list_alerts(
            since=since,
            until=until_dt,
            service_source=service_source,
            status=status,
            classification=classification,
        )
    finally:
        provider.close()

    click.echo(f"Fetched {len(raw)} alert(s).")

    if out_path is None:
        click.echo(json.dumps(raw, indent=2, default=str))
        return

    if out_path.suffix.lower() == ".csv":
        _write_alerts_csv(raw, out_path)
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(raw, indent=2, default=str), encoding="utf-8")

    click.echo(f"Wrote {out_path}")


def _write_alerts_csv(raw: list[dict], path: Path) -> None:
    """Write raw alert dicts as CSV."""
    if not raw:
        path.write_text("", encoding="utf-8")
        return
    # Flatten nested dicts: use top-level keys + properties keys
    fieldnames: list[str] = []
    for item in raw[:10]:
        for key in item:
            if key not in fieldnames:
                fieldnames.append(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for item in raw:
            # Stringify complex values
            row = {}
            for k in fieldnames:
                v = item.get(k)
                if isinstance(v, (dict, list)):
                    row[k] = json.dumps(v, default=str)
                else:
                    row[k] = v
            writer.writerow(row)


@alerts_group.command("sync")
@click.option(
    "--ledger", "ledger_path", default=None, type=click.Path(path_type=Path),
    help="Path to alert ledger JSONL. Default: alerts-reports/alert-ledger.jsonl.",
)
@click.option(
    "--backfill", is_flag=True, default=False,
    help="Fill missing daily files for the last N days (default 30).",
)
@click.option(
    "--backfill-days", default=None, type=int,
    help="Number of days to backfill when --backfill is set (default: from config, 30).",
)
@click.option(
    "--date", "target_date", default=None, type=str,
    help="Export a specific date (YYYY-MM-DD) instead of yesterday.",
)
@click.option(
    "--force", is_flag=True, default=False,
    help="Re-export even if the daily file already exists.",
)
@click.option(
    "--no-enrich", is_flag=True, default=False,
    help="Skip ARM overlay and Graph enrichment (KQL join only).",
)
@click.option(
    "--arm-overlay-days", default=None, type=int,
    help="Days of ARM incidents to overlay (default: from config, 30).",
)
@click.option(
    "--reexport-days", default=None, type=int,
    help="Days to re-export for incident lifecycle updates (default: from config, 7).",
)
def sync_cmd(
    ledger_path: Path | None,
    backfill: bool,
    backfill_days: int,
    target_date: str | None,
    force: bool,
    no_enrich: bool,
    arm_overlay_days: int | None,
    reexport_days: int | None,
) -> None:
    """Export daily alert files from Sentinel SecurityAlert table.

    \b
    Default: exports yesterday's alerts into alerts-reports/daily/<date>.jsonl.
    The monolithic ledger is rebuilt from all daily files on each run.

    \b
    Examples:
      contentops alerts sync                  # yesterday
      contentops alerts sync --backfill       # last 30 days
      contentops alerts sync --backfill --backfill-days 90
      contentops alerts sync --date 2026-05-20
      contentops alerts sync --date 2026-05-20 --force
    """
    _apply_log_levels()

    from datetime import date as _date

    from contentops.alerts.ledger import DEFAULT_DAILY_DIR, DEFAULT_LEDGER_PATH, DEFAULT_WATERMARK_PATH

    if ledger_path is None:
        ledger_path = DEFAULT_LEDGER_PATH
    watermark_path = ledger_path.with_name(
        ledger_path.stem + "-watermark.json"
    )
    daily_dir = DEFAULT_DAILY_DIR

    parsed_date = None
    if target_date:
        parsed_date = _parse_date(target_date)

    _print_run_banner(
        "alerts sync",
        extra={
            "ledger": str(ledger_path),
            "daily_dir": str(daily_dir),
            "backfill": str(backfill),
        },
    )

    alerts_config = None
    try:
        from contentops.config import load_tenant_config

        cfg = load_tenant_config()
        if not cfg.is_alerts_enabled():
            click.echo("Alert sync disabled in tenant.yml (alerts.enabled=false or alerts block absent).")
            return
        alerts_config = cfg.alerts
    except FileNotFoundError:
        pass

    from contentops.alerts.sync import sync_alerts

    provider = _build_provider()
    try:
        result = sync_alerts(
            provider, ledger_path, watermark_path,
            daily_dir=daily_dir,
            alerts_config=alerts_config,
            backfill=backfill,
            backfill_days=backfill_days,
            target_date=parsed_date,
            force=force,
            enrich=not no_enrich,
            arm_overlay_days=arm_overlay_days,
            reexport_days=reexport_days,
        )
    finally:
        provider.close()

    reexport_note = f" + {result.days_reexported} re-exported" if result.days_reexported > 0 else ""
    skip_note = f", skipped {result.days_skipped}" if result.days_skipped > 0 else ""
    click.echo(
        f"Exported {result.days_exported} day(s){reexport_note}{skip_note}. "
        f"Alerts: {result.total_alerts}. "
        f"Source: {result.source}. "
        f"Range: {result.date_range[0]} to {result.date_range[1]}."
    )

    # Pipeline health summary
    kql_status = f"joined ({result.alerts_with_incidents} with incidents)" if result.kql_joined else "plain (no incident data)"
    arm_status = f"{result.arm_files_patched} files patched, {result.arm_entries_updated} entries" if result.arm_available else f"skipped ({result.arm_error or 'not configured'})"
    graph_status = f"{result.graph_alerts_enriched} contributed (merged + enriched)" if result.graph_available else f"skipped ({result.graph_error or 'not configured'})"

    click.echo("")
    click.echo("Pipeline health:")
    click.echo(f"  KQL query    : {kql_status}")
    click.echo(f"  ARM overlay  : {arm_status}")
    click.echo(f"  Graph enrich : {graph_status}")
    if result.reconciliation_stale > 0:
        click.echo(f"  Reconcile    : {result.reconciliation_stale} stale, {result.reconciliation_repaired} repaired")


def _load_alerts_from_ledger_or_api(
    ledger_path: Path | None,
    since: datetime,
    until: datetime,
) -> list[Any]:
    """Load alerts from ledger or Graph/Sentinel API (two-tier fallback)."""
    from contentops.alerts.ledger import (
        DEFAULT_LEDGER_PATH,
        entries_to_normalized_alerts,
        load_ledger_for_range,
    )

    # Tier 1: Ledger
    path = ledger_path or DEFAULT_LEDGER_PATH
    if path.is_file():
        entries = load_ledger_for_range(
            path, start=since.date(), end=(until - timedelta(seconds=1)).date(),
        )
        alerts = entries_to_normalized_alerts(entries)
        click.echo(f"  source         : ledger ({path})")
        click.echo(f"Loaded {len(alerts)} alert(s) from ledger.")
        return alerts

    # Tier 2: Graph/Sentinel API
    try:
        provider = _build_provider()
        try:
            source = provider.detect_source()
            click.echo(f"  source         : {source}")
            click.echo("")
            raw = provider.list_alerts(since=since, until=until)
        finally:
            provider.close()
        alerts = _normalize_alerts(raw, source)
        click.echo(f"Fetched {len(alerts)} alert(s) from API.")
        return alerts
    except Exception as api_exc:
        click.echo(
            f"  [warn] Graph/Sentinel API unavailable: {api_exc}", err=True,
        )

    click.echo(
        "\nNo alert data available. To set up alert collection:\n"
        "  1. Add 'alerts: { enabled: true }' to config/tenant.yml\n"
        "  2. Grant SecurityAlert.Read.All to your app registration\n"
        "  3. Run: contentops alerts sync\n"
        "See docs/operations/alerts-reporting.md for details.",
        err=True,
    )
    return []


@alerts_group.command("rollup")
@click.option(
    "--date", "date_str", default="yesterday",
    help="Target date: YYYY-MM-DD, 'yesterday', or 'today'.",
)
@click.option(
    "--out-md", default=None, type=click.Path(path_type=Path),
    help="Output Markdown file path.",
)
@click.option(
    "--out-json", default=None, type=click.Path(path_type=Path),
    help="Output JSON file path.",
)
@click.option(
    "--out-csv", default=None, type=click.Path(path_type=Path),
    help="Output CSV summary file path.",
)
@click.option(
    "--ledger", "ledger_path", default=None, type=click.Path(path_type=Path),
    help="Path to alert ledger JSONL. Reads from ledger if it exists, else falls back to API.",
)
def rollup_cmd(
    date_str: str,
    out_md: Path | None,
    out_json: Path | None,
    out_csv: Path | None,
    ledger_path: Path | None,
) -> None:
    """Compute a daily alert classification rollup."""
    _apply_log_levels()

    target_date = _parse_date(date_str)

    _print_run_banner(
        "alerts rollup",
        extra={"date": target_date.isoformat()},
    )

    since = datetime(
        target_date.year, target_date.month, target_date.day,
        tzinfo=timezone.utc,
    )
    until = since + timedelta(days=1)

    alerts = _load_alerts_from_ledger_or_api(ledger_path, since, until)
    click.echo(f"{len(alerts)} alert(s) for {target_date.isoformat()}.")

    from contentops.alerts.rollup import (
        compute_daily_rollup,
        render_rollup_json,
        render_rollup_markdown,
    )

    rollup = compute_daily_rollup(alerts, target_date)

    md_text = render_rollup_markdown(rollup)
    json_data = render_rollup_json(rollup)

    # Always print markdown summary to stdout
    click.echo("")
    click.echo(md_text)

    if out_md:
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(md_text, encoding="utf-8")
        click.echo(f"Wrote {out_md}")

    if out_json:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(
            json.dumps(json_data, indent=2, default=str), encoding="utf-8"
        )
        click.echo(f"Wrote {out_json}")

    if out_csv:
        _write_rollup_csv(rollup, out_csv)
        click.echo(f"Wrote {out_csv}")

    # Build persistent daily rollup store (gap filling + idempotent)
    try:
        from contentops.alerts.daily_store import build_daily_rollups
        from contentops.alerts.ledger import DEFAULT_LEDGER_PATH
        from contentops.core.discovery import discover_assets, load_asset
        from contentops.report.assemble import DETECTION_ASSETS

        lpath = ledger_path or DEFAULT_LEDGER_PATH
        if lpath.is_file():
            det_paths = discover_assets(Path("detections"))
            loaded_dets = []
            for p in det_paths:
                try:
                    la = load_asset(p)
                    if la.envelope.asset in DETECTION_ASSETS:
                        loaded_dets.append(la)
                except Exception:
                    pass

            retention = 365
            try:
                from contentops.config import load_tenant_config
                cfg = load_tenant_config()
                if cfg.alerts and cfg.alerts.rollupRetentionDays:
                    retention = cfg.alerts.rollupRetentionDays
            except FileNotFoundError:
                pass

            added = build_daily_rollups(
                lpath, loaded_dets, retention_days=retention,
            )
            if added > 0:
                click.echo(f"Built {added} daily rollup entries.")
    except Exception as exc:
        click.echo(f"  [warn] daily store build skipped: {exc}", err=True)


def _write_rollup_csv(rollup: Any, path: Path) -> None:
    """Write rollup classification counts as CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["date", "total_alerts", "total_resolved", "mttr_hours"])
        writer.writerow([
            rollup.date.isoformat(),
            rollup.total_alerts,
            rollup.total_resolved,
            rollup.mean_time_to_close_hours or "",
        ])
        writer.writerow([])
        writer.writerow(["classification", "count", "percentage"])
        for cc in rollup.classification_counts:
            writer.writerow([cc.classification.name, cc.count, cc.percentage])


@alerts_group.command("report")
@click.option(
    "--period", "period_str", default="7d",
    help="Report period: 7d, 30d, or a custom number of days.",
)
@click.option(
    "--format", "fmt", type=click.Choice(["md", "json", "html"]), default="md",
    help="Output format.",
)
@click.option(
    "--out", "out_path", default=None, type=click.Path(path_type=Path),
    help="Output file path. Omit for stdout.",
)
@click.option(
    "--ledger", "ledger_path", default=None, type=click.Path(path_type=Path),
    help="Path to alert ledger JSONL. Reads from ledger if it exists, else falls back to API.",
)
def report_cmd(
    period_str: str,
    fmt: str,
    out_path: Path | None,
    ledger_path: Path | None,
) -> None:
    """Compute a multi-day alert trend report."""
    _apply_log_levels()

    period_days = _parse_period(period_str)

    _print_run_banner(
        "alerts report",
        extra={
            "period": f"{period_days} days",
            "format": fmt,
        },
    )

    end = date.today()
    start = end - timedelta(days=period_days - 1)

    since = datetime(start.year, start.month, start.day, tzinfo=timezone.utc)
    until = datetime(end.year, end.month, end.day, tzinfo=timezone.utc) + timedelta(days=1)

    alerts = _load_alerts_from_ledger_or_api(ledger_path, since, until)
    click.echo(f"{len(alerts)} alert(s) for {period_days}-day period.")

    from contentops.alerts.report import (
        compute_trend_report,
        render_trend_json,
        render_trend_markdown,
    )

    report = compute_trend_report(alerts, period_days, end_date=end)

    if fmt == "json":
        output = json.dumps(render_trend_json(report), indent=2, default=str)
    elif fmt == "html":
        # HTML wraps the markdown in a minimal HTML shell
        md_text = render_trend_markdown(report)
        output = f"<html><body><pre>\n{md_text}\n</pre></body></html>"
    else:
        output = render_trend_markdown(report)

    if out_path is None:
        click.echo(output)
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        click.echo(f"Wrote {out_path}")


@alerts_group.command("health")
@click.option(
    "--period", "period_str", default="30d",
    help="Lookback period: 7d, 30d, or custom number of days.",
)
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    show_default=True,
    help="Root detections directory.",
)
@click.option(
    "--out-md", default=None, type=click.Path(path_type=Path),
    help="Output Markdown file path.",
)
@click.option(
    "--out-json", default=None, type=click.Path(path_type=Path),
    help="Output JSON file path.",
)
@click.option(
    "--out-csv", default=None, type=click.Path(path_type=Path),
    help="Output CSV file path.",
)
@click.option(
    "--out-badge", default=None, type=click.Path(path_type=Path),
    help="Output shields.io health badge JSON.",
)
@click.option(
    "--previous-snapshot", "previous_snapshot",
    type=click.Path(path_type=Path), default=None,
    help="Previous health snapshot for delta computation.",
)
@click.option(
    "--ledger", "ledger_path", default=None, type=click.Path(path_type=Path),
    help="Path to alert ledger JSONL. Reads from ledger if it exists, else falls back to API.",
)
@click.option(
    "--owners", "owners_path", default=None, type=click.Path(path_type=Path),
    help="Path to owners.yml mapping file. Default: config/owners.yml.",
)
@click.option(
    "--sync-owners", "sync_owners", is_flag=True, default=False,
    help="Auto-add missing detections to the owners file with 'unassigned'.",
)
def health_cmd(
    period_str: str,
    detections_path: Path,
    out_md: Path | None,
    out_json: Path | None,
    out_csv: Path | None,
    out_badge: Path | None,
    previous_snapshot: Path | None,
    ledger_path: Path | None,
    owners_path: Path | None,
    sync_owners: bool,
) -> None:
    """Compute per-detection health by matching alerts to detections.

    \b
    Maps each alert to the detection that fired it (via ARM resource
    ID or display-name matching), computes TP/FP rates, MTTR, and
    silent-days, then assigns a recommendation:

      TUNE            FP rate > 40%
      SILENT          0 alerts in period
      HEALTHY         TP rate > 80%
      REVIEW          everything else
      EXPECTED_SILENT hunting queries (don't fire alerts by design)
    """
    _apply_log_levels()

    period_days = _parse_period(period_str)

    _print_run_banner(
        "alerts health",
        extra={
            "period": f"{period_days} days",
            "detections": str(detections_path),
        },
    )

    from contentops.core.asset import Asset
    from contentops.core.discovery import discover_assets, load_asset
    from contentops.report.assemble import DETECTION_ASSETS

    paths = discover_assets(detections_path)
    loaded = []
    for p in paths:
        try:
            la = load_asset(p)
            if la.envelope.asset in DETECTION_ASSETS:
                loaded.append(la)
        except Exception as exc:
            click.echo(f"  [warn] skipped {p}: {exc}", err=True)

    click.echo(f"  detections     : {len(loaded)}")

    end = date.today()
    start = end - timedelta(days=period_days - 1)
    since = datetime(start.year, start.month, start.day, tzinfo=timezone.utc)
    until = datetime(end.year, end.month, end.day, tzinfo=timezone.utc) + timedelta(days=1)

    alerts = _load_alerts_from_ledger_or_api(ledger_path, since, until)
    click.echo(f"{len(alerts)} alert(s) for {period_days}-day period.")

    from contentops.alerts.detection_health import (
        compute_detection_health,
        render_health_csv,
        render_health_json,
        render_health_markdown,
    )

    from contentops.ownership import load_owner_map, sync_owner_file

    owner_map = load_owner_map(owners_path)
    if sync_owners:
        added = sync_owner_file(owners_path, loaded)
        if added > 0:
            click.echo(f"Added {added} detection(s) to owners file.")
            owner_map = load_owner_map(owners_path)

    report = compute_detection_health(loaded, alerts, period_days, end_date=end, owner_map=owner_map)
    click.echo(
        f"Matched {report.matched_detections}/{report.total_detections} "
        f"detections ({report.unmatched_alerts} unmatched alerts)."
    )

    md_text = render_health_markdown(report)

    # Always print summary to stdout
    click.echo("")
    click.echo(md_text)

    if out_md:
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(md_text, encoding="utf-8")
        click.echo(f"Wrote {out_md}")

    if out_json:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(
            json.dumps(render_health_json(report), indent=2, default=str),
            encoding="utf-8",
        )
        click.echo(f"Wrote {out_json}")

    if out_csv:
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        out_csv.write_text(render_health_csv(report), encoding="utf-8")
        click.echo(f"Wrote {out_csv}")

    if out_badge:
        from contentops.alerts.health_badge import render_health_badge

        out_badge.parent.mkdir(parents=True, exist_ok=True)
        out_badge.write_text(render_health_badge(report), encoding="utf-8")
        click.echo(f"Wrote {out_badge}")

    # Snapshot: write dated snapshot + compute delta vs previous
    from contentops.alerts.health_snapshot import (
        compute_health_delta,
        find_previous_health_snapshot,
        load_health_snapshot,
        render_health_snapshot,
    )

    snapshot_text = render_health_snapshot(report)
    if out_json or out_md:
        snapshot_dir = (out_json or out_md).parent  # type: ignore[union-attr]
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        dated_path = snapshot_dir / f"{end.isoformat()}-health.json"
        dated_path.write_text(snapshot_text, encoding="utf-8")
        click.echo(f"Wrote snapshot {dated_path}")

        # Delta computation
        prev_path = previous_snapshot
        if prev_path is None:
            prev_path = find_previous_health_snapshot(snapshot_dir, end.isoformat())
        if prev_path is not None:
            prev_data = load_health_snapshot(prev_path)
            if prev_data is not None:
                delta = compute_health_delta(prev_data, report)
                if delta.new_tune_ids or delta.resolved_tune_ids or delta.newly_active_ids:
                    click.echo(
                        f"Delta vs {prev_path.name}: "
                        f"+{len(delta.new_tune_ids)} TUNE, "
                        f"-{len(delta.resolved_tune_ids)} resolved, "
                        f"+{len(delta.newly_active_ids)} newly active.",
                        err=True,
                    )


__all__ = ["alerts_group"]
