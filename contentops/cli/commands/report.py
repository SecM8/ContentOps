# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops report`` Click command.

Generates the SOC-grade detection inventory report. See
``contentops.report`` for the design rationale.
"""

from __future__ import annotations

from pathlib import Path

import click

from contentops.report import (
    assemble_report,
    enrich_with_alerts,
    enrich_with_health,
    enrich_with_schema_drift,
    enrich_with_telemetry,
    health_query,
    primary_tables_for_rows,
    render_badge,
    render_html,
    render_markdown,
)
from contentops.report.snapshot import (
    compute_delta,
    find_previous_snapshot,
    load_snapshot,
    prune_dated_snapshots,
    render_snapshot,
)


@click.command("report")
@click.option(
    "--path", "detections_path",
    type=click.Path(exists=True, path_type=Path),
    default=Path("detections"),
    show_default=True,
    help="Root detections directory.",
)
@click.option(
    "--out-html", "out_html",
    type=click.Path(path_type=Path),
    default=Path("reports/latest.html"),
    show_default=True,
    help="HTML output path.",
)
@click.option(
    "--out-md", "out_md",
    type=click.Path(path_type=Path),
    default=Path("reports/latest.md"),
    show_default=True,
    help="Markdown output path.",
)
@click.option(
    "--out-badge", "out_badge",
    type=click.Path(path_type=Path),
    default=Path("reports/badge.json"),
    show_default=True,
    help="shields.io-endpoint badge JSON path.",
)
@click.option(
    "--out-json", "out_json",
    type=click.Path(path_type=Path),
    default=Path("reports/latest.json"),
    show_default=True,
    help=(
        "Structured JSON snapshot path. Used as the diff substrate "
        "for the next run's week-over-week delta. The dated copy "
        "(reports/<YYYY-MM-DD>.json) is also written when the "
        "default reports/ directory is in use, so history accumulates."
    ),
)
@click.option(
    "--previous-snapshot", "previous_snapshot",
    type=click.Path(path_type=Path),
    default=None,
    help=(
        "Path to a previous snapshot JSON. When unset, the most-recent "
        "dated snapshot under reports/ is used. Pass --previous-snapshot "
        "<path> to compare against a specific older report; pass an empty "
        "string to disable the delta."
    ),
)
@click.option(
    "--audit-dir", "audit_dir",
    type=click.Path(path_type=Path),
    default=None,
    help=(
        "Audit JSONL directory (deployment dates source). "
        "Defaults to <detections-parent>/audit."
    ),
)
@click.option(
    "--with-telemetry", "with_telemetry",
    is_flag=True, default=False,
    help=(
        "Add alerts_30d / true_positives / false_positives / fp_rate "
        "/ effectiveness_score columns by querying the LA workspace. "
        "Requires OIDC + workspace access (same path as silent-rules)."
    ),
)
@click.option(
    "--with-health", "with_health",
    is_flag=True, default=False,
    help=(
        "Add the data_source_healthy column by running "
        "`<primary_table> | take 1` per unique primary table against "
        "the workspace. Requires OIDC + workspace access."
    ),
)
@click.option(
    "--with-schema-drift", "with_schema_drift",
    is_flag=True, default=False,
    help=(
        "Add the schema_drift_columns column by cross-referencing each "
        "detection's primary KQL table with tools/kql_strict/schemas.json. "
        "No workspace round-trip; works offline."
    ),
)
@click.option(
    "--workspace-id", "workspace_id",
    envvar="PIPELINE_WORKSPACE_ID",
    default=None,
    help=(
        "LA workspace ID for --with-telemetry / --with-health. "
        "Auto-derived from tenant.yml role=prod when unset."
    ),
)
@click.option(
    "--telemetry-since", "telemetry_since_days",
    type=int, default=30, show_default=True,
    help="Telemetry lookback window in days.",
)
@click.option(
    "--health-since", "health_since_hours",
    type=int, default=24, show_default=True,
    help="Data-source health lookback window in hours.",
)
@click.option(
    "--schemas-path", "schemas_path",
    type=click.Path(path_type=Path),
    default=Path("tools/kql_strict/schemas.json"),
    show_default=True,
    help="Cached LA workspace schema for schema-drift enrichment.",
)
@click.option(
    "--with-alerts", "with_alerts",
    is_flag=True, default=False,
    help=(
        "Add alert performance columns (alerts_30d / TP / FP / fp_rate "
        "/ recommendation / silent_days) by fetching alerts from Graph "
        "Security or Sentinel ARM. Requires OIDC + SecurityAlert.Read.All "
        "(or Sentinel Contributor for fallback)."
    ),
)
@click.option(
    "--unified", "unified",
    is_flag=True, default=False,
    help=(
        "Generate a unified detection program report correlating "
        "inventory, alert health, and MITRE coverage. Layered for "
        "CEO/CISO/SOC Manager/Engineers. Reads from the alert ledger."
    ),
)
@click.option(
    "--retention-days", "retention_days",
    type=int, default=None,
    help=(
        "Prune dated report snapshots (reports/<YYYY-MM-DD>.{html,json}) "
        "older than this many days after writing the current run. When "
        "unset, falls back to tenant.yml `reports.retentionDays` (default "
        "365). Pass 0 to keep every snapshot. reports/ is versioned content, "
        "so this bounds the committed posture history; a reports/ dir with no "
        "dated files prunes nothing."
    ),
)
def report_cmd(
    detections_path: Path,
    out_html: Path,
    out_md: Path,
    out_badge: Path,
    out_json: Path,
    previous_snapshot: Path | None,
    audit_dir: Path | None,
    with_telemetry: bool,
    with_health: bool,
    with_schema_drift: bool,
    workspace_id: str | None,
    telemetry_since_days: int,
    health_since_hours: int,
    schemas_path: Path,
    with_alerts: bool,
    unified: bool,
    retention_days: int | None,
) -> None:
    """Generate the SOC-grade detection inventory report.

    \b
    Joins envelope metadata + git log (merge date) + audit JSONL
    (last deploy) into one row per detection. Renders:

      * HTML: sortable styled table for SOC leads (open in any browser)
      * Markdown: GitHub-renderable for inline PR / wiki use
      * Badge: shields.io endpoint for the README

    Live enrichment (telemetry, data-source health, schema drift)
    will be added in a follow-up; this command stays pure today so
    it works offline / in fork CI without credentials.
    """
    rows, summary = assemble_report(detections_path, audit_dir=audit_dir)

    # Live-enrichment passes (additive; each one mutates rows in
    # place via dataclasses.replace). Failures are reported as
    # warnings so the static report still renders -- the operator
    # gets a clear "what didn't work" signal without losing the
    # report itself.
    primary_tables: dict[str, str | None] | None = None
    if with_health or with_schema_drift:
        primary_tables = primary_tables_for_rows(rows)

    if with_telemetry:
        try:
            from contentops.utils.auth import get_credential
            from contentops.workspace_kql import (
                LA_SCOPE, query as la_query, resolve_workspace_id,
                telemetry_query,
            )
            cred = get_credential()
            if not workspace_id:
                workspace_id = resolve_workspace_id(
                    role="prod", credential=cred,
                )
            token = cred.get_token(LA_SCOPE).token
            result = la_query(
                telemetry_query(since_days=telemetry_since_days),
                workspace_id=workspace_id, token=token,
            )
            tel_by_name = {
                str(r.get("rule_name") or ""): r for r in result.rows
            }
            rows = enrich_with_telemetry(rows, tel_by_name)
        except Exception as exc:  # noqa: BLE001
            click.echo(
                f"[warn] --with-telemetry failed: {exc}; continuing "
                "without telemetry columns.", err=True,
            )

    if with_health:
        try:
            from contentops.utils.auth import get_credential
            from contentops.workspace_kql import (
                LA_SCOPE, query as la_query, resolve_workspace_id,
            )
            cred = get_credential()
            if not workspace_id:
                workspace_id = resolve_workspace_id(
                    role="prod", credential=cred,
                )
            token = cred.get_token(LA_SCOPE).token
            unique_tables = {
                t for t in (primary_tables or {}).values() if t
            }
            table_health: dict[str, bool] = {}
            for table in sorted(unique_tables):
                try:
                    result = la_query(
                        health_query(table, since_hours=health_since_hours),
                        workspace_id=workspace_id, token=token,
                    )
                    table_health[table] = len(result.rows) > 0
                except Exception:
                    table_health[table] = False
            rows = enrich_with_health(
                rows, primary_tables or {}, table_health,
            )
        except Exception as exc:  # noqa: BLE001
            click.echo(
                f"[warn] --with-health failed: {exc}; continuing "
                "without data_source_healthy column.", err=True,
            )

    if with_schema_drift:
        rows = enrich_with_schema_drift(
            rows, primary_tables or {}, schemas_path,
        )

    report_health = None
    if with_alerts:
        try:
            from datetime import datetime as _dt2, timedelta as _td2, timezone as _tz2

            from contentops.alerts.detection_health import compute_detection_health
            from contentops.core.discovery import discover_assets, load_asset
            from contentops.report.assemble import DETECTION_ASSETS

            paths = discover_assets(detections_path)
            loaded = []
            for p in paths:
                try:
                    la = load_asset(p)
                    if la.envelope.asset in DETECTION_ASSETS:
                        loaded.append(la)
                except Exception:
                    pass

            from contentops.utils.auth import get_credential

            cred = get_credential()
            sentinel_provider = None
            try:
                from contentops.config import load_tenant_config

                cfg = load_tenant_config()
                if cfg.sentinelWorkspaces:
                    import os

                    from contentops.providers.sentinel_arm import SentinelArmProvider

                    ws_name = os.environ.get("PIPELINE_WORKSPACE_NAME")
                    if ws_name:
                        ws = cfg.workspace_by_name(ws_name)
                    elif len(cfg.sentinelWorkspaces) == 1:
                        ws = cfg.sentinelWorkspaces[0]
                    else:
                        ws = cfg.sentinelWorkspaces[0]
                    sentinel_provider = SentinelArmProvider(ws, credential=cred)
            except FileNotFoundError:
                pass

            from contentops.alerts.models import NormalizedAlert
            from contentops.alerts.provider import GraphAlertsProvider

            provider = GraphAlertsProvider(cred, sentinel_provider=sentinel_provider)
            try:
                source = provider.detect_source()
                end_dt = _dt2.now(_tz2.utc)
                since_dt = end_dt - _td2(days=telemetry_since_days)
                raw = provider.list_alerts(since=since_dt, until=end_dt)
            finally:
                provider.close()

            alerts = []
            normalize_errors = 0
            for item in raw:
                try:
                    if source == "sentinel":
                        alerts.append(NormalizedAlert.from_sentinel(item))
                    else:
                        alerts.append(NormalizedAlert.from_graph(item))
                except Exception:
                    normalize_errors += 1

            click.echo(
                f"[alerts] fetched {len(raw)} raw, "
                f"normalized {len(alerts)}, "
                f"dropped {normalize_errors}",
                err=True,
            )

            from datetime import date as _date

            report_health = compute_detection_health(
                loaded, alerts, telemetry_since_days, end_date=_date.today(),
            )
            health_by_id = {r.detection_id: r for r in report_health.rows}
            rows = enrich_with_alerts(rows, health_by_id)

            matched_count = sum(1 for r in rows if r.alerts_30d and r.alerts_30d > 0)
            click.echo(
                f"[alerts] {len(report_health.rows)} detections evaluated, "
                f"{matched_count} with alerts, "
                f"{report_health.unmatched_alerts} unmatched alerts",
                err=True,
            )
        except Exception as exc:  # noqa: BLE001
            click.echo(
                f"[warn] --with-alerts failed: {exc}; continuing "
                "without alert health columns.", err=True,
            )

    # Load the previous snapshot for the week-over-week delta. Explicit
    # --previous-snapshot wins; otherwise auto-detect the most-recent
    # dated JSON in the same directory as the current --out-json.
    delta = None
    prev_path = previous_snapshot
    if prev_path is None:
        from datetime import datetime as _dt, timezone as _tz
        today_iso = _dt.now(_tz.utc).strftime("%Y-%m-%d")
        prev_path = find_previous_snapshot(out_json.parent, today_iso)
    elif str(prev_path) == "":
        prev_path = None
    if prev_path is not None:
        prev = load_snapshot(prev_path)
        if prev is not None:
            delta = compute_delta(prev, rows, summary)
            click.echo(
                f"delta vs {prev_path}: "
                f"{delta.total_delta:+d} rules, "
                f"{delta.coverage_techniques_delta:+d} techniques covered, "
                f"{len(delta.new_rule_ids)} added, "
                f"{len(delta.removed_rule_ids)} removed.",
                err=True,
            )

    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text(render_html(rows, summary, delta=delta), encoding="utf-8")
    click.echo(f"wrote html: {out_html}")

    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown(rows, summary), encoding="utf-8")
    click.echo(f"wrote markdown: {out_md}")

    out_badge.parent.mkdir(parents=True, exist_ok=True)
    out_badge.write_text(render_badge(summary), encoding="utf-8")
    click.echo(
        f"wrote badge: {out_badge} "
        f"({summary.total} detections, {summary.coverage_pct}% MITRE)"
    )

    # Structured snapshot for the next run's week-over-week delta.
    out_json.parent.mkdir(parents=True, exist_ok=True)
    snapshot_text = render_snapshot(rows, summary)
    out_json.write_text(snapshot_text, encoding="utf-8")
    click.echo(f"wrote snapshot: {out_json}")

    # Bound the committed report history. reports/ is versioned content, so
    # dated snapshots (reports/<YYYY-MM-DD>.{html,json}) accumulate one per
    # run; this prune trims the ones older than the window. The dated copies
    # are written by the workflow's `cp` step *after* this command, so what
    # we prune here are OLD dated files from prior committed runs — today's
    # hasn't been created yet. A reports/ dir with no dated files (fresh repo)
    # prunes nothing.
    #
    # Precedence: explicit --retention-days wins; else tenant.yml
    # reports.retentionDays; else skip (no tenant.yml / no reports block →
    # keep everything).
    effective_retention = retention_days
    if effective_retention is None:
        try:
            from contentops.config import load_tenant_config
            cfg = load_tenant_config()
            if cfg.reports is not None:
                effective_retention = cfg.reports.retentionDays
        except FileNotFoundError:
            effective_retention = None
    if effective_retention is not None and effective_retention > 0:
        pruned = prune_dated_snapshots(out_json.parent, effective_retention)
        if pruned:
            click.echo(
                f"pruned {pruned} dated report snapshot(s) older than "
                f"{effective_retention}d"
            )

    if unified:
        try:
            from contentops.alerts.daily_store import load_daily_store
            from contentops.alerts.detection_health import compute_detection_health
            from contentops.alerts.health_snapshot import (
                HealthDelta, find_previous_health_snapshot,
                load_health_snapshot, compute_health_delta,
            )
            from contentops.alerts.ledger import (
                DEFAULT_LEDGER_PATH, entries_to_normalized_alerts,
                load_ledger_for_range,
            )
            from contentops.core.discovery import discover_assets, load_asset
            from contentops.report.assemble import DETECTION_ASSETS
            from contentops.report.unified import render_unified_html

            det_paths = discover_assets(detections_path)
            loaded_dets = []
            for p in det_paths:
                try:
                    la = load_asset(p)
                    if la.envelope.asset in DETECTION_ASSETS:
                        loaded_dets.append(la)
                except Exception:
                    pass

            from datetime import date as _d, timedelta as _td

            health_report = report_health if with_alerts and report_health is not None else None
            if health_report is None:
                ledger = DEFAULT_LEDGER_PATH
                if ledger.is_file():
                    end = _d.today()
                    start = end - _td(days=29)
                    from datetime import datetime as _dt, timezone as _tz
                    since = _dt(start.year, start.month, start.day, tzinfo=_tz.utc)
                    until = _dt(end.year, end.month, end.day, tzinfo=_tz.utc) + _td(days=1)
                    entries = load_ledger_for_range(
                        ledger, start=since.date(), end=(until - _td(seconds=1)).date(),
                    )
                    alerts = entries_to_normalized_alerts(entries)
                    health_report = compute_detection_health(
                        loaded_dets, alerts, 30, end_date=end,
                    )

            daily = load_daily_store(Path("alerts-reports/daily-rollups.jsonl"))

            from collections import Counter as _Counter
            service_source_counts: dict[str, int] | None = None
            ledger_path = DEFAULT_LEDGER_PATH
            if ledger_path.is_file():
                end_d = _d.today()
                start_d = end_d - _td(days=29)
                ranged_entries = load_ledger_for_range(
                    ledger_path, start=start_d, end=end_d,
                )
                service_source_counts = dict(_Counter(
                    e.service_source for e in ranged_entries if e.service_source
                ))

            health_delta_obj = None
            hp = find_previous_health_snapshot(
                Path("alerts-reports"),
                _d.today().isoformat() if health_report else "",
            )
            if hp and health_report:
                prev = load_health_snapshot(hp)
                if prev:
                    health_delta_obj = compute_health_delta(prev, health_report)

            unified_html = render_unified_html(
                rows, summary,
                health=health_report,
                daily=daily,
                delta=delta,
                health_delta=health_delta_obj,
                service_source_counts=service_source_counts,
            )
            unified_path = out_html.with_name("unified.html")
            unified_path.write_text(unified_html, encoding="utf-8")
            click.echo(f"wrote unified report: {unified_path}")
        except Exception as exc:  # noqa: BLE001
            click.echo(
                f"[warn] --unified failed: {exc}; "
                "static report still generated.", err=True,
            )


__all__ = ["report_cmd"]
