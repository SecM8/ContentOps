# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Daily alert export with triple-source enrichment.

Each sync exports one day's alerts into a dated JSONL file under
``alerts-reports/daily/``. The monolithic ledger is rebuilt from
all daily files on each run. Missing days are backfilled from the
API automatically.

Three-layer enrichment pipeline:
1. KQL SecurityAlert + SecurityIncident joined query (daily backbone)
2. ARM incidents overlay — patches daily files for lifecycle updates
3. Graph alerts_v2 enrichment — additive MITRE/evidence
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from contentops.alerts.ledger import (
    DEFAULT_DAILY_DIR,
    DEFAULT_LEDGER_PATH,
    DEFAULT_WATERMARK_PATH,
    LedgerEntry,
    LedgerWatermark,
    daily_file_path,
    normalize_to_entry,
    prune_daily_files,
    rebuild_ledger_from_daily,
    write_daily_file,
    write_watermark,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SyncResult:
    days_exported: int
    days_skipped: int
    total_alerts: int
    source: str
    date_range: tuple[date, date]
    days_reexported: int = 0
    alerts_with_incidents: int = 0
    arm_files_patched: int = 0
    arm_entries_updated: int = 0
    graph_alerts_enriched: int = 0
    kql_joined: bool = False
    arm_available: bool = False
    graph_available: bool = False
    arm_error: str | None = None
    graph_error: str | None = None
    reconciliation_stale: int = 0
    reconciliation_repaired: int = 0


@dataclass(frozen=True)
class ReconciliationResult:
    checked: int
    stale: int
    repaired: int
    skipped: int


def sync_day(
    provider: Any,
    target_date: date,
    daily_dir: Path,
    *,
    force: bool = False,
    arm_incidents: list[dict] | None = None,
    graph_alerts: list[Any] | None = None,
) -> tuple[int | None, int, int]:
    """Export one day's alerts to a daily file with enrichment.

    Returns (count, incidents_count, graph_contributed). count is None
    if day was skipped. graph_contributed counts alerts that came from
    or were enriched by Graph.
    """
    from contentops.alerts.merge import enrich_from_graph, overlay_arm_incidents
    from contentops.alerts.models import NormalizedAlert

    path = daily_file_path(daily_dir, target_date)
    if path.is_file() and not force:
        return None, 0, 0

    # Layer 1: KQL joined query (falls back to non-joined)
    try:
        raw = provider.list_alerts_for_date_joined(target_date.isoformat())
    except Exception:
        raw = provider.list_alerts_for_date(target_date.isoformat())

    kql_alerts: list[NormalizedAlert] = []
    for item in raw:
        try:
            if "SystemAlertId" in item:
                alert = NormalizedAlert.from_kql_row(item)
            else:
                alert = NormalizedAlert.from_graph(item)
            kql_alerts.append(alert)
        except Exception as exc:
            logger.debug("skipped alert for %s: %s", target_date, exc)

    # Layer 1b: Graph as complementary source (for non-Unified SOC)
    graph_contributed = 0
    if graph_alerts:
        from contentops.alerts.merge import merge_alerts
        alerts = merge_alerts(graph_alerts, kql_alerts)
        graph_contributed = sum(1 for a in alerts if a.source in ("graph", "both"))
    else:
        alerts = kql_alerts

    incidents_count = sum(1 for a in alerts if a.incident_id is not None)

    # Layer 2: ARM overlay (in-memory, for re-export dates)
    if arm_incidents:
        try:
            alerts = overlay_arm_incidents(alerts, arm_incidents)
        except Exception as exc:
            logger.warning("ARM in-memory overlay failed for %s: %s", target_date, exc)

    # Layer 3: Graph enrichment
    if graph_alerts:
        try:
            alerts = enrich_from_graph(alerts, graph_alerts)
        except Exception as exc:
            logger.warning("Graph enrichment failed for %s: %s", target_date, exc)

    entries: list[LedgerEntry] = []
    for alert in alerts:
        try:
            entries.append(normalize_to_entry(alert))
        except Exception as exc:
            logger.debug("skipped entry for %s: %s", target_date, exc)

    write_daily_file(path, entries)
    return len(entries), incidents_count, graph_contributed


def _reconcile(
    provider: Any,
    daily_dir: Path,
    ledger_entries: dict[str, LedgerEntry],
) -> ReconciliationResult:
    """Run reconciliation check against live SecurityIncident state."""
    try:
        from contentops.workspace_kql import LA_SCOPE, query as kql_query, reconciliation_query
    except ImportError:
        return ReconciliationResult(checked=0, stale=0, repaired=0, skipped=0)

    workspace_id = getattr(provider, "_workspace_id", None)
    if not workspace_id:
        return ReconciliationResult(checked=0, stale=0, repaired=0, skipped=0)

    try:
        credential = provider._credential
        token = credential.get_token(LA_SCOPE).token
        kql = reconciliation_query()
        result = kql_query(kql, workspace_id=workspace_id, token=token)
    except Exception as exc:
        logger.warning("Reconciliation KQL failed: %s", exc)
        return ReconciliationResult(checked=0, stale=0, repaired=0, skipped=0)

    from contentops.alerts.models import AlertClassification

    stale_dates: set[date] = set()
    checked = 0
    stale = 0

    for row in result.rows:
        alert_id = row.get("AlertId") or ""
        if not alert_id:
            continue
        checked += 1
        entry = ledger_entries.get(alert_id)
        if entry is None:
            continue

        current_status = (row.get("CurrentStatus") or "").lower()
        current_classification = row.get("CurrentClassification") or ""
        current_closed = row.get("ClosedTime")

        live_classification = AlertClassification.from_sentinel(current_classification).value

        needs_repair = False
        if live_classification != entry.classification:
            needs_repair = True
        if current_status == "closed" and entry.closed_at is None:
            needs_repair = True
        if current_status in ("new", "active") and entry.closed_at is not None:
            needs_repair = True

        if needs_repair:
            stale += 1
            if entry.created_at:
                try:
                    alert_date = datetime.fromisoformat(
                        entry.created_at.replace("Z", "+00:00")
                    ).date()
                    stale_dates.add(alert_date)
                except (ValueError, TypeError):
                    pass

    repaired = 0
    for d in stale_dates:
        try:
            count, _, _ = sync_day(provider, d, daily_dir, force=True)
            if count is not None:
                repaired += 1
        except Exception as exc:
            logger.warning("Reconciliation re-export for %s failed: %s", d, exc)

    logger.info("Reconciliation: %d checked, %d stale, %d dates repaired", checked, stale, repaired)
    return ReconciliationResult(checked=checked, stale=stale, repaired=repaired, skipped=len(stale_dates) - repaired)


def sync_alerts(
    provider: Any,
    ledger_path: Path = DEFAULT_LEDGER_PATH,
    watermark_path: Path = DEFAULT_WATERMARK_PATH,
    *,
    daily_dir: Path = DEFAULT_DAILY_DIR,
    alerts_config: Any | None = None,
    backfill: bool = False,
    backfill_days: int | None = None,
    target_date: date | None = None,
    force: bool = False,
    enrich: bool = True,
    arm_overlay_days: int | None = None,
    reexport_days: int | None = None,
) -> SyncResult:
    """Export daily alert files and rebuild the ledger.

    Three-layer pipeline:
    1. KQL joined query for each date
    2. ARM overlay patches all daily files
    3. Graph enrichment during KQL export
    4. Reconciliation verifies ledger accuracy
    """
    retention_days = 90
    cfg_arm_days = 30
    cfg_reexport_days = 7
    cfg_reconcile = True

    if alerts_config is not None:
        retention_days = getattr(alerts_config, "ledgerRetentionDays", 90)
        if backfill_days is None:
            backfill_days = getattr(alerts_config, "defenderLookbackDays", 30)
        cfg_arm_days = getattr(alerts_config, "armOverlayDays", 30)
        cfg_reexport_days = getattr(alerts_config, "reexportDays", 7)
        cfg_reconcile = getattr(alerts_config, "reconcile", True)

    if backfill_days is None:
        backfill_days = 30

    if arm_overlay_days is not None:
        cfg_arm_days = arm_overlay_days
    if reexport_days is not None:
        cfg_reexport_days = reexport_days

    source = provider.detect_source()
    today = date.today()

    # Determine primary sync dates
    if target_date:
        primary_dates = [target_date]
    elif backfill:
        start = today - timedelta(days=backfill_days)
        primary_dates = [start + timedelta(days=i) for i in range(backfill_days)]
    else:
        primary_dates = [today - timedelta(days=1)]

    # Re-export last N days for incident lifecycle updates
    reexport_dates: list[date] = []
    if cfg_reexport_days > 0 and not backfill:
        for i in range(1, cfg_reexport_days + 1):
            d = today - timedelta(days=i)
            if d not in primary_dates:
                reexport_dates.append(d)

    # Fetch ARM incidents ONCE for overlay
    arm_incidents: list[dict] = []
    arm_available = False
    arm_error: str | None = None
    if enrich and cfg_arm_days > 0:
        try:
            arm_incidents = provider.list_recently_modified_incidents(modified_days=cfg_arm_days)
            arm_available = bool(arm_incidents) or True
        except Exception as exc:
            arm_error = str(exc)
            logger.warning("ARM overlay fetch failed: %s", exc)

    # Fetch Graph alerts ONCE for enrichment
    graph_normalized: list[Any] = []
    graph_available = False
    graph_error: str | None = None
    graph_enriched_count = 0
    if enrich:
        try:
            from contentops.alerts.models import NormalizedAlert
            all_dates = sorted(set(primary_dates + reexport_dates))
            if all_dates:
                from datetime import datetime as _dt, timezone as _tz
                since = _dt(all_dates[0].year, all_dates[0].month, all_dates[0].day, tzinfo=_tz.utc)
                until = _dt(all_dates[-1].year, all_dates[-1].month, all_dates[-1].day, tzinfo=_tz.utc) + timedelta(days=1)
                sources = provider.detect_available_sources()
                if "graph" in sources:
                    raw_graph = provider._list_graph_alerts(since=since, until=until)
                    graph_normalized = [NormalizedAlert.from_graph(g) for g in raw_graph]
                    graph_available = True
                    logger.info("Graph enrichment: fetched %d alerts for enrichment", len(graph_normalized))
        except Exception as exc:
            graph_error = str(exc)
            logger.warning("Graph enrichment fetch failed: %s", exc)

    # Export primary dates + re-export dates
    days_exported = 0
    days_reexported = 0
    days_skipped = 0
    total_alerts = 0
    total_incidents = 0
    kql_joined = False

    all_sync_dates = primary_dates + reexport_dates
    for d in all_sync_dates:
        is_reexport = d in reexport_dates
        day_force = force or is_reexport

        # Filter Graph alerts to this day's date range for accurate merge
        day_graph: list[Any] = []
        if graph_normalized and enrich:
            from datetime import datetime as _dt, timezone as _tz
            day_start = _dt(d.year, d.month, d.day, tzinfo=_tz.utc)
            day_end = day_start + timedelta(days=1)
            day_graph = [
                ga for ga in graph_normalized
                if ga.created and day_start <= ga.created < day_end
            ]

        count, inc_count, graph_count = sync_day(
            provider, d, daily_dir,
            force=day_force,
            arm_incidents=arm_incidents if enrich else None,
            graph_alerts=day_graph if enrich else None,
        )
        if count is None:
            days_skipped += 1
            logger.debug("Skipped %s (already exported)", d)
        else:
            if is_reexport:
                days_reexported += 1
            else:
                days_exported += 1
            total_alerts += count
            total_incidents += inc_count
            graph_enriched_count += graph_count
            if inc_count > 0:
                kql_joined = True
            logger.info("Exported %s: %d alerts (%d with incidents, %d from Graph)%s", d, count, inc_count, graph_count,
                        " [re-export]" if is_reexport else "")

    # ARM overlay: patch ALL daily files (not just synced dates)
    arm_files_patched = 0
    arm_entries_updated = 0
    if enrich and arm_incidents:
        try:
            from contentops.alerts.merge import apply_arm_overlay_to_daily_files
            arm_files_patched, arm_entries_updated = apply_arm_overlay_to_daily_files(daily_dir, arm_incidents)
        except Exception as exc:
            arm_error = arm_error or str(exc)
            logger.warning("ARM daily-file overlay failed: %s", exc)

    # Rebuild ledger from (now-patched) daily files
    ledger_count = rebuild_ledger_from_daily(daily_dir, ledger_path)

    # Reconciliation check
    recon_stale = 0
    recon_repaired = 0
    if cfg_reconcile and enrich:
        try:
            from contentops.alerts.ledger import load_ledger_deduped
            entries = load_ledger_deduped(ledger_path)
            entries_by_id = {e.alert_id: e for e in entries}
            recon = _reconcile(provider, daily_dir, entries_by_id)
            recon_stale = recon.stale
            recon_repaired = recon.repaired
            if recon.repaired > 0:
                ledger_count = rebuild_ledger_from_daily(daily_dir, ledger_path)
        except Exception as exc:
            logger.warning("Reconciliation failed: %s", exc)

    pruned_files = prune_daily_files(daily_dir, retention_days)
    if pruned_files > 0:
        logger.info("Pruned %d daily files older than %d days", pruned_files, retention_days)

    new_watermark = LedgerWatermark(
        last_sync_at=datetime.now(timezone.utc).isoformat(),
        last_sync_until=today.isoformat(),
        entry_count=ledger_count,
        source=source,
    )
    write_watermark(watermark_path, new_watermark)

    all_dates = sorted(set(primary_dates + reexport_dates))
    date_range = (all_dates[0], all_dates[-1]) if all_dates else (today, today)

    return SyncResult(
        days_exported=days_exported,
        days_skipped=days_skipped,
        total_alerts=total_alerts,
        source=source,
        date_range=date_range,
        days_reexported=days_reexported,
        alerts_with_incidents=total_incidents,
        arm_files_patched=arm_files_patched,
        arm_entries_updated=arm_entries_updated,
        graph_alerts_enriched=graph_enriched_count,
        kql_joined=kql_joined,
        arm_available=arm_available,
        graph_available=graph_available,
        arm_error=arm_error,
        graph_error=graph_error,
        reconciliation_stale=recon_stale,
        reconciliation_repaired=recon_repaired,
    )


def compute_lookback_window(
    watermark: LedgerWatermark | None,
    *,
    defender_lookback_days: int = 30,
    sentinel_lookback_days: int = 90,
    source: str,
    backfill: bool = False,
    now: datetime | None = None,
) -> tuple[datetime, datetime]:
    """Compute (since, until) for legacy callers."""
    if now is None:
        now = datetime.now(timezone.utc)
    until = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    if backfill or watermark is None:
        lookback = (
            sentinel_lookback_days if source in ("sentinel", "both")
            else defender_lookback_days
        )
        since = until - timedelta(days=lookback)
        return since, until
    try:
        last_until = datetime.fromisoformat(
            watermark.last_sync_until.replace("Z", "+00:00")
        )
    except (ValueError, TypeError):
        lookback = (
            sentinel_lookback_days if source in ("sentinel", "both")
            else defender_lookback_days
        )
        since = until - timedelta(days=lookback)
        return since, until
    return last_until, until


__all__ = [
    "ReconciliationResult",
    "SyncResult",
    "compute_lookback_window",
    "sync_alerts",
    "sync_day",
]
