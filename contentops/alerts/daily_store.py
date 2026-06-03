# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Persistent daily rollup store.

Stores one entry per (date, rule_display_name, version) with
classification counts. Built from the per-alert ledger with gap
filling and idempotency — dates that already have rollups are
skipped, missing dates are filled from ledger data.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from contentops.alerts.ledger import (
    LedgerEntry,
    load_ledger,
)
from contentops.core.handler import LoadedAsset

logger = logging.getLogger(__name__)

DEFAULT_DAILY_STORE_PATH = Path("alerts-reports/daily-rollups.jsonl")


@dataclass(frozen=True)
class DailyRollupEntry:
    date: str
    rule_display_name: str
    version: str
    asset_kind: str
    severity: str
    alert_count: int
    resolved_count: int
    tp_count: int
    fp_count: int
    benign_count: int
    undetermined_count: int
    mean_close_hours: float | None


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


def load_daily_store(store_path: Path) -> list[DailyRollupEntry]:
    if not store_path.is_file():
        return []
    entries: list[DailyRollupEntry] = []
    with open(store_path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                entries.append(DailyRollupEntry(**data))
            except (json.JSONDecodeError, TypeError) as exc:
                logger.debug("daily store line %d skipped: %s", lineno, exc)
    return entries


def load_daily_store_for_range(
    store_path: Path, start: date, end: date,
) -> list[DailyRollupEntry]:
    entries = load_daily_store(store_path)
    start_iso = start.isoformat()
    end_iso = end.isoformat()
    return [e for e in entries if start_iso <= e.date <= end_iso]


def dates_with_rollups(store_path: Path) -> set[str]:
    if not store_path.is_file():
        return set()
    dates: set[str] = set()
    with open(store_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                d = data.get("date")
                if isinstance(d, str):
                    dates.add(d)
            except (json.JSONDecodeError, KeyError):
                pass
    return dates


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------


def _append_entries(store_path: Path, entries: list[DailyRollupEntry]) -> None:
    store_path.parent.mkdir(parents=True, exist_ok=True)
    with open(store_path, "a", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(asdict(entry), separators=(",", ":")) + "\n")


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def _build_detection_index(
    detections: list[LoadedAsset],
) -> dict[str, LoadedAsset]:
    """Map display_name.lower() -> LoadedAsset for version/metadata lookup."""
    index: dict[str, LoadedAsset] = {}
    for d in detections:
        name = (
            d.payload.get("displayName")
            or d.payload.get("DisplayName")
            or d.envelope.id
        )
        index[name.strip().lower()] = d
    return index


def _group_alerts_by_date(
    alerts: list[LedgerEntry],
) -> dict[str, list[LedgerEntry]]:
    by_date: dict[str, list[LedgerEntry]] = defaultdict(list)
    for entry in alerts:
        if not entry.created_at:
            continue
        try:
            created = datetime.fromisoformat(
                entry.created_at.replace("Z", "+00:00")
            ).date()
            by_date[created.isoformat()].append(entry)
        except (ValueError, TypeError):
            pass
    return dict(by_date)


def build_daily_rollups(
    ledger_path: Path,
    detections: list[LoadedAsset],
    *,
    store_path: Path | None = None,
    retention_days: int = 365,
) -> int:
    """Rebuild the daily rollup store from the ledger.

    Fully idempotent: rewrites the store from scratch each time.
    Same ledger data always produces the same rollup. This ensures
    reclassified alerts are reflected in the rollups.

    Returns the total count of date+title entries written.
    """
    if store_path is None:
        store_path = DEFAULT_DAILY_STORE_PATH

    all_alerts = load_ledger(ledger_path)
    if not all_alerts:
        return 0

    by_date = _group_alerts_by_date(all_alerts)
    det_index = _build_detection_index(detections)

    new_entries: list[DailyRollupEntry] = []

    for date_str in sorted(by_date.keys()):
        day_alerts = by_date[date_str]
        by_title: dict[str, list[LedgerEntry]] = defaultdict(list)
        for a in day_alerts:
            by_title[a.rule_display_name].append(a)

        for title, group in sorted(by_title.items()):
            det = det_index.get(title.strip().lower())
            version = det.envelope.version if det else ""
            asset_kind = det.envelope.asset.value if det else ""
            severity = group[0].severity

            resolved = sum(1 for a in group if a.closed_at)
            tp = sum(1 for a in group if a.classification == "truePositive")
            fp = sum(1 for a in group if a.classification == "falsePositive")
            benign = sum(1 for a in group if a.classification == "benignPositive")
            undetermined = sum(1 for a in group if a.classification == "undetermined")

            close_hours: list[float] = []
            for a in group:
                if a.closed_at and a.created_at:
                    try:
                        created = datetime.fromisoformat(a.created_at.replace("Z", "+00:00"))
                        closed = datetime.fromisoformat(a.closed_at.replace("Z", "+00:00"))
                        close_hours.append((closed - created).total_seconds() / 3600.0)
                    except (ValueError, TypeError):
                        pass

            mean_close = (
                round(sum(close_hours) / len(close_hours), 2)
                if close_hours else None
            )

            new_entries.append(DailyRollupEntry(
                date=date_str,
                rule_display_name=title,
                version=version,
                asset_kind=asset_kind,
                severity=severity,
                alert_count=len(group),
                resolved_count=resolved,
                tp_count=tp,
                fp_count=fp,
                benign_count=benign,
                undetermined_count=undetermined,
                mean_close_hours=mean_close,
            ))

    # Full rewrite for idempotency — reclassifications are reflected
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_text("", encoding="utf-8")
    if new_entries:
        _append_entries(store_path, new_entries)

    pruned = prune_store(store_path, retention_days)
    if pruned > 0:
        logger.info("Pruned %d entries older than %d days", pruned, retention_days)

    return len(new_entries)


# ---------------------------------------------------------------------------
# Prune
# ---------------------------------------------------------------------------


def prune_store(store_path: Path, retention_days: int) -> int:
    """Remove entries older than retention_days. Returns count removed."""
    if not store_path.is_file():
        return 0

    cutoff = (date.today() - timedelta(days=retention_days)).isoformat()
    entries = load_daily_store(store_path)
    kept = [e for e in entries if e.date >= cutoff]
    removed = len(entries) - len(kept)

    if removed > 0:
        store_path.write_text("", encoding="utf-8")
        _append_entries(store_path, kept)

    return removed


__all__ = [
    "DEFAULT_DAILY_STORE_PATH",
    "DailyRollupEntry",
    "build_daily_rollups",
    "dates_with_rollups",
    "load_daily_store",
    "load_daily_store_for_range",
    "prune_store",
]
