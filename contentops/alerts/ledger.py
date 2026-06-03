# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Persistent PII-free alert ledger.

Append-only JSONL file storing minimal alert classification data.
The ledger is the single source of truth for rollup, health, and
trend reports — once ``alerts sync`` has populated it, downstream
commands read from the ledger instead of hitting the API.

No PII is stored: assigned_to, description, evidence,
mitre_techniques, incident_id, and determination are intentionally
dropped by the :func:`normalize_to_entry` firewall.
"""

from __future__ import annotations

import json
import logging
import tempfile
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from contentops.alerts.models import (
    AlertClassification,
    AlertDetermination,
    AlertSeverity,
    AlertStatus,
    NormalizedAlert,
)

logger = logging.getLogger(__name__)

DEFAULT_LEDGER_PATH = Path("alerts-reports/alert-ledger.jsonl")
DEFAULT_WATERMARK_PATH = Path("alerts-reports/alert-ledger-watermark.json")
DEFAULT_DAILY_DIR = Path("alerts-reports/daily")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LedgerEntry:
    alert_id: str
    rule_display_name: str
    classification: str
    closed_at: str | None
    severity: str
    source: str
    created_at: str
    rule_id: str | None = None
    service_source: str = ""
    detection_source: str = ""
    incident_number: int | None = None


@dataclass(frozen=True)
class LedgerWatermark:
    last_sync_at: str
    last_sync_until: str
    entry_count: int
    source: str


# ---------------------------------------------------------------------------
# PII firewall
# ---------------------------------------------------------------------------


def normalize_to_entry(alert: NormalizedAlert) -> LedgerEntry:
    """Convert a NormalizedAlert to a PII-free LedgerEntry.

    This is the data-minimisation boundary. Only the fields needed
    for rollup/health computation are kept; everything else
    (assigned_to, description, evidence, determination, etc.) is
    intentionally dropped.
    """
    incident_number = None
    if alert.incident_id:
        try:
            incident_number = int(alert.incident_id)
        except (ValueError, TypeError):
            pass

    return LedgerEntry(
        alert_id=alert.id,
        rule_display_name=alert.rule_name or alert.title,
        classification=alert.classification.value,
        closed_at=alert.resolved.isoformat() if alert.resolved else None,
        severity=alert.severity.value,
        source=alert.source,
        created_at=alert.created.isoformat() if alert.created else "",
        rule_id=alert.rule_id,
        service_source=alert.service_source,
        detection_source=alert.detection_source,
        incident_number=incident_number,
    )


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------


def append_entries(ledger_path: Path, entries: list[LedgerEntry]) -> int:
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with open(ledger_path, "a", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(asdict(entry), separators=(",", ":")) + "\n")
    return len(entries)


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


def load_ledger(ledger_path: Path) -> list[LedgerEntry]:
    if not ledger_path.is_file():
        return []
    entries: list[LedgerEntry] = []
    with open(ledger_path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                entries.append(LedgerEntry(**data))
            except (json.JSONDecodeError, TypeError) as exc:
                logger.debug("ledger line %d skipped: %s", lineno, exc)
    return entries


def load_ledger_deduped(ledger_path: Path) -> list[LedgerEntry]:
    """Load ledger, keeping only the latest entry per alert_id."""
    raw = load_ledger(ledger_path)
    by_id: dict[str, LedgerEntry] = {}
    for entry in raw:
        by_id[entry.alert_id] = entry
    return list(by_id.values())


def load_ledger_for_range(
    ledger_path: Path,
    *,
    start: date,
    end: date,
) -> list[LedgerEntry]:
    """Load deduped entries whose created_at falls within [start, end]."""
    entries = load_ledger_deduped(ledger_path)
    filtered: list[LedgerEntry] = []
    for entry in entries:
        if not entry.created_at:
            continue
        try:
            created = datetime.fromisoformat(
                entry.created_at.replace("Z", "+00:00")
            ).date()
        except (ValueError, TypeError):
            continue
        if start <= created <= end:
            filtered.append(entry)
    return filtered


# ---------------------------------------------------------------------------
# Conversion to NormalizedAlert (for computation engines)
# ---------------------------------------------------------------------------


def entries_to_normalized_alerts(entries: list[LedgerEntry]) -> list[NormalizedAlert]:
    """Convert LedgerEntry records to NormalizedAlert objects.

    Creates minimal NormalizedAlert objects with only the fields
    the rollup/health engines actually use. Missing fields are set
    to their defaults.
    """
    alerts: list[NormalizedAlert] = []
    for entry in entries:
        created: datetime | None = None
        if entry.created_at:
            try:
                created = datetime.fromisoformat(
                    entry.created_at.replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        resolved: datetime | None = None
        if entry.closed_at:
            try:
                resolved = datetime.fromisoformat(
                    entry.closed_at.replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        status = AlertStatus.resolved if resolved else AlertStatus.new

        try:
            classification = AlertClassification(entry.classification)
        except ValueError:
            classification = AlertClassification.undetermined

        try:
            severity = AlertSeverity(entry.severity)
        except ValueError:
            severity = AlertSeverity.unknown

        alerts.append(NormalizedAlert(
            id=entry.alert_id,
            title=entry.rule_display_name,
            severity=severity,
            status=status,
            classification=classification,
            determination=AlertDetermination.unknown,
            source=entry.source,
            service_source=entry.service_source,
            created=created,
            resolved=resolved,
            rule_id=entry.rule_id,
            rule_name=entry.rule_display_name,
            detection_source=entry.detection_source,
        ))
    return alerts


# ---------------------------------------------------------------------------
# Prune
# ---------------------------------------------------------------------------


def prune_ledger(ledger_path: Path, retention_days: int) -> int:
    """Remove ledger entries older than retention_days. Returns count removed."""
    if not ledger_path.is_file():
        return 0
    from datetime import date as _date, timedelta as _td

    cutoff = (_date.today() - _td(days=retention_days)).isoformat()
    entries = load_ledger(ledger_path)
    kept: list[LedgerEntry] = []
    for entry in entries:
        if not entry.created_at:
            kept.append(entry)
            continue
        try:
            created_date = datetime.fromisoformat(
                entry.created_at.replace("Z", "+00:00")
            ).date().isoformat()
        except (ValueError, TypeError):
            kept.append(entry)
            continue
        if created_date >= cutoff:
            kept.append(entry)

    removed = len(entries) - len(kept)
    if removed > 0:
        ledger_path.write_text("", encoding="utf-8")
        append_entries(ledger_path, kept)
    return removed


# ---------------------------------------------------------------------------
# Watermark
# ---------------------------------------------------------------------------


def read_watermark(watermark_path: Path) -> LedgerWatermark | None:
    if not watermark_path.is_file():
        return None
    try:
        data = json.loads(watermark_path.read_text(encoding="utf-8"))
        return LedgerWatermark(**data)
    except (json.JSONDecodeError, TypeError, OSError) as exc:
        logger.debug("watermark read failed: %s", exc)
        return None


def write_watermark(watermark_path: Path, watermark: LedgerWatermark) -> None:
    watermark_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = watermark_path.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(asdict(watermark), indent=2) + "\n",
        encoding="utf-8",
    )
    tmp.replace(watermark_path)


# ---------------------------------------------------------------------------
# Daily files
# ---------------------------------------------------------------------------


def daily_file_path(daily_dir: Path, target_date: date) -> Path:
    return daily_dir / f"{target_date.isoformat()}.jsonl"


def write_daily_file(path: Path, entries: list[LedgerEntry]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(asdict(entry), separators=(",", ":")) + "\n")
    return len(entries)


def load_daily_files(daily_dir: Path) -> list[LedgerEntry]:
    if not daily_dir.is_dir():
        return []
    entries: list[LedgerEntry] = []
    for f in sorted(daily_dir.glob("*.jsonl")):
        entries.extend(load_ledger(f))
    return entries


def rebuild_ledger_from_daily(
    daily_dir: Path,
    ledger_path: Path,
) -> int:
    """Union all daily files, dedup by alert_id (latest wins), write ledger."""
    all_entries = load_daily_files(daily_dir)
    by_id: dict[str, LedgerEntry] = {}
    for entry in all_entries:
        by_id[entry.alert_id] = entry
    deduped = list(by_id.values())
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.write_text("", encoding="utf-8")
    append_entries(ledger_path, deduped)
    return len(deduped)


def prune_daily_files(daily_dir: Path, retention_days: int) -> int:
    """Delete daily files older than retention_days. Returns count removed."""
    if not daily_dir.is_dir():
        return 0
    from datetime import timedelta as _td
    cutoff = date.today() - _td(days=retention_days)
    removed = 0
    for f in daily_dir.glob("*.jsonl"):
        try:
            file_date = date.fromisoformat(f.stem)
            if file_date < cutoff:
                f.unlink()
                removed += 1
        except (ValueError, OSError):
            pass
    return removed


__all__ = [
    "DEFAULT_DAILY_DIR",
    "DEFAULT_LEDGER_PATH",
    "DEFAULT_WATERMARK_PATH",
    "LedgerEntry",
    "LedgerWatermark",
    "append_entries",
    "daily_file_path",
    "entries_to_normalized_alerts",
    "load_daily_files",
    "load_ledger",
    "load_ledger_deduped",
    "load_ledger_for_range",
    "normalize_to_entry",
    "prune_daily_files",
    "prune_ledger",
    "read_watermark",
    "rebuild_ledger_from_daily",
    "write_daily_file",
    "write_watermark",
]
