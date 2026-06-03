# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""JSON snapshot + week-over-week delta for detection health reports.

Mirrors ``contentops.report.snapshot`` but tracks recommendation
changes rather than rule additions/removals. Committed to
``alerts-reports/YYYY-MM-DD-health.json`` so history accumulates.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from contentops.alerts.detection_health import DetectionHealthReport

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


def render_health_snapshot(report: DetectionHealthReport) -> str:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "period_days": report.period_days,
            "total_detections": report.total_detections,
            "matched_detections": report.matched_detections,
            "unmatched_alerts": report.unmatched_alerts,
            "total_alerts": report.total_alerts,
        },
        "detections": sorted(
            [
                {
                    "detection_id": r.detection_id,
                    "version": r.version,
                    "recommendation": r.recommendation,
                    "alert_count": r.alert_count,
                    "fp_rate": r.fp_rate,
                    "tp_rate": r.tp_rate,
                    "silent_days": r.silent_days,
                }
                for r in report.rows
            ],
            key=lambda d: d["detection_id"],
        ),
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


@dataclass(frozen=True)
class RecommendationChange:
    detection_id: str
    old_recommendation: str
    new_recommendation: str


@dataclass(frozen=True)
class HealthDelta:
    previous_date: str
    new_tune_ids: tuple[str, ...] = field(default_factory=tuple)
    resolved_tune_ids: tuple[str, ...] = field(default_factory=tuple)
    new_silent_ids: tuple[str, ...] = field(default_factory=tuple)
    newly_active_ids: tuple[str, ...] = field(default_factory=tuple)
    recommendation_changes: tuple[RecommendationChange, ...] = field(default_factory=tuple)


def load_health_snapshot(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.debug("could not parse health snapshot %s: %s", path, exc)
        return None
    if not isinstance(raw, dict):
        return None
    return raw


def find_previous_health_snapshot(
    reports_dir: Path, today_iso: str,
) -> Path | None:
    if not reports_dir.is_dir():
        return None
    candidates: list[Path] = []
    for p in reports_dir.glob("*-health.json"):
        stem = p.stem.replace("-health", "")
        if len(stem) != 10 or stem[4] != "-" or stem[7] != "-":
            continue
        if stem >= today_iso:
            continue
        candidates.append(p)
    if not candidates:
        return None
    candidates.sort()
    return candidates[-1]


def compute_health_delta(
    previous: dict,
    current: DetectionHealthReport,
) -> HealthDelta:
    prev_generated = previous.get("generated_at") or ""
    previous_date = prev_generated[:10] if len(prev_generated) >= 10 else "unknown"

    prev_detections = previous.get("detections", []) or []
    prev_by_id: dict[str, dict] = {}
    for d in prev_detections:
        if isinstance(d, dict) and isinstance(d.get("detection_id"), str):
            prev_by_id[d["detection_id"]] = d

    curr_by_id: dict[str, str] = {r.detection_id: r.recommendation for r in current.rows}

    new_tune: list[str] = []
    resolved_tune: list[str] = []
    new_silent: list[str] = []
    newly_active: list[str] = []
    changes: list[RecommendationChange] = []

    all_ids = set(prev_by_id.keys()) | set(curr_by_id.keys())
    for det_id in sorted(all_ids):
        old_rec = prev_by_id.get(det_id, {}).get("recommendation", "")
        new_rec = curr_by_id.get(det_id, "")

        if old_rec == new_rec:
            continue

        if new_rec and old_rec:
            changes.append(RecommendationChange(det_id, old_rec, new_rec))

        if new_rec == "TUNE" and old_rec != "TUNE":
            new_tune.append(det_id)
        elif old_rec == "TUNE" and new_rec != "TUNE":
            resolved_tune.append(det_id)

        if new_rec == "SILENT" and old_rec != "SILENT":
            new_silent.append(det_id)
        elif old_rec == "SILENT" and new_rec != "SILENT":
            newly_active.append(det_id)

    return HealthDelta(
        previous_date=previous_date,
        new_tune_ids=tuple(new_tune),
        resolved_tune_ids=tuple(resolved_tune),
        new_silent_ids=tuple(new_silent),
        newly_active_ids=tuple(newly_active),
        recommendation_changes=tuple(changes),
    )


__all__ = [
    "SCHEMA_VERSION",
    "HealthDelta",
    "RecommendationChange",
    "compute_health_delta",
    "find_previous_health_snapshot",
    "load_health_snapshot",
    "render_health_snapshot",
]
