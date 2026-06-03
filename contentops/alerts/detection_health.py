# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Detection health engine — maps alerts to detections and computes
per-detection performance metrics with actionable recommendations.
"""

from __future__ import annotations

import csv
import io
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

from contentops.alerts.models import AlertClassification, AlertStatus, NormalizedAlert
from contentops.core.asset import Asset
from contentops.core.handler import LoadedAsset
from contentops.utils.markdown import gfm_cell

logger = logging.getLogger(__name__)

RECOMMENDATION_ORDER = {
    "TUNE": 0,
    "CLASSIFY": 1,
    "SILENT": 2,
    "REVIEW": 3,
    "HEALTHY": 4,
    "EXPECTED_SILENT": 5,
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectionHealthRow:
    detection_id: str
    display_name: str
    asset_kind: str
    severity: str
    status: str
    mitre_techniques: tuple[str, ...]
    owner: str
    version: str = ""

    alert_count: int = 0
    tp_count: int = 0
    fp_count: int = 0
    benign_count: int = 0
    undetermined_count: int = 0

    fp_rate: float | None = None
    tp_rate: float | None = None
    mean_time_to_close_hours: float | None = None

    silent_days: int | None = None
    recommendation: str = "REVIEW"
    expected_alerts_per_day: int | None = None
    volume_ratio: float | None = None


@dataclass(frozen=True)
class OwnerSummary:
    owner: str
    total: int = 0
    tune_count: int = 0
    classify_count: int = 0
    silent_count: int = 0
    healthy_count: int = 0
    review_count: int = 0
    expected_silent_count: int = 0


@dataclass(frozen=True)
class DetectionHealthReport:
    period_days: int
    start_date: date
    end_date: date
    rows: list[DetectionHealthRow]
    total_detections: int = 0
    matched_detections: int = 0
    unmatched_alerts: int = 0
    total_alerts: int = 0
    owner_summary: dict[str, OwnerSummary] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Mapping algorithm
# ---------------------------------------------------------------------------


_MIN_SUBSTRING_LEN = 8


def _build_detection_alert_map(
    detections: list[LoadedAsset],
    alerts: list[NormalizedAlert],
) -> tuple[dict[str, list[NormalizedAlert]], int]:
    """Map alerts to detections. Returns (matched_map, unmatched_count).

    Four-tier strategy (in priority order):
    1. ARM GUID match (Sentinel relatedAnalyticRuleIds)
    2. Exact title match (Defender displayName)
    3. Alert format prefix match (Sentinel alertDisplayNameFormat)
    4. Substring containment (MITRE-prefixed names, dynamic suffixes)
    """
    title_index: dict[str, str] = {}
    arm_guid_index: dict[str, str] = {}
    prefix_index: list[tuple[str, str]] = []

    for d in detections:
        det_id = d.envelope.id
        display = (d.payload.get("displayName") or d.payload.get("DisplayName") or det_id)
        title_key = display.strip().lower()
        if title_key in title_index:
            logger.debug(
                "Duplicate displayName '%s' — first wins (%s over %s)",
                display, title_index[title_key], det_id,
            )
        else:
            title_index[title_key] = det_id

        arm = d.envelope.arm_name
        if arm:
            arm_guid_index[arm.strip().lower()] = det_id

        override = d.payload.get("alertDetailsOverride") or {}
        fmt = override.get("alertDisplayNameFormat") or ""
        if "{{" in fmt:
            prefix = fmt.split("{{")[0].strip()
            if len(prefix) >= _MIN_SUBSTRING_LEN:
                prefix_index.append((prefix.lower(), det_id))

    matched: dict[str, list[NormalizedAlert]] = defaultdict(list)
    unmatched = 0

    for alert in alerts:
        detection_id: str | None = None
        alert_title_lower = (alert.title or "").strip().lower()

        # Tier 1: ARM GUID / detectorId
        if alert.rule_id:
            raw_id = alert.rule_id.strip().lower()
            guid = raw_id.rsplit("/", 1)[-1]
            detection_id = arm_guid_index.get(guid)
            # Graph detectorId uses composite format like
            # "prefix_sentinel-GUID" where GUID may be truncated.
            if detection_id is None and "_" in raw_id:
                suffix = raw_id.rsplit("_", 1)[-1]
                if len(suffix) >= 8:
                    for arm_key, det_id in arm_guid_index.items():
                        if arm_key.startswith(suffix) or suffix.startswith(arm_key):
                            detection_id = det_id
                            break

        # Tier 2: Exact title
        if detection_id is None and alert_title_lower:
            detection_id = title_index.get(alert_title_lower)

        # Tier 3: Alert format prefix
        if detection_id is None and alert_title_lower:
            for prefix, det_id in prefix_index:
                if alert_title_lower.startswith(prefix):
                    detection_id = det_id
                    break

        # Tier 4: Substring containment (both directions)
        if detection_id is None and alert_title_lower:
            for det_display, det_id in title_index.items():
                if len(det_display) < _MIN_SUBSTRING_LEN:
                    continue
                if det_display in alert_title_lower or alert_title_lower in det_display:
                    detection_id = det_id
                    break

        if detection_id is not None:
            matched[detection_id].append(alert)
        else:
            unmatched += 1
            logger.debug("Unmatched alert: id=%s title='%s'", alert.id, alert.title)

    return dict(matched), unmatched


# ---------------------------------------------------------------------------
# Recommendation engine
# ---------------------------------------------------------------------------


def _compute_recommendation(
    alert_count: int,
    tp_count: int,
    fp_count: int,
    fp_rate: float | None,
    asset_kind: str,
    undetermined_count: int = 0,
) -> str:
    if asset_kind == Asset.SENTINEL_HUNTING.value:
        return "EXPECTED_SILENT"
    if alert_count == 0:
        return "SILENT"
    if fp_rate is not None and fp_rate > 40.0:
        return "TUNE"
    if alert_count > 5 and undetermined_count / alert_count > 0.5:
        return "CLASSIFY"
    tp_rate = (tp_count / alert_count * 100) if alert_count > 0 else 0.0
    if tp_rate > 80.0:
        return "HEALTHY"
    return "REVIEW"


# ---------------------------------------------------------------------------
# Core computation
# ---------------------------------------------------------------------------


def _close_time_hours(alert: NormalizedAlert) -> float | None:
    if alert.created is None or alert.resolved is None:
        return None
    delta = alert.resolved - alert.created
    return delta.total_seconds() / 3600.0


def _extract_expected_alerts(d: LoadedAsset) -> int | None:
    meta = d.envelope.metadata
    if meta is not None and hasattr(meta, "expectedAlertsPerDay"):
        val = meta.expectedAlertsPerDay
        if isinstance(val, int) and val >= 0:
            return val
    return None


def _extract_owner(d: LoadedAsset, owner_map: dict[str, str] | None = None) -> str:
    if owner_map:
        mapped = owner_map.get(d.envelope.id)
        if mapped and mapped != "unassigned":
            return mapped
    meta = d.envelope.metadata
    if meta is not None and hasattr(meta, "owner") and meta.owner:
        return meta.owner
    return "unassigned"


def _extract_severity(d: LoadedAsset) -> str:
    meta = d.envelope.metadata
    if meta is not None and hasattr(meta, "severity") and meta.severity:
        return meta.severity
    sev = d.payload.get("severity") or d.payload.get("Severity")
    if sev:
        return str(sev).lower()
    action = d.payload.get("detectionAction") or {}
    template = action.get("alertTemplate") or {}
    sev = template.get("severity")
    if sev:
        return str(sev).lower()
    return "unknown"


def _extract_techniques(d: LoadedAsset) -> tuple[str, ...]:
    meta = d.envelope.metadata
    if meta is not None and hasattr(meta, "techniques") and meta.techniques:
        return tuple(meta.techniques)
    techs = d.payload.get("techniques") or []
    return tuple(techs)


def compute_detection_health(
    detections: list[LoadedAsset],
    alerts: list[NormalizedAlert],
    period_days: int,
    *,
    end_date: date | None = None,
    owner_map: dict[str, str] | None = None,
) -> DetectionHealthReport:
    if end_date is None:
        end_date = date.today()
    start_date = end_date - timedelta(days=period_days - 1)

    alert_map, unmatched = _build_detection_alert_map(detections, alerts)

    rows: list[DetectionHealthRow] = []
    matched_count = 0
    now = datetime.now(timezone.utc)

    for d in detections:
        det_id = d.envelope.id
        det_alerts = alert_map.get(det_id, [])
        alert_count = len(det_alerts)

        if alert_count > 0:
            matched_count += 1

        tp = sum(1 for a in det_alerts if a.classification == AlertClassification.true_positive)
        fp = sum(1 for a in det_alerts if a.classification == AlertClassification.false_positive)
        benign = sum(1 for a in det_alerts if a.classification == AlertClassification.benign_positive)
        undetermined = sum(1 for a in det_alerts if a.classification == AlertClassification.undetermined)

        fp_rate = round(fp / alert_count * 100, 1) if alert_count > 0 else None
        tp_rate = round(tp / alert_count * 100, 1) if alert_count > 0 else None

        close_times = [ct for a in det_alerts if (ct := _close_time_hours(a)) is not None]
        mttr = round(sum(close_times) / len(close_times), 2) if close_times else None

        silent_days: int | None = None
        if alert_count == 0:
            silent_days = period_days
        else:
            latest_created = max(
                (a.created for a in det_alerts if a.created is not None),
                default=None,
            )
            if latest_created is not None:
                delta_days = (now - latest_created).days
                silent_days = delta_days if delta_days > 0 else None

        display_name = (
            d.payload.get("displayName")
            or d.payload.get("DisplayName")
            or det_id
        )

        rec = _compute_recommendation(
            alert_count, tp, fp, fp_rate, d.envelope.asset.value,
            undetermined_count=undetermined,
        )

        expected = _extract_expected_alerts(d)
        vol_ratio: float | None = None
        if expected is not None and expected > 0 and period_days > 0:
            actual_per_day = alert_count / period_days
            vol_ratio = round(actual_per_day / expected, 2)
            if vol_ratio < 0.1 and alert_count > 0:
                rec += " (LOW VOLUME)"
            elif vol_ratio > 5.0:
                rec += " (HIGH VOLUME)"

        rows.append(DetectionHealthRow(
            detection_id=det_id,
            display_name=display_name,
            asset_kind=d.envelope.asset.value,
            severity=_extract_severity(d),
            status=d.envelope.status,
            mitre_techniques=_extract_techniques(d),
            owner=_extract_owner(d, owner_map),
            version=d.envelope.version,
            alert_count=alert_count,
            tp_count=tp,
            fp_count=fp,
            benign_count=benign,
            undetermined_count=undetermined,
            fp_rate=fp_rate,
            tp_rate=tp_rate,
            mean_time_to_close_hours=mttr,
            silent_days=silent_days,
            recommendation=rec,
            expected_alerts_per_day=expected,
            volume_ratio=vol_ratio,
        ))

    rows.sort(key=lambda r: (RECOMMENDATION_ORDER.get(r.recommendation, 99), r.detection_id))
    owner_summary = _compute_owner_summary(rows)

    return DetectionHealthReport(
        period_days=period_days,
        start_date=start_date,
        end_date=end_date,
        rows=rows,
        total_detections=len(detections),
        matched_detections=matched_count,
        unmatched_alerts=unmatched,
        total_alerts=len(alerts),
        owner_summary=owner_summary,
    )


# ---------------------------------------------------------------------------
# Owner summary
# ---------------------------------------------------------------------------


def _compute_owner_summary(rows: list[DetectionHealthRow]) -> dict[str, OwnerSummary]:
    groups: dict[str, list[DetectionHealthRow]] = defaultdict(list)
    for r in rows:
        groups[r.owner].append(r)

    result: dict[str, OwnerSummary] = {}
    for owner, group in sorted(groups.items()):
        result[owner] = OwnerSummary(
            owner=owner,
            total=len(group),
            tune_count=sum(1 for r in group if r.recommendation == "TUNE"),
            classify_count=sum(1 for r in group if r.recommendation == "CLASSIFY"),
            silent_count=sum(1 for r in group if r.recommendation == "SILENT"),
            healthy_count=sum(1 for r in group if r.recommendation == "HEALTHY"),
            review_count=sum(1 for r in group if r.recommendation == "REVIEW"),
            expected_silent_count=sum(1 for r in group if r.recommendation == "EXPECTED_SILENT"),
        )
    return result


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def render_health_markdown(report: DetectionHealthReport) -> str:
    lines: list[str] = []
    lines.append(f"# Detection Health Report -- {report.end_date.isoformat()}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Period**: {report.period_days} days ({report.start_date.isoformat()} to {report.end_date.isoformat()})")
    lines.append(f"- **Detections**: {report.total_detections} ({report.matched_detections} matched, {report.total_detections - report.matched_detections} silent)")
    lines.append(f"- **Alerts**: {report.total_alerts} ({report.unmatched_alerts} unmatched)")

    rec_counts: dict[str, int] = defaultdict(int)
    for r in report.rows:
        rec_counts[r.recommendation] += 1
    rec_parts = []
    for rec in ("TUNE", "CLASSIFY", "SILENT", "REVIEW", "HEALTHY", "EXPECTED_SILENT"):
        if rec_counts.get(rec, 0) > 0:
            rec_parts.append(f"{rec_counts[rec]} {rec}")
    lines.append(f"- **Recommendations**: {' · '.join(rec_parts)}")
    lines.append("")

    # Owner summary
    if report.owner_summary:
        lines.append("## Owner Summary")
        lines.append("")
        lines.append("| Owner | Total | TUNE | SILENT | REVIEW | HEALTHY |")
        lines.append("|---|---:|---:|---:|---:|---:|")
        for os in report.owner_summary.values():
            lines.append(
                f"| {gfm_cell(os.owner)} | {os.total} | {os.tune_count} | "
                f"{os.silent_count} | {os.review_count} | {os.healthy_count} |"
            )
        lines.append("")

    # TUNE detections
    tune_rows = [r for r in report.rows if r.recommendation == "TUNE"]
    if tune_rows:
        lines.append("## Detections Needing Attention")
        lines.append("")
        lines.append("### TUNE (FP rate > 40%)")
        lines.append("")
        lines.append("| Detection | FP Rate | Alerts | TP | FP | Owner |")
        lines.append("|---|---:|---:|---:|---:|---|")
        for r in tune_rows:
            fp = f"{r.fp_rate:.0f}%" if r.fp_rate is not None else "-"
            name = r.display_name[:60] + "..." if len(r.display_name) > 60 else r.display_name
            lines.append(f"| {gfm_cell(name)} | {fp} | {r.alert_count} | {r.tp_count} | {r.fp_count} | {gfm_cell(r.owner)} |")
        lines.append("")

    # SILENT detections
    silent_rows = [r for r in report.rows if r.recommendation == "SILENT"]
    if silent_rows:
        if not tune_rows:
            lines.append("## Detections Needing Attention")
            lines.append("")
        lines.append("### SILENT (0 alerts in period)")
        lines.append("")
        lines.append("| Detection | Silent Days | Severity | Owner |")
        lines.append("|---|---:|---|---|")
        for r in silent_rows:
            sd = str(r.silent_days) if r.silent_days is not None else "-"
            name = r.display_name[:60] + "..." if len(r.display_name) > 60 else r.display_name
            lines.append(f"| {gfm_cell(name)} | {sd} | {gfm_cell(r.severity)} | {gfm_cell(r.owner)} |")
        lines.append("")

    # All detections table
    lines.append("## All Detections")
    lines.append("")
    lines.append("| Detection | Version | Severity | Alerts | TP% | FP% | MTTR (h) | Silent Days | Rec |")
    lines.append("|---|---|---|---:|---:|---:|---:|---:|---|")
    for r in report.rows:
        tp_pct = f"{r.tp_rate:.0f}" if r.tp_rate is not None else "-"
        fp_pct = f"{r.fp_rate:.0f}" if r.fp_rate is not None else "-"
        mttr = f"{r.mean_time_to_close_hours:.1f}" if r.mean_time_to_close_hours is not None else "-"
        sd = str(r.silent_days) if r.silent_days is not None else "-"
        name = r.display_name[:50] + "..." if len(r.display_name) > 50 else r.display_name
        lines.append(
            f"| {gfm_cell(name)} | {gfm_cell(r.version)} | {gfm_cell(r.severity)} | {r.alert_count} | "
            f"{tp_pct} | {fp_pct} | {mttr} | {sd} | {gfm_cell(r.recommendation)} |"
        )
    lines.append("")

    return "\n".join(lines)


def render_health_json(report: DetectionHealthReport) -> dict[str, Any]:
    return {
        "period_days": report.period_days,
        "start_date": report.start_date.isoformat(),
        "end_date": report.end_date.isoformat(),
        "total_detections": report.total_detections,
        "matched_detections": report.matched_detections,
        "unmatched_alerts": report.unmatched_alerts,
        "total_alerts": report.total_alerts,
        "owner_summary": {
            owner: {
                "total": os.total,
                "tune": os.tune_count,
                "silent": os.silent_count,
                "review": os.review_count,
                "healthy": os.healthy_count,
                "expected_silent": os.expected_silent_count,
            }
            for owner, os in report.owner_summary.items()
        },
        "detections": [
            {
                "detection_id": r.detection_id,
                "display_name": r.display_name,
                "asset_kind": r.asset_kind,
                "severity": r.severity,
                "status": r.status,
                "mitre_techniques": list(r.mitre_techniques),
                "owner": r.owner,
                "version": r.version,
                "alert_count": r.alert_count,
                "tp_count": r.tp_count,
                "fp_count": r.fp_count,
                "benign_count": r.benign_count,
                "undetermined_count": r.undetermined_count,
                "fp_rate": r.fp_rate,
                "tp_rate": r.tp_rate,
                "mean_time_to_close_hours": r.mean_time_to_close_hours,
                "silent_days": r.silent_days,
                "recommendation": r.recommendation,
                "expected_alerts_per_day": r.expected_alerts_per_day,
                "volume_ratio": r.volume_ratio,
            }
            for r in report.rows
        ],
    }


def render_health_csv(report: DetectionHealthReport) -> str:
    buf = io.StringIO()
    fieldnames = [
        "detection_id", "display_name", "asset_kind", "severity", "status",
        "owner", "version", "alert_count", "tp_count", "fp_count", "benign_count",
        "undetermined_count", "fp_rate", "tp_rate", "mean_time_to_close_hours",
        "silent_days", "recommendation", "expected_alerts_per_day",
        "volume_ratio", "mitre_techniques",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for r in report.rows:
        writer.writerow({
            "detection_id": r.detection_id,
            "display_name": r.display_name,
            "asset_kind": r.asset_kind,
            "severity": r.severity,
            "status": r.status,
            "owner": r.owner,
            "version": r.version,
            "expected_alerts_per_day": r.expected_alerts_per_day,
            "volume_ratio": r.volume_ratio,
            "alert_count": r.alert_count,
            "tp_count": r.tp_count,
            "fp_count": r.fp_count,
            "benign_count": r.benign_count,
            "undetermined_count": r.undetermined_count,
            "fp_rate": r.fp_rate,
            "tp_rate": r.tp_rate,
            "mean_time_to_close_hours": r.mean_time_to_close_hours,
            "silent_days": r.silent_days,
            "recommendation": r.recommendation,
            "mitre_techniques": ";".join(r.mitre_techniques),
        })
    return buf.getvalue()


__all__ = [
    "DetectionHealthReport",
    "DetectionHealthRow",
    "OwnerSummary",
    "compute_detection_health",
    "render_health_csv",
    "render_health_json",
    "render_health_markdown",
]
