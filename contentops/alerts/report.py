# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Multi-day trend report for alert classification, MTTR, and rule noise.

Builds on top of the daily rollup engine to produce a period-level view
covering 7, 30, or custom-range days. Output is a ``TrendReport`` that
can be rendered as Markdown or JSON.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

from contentops.alerts.models import (
    AlertClassification,
    AlertStatus,
    NormalizedAlert,
)
from contentops.alerts.rollup import _close_time_hours


# ------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------


@dataclass
class DayVolume:
    """Alert volume for a single day."""

    day: date
    total: int
    resolved: int


@dataclass
class DayClassificationRatio:
    """TP/FP ratio for a single day."""

    day: date
    tp: int
    fp: int
    benign: int
    undetermined: int
    tp_fp_ratio: float | None  # None when FP == 0


@dataclass
class DayMTTR:
    """Mean time to resolve for a single day (hours)."""

    day: date
    mttr_hours: float | None


@dataclass
class NoisyRule:
    """A rule ranked by false-positive rate over the period."""

    rule_name: str
    total: int
    fp: int
    fp_rate: float


@dataclass
class TrendReport:
    """Multi-day trend report covering ``period_days`` calendar days."""

    start_date: date
    end_date: date
    period_days: int
    total_alerts: int = 0
    daily_volumes: list[DayVolume] = field(default_factory=list)
    classification_trend: list[DayClassificationRatio] = field(default_factory=list)
    mttr_trend: list[DayMTTR] = field(default_factory=list)
    top_titles_period: list[tuple[str, int]] = field(default_factory=list)
    noisiest_rules: list[NoisyRule] = field(default_factory=list)
    unresolved_backlog: int = 0


# ------------------------------------------------------------------
# Computation
# ------------------------------------------------------------------


def compute_trend_report(
    alerts: list[NormalizedAlert],
    period_days: int,
    *,
    end_date: date | None = None,
) -> TrendReport:
    """Compute a trend report covering ``period_days`` calendar days.

    ``end_date`` defaults to today. The report covers
    ``[end_date - period_days + 1, end_date]`` inclusive.
    """
    if end_date is None:
        end_date = date.today()
    start_date = end_date - timedelta(days=period_days - 1)

    report = TrendReport(
        start_date=start_date,
        end_date=end_date,
        period_days=period_days,
    )

    # Bucket alerts by creation date
    by_day: dict[date, list[NormalizedAlert]] = defaultdict(list)
    for a in alerts:
        if a.created is not None:
            by_day[a.created.date()].append(a)

    # Collect all alerts in the period window
    period_alerts: list[NormalizedAlert] = []
    for d in range(period_days):
        day = start_date + timedelta(days=d)
        day_alerts = by_day.get(day, [])
        period_alerts.extend(day_alerts)

        resolved = [a for a in day_alerts if a.status == AlertStatus.resolved]

        # Daily volume
        report.daily_volumes.append(
            DayVolume(day=day, total=len(day_alerts), resolved=len(resolved))
        )

        # Classification ratio
        tp = sum(1 for a in day_alerts if a.classification == AlertClassification.true_positive)
        fp = sum(1 for a in day_alerts if a.classification == AlertClassification.false_positive)
        benign = sum(1 for a in day_alerts if a.classification == AlertClassification.benign_positive)
        undetermined = sum(1 for a in day_alerts if a.classification == AlertClassification.undetermined)
        ratio = round(tp / fp, 2) if fp > 0 else None
        report.classification_trend.append(
            DayClassificationRatio(
                day=day, tp=tp, fp=fp, benign=benign,
                undetermined=undetermined, tp_fp_ratio=ratio,
            )
        )

        # MTTR per day
        close_times = [
            ct for a in resolved if (ct := _close_time_hours(a)) is not None
        ]
        mttr = round(sum(close_times) / len(close_times), 2) if close_times else None
        report.mttr_trend.append(DayMTTR(day=day, mttr_hours=mttr))

    report.total_alerts = len(period_alerts)

    # Top titles across the period
    title_counter: Counter[str] = Counter()
    for a in period_alerts:
        title_counter[a.title] += 1
    report.top_titles_period = title_counter.most_common(20)

    # Noisiest rules (highest FP rate, minimum 2 alerts to avoid noise)
    rule_groups: dict[str, list[NormalizedAlert]] = defaultdict(list)
    for a in period_alerts:
        rule_key = a.rule_name or a.title
        rule_groups[rule_key].append(a)

    noisy: list[NoisyRule] = []
    for rule_name, group in rule_groups.items():
        total_rule = len(group)
        if total_rule < 2:
            continue
        fp = sum(1 for a in group if a.classification == AlertClassification.false_positive)
        if fp == 0:
            continue
        noisy.append(NoisyRule(
            rule_name=rule_name,
            total=total_rule,
            fp=fp,
            fp_rate=round(fp / total_rule * 100, 1),
        ))
    report.noisiest_rules = sorted(noisy, key=lambda r: -r.fp_rate)[:20]

    # Unresolved backlog (created in period, still not resolved)
    report.unresolved_backlog = sum(
        1 for a in period_alerts if a.status != AlertStatus.resolved
    )

    return report


# ------------------------------------------------------------------
# Rendering
# ------------------------------------------------------------------


def render_trend_markdown(report: TrendReport) -> str:
    """Render a TrendReport as a Markdown document."""
    lines: list[str] = []
    lines.append(
        f"# Alert Trend Report -- "
        f"{report.start_date.isoformat()} to {report.end_date.isoformat()}"
    )
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Period**: {report.period_days} days")
    lines.append(f"- **Total alerts**: {report.total_alerts}")
    lines.append(f"- **Unresolved backlog**: {report.unresolved_backlog}")
    lines.append("")

    # Daily volume table
    lines.append("## Daily Volume")
    lines.append("")
    lines.append("| Date | Total | Resolved |")
    lines.append("|---|---:|---:|")
    for dv in report.daily_volumes:
        lines.append(f"| {dv.day.isoformat()} | {dv.total} | {dv.resolved} |")
    lines.append("")

    # Classification trend
    lines.append("## Classification Trend")
    lines.append("")
    lines.append("| Date | TP | FP | Benign | Undetermined | TP/FP Ratio |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for ct in report.classification_trend:
        ratio = f"{ct.tp_fp_ratio:.2f}" if ct.tp_fp_ratio is not None else "-"
        lines.append(
            f"| {ct.day.isoformat()} | {ct.tp} | {ct.fp} | "
            f"{ct.benign} | {ct.undetermined} | {ratio} |"
        )
    lines.append("")

    # MTTR trend
    lines.append("## MTTR Trend")
    lines.append("")
    lines.append("| Date | MTTR (hours) |")
    lines.append("|---|---:|")
    for m in report.mttr_trend:
        mttr = f"{m.mttr_hours:.1f}" if m.mttr_hours is not None else "-"
        lines.append(f"| {m.day.isoformat()} | {mttr} |")
    lines.append("")

    # Top titles
    if report.top_titles_period:
        lines.append("## Top Titles (Period)")
        lines.append("")
        lines.append("| Title | Count |")
        lines.append("|---|---:|")
        for title, count in report.top_titles_period:
            display = title[:60] + "..." if len(title) > 60 else title
            lines.append(f"| {display} | {count} |")
        lines.append("")

    # Noisiest rules
    if report.noisiest_rules:
        lines.append("## Noisiest Rules (Highest FP Rate)")
        lines.append("")
        lines.append("| Rule | Total | FP | FP Rate |")
        lines.append("|---|---:|---:|---:|")
        for r in report.noisiest_rules:
            display = r.rule_name[:50] + "..." if len(r.rule_name) > 50 else r.rule_name
            lines.append(
                f"| {display} | {r.total} | {r.fp} | {r.fp_rate}% |"
            )
        lines.append("")

    return "\n".join(lines)


def render_trend_json(report: TrendReport) -> dict[str, Any]:
    """Render a TrendReport as a JSON-serializable dict."""
    return {
        "start_date": report.start_date.isoformat(),
        "end_date": report.end_date.isoformat(),
        "period_days": report.period_days,
        "total_alerts": report.total_alerts,
        "unresolved_backlog": report.unresolved_backlog,
        "daily_volumes": [
            {"date": dv.day.isoformat(), "total": dv.total, "resolved": dv.resolved}
            for dv in report.daily_volumes
        ],
        "classification_trend": [
            {
                "date": ct.day.isoformat(),
                "tp": ct.tp,
                "fp": ct.fp,
                "benign": ct.benign,
                "undetermined": ct.undetermined,
                "tp_fp_ratio": ct.tp_fp_ratio,
            }
            for ct in report.classification_trend
        ],
        "mttr_trend": [
            {"date": m.day.isoformat(), "mttr_hours": m.mttr_hours}
            for m in report.mttr_trend
        ],
        "top_titles_period": [
            {"title": t, "count": c} for t, c in report.top_titles_period
        ],
        "noisiest_rules": [
            {
                "rule_name": r.rule_name,
                "total": r.total,
                "fp": r.fp,
                "fp_rate": r.fp_rate,
            }
            for r in report.noisiest_rules
        ],
    }


__all__ = [
    "DayClassificationRatio",
    "DayMTTR",
    "DayVolume",
    "NoisyRule",
    "TrendReport",
    "compute_trend_report",
    "render_trend_json",
    "render_trend_markdown",
]
