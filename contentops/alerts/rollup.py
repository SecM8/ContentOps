# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Daily rollup computation and rendering.

Computes classification counts, MTTR, top-titles breakdown, rule
effectiveness, and still-open alerts for a single calendar date.
Renders the result as Markdown or JSON for GitHub Actions step-summary
/ workflow artefact consumption.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

from contentops.alerts.models import (
    AlertClassification,
    AlertStatus,
    NormalizedAlert,
)
from contentops.utils.markdown import gfm_cell


# ------------------------------------------------------------------
# Data structures
# ------------------------------------------------------------------


@dataclass
class ClassificationCount:
    """One row in the classification breakdown."""

    classification: AlertClassification
    count: int
    percentage: float


@dataclass
class TitleBreakdown:
    """Per-title stats in the top-titles ranking."""

    title: str
    count: int
    tp: int = 0
    fp: int = 0
    benign: int = 0
    undetermined: int = 0
    avg_close_hours: float | None = None
    mitre_techniques: list[str] = field(default_factory=list)


@dataclass
class RuleEffectiveness:
    """Alerts-per-rule with TP/FP rates."""

    rule_name: str
    total: int
    tp: int = 0
    fp: int = 0
    benign: int = 0
    undetermined: int = 0
    tp_rate: float = 0.0
    fp_rate: float = 0.0


@dataclass
class DailyRollup:
    """Aggregate stats for a single calendar date."""

    date: date
    total_alerts: int = 0
    total_resolved: int = 0
    classification_counts: list[ClassificationCount] = field(default_factory=list)
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    mean_time_to_close_hours: float | None = None
    top_titles: list[TitleBreakdown] = field(default_factory=list)
    still_open: list[NormalizedAlert] = field(default_factory=list)
    rule_effectiveness: list[RuleEffectiveness] = field(default_factory=list)


# ------------------------------------------------------------------
# Computation
# ------------------------------------------------------------------


def _close_time_hours(alert: NormalizedAlert) -> float | None:
    """Compute time-to-close in hours, or None if not resolved."""
    if alert.created is None or alert.resolved is None:
        return None
    delta = alert.resolved - alert.created
    return delta.total_seconds() / 3600.0


def compute_daily_rollup(
    alerts: list[NormalizedAlert],
    target_date: date,
) -> DailyRollup:
    """Compute the daily rollup for ``target_date``.

    Considers all alerts that were *created* on ``target_date`` (any
    timezone).
    """
    # Filter to alerts created on target_date
    day_alerts = [
        a for a in alerts
        if a.created is not None
        and a.created.date() == target_date
    ]

    rollup = DailyRollup(date=target_date)
    rollup.total_alerts = len(day_alerts)

    # Resolved count
    resolved = [a for a in day_alerts if a.status == AlertStatus.resolved]
    rollup.total_resolved = len(resolved)

    # Classification counts
    class_counter: Counter[AlertClassification] = Counter()
    for a in day_alerts:
        class_counter[a.classification] += 1

    total = rollup.total_alerts or 1  # avoid div-by-zero
    for cls in AlertClassification:
        count = class_counter.get(cls, 0)
        rollup.classification_counts.append(
            ClassificationCount(
                classification=cls,
                count=count,
                percentage=round(count / total * 100, 1),
            )
        )

    # Severity breakdown
    sev_counter: Counter[str] = Counter()
    for a in day_alerts:
        sev_counter[a.severity.value] += 1
    rollup.severity_breakdown = dict(sev_counter.most_common())

    # Mean time to close (resolved alerts only)
    close_times = [
        ct for a in resolved if (ct := _close_time_hours(a)) is not None
    ]
    if close_times:
        rollup.mean_time_to_close_hours = round(
            sum(close_times) / len(close_times), 2
        )

    # Top titles (by volume)
    title_groups: dict[str, list[NormalizedAlert]] = defaultdict(list)
    for a in day_alerts:
        title_groups[a.title].append(a)

    for title, group in sorted(
        title_groups.items(), key=lambda kv: -len(kv[1])
    ):
        tp = sum(1 for a in group if a.classification == AlertClassification.true_positive)
        fp = sum(1 for a in group if a.classification == AlertClassification.false_positive)
        benign = sum(1 for a in group if a.classification == AlertClassification.benign_positive)
        undetermined = sum(1 for a in group if a.classification == AlertClassification.undetermined)
        group_close_times = [
            ct for a in group if (ct := _close_time_hours(a)) is not None
        ]
        avg_close = (
            round(sum(group_close_times) / len(group_close_times), 2)
            if group_close_times
            else None
        )
        techniques: set[str] = set()
        for a in group:
            techniques.update(a.mitre_techniques)
        rollup.top_titles.append(
            TitleBreakdown(
                title=title,
                count=len(group),
                tp=tp,
                fp=fp,
                benign=benign,
                undetermined=undetermined,
                avg_close_hours=avg_close,
                mitre_techniques=sorted(techniques),
            )
        )

    # Still open (created on target_date, not yet resolved)
    rollup.still_open = [
        a for a in day_alerts if a.status != AlertStatus.resolved
    ]

    # Rule effectiveness
    rule_groups: dict[str, list[NormalizedAlert]] = defaultdict(list)
    for a in day_alerts:
        rule_key = a.rule_name or a.title
        rule_groups[rule_key].append(a)

    for rule_name, group in sorted(
        rule_groups.items(), key=lambda kv: -len(kv[1])
    ):
        total_rule = len(group)
        tp = sum(1 for a in group if a.classification == AlertClassification.true_positive)
        fp = sum(1 for a in group if a.classification == AlertClassification.false_positive)
        benign = sum(1 for a in group if a.classification == AlertClassification.benign_positive)
        undetermined = sum(1 for a in group if a.classification == AlertClassification.undetermined)
        rollup.rule_effectiveness.append(
            RuleEffectiveness(
                rule_name=rule_name,
                total=total_rule,
                tp=tp,
                fp=fp,
                benign=benign,
                undetermined=undetermined,
                tp_rate=round(tp / total_rule * 100, 1) if total_rule else 0.0,
                fp_rate=round(fp / total_rule * 100, 1) if total_rule else 0.0,
            )
        )

    return rollup


# ------------------------------------------------------------------
# Rendering
# ------------------------------------------------------------------


def render_rollup_markdown(rollup: DailyRollup) -> str:
    """Render a DailyRollup as a Markdown document."""
    lines: list[str] = []
    lines.append(f"# Alert Rollup -- {rollup.date.isoformat()}")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Total alerts**: {rollup.total_alerts}")
    lines.append(f"- **Resolved**: {rollup.total_resolved}")
    if rollup.mean_time_to_close_hours is not None:
        lines.append(
            f"- **Mean time to close**: {rollup.mean_time_to_close_hours:.1f}h"
        )
    lines.append("")

    # Classification breakdown
    lines.append("## Classification Breakdown")
    lines.append("")
    lines.append("| Classification | Count | % |")
    lines.append("|---|---:|---:|")
    for cc in rollup.classification_counts:
        label = cc.classification.name.replace("_", " ").title()
        lines.append(f"| {label} | {cc.count} | {cc.percentage}% |")
    lines.append("")

    # Severity breakdown
    if rollup.severity_breakdown:
        lines.append("## Severity Breakdown")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|---|---:|")
        for sev, count in rollup.severity_breakdown.items():
            lines.append(f"| {gfm_cell(sev)} | {count} |")
        lines.append("")

    # Top titles
    if rollup.top_titles:
        lines.append("## Top Titles")
        lines.append("")
        lines.append(
            "| Title | Count | TP | FP | Benign | Avg Close (h) | MITRE |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|---|")
        for t in rollup.top_titles[:20]:
            avg = f"{t.avg_close_hours:.1f}" if t.avg_close_hours is not None else "-"
            mitre = ", ".join(t.mitre_techniques[:5]) or "-"
            # Truncate long titles for table readability
            display_title = t.title[:60] + "..." if len(t.title) > 60 else t.title
            lines.append(
                f"| {gfm_cell(display_title)} | {t.count} | {t.tp} | {t.fp} | "
                f"{t.benign} | {avg} | {gfm_cell(mitre)} |"
            )
        lines.append("")

    # Rule effectiveness
    if rollup.rule_effectiveness:
        lines.append("## Rule Effectiveness")
        lines.append("")
        lines.append("| Rule | Total | TP Rate | FP Rate |")
        lines.append("|---|---:|---:|---:|")
        for r in rollup.rule_effectiveness[:20]:
            display_name = r.rule_name[:50] + "..." if len(r.rule_name) > 50 else r.rule_name
            lines.append(
                f"| {gfm_cell(display_name)} | {r.total} | {r.tp_rate}% | {r.fp_rate}% |"
            )
        lines.append("")

    # Still open
    if rollup.still_open:
        lines.append("## Still Open")
        lines.append("")
        lines.append(f"{len(rollup.still_open)} alert(s) created on "
                      f"{rollup.date.isoformat()} are not yet resolved.")
        lines.append("")

    return "\n".join(lines)


def render_rollup_json(rollup: DailyRollup) -> dict[str, Any]:
    """Render a DailyRollup as a JSON-serializable dict."""
    return {
        "date": rollup.date.isoformat(),
        "total_alerts": rollup.total_alerts,
        "total_resolved": rollup.total_resolved,
        "mean_time_to_close_hours": rollup.mean_time_to_close_hours,
        "classification_counts": {
            cc.classification.name: {
                "count": cc.count,
                "percentage": cc.percentage,
            }
            for cc in rollup.classification_counts
        },
        "severity_breakdown": rollup.severity_breakdown,
        "top_titles": [
            {
                "title": t.title,
                "count": t.count,
                "tp": t.tp,
                "fp": t.fp,
                "benign": t.benign,
                "undetermined": t.undetermined,
                "avg_close_hours": t.avg_close_hours,
                "mitre_techniques": t.mitre_techniques,
            }
            for t in rollup.top_titles
        ],
        "still_open_count": len(rollup.still_open),
        "rule_effectiveness": [
            {
                "rule_name": r.rule_name,
                "total": r.total,
                "tp_rate": r.tp_rate,
                "fp_rate": r.fp_rate,
            }
            for r in rollup.rule_effectiveness
        ],
    }


__all__ = [
    "ClassificationCount",
    "DailyRollup",
    "RuleEffectiveness",
    "TitleBreakdown",
    "compute_daily_rollup",
    "render_rollup_json",
    "render_rollup_markdown",
]
