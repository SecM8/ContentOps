# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unified detection program report — one HTML for all audiences.

Correlates detection inventory, alert health, daily rollups, and
MITRE coverage into a single self-contained HTML file with
collapsible sections layered from executive (CEO/CFO) to operational
(detection engineers).
"""

from __future__ import annotations

from collections import Counter
from html import escape
from typing import Any

from contentops.alerts.daily_store import DailyRollupEntry
from contentops.alerts.detection_health import (
    DetectionHealthReport,
    DetectionHealthRow,
)
from contentops.alerts.health_snapshot import HealthDelta
from contentops.report.assemble import ReportRow, ReportSummary
from contentops.report.snapshot import ReportDelta


# ---------------------------------------------------------------------------
# Posture score
# ---------------------------------------------------------------------------


def compute_posture_score(
    summary: ReportSummary,
    health: DetectionHealthReport | None,
) -> int:
    """Compute a 0-100 security posture score from weighted inputs."""
    coverage_score = min(summary.coverage_pct, 100) * 0.30

    healthy_pct = 0.0
    tune_penalty = 0.0
    owned_pct_val = 0.0
    if health and health.total_detections > 0:
        healthy = sum(1 for r in health.rows if r.recommendation == "HEALTHY")
        tune = sum(1 for r in health.rows if r.recommendation.startswith("TUNE"))
        healthy_pct = healthy / health.total_detections * 100
        tune_penalty = min(tune / health.total_detections * 100, 100)
        owners = sum(1 for r in health.rows if r.owner != "unassigned")
        owned_pct_val = owners / health.total_detections * 100

    healthy_score = min(healthy_pct, 100) * 0.25
    owned_score = min(owned_pct_val, 100) * 0.15

    fresh_pct = 0.0
    if summary.total > 0:
        fresh_pct = 100  # placeholder — computed from rows in the CLI

    fresh_score = min(fresh_pct, 100) * 0.15
    tune_score = max(0, (100 - tune_penalty * 5)) * 0.15

    return min(100, max(0, int(coverage_score + healthy_score + owned_score + fresh_score + tune_score)))


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------


def _pill(label: str, bg: str) -> str:
    return (
        f'<span style="background:{bg}; color:#fff; padding:2px 10px; '
        f'border-radius:10px; font-size:0.8rem; font-weight:600;">'
        f'{escape(label)}</span>'
    )


def _card(title: str, value: str, subtitle: str = "", color: str = "#1a73e8") -> str:
    return (
        f'<div style="background:#fff; border-radius:8px; padding:20px; '
        f'box-shadow:0 1px 3px rgba(0,0,0,0.1); text-align:center; min-width:180px;">'
        f'<div style="font-size:2rem; font-weight:700; color:{color};">{escape(value)}</div>'
        f'<div style="font-size:0.9rem; color:#5f6368; margin-top:4px;">{escape(title)}</div>'
        f'{"<div style=font-size:0.75rem;color:#80868b;margin-top:2px;>" + escape(subtitle) + "</div>" if subtitle else ""}'
        f'</div>'
    )


def _score_gauge(score: int) -> str:
    if score >= 80:
        color = "#188038"
    elif score >= 60:
        color = "#f9ab00"
    elif score >= 40:
        color = "#e37400"
    else:
        color = "#d93025"
    return (
        f'<div style="text-align:center; margin:20px 0;">'
        f'<div style="font-size:4rem; font-weight:800; color:{color};">{score}</div>'
        f'<div style="font-size:1rem; color:#5f6368;">Security Posture Score</div>'
        f'</div>'
    )


def _section(title: str, audience: str, content: str, collapsed: bool = False) -> str:
    state = "" if not collapsed else " open"
    return (
        f'<details{state} style="margin:24px 0; border:1px solid #dadce0; border-radius:8px; overflow:hidden;">'
        f'<summary style="padding:16px 20px; background:#f8f9fa; cursor:pointer; '
        f'font-size:1.1rem; font-weight:600; display:flex; justify-content:space-between; align-items:center;">'
        f'{escape(title)}'
        f'<span style="font-size:0.75rem; color:#80868b; font-weight:400;">{escape(audience)}</span>'
        f'</summary>'
        f'<div style="padding:20px;">{content}</div>'
        f'</details>'
    )


def _table(headers: list[str], rows: list[list[str]], align: list[str] | None = None) -> str:
    if not align:
        align = ["left"] * len(headers)
    html = '<table style="width:100%; border-collapse:collapse; font-size:0.85rem; margin:16px 0;">'
    html += '<thead><tr>'
    for h, a in zip(headers, align):
        html += f'<th style="text-align:{a}; padding:8px 12px; border-bottom:2px solid #dadce0; color:#5f6368;">{escape(h)}</th>'
    html += '</tr></thead><tbody>'
    for row in rows:
        html += '<tr>'
        for cell, a in zip(row, align):
            html += f'<td style="text-align:{a}; padding:6px 12px; border-bottom:1px solid #f0f0f0;">{cell}</td>'
        html += '</tr>'
    html += '</tbody></table>'
    return html


def _rec_pill(rec: str) -> str:
    colors = {
        "TUNE": "#d93025", "CLASSIFY": "#7b1fa2", "SILENT": "#f9ab00",
        "REVIEW": "#1a73e8", "HEALTHY": "#188038", "EXPECTED_SILENT": "#80868b",
    }
    base = rec.split(" (")[0]
    bg = colors.get(base, "#80868b")
    return _pill(rec, bg)


# ---------------------------------------------------------------------------
# SVG helpers
# ---------------------------------------------------------------------------


_SERVICE_SOURCE_LABELS: dict[str, str] = {
    "microsoftDefenderForEndpoint": "Defender for Endpoint",
    "microsoftDefenderForIdentity": "Defender for Identity",
    "microsoftDefenderForOffice365": "Defender for Office 365",
    "microsoftDefenderForCloudApps": "Defender for Cloud Apps",
    "microsoftCloudAppSecurity": "Defender for Cloud Apps",
    "azureSentinel": "Microsoft Sentinel",
    "sentinel": "Microsoft Sentinel",
    "Azure Sentinel": "Microsoft Sentinel",
    "microsoftDefenderAdvancedThreatProtection": "Defender for Endpoint",
    "microsoft365Defender": "Microsoft 365 Defender",
}


def _friendly_service_source(raw: str) -> str:
    return escape(_SERVICE_SOURCE_LABELS.get(raw, raw.replace("microsoft", "Microsoft ").strip()))


def _svg_horizontal_bars(
    segments: list[tuple[str, int, str]],
    *,
    width: int = 520,
    bar_h: int = 22,
    row_h: int = 32,
) -> str:
    if not segments:
        return ""
    max_val = max(v for _, v, _ in segments) or 1
    label_x = 160
    bar_x = 170
    bar_max_w = width - bar_x - 60
    height = row_h * len(segments) + 16

    parts = [
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'style="display:block; width:100%; max-width:{width}px; height:auto;" '
        f'role="img" aria-label="Horizontal bar chart">'
    ]
    for i, (label, value, color) in enumerate(segments):
        y = 8 + i * row_h
        w = (value / max_val) * bar_max_w if value else 0
        parts.append(
            f'<text x="{label_x}" y="{y + bar_h * 0.7}" text-anchor="end" '
            f'font-size="12" fill="#5f6368">{escape(label)}</text>'
        )
        parts.append(
            f'<rect x="{bar_x}" y="{y}" width="{w:.1f}" height="{bar_h}" '
            f'fill="{color}" rx="3" />'
        )
        parts.append(
            f'<text x="{bar_x + w + 6:.1f}" y="{y + bar_h * 0.7}" '
            f'font-size="12" fill="#5f6368">{value}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def _svg_bar_sparkline(
    data: list[tuple[str, int]],
    *,
    width: int = 520,
    height: int = 100,
) -> str:
    if not data:
        return ""
    max_val = max(v for _, v in data) or 1
    n = len(data)
    pad_top = 8
    pad_bottom = 20
    chart_h = height - pad_top - pad_bottom
    bar_gap = 2
    bar_w = max(4, (width - bar_gap * n) / n)

    parts = [
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'style="display:block; width:100%; max-width:{width}px; height:auto;" '
        f'role="img" aria-label="Daily alert volume">'
    ]
    for i, (label, value) in enumerate(data):
        x = i * (bar_w + bar_gap)
        h = (value / max_val) * chart_h if value else 0
        y = pad_top + chart_h - h
        parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{h:.1f}" '
            f'fill="#1a73e8" rx="2"><title>{escape(label)}: {value}</title></rect>'
        )
        if i % max(1, n // 7) == 0 or i == n - 1:
            parts.append(
                f'<text x="{x + bar_w / 2:.1f}" y="{height - 4}" text-anchor="middle" '
                f'font-size="9" fill="#80868b">{escape(label[-5:])}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)


def _fmt_num(v: float) -> str:
    """Whole numbers without a decimal, otherwise one decimal place."""
    return f"{v:.0f}" if float(v).is_integer() else f"{v:.1f}"


def _svg_line_trend(
    data: list[tuple[str, float]],
    *,
    color: str = "#1a73e8",
    value_suffix: str = "",
    width: int = 520,
    height: int = 110,
) -> str:
    """A small line chart for a rate/duration trend over a date series.

    Each point is (date_label, value). Y-axis is labelled with the min and
    max value; the first and last dates anchor the X-axis. A single point
    renders as a lone marker (no line)."""
    if not data:
        return ""
    values = [v for _, v in data]
    vmax = max(values)
    vmin = min(values)
    span = (vmax - vmin) or 1.0
    pad_top, pad_bottom, pad_left, pad_right = 12, 22, 42, 14
    chart_w = width - pad_left - pad_right
    chart_h = height - pad_top - pad_bottom
    n = len(data)

    def _x(i: int) -> float:
        if n == 1:
            return pad_left + chart_w / 2
        return pad_left + (i / (n - 1)) * chart_w

    def _y(v: float) -> float:
        return pad_top + (1 - (v - vmin) / span) * chart_h

    parts = [
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" '
        f'style="display:block; width:100%; max-width:{width}px; height:auto;" '
        f'role="img" aria-label="Trend line">'
    ]
    # Axes (left + baseline).
    parts.append(
        f'<line x1="{pad_left}" y1="{pad_top}" x2="{pad_left}" '
        f'y2="{pad_top + chart_h}" stroke="#dadce0" stroke-width="1" />'
    )
    parts.append(
        f'<line x1="{pad_left}" y1="{pad_top + chart_h}" '
        f'x2="{width - pad_right}" y2="{pad_top + chart_h}" '
        f'stroke="#dadce0" stroke-width="1" />'
    )
    # Y-axis min/max labels.
    parts.append(
        f'<text x="{pad_left - 4}" y="{pad_top + 4}" text-anchor="end" '
        f'font-size="9" fill="#80868b">{_fmt_num(vmax)}{value_suffix}</text>'
    )
    parts.append(
        f'<text x="{pad_left - 4}" y="{pad_top + chart_h}" text-anchor="end" '
        f'font-size="9" fill="#80868b">{_fmt_num(vmin)}{value_suffix}</text>'
    )
    if n > 1:
        points = " ".join(f"{_x(i):.1f},{_y(v):.1f}" for i, (_, v) in enumerate(data))
        parts.append(
            f'<polyline points="{points}" fill="none" stroke="{color}" '
            f'stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />'
        )
    for i, (label, v) in enumerate(data):
        parts.append(
            f'<circle cx="{_x(i):.1f}" cy="{_y(v):.1f}" r="2.5" fill="{color}">'
            f'<title>{escape(label)}: {_fmt_num(v)}{value_suffix}</title></circle>'
        )
    # X-axis first / last date.
    parts.append(
        f'<text x="{pad_left}" y="{height - 6}" font-size="9" '
        f'fill="#80868b">{escape(data[0][0][-5:])}</text>'
    )
    if n > 1:
        parts.append(
            f'<text x="{width - pad_right}" y="{height - 6}" text-anchor="end" '
            f'font-size="9" fill="#80868b">{escape(data[-1][0][-5:])}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Daily-trend aggregation (from the persistent rollup store)
# ---------------------------------------------------------------------------


def _daily_fp_rate_trend(
    daily: list[DailyRollupEntry], *, days: int = 14,
) -> list[tuple[str, float]]:
    """Per-day false-positive rate (%) over the last ``days`` with classifications.

    FP-rate for a day = fp / (tp + fp + benign + undetermined) across all
    rules that day. Days with no classified alerts are skipped (no signal)."""
    fp_by_date: dict[str, int] = {}
    classified_by_date: dict[str, int] = {}
    for e in daily:
        classified = e.tp_count + e.fp_count + e.benign_count + e.undetermined_count
        if classified <= 0:
            continue
        fp_by_date[e.date] = fp_by_date.get(e.date, 0) + e.fp_count
        classified_by_date[e.date] = classified_by_date.get(e.date, 0) + classified
    dates = sorted(classified_by_date)[-days:]
    return [(d, round(fp_by_date[d] / classified_by_date[d] * 100, 1)) for d in dates]


def _daily_mttr_trend(
    daily: list[DailyRollupEntry], *, days: int = 14,
) -> list[tuple[str, float]]:
    """Per-day mean-time-to-resolve (hours), resolved-count-weighted across rules.

    Days with no resolved alerts (or no close-time data) are skipped."""
    wsum_by_date: dict[str, float] = {}
    wcnt_by_date: dict[str, int] = {}
    for e in daily:
        if e.mean_close_hours is None or e.resolved_count <= 0:
            continue
        wsum_by_date[e.date] = (
            wsum_by_date.get(e.date, 0.0) + e.mean_close_hours * e.resolved_count
        )
        wcnt_by_date[e.date] = wcnt_by_date.get(e.date, 0) + e.resolved_count
    dates = sorted(wcnt_by_date)[-days:]
    return [(d, round(wsum_by_date[d] / wcnt_by_date[d], 1)) for d in dates]


# ---------------------------------------------------------------------------
# Alerts Overview section
# ---------------------------------------------------------------------------


def _render_alerts_overview(
    health: DetectionHealthReport | None,
    daily: list[DailyRollupEntry],
    service_source_counts: dict[str, int] | None = None,
) -> str:
    if not health and not daily and not service_source_counts:
        return "<p>No alert data available. Run <code>contentops alerts sync</code> to populate the ledger.</p>"

    parts: list[str] = []

    # --- Classification breakdown ---
    if health and health.total_alerts > 0:
        total_tp = sum(r.tp_count for r in health.rows)
        total_fp = sum(r.fp_count for r in health.rows)
        total_benign = sum(r.benign_count for r in health.rows)
        total_undet = sum(r.undetermined_count for r in health.rows)
        total = total_tp + total_fp + total_benign + total_undet or 1

        def _pct(n: int) -> str:
            return f"{round(n / total * 100)}%"

        parts.append("<h3>Classification Breakdown</h3>")
        cards = [
            _card("True Positive", str(total_tp), _pct(total_tp), "#188038"),
            _card("False Positive", str(total_fp), _pct(total_fp), "#d93025"),
            _card("Benign Positive", str(total_benign), _pct(total_benign), "#f9ab00"),
            _card("Undetermined", str(total_undet), _pct(total_undet), "#80868b"),
        ]
        parts.append(
            f'<div style="display:flex; gap:12px; flex-wrap:wrap; margin:12px 0;">'
            f'{"".join(cards)}</div>'
        )

        segments = [
            ("True Positive", total_tp, "#188038"),
            ("False Positive", total_fp, "#d93025"),
            ("Benign Positive", total_benign, "#f9ab00"),
            ("Undetermined", total_undet, "#80868b"),
        ]
        bar_svg = _svg_horizontal_bars(
            [s for s in segments if s[1] > 0], width=480, bar_h=18, row_h=26,
        )
        if bar_svg:
            parts.append(f'<div style="margin:12px 0;">{bar_svg}</div>')

    # --- Daily volume trend ---
    if daily:
        volume_by_date: dict[str, int] = {}
        for e in daily:
            volume_by_date[e.date] = volume_by_date.get(e.date, 0) + e.alert_count
        sorted_dates = sorted(volume_by_date.keys())[-14:]
        if sorted_dates:
            parts.append("<h3>Daily Alert Volume (last 14 days)</h3>")
            sparkline_data = [(d, volume_by_date[d]) for d in sorted_dates]
            parts.append(
                f'<div style="margin:12px 0;">'
                f'{_svg_bar_sparkline(sparkline_data)}</div>'
            )

    # --- False-positive rate trend ---
    fp_trend = _daily_fp_rate_trend(daily) if daily else []
    if len(fp_trend) >= 2:
        parts.append("<h3>False-Positive Rate (last 14 days)</h3>")
        parts.append(
            f'<div style="margin:12px 0;">'
            f'{_svg_line_trend(fp_trend, color="#d93025", value_suffix="%")}</div>'
        )

    # --- Service source breakdown ---
    if service_source_counts:
        parts.append("<h3>Alert Sources</h3>")
        source_colors = [
            "#1a73e8", "#188038", "#e37400", "#7b1fa2",
            "#d93025", "#00897b", "#5f6368",
        ]
        sorted_sources = sorted(
            service_source_counts.items(), key=lambda kv: -kv[1],
        )
        segments = [
            (_friendly_service_source(name), count, source_colors[i % len(source_colors)])
            for i, (name, count) in enumerate(sorted_sources)
            if count > 0
        ]
        parts.append(
            f'<div style="margin:12px 0;">'
            f'{_svg_horizontal_bars(segments)}</div>'
        )

    # --- MTTR summary ---
    if health:
        weighted_sum = 0.0
        weighted_count = 0
        for r in health.rows:
            if r.mean_time_to_close_hours is not None and r.alert_count > 0:
                weighted_sum += r.mean_time_to_close_hours * r.alert_count
                weighted_count += r.alert_count
        if weighted_count > 0:
            avg_mttr = weighted_sum / weighted_count
            if avg_mttr <= 4:
                mttr_color = "#188038"
            elif avg_mttr <= 24:
                mttr_color = "#f9ab00"
            else:
                mttr_color = "#d93025"
            parts.append("<h3>Mean Time to Resolve</h3>")
            parts.append(
                f'<div style="margin:12px 0;">'
                f'{_card("Avg MTTR", f"{avg_mttr:.1f}h", f"across {weighted_count} resolved alerts", mttr_color)}'
                f'</div>'
            )

    # --- MTTR trend (day-by-day, from the rollup store) ---
    mttr_trend = _daily_mttr_trend(daily) if daily else []
    if len(mttr_trend) >= 2:
        parts.append("<h3>Resolution Time Trend (last 14 days)</h3>")
        parts.append(
            f'<div style="margin:12px 0;">'
            f'{_svg_line_trend(mttr_trend, color="#1a73e8", value_suffix="h")}</div>'
        )

    # --- Top 5 triggered detections ---
    if daily:
        volume: Counter[str] = Counter()
        for e in daily:
            volume[e.rule_display_name] += e.alert_count
        top5 = volume.most_common(5)
        if top5:
            parts.append("<h3>Top 5 Triggered Detections</h3>")
            top_rows = []
            for name, count in top5:
                top_rows.append([escape(name[:60]), str(count)])
            parts.append(_table(
                ["Detection", "Alerts"], top_rows, ["left", "right"],
            ))

    return "\n".join(parts) if parts else "<p>No alert data available.</p>"


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------


def _render_executive(
    summary: ReportSummary,
    health: DetectionHealthReport | None,
    score: int,
    delta: ReportDelta | None,
    health_delta: HealthDelta | None,
) -> str:
    parts: list[str] = []
    parts.append(_score_gauge(score))

    cards = []
    cards.append(_card("Active Detections", str(summary.production), f"{summary.coverage_pct}% MITRE coverage"))

    if health:
        healthy = sum(1 for r in health.rows if r.recommendation == "HEALTHY")
        tune = sum(1 for r in health.rows if r.recommendation.startswith("TUNE"))
        healthy_pct = round(healthy / max(health.total_detections, 1) * 100)
        cards.append(_card("Healthy", f"{healthy_pct}%", f"{tune} need tuning", "#188038" if tune == 0 else "#f9ab00"))

        owned = sum(1 for r in health.rows if r.owner != "unassigned")
        owned_pct = round(owned / max(health.total_detections, 1) * 100)
        cards.append(_card("Owner Accountability", f"{owned_pct}%", f"{owned}/{health.total_detections} have owners"))

        cards.append(_card("Alerts (30d)", str(health.total_alerts), f"{health.matched_detections} detections fired"))

    parts.append(f'<div style="display:flex; gap:16px; flex-wrap:wrap; justify-content:center; margin:20px 0;">{"".join(cards)}</div>')

    if health:
        silent_high = [r for r in health.rows if r.recommendation == "SILENT" and r.severity in ("high", "medium")]
        if silent_high:
            parts.append(
                f'<div style="background:#fce8e6; border-left:4px solid #d93025; padding:12px 16px; '
                f'border-radius:4px; margin:16px 0; font-size:0.9rem;">'
                f'<strong>Risk:</strong> {len(silent_high)} medium/high severity detection(s) '
                f'have been SILENT for 30+ days</div>'
            )

    if delta:
        delta_parts = []
        if delta.total_delta:
            delta_parts.append(f"{delta.total_delta:+d} rules")
        if delta.coverage_techniques_delta:
            delta_parts.append(f"{delta.coverage_techniques_delta:+d} techniques covered")
        if delta.new_rule_ids:
            delta_parts.append(f"{len(delta.new_rule_ids)} added")
        if delta_parts:
            parts.append(f'<div style="color:#5f6368; font-size:0.85rem; text-align:center;">Week-over-week: {" · ".join(delta_parts)}</div>')

    return "\n".join(parts)


def _render_ciso(
    summary: ReportSummary,
    health: DetectionHealthReport | None,
    rows: list[ReportRow],
) -> str:
    parts: list[str] = []

    # MITRE coverage heatmap
    tactic_data: dict[str, dict[str, int]] = {}
    for r in rows:
        for t in r.tactics:
            if t not in tactic_data:
                tactic_data[t] = {"detections": 0, "with_alerts": 0, "silent": 0}
            tactic_data[t]["detections"] += 1

    if health:
        health_by_id = {r.detection_id: r for r in health.rows}
        for r in rows:
            hr = health_by_id.get(r.rule_id)
            if hr and hr.alert_count > 0:
                for t in r.tactics:
                    if t in tactic_data:
                        tactic_data[t]["with_alerts"] += 1
            elif hr:
                for t in r.tactics:
                    if t in tactic_data:
                        tactic_data[t]["silent"] += 1

    if tactic_data:
        parts.append("<h3>MITRE ATT&CK Coverage</h3>")
        tactic_rows = []
        for tactic in sorted(tactic_data.keys()):
            d = tactic_data[tactic]
            total = d["detections"]
            active = d["with_alerts"]
            silent = d["silent"]
            if active > 0:
                status = _pill("ACTIVE", "#188038")
            elif total > 0:
                status = _pill("SILENT", "#f9ab00")
            else:
                status = _pill("GAP", "#d93025")
            tactic_rows.append([escape(tactic), str(total), str(active), str(silent), status])
        parts.append(_table(
            ["Tactic", "Detections", "Active", "Silent", "Status"],
            tactic_rows,
            ["left", "right", "right", "right", "center"],
        ))

    # Risk register
    if health:
        risks = [r for r in health.rows if r.severity in ("high", "medium") and r.recommendation in ("SILENT", "TUNE")]
        if risks:
            parts.append("<h3>Risk Register</h3>")
            risk_rows = []
            for r in sorted(risks, key=lambda x: (0 if x.recommendation.startswith("TUNE") else 1, x.detection_id)):
                risk_rows.append([
                    escape(r.display_name[:50]),
                    _pill(r.severity, "#d93025" if r.severity == "high" else "#e37400"),
                    _rec_pill(r.recommendation),
                    escape(r.owner),
                ])
            parts.append(_table(["Detection", "Severity", "Status", "Owner"], risk_rows))

    return "\n".join(parts)


def _render_soc_manager(health: DetectionHealthReport | None, daily: list[DailyRollupEntry]) -> str:
    parts: list[str] = []

    if health and health.owner_summary:
        parts.append("<h3>Owner Accountability</h3>")
        owner_rows = []
        for os in sorted(health.owner_summary.values(), key=lambda o: -o.tune_count):
            total = os.total
            healthy_pct = round(os.healthy_count / max(total, 1) * 100)
            owner_rows.append([
                escape(os.owner),
                str(total),
                f'<strong style="color:#d93025;">{os.tune_count}</strong>' if os.tune_count else "0",
                str(os.silent_count),
                str(os.review_count),
                f"{healthy_pct}%",
            ])
        parts.append(_table(
            ["Owner", "Total", "TUNE", "SILENT", "REVIEW", "Healthy %"],
            owner_rows,
            ["left", "right", "right", "right", "right", "right"],
        ))

    if daily:
        parts.append("<h3>Top 10 Noisiest Detections (by alert volume)</h3>")
        volume: Counter[str] = Counter()
        for e in daily:
            volume[e.rule_display_name] += e.alert_count
        noisy_rows = []
        for name, count in volume.most_common(10):
            noisy_rows.append([escape(name[:50]), str(count)])
        parts.append(_table(["Detection", "Total Alerts"], noisy_rows, ["left", "right"]))

    return "\n".join(parts)


def _render_operational(health: DetectionHealthReport | None) -> str:
    if not health or not health.rows:
        return "<p>No detection health data available.</p>"

    parts: list[str] = []
    parts.append("<h3>Attention Queue</h3>")

    det_rows = []
    for r in health.rows:
        if r.recommendation == "EXPECTED_SILENT":
            continue
        tp_pct = f"{r.tp_rate:.0f}%" if r.tp_rate is not None else "-"
        fp_pct = f"{r.fp_rate:.0f}%" if r.fp_rate is not None else "-"
        mttr = f"{r.mean_time_to_close_hours:.1f}h" if r.mean_time_to_close_hours else "-"
        sd = str(r.silent_days) if r.silent_days is not None else "-"
        det_rows.append([
            escape(r.display_name[:45]),
            escape(r.version),
            _pill(r.severity, {"high": "#d93025", "medium": "#e37400", "low": "#1a73e8"}.get(r.severity, "#80868b")),
            str(r.alert_count),
            tp_pct,
            fp_pct,
            mttr,
            sd,
            _rec_pill(r.recommendation),
        ])

    parts.append(_table(
        ["Detection", "Version", "Severity", "Alerts", "TP%", "FP%", "MTTR", "Silent", "Rec"],
        det_rows,
        ["left", "left", "center", "right", "right", "right", "right", "right", "center"],
    ))
    return "\n".join(parts)


def _render_threat_hunter(rows: list[ReportRow], health: DetectionHealthReport | None) -> str:
    parts: list[str] = []

    tech_count: Counter[str] = Counter()
    tech_alerts: Counter[str] = Counter()
    for r in rows:
        for t in r.techniques:
            tech_count[t] += 1

    if health:
        for hr in health.rows:
            for t in hr.mitre_techniques:
                if hr.alert_count > 0:
                    tech_alerts[t] += hr.alert_count

    if tech_count:
        parts.append("<h3>Coverage Depth by Technique</h3>")
        thin = [(t, c) for t, c in tech_count.most_common() if c <= 2]
        if thin:
            parts.append(f"<p>{len(thin)} technique(s) with thin coverage (1-2 detections):</p>")
            thin_rows = []
            for t, c in thin[:20]:
                alerts = tech_alerts.get(t, 0)
                status = _pill("ACTIVE", "#188038") if alerts > 0 else _pill("NO ALERTS", "#f9ab00")
                thin_rows.append([escape(t), str(c), str(alerts), status])
            parts.append(_table(["Technique", "Detections", "Alerts", "Status"], thin_rows, ["left", "right", "right", "center"]))

    return "\n".join(parts) if parts else "<p>No technique data available.</p>"


# ---------------------------------------------------------------------------
# Main renderer
# ---------------------------------------------------------------------------


def render_unified_html(
    rows: list[ReportRow],
    summary: ReportSummary,
    *,
    health: DetectionHealthReport | None = None,
    daily: list[DailyRollupEntry] | None = None,
    delta: ReportDelta | None = None,
    health_delta: HealthDelta | None = None,
    service_source_counts: dict[str, int] | None = None,
) -> str:
    score = compute_posture_score(summary, health)

    executive = _render_executive(summary, health, score, delta, health_delta)
    ciso = _render_ciso(summary, health, rows)
    soc_mgr = _render_soc_manager(health, daily or [])
    alerts_overview = _render_alerts_overview(health, daily or [], service_source_counts)
    operational = _render_operational(health)
    hunter = _render_threat_hunter(rows, health)

    body = (
        _section("Executive Summary", "CEO / CFO / Board", executive, collapsed=False)
        + _section("Security Posture", "CISO / Security Director", ciso, collapsed=False)
        + _section("Team Performance", "SOC Manager", soc_mgr, collapsed=False)
        + _section("Alerts Overview", "SOC Analysts / All Audiences", alerts_overview, collapsed=False)
        + _section("Detection Detail", "Detection Engineers / SOC Analysts", operational, collapsed=True)
        + _section("Threat Coverage", "Threat Hunters / Red Team", hunter, collapsed=True)
    )

    return (
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<title>Detection Program Report — ContentOps powered by SecM8</title>\n'
        '<style>\n'
        '  * { box-sizing: border-box; margin: 0; padding: 0; }\n'
        '  body { font-family: "Segoe UI", system-ui, -apple-system, sans-serif; '
        'background: #f8f9fa; color: #202124; line-height: 1.6; padding: 24px; max-width: 1200px; margin: 0 auto; }\n'
        '  h1 { font-size: 1.5rem; color: #202124; margin-bottom: 4px; }\n'
        '  h3 { font-size: 1rem; color: #202124; margin: 16px 0 8px; }\n'
        '  .subtitle { font-size: 0.85rem; color: #5f6368; margin-bottom: 24px; }\n'
        '  details > summary { list-style: none; }\n'
        '  details > summary::-webkit-details-marker { display: none; }\n'
        '  details[open] > summary { border-bottom: 1px solid #dadce0; }\n'
        '  @media print { details { open: true; } details > summary { display: none; } }\n'
        '</style>\n'
        '</head>\n<body>\n'
        f'<h1>Detection Program Report</h1>\n'
        f'<div class="subtitle">Generated {escape(summary.generated_at)} by ContentOps powered by SecM8 '
        f'· {summary.total} detections · {summary.coverage_pct}% MITRE coverage</div>\n'
        f'{body}\n'
        '</body>\n</html>\n'
    )


__all__ = [
    "compute_posture_score",
    "render_unified_html",
]
