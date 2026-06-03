# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""HTML renderer for the detection inventory report.

Single self-contained file: embedded ``<style>`` block, embedded
vanilla-JS sort handler, no external dependencies. Looks like
something a SOC lead would actually open and read.

Design choices:

* Zero JS framework. ~40 lines of vanilla JS handles sort + filter.
  Adding Jinja2 / Chart.js / D3 for a single static page would balloon
  the dependency surface and break the "open the file in any browser"
  contract.
* Color-coded status pills + severity pills (matches Defender XDR /
  Sentinel visual conventions so the SOC lead doesn't have to context-
  switch).
* All HTML/text values are escaped via :func:`html.escape` because
  ``payload.displayName`` is operator-authored content that historically
  contains apostrophes, ampersands, and the occasional angle bracket.
"""

from __future__ import annotations

from html import escape
from typing import Iterable

from contentops.report.assemble import ReportRow, ReportSummary


# Friendly display labels for asset kinds. The internal enum values
# ("defender_custom_detection") are taxonomy keys -- functional but
# clunky in a SOC-lead-facing table. These labels are what shows up
# in the report; the underlying enum is unchanged.
_ASSET_KIND_LABELS = {
    "sentinel_analytic": "Sentinel Analytic",
    "sentinel_hunting": "Sentinel Hunting",
    "sentinel_parser": "Sentinel Parser",
    "sentinel_watchlist": "Sentinel Watchlist",
    "sentinel_data_connector": "Sentinel Data Connector",
    "defender_custom_detection": "Defender XDR Custom Detection",
}


def _spaced_tactic(value: str) -> str:
    """Split a PascalCase tactic into "Spaced Words": InitialAccess
    -> "Initial Access". Single-word tactics pass through unchanged.
    Tactics ship in PascalCase in envelopes; the report renders them
    with spaces for human reading. The values still match the
    canonical ATT&CK names."""
    if not value or not value[0].isupper():
        return value
    result = [value[0]]
    for ch in value[1:]:
        if ch.isupper():
            result.append(" ")
        result.append(ch)
    return "".join(result)


def _friendly_kind(kind: str) -> str:
    return _ASSET_KIND_LABELS.get(kind, kind)


# attack.mitre.org link template for technique IDs in the report.
# T1059 -> https://attack.mitre.org/techniques/T1059/
# T1059.001 -> https://attack.mitre.org/techniques/T1059/001/
def _attack_url(technique_id: str) -> str:
    if "." in technique_id:
        parent, sub = technique_id.split(".", 1)
        return f"https://attack.mitre.org/techniques/{parent}/{sub}/"
    return f"https://attack.mitre.org/techniques/{technique_id}/"


_STYLE = """\
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
       margin: 0; padding: 0 2rem 2rem; color: #1a1a1a; background: #fafafa; }
h1 { font-weight: 600; margin: 1.5rem 0 0.25rem; }
.subtitle { color: #666; font-size: 0.9rem; margin-bottom: 1.5rem; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
           gap: 1rem; margin: 1rem 0 1.5rem; }
.card { background: white; padding: 1rem 1.25rem; border-radius: 8px;
        border: 1px solid #e5e5e5; }
.card .label { color: #888; font-size: 0.75rem; text-transform: uppercase;
               letter-spacing: 0.05em; margin-bottom: 0.25rem; }
.card .value { font-size: 1.5rem; font-weight: 600; }
.card .value.green { color: #1f8e3c; }
.card .value.amber { color: #b66100; }
.card .value.red   { color: #c62828; }
.controls { margin-bottom: 0.75rem; }
.controls input { padding: 0.4rem 0.65rem; font-size: 0.9rem; border: 1px solid #d0d0d0;
                  border-radius: 6px; width: 280px; }
table { width: 100%; background: white; border-collapse: collapse;
        border: 1px solid #e5e5e5; border-radius: 8px; overflow: hidden;
        font-size: 0.875rem; }
thead th { background: #f4f4f4; padding: 0.6rem 0.75rem; text-align: left;
           font-weight: 600; cursor: pointer; user-select: none;
           border-bottom: 1px solid #e5e5e5; white-space: nowrap; }
thead th:hover { background: #ececec; }
thead th.sorted-asc::after  { content: " \\25B2"; color: #888; }
thead th.sorted-desc::after { content: " \\25BC"; color: #888; }
tbody td { padding: 0.55rem 0.75rem; border-bottom: 1px solid #f0f0f0;
           vertical-align: top; }
tbody tr:hover { background: #fafafa; }
.pill { display: inline-block; padding: 0.1rem 0.55rem; border-radius: 999px;
        font-size: 0.75rem; font-weight: 500; }
.pill.status-production    { background: #d9efe1; color: #1f6b35; }
.pill.status-experimental  { background: #fcecd3; color: #815614; }
.pill.status-deprecated    { background: #e6e6e6; color: #555; }
.pill.status-test          { background: #d8e6f7; color: #1e3f6b; }
.pill.sev-high             { background: #f8d4d4; color: #861a1a; }
.pill.sev-medium           { background: #fcecd3; color: #815614; }
.pill.sev-low              { background: #fff6cc; color: #6b5b1a; }
.pill.sev-informational    { background: #e0e0e0; color: #555; }
.mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
.muted { color: #888; }
footer { margin-top: 2rem; color: #666; font-size: 0.8rem; }
.exec-summary { background: linear-gradient(135deg, #f5f7fb, #ffffff);
                border: 1px solid #d9dee8; border-radius: 10px;
                padding: 1.25rem 1.5rem; margin: 1.25rem 0 0.5rem;
                box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
.exec-summary .exec-label { color: #888; font-size: 0.7rem;
                            text-transform: uppercase; letter-spacing: 0.08em;
                            margin-bottom: 0.4rem; }
.exec-summary .exec-tldr { margin: 0; font-size: 1rem; line-height: 1.55;
                           color: #222; }
.exec-summary strong { color: #1a73e8; }
.exec-summary .delta { display: inline-block; margin-left: 0.5rem;
                       padding: 0.05rem 0.45rem; border-radius: 4px;
                       background: #eef3fa; color: #1a3a6b;
                       font-size: 0.85rem; font-weight: 500; }
.chart-block { background: white; border: 1px solid #e5e5e5;
               border-radius: 8px; padding: 1rem 1.25rem;
               margin: 0.5rem 0 1.25rem; }
.chart-block .chart-title { color: #888; font-size: 0.75rem;
                            text-transform: uppercase;
                            letter-spacing: 0.05em;
                            margin-bottom: 0.75rem; }
.sev-chart { display: block; width: 100%; height: auto; max-width: 720px; }
@media print {
  body { background: white; padding: 0 0.5rem; }
  .controls { display: none; }
  thead th { cursor: default; }
  .card, .exec-summary { break-inside: avoid; box-shadow: none; }
  table { font-size: 0.8rem; }
  tr { break-inside: avoid; }
}
"""

_SCRIPT = """\
(function () {
  const table = document.querySelector('table.report');
  if (!table) return;
  const headers = table.querySelectorAll('thead th');
  const tbody = table.querySelector('tbody');
  let sortState = { idx: null, dir: null };

  function compare(a, b, idx) {
    const av = a.children[idx].dataset.sortKey ?? a.children[idx].textContent;
    const bv = b.children[idx].dataset.sortKey ?? b.children[idx].textContent;
    const anum = parseFloat(av);
    const bnum = parseFloat(bv);
    if (!isNaN(anum) && !isNaN(bnum)) return anum - bnum;
    return av.localeCompare(bv);
  }

  headers.forEach((th, idx) => th.addEventListener('click', () => {
    headers.forEach(h => h.classList.remove('sorted-asc', 'sorted-desc'));
    const dir = (sortState.idx === idx && sortState.dir === 'asc') ? 'desc' : 'asc';
    sortState = { idx, dir };
    th.classList.add(dir === 'asc' ? 'sorted-asc' : 'sorted-desc');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort((a, b) => compare(a, b, idx) * (dir === 'asc' ? 1 : -1));
    rows.forEach(r => tbody.appendChild(r));
  }));

  const filter = document.querySelector('input.filter');
  if (filter) filter.addEventListener('input', () => {
    const q = filter.value.toLowerCase();
    tbody.querySelectorAll('tr').forEach(tr => {
      tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });
})();
"""


def _status_pill(status: str) -> str:
    classes = f"pill status-{escape(status)}"
    return f'<span class="{classes}">{escape(status)}</span>'


def _severity_pill(severity: str) -> str:
    classes = f"pill sev-{escape(severity)}"
    return f'<span class="{classes}">{escape(severity)}</span>'


def _date_cell(value: str | None) -> str:
    """Render a date column. Sort key kept as the raw ISO string so
    column sort is chronological regardless of display formatting."""
    if not value:
        return '<span class="muted">—</span>'
    short = value[:10]  # YYYY-MM-DD prefix
    return f'<span class="mono" data-sort-key="{escape(value)}">{escape(short)}</span>'


def _list_cell(items: Iterable[str]) -> str:
    items = list(items)
    if not items:
        return '<span class="muted">—</span>'
    return ", ".join(escape(i) for i in items)


def _tactics_cell(items: Iterable[str]) -> str:
    items = list(items)
    if not items:
        return '<span class="muted">—</span>'
    return ", ".join(escape(_spaced_tactic(i)) for i in items)


def _techniques_cell(items: Iterable[str]) -> str:
    """Render technique IDs as hyperlinks to attack.mitre.org."""
    items = list(items)
    if not items:
        return '<span class="muted">—</span>'
    return ", ".join(
        f'<a href="{_attack_url(i)}" target="_blank" '
        f'class="mono" style="color: #1a73e8; text-decoration: none;">'
        f"{escape(i)}</a>"
        for i in items
    )


def _summary_card(label: str, value: str, klass: str = "") -> str:
    value_class = f"value {klass}".strip()
    return (
        f'<div class="card"><div class="label">{escape(label)}</div>'
        f'<div class="{value_class}">{value}</div></div>'
    )


def _coverage_klass(pct: int) -> str:
    if pct < 40:
        return "red"
    if pct < 60:
        return "amber"
    return "green"


def _has_live_data(rows: list[ReportRow]) -> bool:
    """True iff any row has any live-enrichment field populated.

    Used to decide whether to render the extra columns. Adopters
    running ``contentops report`` without ``--with-telemetry`` see
    the static-only column set; adopters with telemetry / health /
    schema-drift see the full table without cluttering the static
    case with empty cells.
    """
    return any(
        r.alerts_30d is not None
        or r.effectiveness_score is not None
        or r.data_source_healthy is not None
        or r.schema_drift_columns
        or r.alert_recommendation is not None
        for r in rows
    )


def _score_cell(score: float | None) -> str:
    if score is None:
        return '<span class="muted">—</span>'
    klass = "green" if score >= 0 else "red"
    return (
        f'<span class="value {klass}" style="font-size: 0.875rem" '
        f'data-sort-key="{score}">{score:g}</span>'
    )


def _health_cell(healthy: bool | None) -> str:
    if healthy is None:
        return '<span class="muted">—</span>'
    if healthy:
        return '<span class="pill status-production" data-sort-key="1">healthy</span>'
    return '<span class="pill sev-high" data-sort-key="0">no data</span>'


def _drift_cell(drift: tuple[str, ...]) -> str:
    if not drift:
        return '<span class="muted">—</span>'
    return (
        '<span class="pill sev-medium">unknown table: '
        + ", ".join(escape(t) for t in drift)
        + "</span>"
    )


def _recommendation_pill(rec: str | None) -> str:
    if rec is None:
        return '<span class="muted">—</span>'
    color_map = {
        "TUNE": "#d93025",
        "CLASSIFY": "#7b1fa2",
        "SILENT": "#f9ab00",
        "REVIEW": "#1a73e8",
        "HEALTHY": "#188038",
        "EXPECTED_SILENT": "#80868b",
    }
    bg = color_map.get(rec, "#80868b")
    return (
        f'<span style="background:{bg}; color:#fff; padding:2px 8px; '
        f'border-radius:8px; font-size:0.75rem; font-weight:600;">'
        f'{escape(rec)}</span>'
    )


def _severity_chart(rows: list[ReportRow]) -> str:
    """Render an inline-SVG horizontal bar chart of detections per severity.

    Four bars, same colour palette as the .pill.sev-* classes elsewhere
    in the report so the chart and the per-row pills read consistently.
    Zero external dependencies; the chart works in any browser, offline,
    and prints cleanly.

    Empty rows -> empty chart block (suppressed entirely).
    """
    if not rows:
        return ""

    order = ("high", "medium", "low", "informational")
    colors = {
        "high": "#c62828",
        "medium": "#b66100",
        "low": "#a08400",
        "informational": "#777",
    }
    counts: dict[str, int] = {s: 0 for s in order}
    for r in rows:
        sev = (r.severity or "informational").lower()
        if sev not in counts:
            sev = "informational"
        counts[sev] += 1

    max_count = max(counts.values()) or 1
    # Layout (SVG user units):
    #   width 640, bar-row 32, label gutter 110, right gutter 60 (for value labels)
    bar_h = 22
    row_h = 32
    label_x = 110
    bar_x = 120
    chart_w = 640
    bar_max_w = chart_w - bar_x - 70
    height = row_h * len(order) + 16

    svg_parts: list[str] = []
    svg_parts.append(
        f'<svg viewBox="0 0 {chart_w} {height}" '
        f'xmlns="http://www.w3.org/2000/svg" class="sev-chart" '
        f'role="img" aria-label="Detections by severity">'
    )
    for i, sev in enumerate(order):
        count = counts[sev]
        y = 8 + i * row_h
        w = (count / max_count) * bar_max_w if count else 0
        svg_parts.append(
            f'<text x="{label_x}" y="{y + bar_h * 0.7}" '
            f'text-anchor="end" font-size="13" fill="#1a1a1a" '
            f'style="text-transform: capitalize">{sev}</text>'
        )
        svg_parts.append(
            f'<rect x="{bar_x}" y="{y}" width="{w:.1f}" height="{bar_h}" '
            f'fill="{colors[sev]}" rx="3" />'
        )
        svg_parts.append(
            f'<text x="{bar_x + w + 6:.1f}" y="{y + bar_h * 0.7}" '
            f'font-size="13" fill="#555">{count}</text>'
        )
    svg_parts.append("</svg>")
    chart_svg = "".join(svg_parts)
    return (
        '<div class="chart-block">'
        '<div class="chart-title">Severity distribution</div>'
        f"{chart_svg}"
        "</div>"
    )


def _delta_phrase(delta) -> str:
    """Render the week-over-week delta as a one-line phrase appended
    to the executive summary. Returns "" when no previous snapshot
    was available."""
    if delta is None:
        return ""
    parts: list[str] = []

    def _signed(n: int, label: str) -> str:
        if n == 0:
            return ""
        sign = "+" if n > 0 else ""
        return f"{sign}{n} {label}"

    total_phrase = _signed(delta.total_delta, "rules")
    if total_phrase:
        parts.append(total_phrase)
    cov_phrase = _signed(
        delta.coverage_techniques_delta, "techniques covered",
    )
    if cov_phrase:
        parts.append(cov_phrase)
    sub_phrase = _signed(
        delta.coverage_sub_techniques_delta, "sub-techniques covered",
    )
    if sub_phrase:
        parts.append(sub_phrase)
    if not parts:
        parts.append("no portfolio change")
    return (
        f' <span class="delta">Since {escape(delta.previous_date)}: '
        + escape(" · ".join(parts))
        + "</span>"
    )


def _exec_summary_block(
    rows: list[ReportRow],
    summary: ReportSummary,
    delta=None,
) -> str:
    """One-paragraph executive TL;DR for the CFO at the top of the
    report. Pulled from the assembled data so it's always honest /
    auto-updated; no hand-written marketing.

    Surfaces:

    * Total active detections (\"production\" status)
    * MITRE technique coverage % against the full Enterprise matrix
    * Owner accountability (% of rules with metadata.owner)
    * Review freshness (% reviewed in the last 90 days, when a date is set)
    * Retirement candidates (rules with effectiveness_score < 0 when
      telemetry is loaded)
    """
    from datetime import date as _date, datetime as _datetime
    active = summary.production
    coverage_pct = summary.coverage_pct
    owned = sum(1 for r in rows if r.owner)
    owned_pct = round(100 * owned / len(rows)) if rows else 0

    # Recently reviewed: last_review_date within 90 days of today.
    today = _date.today()
    fresh = 0
    has_dates = 0
    for r in rows:
        if not r.last_review_date:
            continue
        try:
            d = _date.fromisoformat(r.last_review_date[:10])
        except ValueError:
            continue
        has_dates += 1
        if (today - d).days <= 90:
            fresh += 1
    fresh_pct = round(100 * fresh / has_dates) if has_dates else 0

    # Retirement candidates -- only meaningful when telemetry was loaded.
    retire = sum(
        1 for r in rows
        if r.effectiveness_score is not None and r.effectiveness_score < 0
    )

    tldr = (
        f"<strong>{active}</strong> active detections covering "
        f"<strong>{coverage_pct}%</strong> of the MITRE ATT&amp;CK "
        f"Enterprise technique matrix. "
        f"<strong>{owned_pct}%</strong> have a named owner; "
        f"<strong>{fresh_pct}%</strong> were reviewed in the last 90 days."
    )
    if retire > 0:
        tldr += f" <strong>{retire}</strong> rules flagged as retirement candidates."

    delta_phrase = _delta_phrase(delta)

    return (
        '<div class="exec-summary">'
        '<div class="exec-label">Executive summary</div>'
        f'<p class="exec-tldr">{tldr}{delta_phrase}</p>'
        "</div>"
    )


def render_html(
    rows: list[ReportRow],
    summary: ReportSummary,
    *,
    delta=None,
) -> str:
    """Return the complete HTML document body.

    ``delta`` is an optional :class:`contentops.report.snapshot.ReportDelta`
    -- when present, the exec-summary block grows a one-line
    "Since <date>: +N rules · ..." appendix.
    """
    cards = [
        _summary_card("Total detections", str(summary.total)),
        _summary_card("Production", str(summary.production), "green"),
        _summary_card("Experimental", str(summary.experimental), "amber"),
        _summary_card("Deprecated", str(summary.deprecated), "muted"),
    ]
    # Three-level MITRE cards when the new structured shape is available.
    # Falls back to the single legacy card if a caller built a
    # ReportSummary with only the old fields (defensive).
    if summary.coverage_tactics_total > 0:
        cards.append(_summary_card(
            "Tactic coverage",
            f"{summary.coverage_tactics_pct}% "
            f'<span class="muted" style="font-size: 0.65em;">'
            f"({summary.coverage_tactics_covered}/"
            f"{summary.coverage_tactics_total})</span>",
            _coverage_klass(summary.coverage_tactics_pct),
        ))
    cards.append(_summary_card(
        "Technique coverage",
        f"{summary.coverage_pct}% "
        f'<span class="muted" style="font-size: 0.65em;">'
        f"({summary.coverage_covered}/{summary.coverage_total})</span>",
        _coverage_klass(summary.coverage_pct),
    ))
    if summary.coverage_sub_techniques_total > 0:
        cards.append(_summary_card(
            "Sub-technique coverage",
            f"{summary.coverage_sub_techniques_pct}% "
            f'<span class="muted" style="font-size: 0.65em;">'
            f"({summary.coverage_sub_techniques_covered}/"
            f"{summary.coverage_sub_techniques_total})</span>",
            _coverage_klass(summary.coverage_sub_techniques_pct),
        ))
    if _has_live_data(rows):
        total_alerts = sum(r.alerts_30d or 0 for r in rows)
        total_tp = sum(r.true_positives_30d or 0 for r in rows)
        total_fp = sum(r.false_positives_30d or 0 for r in rows)
        firing = sum(1 for r in rows if r.alerts_30d and r.alerts_30d > 0)
        if total_alerts > 0:
            cards.append(_summary_card("Alerts (30d)", str(total_alerts)))
            classified = total_tp + total_fp
            if classified > 0:
                tp_pct = round(100 * total_tp / classified)
                klass = "green" if tp_pct >= 70 else ("amber" if tp_pct >= 40 else "red")
                cards.append(_summary_card("TP rate", f"{tp_pct}%", klass))
            cards.append(_summary_card("Detections firing", str(firing)))

    summary_block = (
        _exec_summary_block(rows, summary, delta=delta)
        + '<div class="summary">'
        + "".join(cards)
        + "</div>"
        + _severity_chart(rows)
    )

    show_live = _has_live_data(rows)
    head_cols = [
        "Title", "Status", "Severity", "Kind",
        "Tactics", "Techniques",
        "Owner",
        "Merge date", "Deployment date", "Last review",
        "Last PR",
    ]
    if show_live:
        head_cols.extend([
            "Alerts 30d", "TP", "FP", "FP rate",
            "Score", "Data source", "Schema",
            "Silent days", "Rec",
        ])
    header_html = "".join(f"<th>{escape(c)}</th>" for c in head_cols)

    row_html_parts: list[str] = []
    for r in rows:
        # Owner: render the local-part of the email so the column stays
        # narrow; full address on hover via title=. blue@acme.com -> "blue".
        if r.owner:
            owner_display = r.owner.split("@", 1)[0]
            owner_html = (
                f'<span title="{escape(r.owner)}">{escape(owner_display)}</span>'
            )
        else:
            owner_html = '<span class="muted">—</span>'

        # Last PR: clickable if we have a URL, plain "#NNN" otherwise.
        if r.last_pr_url:
            pr_html = (
                f'<a href="{escape(r.last_pr_url)}" target="_blank" '
                f'style="color: #1a73e8; text-decoration: none;" '
                f'data-sort-key="{r.last_pr_number}">#{r.last_pr_number}</a>'
            )
        elif r.last_pr_number is not None:
            pr_html = f'<span data-sort-key="{r.last_pr_number}">#{r.last_pr_number}</span>'
        else:
            pr_html = '<span class="muted">—</span>'

        # Title cell: keep the runbook link inline if present, so a SOC
        # lead can click straight from the rule to its response process.
        title_cell = f"{escape(r.title)}<br>"
        title_cell += f'<span class="mono muted">{escape(r.rule_id)}</span>'
        if r.runbook_url and r.runbook_url.startswith(("https://", "http://")):
            title_cell += (
                f' · <a href="{escape(r.runbook_url)}" target="_blank" '
                f'style="color: #1a73e8; text-decoration: none; '
                f'font-size: 0.75rem;" title="Open the runbook">runbook</a>'
            )

        cells = [
            f"<td>{title_cell}</td>",
            f"<td>{_status_pill(r.status)}</td>",
            f"<td>{_severity_pill(r.severity)}</td>",
            f"<td>{escape(_friendly_kind(r.asset_kind))}</td>",
            f"<td>{_tactics_cell(r.tactics)}</td>",
            f"<td>{_techniques_cell(r.techniques)}</td>",
            f"<td>{owner_html}</td>",
            f"<td>{_date_cell(r.merge_date)}</td>",
            f"<td>{_date_cell(r.deployment_date)}</td>",
            f"<td>{_date_cell(r.last_review_date)}</td>",
            f"<td>{pr_html}</td>",
        ]
        if show_live:
            def _num(v: int | None) -> str:
                if v is None:
                    return '<span class="muted">—</span>'
                return f'<span data-sort-key="{v}">{v}</span>'
            def _rate(v: float | None) -> str:
                if v is None:
                    return '<span class="muted">—</span>'
                return f'<span data-sort-key="{v}">{v:.1%}</span>'
            cells.extend([
                f"<td>{_num(r.alerts_30d)}</td>",
                f"<td>{_num(r.true_positives_30d)}</td>",
                f"<td>{_num(r.false_positives_30d)}</td>",
                f"<td>{_rate(r.fp_rate)}</td>",
                f"<td>{_score_cell(r.effectiveness_score)}</td>",
                f"<td>{_health_cell(r.data_source_healthy)}</td>",
                f"<td>{_drift_cell(r.schema_drift_columns)}</td>",
                f"<td>{_num(r.alert_silent_days)}</td>",
                f"<td>{_recommendation_pill(r.alert_recommendation)}</td>",
            ])
        row_html_parts.append("<tr>" + "".join(cells) + "</tr>")

    table_html = (
        '<table class="report"><thead><tr>'
        + header_html
        + "</tr></thead><tbody>"
        + "".join(row_html_parts)
        + "</tbody></table>"
    )

    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>ContentOps — Detection Inventory</title>\n"
        f"<style>{_STYLE}</style>\n"
        "</head>\n<body>\n"
        "<h1>Detection inventory</h1>\n"
        f'<div class="subtitle">Generated {escape(summary.generated_at)} '
        f"by ContentOps powered by SecM8. Click a column header to sort.</div>\n"
        + summary_block
        + '\n<div class="controls">'
          '<input type="text" class="filter" placeholder="Filter by any text in any column...">'
          "</div>\n"
        + table_html
        + "\n<footer>"
          'Generated catalog at <span class="mono">docs/reference/generated-catalog.md</span> '
          '· MITRE layer at <span class="mono">coverage/navigator-layer.json</span> · '
          "Source of truth: this repo.</footer>\n"
        f"<script>{_SCRIPT}</script>\n"
        "</body>\n</html>\n"
    )
