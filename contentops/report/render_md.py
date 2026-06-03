# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Markdown renderer for the detection inventory report.

Renders the same data the HTML report shows, in a GitHub-friendly
table. Intended for inline PR / wiki / README consumption — the HTML
report is the polished version for SOC leads.
"""

from __future__ import annotations

from contentops.report.assemble import ReportRow, ReportSummary


_ASSET_KIND_LABELS = {
    "sentinel_analytic": "Sentinel Analytic",
    "sentinel_hunting": "Sentinel Hunting",
    "sentinel_parser": "Sentinel Parser",
    "sentinel_watchlist": "Sentinel Watchlist",
    "sentinel_data_connector": "Sentinel Data Connector",
    "defender_custom_detection": "Defender XDR Custom Detection",
}


def _md_escape(value: str) -> str:
    """Escape characters that would otherwise break a markdown table cell."""
    return value.replace("|", "\\|").replace("\n", " ")


def _spaced_tactic(value: str) -> str:
    """PascalCase tactic -> spaced. InitialAccess -> 'Initial Access'."""
    if not value or not value[0].isupper():
        return value
    out = [value[0]]
    for ch in value[1:]:
        if ch.isupper():
            out.append(" ")
        out.append(ch)
    return "".join(out)


def _friendly_kind(kind: str) -> str:
    return _ASSET_KIND_LABELS.get(kind, kind)


def _date_short(value: str | None) -> str:
    if not value:
        return "—"
    return value[:10]


def _list_short(items: tuple[str, ...]) -> str:
    if not items:
        return "—"
    return ", ".join(items)


def render_markdown(rows: list[ReportRow], summary: ReportSummary) -> str:
    """Return the full markdown body."""
    lines: list[str] = []
    lines.append("# Detection inventory")
    lines.append("")
    lines.append(
        f"_Generated {summary.generated_at} by ContentOps powered by SecM8._"
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Total detections | **{summary.total}** |")
    lines.append(f"| Production | {summary.production} |")
    lines.append(f"| Experimental | {summary.experimental} |")
    lines.append(f"| Deprecated | {summary.deprecated} |")
    if summary.coverage_tactics_total > 0:
        lines.append(
            f"| Tactic coverage | **{summary.coverage_tactics_pct}%** "
            f"({summary.coverage_tactics_covered} / "
            f"{summary.coverage_tactics_total}) |"
        )
    lines.append(
        f"| Technique coverage | **{summary.coverage_pct}%** "
        f"({summary.coverage_covered} / {summary.coverage_total}) |"
    )
    if summary.coverage_sub_techniques_total > 0:
        lines.append(
            f"| Sub-technique coverage | "
            f"**{summary.coverage_sub_techniques_pct}%** "
            f"({summary.coverage_sub_techniques_covered} / "
            f"{summary.coverage_sub_techniques_total}) |"
        )
    lines.append("")

    lines.append("## Detections")
    lines.append("")

    has_alerts = any(r.alert_recommendation is not None for r in rows)

    header = (
        "| Title | Status | Severity | Kind | Tactics | Techniques | "
        "Owner | Merge | Deploy | Last review | Last PR |"
    )
    sep = "|---|---|---|---|---|---|---|---|---|---|---|"
    if has_alerts:
        header += " Silent days | Rec |"
        sep += "---:|---|"

    lines.append(header)
    lines.append(sep)

    for r in rows:
        spaced_tactics = tuple(_spaced_tactic(t) for t in r.tactics)
        owner = (r.owner.split("@", 1)[0] if r.owner else "—")
        if r.last_pr_url:
            pr_cell = f"[#{r.last_pr_number}]({r.last_pr_url})"
        elif r.last_pr_number is not None:
            pr_cell = f"#{r.last_pr_number}"
        else:
            pr_cell = "—"
        title_cell = f"{_md_escape(r.title)}<br>`{_md_escape(r.rule_id)}`"
        if r.runbook_url and r.runbook_url.startswith(("https://", "http://")):
            title_cell += f" · [runbook]({r.runbook_url})"
        row_text = (
            "| "
            f"{title_cell} | "
            f"{r.status} | {r.severity} | {_friendly_kind(r.asset_kind)} | "
            f"{_md_escape(_list_short(spaced_tactics))} | "
            f"{_md_escape(_list_short(r.techniques))} | "
            f"{_md_escape(owner)} | "
            f"{_date_short(r.merge_date)} | "
            f"{_date_short(r.deployment_date)} | "
            f"{_date_short(r.last_review_date)} | "
            f"{pr_cell} |"
        )
        if has_alerts:
            sd = str(r.alert_silent_days) if r.alert_silent_days is not None else "—"
            rec = r.alert_recommendation or "—"
            row_text += f" {sd} | {rec} |"
        lines.append(row_text)
    lines.append("")
    return "\n".join(lines) + "\n"
