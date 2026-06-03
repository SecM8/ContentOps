# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""shields.io endpoint badge for the SOC report.

Matches the existing coverage/badge.json pattern. The README points at
the mirrored copy in SecM8/ContentOps/main/reports/badge.json so
the badge resolves for adopters too.
"""

from __future__ import annotations

import json

from contentops.report.assemble import ReportSummary


def render_badge(summary: ReportSummary) -> str:
    """Render a shields.io-endpoint JSON for the README badge.

    Message format: ``"<N> detections · <tactic_pct>% / <tech_pct>% /
    <sub_pct>% ATT&CK"``. The three percentages cover tactic /
    technique / sub-technique coverage levels — so the badge reads
    out at a glance the ATT&CK depth of the portfolio. Colour bands
    track the technique-level number (the most-cited industry
    metric); palette matches coverage/badge.json.
    """
    tech_pct = summary.coverage_pct
    if tech_pct < 20:
        color = "red"
    elif tech_pct < 40:
        color = "orange"
    elif tech_pct < 60:
        color = "yellow"
    elif tech_pct < 80:
        color = "yellowgreen"
    else:
        color = "brightgreen"
    # When tactic / sub-technique levels are unset (e.g. tests
    # constructing a minimal ReportSummary), fall back to the
    # single-number form so the badge still renders something
    # readable.
    if summary.coverage_tactics_total > 0:
        coverage_str = (
            f"{summary.coverage_tactics_pct}% T · "
            f"{tech_pct}% Tech · "
            f"{summary.coverage_sub_techniques_pct}% Sub"
        )
    else:
        coverage_str = f"{tech_pct}% MITRE"
    payload = {
        "schemaVersion": 1,
        "label": "detections",
        "message": f"{summary.total} · {coverage_str}",
        "color": color,
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
