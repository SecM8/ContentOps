# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""SOC-grade detection inventory report.

Per-detection row joining envelope metadata + git log (merge date) +
audit JSONL (last deploy) into one structured record. Renders to
HTML (sortable styled), Markdown (GitHub-renderable), and a
shields.io endpoint badge.

Live enrichment (telemetry, data-source health, schema drift) lands
in a follow-up PR; this module's pure-function assembly stays
identical between static and live modes — only the row class gains
optional fields when enrichment runs.
"""

from __future__ import annotations

from contentops.report.assemble import (
    ReportRow,
    ReportSummary,
    assemble_report,
)
from contentops.report.enrich import (
    enrich_with_alerts,
    enrich_with_health,
    enrich_with_schema_drift,
    enrich_with_telemetry,
    extract_primary_table,
    health_query,
    primary_tables_for_rows,
)
from contentops.report.render_badge import render_badge
from contentops.report.render_html import render_html
from contentops.report.render_md import render_markdown
from contentops.report.snapshot import (
    ReportDelta,
    compute_delta,
    find_previous_snapshot,
    load_snapshot,
    render_snapshot,
)

__all__ = [
    "ReportDelta",
    "ReportRow",
    "ReportSummary",
    "assemble_report",
    "compute_delta",
    "enrich_with_alerts",
    "enrich_with_health",
    "enrich_with_schema_drift",
    "enrich_with_telemetry",
    "extract_primary_table",
    "find_previous_snapshot",
    "health_query",
    "load_snapshot",
    "primary_tables_for_rows",
    "render_badge",
    "render_html",
    "render_markdown",
    "render_snapshot",
]
