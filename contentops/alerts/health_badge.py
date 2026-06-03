# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""shields.io endpoint badge for detection health."""

from __future__ import annotations

import json

from contentops.alerts.detection_health import DetectionHealthReport


def render_health_badge(report: DetectionHealthReport) -> str:
    total = report.total_detections or 1
    tune_count = sum(1 for r in report.rows if r.recommendation == "TUNE")
    silent_count = sum(1 for r in report.rows if r.recommendation == "SILENT")
    healthy_count = sum(1 for r in report.rows if r.recommendation == "HEALTHY")
    silent_pct = silent_count / total * 100

    if tune_count > 10:
        color = "red"
    elif tune_count > 5 or silent_pct > 20:
        color = "orange"
    elif tune_count > 2:
        color = "yellow"
    elif tune_count > 0:
        color = "yellowgreen"
    else:
        color = "brightgreen"

    healthy_pct = round(healthy_count / total * 100)
    parts = [f"{healthy_pct}% HEALTHY"]
    if tune_count > 0:
        parts.append(f"{tune_count} TUNE")
    if silent_count > 0:
        parts.append(f"{silent_count} SILENT")

    payload = {
        "schemaVersion": 1,
        "label": "detection health",
        "message": " · ".join(parts),
        "color": color,
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


__all__ = ["render_health_badge"]
