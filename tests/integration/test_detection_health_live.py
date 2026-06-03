# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Live integration test for detection health.

Gated by RUN_LIVE_TESTS=1. Read-only: discovers detections, fetches
alerts from Graph/Sentinel, and computes the health report.
"""

from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not os.getenv("RUN_LIVE_TESTS"),
    reason="Live test — set RUN_LIVE_TESTS=1 to run",
)


class TestDetectionHealthLive:
    def test_health_report_against_live_tenant(self) -> None:
        from contentops.alerts.detection_health import compute_detection_health
        from contentops.alerts.models import NormalizedAlert
        from contentops.alerts.provider import GraphAlertsProvider
        from contentops.core.discovery import discover_assets, load_asset
        from contentops.report.assemble import DETECTION_ASSETS
        from contentops.utils.auth import get_credential

        detections_path = Path("detections")
        assert detections_path.is_dir(), "detections/ directory not found"

        paths = discover_assets(detections_path)
        loaded = []
        for p in paths:
            la = load_asset(p)
            if la.envelope.asset in DETECTION_ASSETS:
                loaded.append(la)

        assert len(loaded) > 0, "No detections found"

        credential = get_credential()
        provider = GraphAlertsProvider(credential)
        try:
            source = provider.detect_source()
            end = datetime.now(timezone.utc)
            since = end - timedelta(days=30)
            raw = provider.list_alerts(since=since, until=end)
        finally:
            provider.close()

        alerts = []
        for item in raw:
            if source == "sentinel":
                alerts.append(NormalizedAlert.from_sentinel(item))
            else:
                alerts.append(NormalizedAlert.from_graph(item))

        report = compute_detection_health(
            loaded, alerts, 30, end_date=date.today(),
        )

        assert report.total_detections > 0
        assert report.total_detections == len(loaded)
        assert len(report.rows) == report.total_detections
