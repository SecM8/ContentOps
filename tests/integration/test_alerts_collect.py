# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Live integration test for the alerts collect pipeline.

Gated by ``RUN_LIVE_TESTS=1`` -- skipped in CI unit-test runs.

Exercises:
* Source detection (Graph vs Sentinel fallback).
* Alert listing with a 24h window.
* NormalizedAlert round-trip.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LIVE_TESTS") != "1",
    reason="Live tests disabled (set RUN_LIVE_TESTS=1 to enable)",
)


def test_collect_and_normalize() -> None:
    """Collect alerts from the live tenant and normalize them."""
    from datetime import datetime, timedelta, timezone

    from contentops.alerts.models import NormalizedAlert
    from contentops.alerts.provider import GraphAlertsProvider
    from contentops.utils.auth import get_credential

    credential = get_credential()

    # Try to build Sentinel fallback
    sentinel_provider = None
    try:
        from contentops.config import load_tenant_config
        from contentops.providers.sentinel_arm import SentinelArmProvider

        cfg = load_tenant_config()
        if cfg.sentinelWorkspaces:
            workspace = cfg.sentinelWorkspaces[0]
            sentinel_provider = SentinelArmProvider(
                workspace, credential=credential,
            )
    except FileNotFoundError:
        pass

    provider = GraphAlertsProvider(
        credential, sentinel_provider=sentinel_provider,
    )
    try:
        source = provider.detect_source()
        assert source in ("graph", "sentinel", "both")

        since = datetime.now(timezone.utc) - timedelta(hours=24)
        raw = provider.list_alerts(since=since)
        assert isinstance(raw, list)

        # Normalize all results
        normalized = []
        for item in raw:
            if source == "sentinel":
                normalized.append(NormalizedAlert.from_sentinel(item))
            else:
                normalized.append(NormalizedAlert.from_graph(item))

        # Spot-check first alert if any
        if normalized:
            na = normalized[0]
            assert na.id
            assert na.source in ("graph", "sentinel")
            assert na.severity is not None
    finally:
        provider.close()
        if sentinel_provider is not None:
            sentinel_provider.close()


def test_rollup_live() -> None:
    """Compute a rollup for yesterday against the live tenant."""
    from datetime import date, datetime, timedelta, timezone

    from contentops.alerts.models import NormalizedAlert
    from contentops.alerts.provider import GraphAlertsProvider
    from contentops.alerts.rollup import compute_daily_rollup, render_rollup_markdown
    from contentops.utils.auth import get_credential

    credential = get_credential()
    provider = GraphAlertsProvider(credential)
    try:
        source = provider.detect_source()
        yesterday = date.today() - timedelta(days=1)
        since = datetime(
            yesterday.year, yesterday.month, yesterday.day,
            tzinfo=timezone.utc,
        )
        until = since + timedelta(days=1)
        raw = provider.list_alerts(since=since, until=until)

        alerts = []
        for item in raw:
            if source == "sentinel":
                alerts.append(NormalizedAlert.from_sentinel(item))
            else:
                alerts.append(NormalizedAlert.from_graph(item))

        rollup = compute_daily_rollup(alerts, yesterday)
        md = render_rollup_markdown(rollup)
        assert "Alert Rollup" in md
        assert yesterday.isoformat() in md
    finally:
        provider.close()
