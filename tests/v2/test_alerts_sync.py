# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the alert sync engine: lookback window computation
and sync orchestration with mock provider.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from contentops.alerts.ledger import (
    LedgerWatermark,
    append_entries,
    load_ledger,
    read_watermark,
)
from contentops.alerts.sync import (
    SyncResult,
    compute_lookback_window,
    sync_alerts,
)


_NOW = datetime(2026, 5, 25, 7, 0, tzinfo=timezone.utc)
_MIDNIGHT = datetime(2026, 5, 25, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Lookback window
# ---------------------------------------------------------------------------


class TestLookbackWindow:
    def test_first_run_defender_30_days(self) -> None:
        since, until = compute_lookback_window(
            None, source="graph", now=_NOW,
        )
        assert until == _MIDNIGHT
        assert since == _MIDNIGHT - timedelta(days=30)

    def test_first_run_sentinel_90_days(self) -> None:
        since, until = compute_lookback_window(
            None, source="sentinel", now=_NOW,
        )
        assert until == _MIDNIGHT
        assert since == _MIDNIGHT - timedelta(days=90)

    def test_subsequent_run_fills_gap(self) -> None:
        wm = LedgerWatermark(
            last_sync_at="2026-05-22T07:00:00+00:00",
            last_sync_until="2026-05-22T00:00:00+00:00",
            entry_count=100,
            source="graph",
        )
        since, until = compute_lookback_window(
            wm, source="graph", now=_NOW,
        )
        assert since == datetime(2026, 5, 22, 0, 0, tzinfo=timezone.utc)
        assert until == _MIDNIGHT

    def test_up_to_date_returns_equal_window(self) -> None:
        wm = LedgerWatermark(
            last_sync_at="2026-05-25T07:00:00+00:00",
            last_sync_until="2026-05-25T00:00:00+00:00",
            entry_count=100,
            source="graph",
        )
        since, until = compute_lookback_window(
            wm, source="graph", now=_NOW,
        )
        assert since >= until

    def test_backfill_overrides_watermark(self) -> None:
        wm = LedgerWatermark(
            last_sync_at="2026-05-24T07:00:00+00:00",
            last_sync_until="2026-05-24T00:00:00+00:00",
            entry_count=100,
            source="graph",
        )
        since, until = compute_lookback_window(
            wm, source="graph", backfill=True, now=_NOW,
        )
        assert since == _MIDNIGHT - timedelta(days=30)

    def test_until_is_midnight_today(self) -> None:
        _, until = compute_lookback_window(
            None, source="graph", now=_NOW,
        )
        assert until.hour == 0
        assert until.minute == 0
        assert until.second == 0

    def test_custom_lookback_from_config(self) -> None:
        since, until = compute_lookback_window(
            None, source="graph",
            defender_lookback_days=14,
            now=_NOW,
        )
        assert since == _MIDNIGHT - timedelta(days=14)


# ---------------------------------------------------------------------------
# Sync orchestration (mock provider)
# ---------------------------------------------------------------------------


def _mock_provider(
    source: str = "graph",
    alerts: list[dict] | None = None,
) -> MagicMock:
    from contentops.alerts.provider import SourcedAlerts

    provider = MagicMock()
    provider.detect_source.return_value = source
    provider.detect_available_sources.return_value = {source} if source != "both" else {"graph", "sentinel"}
    provider.list_alerts.return_value = alerts or []
    provider.list_alerts_for_date.return_value = alerts or []
    provider.list_alerts_for_date_joined.return_value = alerts or []
    provider.list_recently_modified_incidents.return_value = []
    provider.list_graph_alerts_for_date.return_value = []
    provider._list_graph_alerts.return_value = []
    provider._workspace_id = None
    provider._credential = None
    provider._sentinel = None
    if source == "sentinel":
        provider.list_alerts_dual.return_value = SourcedAlerts(
            sentinel_incidents=alerts or [],
        )
    else:
        provider.list_alerts_dual.return_value = SourcedAlerts(
            graph_alerts=alerts or [],
        )
    provider.close.return_value = None
    return provider


def _raw_graph_alert(
    alert_id: str = "ga-1",
    title: str = "Test Alert",
    severity: str = "medium",
    status: str = "resolved",
    classification: str = "truePositive",
    created: str = "2026-05-20T10:00:00Z",
    resolved: str = "2026-05-20T12:00:00Z",
) -> dict:
    return {
        "id": alert_id,
        "title": title,
        "severity": severity,
        "status": status,
        "classification": classification,
        "serviceSource": "test",
        "createdDateTime": created,
        "resolvedDateTime": resolved,
    }


class TestSyncOrchestration:
    def test_exports_yesterday_and_builds_ledger(self, tmp_path: Path) -> None:
        ledger = tmp_path / "ledger.jsonl"
        watermark = tmp_path / "watermark.json"
        daily_dir = tmp_path / "daily"
        provider = _mock_provider(alerts=[
            _raw_graph_alert(alert_id="ga-1"),
            _raw_graph_alert(alert_id="ga-2"),
        ])

        result = sync_alerts(
            provider, ledger, watermark, daily_dir=daily_dir,
            reexport_days=0, enrich=False,
        )

        assert result.days_exported == 1
        assert result.total_alerts == 2

        entries = load_ledger(ledger)
        assert len(entries) == 2

        wm = read_watermark(watermark)
        assert wm is not None

    def test_skips_existing_daily_file(self, tmp_path: Path) -> None:
        from datetime import date as _date, timedelta as _td

        ledger = tmp_path / "ledger.jsonl"
        watermark = tmp_path / "watermark.json"
        daily_dir = tmp_path / "daily"
        yesterday = _date.today() - _td(days=1)

        daily_dir.mkdir(parents=True)
        (daily_dir / f"{yesterday.isoformat()}.jsonl").write_text("")

        provider = _mock_provider(alerts=[_raw_graph_alert()])
        result = sync_alerts(
            provider, ledger, watermark, daily_dir=daily_dir,
            reexport_days=0, enrich=False,
        )

        assert result.days_exported == 0
        assert result.days_skipped == 1

    def test_force_re_exports_existing(self, tmp_path: Path) -> None:
        from datetime import date as _date, timedelta as _td

        ledger = tmp_path / "ledger.jsonl"
        watermark = tmp_path / "watermark.json"
        daily_dir = tmp_path / "daily"
        yesterday = _date.today() - _td(days=1)

        daily_dir.mkdir(parents=True)
        (daily_dir / f"{yesterday.isoformat()}.jsonl").write_text("")

        provider = _mock_provider(alerts=[_raw_graph_alert()])
        result = sync_alerts(
            provider, ledger, watermark, daily_dir=daily_dir, force=True,
            reexport_days=0, enrich=False,
        )

        assert result.days_exported == 1
        assert result.days_skipped == 0

    def test_backfill_creates_daily_files(self, tmp_path: Path) -> None:
        ledger = tmp_path / "ledger.jsonl"
        watermark = tmp_path / "watermark.json"
        daily_dir = tmp_path / "daily"

        provider = _mock_provider(alerts=[_raw_graph_alert()])
        result = sync_alerts(
            provider, ledger, watermark, daily_dir=daily_dir,
            backfill=True, backfill_days=5, enrich=False,
        )

        assert result.days_exported == 5
        assert (daily_dir).is_dir()
        files = list(daily_dir.glob("*.jsonl"))
        assert len(files) == 5

    def test_specific_date(self, tmp_path: Path) -> None:
        from datetime import date as _date

        ledger = tmp_path / "ledger.jsonl"
        watermark = tmp_path / "watermark.json"
        daily_dir = tmp_path / "daily"

        provider = _mock_provider(alerts=[_raw_graph_alert()])
        target = _date(2026, 5, 20)
        result = sync_alerts(
            provider, ledger, watermark, daily_dir=daily_dir,
            target_date=target, reexport_days=0, enrich=False,
        )

        assert result.days_exported == 1
        assert (daily_dir / "2026-05-20.jsonl").is_file()
