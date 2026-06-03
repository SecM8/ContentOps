# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the persistent daily rollup store."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest

from contentops.alerts.daily_store import (
    DailyRollupEntry,
    build_daily_rollups,
    dates_with_rollups,
    load_daily_store,
    prune_store,
)
from contentops.alerts.ledger import LedgerEntry, append_entries
from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset


def _make_ledger_entry(
    *,
    alert_id: str = "a1",
    rule_display_name: str = "Rule A",
    classification: str = "truePositive",
    created_at: str = "2026-05-20T10:00:00+00:00",
    closed_at: str | None = "2026-05-20T12:00:00+00:00",
) -> LedgerEntry:
    return LedgerEntry(
        alert_id=alert_id,
        rule_display_name=rule_display_name,
        classification=classification,
        closed_at=closed_at,
        severity="medium",
        source="graph",
        created_at=created_at,
    )


def _make_detection(
    display_name: str = "Rule A",
    version: str = "1.0.0",
) -> LoadedAsset:
    envelope = EnvelopeV2(
        id=display_name.lower().replace(" ", "-"),
        version=version,
        asset=Asset.SENTINEL_ANALYTIC,
        status="production",
        metadata=None,
        arm_name=None,
    )
    return LoadedAsset(
        path=Path(f"detections/sentinel_analytic/{envelope.id}.yml"),
        envelope=envelope,
        payload={"displayName": display_name},
    )


class TestBuildDailyRollups:
    def test_creates_rollups_for_each_date(self, tmp_path: Path) -> None:
        ledger = tmp_path / "ledger.jsonl"
        store = tmp_path / "store.jsonl"

        append_entries(ledger, [
            _make_ledger_entry(alert_id="a1", created_at="2026-05-20T10:00:00+00:00"),
            _make_ledger_entry(alert_id="a2", created_at="2026-05-21T10:00:00+00:00"),
            _make_ledger_entry(alert_id="a3", created_at="2026-05-22T10:00:00+00:00"),
        ])
        dets = [_make_detection("Rule A", "1.0.0")]

        added = build_daily_rollups(ledger, dets, store_path=store)
        assert added == 3

        entries = load_daily_store(store)
        assert len(entries) == 3
        dates = {e.date for e in entries}
        assert dates == {"2026-05-20", "2026-05-21", "2026-05-22"}

    def test_is_idempotent(self, tmp_path: Path) -> None:
        ledger = tmp_path / "ledger.jsonl"
        store = tmp_path / "store.jsonl"

        append_entries(ledger, [
            _make_ledger_entry(alert_id="a1", created_at="2026-05-20T10:00:00+00:00"),
        ])
        dets = [_make_detection()]

        first = build_daily_rollups(ledger, dets, store_path=store)
        second = build_daily_rollups(ledger, dets, store_path=store)
        assert first == 1
        assert second == 1  # full rebuild produces same data

        entries = load_daily_store(store)
        assert len(entries) == 1

    def test_fills_gaps(self, tmp_path: Path) -> None:
        ledger = tmp_path / "ledger.jsonl"
        store = tmp_path / "store.jsonl"

        append_entries(ledger, [
            _make_ledger_entry(alert_id="a1", created_at="2026-05-20T10:00:00+00:00"),
            _make_ledger_entry(alert_id="a2", created_at="2026-05-21T10:00:00+00:00"),
            _make_ledger_entry(alert_id="a3", created_at="2026-05-22T10:00:00+00:00"),
        ])
        dets = [_make_detection()]

        # Pre-populate days 1 and 3
        from contentops.alerts.daily_store import _append_entries
        _append_entries(store, [
            DailyRollupEntry(
                date="2026-05-20", rule_display_name="Rule A", version="1.0.0",
                asset_kind="sentinel_analytic", severity="medium",
                alert_count=1, resolved_count=1, tp_count=1,
                fp_count=0, benign_count=0, undetermined_count=0,
                mean_close_hours=2.0,
            ),
            DailyRollupEntry(
                date="2026-05-22", rule_display_name="Rule A", version="1.0.0",
                asset_kind="sentinel_analytic", severity="medium",
                alert_count=1, resolved_count=1, tp_count=1,
                fp_count=0, benign_count=0, undetermined_count=0,
                mean_close_hours=2.0,
            ),
        ])

        added = build_daily_rollups(ledger, dets, store_path=store)
        assert added == 3  # full rebuild from ledger

        entries = load_daily_store(store)
        dates = {e.date for e in entries}
        assert "2026-05-21" in dates

    def test_version_from_detection(self, tmp_path: Path) -> None:
        ledger = tmp_path / "ledger.jsonl"
        store = tmp_path / "store.jsonl"

        append_entries(ledger, [
            _make_ledger_entry(alert_id="a1", rule_display_name="Rule A"),
        ])
        dets = [_make_detection("Rule A", "2.1.0")]

        build_daily_rollups(ledger, dets, store_path=store)
        entries = load_daily_store(store)
        assert entries[0].version == "2.1.0"

    def test_classification_counts(self, tmp_path: Path) -> None:
        ledger = tmp_path / "ledger.jsonl"
        store = tmp_path / "store.jsonl"

        append_entries(ledger, [
            _make_ledger_entry(alert_id="a1", classification="truePositive", created_at="2026-05-20T10:00:00+00:00"),
            _make_ledger_entry(alert_id="a2", classification="falsePositive", created_at="2026-05-20T11:00:00+00:00"),
            _make_ledger_entry(alert_id="a3", classification="falsePositive", created_at="2026-05-20T12:00:00+00:00"),
            _make_ledger_entry(alert_id="a4", classification="undetermined", created_at="2026-05-20T13:00:00+00:00", closed_at=None),
        ])
        dets = [_make_detection()]

        build_daily_rollups(ledger, dets, store_path=store)
        entries = load_daily_store(store)
        assert len(entries) == 1
        e = entries[0]
        assert e.alert_count == 4
        assert e.tp_count == 1
        assert e.fp_count == 2
        assert e.undetermined_count == 1
        assert e.resolved_count == 3


class TestPruneStore:
    def test_removes_old_entries(self, tmp_path: Path) -> None:
        store = tmp_path / "store.jsonl"
        old_date = (date.today() - timedelta(days=100)).isoformat()
        recent_date = (date.today() - timedelta(days=5)).isoformat()

        from contentops.alerts.daily_store import _append_entries
        _append_entries(store, [
            DailyRollupEntry(
                date=old_date, rule_display_name="R1", version="1.0.0",
                asset_kind="sentinel_analytic", severity="medium",
                alert_count=1, resolved_count=0, tp_count=1,
                fp_count=0, benign_count=0, undetermined_count=0,
                mean_close_hours=None,
            ),
            DailyRollupEntry(
                date=recent_date, rule_display_name="R1", version="1.0.0",
                asset_kind="sentinel_analytic", severity="medium",
                alert_count=2, resolved_count=1, tp_count=1,
                fp_count=1, benign_count=0, undetermined_count=0,
                mean_close_hours=1.5,
            ),
        ])

        removed = prune_store(store, retention_days=90)
        assert removed == 1

        entries = load_daily_store(store)
        assert len(entries) == 1
        assert entries[0].date == recent_date


class TestDatesWithRollups:
    def test_returns_dates(self, tmp_path: Path) -> None:
        store = tmp_path / "store.jsonl"
        from contentops.alerts.daily_store import _append_entries
        _append_entries(store, [
            DailyRollupEntry(
                date="2026-05-20", rule_display_name="R1", version="1.0.0",
                asset_kind="sentinel_analytic", severity="medium",
                alert_count=1, resolved_count=0, tp_count=1,
                fp_count=0, benign_count=0, undetermined_count=0,
                mean_close_hours=None,
            ),
        ])

        dates = dates_with_rollups(store)
        assert "2026-05-20" in dates

    def test_empty_when_missing(self, tmp_path: Path) -> None:
        assert dates_with_rollups(tmp_path / "nonexistent.jsonl") == set()
