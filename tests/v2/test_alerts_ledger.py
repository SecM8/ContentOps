# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the alert ledger: entry model, read/write, dedup,
date filtering, watermark, PII stripping, and NormalizedAlert conversion.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from contentops.alerts.ledger import (
    LedgerEntry,
    LedgerWatermark,
    append_entries,
    entries_to_normalized_alerts,
    load_ledger,
    load_ledger_deduped,
    load_ledger_for_range,
    normalize_to_entry,
    read_watermark,
    write_watermark,
)
from contentops.alerts.models import (
    AlertClassification,
    AlertDetermination,
    AlertSeverity,
    AlertStatus,
    NormalizedAlert,
)


def _make_entry(
    *,
    alert_id: str = "a1",
    rule_display_name: str = "Test Rule",
    classification: str = "truePositive",
    closed_at: str | None = "2026-05-20T12:00:00+00:00",
    severity: str = "medium",
    source: str = "graph",
    created_at: str = "2026-05-20T10:00:00+00:00",
    rule_id: str | None = None,
) -> LedgerEntry:
    return LedgerEntry(
        alert_id=alert_id,
        rule_display_name=rule_display_name,
        classification=classification,
        closed_at=closed_at,
        severity=severity,
        source=source,
        created_at=created_at,
        rule_id=rule_id,
    )


# ---------------------------------------------------------------------------
# LedgerEntry model
# ---------------------------------------------------------------------------


class TestLedgerEntry:
    def test_construction(self) -> None:
        entry = _make_entry()
        assert entry.alert_id == "a1"
        assert entry.rule_display_name == "Test Rule"
        assert entry.classification == "truePositive"

    def test_frozen(self) -> None:
        entry = _make_entry()
        with pytest.raises(AttributeError):
            entry.alert_id = "changed"  # type: ignore[misc]

    def test_optional_fields(self) -> None:
        entry = _make_entry(closed_at=None, rule_id=None)
        assert entry.closed_at is None
        assert entry.rule_id is None


# ---------------------------------------------------------------------------
# Write / Read
# ---------------------------------------------------------------------------


class TestWriteRead:
    def test_roundtrip(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        entries = [_make_entry(alert_id="a1"), _make_entry(alert_id="a2")]
        append_entries(path, entries)
        loaded = load_ledger(path)
        assert len(loaded) == 2
        assert loaded[0].alert_id == "a1"
        assert loaded[1].alert_id == "a2"

    def test_additive_append(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        append_entries(path, [_make_entry(alert_id="a1")])
        append_entries(path, [_make_entry(alert_id="a2")])
        loaded = load_ledger(path)
        assert len(loaded) == 2

    def test_empty_file(self, tmp_path: Path) -> None:
        path = tmp_path / "missing.jsonl"
        assert load_ledger(path) == []

    def test_malformed_lines_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        good = json.dumps({
            "alert_id": "a1", "rule_display_name": "R1",
            "classification": "truePositive", "closed_at": None,
            "severity": "medium", "source": "graph",
            "created_at": "2026-05-20T10:00:00+00:00",
        })
        path.write_text(f"{good}\nBAD LINE\n{good}\n", encoding="utf-8")
        loaded = load_ledger(path)
        assert len(loaded) == 2


# ---------------------------------------------------------------------------
# Dedup
# ---------------------------------------------------------------------------


class TestDedup:
    def test_latest_wins(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        e1 = _make_entry(alert_id="a1", classification="undetermined")
        e2 = _make_entry(alert_id="a1", classification="truePositive")
        append_entries(path, [e1, e2])
        deduped = load_ledger_deduped(path)
        assert len(deduped) == 1
        assert deduped[0].classification == "truePositive"

    def test_unique_preserved(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        append_entries(path, [_make_entry(alert_id="a1"), _make_entry(alert_id="a2")])
        deduped = load_ledger_deduped(path)
        assert len(deduped) == 2


# ---------------------------------------------------------------------------
# Date filtering
# ---------------------------------------------------------------------------


class TestDateFiltering:
    def test_single_day(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        append_entries(path, [
            _make_entry(alert_id="a1", created_at="2026-05-20T10:00:00+00:00"),
            _make_entry(alert_id="a2", created_at="2026-05-21T10:00:00+00:00"),
        ])
        filtered = load_ledger_for_range(path, start=date(2026, 5, 20), end=date(2026, 5, 20))
        assert len(filtered) == 1
        assert filtered[0].alert_id == "a1"

    def test_range(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        append_entries(path, [
            _make_entry(alert_id="a1", created_at="2026-05-19T10:00:00+00:00"),
            _make_entry(alert_id="a2", created_at="2026-05-20T10:00:00+00:00"),
            _make_entry(alert_id="a3", created_at="2026-05-21T10:00:00+00:00"),
        ])
        filtered = load_ledger_for_range(path, start=date(2026, 5, 20), end=date(2026, 5, 21))
        assert len(filtered) == 2

    def test_exclusion(self, tmp_path: Path) -> None:
        path = tmp_path / "ledger.jsonl"
        append_entries(path, [
            _make_entry(alert_id="a1", created_at="2026-05-15T10:00:00+00:00"),
        ])
        filtered = load_ledger_for_range(path, start=date(2026, 5, 20), end=date(2026, 5, 25))
        assert len(filtered) == 0


# ---------------------------------------------------------------------------
# Watermark
# ---------------------------------------------------------------------------


class TestWatermark:
    def test_roundtrip(self, tmp_path: Path) -> None:
        path = tmp_path / "watermark.json"
        wm = LedgerWatermark(
            last_sync_at="2026-05-25T07:00:00+00:00",
            last_sync_until="2026-05-25T00:00:00+00:00",
            entry_count=42,
            source="graph",
        )
        write_watermark(path, wm)
        loaded = read_watermark(path)
        assert loaded is not None
        assert loaded.last_sync_until == "2026-05-25T00:00:00+00:00"
        assert loaded.entry_count == 42

    def test_none_when_missing(self, tmp_path: Path) -> None:
        assert read_watermark(tmp_path / "nonexistent.json") is None


# ---------------------------------------------------------------------------
# PII stripping
# ---------------------------------------------------------------------------


class TestPIIStripping:
    def test_strips_pii(self) -> None:
        alert = NormalizedAlert(
            id="a1",
            title="Alert Title",
            severity=AlertSeverity.high,
            status=AlertStatus.resolved,
            classification=AlertClassification.true_positive,
            determination=AlertDetermination.malware,
            source="graph",
            service_source="microsoftDefenderForEndpoint",
            created=datetime(2026, 5, 20, 10, 0, tzinfo=timezone.utc),
            resolved=datetime(2026, 5, 20, 12, 0, tzinfo=timezone.utc),
            assigned_to="analyst@contoso.com",
            description="Sensitive description with PII",
            incident_id="inc-123",
            mitre_techniques=["T1059"],
        )
        entry = normalize_to_entry(alert)
        assert entry.alert_id == "a1"
        assert not hasattr(entry, "assigned_to")
        assert not hasattr(entry, "description")
        assert not hasattr(entry, "incident_id")
        assert not hasattr(entry, "mitre_techniques")
        assert not hasattr(entry, "determination")

    def test_preserves_classification(self) -> None:
        for cls in AlertClassification:
            alert = NormalizedAlert(
                id="a1", title="T", severity=AlertSeverity.medium,
                status=AlertStatus.new, classification=cls,
                determination=AlertDetermination.unknown,
                source="graph", service_source="",
            )
            entry = normalize_to_entry(alert)
            assert entry.classification == cls.value

    def test_maps_display_name(self) -> None:
        alert = NormalizedAlert(
            id="a1", title="Dynamic Title",
            severity=AlertSeverity.medium, status=AlertStatus.new,
            classification=AlertClassification.undetermined,
            determination=AlertDetermination.unknown,
            source="graph", service_source="",
            rule_name="Stable Display Name",
        )
        entry = normalize_to_entry(alert)
        assert entry.rule_display_name == "Stable Display Name"

    def test_falls_back_to_title(self) -> None:
        alert = NormalizedAlert(
            id="a1", title="Title Fallback",
            severity=AlertSeverity.medium, status=AlertStatus.new,
            classification=AlertClassification.undetermined,
            determination=AlertDetermination.unknown,
            source="graph", service_source="",
            rule_name=None,
        )
        entry = normalize_to_entry(alert)
        assert entry.rule_display_name == "Title Fallback"


# ---------------------------------------------------------------------------
# entries_to_normalized_alerts
# ---------------------------------------------------------------------------


class TestEntriesToNormalizedAlerts:
    def test_roundtrip_conversion(self) -> None:
        entry = _make_entry(
            alert_id="a1", rule_display_name="Rule A",
            classification="falsePositive",
            created_at="2026-05-20T10:00:00+00:00",
            closed_at="2026-05-20T12:00:00+00:00",
            rule_id="guid-123",
        )
        alerts = entries_to_normalized_alerts([entry])
        assert len(alerts) == 1
        a = alerts[0]
        assert a.id == "a1"
        assert a.title == "Rule A"
        assert a.rule_name == "Rule A"
        assert a.classification == AlertClassification.false_positive
        assert a.status == AlertStatus.resolved
        assert a.rule_id == "guid-123"

    def test_none_fields_handled(self) -> None:
        entry = _make_entry(closed_at=None, rule_id=None)
        alerts = entries_to_normalized_alerts([entry])
        assert alerts[0].resolved is None
        assert alerts[0].status == AlertStatus.new
        assert alerts[0].rule_id is None
