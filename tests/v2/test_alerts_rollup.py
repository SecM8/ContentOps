# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the daily rollup computation and rendering.

Covers:
* compute_daily_rollup classification counts and percentages.
* MTTR computation.
* Top-titles ranking.
* Rule effectiveness.
* Still-open filtering.
* Markdown rendering structure.
* JSON rendering structure.
* Trend report computation and rendering.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone

import pytest

from contentops.alerts.models import (
    AlertClassification,
    AlertDetermination,
    AlertSeverity,
    AlertStatus,
    NormalizedAlert,
)
from contentops.alerts.rollup import (
    DailyRollup,
    compute_daily_rollup,
    render_rollup_json,
    render_rollup_markdown,
)
from contentops.alerts.report import (
    TrendReport,
    compute_trend_report,
    render_trend_json,
    render_trend_markdown,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_alert(
    *,
    id: str = "a1",
    title: str = "Test Alert",
    severity: AlertSeverity = AlertSeverity.medium,
    status: AlertStatus = AlertStatus.resolved,
    classification: AlertClassification = AlertClassification.true_positive,
    created: datetime | None = None,
    resolved: datetime | None = None,
    mitre: list[str] | None = None,
    rule_name: str | None = None,
) -> NormalizedAlert:
    if created is None:
        created = datetime(2026, 5, 20, 10, 0, tzinfo=timezone.utc)
    if resolved is None and status == AlertStatus.resolved:
        resolved = created + timedelta(hours=2)
    return NormalizedAlert(
        id=id,
        title=title,
        severity=severity,
        status=status,
        classification=classification,
        determination=AlertDetermination.unknown,
        source="graph",
        service_source="test",
        created=created,
        resolved=resolved,
        mitre_techniques=mitre or [],
        rule_name=rule_name,
    )


TARGET_DATE = date(2026, 5, 20)


# ---------------------------------------------------------------------------
# compute_daily_rollup
# ---------------------------------------------------------------------------


class TestComputeDailyRollup:
    def test_empty_alerts(self) -> None:
        rollup = compute_daily_rollup([], TARGET_DATE)
        assert rollup.total_alerts == 0
        assert rollup.total_resolved == 0
        assert rollup.mean_time_to_close_hours is None
        assert rollup.top_titles == []
        assert rollup.still_open == []

    def test_counts_only_target_date(self) -> None:
        """Alerts from other dates are excluded."""
        a1 = _make_alert(id="a1", created=datetime(2026, 5, 20, 8, 0, tzinfo=timezone.utc))
        a2 = _make_alert(id="a2", created=datetime(2026, 5, 19, 8, 0, tzinfo=timezone.utc))
        rollup = compute_daily_rollup([a1, a2], TARGET_DATE)
        assert rollup.total_alerts == 1

    def test_classification_counts(self) -> None:
        alerts = [
            _make_alert(id="tp1", classification=AlertClassification.true_positive),
            _make_alert(id="tp2", classification=AlertClassification.true_positive),
            _make_alert(id="fp1", classification=AlertClassification.false_positive),
            _make_alert(id="bp1", classification=AlertClassification.benign_positive),
        ]
        rollup = compute_daily_rollup(alerts, TARGET_DATE)
        assert rollup.total_alerts == 4

        counts = {cc.classification: cc for cc in rollup.classification_counts}
        assert counts[AlertClassification.true_positive].count == 2
        assert counts[AlertClassification.true_positive].percentage == 50.0
        assert counts[AlertClassification.false_positive].count == 1
        assert counts[AlertClassification.false_positive].percentage == 25.0
        assert counts[AlertClassification.benign_positive].count == 1
        assert counts[AlertClassification.undetermined].count == 0

    def test_mttr_computation(self) -> None:
        """MTTR is average of resolved alerts' close times."""
        created = datetime(2026, 5, 20, 10, 0, tzinfo=timezone.utc)
        a1 = _make_alert(id="a1", created=created, resolved=created + timedelta(hours=2))
        a2 = _make_alert(id="a2", created=created, resolved=created + timedelta(hours=4))
        rollup = compute_daily_rollup([a1, a2], TARGET_DATE)
        assert rollup.mean_time_to_close_hours == 3.0

    def test_mttr_none_when_no_resolved(self) -> None:
        a = _make_alert(status=AlertStatus.new, resolved=None)
        rollup = compute_daily_rollup([a], TARGET_DATE)
        assert rollup.mean_time_to_close_hours is None

    def test_severity_breakdown(self) -> None:
        alerts = [
            _make_alert(id="h1", severity=AlertSeverity.high),
            _make_alert(id="h2", severity=AlertSeverity.high),
            _make_alert(id="m1", severity=AlertSeverity.medium),
        ]
        rollup = compute_daily_rollup(alerts, TARGET_DATE)
        assert rollup.severity_breakdown["high"] == 2
        assert rollup.severity_breakdown["medium"] == 1

    def test_top_titles_ordered_by_count(self) -> None:
        alerts = [
            _make_alert(id="a1", title="Frequent Alert"),
            _make_alert(id="a2", title="Frequent Alert"),
            _make_alert(id="a3", title="Rare Alert"),
        ]
        rollup = compute_daily_rollup(alerts, TARGET_DATE)
        assert rollup.top_titles[0].title == "Frequent Alert"
        assert rollup.top_titles[0].count == 2
        assert rollup.top_titles[1].title == "Rare Alert"
        assert rollup.top_titles[1].count == 1

    def test_top_titles_classification_breakdown(self) -> None:
        alerts = [
            _make_alert(id="a1", title="Mixed", classification=AlertClassification.true_positive),
            _make_alert(id="a2", title="Mixed", classification=AlertClassification.false_positive),
        ]
        rollup = compute_daily_rollup(alerts, TARGET_DATE)
        title = rollup.top_titles[0]
        assert title.tp == 1
        assert title.fp == 1

    def test_top_titles_mitre_techniques(self) -> None:
        alerts = [
            _make_alert(id="a1", title="MDE", mitre=["T1059", "T1071"]),
            _make_alert(id="a2", title="MDE", mitre=["T1059", "T1078"]),
        ]
        rollup = compute_daily_rollup(alerts, TARGET_DATE)
        assert set(rollup.top_titles[0].mitre_techniques) == {"T1059", "T1071", "T1078"}

    def test_still_open(self) -> None:
        alerts = [
            _make_alert(id="open1", status=AlertStatus.new, resolved=None),
            _make_alert(id="closed1", status=AlertStatus.resolved),
        ]
        rollup = compute_daily_rollup(alerts, TARGET_DATE)
        assert len(rollup.still_open) == 1
        assert rollup.still_open[0].id == "open1"

    def test_rule_effectiveness(self) -> None:
        alerts = [
            _make_alert(id="a1", rule_name="RuleA", classification=AlertClassification.true_positive),
            _make_alert(id="a2", rule_name="RuleA", classification=AlertClassification.false_positive),
            _make_alert(id="a3", rule_name="RuleB", classification=AlertClassification.true_positive),
        ]
        rollup = compute_daily_rollup(alerts, TARGET_DATE)
        rules = {r.rule_name: r for r in rollup.rule_effectiveness}
        assert rules["RuleA"].total == 2
        assert rules["RuleA"].tp_rate == 50.0
        assert rules["RuleA"].fp_rate == 50.0
        assert rules["RuleB"].tp_rate == 100.0


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


class TestRenderRollupMarkdown:
    def test_header_contains_date(self) -> None:
        rollup = compute_daily_rollup([], TARGET_DATE)
        md = render_rollup_markdown(rollup)
        assert "2026-05-20" in md

    def test_contains_summary_section(self) -> None:
        alerts = [_make_alert()]
        rollup = compute_daily_rollup(alerts, TARGET_DATE)
        md = render_rollup_markdown(rollup)
        assert "## Summary" in md
        assert "**Total alerts**: 1" in md

    def test_contains_classification_table(self) -> None:
        alerts = [_make_alert()]
        rollup = compute_daily_rollup(alerts, TARGET_DATE)
        md = render_rollup_markdown(rollup)
        assert "## Classification Breakdown" in md
        assert "True Positive" in md

    def test_contains_top_titles(self) -> None:
        alerts = [_make_alert(title="Suspicious Login")]
        rollup = compute_daily_rollup(alerts, TARGET_DATE)
        md = render_rollup_markdown(rollup)
        assert "## Top Titles" in md
        assert "Suspicious Login" in md

    def test_still_open_section(self) -> None:
        alerts = [_make_alert(status=AlertStatus.new, resolved=None)]
        rollup = compute_daily_rollup(alerts, TARGET_DATE)
        md = render_rollup_markdown(rollup)
        assert "## Still Open" in md
        assert "1 alert(s)" in md


# ---------------------------------------------------------------------------
# JSON rendering
# ---------------------------------------------------------------------------


class TestRenderRollupJson:
    def test_structure(self) -> None:
        alerts = [
            _make_alert(id="a1", classification=AlertClassification.true_positive),
            _make_alert(id="a2", classification=AlertClassification.false_positive),
        ]
        rollup = compute_daily_rollup(alerts, TARGET_DATE)
        data = render_rollup_json(rollup)

        assert data["date"] == "2026-05-20"
        assert data["total_alerts"] == 2
        assert "true_positive" in data["classification_counts"]
        assert data["classification_counts"]["true_positive"]["count"] == 1
        assert isinstance(data["top_titles"], list)
        assert isinstance(data["rule_effectiveness"], list)

    def test_json_serializable(self) -> None:
        rollup = compute_daily_rollup([], TARGET_DATE)
        data = render_rollup_json(rollup)
        # Must not raise
        json.dumps(data)


# ---------------------------------------------------------------------------
# Trend report
# ---------------------------------------------------------------------------


class TestComputeTrendReport:
    def test_empty_alerts(self) -> None:
        report = compute_trend_report([], 7, end_date=TARGET_DATE)
        assert report.period_days == 7
        assert report.total_alerts == 0
        assert len(report.daily_volumes) == 7
        assert report.unresolved_backlog == 0

    def test_daily_volumes(self) -> None:
        alerts = [
            _make_alert(id="a1", created=datetime(2026, 5, 20, 10, 0, tzinfo=timezone.utc)),
            _make_alert(id="a2", created=datetime(2026, 5, 19, 10, 0, tzinfo=timezone.utc)),
        ]
        report = compute_trend_report(alerts, 3, end_date=TARGET_DATE)
        assert report.total_alerts == 2
        # Day volumes for 2026-05-18, 2026-05-19, 2026-05-20
        assert len(report.daily_volumes) == 3

    def test_noisiest_rules(self) -> None:
        """Rules with high FP rates surface in noisiest_rules."""
        alerts = [
            _make_alert(id="a1", title="NoisyRule", classification=AlertClassification.false_positive),
            _make_alert(id="a2", title="NoisyRule", classification=AlertClassification.false_positive),
            _make_alert(id="a3", title="GoodRule", classification=AlertClassification.true_positive),
            _make_alert(id="a4", title="GoodRule", classification=AlertClassification.true_positive),
        ]
        report = compute_trend_report(alerts, 1, end_date=TARGET_DATE)
        noisy_names = [r.rule_name for r in report.noisiest_rules]
        assert "NoisyRule" in noisy_names
        assert "GoodRule" not in noisy_names  # 0 FP -> excluded

    def test_unresolved_backlog(self) -> None:
        alerts = [
            _make_alert(id="open1", status=AlertStatus.new, resolved=None),
            _make_alert(id="closed1", status=AlertStatus.resolved),
        ]
        report = compute_trend_report(alerts, 1, end_date=TARGET_DATE)
        assert report.unresolved_backlog == 1


class TestRenderTrendMarkdown:
    def test_header(self) -> None:
        report = compute_trend_report([], 7, end_date=TARGET_DATE)
        md = render_trend_markdown(report)
        assert "Alert Trend Report" in md
        assert "2026-05-20" in md

    def test_contains_sections(self) -> None:
        alerts = [_make_alert()]
        report = compute_trend_report(alerts, 1, end_date=TARGET_DATE)
        md = render_trend_markdown(report)
        assert "## Daily Volume" in md
        assert "## Classification Trend" in md
        assert "## MTTR Trend" in md


class TestRenderTrendJson:
    def test_serializable(self) -> None:
        report = compute_trend_report([], 3, end_date=TARGET_DATE)
        data = render_trend_json(report)
        json.dumps(data)  # must not raise
        assert data["period_days"] == 3
        assert len(data["daily_volumes"]) == 3
