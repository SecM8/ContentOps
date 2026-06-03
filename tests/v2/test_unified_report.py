# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the unified detection program report."""

from __future__ import annotations

from datetime import date

import pytest

from contentops.alerts.detection_health import (
    DetectionHealthReport,
    DetectionHealthRow,
    OwnerSummary,
)
from contentops.alerts.daily_store import DailyRollupEntry
from contentops.report.assemble import ReportRow, ReportSummary
from contentops.report.unified import (
    _daily_fp_rate_trend,
    _daily_mttr_trend,
    _friendly_service_source,
    _render_alerts_overview,
    _svg_bar_sparkline,
    _svg_horizontal_bars,
    _svg_line_trend,
    compute_posture_score,
    render_unified_html,
)


def _roll(
    date_str: str, *, tp: int = 0, fp: int = 0, benign: int = 0,
    undetermined: int = 0, resolved: int = 0, mean_close: float | None = None,
    name: str = "Rule X",
) -> DailyRollupEntry:
    return DailyRollupEntry(
        date=date_str, rule_display_name=name, version="1",
        asset_kind="sentinel_analytic", severity="high",
        alert_count=tp + fp + benign + undetermined, resolved_count=resolved,
        tp_count=tp, fp_count=fp, benign_count=benign,
        undetermined_count=undetermined, mean_close_hours=mean_close,
    )


def _summary(
    total: int = 100, production: int = 80,
    coverage_pct: int = 45,
) -> ReportSummary:
    return ReportSummary(
        total=total, production=production, experimental=15,
        deprecated=5, coverage_pct=coverage_pct,
        coverage_covered=45, coverage_total=100,
        generated_at="2026-05-25T12:00:00Z",
    )


def _health(
    healthy: int = 60, tune: int = 5, silent: int = 30, review: int = 5,
) -> DetectionHealthReport:
    rows = []
    for i in range(healthy):
        rows.append(DetectionHealthRow(
            detection_id=f"h-{i}", display_name=f"Healthy {i}",
            asset_kind="sentinel_analytic", severity="medium",
            status="production", mitre_techniques=(), owner="a@x.com",
            recommendation="HEALTHY", alert_count=10,
        ))
    for i in range(tune):
        rows.append(DetectionHealthRow(
            detection_id=f"t-{i}", display_name=f"Tune {i}",
            asset_kind="sentinel_analytic", severity="high",
            status="production", mitre_techniques=(), owner="b@x.com",
            recommendation="TUNE", alert_count=20, fp_count=12, fp_rate=60.0,
        ))
    for i in range(silent):
        rows.append(DetectionHealthRow(
            detection_id=f"s-{i}", display_name=f"Silent {i}",
            asset_kind="sentinel_analytic", severity="medium",
            status="production", mitre_techniques=(), owner="unassigned",
            recommendation="SILENT", silent_days=30,
        ))
    for i in range(review):
        rows.append(DetectionHealthRow(
            detection_id=f"r-{i}", display_name=f"Review {i}",
            asset_kind="sentinel_analytic", severity="low",
            status="production", mitre_techniques=(), owner="c@x.com",
            recommendation="REVIEW", alert_count=3,
        ))
    return DetectionHealthReport(
        period_days=30, start_date=date(2026, 4, 26),
        end_date=date(2026, 5, 25), rows=rows,
        total_detections=len(rows), matched_detections=healthy + tune + review,
        total_alerts=sum(r.alert_count for r in rows),
        owner_summary={
            "a@x.com": OwnerSummary(owner="a@x.com", total=healthy, healthy_count=healthy),
            "b@x.com": OwnerSummary(owner="b@x.com", total=tune, tune_count=tune),
            "c@x.com": OwnerSummary(owner="c@x.com", total=review, review_count=review),
            "unassigned": OwnerSummary(owner="unassigned", total=silent, silent_count=silent),
        },
    )


class TestPostureScore:
    def test_high_score_for_good_posture(self) -> None:
        score = compute_posture_score(_summary(coverage_pct=80), _health(healthy=90, tune=0, silent=5, review=5))
        assert score >= 60

    def test_low_score_for_poor_posture(self) -> None:
        score = compute_posture_score(_summary(coverage_pct=10), _health(healthy=5, tune=20, silent=70, review=5))
        assert score <= 30

    def test_score_without_health(self) -> None:
        score = compute_posture_score(_summary(coverage_pct=50), None)
        assert 0 <= score <= 100


class TestRenderUnifiedHtml:
    def test_contains_all_sections(self) -> None:
        html = render_unified_html([], _summary(), health=_health())
        assert "Executive Summary" in html
        assert "Security Posture" in html
        assert "Team Performance" in html
        assert "Detection Detail" in html
        assert "Threat Coverage" in html

    def test_contains_posture_score(self) -> None:
        html = render_unified_html([], _summary(), health=_health())
        assert "Security Posture Score" in html

    def test_contains_owner_accountability(self) -> None:
        html = render_unified_html([], _summary(), health=_health())
        assert "Owner Accountability" in html
        assert "a@x.com" in html

    def test_risk_warning_for_silent_high(self) -> None:
        health = _health(healthy=0, tune=0, silent=5, review=0)
        html = render_unified_html([], _summary(), health=health)
        assert "SILENT" in html
        assert "Risk" in html

    def test_renders_without_health(self) -> None:
        html = render_unified_html([], _summary())
        assert "Detection Program Report" in html

    def test_contains_alerts_overview_section(self) -> None:
        html = render_unified_html([], _summary(), health=_health())
        assert "Alerts Overview" in html

    def test_alerts_overview_with_daily_data(self) -> None:
        daily = [
            DailyRollupEntry(
                date="2026-05-24", rule_display_name="Rule A",
                version="1", asset_kind="sentinel_analytic", severity="high",
                alert_count=10, resolved_count=8, tp_count=6, fp_count=2,
                benign_count=1, undetermined_count=1, mean_close_hours=3.5,
            ),
            DailyRollupEntry(
                date="2026-05-25", rule_display_name="Rule B",
                version="1", asset_kind="sentinel_analytic", severity="medium",
                alert_count=5, resolved_count=3, tp_count=2, fp_count=1,
                benign_count=1, undetermined_count=1, mean_close_hours=6.0,
            ),
        ]
        html = render_unified_html(
            [], _summary(), health=_health(), daily=daily,
        )
        assert "Daily Alert Volume" in html
        assert "Top 5 Triggered" in html

    def test_alerts_overview_with_service_sources(self) -> None:
        html = render_unified_html(
            [], _summary(), health=_health(),
            service_source_counts={
                "microsoftDefenderForEndpoint": 120,
                "sentinel": 45,
            },
        )
        assert "Alert Sources" in html
        assert "Defender for Endpoint" in html


def _daily_entries() -> list[DailyRollupEntry]:
    return [
        DailyRollupEntry(
            date=f"2026-05-{d:02d}", rule_display_name="Rule X",
            version="1", asset_kind="sentinel_analytic", severity="high",
            alert_count=d * 2, resolved_count=d, tp_count=d, fp_count=0,
            benign_count=0, undetermined_count=0, mean_close_hours=2.0,
        )
        for d in range(12, 26)
    ]


class TestSvgHelpers:
    def test_horizontal_bars_produces_svg(self) -> None:
        svg = _svg_horizontal_bars([
            ("Label A", 10, "#ff0000"),
            ("Label B", 5, "#00ff00"),
        ])
        assert "<svg" in svg
        assert "<rect" in svg
        assert "Label A" in svg

    def test_horizontal_bars_empty(self) -> None:
        assert _svg_horizontal_bars([]) == ""

    def test_bar_sparkline_produces_svg(self) -> None:
        data = [("05-20", 10), ("05-21", 20), ("05-22", 15)]
        svg = _svg_bar_sparkline(data)
        assert "<svg" in svg
        assert "<rect" in svg

    def test_bar_sparkline_empty(self) -> None:
        assert _svg_bar_sparkline([]) == ""

    def test_bar_sparkline_single_day(self) -> None:
        svg = _svg_bar_sparkline([("05-25", 42)])
        assert "<svg" in svg


class TestRenderAlertsOverview:
    def test_classification_breakdown_with_health(self) -> None:
        html = _render_alerts_overview(_health(), [])
        assert "Classification Breakdown" in html
        assert "True Positive" in html
        assert "False Positive" in html

    def test_daily_volume_trend(self) -> None:
        html = _render_alerts_overview(None, _daily_entries())
        assert "Daily Alert Volume" in html

    def test_service_source_breakdown(self) -> None:
        html = _render_alerts_overview(
            None, [],
            service_source_counts={"microsoftDefenderForEndpoint": 50},
        )
        assert "Alert Sources" in html
        assert "Defender for Endpoint" in html

    def test_mttr_summary(self) -> None:
        health = _health(healthy=10, tune=0, silent=0, review=0)
        html = _render_alerts_overview(health, [])
        assert "Mean Time to Resolve" not in html
        rows = [
            DetectionHealthRow(
                detection_id="m-0", display_name="MTTR Rule",
                asset_kind="sentinel_analytic", severity="medium",
                status="production", mitre_techniques=(), owner="a@x.com",
                recommendation="HEALTHY", alert_count=20,
                mean_time_to_close_hours=4.5,
            ),
        ]
        health_with_mttr = DetectionHealthReport(
            period_days=30, start_date=date(2026, 4, 26),
            end_date=date(2026, 5, 25), rows=rows,
            total_detections=1, matched_detections=1,
            total_alerts=20,
        )
        html = _render_alerts_overview(health_with_mttr, [])
        assert "Mean Time to Resolve" in html
        assert "4.5h" in html

    def test_no_data_message(self) -> None:
        html = _render_alerts_overview(None, [])
        assert "No alert data available" in html

    def test_top5_triggered(self) -> None:
        html = _render_alerts_overview(None, _daily_entries())
        assert "Top 5 Triggered" in html
        assert "Rule X" in html

    def test_empty_service_source_dict_no_crash(self) -> None:
        html = _render_alerts_overview(None, [], service_source_counts={})
        assert "No alert data available" in html
        assert "Alert Sources" not in html

    def test_zero_alerts_skips_classification(self) -> None:
        rows = [
            DetectionHealthRow(
                detection_id=f"s-{i}", display_name=f"Silent {i}",
                asset_kind="sentinel_analytic", severity="medium",
                status="production", mitre_techniques=(), owner="unassigned",
                recommendation="SILENT", alert_count=0,
            )
            for i in range(5)
        ]
        health = DetectionHealthReport(
            period_days=30, start_date=date(2026, 4, 26),
            end_date=date(2026, 5, 25), rows=rows,
            total_detections=5, matched_detections=0, total_alerts=0,
        )
        html = _render_alerts_overview(health, [])
        assert "Classification Breakdown" not in html


def _mttr_health(hours: float) -> DetectionHealthReport:
    rows = [
        DetectionHealthRow(
            detection_id="m-0", display_name="MTTR Rule",
            asset_kind="sentinel_analytic", severity="medium",
            status="production", mitre_techniques=(), owner="a@x.com",
            recommendation="HEALTHY", alert_count=10,
            mean_time_to_close_hours=hours,
        ),
    ]
    return DetectionHealthReport(
        period_days=30, start_date=date(2026, 4, 26),
        end_date=date(2026, 5, 25), rows=rows,
        total_detections=1, matched_detections=1, total_alerts=10,
    )


class TestMttrColorThresholds:
    def test_green_under_4h(self) -> None:
        html = _render_alerts_overview(_mttr_health(3.5), [])
        assert "#188038" in html
        assert "3.5h" in html

    def test_amber_between_4h_and_24h(self) -> None:
        html = _render_alerts_overview(_mttr_health(12.0), [])
        assert "#f9ab00" in html
        assert "12.0h" in html

    def test_red_over_24h(self) -> None:
        html = _render_alerts_overview(_mttr_health(48.0), [])
        assert "#d93025" in html
        assert "48.0h" in html


class TestDailyTrendHelpers:
    def test_fp_rate_aggregates_across_rules_per_day(self) -> None:
        daily = [
            _roll("2026-05-20", tp=8, fp=2, name="A"),   # 10 classified, 2 fp
            _roll("2026-05-20", tp=0, fp=0, benign=10, name="B"),  # +10 classified, 0 fp
            _roll("2026-05-21", tp=5, fp=5, name="A"),   # 50%
        ]
        assert _daily_fp_rate_trend(daily) == [("2026-05-20", 10.0), ("2026-05-21", 50.0)]

    def test_fp_rate_skips_unclassified_days(self) -> None:
        # A day whose alerts are all unclassified contributes no FP signal.
        daily = [_roll("2026-05-20", tp=0, fp=0), _roll("2026-05-21", tp=3, fp=1)]
        assert _daily_fp_rate_trend(daily) == [("2026-05-21", 25.0)]

    def test_fp_rate_caps_to_last_14_days(self) -> None:
        daily = [_roll(f"2026-05-{d:02d}", tp=1, fp=1) for d in range(1, 21)]
        trend = _daily_fp_rate_trend(daily)
        assert len(trend) == 14
        assert trend[-1][0] == "2026-05-20"

    def test_mttr_weighted_by_resolved(self) -> None:
        daily = [
            _roll("2026-05-20", resolved=3, mean_close=2.0),
            _roll("2026-05-20", resolved=1, mean_close=8.0),  # (2*3+8*1)/4 = 3.5
            _roll("2026-05-21", resolved=2, mean_close=4.0),
        ]
        assert _daily_mttr_trend(daily) == [("2026-05-20", 3.5), ("2026-05-21", 4.0)]

    def test_mttr_skips_no_resolution(self) -> None:
        daily = [
            _roll("2026-05-20", resolved=0, mean_close=None),
            _roll("2026-05-21", resolved=2, mean_close=5.0),
        ]
        assert _daily_mttr_trend(daily) == [("2026-05-21", 5.0)]


class TestSvgLineTrend:
    def test_empty(self) -> None:
        assert _svg_line_trend([]) == ""

    def test_single_point_has_marker_no_line(self) -> None:
        svg = _svg_line_trend([("05-20", 12.0)], value_suffix="%")
        assert "<circle" in svg
        assert "<polyline" not in svg

    def test_multi_point_has_polyline_and_suffix(self) -> None:
        svg = _svg_line_trend(
            [("05-20", 10.0), ("05-21", 50.0)], value_suffix="%",
        )
        assert "<polyline" in svg
        assert "50%" in svg  # max y-axis label carries the suffix


class TestTrendRendering:
    def test_fp_and_mttr_trends_render(self) -> None:
        daily = [
            _roll("2026-05-20", tp=8, fp=2, resolved=5, mean_close=3.0),
            _roll("2026-05-21", tp=5, fp=5, resolved=4, mean_close=6.0),
        ]
        html = _render_alerts_overview(None, daily)
        assert "False-Positive Rate (last 14 days)" in html
        assert "Resolution Time Trend (last 14 days)" in html

    def test_trends_absent_with_single_day(self) -> None:
        # A trend needs >= 2 days; one day shows volume but no trend lines.
        html = _render_alerts_overview(
            None, [_roll("2026-05-20", tp=8, fp=2, resolved=5, mean_close=3.0)],
        )
        assert "False-Positive Rate (last 14 days)" not in html
        assert "Resolution Time Trend (last 14 days)" not in html


class TestFriendlyServiceSource:
    def test_known_label(self) -> None:
        assert _friendly_service_source("microsoftDefenderForEndpoint") == "Defender for Endpoint"

    def test_unknown_fallback(self) -> None:
        assert _friendly_service_source("microsoftCustomThing") == "Microsoft CustomThing"

    def test_no_microsoft_prefix(self) -> None:
        assert _friendly_service_source("someProvider") == "someProvider"

    def test_escapes_html(self) -> None:
        result = _friendly_service_source('<script>microsoft</script>')
        assert "<script>" not in result
        assert "&lt;script&gt;" in result
