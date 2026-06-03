# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for detection health engine, mapping, recommendations,
rendering, enrichment, snapshot/delta, and badge.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from contentops.alerts.detection_health import (
    DetectionHealthReport,
    DetectionHealthRow,
    OwnerSummary,
    _build_detection_alert_map,
    _compute_recommendation,
    compute_detection_health,
    render_health_csv,
    render_health_json,
    render_health_markdown,
)
from contentops.alerts.health_badge import render_health_badge
from contentops.alerts.health_snapshot import (
    HealthDelta,
    RecommendationChange,
    compute_health_delta,
    find_previous_health_snapshot,
    load_health_snapshot,
    render_health_snapshot,
)
from contentops.alerts.models import (
    AlertClassification,
    AlertDetermination,
    AlertSeverity,
    AlertStatus,
    NormalizedAlert,
)
from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_alert(
    *,
    id: str = "a1",
    title: str = "Test Alert",
    classification: AlertClassification = AlertClassification.true_positive,
    status: AlertStatus = AlertStatus.resolved,
    created: datetime | None = None,
    resolved: datetime | None = None,
    rule_id: str | None = None,
    source: str = "graph",
) -> NormalizedAlert:
    if created is None:
        created = datetime(2026, 5, 20, 10, 0, tzinfo=timezone.utc)
    if resolved is None and status == AlertStatus.resolved:
        resolved = created + timedelta(hours=2)
    return NormalizedAlert(
        id=id,
        title=title,
        severity=AlertSeverity.medium,
        status=status,
        classification=classification,
        determination=AlertDetermination.unknown,
        source=source,
        service_source="test",
        created=created,
        resolved=resolved,
        rule_id=rule_id,
    )


def _make_detection(
    *,
    id: str = "det-1",
    display_name: str = "Test Detection",
    arm_name: str | None = "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
    asset: Asset = Asset.SENTINEL_ANALYTIC,
    owner: str | None = None,
    severity: str = "medium",
) -> LoadedAsset:
    from contentops.core.metadata import RuleMetadata

    metadata: RuleMetadata | None = None
    if owner:
        metadata = RuleMetadata(
            owner=owner,
            runbookUrl="https://example.com/runbook",
            severity=severity,  # type: ignore[arg-type]
            tactics=["InitialAccess"],
            techniques=["T1078"],
            expectedAlertsPerDay=0,
            fpHandling="N/A",
        )

    envelope = EnvelopeV2(
        id=id,
        version="1.0.0",
        asset=asset,
        status="production",
        metadata=metadata,
        arm_name=arm_name,
    )
    payload: dict[str, Any] = {"displayName": display_name, "severity": severity.capitalize(), "techniques": ["T1078"]}
    return LoadedAsset(path=Path(f"detections/{asset.value}/{id}.yml"), envelope=envelope, payload=payload)


# ---------------------------------------------------------------------------
# Mapping tests
# ---------------------------------------------------------------------------


class TestDetectionAlertMapping:
    def test_sentinel_arm_guid_match(self) -> None:
        det = _make_detection(id="det-1", arm_name="abc-123")
        alert = _make_alert(
            rule_id="/subscriptions/sub/providers/Microsoft.SecurityInsights/alertRules/abc-123",
            source="sentinel",
        )
        matched, unmatched = _build_detection_alert_map([det], [alert])
        assert "det-1" in matched
        assert len(matched["det-1"]) == 1
        assert unmatched == 0

    def test_sentinel_bare_guid_match(self) -> None:
        det = _make_detection(id="det-1", arm_name="abc-123")
        alert = _make_alert(rule_id="abc-123", source="sentinel")
        matched, _ = _build_detection_alert_map([det], [alert])
        assert "det-1" in matched

    def test_graph_title_match(self) -> None:
        det = _make_detection(id="det-1", display_name="Failed Logins")
        alert = _make_alert(title="Failed Logins")
        matched, unmatched = _build_detection_alert_map([det], [alert])
        assert "det-1" in matched
        assert unmatched == 0

    def test_defender_numeric_arm_name(self) -> None:
        det = _make_detection(
            id="det-defender", arm_name="18210",
            asset=Asset.DEFENDER_CUSTOM_DETECTION,
        )
        alert = _make_alert(
            rule_id="/detectionRules/18210", source="sentinel",
        )
        matched, _ = _build_detection_alert_map([det], [alert])
        assert "det-defender" in matched

    def test_unmatched_alert_counted(self) -> None:
        det = _make_detection(id="det-1", display_name="Brute Force Detection")
        alert = _make_alert(title="Completely Different Alert Name")
        _, unmatched = _build_detection_alert_map([det], [alert])
        assert unmatched == 1

    def test_arm_match_takes_priority(self) -> None:
        det1 = _make_detection(id="det-arm", arm_name="guid-1", display_name="Same Title")
        det2 = _make_detection(id="det-title", arm_name="other-guid", display_name="Same Title")
        alert = _make_alert(
            title="Same Title", rule_id="guid-1", source="sentinel",
        )
        matched, _ = _build_detection_alert_map([det1, det2], [alert])
        assert "det-arm" in matched
        assert "det-title" not in matched

    def test_case_insensitive_title_match(self) -> None:
        det = _make_detection(id="det-1", display_name="Detection of Attempts")
        alert = _make_alert(title="detection of attempts")
        matched, _ = _build_detection_alert_map([det], [alert])
        assert "det-1" in matched

    def test_prefix_match_sentinel_format(self) -> None:
        det = _make_detection(id="det-1", display_name="Brute Force Attack")
        det = LoadedAsset(
            path=det.path, envelope=det.envelope,
            payload={**det.payload, "alertDetailsOverride": {
                "alertDisplayNameFormat": "Brute Force Attack from {{IpAddress}}"
            }},
        )
        alert = _make_alert(title="Brute Force Attack from 10.0.0.1")
        matched, unmatched = _build_detection_alert_map([det], [alert])
        assert "det-1" in matched
        assert unmatched == 0

    def test_substring_match_mitre_prefix(self) -> None:
        det = _make_detection(id="det-1", display_name="T1087.001 Account Discovery: Local Account")
        alert = _make_alert(title="Account Discovery: Local Account")
        matched, _ = _build_detection_alert_map([det], [alert])
        assert "det-1" in matched

    def test_substring_match_dynamic_suffix(self) -> None:
        det = _make_detection(id="det-1", display_name="Failed Login Attempts Detected")
        alert = _make_alert(title="Failed Login Attempts Detected - john@contoso.com on WORKSTATION1")
        matched, _ = _build_detection_alert_map([det], [alert])
        assert "det-1" in matched

    def test_short_substring_no_match(self) -> None:
        det = _make_detection(id="det-1", display_name="Test")
        alert = _make_alert(title="Testing something entirely different")
        _, unmatched = _build_detection_alert_map([det], [alert])
        assert unmatched == 1


# ---------------------------------------------------------------------------
# Recommendation engine
# ---------------------------------------------------------------------------


class TestRecommendationEngine:
    def test_tune_when_fp_rate_above_40(self) -> None:
        assert _compute_recommendation(10, 3, 5, 50.0, "sentinel_analytic") == "TUNE"

    def test_silent_when_zero_alerts(self) -> None:
        assert _compute_recommendation(0, 0, 0, None, "sentinel_analytic") == "SILENT"

    def test_healthy_when_tp_rate_above_80(self) -> None:
        assert _compute_recommendation(10, 9, 0, 0.0, "sentinel_analytic") == "HEALTHY"

    def test_review_for_middleground(self) -> None:
        assert _compute_recommendation(10, 5, 2, 20.0, "sentinel_analytic") == "REVIEW"

    def test_boundary_fp_rate_exactly_40(self) -> None:
        assert _compute_recommendation(10, 3, 4, 40.0, "sentinel_analytic") == "REVIEW"

    def test_boundary_tp_rate_exactly_80(self) -> None:
        assert _compute_recommendation(10, 8, 0, 0.0, "sentinel_analytic") == "REVIEW"

    def test_expected_silent_for_hunting(self) -> None:
        assert _compute_recommendation(0, 0, 0, None, "sentinel_hunting") == "EXPECTED_SILENT"

    def test_expected_silent_even_with_alerts(self) -> None:
        assert _compute_recommendation(5, 3, 1, 20.0, "sentinel_hunting") == "EXPECTED_SILENT"


# ---------------------------------------------------------------------------
# Owner summary
# ---------------------------------------------------------------------------


class TestOwnerSummary:
    def test_single_owner(self) -> None:
        dets = [
            _make_detection(id="d1", owner="alice@example.com"),
            _make_detection(id="d2", owner="alice@example.com"),
        ]
        alerts = [
            _make_alert(id="a1", title="Test Detection", classification=AlertClassification.true_positive),
        ]
        # Override display names to match first detection only
        dets[0] = _make_detection(id="d1", display_name="Rule A", owner="alice@example.com")
        dets[1] = _make_detection(id="d2", display_name="Rule B", owner="alice@example.com")
        alerts = [_make_alert(id="a1", title="Rule A")]

        report = compute_detection_health(dets, alerts, 30, end_date=date(2026, 5, 24))
        assert "alice@example.com" in report.owner_summary
        os = report.owner_summary["alice@example.com"]
        assert os.total == 2

    def test_multiple_owners(self) -> None:
        dets = [
            _make_detection(id="d1", display_name="R1", owner="alice@x.com"),
            _make_detection(id="d2", display_name="R2", owner="bob@x.com"),
        ]
        report = compute_detection_health(dets, [], 30, end_date=date(2026, 5, 24))
        assert len(report.owner_summary) == 2

    def test_missing_owner_defaults_to_unassigned(self) -> None:
        dets = [_make_detection(id="d1", display_name="R1", owner=None)]
        report = compute_detection_health(dets, [], 30, end_date=date(2026, 5, 24))
        assert "unassigned" in report.owner_summary


# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------


class TestComputeDetectionHealth:
    def test_full_pipeline(self) -> None:
        dets = [
            _make_detection(id="d1", display_name="Rule A", owner="a@x.com"),
            _make_detection(id="d2", display_name="Rule B", owner="b@x.com"),
        ]
        alerts = [
            _make_alert(id="a1", title="Rule A", classification=AlertClassification.true_positive),
            _make_alert(id="a2", title="Rule A", classification=AlertClassification.false_positive),
            _make_alert(id="a3", title="Rule A", classification=AlertClassification.true_positive),
        ]
        report = compute_detection_health(dets, alerts, 30, end_date=date(2026, 5, 24))
        assert report.total_detections == 2
        assert report.matched_detections == 1
        assert report.total_alerts == 3
        assert report.unmatched_alerts == 0

        d1_row = next(r for r in report.rows if r.detection_id == "d1")
        assert d1_row.alert_count == 3
        assert d1_row.tp_count == 2
        assert d1_row.fp_count == 1
        assert d1_row.version == "1.0.0"

    def test_empty_alerts(self) -> None:
        dets = [_make_detection(id="d1", display_name="R1")]
        report = compute_detection_health(dets, [], 30, end_date=date(2026, 5, 24))
        assert report.matched_detections == 0
        assert all(r.recommendation == "SILENT" for r in report.rows)

    def test_empty_detections(self) -> None:
        alerts = [_make_alert(id="a1", title="Orphan")]
        report = compute_detection_health([], alerts, 30, end_date=date(2026, 5, 24))
        assert report.total_detections == 0
        assert report.unmatched_alerts == 1

    def test_silent_days_computed(self) -> None:
        dets = [_make_detection(id="d1", display_name="R1")]
        report = compute_detection_health(dets, [], 30, end_date=date(2026, 5, 24))
        assert report.rows[0].silent_days == 30

    def test_mttr_only_for_resolved(self) -> None:
        dets = [_make_detection(id="d1", display_name="R1")]
        created = datetime(2026, 5, 20, 10, 0, tzinfo=timezone.utc)
        alerts = [
            _make_alert(id="a1", title="R1", status=AlertStatus.resolved, created=created, resolved=created + timedelta(hours=4)),
            _make_alert(id="a2", title="R1", status=AlertStatus.new, created=created, resolved=None),
        ]
        report = compute_detection_health(dets, alerts, 30, end_date=date(2026, 5, 24))
        d1 = report.rows[0]
        assert d1.mean_time_to_close_hours == 4.0


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


class TestRenderHealthMarkdown:
    def test_markdown_contains_table_headers(self) -> None:
        report = DetectionHealthReport(
            period_days=30, start_date=date(2026, 4, 25),
            end_date=date(2026, 5, 24),
            rows=[DetectionHealthRow(
                detection_id="d1", display_name="R1", asset_kind="sentinel_analytic",
                severity="medium", status="production", mitre_techniques=("T1078",),
                owner="a@x.com", recommendation="HEALTHY", alert_count=10,
                tp_count=9, fp_count=0, tp_rate=90.0, fp_rate=0.0,
            )],
            total_detections=1, matched_detections=1,
        )
        md = render_health_markdown(report)
        assert "Detection Health Report" in md
        assert "| Detection | Version | Severity |" in md

    def test_tune_rules_listed_first(self) -> None:
        rows = [
            DetectionHealthRow(
                detection_id="healthy", display_name="Healthy Rule",
                asset_kind="sentinel_analytic", severity="low", status="production",
                mitre_techniques=(), owner="x", recommendation="HEALTHY",
            ),
            DetectionHealthRow(
                detection_id="tune", display_name="Tune Rule",
                asset_kind="sentinel_analytic", severity="high", status="production",
                mitre_techniques=(), owner="x", recommendation="TUNE",
                alert_count=10, fp_count=6, fp_rate=60.0,
            ),
        ]
        report = DetectionHealthReport(
            period_days=30, start_date=date(2026, 4, 25),
            end_date=date(2026, 5, 24), rows=rows,
            total_detections=2, matched_detections=1,
        )
        md = render_health_markdown(report)
        lines = md.split("\n")
        table_lines = [l for l in lines if l.startswith("| ") and "Tune Rule" in l or "Healthy Rule" in l]
        assert len(table_lines) >= 2
        tune_idx = next(i for i, l in enumerate(lines) if "Tune Rule" in l)
        healthy_idx = next(i for i, l in enumerate(lines) if "Healthy Rule" in l)
        assert tune_idx < healthy_idx

    def test_owner_summary_section(self) -> None:
        report = DetectionHealthReport(
            period_days=30, start_date=date(2026, 4, 25),
            end_date=date(2026, 5, 24), rows=[],
            total_detections=0, matched_detections=0,
            owner_summary={
                "alice@x.com": OwnerSummary(
                    owner="alice@x.com", total=5,
                    tune_count=1, silent_count=2, healthy_count=2,
                ),
            },
        )
        md = render_health_markdown(report)
        assert "Owner Summary" in md
        assert "alice@x.com" in md


class TestRenderHealthJson:
    def test_json_roundtrip(self) -> None:
        report = DetectionHealthReport(
            period_days=30, start_date=date(2026, 4, 25),
            end_date=date(2026, 5, 24),
            rows=[DetectionHealthRow(
                detection_id="d1", display_name="R1", asset_kind="sentinel_analytic",
                severity="medium", status="production", mitre_techniques=("T1078",),
                owner="a@x.com",
            )],
            total_detections=1, matched_detections=0,
        )
        data = render_health_json(report)
        text = json.dumps(data, default=str)
        reloaded = json.loads(text)
        assert reloaded["total_detections"] == 1
        assert len(reloaded["detections"]) == 1

    def test_all_fields_present(self) -> None:
        report = DetectionHealthReport(
            period_days=7, start_date=date(2026, 5, 18),
            end_date=date(2026, 5, 24),
            rows=[DetectionHealthRow(
                detection_id="d1", display_name="R1", asset_kind="sentinel_analytic",
                severity="high", status="production", mitre_techniques=(),
                owner="o@x.com", alert_count=5, tp_count=3, fp_count=1,
                fp_rate=20.0, tp_rate=60.0, mean_time_to_close_hours=1.5,
                silent_days=None, recommendation="REVIEW",
            )],
            total_detections=1, matched_detections=1,
        )
        data = render_health_json(report)
        det = data["detections"][0]
        expected_keys = {
            "detection_id", "display_name", "asset_kind", "severity", "status",
            "mitre_techniques", "owner", "version", "alert_count", "tp_count",
            "fp_count", "benign_count", "undetermined_count", "fp_rate",
            "tp_rate", "mean_time_to_close_hours", "silent_days",
            "recommendation", "expected_alerts_per_day", "volume_ratio",
        }
        assert set(det.keys()) == expected_keys


class TestRenderHealthCsv:
    def test_csv_output(self) -> None:
        report = DetectionHealthReport(
            period_days=30, start_date=date(2026, 4, 25),
            end_date=date(2026, 5, 24),
            rows=[DetectionHealthRow(
                detection_id="d1", display_name="R1", asset_kind="sentinel_analytic",
                severity="medium", status="production", mitre_techniques=("T1078",),
                owner="a@x.com", recommendation="HEALTHY",
            )],
            total_detections=1, matched_detections=0,
        )
        csv_text = render_health_csv(report)
        assert "detection_id" in csv_text
        assert "d1" in csv_text
        assert "T1078" in csv_text


# ---------------------------------------------------------------------------
# Enricher
# ---------------------------------------------------------------------------


class TestEnrichWithAlerts:
    def test_populates_existing_fields(self) -> None:
        from contentops.report.assemble import ReportRow
        from contentops.report.enrich import enrich_with_alerts

        rows = [ReportRow(
            rule_id="d1", asset_kind="sentinel_analytic", path="detections/d1.yml",
            title="R1", status="production", severity="medium",
            tactics=(), techniques=(), merge_date=None,
            deployment_date=None, last_review_date=None,
        )]
        health = DetectionHealthRow(
            detection_id="d1", display_name="R1", asset_kind="sentinel_analytic",
            severity="medium", status="production", mitre_techniques=(),
            owner="a@x.com", alert_count=50, tp_count=40, fp_count=5,
            fp_rate=10.0, tp_rate=80.0,
        )
        result = enrich_with_alerts(rows, {"d1": health})
        assert result[0].alerts_30d == 50
        assert result[0].true_positives_30d == 40
        assert result[0].false_positives_30d == 5

    def test_adds_new_fields(self) -> None:
        from contentops.report.assemble import ReportRow
        from contentops.report.enrich import enrich_with_alerts

        rows = [ReportRow(
            rule_id="d1", asset_kind="sentinel_analytic", path="detections/d1.yml",
            title="R1", status="production", severity="medium",
            tactics=(), techniques=(), merge_date=None,
            deployment_date=None, last_review_date=None,
        )]
        health = DetectionHealthRow(
            detection_id="d1", display_name="R1", asset_kind="sentinel_analytic",
            severity="medium", status="production", mitre_techniques=(),
            owner="a@x.com", silent_days=15, recommendation="SILENT",
        )
        result = enrich_with_alerts(rows, {"d1": health})
        assert result[0].alert_silent_days == 15
        assert result[0].alert_recommendation == "SILENT"

    def test_no_match_leaves_none(self) -> None:
        from contentops.report.assemble import ReportRow
        from contentops.report.enrich import enrich_with_alerts

        rows = [ReportRow(
            rule_id="d1", asset_kind="sentinel_analytic", path="detections/d1.yml",
            title="R1", status="production", severity="medium",
            tactics=(), techniques=(), merge_date=None,
            deployment_date=None, last_review_date=None,
        )]
        result = enrich_with_alerts(rows, {})
        assert result[0].alerts_30d is None
        assert result[0].alert_recommendation is None


# ---------------------------------------------------------------------------
# Snapshot + delta
# ---------------------------------------------------------------------------


class TestHealthSnapshot:
    def test_snapshot_roundtrip(self) -> None:
        report = DetectionHealthReport(
            period_days=30, start_date=date(2026, 4, 25),
            end_date=date(2026, 5, 24),
            rows=[DetectionHealthRow(
                detection_id="d1", display_name="R1", asset_kind="sentinel_analytic",
                severity="medium", status="production", mitre_techniques=(),
                owner="a@x.com", recommendation="HEALTHY", alert_count=10,
            )],
            total_detections=1, matched_detections=1,
        )
        snapshot_text = render_health_snapshot(report)
        data = json.loads(snapshot_text)
        assert data["schema_version"] == 1
        assert data["summary"]["total_detections"] == 1
        assert len(data["detections"]) == 1
        assert data["detections"][0]["detection_id"] == "d1"

    def test_delta_detects_new_tune(self) -> None:
        previous = {
            "generated_at": "2026-05-17T00:00:00Z",
            "detections": [
                {"detection_id": "d1", "recommendation": "HEALTHY"},
            ],
        }
        current = DetectionHealthReport(
            period_days=30, start_date=date(2026, 4, 25),
            end_date=date(2026, 5, 24),
            rows=[DetectionHealthRow(
                detection_id="d1", display_name="R1", asset_kind="sentinel_analytic",
                severity="medium", status="production", mitre_techniques=(),
                owner="a@x.com", recommendation="TUNE",
            )],
            total_detections=1, matched_detections=1,
        )
        delta = compute_health_delta(previous, current)
        assert "d1" in delta.new_tune_ids
        assert len(delta.recommendation_changes) == 1

    def test_delta_detects_resolved_tune(self) -> None:
        previous = {
            "generated_at": "2026-05-17T00:00:00Z",
            "detections": [
                {"detection_id": "d1", "recommendation": "TUNE"},
            ],
        }
        current = DetectionHealthReport(
            period_days=30, start_date=date(2026, 4, 25),
            end_date=date(2026, 5, 24),
            rows=[DetectionHealthRow(
                detection_id="d1", display_name="R1", asset_kind="sentinel_analytic",
                severity="medium", status="production", mitre_techniques=(),
                owner="a@x.com", recommendation="HEALTHY",
            )],
            total_detections=1, matched_detections=1,
        )
        delta = compute_health_delta(previous, current)
        assert "d1" in delta.resolved_tune_ids

    def test_delta_with_no_previous(self, tmp_path: Path) -> None:
        result = find_previous_health_snapshot(tmp_path, "2026-05-24")
        assert result is None

    def test_find_previous_snapshot(self, tmp_path: Path) -> None:
        (tmp_path / "2026-05-17-health.json").write_text("{}", encoding="utf-8")
        (tmp_path / "2026-05-20-health.json").write_text("{}", encoding="utf-8")
        result = find_previous_health_snapshot(tmp_path, "2026-05-24")
        assert result is not None
        assert result.name == "2026-05-20-health.json"

    def test_load_health_snapshot(self, tmp_path: Path) -> None:
        p = tmp_path / "test.json"
        p.write_text('{"schema_version": 1}', encoding="utf-8")
        data = load_health_snapshot(p)
        assert data is not None
        assert data["schema_version"] == 1

    def test_load_missing_returns_none(self, tmp_path: Path) -> None:
        assert load_health_snapshot(tmp_path / "nonexistent.json") is None


# ---------------------------------------------------------------------------
# Badge
# ---------------------------------------------------------------------------


class TestHealthBadge:
    def test_all_healthy_green(self) -> None:
        report = DetectionHealthReport(
            period_days=30, start_date=date(2026, 4, 25),
            end_date=date(2026, 5, 24),
            rows=[DetectionHealthRow(
                detection_id=f"d{i}", display_name=f"R{i}",
                asset_kind="sentinel_analytic", severity="medium",
                status="production", mitre_techniques=(), owner="a@x.com",
                recommendation="HEALTHY", alert_count=10,
            ) for i in range(10)],
            total_detections=10, matched_detections=10,
        )
        badge_text = render_health_badge(report)
        badge = json.loads(badge_text)
        assert badge["color"] == "brightgreen"
        assert "100% HEALTHY" in badge["message"]

    def test_some_tune_yellow(self) -> None:
        rows = [
            DetectionHealthRow(
                detection_id="d1", display_name="R1",
                asset_kind="sentinel_analytic", severity="medium",
                status="production", mitre_techniques=(), owner="a@x.com",
                recommendation="TUNE",
            ),
            DetectionHealthRow(
                detection_id="d2", display_name="R2",
                asset_kind="sentinel_analytic", severity="medium",
                status="production", mitre_techniques=(), owner="a@x.com",
                recommendation="TUNE",
            ),
            DetectionHealthRow(
                detection_id="d3", display_name="R3",
                asset_kind="sentinel_analytic", severity="medium",
                status="production", mitre_techniques=(), owner="a@x.com",
                recommendation="TUNE",
            ),
        ]
        rows += [
            DetectionHealthRow(
                detection_id=f"h{i}", display_name=f"H{i}",
                asset_kind="sentinel_analytic", severity="medium",
                status="production", mitre_techniques=(), owner="a@x.com",
                recommendation="HEALTHY", alert_count=10,
            ) for i in range(7)
        ]
        report = DetectionHealthReport(
            period_days=30, start_date=date(2026, 4, 25),
            end_date=date(2026, 5, 24), rows=rows,
            total_detections=10, matched_detections=7,
        )
        badge_text = render_health_badge(report)
        badge = json.loads(badge_text)
        assert badge["color"] == "yellow"
        assert "3 TUNE" in badge["message"]

    def test_many_tune_red(self) -> None:
        rows = [
            DetectionHealthRow(
                detection_id=f"d{i}", display_name=f"R{i}",
                asset_kind="sentinel_analytic", severity="medium",
                status="production", mitre_techniques=(), owner="a@x.com",
                recommendation="TUNE",
            ) for i in range(15)
        ]
        report = DetectionHealthReport(
            period_days=30, start_date=date(2026, 4, 25),
            end_date=date(2026, 5, 24), rows=rows,
            total_detections=15, matched_detections=15,
        )
        badge_text = render_health_badge(report)
        badge = json.loads(badge_text)
        assert badge["color"] == "red"
