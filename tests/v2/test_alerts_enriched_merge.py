# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the triple-source alert merge: ARM overlay, Graph enrichment,
and daily file patching.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from contentops.alerts.ledger import LedgerEntry, load_ledger, write_daily_file
from contentops.alerts.merge import (
    apply_arm_overlay_to_daily_files,
    enrich_from_graph,
    overlay_arm_incidents,
)
from contentops.alerts.models import (
    AlertClassification,
    AlertDetermination,
    AlertSeverity,
    AlertStatus,
    NormalizedAlert,
)


def _alert(
    id: str = "sa-1",
    classification: AlertClassification = AlertClassification.undetermined,
    status: AlertStatus = AlertStatus.new,
    incident_id: str | None = None,
    resolved: datetime | None = None,
    mitre_techniques: list[str] | None = None,
    detection_source: str = "",
    rule_id: str = "",
) -> NormalizedAlert:
    return NormalizedAlert(
        id=id,
        title="Test Alert",
        severity=AlertSeverity.medium,
        status=status,
        classification=classification,
        determination=AlertDetermination.unknown,
        source="sentinel",
        service_source="test",
        incident_id=incident_id,
        resolved=resolved,
        mitre_techniques=mitre_techniques or [],
        detection_source=detection_source,
        rule_id=rule_id,
    )


def _graph_alert(
    provider_alert_id: str = "sa-1",
    mitre: list[str] | None = None,
    detection_source: str = "customDetection",
    rule_id: str = "detector-123",
) -> NormalizedAlert:
    return NormalizedAlert(
        id=f"graph-{provider_alert_id}",
        title="Test Alert",
        severity=AlertSeverity.medium,
        status=AlertStatus.new,
        classification=AlertClassification.undetermined,
        determination=AlertDetermination.unknown,
        source="graph",
        service_source="microsoftDefenderForEndpoint",
        provider_alert_id=provider_alert_id,
        mitre_techniques=mitre or ["T1059"],
        detection_source=detection_source,
        rule_id=rule_id,
    )


def _arm_incident(
    incident_number: int = 100,
    status: str = "Closed",
    classification: str = "FalsePositive",
    classification_reason: str = "InaccurateData",
    closed_time: str = "2026-05-26T14:00:00Z",
    alert_product_ids: list[str] | None = None,
) -> dict:
    return {
        "properties": {
            "incidentNumber": incident_number,
            "status": status,
            "classification": classification,
            "classificationReason": classification_reason,
            "closedTimeUtc": closed_time if status == "Closed" else None,
            "owner": {"assignedTo": "analyst@test.com"},
            "additionalData": {
                "alertProductIds": alert_product_ids or [],
            },
        },
    }


# ---------------------------------------------------------------------------
# overlay_arm_incidents (in-memory)
# ---------------------------------------------------------------------------


class TestOverlayArmIncidents:
    def test_updates_classification(self) -> None:
        alerts = [_alert(id="sa-1", incident_id="100")]
        incidents = [_arm_incident(incident_number=100, alert_product_ids=["sa-1"])]
        result = overlay_arm_incidents(alerts, incidents)
        assert result[0].classification == AlertClassification.false_positive

    def test_updates_resolved(self) -> None:
        alerts = [_alert(id="sa-1", incident_id="100")]
        incidents = [_arm_incident(incident_number=100, alert_product_ids=["sa-1"])]
        result = overlay_arm_incidents(alerts, incidents)
        assert result[0].resolved is not None
        assert result[0].status == AlertStatus.resolved

    def test_reopened_clears_resolved(self) -> None:
        resolved_time = datetime(2026, 5, 26, 14, 0, tzinfo=timezone.utc)
        alerts = [_alert(id="sa-1", incident_id="100", resolved=resolved_time,
                         status=AlertStatus.resolved,
                         classification=AlertClassification.false_positive)]
        incidents = [_arm_incident(incident_number=100, status="Active",
                                   classification="", classification_reason="",
                                   alert_product_ids=["sa-1"])]
        result = overlay_arm_incidents(alerts, incidents)
        assert result[0].resolved is None
        assert result[0].status == AlertStatus.in_progress

    def test_no_match_passthrough(self) -> None:
        alerts = [_alert(id="sa-1")]
        incidents = [_arm_incident(alert_product_ids=["sa-99"])]
        result = overlay_arm_incidents(alerts, incidents)
        assert result[0].classification == AlertClassification.undetermined

    def test_empty_incidents(self) -> None:
        alerts = [_alert(id="sa-1")]
        result = overlay_arm_incidents(alerts, [])
        assert len(result) == 1
        assert result[0].classification == AlertClassification.undetermined

    def test_fallback_to_incident_number(self) -> None:
        alerts = [_alert(id="sa-1", incident_id="100")]
        incidents = [_arm_incident(incident_number=100, alert_product_ids=[])]
        result = overlay_arm_incidents(alerts, incidents)
        assert result[0].classification == AlertClassification.false_positive


# ---------------------------------------------------------------------------
# apply_arm_overlay_to_daily_files
# ---------------------------------------------------------------------------


class TestArmDailyFilePatching:
    def _write_entry(self, daily_dir: Path, date_str: str, entry: LedgerEntry) -> None:
        write_daily_file(daily_dir / f"{date_str}.jsonl", [entry])

    def test_patches_correct_file(self, tmp_path: Path) -> None:
        daily_dir = tmp_path / "daily"
        daily_dir.mkdir()
        entry = LedgerEntry(
            alert_id="sa-1", rule_display_name="Test",
            classification="undetermined", closed_at=None,
            severity="medium", source="sentinel",
            created_at="2026-05-25T10:00:00+00:00",
            incident_number=100,
        )
        self._write_entry(daily_dir, "2026-05-25", entry)
        incidents = [_arm_incident(incident_number=100, alert_product_ids=["sa-1"])]

        files_patched, entries_updated = apply_arm_overlay_to_daily_files(daily_dir, incidents)
        assert files_patched == 1
        assert entries_updated == 1

        patched = load_ledger(daily_dir / "2026-05-25.jsonl")
        assert patched[0].classification == "falsePositive"
        assert patched[0].closed_at is not None

    def test_reopened_clears_closure(self, tmp_path: Path) -> None:
        daily_dir = tmp_path / "daily"
        daily_dir.mkdir()
        entry = LedgerEntry(
            alert_id="sa-1", rule_display_name="Test",
            classification="falsePositive", closed_at="2026-05-26T14:00:00+00:00",
            severity="medium", source="sentinel",
            created_at="2026-05-25T10:00:00+00:00",
            incident_number=100,
        )
        self._write_entry(daily_dir, "2026-05-25", entry)
        incidents = [_arm_incident(incident_number=100, status="Active",
                                   classification="", classification_reason="",
                                   alert_product_ids=["sa-1"])]

        files_patched, entries_updated = apply_arm_overlay_to_daily_files(daily_dir, incidents)
        assert entries_updated == 1

        patched = load_ledger(daily_dir / "2026-05-25.jsonl")
        assert patched[0].closed_at is None
        assert patched[0].classification == "undetermined"

    def test_skips_up_to_date_entries(self, tmp_path: Path) -> None:
        daily_dir = tmp_path / "daily"
        daily_dir.mkdir()
        entry = LedgerEntry(
            alert_id="sa-1", rule_display_name="Test",
            classification="falsePositive", closed_at="2026-05-26T14:00:00+00:00",
            severity="medium", source="both",
            created_at="2026-05-25T10:00:00+00:00",
            incident_number=100,
        )
        self._write_entry(daily_dir, "2026-05-25", entry)
        incidents = [_arm_incident(incident_number=100, alert_product_ids=["sa-1"])]

        _, entries_updated = apply_arm_overlay_to_daily_files(daily_dir, incidents)
        assert entries_updated == 0

    def test_empty_daily_dir(self, tmp_path: Path) -> None:
        daily_dir = tmp_path / "daily"
        daily_dir.mkdir()
        files_patched, entries_updated = apply_arm_overlay_to_daily_files(daily_dir, [])
        assert files_patched == 0
        assert entries_updated == 0


# ---------------------------------------------------------------------------
# enrich_from_graph
# ---------------------------------------------------------------------------


class TestGraphEnrichment:
    def test_adds_mitre(self) -> None:
        alerts = [_alert(id="sa-1")]
        graph = [_graph_alert(provider_alert_id="sa-1", mitre=["T1059", "T1071"])]
        result = enrich_from_graph(alerts, graph)
        assert result[0].mitre_techniques == ["T1059", "T1071"]

    def test_no_overwrite_existing_mitre(self) -> None:
        alerts = [_alert(id="sa-1", mitre_techniques=["T1003"])]
        graph = [_graph_alert(provider_alert_id="sa-1", mitre=["T1059"])]
        result = enrich_from_graph(alerts, graph)
        assert result[0].mitre_techniques == ["T1003"]

    def test_no_match(self) -> None:
        alerts = [_alert(id="sa-1")]
        graph = [_graph_alert(provider_alert_id="sa-99")]
        result = enrich_from_graph(alerts, graph)
        assert result[0].mitre_techniques == []

    def test_empty_graph(self) -> None:
        alerts = [_alert(id="sa-1")]
        result = enrich_from_graph(alerts, [])
        assert len(result) == 1

    def test_adds_detection_source(self) -> None:
        alerts = [_alert(id="sa-1", detection_source="")]
        graph = [_graph_alert(provider_alert_id="sa-1", detection_source="customDetection")]
        result = enrich_from_graph(alerts, graph)
        assert result[0].detection_source == "customDetection"


# ---------------------------------------------------------------------------
# Full three-way pipeline
# ---------------------------------------------------------------------------


class TestFullPipeline:
    def test_kql_plus_arm_plus_graph(self) -> None:
        # KQL alert with incident data (but classification undetermined)
        alerts = [_alert(id="sa-1", incident_id="100",
                         status=AlertStatus.new,
                         classification=AlertClassification.undetermined)]

        # ARM says incident is closed as FP
        arm = [_arm_incident(incident_number=100,
                             classification="FalsePositive",
                             alert_product_ids=["sa-1"])]

        # Graph has MITRE data
        graph = [_graph_alert(provider_alert_id="sa-1",
                              mitre=["T1059.001"])]

        # Apply ARM overlay
        enriched = overlay_arm_incidents(alerts, arm)
        assert enriched[0].classification == AlertClassification.false_positive
        assert enriched[0].resolved is not None

        # Apply Graph enrichment
        final = enrich_from_graph(enriched, graph)
        assert final[0].mitre_techniques == ["T1059.001"]
        assert final[0].classification == AlertClassification.false_positive
