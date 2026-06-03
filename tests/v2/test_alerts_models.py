# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for Pydantic alert models, classification mapping, and rollup math.

Covers:
* Enum round-trip and case-insensitive mapping.
* GraphAlert / SentinelIncident model validation.
* NormalizedAlert factory classmethods (from_graph, from_sentinel).
* Classification mapping edge cases.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from contentops.alerts.models import (
    AlertClassification,
    AlertDetermination,
    AlertSeverity,
    AlertStatus,
    GraphAlert,
    NormalizedAlert,
    SentinelIncident,
)


# ---------------------------------------------------------------------------
# Enum mapping tests
# ---------------------------------------------------------------------------


class TestAlertSeverity:
    def test_from_graph_case_insensitive(self) -> None:
        assert AlertSeverity.from_graph("High") == AlertSeverity.high
        assert AlertSeverity.from_graph("LOW") == AlertSeverity.low
        assert AlertSeverity.from_graph("Medium") == AlertSeverity.medium

    def test_from_graph_empty(self) -> None:
        assert AlertSeverity.from_graph("") == AlertSeverity.unknown

    def test_from_sentinel(self) -> None:
        assert AlertSeverity.from_sentinel("Informational") == AlertSeverity.informational


class TestAlertStatus:
    def test_from_graph_mapping(self) -> None:
        assert AlertStatus.from_graph("new") == AlertStatus.new
        assert AlertStatus.from_graph("inProgress") == AlertStatus.in_progress
        assert AlertStatus.from_graph("resolved") == AlertStatus.resolved
        assert AlertStatus.from_graph("") == AlertStatus.unknown

    def test_from_sentinel_mapping(self) -> None:
        assert AlertStatus.from_sentinel("New") == AlertStatus.new
        assert AlertStatus.from_sentinel("Active") == AlertStatus.in_progress
        assert AlertStatus.from_sentinel("Closed") == AlertStatus.resolved
        assert AlertStatus.from_sentinel("SomethingElse") == AlertStatus.unknown

    def test_from_graph_empty(self) -> None:
        assert AlertStatus.from_graph("") == AlertStatus.unknown

    def test_from_sentinel_empty(self) -> None:
        assert AlertStatus.from_sentinel("") == AlertStatus.unknown


class TestAlertClassification:
    def test_from_graph_standard(self) -> None:
        assert AlertClassification.from_graph("truePositive") == AlertClassification.true_positive
        assert AlertClassification.from_graph("falsePositive") == AlertClassification.false_positive
        assert AlertClassification.from_graph("benignPositive") == AlertClassification.benign_positive

    def test_from_graph_informational_expected_activity(self) -> None:
        """Graph maps 'informationalExpectedActivity' to benign_positive."""
        assert AlertClassification.from_graph("informationalExpectedActivity") == AlertClassification.benign_positive

    def test_from_graph_none(self) -> None:
        assert AlertClassification.from_graph(None) == AlertClassification.undetermined

    def test_from_graph_empty_string(self) -> None:
        assert AlertClassification.from_graph("") == AlertClassification.undetermined

    def test_from_graph_unknown_value(self) -> None:
        assert AlertClassification.from_graph("something_new") == AlertClassification.undetermined

    def test_from_sentinel_standard(self) -> None:
        assert AlertClassification.from_sentinel("TruePositive") == AlertClassification.true_positive
        assert AlertClassification.from_sentinel("FalsePositive") == AlertClassification.false_positive

    def test_from_sentinel_none(self) -> None:
        assert AlertClassification.from_sentinel(None) == AlertClassification.undetermined

    def test_from_sentinel_with_spaces_and_underscores(self) -> None:
        """Sentinel sometimes sends 'True Positive' or 'true_positive'."""
        assert AlertClassification.from_sentinel("True Positive") == AlertClassification.true_positive
        assert AlertClassification.from_sentinel("true_positive") == AlertClassification.true_positive


class TestAlertDetermination:
    def test_from_graph_standard(self) -> None:
        assert AlertDetermination.from_graph("malware") == AlertDetermination.malware
        assert AlertDetermination.from_graph("phishing") == AlertDetermination.phishing

    def test_from_graph_case_insensitive(self) -> None:
        assert AlertDetermination.from_graph("Malware") == AlertDetermination.malware

    def test_from_graph_none(self) -> None:
        assert AlertDetermination.from_graph(None) == AlertDetermination.unknown

    def test_from_graph_unknown_value(self) -> None:
        assert AlertDetermination.from_graph("nonexistent") == AlertDetermination.unknown

    def test_all_values_exist(self) -> None:
        """Ensure all expected determination values are present."""
        expected = {
            "unknown", "apt", "malware", "phishing", "compromisedAccount",
            "securityPersonnel", "securityTesting", "unwantedSoftware",
            "multiStagedAttack", "maliciousUserActivity", "notMalicious",
            "notEnoughDataToValidate", "confirmedActivity",
            "lineOfBusinessApplication", "other",
        }
        actual = {d.value for d in AlertDetermination}
        assert actual == expected


# ---------------------------------------------------------------------------
# Model validation tests
# ---------------------------------------------------------------------------


class TestGraphAlert:
    def test_basic_validation(self) -> None:
        data = {
            "id": "alert-1",
            "title": "Test alert",
            "severity": "high",
            "status": "new",
            "serviceSource": "microsoftDefenderForEndpoint",
            "createdDateTime": "2026-05-20T10:00:00Z",
        }
        alert = GraphAlert.model_validate(data)
        assert alert.id == "alert-1"
        assert alert.title == "Test alert"
        assert alert.severity == "high"

    def test_extra_fields_ignored(self) -> None:
        data = {"id": "a1", "unknownField": "ignored"}
        alert = GraphAlert.model_validate(data)
        assert alert.id == "a1"

    def test_defaults(self) -> None:
        alert = GraphAlert(id="a2")
        assert alert.title == ""
        assert alert.mitreTechniques == []
        assert alert.evidence == []

    def test_mitre_techniques(self) -> None:
        data = {
            "id": "a3",
            "mitreTechniques": ["T1059.001", "T1071"],
        }
        alert = GraphAlert.model_validate(data)
        assert alert.mitreTechniques == ["T1059.001", "T1071"]


class TestSentinelIncident:
    def test_basic_validation(self) -> None:
        data = {
            "id": "inc-1",
            "title": "Suspicious login",
            "severity": "Medium",
            "status": "Active",
            "createdTimeUtc": "2026-05-20T08:00:00Z",
        }
        inc = SentinelIncident.model_validate(data)
        assert inc.id == "inc-1"
        assert inc.severity == "Medium"

    def test_owner_dict(self) -> None:
        data = {
            "id": "inc-2",
            "owner": {"assignedTo": "analyst@contoso.com"},
        }
        inc = SentinelIncident.model_validate(data)
        assert inc.owner["assignedTo"] == "analyst@contoso.com"


# ---------------------------------------------------------------------------
# NormalizedAlert factory tests
# ---------------------------------------------------------------------------


class TestNormalizedAlertFromGraph:
    def test_basic(self) -> None:
        data = {
            "id": "ga-1",
            "title": "MDE alert",
            "severity": "High",
            "status": "resolved",
            "classification": "truePositive",
            "determination": "malware",
            "serviceSource": "microsoftDefenderForEndpoint",
            "createdDateTime": "2026-05-20T10:00:00Z",
            "resolvedDateTime": "2026-05-20T12:00:00Z",
            "mitreTechniques": ["T1059"],
        }
        na = NormalizedAlert.from_graph(data)
        assert na.source == "graph"
        assert na.severity == AlertSeverity.high
        assert na.status == AlertStatus.resolved
        assert na.classification == AlertClassification.true_positive
        assert na.determination == AlertDetermination.malware
        assert na.mitre_techniques == ["T1059"]

    def test_from_graph_alert_object(self) -> None:
        alert = GraphAlert(
            id="ga-2",
            title="Test",
            severity="low",
            status="new",
        )
        na = NormalizedAlert.from_graph(alert)
        assert na.id == "ga-2"
        assert na.severity == AlertSeverity.low


class TestNormalizedAlertFromSentinel:
    def test_basic(self) -> None:
        data = {
            "id": "/subscriptions/.../incidents/inc-1",
            "name": "inc-1",
            "properties": {
                "title": "Sentinel incident",
                "severity": "Medium",
                "status": "Closed",
                "classification": "FalsePositive",
                "classificationReason": "notMalicious",
                "createdTimeUtc": "2026-05-20T06:00:00Z",
                "closedTimeUtc": "2026-05-20T08:00:00Z",
                "owner": {"assignedTo": "analyst@example.com"},
                "incidentNumber": 42,
                "relatedAnalyticRuleIds": ["rule-abc"],
            },
        }
        na = NormalizedAlert.from_sentinel(data)
        assert na.source == "sentinel"
        assert na.severity == AlertSeverity.medium
        assert na.status == AlertStatus.resolved
        assert na.classification == AlertClassification.false_positive
        assert na.determination == AlertDetermination.not_malicious
        assert na.assigned_to == "analyst@example.com"
        assert na.rule_id == "rule-abc"

    def test_from_sentinel_incident_object(self) -> None:
        inc = SentinelIncident(
            id="inc-3",
            title="Direct",
            severity="Low",
            status="New",
        )
        na = NormalizedAlert.from_sentinel(inc)
        assert na.id == "inc-3"
        assert na.status == AlertStatus.new

    def test_missing_owner(self) -> None:
        data = {
            "id": "inc-4",
            "properties": {
                "title": "No owner",
                "severity": "High",
                "status": "Active",
            },
        }
        na = NormalizedAlert.from_sentinel(data)
        assert na.assigned_to is None
