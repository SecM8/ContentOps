# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the dual-source alert merge logic."""

from __future__ import annotations

from datetime import datetime, timezone

from contentops.alerts.merge import merge_alerts
from contentops.alerts.models import (
    AlertClassification,
    AlertDetermination,
    AlertSeverity,
    AlertStatus,
    NormalizedAlert,
)


def _graph_alert(id: str, incident_id: str | None = None, title: str = "Test") -> NormalizedAlert:
    return NormalizedAlert(
        id=id,
        title=title,
        severity=AlertSeverity.medium,
        status=AlertStatus.new,
        classification=AlertClassification.undetermined,
        determination=AlertDetermination.unknown,
        source="graph",
        service_source="microsoftDefenderForEndpoint",
        incident_id=incident_id,
        mitre_techniques=["T1059"],
        detection_source="customDetection",
    )


def _sentinel_alert(id: str, incident_id: str | None = None, title: str = "Test", rule_id: str | None = None) -> NormalizedAlert:
    return NormalizedAlert(
        id=id,
        title=title,
        severity=AlertSeverity.medium,
        status=AlertStatus.new,
        classification=AlertClassification.true_positive,
        determination=AlertDetermination.unknown,
        source="sentinel",
        service_source="sentinel",
        incident_id=incident_id,
        rule_id=rule_id,
    )


def test_merge_empty_graph() -> None:
    sentinel = [_sentinel_alert("s1", incident_id="10")]
    result = merge_alerts([], sentinel)
    assert len(result) == 1
    assert result[0].source == "sentinel"


def test_merge_empty_sentinel() -> None:
    graph = [_graph_alert("g1", incident_id="10")]
    result = merge_alerts(graph, [])
    assert len(result) == 1
    assert result[0].source == "graph"


def test_merge_both_empty() -> None:
    assert merge_alerts([], []) == []


def test_merge_no_overlap() -> None:
    graph = [_graph_alert("g1", incident_id="10")]
    sentinel = [_sentinel_alert("s1", incident_id="20")]
    result = merge_alerts(graph, sentinel)
    assert len(result) == 2
    sources = {a.source for a in result}
    assert sources == {"graph", "sentinel"}


def test_merge_full_overlap_by_incident_id() -> None:
    graph = [_graph_alert("g1", incident_id="42")]
    sentinel = [_sentinel_alert("s1", incident_id="42", rule_id="/subscriptions/.../alertRules/abc")]
    result = merge_alerts(graph, sentinel)
    assert len(result) == 1
    merged = result[0]
    assert merged.source == "both"
    assert merged.id == "g1"
    assert merged.rule_id == "/subscriptions/.../alertRules/abc"
    assert merged.mitre_techniques == ["T1059"]
    assert merged.classification == AlertClassification.true_positive


def test_merge_one_sentinel_multiple_graph_alerts() -> None:
    """One Sentinel incident matches multiple Graph alerts (grouped incident)."""
    graph = [
        _graph_alert("g1", incident_id="42", title="Alert A"),
        _graph_alert("g2", incident_id="42", title="Alert B"),
    ]
    sentinel = [_sentinel_alert("s1", incident_id="42", rule_id="rule-abc")]
    result = merge_alerts(graph, sentinel)
    assert len(result) == 2
    assert all(a.source == "both" for a in result)
    assert all(a.rule_id == "rule-abc" for a in result)


def test_merge_partial_overlap() -> None:
    graph = [
        _graph_alert("g1", incident_id="10"),
        _graph_alert("g2", incident_id="20"),
    ]
    sentinel = [
        _sentinel_alert("s1", incident_id="10"),
        _sentinel_alert("s2", incident_id="30"),
    ]
    result = merge_alerts(graph, sentinel)
    assert len(result) == 3
    by_source = {a.source for a in result}
    assert by_source == {"both", "graph", "sentinel"}


def test_merge_graph_alert_without_incident_id() -> None:
    graph = [_graph_alert("g1", incident_id=None)]
    sentinel = [_sentinel_alert("s1", incident_id="10")]
    result = merge_alerts(graph, sentinel)
    assert len(result) == 2


def test_merge_classification_enrichment() -> None:
    """Graph undetermined + Sentinel true_positive → merged gets true_positive."""
    graph = [_graph_alert("g1", incident_id="42")]
    sentinel = [_sentinel_alert("s1", incident_id="42")]
    result = merge_alerts(graph, sentinel)
    assert result[0].classification == AlertClassification.true_positive
