# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the dual-source alert merge logic."""

from __future__ import annotations

from datetime import datetime, timezone

from contentops.alerts.merge import enrich_from_graph, merge_alerts
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


# ---------------------------------------------------------------------------
# Cross-source correlation (VendorOriginalId) — the de-dup / double-count fix.
# A Defender alert appears in Graph (id/providerAlertId) AND Sentinel
# (VendorOriginalId → provider_alert_id); they must collapse to one "both"
# alert, not two. The old key (Graph providerAlertId ↔ Sentinel SystemAlertId)
# never matched, so every Defender alert was double-counted.
# ---------------------------------------------------------------------------


def test_merge_correlates_graph_id_to_sentinel_vendor_id() -> None:
    graph = [_graph_alert("defender-alert-abc")]  # Graph id == the vendor id
    sentinel = [
        _sentinel_alert("la-system-xyz").model_copy(
            update={"provider_alert_id": "defender-alert-abc"}
        )
    ]
    result = merge_alerts(graph, sentinel)
    assert len(result) == 1
    assert result[0].source == "both"


def test_merge_correlates_graph_provider_id_to_sentinel_vendor_id() -> None:
    graph = [
        _graph_alert("graph-unified-1").model_copy(
            update={"provider_alert_id": "defender-alert-abc"}
        )
    ]
    sentinel = [
        _sentinel_alert("la-system-xyz").model_copy(
            update={"provider_alert_id": "defender-alert-abc"}
        )
    ]
    result = merge_alerts(graph, sentinel)
    assert len(result) == 1
    assert result[0].source == "both"


def test_merge_no_double_count_on_vendor_id_match() -> None:
    """The regression: N Defender alerts in both sources must yield N rows, not 2N."""
    graph = [_graph_alert(f"d{i}") for i in range(5)]
    sentinel = [
        _sentinel_alert(f"s{i}").model_copy(update={"provider_alert_id": f"d{i}"})
        for i in range(5)
    ]
    result = merge_alerts(graph, sentinel)
    assert len(result) == 5
    assert all(a.source == "both" for a in result)


def test_merge_keeps_genuinely_distinct_alerts_separate() -> None:
    graph = [_graph_alert("g-only")]
    sentinel = [
        _sentinel_alert("s-only").model_copy(update={"provider_alert_id": "unrelated"})
    ]
    result = merge_alerts(graph, sentinel)
    assert len(result) == 2
    assert {a.source for a in result} == {"graph", "sentinel"}


def test_from_kql_row_populates_provider_alert_id_from_vendor_original_id() -> None:
    row = {
        "SystemAlertId": "la-system-xyz",
        "VendorOriginalId": "defender-alert-abc",
        "AlertName": "Test",
        "AlertSeverity": "Medium",
        "Status": "New",
    }
    alert = NormalizedAlert.from_kql_row(row)
    assert alert.id == "la-system-xyz"
    assert alert.provider_alert_id == "defender-alert-abc"


def test_enrich_from_graph_matches_on_vendor_id_not_system_id() -> None:
    """A Sentinel alert lacking MITRE is enriched from its Graph twin,
    correlated on VendorOriginalId — SystemAlertId would never match."""
    sentinel = _sentinel_alert("la-system-xyz").model_copy(
        update={"provider_alert_id": "defender-alert-abc", "mitre_techniques": []}
    )
    graph = _graph_alert("defender-alert-abc")  # carries T1059
    result = enrich_from_graph([sentinel], [graph])
    assert result[0].mitre_techniques == ["T1059"]
