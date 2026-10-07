# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the workspace KQL helper + F4 silent-rules + F20 telemetry."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from contentops.workspace_kql import (
    LA_QUERY_BASE,
    QueryResult,
    WorkspaceKqlError,
    auto_disabled_query,
    closed_fp_rate,
    parse_response,
    query,
    silent_rules_query,
    telemetry_query,
)


# ---------------------------------------------------------------------------
# parse_response
# ---------------------------------------------------------------------------


def test_parse_response_empty_body() -> None:
    assert parse_response({}).rows == []


def test_parse_response_zips_columns_to_rows() -> None:
    body = {
        "tables": [{
            "name": "PrimaryResult",
            "columns": [
                {"name": "rule_name", "type": "string"},
                {"name": "alerts_30d", "type": "long"},
            ],
            "rows": [
                ["BruteForce SSH", 7],
                ["O365 anomaly", 0],
            ],
        }],
    }
    result = parse_response(body)
    assert result.column_names == ["rule_name", "alerts_30d"]
    assert result.rows == [
        {"rule_name": "BruteForce SSH", "alerts_30d": 7},
        {"rule_name": "O365 anomaly", "alerts_30d": 0},
    ]


def test_parse_response_handles_short_rows() -> None:
    """Defensive: a row shorter than column count fills missing with None."""
    body = {
        "tables": [{
            "columns": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
            "rows": [["x", "y"]],  # only 2 values
        }],
    }
    result = parse_response(body)
    assert result.rows[0] == {"a": "x", "b": "y", "c": None}


# ---------------------------------------------------------------------------
# query() — uses httpx.MockTransport so no real network
# ---------------------------------------------------------------------------


def _mock_transport(handler):
    return httpx.MockTransport(handler)


def test_query_happy_path() -> None:
    def _h(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/v1/workspaces/abc-123/query")
        return httpx.Response(200, json={
            "tables": [{
                "columns": [{"name": "n"}],
                "rows": [[1], [2]],
            }],
        })
    result = query(
        "T | take 1",
        workspace_id="abc-123", token="t",
        transport=_mock_transport(_h),
    )
    assert [r["n"] for r in result.rows] == [1, 2]


def test_query_empty_workspace_id_raises() -> None:
    with pytest.raises(WorkspaceKqlError):
        query("T", workspace_id="", token="t")


def test_query_4xx_raises_with_status() -> None:
    def _h(request):
        return httpx.Response(400, text="bad query")
    with pytest.raises(WorkspaceKqlError) as exc_info:
        query("T", workspace_id="abc", token="t",
              transport=_mock_transport(_h))
    assert "400" in str(exc_info.value)


def test_query_5xx_raises() -> None:
    def _h(request):
        return httpx.Response(500, text="server error")
    with pytest.raises(WorkspaceKqlError):
        query("T", workspace_id="abc", token="t",
              transport=_mock_transport(_h))


def test_query_non_json_response_raises() -> None:
    def _h(request):
        return httpx.Response(200, text="not json")
    with pytest.raises(WorkspaceKqlError):
        query("T", workspace_id="abc", token="t",
              transport=_mock_transport(_h))


# ---------------------------------------------------------------------------
# silent_rules_query / telemetry_query — same KQL
# ---------------------------------------------------------------------------


def test_silent_rules_query_includes_window() -> None:
    kql = silent_rules_query(since_days=7)
    assert "7d" in kql
    assert "alerts_30d" in kql
    assert "closed_fp_30d" in kql


def _incidents_let(kql: str) -> str:
    """The ``let incidents = ...;`` statement of a query."""
    start = kql.index("let incidents = incident_latest")
    return kql[start:kql.index(";", start)]


def _incident_latest_let(kql: str) -> str:
    start = kql.index("let incident_latest = materialize(SecurityIncident")
    return kql[start:kql.index(";", start)]


def test_silent_rules_query_dedupes_incidents_before_counting() -> None:
    """SecurityIncident logs one row per incident update. Counting raw
    rows inflated incidents_30d (the FP-rate denominator) and counted a
    FalsePositive incident once per update. Dedupe to the latest row per
    IncidentNumber BEFORE the counts."""
    kql = silent_rules_query(since_days=30)
    latest = _incident_latest_let(kql)
    assert "summarize arg_max(TimeGenerated, *) by IncidentNumber" in latest, latest
    # The counts are computed from the deduplicated incidents only.
    incidents = _incidents_let(kql)
    counts = incidents.find("incidents_30d = count()")
    fp = incidents.find('Classification == "FalsePositive")')
    assert -1 < counts < fp, incidents
    assert kql.count("SecurityIncident") == 1


def test_suppression_impact_query_dedupes_incidents_before_counting() -> None:
    from contentops.workspace_kql import suppression_impact_query
    kql = suppression_impact_query(rule_names=["X"])
    assert "summarize arg_max(TimeGenerated, *) by IncidentNumber" in _incident_latest_let(kql)
    assert "incidents_count = count()" in _incidents_let(kql)
    assert kql.count("SecurityIncident") == 1


def _alerts_let(kql: str) -> str:
    start = kql.index("let alerts = SecurityAlert")
    return kql[start:kql.index(";", start)]


def test_silent_rules_query_dedupes_alerts_before_counting() -> None:
    """SecurityAlert writes a row per status change: count each
    SystemAlertId once."""
    alerts = _alerts_let(silent_rules_query())
    dedupe = alerts.find("by SystemAlertId")
    assert -1 < dedupe < alerts.find("alerts_30d = count()"), alerts


def test_silent_rules_query_keys_rows_by_rule_id_then_display_name() -> None:
    kql = silent_rules_query()
    alerts, incidents = _alerts_let(kql), _incidents_let(kql)
    # Sentinel analytic alerts: AlertType is "<workspace-guid>_<rule>".
    assert 'ProductName in ("Azure Sentinel", "Microsoft Sentinel")' in alerts
    assert "AlertType" in alerts and '"id:"' in alerts and '"name:"' in alerts
    # Incidents: one row per related analytic rule, last ARM path segment.
    assert "mv-expand rule_ref = rule_refs to typeof(string)" in incidents
    assert "RelatedAnalyticRuleIds" in incidents
    assert 'extract(@"([^/]+)$", 1, rule_ref)' in incidents
    # The same incident is counted once per rule key.
    assert incidents.find("distinct IncidentNumber, rule_key") < incidents.find(
        "incidents_30d = count()",
    )
    assert "join kind=fullouter (incidents) on rule_key" in kql


def test_silent_rules_query_counts_closed_classifications() -> None:
    """TP is incidents closed TruePositive (not incidents - FP)."""
    kql = silent_rules_query()
    for column, classification in (
        ("closed_tp_30d", "TruePositive"),
        ("closed_fp_30d", "FalsePositive"),
        ("closed_bp_30d", "BenignPositive"),
    ):
        assert (
            f'{column} = countif(Status == "Closed" and Classification == "{classification}")'
        ) in kql
        assert f"{column} = coalesce({column}, 0)" in kql
    assert "rule_key = coalesce(rule_key, rule_key1)" in kql


def test_silent_rules_query_ignores_classification_of_reopened_incidents() -> None:
    """Classification survives a reopen, so a reopened incident still
    carries it: every classification count also requires the incident's
    latest status to be Closed, and Status is kept through the distinct."""
    incidents = _incidents_let(silent_rules_query())
    assert "distinct IncidentNumber, rule_key, Title, Classification, Status" in incidents
    countifs = [line for line in incidents.splitlines() if "countif(" in line]
    assert len(countifs) == 3
    assert all('Status == "Closed" and Classification ==' in line for line in countifs)


def _assert_alerts_take_their_incidents_rule(kql: str) -> None:
    link = kql[kql.index("let alert_rule_link"):kql.index(";", kql.index("let alert_rule_link"))]
    # Only incidents with exactly one related rule attribute their alerts.
    assert "where array_length(RelatedAnalyticRuleIds) == 1" in link
    assert "tostring(RelatedAnalyticRuleIds[0])" in link
    assert "mv-expand AlertId = AlertIds to typeof(string)" in link
    alerts = _alerts_let(kql)
    assert "join kind=leftouter (alert_rule_link) on $left.SystemAlertId == $right.AlertId" in alerts
    # Sentinel alerts only; the incident's rule wins over the AlertType parse.
    assert 'iff(ProductName in ("Azure Sentinel", "Microsoft Sentinel"), coalesce(linked_rule_id, ' in alerts


def test_silent_rules_query_links_alerts_to_their_incidents_rule() -> None:
    """Review of #395: AlertType's format is undocumented. An alert in an
    incident created from one analytic rule belongs to that rule (Microsoft
    documents RelatedAnalyticRuleIds), so a mismatched AlertType no longer
    splits the rule's alerts from its incidents."""
    _assert_alerts_take_their_incidents_rule(silent_rules_query())


def test_suppression_impact_query_links_alerts_to_their_incidents_rule() -> None:
    from contentops.workspace_kql import suppression_impact_query

    _assert_alerts_take_their_incidents_rule(suppression_impact_query(rule_keys=["id:x"]))


def test_kql_and_python_strip_the_same_workspace_prefix() -> None:
    """contentops.rule_keys mirrors the KQL normalisation."""
    import re

    from contentops.rule_keys import normalise_rule_id
    from contentops.workspace_kql import _WS_PREFIXED_RULE

    pattern = re.compile(_WS_PREFIXED_RULE[2:-1])  # strip @"..."
    alert_type = "0B3C1F2E-1111-4A2B-9C3D-ABCDEFABCDEF_My_Rule"
    assert pattern.match(alert_type).group(1).lower() == normalise_rule_id(alert_type)


def test_suppression_impact_query_matches_rule_keys() -> None:
    from contentops.workspace_kql import suppression_impact_query

    kql = suppression_impact_query(
        rule_keys=["id:brute-force", "name:brute force"], rule_names=["Other Rule "],
    )
    assert 'dynamic(["id:brute-force", "name:brute force", "name:other rule"])' in kql
    alerts = _alerts_let(kql)
    assert -1 < alerts.find("by SystemAlertId") < alerts.find("alerts_count = count()")
    # One key per alert / incident: its id when listed, else its name.
    assert "iff(id_key in (keys), id_key, iff(name_key in (keys), name_key, \"\"))" in alerts
    assert "distinct IncidentNumber, match_key" in _incidents_let(kql)
    assert "match_key = coalesce(match_key, match_key1)" in kql


def test_suppression_impact_query_without_keys_returns_nothing() -> None:
    from contentops.workspace_kql import suppression_impact_query

    assert suppression_impact_query() == "print match_key=''| where false"
    assert suppression_impact_query(rule_names=["  "]) == "print match_key=''| where false"


def test_telemetry_query_matches_silent_rules_query() -> None:
    """F4 and F20 deliberately share one KQL — keeps the LA round-trip
    consistent and lets one fetch power both views."""
    assert silent_rules_query() == telemetry_query()


# ---------------------------------------------------------------------------
# auto_disabled_query — NVISO Part 7
# ---------------------------------------------------------------------------


def test_auto_disabled_query_unions_both_signals() -> None:
    """Two tables are unioned: SentinelHealth (platform-side disable
    event) and LAQueryLogs (recent query failures). Drop either branch
    silently and operators miss half the picture."""
    kql = auto_disabled_query(since_days=7)
    assert "SentinelHealth" in kql
    assert "LAQueryLogs" in kql
    assert "union" in kql


def test_auto_disabled_query_respects_window() -> None:
    kql = auto_disabled_query(since_days=14)
    assert "14d" in kql
    assert "7d" not in kql or kql.count("7d") == 0


def test_auto_disabled_query_filters_alert_rule_kind() -> None:
    """SentinelHealth carries lifecycle events for every Sentinel
    resource kind; the query must scope to Alert Rule, otherwise it
    surfaces noise from connectors and workbooks."""
    kql = auto_disabled_query()
    assert 'SentinelResourceKind == "Alert Rule"' in kql


def test_auto_disabled_query_does_not_reference_errormessage_column() -> None:
    """LAQueryLogs has no `ErrorMessage` column -- referencing one
    fails at parse time with a SemanticError, taking the whole union
    down. Regression pin: a dispatched workflow run on 2026-05-22
    returned LA Query 400 against the original draft of this query
    which had `or isnotempty(ErrorMessage)` on the failing-queries
    filter."""
    kql = auto_disabled_query(since_days=7)
    assert "ErrorMessage" not in kql


def test_auto_disabled_query_casts_request_context_to_string() -> None:
    """LAQueryLogs.RequestContext is a dynamic column; the `has`
    operator needs a string. `tostring(RequestContext) has "..."`
    is the portable form."""
    kql = auto_disabled_query(since_days=7)
    assert 'tostring(RequestContext) has "Microsoft.SecurityInsights"' in kql


# ---------------------------------------------------------------------------
# CLI integration — silent-rules
# ---------------------------------------------------------------------------


def test_cli_silent_rules_fails_loud_without_credentials(
    tmp_path: Path, monkeypatch,
) -> None:
    """No --workspace-id, no env, and no Azure creds → exit 1 with a clear
    credential-error message. (PR-J: workspace-id used to be required at
    Click-parse time; now it auto-derives from tenant.yml + ARM. Missing
    credentials surface from `get_credential()` instead.)"""
    monkeypatch.delenv("PIPELINE_WORKSPACE_ID", raising=False)
    # Force DefaultAzureCredential to fail by clearing the obvious paths.
    for var in ("AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL"):
        monkeypatch.delenv(var, raising=False)
    import contentops.utils.auth as auth_mod

    def _raise(*_a, **_kw):
        raise RuntimeError("no creds in test env")

    monkeypatch.setattr(auth_mod, "get_credential", _raise)

    from click.testing import CliRunner
    from contentops.cli import cli
    runner = CliRunner()
    detections = tmp_path / "detections"
    detections.mkdir()
    result = runner.invoke(cli, ["silent-rules", "--path", str(detections)])
    assert result.exit_code == 1
    assert "credential acquisition failed" in result.output


# ---------------------------------------------------------------------------
# CLI integration — portfolio --with-telemetry (no workspace -> graceful)
# ---------------------------------------------------------------------------


def test_cli_portfolio_with_telemetry_falls_back_without_credentials(
    tmp_path: Path, monkeypatch,
) -> None:
    """No --workspace-id + no creds + --with-telemetry → exit 0 with a
    `[warn] telemetry ... failed` message (graceful degrade). PR-J makes
    `--workspace-id` optional via auto-derive; the auth failure surfaces
    from `get_credential()` and is caught by portfolio's graceful path."""
    monkeypatch.delenv("PIPELINE_WORKSPACE_ID", raising=False)
    import contentops.utils.auth as auth_mod

    def _raise(*_a, **_kw):
        raise RuntimeError("no creds in test env")

    monkeypatch.setattr(auth_mod, "get_credential", _raise)

    from click.testing import CliRunner
    from contentops.cli import cli
    detections = tmp_path / "detections"
    detections.mkdir()
    runner = CliRunner()
    result = runner.invoke(cli, [
        "portfolio", "--path", str(detections), "--with-telemetry",
    ])
    assert result.exit_code == 0, result.output
    # Telemetry off in the output (auth failure → fall back to inputs-only).
    assert "telemetry" in result.output.lower()


def test_cli_portfolio_without_telemetry_unchanged(tmp_path: Path) -> None:
    """Plain `pipeline portfolio` (no --with-telemetry) works unchanged."""
    from click.testing import CliRunner
    from contentops.cli import cli
    detections = tmp_path / "detections"
    detections.mkdir()
    runner = CliRunner()
    result = runner.invoke(cli, [
        "portfolio", "--path", str(detections),
    ])
    assert result.exit_code == 0
    # Default header (no telemetry columns).
    assert "alerts_30d" not in result.output


# ---------------------------------------------------------------------------
# closed_fp_rate -- the one FP-rate definition
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("row, expected", [
    # FP / closed TP + FP + BP; open / Undetermined incidents don't count.
    ({"incidents_30d": 10, "closed_tp_30d": 3, "closed_fp_30d": 1, "closed_bp_30d": 1}, 0.2),
    ({"incidents_30d": 10, "closed_fp_30d": 3}, 1.0),
    ({"closed_tp_30d": 0, "closed_fp_30d": 0, "closed_bp_30d": 4}, 0.0),
    # Nothing closed with a verdict -> undefined.
    ({"incidents_30d": 5}, None),
    ({}, None),
    ({"closed_tp_30d": None, "closed_fp_30d": None}, None),
])
def test_closed_fp_rate(row, expected) -> None:
    assert closed_fp_rate(row) == expected
