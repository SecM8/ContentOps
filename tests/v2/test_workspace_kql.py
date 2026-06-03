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
    result = runner.invoke(cli, ["silent-rules"])
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
