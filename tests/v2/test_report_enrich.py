# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the live-enrichment passes (``contentops.report.enrich``).

Pure-function tests — every enricher takes the data it needs as a
plain dict so no network mocking is required. The CLI integration
(which DOES make LA workspace calls) is mocked at the
get_credential / query boundary in test_report.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from contentops.report.assemble import ReportRow
from contentops.report.enrich import (
    enrich_with_health,
    enrich_with_schema_drift,
    enrich_with_telemetry,
    extract_primary_table,
    primary_tables_for_rows,
)


def _row(**over) -> ReportRow:
    """Build a minimal ReportRow for enrichment tests."""
    base = dict(
        rule_id="rule-a", asset_kind="sentinel_analytic",
        path="detections/sentinel_analytic/rule-a.yml",
        title="Example", status="production", severity="medium",
        tactics=("Execution",), techniques=("T1059",),
        merge_date=None, deployment_date=None, last_review_date=None,
    )
    base.update(over)
    return ReportRow(**base)


# ---------------------------------------------------------------------------
# extract_primary_table
# ---------------------------------------------------------------------------


def test_primary_table_simple_query() -> None:
    assert extract_primary_table("SecurityEvent | where EventID == 4624") == "SecurityEvent"


def test_primary_table_multiline_query() -> None:
    q = """SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624
"""
    assert extract_primary_table(q) == "SecurityEvent"


def test_primary_table_skips_comments() -> None:
    """// comments at the top are ignored — the real table sits below."""
    q = """// this rule fires on logins
// thresholds were tuned 2026-04-15
DeviceProcessEvents | take 10
"""
    assert extract_primary_table(q) == "DeviceProcessEvents"


def test_primary_table_skips_let_bindings() -> None:
    """`let X = ...` bindings are helpers, not the primary table."""
    q = """let lookback = 1d;
let threshold = 5;
SigninLogs | where TimeGenerated > ago(lookback)
"""
    assert extract_primary_table(q) == "SigninLogs"


def test_primary_table_strips_leading_union() -> None:
    """A query starting with `union A, B` resolves to the first of the
    unioned tables — that's the most common interpretation for SOC
    operators reading the report."""
    q = "union DeviceProcessEvents, DeviceFileEvents | take 5"
    assert extract_primary_table(q) == "DeviceProcessEvents"


def test_primary_table_returns_none_for_empty() -> None:
    assert extract_primary_table("") is None
    assert extract_primary_table(None) is None
    assert extract_primary_table("   \n  \n  ") is None


def test_primary_table_returns_none_for_unparseable_start() -> None:
    """A query starting with a non-identifier (e.g. ``(SubQuery)``)
    falls through to None — better to render 'unknown' than guess
    wrong."""
    assert extract_primary_table("(some inner query) | take 1") is None


# ---------------------------------------------------------------------------
# enrich_with_telemetry
# ---------------------------------------------------------------------------


def test_enrich_telemetry_populates_all_fields() -> None:
    rows = [_row(rule_id="rule-a", title="Failed Logins")]
    tel = {
        "Failed Logins": {
            "alerts_30d": 50,
            "incidents_30d": 10,
            "closed_fp_30d": 3,
        },
    }
    out = enrich_with_telemetry(rows, tel)
    assert out[0].alerts_30d == 50
    assert out[0].true_positives_30d == 7    # 10 - 3
    assert out[0].false_positives_30d == 3
    assert out[0].fp_rate == 0.3              # 3/10
    # Default ScoreWeights: 7*1 - 3*2 = 1
    assert out[0].effectiveness_score == 1


def test_enrich_telemetry_no_match_leaves_row_untouched() -> None:
    """A rule whose displayName doesn't appear in the telemetry dict
    keeps every enrichment field as None — 'unknown' distinct from
    'known to be zero'."""
    rows = [_row(rule_id="r1", title="Unknown Rule")]
    out = enrich_with_telemetry(rows, {})
    assert out[0].alerts_30d is None
    assert out[0].true_positives_30d is None
    assert out[0].effectiveness_score is None


def test_enrich_telemetry_silent_rule_hits_silence_penalty() -> None:
    """alerts_30d=0 means the rule never fired. Effectiveness score
    drops by the silence penalty (default 30); confirms the score
    column tracks the portfolio --rank formula."""
    rows = [_row(rule_id="r1", title="Silent")]
    tel = {"Silent": {"alerts_30d": 0, "incidents_30d": 0, "closed_fp_30d": 0}}
    out = enrich_with_telemetry(rows, tel)
    assert out[0].effectiveness_score == -30


# ---------------------------------------------------------------------------
# enrich_with_health
# ---------------------------------------------------------------------------


def test_enrich_health_marks_healthy_and_unhealthy() -> None:
    rows = [
        _row(rule_id="r1", title="A"),
        _row(rule_id="r2", title="B"),
        _row(rule_id="r3", title="C"),
    ]
    primary = {
        "r1": "SecurityEvent",
        "r2": "DeviceProcessEvents",
        "r3": None,                # no detectable primary
    }
    health = {
        "SecurityEvent": True,
        "DeviceProcessEvents": False,
    }
    out = enrich_with_health(rows, primary, health)
    assert out[0].data_source_healthy is True
    assert out[1].data_source_healthy is False
    # r3 has no primary table -> stays None ("unknown")
    assert out[2].data_source_healthy is None


def test_enrich_health_unknown_table_stays_unknown() -> None:
    """A primary table that isn't in the health map gets None, not
    False — we don't know its state, distinct from 'no data'."""
    rows = [_row(rule_id="r1", title="A")]
    out = enrich_with_health(
        rows, {"r1": "MysteryTable"}, table_health={},
    )
    assert out[0].data_source_healthy is None


# ---------------------------------------------------------------------------
# enrich_with_schema_drift
# ---------------------------------------------------------------------------


def test_enrich_schema_drift_flags_missing_table(tmp_path: Path) -> None:
    """A primary table not in the cached schema surfaces as drift."""
    schemas = tmp_path / "schemas.json"
    schemas.write_text(
        '{"database": "X", "schema_version": 1, "tables": ['
        '{"name": "SecurityEvent", "columns": []}'
        ']}',
        encoding="utf-8",
    )
    rows = [
        _row(rule_id="ok", title="A"),
        _row(rule_id="drift", title="B"),
    ]
    primary = {
        "ok": "SecurityEvent",         # exists in schema
        "drift": "RenamedTable",       # not in schema
    }
    out = enrich_with_schema_drift(rows, primary, schemas)
    assert out[0].schema_drift_columns == ()
    assert out[1].schema_drift_columns == ("RenamedTable",)


def test_enrich_schema_drift_handles_missing_schema_file(tmp_path: Path) -> None:
    """A missing/unparseable schemas.json yields empty drift on every
    row — best-effort, doesn't crash the report."""
    rows = [_row(rule_id="r1", title="A")]
    out = enrich_with_schema_drift(
        rows, {"r1": "SomeTable"}, tmp_path / "nonexistent.json",
    )
    assert out[0].schema_drift_columns == ()


# ---------------------------------------------------------------------------
# primary_tables_for_rows
# ---------------------------------------------------------------------------


def test_primary_tables_for_rows_uses_query_loader_stub() -> None:
    """The query_loader callable lets tests inject KQL per row without
    touching disk."""
    rows = [
        _row(rule_id="a", title="A"),
        _row(rule_id="b", title="B"),
    ]
    queries = {
        "a": "DeviceProcessEvents | take 1",
        "b": None,
    }
    out = primary_tables_for_rows(
        rows, query_loader=lambda r: queries[r.rule_id],
    )
    assert out["a"] == "DeviceProcessEvents"
    assert out["b"] is None


def test_primary_tables_for_rows_catches_loader_exceptions() -> None:
    """If the loader raises (corrupt YAML, etc.), the result is None
    for that row — the rest of the report still assembles."""
    rows = [_row(rule_id="a", title="A")]

    def _explode(_r):
        raise OSError("permission denied")

    out = primary_tables_for_rows(rows, query_loader=_explode)
    assert out["a"] is None
