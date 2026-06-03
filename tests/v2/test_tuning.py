# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the tuning impact preview module (`contentops.tuning`)."""

from __future__ import annotations

from contentops.tuning import (
    SuppressionEntry,
    new_suppressions,
    render_report,
)
from contentops.workspace_kql import suppression_impact_query


# ---------------------------------------------------------------------------
# new_suppressions — diff logic
# ---------------------------------------------------------------------------


def test_new_suppressions_empty_base_returns_all_head() -> None:
    head = """
schema_version: "1.0"
suppressions:
  - asset: sentinel_analytic
    id: noisy-rule-a
    reason: tuning out CI false positive
    expires: 2026-06-01
"""
    out = new_suppressions(head, None)
    assert len(out) == 1
    assert out[0].id == "noisy-rule-a"


def test_new_suppressions_excludes_entries_already_in_base() -> None:
    head = """
schema_version: "1.0"
suppressions:
  - asset: sentinel_analytic
    id: noisy-rule-a
    reason: tuning out CI false positive
    expires: 2026-06-01
  - asset: sentinel_analytic
    id: noisy-rule-b
    reason: ditto
    expires: 2026-06-01
"""
    base = """
schema_version: "1.0"
suppressions:
  - asset: sentinel_analytic
    id: noisy-rule-a
    reason: tuning out CI false positive
    expires: 2026-06-01
"""
    out = new_suppressions(head, base)
    assert len(out) == 1
    assert out[0].id == "noisy-rule-b"


def test_new_suppressions_tolerates_unparseable_input() -> None:
    """A malformed file should not crash the workflow — return [] and
    let lint surface the parse error elsewhere."""
    assert new_suppressions(":\nbroken yaml", None) == []
    assert new_suppressions(None, None) == []
    assert new_suppressions("not a mapping", None) == []


# ---------------------------------------------------------------------------
# render_report — markdown shape
# ---------------------------------------------------------------------------


def test_render_report_no_entries_is_clear() -> None:
    body = render_report([], {}, name_lookup={}, since_days=30)
    assert "No new suppressions" in body
    assert body.endswith("\n")


def test_render_report_emits_table_for_entries() -> None:
    entries = [
        SuppressionEntry(
            asset="sentinel_analytic", id="noisy-rule",
            reason="known cluster admin tool", expires="2026-06-01",
        ),
    ]
    impact = {"Noisy rule display name": {"alerts_count": 309, "incidents_count": 21}}
    name_lookup = {("sentinel_analytic", "noisy-rule"): "Noisy rule display name"}
    body = render_report(entries, impact, name_lookup=name_lookup, since_days=30)
    assert "309" in body
    assert "21" in body
    assert "Noisy rule display name" in body
    assert "Total impact" in body


def test_render_report_envelope_not_found_marker() -> None:
    entries = [
        SuppressionEntry(asset="sentinel_analytic", id="missing", reason="x", expires="2026-06-01"),
    ]
    name_lookup = {("sentinel_analytic", "missing"): None}
    body = render_report(entries, {}, name_lookup=name_lookup, since_days=30)
    assert "envelope not found" in body


def test_render_report_dashes_when_workspace_query_skipped() -> None:
    """When --no-workspace-query is in effect (fork PR), counts render
    as '—' so the comment still appears but doesn't lie about impact."""
    entries = [
        SuppressionEntry(asset="sentinel_analytic", id="x", reason="r", expires="2026-06-01"),
    ]
    name_lookup = {("sentinel_analytic", "x"): "X"}
    body = render_report(entries, None, name_lookup=name_lookup, since_days=30)
    assert "—" in body
    assert "Total impact" not in body


# ---------------------------------------------------------------------------
# suppression_impact_query
# ---------------------------------------------------------------------------


def test_suppression_impact_query_handles_empty_names() -> None:
    """Empty rule_names must not emit ``in ()`` which LA rejects."""
    kql = suppression_impact_query(rule_names=[], since_days=30)
    assert "in ()" not in kql
    assert "false" in kql


def test_suppression_impact_query_escapes_quotes() -> None:
    """Rule names with embedded double-quotes must be properly escaped
    so we don't emit broken KQL."""
    kql = suppression_impact_query(
        rule_names=['Name with "quote"'], since_days=30,
    )
    assert '"quote"' not in kql  # escaped form, not raw
    assert '\\"quote\\"' in kql


def test_suppression_impact_query_unions_alerts_and_incidents() -> None:
    kql = suppression_impact_query(rule_names=["X"], since_days=14)
    assert "SecurityAlert" in kql
    assert "SecurityIncident" in kql
    assert "14d" in kql
