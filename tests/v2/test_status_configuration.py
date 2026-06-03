# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the configuration-status renderer.

Pure-function tests against synthetic ConformanceReport fixtures; no
real conformance probes run. The renderer is the only thing under
test here — the conformance module's own probes are covered elsewhere.
"""

from __future__ import annotations

from datetime import datetime, timezone

from contentops.devex.conformance import ConformanceCheck, ConformanceReport
from contentops.status.configuration import render_configuration


def _check(layer: str, name: str, status: str, detail: str = "", remediation: str = "") -> ConformanceCheck:
    return ConformanceCheck(layer=layer, name=name, status=status, detail=detail, remediation=remediation)


def _fixed_now() -> datetime:
    return datetime(2026, 5, 20, 12, 34, 56, tzinfo=timezone.utc)


def test_renders_title_and_generated_at_marker() -> None:
    report = ConformanceReport(checks=[], scope=("L1", "L2"))
    md = render_configuration(report, generated_at=_fixed_now())
    assert md.startswith("# Configuration status\n")
    assert "Last refreshed 2026-05-20 12:34 UTC" in md
    assert "**Scope:** L1, L2" in md


def test_refresh_banner_links_to_workflow() -> None:
    report = ConformanceReport(checks=[], scope=("L1",))
    md = render_configuration(report, generated_at=_fixed_now())
    assert ".github/workflows/status-refresh.yml" in md


def test_summary_counts_appear_with_glyphs() -> None:
    report = ConformanceReport(
        checks=[
            _check("L1", "python_version", "PASS"),
            _check("L1", "package_import", "PASS"),
            _check("L2", "tenant_yml_parse", "FAIL", remediation="Run `contentops bootstrap`"),
            _check("L2", "workspace_sub_ids", "SKIP"),
        ],
        scope=("L1", "L2"),
    )
    md = render_configuration(report, generated_at=_fixed_now())
    assert "✅ 2 passed" in md
    assert "❌ 1 failed" in md
    assert "⚪ 1 skipped" in md


def test_one_section_per_layer_with_table() -> None:
    report = ConformanceReport(
        checks=[
            _check("L1", "python_version", "PASS", detail="3.12.13"),
            _check("L2", "tenant_yml_parse", "FAIL", detail="not found", remediation="copy example"),
        ],
        scope=("L1", "L2"),
    )
    md = render_configuration(report, generated_at=_fixed_now())
    assert "## L1 ✅" in md  # passing layer gets pass glyph
    assert "## L2 ❌" in md  # failing layer gets fail glyph
    assert "| Check | Status | Detail | Remediation |" in md
    assert "| `python_version` | ✅ PASS | 3.12.13 | — |" in md
    assert "| `tenant_yml_parse` | ❌ FAIL | not found | copy example |" in md


def test_empty_report_says_no_checks() -> None:
    report = ConformanceReport(checks=[], scope=())
    md = render_configuration(report, generated_at=_fixed_now())
    assert "_No checks in scope._" in md


def test_escape_pipe_in_detail_cell() -> None:
    report = ConformanceReport(
        checks=[_check("L1", "weird_value", "PASS", detail="a|b|c")],
        scope=("L1",),
    )
    md = render_configuration(report, generated_at=_fixed_now())
    # Each '|' inside the cell is backslash-escaped so the table renders.
    assert "a\\|b\\|c" in md


def test_newlines_in_detail_collapsed_to_space() -> None:
    report = ConformanceReport(
        checks=[_check("L1", "multiline", "FAIL", detail="line1\nline2", remediation="rem1\nrem2")],
        scope=("L1",),
    )
    md = render_configuration(report, generated_at=_fixed_now())
    assert "line1 line2" in md
    assert "rem1 rem2" in md


def test_tenant_guids_are_redacted_before_rendering() -> None:
    """L3-L7 detail strings carry tenant identifiers; the renderer must redact them."""
    report = ConformanceReport(
        checks=[
            _check(
                "L4", "service_principal", "PASS",
                detail="objectId=550e8400... displayName=ContentOps",
            ),
            _check(
                "L5", "workspace[prod:law-sentinel-prod]", "FAIL",
                detail=(
                    "403 lacks Reader on "
                    "/subscriptions/550e8400-e29b-41d4-a716-446655440000/"
                    "resourceGroups/rg-prod/providers/"
                    "Microsoft.OperationalInsights/workspaces/law-sentinel-prod"
                ),
                remediation=(
                    "Grant Reader on subscription "
                    "550e8400-e29b-41d4-a716-446655440000"
                ),
            ),
        ],
        scope=("L4", "L5"),
    )
    md = render_configuration(report, generated_at=_fixed_now())
    # Raw GUIDs must not appear anywhere in the rendered output.
    assert "550e8400-e29b-41d4-a716-446655440000" not in md
    assert "550e8400..." not in md
    # The placeholder tokens are present.
    assert "<redacted-guid>" in md
    assert "<redacted-resource-path>" in md
    assert "<redacted>" in md
    # Operator-readable preserves: display name, workspace name in the
    # check name column, app permission scope name.
    assert "ContentOps" in md
    assert "law-sentinel-prod" in md  # in the check name (not redacted by design)
