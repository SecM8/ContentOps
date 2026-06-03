# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for per-log-source coverage (`contentops coverage --by-source`).

Source tables are extracted at line-start / after `join` / in `union`,
then validated against the committed schema surface so columns, operators,
and typos never bucket as sources. Status-aware (production count).
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.coverage import sources as S
from contentops.coverage.sources import (
    SourceCoverage,
    SourceCoverageReport,
    extract_source_tables,
    load_known_tables,
    render_markdown,
)

_KNOWN = frozenset({"DeviceProcessEvents", "DeviceNetworkEvents", "SigninLogs", "AuditLogs"})


def _write_rule(det: Path, rule_id: str, status: str, query: str,
                asset: str = "sentinel_analytic") -> None:
    d = det / asset
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{rule_id}.yml").write_text(yaml.safe_dump({
        "id": rule_id, "version": "1.0.0", "asset": asset, "status": status,
        "metadata": {
            "owner": "blue@contoso.com", "runbookUrl": "https://wiki/r",
            "severity": "medium", "tactics": ["Execution"],
            "techniques": ["T1059"], "expectedAlertsPerDay": 1, "fpHandling": "n/a",
        },
        "payload": {"query": query, "displayName": rule_id},
    }, sort_keys=False), encoding="utf-8")


# ---------------------------------------------------------------------------
# extract_source_tables — the three positions + validation
# ---------------------------------------------------------------------------


def test_extract_line_start_table() -> None:
    assert extract_source_tables("DeviceProcessEvents | where x == 1", _KNOWN) == {"DeviceProcessEvents"}


def test_extract_join_with_paren_and_kind() -> None:
    q = "DeviceProcessEvents\n| join kind=inner (DeviceNetworkEvents | where y) on DeviceId"
    assert extract_source_tables(q, _KNOWN) == {"DeviceProcessEvents", "DeviceNetworkEvents"}


def test_extract_join_without_paren() -> None:
    q = "DeviceProcessEvents\n| join kind=leftouter SigninLogs on AccountSid"
    assert extract_source_tables(q, _KNOWN) == {"DeviceProcessEvents", "SigninLogs"}


def test_extract_union_paren_and_comma_list() -> None:
    q = "union (SigninLogs | where a), AuditLogs"
    assert extract_source_tables(q, _KNOWN) == {"SigninLogs", "AuditLogs"}


def test_extract_validation_drops_non_tables() -> None:
    # FakeColumn (a where-column) is not a known table -> dropped.
    assert extract_source_tables("SigninLogs | where FakeColumn > 1", _KNOWN) == {"SigninLogs"}


def test_extract_skips_let_and_comments() -> None:
    q = "// a comment\nlet Threshold = 5;\nSigninLogs | where x > Threshold"
    assert extract_source_tables(q, _KNOWN) == {"SigninLogs"}


# ---------------------------------------------------------------------------
# load_known_tables (reads the committed schema surface)
# ---------------------------------------------------------------------------


def test_load_known_tables_includes_real_tables() -> None:
    known = load_known_tables()
    assert "SigninLogs" in known and "DeviceProcessEvents" in known
    assert len(known) > 100  # full Sentinel + Defender surface


# ---------------------------------------------------------------------------
# compute_source_coverage (status-aware + unrecognised)
# ---------------------------------------------------------------------------


def test_compute_source_coverage_buckets_and_status(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(S, "load_known_tables",
                        lambda: frozenset({"SigninLogs", "DeviceProcessEvents"}))
    det = tmp_path / "detections"
    _write_rule(det, "r-prod", "production", "SigninLogs | where a")
    _write_rule(det, "r-exp", "experimental", "SigninLogs | where b")
    _write_rule(det, "r-dev", "production", "DeviceProcessEvents | where c")
    _write_rule(det, "r-custom", "production", "Custom_CL | where d")  # unknown source

    rep = S.compute_source_coverage(det)
    by = {s.table: s for s in rep.sources}
    assert by["SigninLogs"].detection_count == 2
    assert by["SigninLogs"].production_detection_count == 1  # 1 prod, 1 experimental
    assert by["DeviceProcessEvents"].detection_count == 1
    assert rep.total_detections == 4
    assert rep.detections_without_known_source == 1  # Custom_CL not in schema
    assert "Custom_CL" in rep.unrecognised_tables
    # Sorted by detection_count desc -> SigninLogs first.
    assert rep.sources[0].table == "SigninLogs"


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------


def test_render_markdown_flags_zero_production() -> None:
    rep = SourceCoverageReport(
        sources=[SourceCoverage("SigninLogs", detection_count=3, production_detection_count=0)],
        total_detections=3, detections_with_a_known_source=3,
        detections_without_known_source=0, unrecognised_tables=(),
        known_tables_available=True,
    )
    row = next(l for l in render_markdown(rep).splitlines() if "SigninLogs" in l)
    assert "⚠️" in row  # detections exist but none production


def test_render_markdown_schema_unavailable() -> None:
    rep = SourceCoverageReport([], 0, 0, 0, (), known_tables_available=False)
    assert "Schema surface unavailable" in render_markdown(rep)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_by_source_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(S, "load_known_tables", lambda: frozenset({"SigninLogs"}))
    det = tmp_path / "detections"
    _write_rule(det, "r1", "production", "SigninLogs | where x")
    result = CliRunner().invoke(
        cli, ["coverage", "--by-source", "--path", str(det), "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["sources"][0]["table"] == "SigninLogs"
    assert data["sources"][0]["detection_count"] == 1
