# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for the portfolio CSV/JSON renderer (W4-6)."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.portfolio import COLUMNS, build_rows, write_csv, write_json
from contentops.portfolio.report import (
    iso8601_duration_to_minutes,
    render_csv_string,
)


# --------------------------------------------------------------------------
# fixtures: write a self-contained mini-tree of detections so the test is
# independent of the live repo content.
# --------------------------------------------------------------------------


def _md(**overrides) -> dict:
    base = {
        "owner": "blue@example.com",
        "runbookUrl": "https://wiki/r",
        "severity": "high",
        "tactics": ["Execution"],
        "techniques": ["T1059.001"],
        "expectedAlertsPerDay": 3,
        "fpHandling": "FP guidance.",
    }
    base.update(overrides)
    return base


def _write(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    base = tmp_path / "detections"
    # sentinel_analytic — non-legacy with cohort
    _write(
        base / "sentinel_analytic" / "pipeline-self" / "rule-a.yml",
        {
            "id": "rule-a",
            "version": "1.0.0",
            "asset": "sentinel_analytic",
            "status": "production",
            "metadata": _md(
                cohort="pipeline-self",
                lastValidatedAt="2026-04-01T00:00:00Z",
                tactics=["Execution", "DefenseEvasion"],
                techniques=["T1059.001", "T1027"],
            ),
            "payload": {
                "displayName": "Rule A",
                "enabled": True,
                "queryPeriod": "PT1H",
                "query": "T\n| where x == 1\n\n| take 10\n",
            },
        },
    )
    # sentinel_analytic — non-legacy, different cohort
    _write(
        base / "sentinel_analytic" / "other" / "rule-b.yml",
        {
            "id": "rule-b",
            "version": "1.0.0",
            "asset": "sentinel_analytic",
            "status": "production",
            "metadata": _md(cohort="other", expectedAlertsPerDay=10),
            "payload": {
                "displayName": "Rule B",
                "enabled": False,
                "queryPeriod": "P1D",
                "query": "T | take 1",
            },
        },
    )
    # sentinel_hunting — no enabled flag, no metadata cohort
    _write(
        base / "sentinel_hunting" / "hunt-c.yml",
        {
            "id": "hunt-c",
            "version": "1.0.0",
            "asset": "sentinel_hunting",
            "status": "experimental",
            "metadata": _md(severity="medium"),
            "payload": {
                "displayName": "Hunt C",
                "query": "DeviceProcessEvents\n| take 5\n",
            },
        },
    )
    # defender — non-legacy, queryCondition.queryText
    _write(
        base / "defender" / "det-d.yml",
        {
            "id": "det-d",
            "version": "1.0.0",
            "asset": "defender_custom_detection",
            "status": "production",
            "metadata": _md(severity="low"),
            "payload": {
                "displayName": "Det D",
                "isEnabled": True,
                "queryCondition": {"queryText": "DeviceEvents | take 1"},
            },
        },
    )
    # collected envelope — only metadata.arm_name, no rich author fields
    _write(
        base / "sentinel_analytic" / "loose" / "loose-e.yml",
        {
            "id": "loose-e",
            "version": "1.0.0",
            "asset": "sentinel_analytic",
            "status": "production",
            "metadata": {"arm_name": "loose-e-arm"},
            "payload": {
                "displayName": "Loose E",
                "enabled": True,
                "query": "T | take 1",
                "queryPeriod": "PT5M",
            },
        },
    )
    # non-detection asset — must be filtered out
    _write(
        base / "sentinel_watchlist" / "wl.yml",
        {
            "id": "wl-x",
            "version": "1.0.0",
            "asset": "sentinel_watchlist",
            "status": "production",
            "payload": {"displayName": "WL"},
        },
    )
    return base


# --------------------------------------------------------------------------
# tests
# --------------------------------------------------------------------------


def test_iso_duration_conversions() -> None:
    assert iso8601_duration_to_minutes("PT5M") == 5
    assert iso8601_duration_to_minutes("PT1H") == 60
    assert iso8601_duration_to_minutes("PT1D") == 1440
    assert iso8601_duration_to_minutes("P1D") == 1440
    assert iso8601_duration_to_minutes("PT90M") == 90
    # unsupported / bogus → None (not a crash)
    assert iso8601_duration_to_minutes(None) is None
    assert iso8601_duration_to_minutes("") is None
    assert iso8601_duration_to_minutes("P1W") is None
    assert iso8601_duration_to_minutes("notaduration") is None
    assert iso8601_duration_to_minutes("PT1H30M") is None


def test_row_shape_per_asset_type(tree: Path) -> None:
    rows = build_rows(tree)
    by_id = {r["id"]: r for r in rows}

    # non-detection asset filtered out
    assert "wl-x" not in by_id
    # all detection assets included (rich + loose)
    assert set(by_id) == {"rule-a", "rule-b", "hunt-c", "det-d", "loose-e"}

    # analytic
    a = by_id["rule-a"]
    assert a["asset"] == "sentinel_analytic"
    assert a["display_name"] == "Rule A"
    assert a["enabled"] is True
    assert a["query_period_minutes"] == 60
    assert a["expected_alerts_per_day"] == 3
    assert a["cohort"] == "pipeline-self"
    assert a["last_validated_at"] == "2026-04-01T00:00:00Z"
    # the KQL has 4 lines but 1 blank → 3 non-blank
    assert a["query_lines"] == 3

    # hunting — no enabled, no cohort, no query period
    h = by_id["hunt-c"]
    assert h["asset"] == "sentinel_hunting"
    assert h["enabled"] is None
    assert h["query_period_minutes"] is None
    assert h["cohort"] is None
    assert h["query_lines"] == 2

    # defender — uses queryCondition.queryText, isEnabled
    d = by_id["det-d"]
    assert d["asset"] == "defender_custom_detection"
    assert d["enabled"] is True
    assert d["query_lines"] == 1
    assert d["query_period_minutes"] is None

    # loose — only arm_name in metadata; rich-metadata fields empty
    e = by_id["loose-e"]
    assert e["severity"] is None
    assert e["tactics"] == []
    assert e["expected_alerts_per_day"] is None
    assert e["last_validated_at"] is None


def test_cohort_filter(tree: Path) -> None:
    rows = build_rows(tree, cohort="pipeline-self")
    assert [r["id"] for r in rows] == ["rule-a"]


def test_csv_column_order_stable(tree: Path) -> None:
    rows = build_rows(tree)
    text = render_csv_string(rows)
    reader = csv.reader(io.StringIO(text))
    header = next(reader)
    assert tuple(header) == COLUMNS
    # And the rendered row count matches
    body = list(reader)
    assert len(body) == len(rows)


def test_csv_renders_lists_and_bools_and_empties(tree: Path) -> None:
    rows = build_rows(tree, cohort="pipeline-self")
    text = render_csv_string(rows)
    reader = csv.DictReader(io.StringIO(text))
    row = next(reader)
    # tactics joined by ';'
    assert row["tactics"] == "Execution;DefenseEvasion"
    assert row["techniques"] == "T1059.001;T1027"
    assert row["enabled"] == "true"
    # cohort + last_validated populated
    assert row["cohort"] == "pipeline-self"
    assert row["last_validated_at"] == "2026-04-01T00:00:00Z"


def test_csv_loose_metadata_optional_fields_render_empty(tree: Path) -> None:
    rows = build_rows(tree)
    text = render_csv_string(rows)
    reader = csv.DictReader(io.StringIO(text))
    loose_row = next(r for r in reader if r["id"] == "loose-e")
    assert loose_row["severity"] == ""
    assert loose_row["tactics"] == ""
    assert loose_row["expected_alerts_per_day"] == ""
    assert loose_row["last_validated_at"] == ""
    assert loose_row["cohort"] == ""


def test_json_shape(tree: Path, tmp_path: Path) -> None:
    rows = build_rows(tree)
    out = tmp_path / "p.json"
    write_json(rows, out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) == len(rows)
    sample = next(r for r in data if r["id"] == "hunt-c")
    # Every documented column key is present, even when value is null.
    for col in COLUMNS:
        assert col in sample
    assert sample["enabled"] is None
    assert sample["query_period_minutes"] is None
    assert sample["tactics"] == ["Execution"]


def test_query_line_count_ignores_blank_lines(tree: Path) -> None:
    rows = build_rows(tree)
    by_id = {r["id"]: r for r in rows}
    # rule-a query was 4 physical lines with 1 blank
    assert by_id["rule-a"]["query_lines"] == 3


def test_write_csv_to_path(tree: Path, tmp_path: Path) -> None:
    rows = build_rows(tree)
    out = tmp_path / "p.csv"
    write_csv(rows, out)
    text = out.read_text(encoding="utf-8")
    reader = csv.reader(io.StringIO(text))
    assert tuple(next(reader)) == COLUMNS
    assert sum(1 for _ in reader) == len(rows)


def test_cli_default_prints_csv_to_stdout(tree: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["portfolio", "--path", str(tree)])
    assert result.exit_code == 0, result.output
    # First line is the header.
    first_line = result.output.splitlines()[0]
    assert first_line == ",".join(COLUMNS)


def test_cli_cohort_pipeline_self_4_rows(tmp_path: Path) -> None:
    """Cohort filter returns exactly the fixture rows tagged with that cohort."""
    base = tmp_path / "detections"
    for name in ("rule-1", "rule-2", "rule-3", "rule-4"):
        _write(
            base / "sentinel_analytic" / "pipeline-self" / f"{name}.yml",
            {
                "id": name,
                "version": "1.0.0",
                "asset": "sentinel_analytic",
                "status": "production",
                "metadata": _md(cohort="pipeline-self"),
                "payload": {
                    "displayName": name,
                    "enabled": True,
                    "queryPeriod": "PT1H",
                    "query": "T | take 1",
                },
            },
        )
    # Decoy in a different cohort that must NOT be returned.
    _write(
        base / "sentinel_analytic" / "other" / "rule-x.yml",
        {
            "id": "rule-x",
            "version": "1.0.0",
            "asset": "sentinel_analytic",
            "status": "production",
            "metadata": _md(cohort="other"),
            "payload": {
                "displayName": "Rule X",
                "enabled": True,
                "queryPeriod": "PT1H",
                "query": "T | take 1",
            },
        },
    )

    rows = build_rows(base, cohort="pipeline-self")
    assert len(rows) == 4
    assert all(r["asset"] == "sentinel_analytic" for r in rows)
    assert all(r["cohort"] == "pipeline-self" for r in rows)


# --------------------------------------------------------------------------
# MITRE coverage footer
# --------------------------------------------------------------------------


def test_cli_portfolio_emits_mitre_footer_to_stderr(tree: Path) -> None:
    """Portfolio output gains a single stderr line summarising MITRE
    coverage when the detection set is non-empty. Same number as the
    README badge (uses contentops.coverage.coverage_summary). Stderr
    so it doesn't pollute the CSV on stdout."""
    runner = CliRunner()
    result = runner.invoke(cli, ["portfolio", "--path", str(tree)])
    assert result.exit_code == 0, result.output

    # CliRunner merges stderr into result.output by default unless
    # mix_stderr=False; both Click 8.x and 9.x default to mixed. Look
    # in the full output, anchored on the footer prefix.
    assert "MITRE ATT&CK coverage:" in result.output
    assert "techniques (" in result.output  # contains pct + slash counts


def test_cli_portfolio_skips_mitre_footer_when_empty(tmp_path: Path) -> None:
    """No detections in tree -> no MITRE footer (graceful no-data
    short-circuit, matches the no-detections behaviour of the rest
    of the portfolio render path)."""
    empty = tmp_path / "detections"
    empty.mkdir()
    runner = CliRunner()
    result = runner.invoke(cli, ["portfolio", "--path", str(empty)])
    assert result.exit_code == 0
    assert "MITRE ATT&CK coverage:" not in result.output
