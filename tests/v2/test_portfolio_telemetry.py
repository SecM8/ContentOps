# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for F20 portfolio telemetry column population.

Covers the merge logic in `contentops/cli/commands/portfolio.py` between
`portfolio_build_rows` output and the workspace KQL response from
`contentops.workspace_kql.telemetry_query`. Mocks at the
`contentops.workspace_kql.query` symbol (imported inside the CLI
function so monkeypatch on the module attribute takes effect each call).
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.workspace_kql import QueryResult, WorkspaceKqlError


# ---------------------------------------------------------------------------
# Fixture helpers — mirror tests/v2/test_portfolio.py shape
# ---------------------------------------------------------------------------


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
    """Three rules: two telemetry-matched, one with no telemetry row."""
    base = tmp_path / "detections"
    for rule_id, display in [
        ("rule-a", "Rule A"),
        ("rule-b", "Rule B"),
        ("rule-orphan", "Orphan Rule"),
    ]:
        _write(
            base / "sentinel_analytic" / f"{rule_id}.yml",
            {
                "id": rule_id,
                "version": "1.0.0",
                "asset": "sentinel_analytic",
                "status": "production",
                "metadata": _md(),
                "payload": {
                    "displayName": display,
                    "enabled": True,
                    "queryPeriod": "PT1H",
                    "query": "T | take 1",
                },
            },
        )
    return base


def _fake_credential():
    """Mimic the minimal surface of azure.identity credentials."""
    class _Token:
        def __init__(self, value: str) -> None:
            self.token = value

    class _Cred:
        def get_token(self, *scopes):
            return _Token("stub-token")

    return _Cred()


def _patch_auth_ok(monkeypatch) -> None:
    """Make `get_credential()` return a stub credential."""
    import contentops.utils.auth as auth_mod
    monkeypatch.setattr(auth_mod, "get_credential", _fake_credential)


def _telemetry_rows(rows: list[dict]) -> QueryResult:
    """Build a QueryResult shaped like the LA Query API would deliver."""
    return QueryResult(
        rows=rows,
        column_names=["rule_name", "alerts_30d", "incidents_30d", "closed_fp_30d"],
    )


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
        return reader.fieldnames or [], rows


def _by_display(rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    return {r["display_name"]: r for r in rows}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_telemetry_populates_all_four_columns(
    tree: Path, tmp_path: Path, monkeypatch,
) -> None:
    """Happy path: telemetry response covers two rules; third gets Nones.

    Rule A: alerts=10, incidents=5, fp=1 -> fp_rate=0.2
    Rule B: alerts=0, incidents=0 -> fp_rate empty (None branch)
    Orphan Rule: absent from KQL response -> all four cells empty
    """
    _patch_auth_ok(monkeypatch)
    import contentops.workspace_kql as ws

    def fake_query(*args, **kwargs):
        return _telemetry_rows([
            {"rule_name": "Rule A", "alerts_30d": 10, "incidents_30d": 5, "closed_fp_30d": 1},
            {"rule_name": "Rule B", "alerts_30d": 0, "incidents_30d": 0, "closed_fp_30d": 0},
        ])

    monkeypatch.setattr(ws, "query", fake_query)

    out_csv = tmp_path / "p.csv"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "portfolio", "--path", str(tree),
        "--with-telemetry", "--workspace-id", "ws-test",
        "--out-csv", str(out_csv),
    ])
    assert result.exit_code == 0, result.output

    headers, rows = _read_csv(out_csv)
    assert "alerts_30d" in headers
    assert "incidents_30d" in headers
    assert "closed_fp_30d" in headers
    assert "fp_rate" in headers
    assert len(rows) == 3

    by_name = _by_display(rows)
    # Rule A: full telemetry.
    a = by_name["Rule A"]
    assert a["alerts_30d"] == "10"
    assert a["incidents_30d"] == "5"
    assert a["closed_fp_30d"] == "1"
    assert a["fp_rate"] == "0.2"
    # Rule B: zero incidents -> fp_rate empty cell (None serialised).
    b = by_name["Rule B"]
    assert b["alerts_30d"] == "0"
    assert b["incidents_30d"] == "0"
    assert b["closed_fp_30d"] == "0"
    assert b["fp_rate"] == ""
    # Orphan: not in response -> all four cells empty.
    o = by_name["Orphan Rule"]
    assert o["alerts_30d"] == ""
    assert o["incidents_30d"] == ""
    assert o["closed_fp_30d"] == ""
    assert o["fp_rate"] == ""


def test_fp_rate_rounded_to_three_dp(
    tree: Path, tmp_path: Path, monkeypatch,
) -> None:
    """1/3 -> 0.333; 2/7 -> 0.286 (rounded). The CLI uses round(_, 3)."""
    _patch_auth_ok(monkeypatch)
    import contentops.workspace_kql as ws

    def fake_query(*args, **kwargs):
        return _telemetry_rows([
            {"rule_name": "Rule A", "alerts_30d": 100, "incidents_30d": 3, "closed_fp_30d": 1},
            {"rule_name": "Rule B", "alerts_30d": 200, "incidents_30d": 7, "closed_fp_30d": 2},
        ])

    monkeypatch.setattr(ws, "query", fake_query)

    out_csv = tmp_path / "p.csv"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "portfolio", "--path", str(tree),
        "--with-telemetry", "--workspace-id", "ws-test",
        "--out-csv", str(out_csv),
    ])
    assert result.exit_code == 0, result.output

    _, rows = _read_csv(out_csv)
    by_name = _by_display(rows)
    assert by_name["Rule A"]["fp_rate"] == "0.333"
    assert by_name["Rule B"]["fp_rate"] == "0.286"


def test_telemetry_graceful_degradation_on_kql_error(
    tree: Path, tmp_path: Path, monkeypatch, capsys,
) -> None:
    """workspace_kql.query raises WorkspaceKqlError -> exit 0, columns empty."""
    _patch_auth_ok(monkeypatch)
    import contentops.workspace_kql as ws

    def raise_kql(*args, **kwargs):
        raise WorkspaceKqlError("LA Query returned 500: server error")

    monkeypatch.setattr(ws, "query", raise_kql)

    out_csv = tmp_path / "p.csv"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "portfolio", "--path", str(tree),
        "--with-telemetry", "--workspace-id", "ws-test",
        "--out-csv", str(out_csv),
    ])
    assert result.exit_code == 0, result.output
    assert "telemetry fetch failed" in result.stderr

    headers, rows = _read_csv(out_csv)
    # Columns are still added (extra_columns is set), but cells are empty.
    assert "fp_rate" in headers
    for row in rows:
        assert row["alerts_30d"] == ""
        assert row["incidents_30d"] == ""
        assert row["closed_fp_30d"] == ""
        assert row["fp_rate"] == ""


def test_telemetry_graceful_degradation_on_auth_error(
    tree: Path, tmp_path: Path, monkeypatch,
) -> None:
    """get_credential() raises -> exit 0, columns empty."""
    import contentops.utils.auth as auth_mod

    def raise_auth():
        raise RuntimeError("no OIDC token")

    monkeypatch.setattr(auth_mod, "get_credential", raise_auth)

    out_csv = tmp_path / "p.csv"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "portfolio", "--path", str(tree),
        "--with-telemetry", "--workspace-id", "ws-test",
        "--out-csv", str(out_csv),
    ])
    assert result.exit_code == 0, result.output
    assert "telemetry token/auth failed" in result.stderr

    _, rows = _read_csv(out_csv)
    for row in rows:
        assert row["fp_rate"] == ""


def test_telemetry_off_omits_columns(
    tree: Path, tmp_path: Path,
) -> None:
    """Without --with-telemetry the four columns are not in the header."""
    out_csv = tmp_path / "p.csv"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "portfolio", "--path", str(tree),
        "--out-csv", str(out_csv),
    ])
    assert result.exit_code == 0, result.output

    headers, _ = _read_csv(out_csv)
    for col in ("alerts_30d", "incidents_30d", "closed_fp_30d", "fp_rate"):
        assert col not in headers
