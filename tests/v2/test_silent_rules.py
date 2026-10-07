# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops silent-rules`` lists the repo's deployed rules.

Regression tests for the follow-up to #395: the command printed only the
telemetry KQL's rows, so a rule that never fired (no alert, no incident,
no row) was missing instead of listed as silent.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.silent_rules import build_report, deployed_statuses, select_rules
from contentops.workspace_kql import QueryResult


def _write(base: Path, asset: str, rule_id: str, payload: dict, status: str = "production",
           arm_name: str | None = None) -> None:
    doc = {"id": rule_id, "version": "1.0.0", "asset": asset, "status": status,
           "payload": payload}
    if arm_name:
        doc["metadata"] = {"arm_name": arm_name}
    path = base / asset / f"{rule_id}.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _defender(title: str, enabled: bool = True) -> dict:
    return {"displayName": title, "isEnabled": enabled,
            "detectionAction": {"alertTemplate": {"title": title}},
            "queryCondition": {"queryText": "DeviceEvents | take 1"}}


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    base = tmp_path / "detections"
    _write(base, "sentinel_analytic", "firing", {"displayName": "Firing", "query": "T"})
    _write(base, "sentinel_analytic", "incident-only",
           {"displayName": "Incident Only", "query": "T"}, arm_name="GUID-2")
    _write(base, "sentinel_analytic", "never-fired", {"displayName": "Never Fired", "query": "T"})
    _write(base, "sentinel_analytic", "disabled",
           {"displayName": "Disabled", "enabled": False, "query": "T"})
    _write(base, "sentinel_analytic", "in-test", {"displayName": "In Test", "query": "T"},
           status="test")
    _write(base, "sentinel_analytic", "retired", {"displayName": "Retired", "query": "T"},
           status="deprecated")
    _write(base, "sentinel_hunting", "hunt", {"displayName": "Hunt", "query": "T"})
    _write(base, "defender_custom_detection", "lsass", _defender("LSASS dump"))
    return base


TELEMETRY = [
    {"rule_key": "id:firing", "rule_name": "Firing from 10.0.0.1",
     "alerts_30d": 7, "incidents_30d": 2, "closed_tp_30d": 1},
    {"rule_key": "id:guid-2", "rule_name": "Incident Only",
     "alerts_30d": 0, "incidents_30d": 1},
    {"rule_key": "name:built-in alert", "rule_name": "Built-in alert", "alerts_30d": 3},
]


def test_select_rules_follows_the_role(repo: Path) -> None:
    prod = {la.envelope.id for la in select_rules(repo, role="prod")}
    # Enabled production analytics + the Defender rule; not disabled,
    # test, deprecated or hunting.
    assert prod == {"firing", "incident-only", "never-fired", "lsass"}
    integration = {la.envelope.id for la in select_rules(repo, role="integration")}
    # Lower env: test + production analytics; Defender deploys to prod only.
    assert integration == {"firing", "incident-only", "never-fired", "in-test"}
    assert deployed_statuses("prod") == ("production",)
    assert deployed_statuses("dev") == ("experimental", "production", "test")


def test_a_rule_that_never_fired_is_listed_as_silent(repo: Path) -> None:
    report = build_report(select_rules(repo, role="prod"), TELEMETRY)
    by_id = {row["id"]: row for row in report.rows}
    assert by_id["never-fired"]["silent"] is True
    assert by_id["never-fired"]["alerts_30d"] == 0
    assert by_id["never-fired"]["rule_keys"] == []
    # Incidents but no alerts: not silent.
    assert by_id["incident-only"]["silent"] is False
    assert by_id["incident-only"]["rule_keys"] == ["id:guid-2"]
    assert by_id["firing"]["alerts_30d"] == 7
    # Silent rules first.
    assert [row["silent"] for row in report.rows] == [True, True, False, False]
    assert (report.rule_count, report.silent_count) == (4, 2)
    # The unmatched built-in alert is not listed by default.
    assert all(row["source"] == "repo" for row in report.rows)


def test_include_unmatched_appends_workspace_rows(repo: Path) -> None:
    report = build_report(select_rules(repo, role="prod"), TELEMETRY, include_unmatched=True)
    workspace = [row for row in report.rows if row["source"] == "workspace"]
    assert [(row["rule_name"], row["alerts_30d"], row["rule_keys"]) for row in workspace] == [
        ("Built-in alert", 3, ["name:built-in alert"]),
    ]
    assert report.rule_count == 4


def test_defender_note_when_no_defender_rule_matches(repo: Path) -> None:
    rules = select_rules(repo, role="prod")
    report = build_report(rules, TELEMETRY)
    assert len(report.notes) == 1
    assert "Defender XDR connector" in report.notes[0]
    matched = build_report(rules, [*TELEMETRY, {"rule_key": "name:lsass dump", "alerts_30d": 1}])
    assert matched.notes == []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@pytest.fixture
def mocked_workspace(monkeypatch):
    import contentops.utils.auth as auth_mod
    import contentops.workspace_kql as ws

    class _Token:
        token = "stub"

    class _Cred:
        def get_token(self, *a, **kw):
            return _Token()

    monkeypatch.setattr(auth_mod, "get_credential", lambda: _Cred())
    monkeypatch.setattr(ws, "query", lambda *a, **kw: QueryResult(rows=[dict(r) for r in TELEMETRY]))


def _run(repo: Path, *args: str):
    return CliRunner().invoke(cli, [
        "silent-rules", "--path", str(repo), "--workspace-id", "ws", *args,
    ])


def test_cli_table_lists_silent_rules_with_zeros(repo: Path, mocked_workspace) -> None:
    result = _run(repo)
    assert result.exit_code == 0, result.output
    lines = result.stdout.splitlines()
    never = next(line for line in lines if " never-fired " in line)
    # 0 is printed, not a blank cell.
    assert never.split()[:4] == ["yes", "sentinel_analytic", "never-fired", "production"]
    assert " 0 " in never
    assert "2 of 4 rule(s) silent over the last 30d" in result.stdout
    assert "source" not in lines[0]
    assert "note: none of the 1 Defender custom detection(s)" in result.stderr


def test_cli_json_and_csv(repo: Path, mocked_workspace) -> None:
    rows = json.loads(_run(repo, "--format", "json").stdout)
    assert {r["id"] for r in rows if r["silent"]} == {"never-fired", "lsass"}
    with_unmatched = json.loads(_run(repo, "--format", "json", "--include-unmatched").stdout)
    assert [r["rule_name"] for r in with_unmatched if r["source"] == "workspace"] == [
        "Built-in alert",
    ]
    parsed = list(csv.DictReader(io.StringIO(_run(repo, "--format", "csv").stdout)))
    never = next(r for r in parsed if r["id"] == "never-fired")
    assert (never["silent"], never["alerts_30d"], never["rule_keys"]) == ("true", "0", "")


def test_cli_reports_files_that_do_not_load(repo: Path, mocked_workspace) -> None:
    (repo / "sentinel_analytic" / "broken.yml").write_text("id: [\n", encoding="utf-8")
    result = _run(repo)
    assert result.exit_code == 0, result.output
    assert "warning: 1 file(s)" in result.stderr


def test_cli_missing_path_fails_before_any_query(tmp_path: Path, monkeypatch) -> None:
    import contentops.utils.auth as auth_mod

    def _no_credential():
        raise AssertionError("must not authenticate")

    monkeypatch.setattr(auth_mod, "get_credential", _no_credential)
    result = _run(tmp_path / "nope")
    assert result.exit_code == 1
    assert "detections path not found" in result.stderr
