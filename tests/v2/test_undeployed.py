# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops undeployed-rules` (authored-but-never-deployed).

Reconciles repo envelopes against the applied-state managed set: a repo
rule with no state record was never deployed. A production rule there is
the blind spot (flagged); an experimental rule is expected.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.state import EnvState, save_state
from contentops.undeployed import find_undeployed, render_json, render_markdown


def _write_rule(detections: Path, rule_id: str, status: str,
                asset: str = "sentinel_analytic") -> None:
    d = detections / asset
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{rule_id}.yml").write_text(yaml.safe_dump({
        "id": rule_id, "version": "1.0.0", "asset": asset, "status": status,
        "metadata": {
            "owner": "blue@contoso.com", "runbookUrl": "https://wiki/runbook",
            "severity": "medium", "tactics": ["Execution"],
            "techniques": ["T1059"], "expectedAlertsPerDay": 1,
            "fpHandling": "n/a",
        },
        "payload": {"query": "T | take 1", "displayName": rule_id},
    }, sort_keys=False), encoding="utf-8")


def _three_rule_repo(tmp_path: Path) -> Path:
    det = tmp_path / "detections"
    _write_rule(det, "deployed-prod", "production")
    _write_rule(det, "undeployed-prod", "production")
    _write_rule(det, "undeployed-exp", "experimental")
    return det


# ---------------------------------------------------------------------------
# find_undeployed
# ---------------------------------------------------------------------------


def test_find_undeployed_classifies_against_state(tmp_path: Path) -> None:
    det = _three_rule_repo(tmp_path)
    state = EnvState(env="prod")
    state.remember("sentinel_analytic", "deployed-prod", sha="abc")
    report = find_undeployed(det, state)

    assert {r.rule_id for r in report.undeployed} == {"undeployed-prod", "undeployed-exp"}
    assert {r.rule_id for r in report.production_undeployed} == {"undeployed-prod"}
    assert report.state_available is True
    assert report.total_repo == 3 and report.total_managed == 1


def test_find_undeployed_empty_state_is_unavailable(tmp_path: Path) -> None:
    det = _three_rule_repo(tmp_path)
    report = find_undeployed(det, EnvState(env=""))
    assert report.state_available is False
    # With no state, everything is technically "not managed".
    assert len(report.undeployed) == 3


def test_find_undeployed_production_sorted_first(tmp_path: Path) -> None:
    det = _three_rule_repo(tmp_path)
    report = find_undeployed(det, EnvState(env="prod"))  # empty -> all undeployed
    # Production rule(s) sort before non-production.
    assert report.undeployed[0].status == "production"


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------


def test_render_markdown_flags_only_production(tmp_path: Path) -> None:
    det = _three_rule_repo(tmp_path)
    state = EnvState(env="prod")
    state.remember("sentinel_analytic", "deployed-prod", sha="abc")
    md = render_markdown(find_undeployed(det, state))
    prod_row = next(l for l in md.splitlines() if "undeployed-prod" in l)
    exp_row = next(l for l in md.splitlines() if "undeployed-exp" in l)
    assert "⚠️" in prod_row and "⚠️" not in exp_row


def test_render_markdown_state_unavailable_suppresses_list(tmp_path: Path) -> None:
    det = _three_rule_repo(tmp_path)
    md = render_markdown(find_undeployed(det, EnvState(env="")))
    assert "State unavailable" in md
    # The per-rule list is suppressed when state is unavailable.
    assert "undeployed-prod" not in md


def test_render_json_structure(tmp_path: Path) -> None:
    det = _three_rule_repo(tmp_path)
    state = EnvState(env="prod")
    state.remember("sentinel_analytic", "deployed-prod", sha="abc")
    data = json.loads(render_json(find_undeployed(det, state)))
    assert data["state_available"] is True
    assert data["total_repo"] == 3 and data["total_managed"] == 1
    assert data["production_undeployed_count"] == 1
    assert {r["rule_id"] for r in data["undeployed"]} == {"undeployed-prod", "undeployed-exp"}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_runs_and_reports_state_unavailable(tmp_path: Path) -> None:
    det = tmp_path / "detections"
    _write_rule(det, "r1", "production")
    result = CliRunner().invoke(cli, ["undeployed-rules", "--path", str(det)])
    assert result.exit_code == 0, result.output
    assert "Authored but never deployed" in result.output
    assert "State unavailable" in result.output  # no state/state.json in cwd


def test_cli_with_state_reports_undeployed(tmp_path: Path) -> None:
    # conftest chdir's to tmp_path, so save_state writes state/state.json that
    # the command's load_state() (cwd-relative) then reads.
    det = tmp_path / "detections"
    _write_rule(det, "deployed", "production")
    _write_rule(det, "undeployed", "production")
    st = EnvState(env="")
    st.remember("sentinel_analytic", "deployed", sha="x")
    save_state(st)

    result = CliRunner().invoke(
        cli, ["undeployed-rules", "--path", str(det), "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["state_available"] is True and data["total_managed"] == 1
    assert {r["rule_id"] for r in data["undeployed"]} == {"undeployed"}
    assert data["production_undeployed_count"] == 1
