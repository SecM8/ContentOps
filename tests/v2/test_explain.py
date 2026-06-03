# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops explain <rule-id>` (F16).

Layered:
* Pure-function tests for build_explain against synthetic
  detections + state + audit fixtures.
* Render tests (markdown sections, JSON parseability).
* CLI integration via CliRunner.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from contentops import explain as ex
from contentops.cli import cli


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_RULE_V2 = """\
id: brute-force-ssh-001
version: 1.0.0
asset: sentinel_analytic
status: production
metadata:
  owner: secops@example.com
  runbookUrl: https://runbooks.example.com/brute-force-ssh-001
  severity: medium
  tactics: [CredentialAccess]
  techniques: [T1110]
  expectedAlertsPerDay: 1
  fpHandling: "Triage manually."
payload:
  displayName: Brute Force SSH
  query: |
    SecurityEvent | where TimeGenerated > ago(1h)
"""


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Build a synthetic workspace with detections + audit + state."""
    detections = tmp_path / "detections"
    sentinel_analytic = detections / "sentinel_analytic"
    sentinel_analytic.mkdir(parents=True)
    (sentinel_analytic / "brute-force-ssh-001.yml").write_text(
        _RULE_V2, encoding="utf-8",
    )

    # dependencies.yml
    (detections / "dependencies.yml").write_text(yaml.safe_dump({
        "version": "1.0",
        "assets": {
            "brute-force-ssh-001": {
                "tables": ["SecurityEvent"],
                "watchlists": [],
                "parsers": [],
                "detections": [],
            },
        },
    }), encoding="utf-8")

    # audit/*.jsonl
    audit = tmp_path / "audit"
    audit.mkdir()
    records = [
        {
            "timestamp": "2026-05-04T19:02:07.000000Z",
            "asset": "sentinel_analytic", "id": "brute-force-ssh-001",
            "action": "update", "status": "success",
            "sha": "93f213600000", "actor": "github-actions",
            "workflow_run": "9000", "message": None,
            "metadata_owner": "secops@example.com",
            "prev_hash": "0" * 64, "record_hash": "x" * 64,
        },
        {
            "timestamp": "2026-05-06T22:14:33.481000Z",
            "asset": "sentinel_analytic", "id": "brute-force-ssh-001",
            "action": "update", "status": "success",
            "sha": "8356ae9b1234", "actor": "github-actions",
            "workflow_run": "9100", "message": None,
            "metadata_owner": "secops@example.com",
            "prev_hash": "0" * 64, "record_hash": "y" * 64,
        },
    ]
    (audit / "2026-05-06.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )

    # drift_report.json (rule reported as in-sync via absence)
    (tmp_path / "drift_report.json").write_text(json.dumps({
        "tenant": "production",
        "workspace": "law-sentinel",
        "run_id": "",
        "entries": [
            {"asset": "sentinel_analytic", "id": "another-rule", "kind": "changed"},
        ],
    }), encoding="utf-8")

    return tmp_path


# ---------------------------------------------------------------------------
# build_explain
# ---------------------------------------------------------------------------


def test_build_explain_unknown_id_returns_not_found(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    detections.mkdir()
    e = ex.build_explain(
        "ghost-rule",
        detections_root=detections, audit_dir=tmp_path / "audit",
        state_root=tmp_path, drift_root=tmp_path,
    )
    assert e.found is False
    assert e.rule_id == "ghost-rule"


def test_build_explain_v2_envelope_populates_metadata(workspace: Path) -> None:
    e = ex.build_explain(
        "brute-force-ssh-001",
        detections_root=workspace / "detections",
        audit_dir=workspace / "audit",
        state_root=workspace, drift_root=workspace,
    )
    assert e.found is True
    assert e.asset == "sentinel_analytic"
    assert e.status == "production"
    assert e.owner == "secops@example.com"
    assert e.runbook_url == "https://runbooks.example.com/brute-force-ssh-001"
    assert e.severity == "medium"
    assert e.tactics == ["CredentialAccess"]
    assert e.techniques == ["T1110"]


def test_build_explain_dependencies_populated(workspace: Path) -> None:
    e = ex.build_explain(
        "brute-force-ssh-001",
        detections_root=workspace / "detections",
        audit_dir=workspace / "audit",
        state_root=workspace, drift_root=workspace,
    )
    assert e.needs_tables == ["SecurityEvent"]


def test_build_explain_audit_records_newest_first(workspace: Path) -> None:
    e = ex.build_explain(
        "brute-force-ssh-001",
        detections_root=workspace / "detections",
        audit_dir=workspace / "audit",
        state_root=workspace, drift_root=workspace,
    )
    assert len(e.recent_audit) == 2
    # Newer record first.
    assert e.recent_audit[0].timestamp == "2026-05-06T22:14:33.481000Z"
    assert e.recent_audit[1].timestamp == "2026-05-04T19:02:07.000000Z"


def test_build_explain_drift_in_sync_when_not_in_report(workspace: Path) -> None:
    """Rule absent from drift_report.json entries means in-sync."""
    e = ex.build_explain(
        "brute-force-ssh-001",
        detections_root=workspace / "detections",
        audit_dir=workspace / "audit",
        state_root=workspace, drift_root=workspace,
    )
    assert e.drift_status == "in-sync"


def test_build_explain_drift_status_changed_when_listed(workspace: Path) -> None:
    """Rule listed in entries surfaces with that kind."""
    # 'another-rule' is listed as changed in the workspace fixture's drift report.
    detections = workspace / "detections"
    sentinel = detections / "sentinel_analytic"
    (sentinel / "another-rule.yml").write_text(
        _RULE_V2.replace("brute-force-ssh-001", "another-rule"),
        encoding="utf-8",
    )
    e = ex.build_explain(
        "another-rule",
        detections_root=detections,
        audit_dir=workspace / "audit",
        state_root=workspace, drift_root=workspace,
    )
    assert e.drift_status == "changed"


def test_build_explain_drift_status_none_without_report(tmp_path: Path) -> None:
    """No drift_report.json in cwd → drift_status is None."""
    detections = tmp_path / "detections" / "sentinel_analytic"
    detections.mkdir(parents=True)
    (detections / "rule-x.yml").write_text(
        _RULE_V2.replace("brute-force-ssh-001", "rule-x"),
        encoding="utf-8",
    )
    e = ex.build_explain(
        "rule-x",
        detections_root=tmp_path / "detections",
        audit_dir=tmp_path / "audit",
        state_root=tmp_path, drift_root=tmp_path,
    )
    assert e.drift_status is None


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_render_markdown_unknown_id_minimal(tmp_path: Path) -> None:
    e = ex.build_explain(
        "ghost",
        detections_root=tmp_path,
        audit_dir=tmp_path / "audit", state_root=tmp_path, drift_root=tmp_path,
    )
    md = ex.render_markdown(e)
    assert "ghost" in md
    assert "no rule found" in md


def test_render_markdown_v2_includes_all_sections(workspace: Path) -> None:
    e = ex.build_explain(
        "brute-force-ssh-001",
        detections_root=workspace / "detections",
        audit_dir=workspace / "audit",
        state_root=workspace, drift_root=workspace,
    )
    md = ex.render_markdown(e)
    assert "## brute-force-ssh-001" in md
    assert "Owner:" in md
    assert "### Dependencies" in md
    assert "### State" in md
    assert "### Recent audit" in md
    assert "### Drift status" in md


def test_render_json_is_parseable(workspace: Path) -> None:
    e = ex.build_explain(
        "brute-force-ssh-001",
        detections_root=workspace / "detections",
        audit_dir=workspace / "audit",
        state_root=workspace, drift_root=workspace,
    )
    parsed = json.loads(ex.render_json(e))
    assert parsed["found"] is True
    assert parsed["rule_id"] == "brute-force-ssh-001"
    assert parsed["owner"] == "secops@example.com"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_explain_unknown_id_exits_1(workspace: Path) -> None:
    runner = CliRunner()
    import os
    cwd = os.getcwd()
    os.chdir(workspace)
    try:
        result = runner.invoke(cli, [
            "explain", "no-such-id",
            "--path", str(workspace / "detections"),
            "--audit-dir", str(workspace / "audit"),
        ])
    finally:
        os.chdir(cwd)
    assert result.exit_code == 1
    assert "no rule found" in result.output


def test_cli_explain_known_id_markdown(workspace: Path) -> None:
    runner = CliRunner()
    import os
    cwd = os.getcwd()
    os.chdir(workspace)
    try:
        result = runner.invoke(cli, [
            "explain", "brute-force-ssh-001",
            "--path", str(workspace / "detections"),
            "--audit-dir", str(workspace / "audit"),
        ])
    finally:
        os.chdir(cwd)
    assert result.exit_code == 0, result.output
    assert "brute-force-ssh-001" in result.output
    assert "secops@example.com" in result.output


def test_cli_explain_json_format(workspace: Path) -> None:
    runner = CliRunner()
    import os
    cwd = os.getcwd()
    os.chdir(workspace)
    try:
        result = runner.invoke(cli, [
            "explain", "brute-force-ssh-001",
            "--path", str(workspace / "detections"),
            "--audit-dir", str(workspace / "audit"),
            "--format", "json",
        ])
    finally:
        os.chdir(cwd)
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed["found"] is True
    assert parsed["asset"] == "sentinel_analytic"
