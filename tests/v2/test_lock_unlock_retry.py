# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for `contentops lock`, `contentops unlock`, and `contentops retry-failed`.

Lock/unlock toggle a top-level ``localCustomization: true`` flag in the
envelope on disk. Apply then refuses to push locked assets unless
``--force-overwrite`` is set.

retry-failed parses the latest audit JSONL, derives (asset, id) pairs
with status=failed, and re-applies just those.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.cli.commands import _is_locked
from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset


def _write_rule(detections: Path, rule_id: str, *, locked: bool = False) -> Path:
    detections.mkdir(parents=True, exist_ok=True)
    target = detections / f"{rule_id}.yml"
    body = {
        "id": rule_id,
        "version": "1.0.0",
        "asset": "sentinel_analytic",
        "status": "production",
        "payload": {
            "kind": "Scheduled",
            "displayName": "x",
            "severity": "Low",
            "query": "print 1",
            "queryFrequency": "PT5M",
            "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
        },
    }
    if locked:
        body["localCustomization"] = True
    target.write_text(yaml.safe_dump(body), encoding="utf-8")
    return target


def test_lock_adds_flag(tmp_path: Path) -> None:
    target = _write_rule(tmp_path, "rule-1")
    result = CliRunner().invoke(
        cli, ["lock", "rule-1", "--path", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert raw["localCustomization"] is True


def test_lock_idempotent(tmp_path: Path) -> None:
    _write_rule(tmp_path, "rule-1", locked=True)
    result = CliRunner().invoke(
        cli, ["lock", "rule-1", "--path", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    assert "locked" in result.output


def test_unlock_removes_flag(tmp_path: Path) -> None:
    target = _write_rule(tmp_path, "rule-1", locked=True)
    result = CliRunner().invoke(
        cli, ["unlock", "rule-1", "--path", str(tmp_path)],
    )
    assert result.exit_code == 0, result.output
    raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert "localCustomization" not in raw


def test_unlock_no_flag_present(tmp_path: Path) -> None:
    _write_rule(tmp_path, "rule-1", locked=False)
    result = CliRunner().invoke(
        cli, ["unlock", "rule-1", "--path", str(tmp_path)],
    )
    assert result.exit_code == 0
    assert "not locked" in result.output


def test_lock_rejects_unknown_id(tmp_path: Path) -> None:
    _write_rule(tmp_path, "rule-1")
    result = CliRunner().invoke(
        cli, ["lock", "absent", "--path", str(tmp_path)],
    )
    assert result.exit_code == 1
    assert "no rule with id" in result.output


def test_is_locked_helper(tmp_path: Path) -> None:
    target = _write_rule(tmp_path, "rule-1", locked=True)
    env = EnvelopeV2(
        id="rule-1", version="1.0.0",
        asset=Asset.SENTINEL_ANALYTIC, status="production",
    )
    la = LoadedAsset(path=target, envelope=env, payload={})
    assert _is_locked(la) is True


def test_is_locked_returns_false_when_flag_missing(tmp_path: Path) -> None:
    target = _write_rule(tmp_path, "rule-x", locked=False)
    env = EnvelopeV2(
        id="rule-x", version="1.0.0",
        asset=Asset.SENTINEL_ANALYTIC, status="production",
    )
    la = LoadedAsset(path=target, envelope=env, payload={})
    assert _is_locked(la) is False


def test_retry_failed_dry_run_lists_pairs(tmp_path: Path) -> None:
    runner = CliRunner()
    detections = tmp_path / "detections"
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()

    _write_rule(detections, "rule-fail-1")
    _write_rule(detections, "rule-pass-1")

    audit_file = audit_dir / "2026-05-05.jsonl"
    lines = [
        {"asset": "sentinel_analytic", "id": "rule-fail-1", "status": "failed"},
        {"asset": "sentinel_analytic", "id": "rule-pass-1", "status": "success"},
        {"asset": "sentinel_analytic", "id": "absent-locally", "status": "failed"},
    ]
    audit_file.write_text(
        "\n".join(json.dumps(line) for line in lines) + "\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        cli,
        [
            "retry-failed",
            "--path", str(detections),
            "--audit-dir", str(audit_dir),
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "rule-fail-1" in result.output
    assert "rule-pass-1" not in result.output
    assert "absent-locally" in result.output  # warned about
    assert "[dry-run]" in result.output


def test_retry_failed_no_audit_dir(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "retry-failed",
            "--path", str(tmp_path),
            "--audit-dir", str(tmp_path / "missing"),
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert "no audit directory" in result.output


def test_apply_skips_locked_without_force(tmp_path: Path) -> None:
    """Locked rules are filtered out of the apply set unless --force-overwrite.

    We rely on the dry-run path so the test does not need an Azure
    credential or a mocked HTTP transport: ``--dry-run`` exercises the
    full plan/skip path without calling any client.
    """
    detections = tmp_path / "detections"
    _write_rule(detections, "rule-locked", locked=True)
    _write_rule(detections, "rule-open", locked=False)

    runner = CliRunner()
    out = runner.invoke(
        cli,
        [
            "apply",
            "--path", str(detections),
            "--dry-run",
            "--no-audit",
            "--skip-deps-check",
        ],
    )
    assert out.exit_code == 0, out.output
    assert "rule-locked" in out.output
    assert "skipped (locked" in out.output
    # rule-open should still appear in the plan summary
    assert "rule-open" in out.output


def test_apply_force_overwrite_keeps_locked(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    _write_rule(detections, "rule-locked", locked=True)

    runner = CliRunner()
    out = runner.invoke(
        cli,
        [
            "apply",
            "--path", str(detections),
            "--dry-run",
            "--no-audit",
            "--skip-deps-check",
            "--force-overwrite",
        ],
    )
    assert out.exit_code == 0, out.output
    assert "skipped (locked" not in out.output


def test_retry_failed_no_failed_records(tmp_path: Path) -> None:
    detections = tmp_path / "detections"
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    _write_rule(detections, "rule-1")
    audit_file = audit_dir / "2026-05-05.jsonl"
    audit_file.write_text(
        json.dumps({"asset": "sentinel_analytic", "id": "rule-1",
                    "status": "success"}) + "\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        [
            "retry-failed",
            "--path", str(detections),
            "--audit-dir", str(audit_dir),
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert "no failed records" in result.output
