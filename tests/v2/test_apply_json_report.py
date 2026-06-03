# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops apply --json-report`.

Two layers:
* Pure-function tests for ``contentops.apply_report`` — build_report,
  to_json, write_report — no Click, no handlers.
* CLI integration via CliRunner asserting the report shape lands
  on disk after a real `apply --dry-run`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from contentops import apply_report as ar
from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.core.result import ActionResult, PlanAction


def _envelope(asset_id: str, asset: Asset = Asset.SENTINEL_ANALYTIC) -> EnvelopeV2:
    return EnvelopeV2(
        id=asset_id, version="1.0.0", asset=asset, status="production",
        legacy=True,
    )


def _loaded(asset_id: str, asset: Asset = Asset.SENTINEL_ANALYTIC) -> LoadedAsset:
    return LoadedAsset(
        path=Path(f"detections/{asset.value}/{asset_id}.yml"),
        envelope=_envelope(asset_id, asset),
        payload={},
    )


def _success(la: LoadedAsset, action=PlanAction.UPDATE, verified: bool = True) -> ActionResult:
    return ActionResult(
        asset_id=la.envelope.id, asset_kind=la.envelope.asset.value,
        action=action, status="success", verified=verified,
    )


def _failure(la: LoadedAsset, status: str = "error-400") -> ActionResult:
    return ActionResult(
        asset_id=la.envelope.id, asset_kind=la.envelope.asset.value,
        action=PlanAction.UPDATE, status=status,
        detail="boom", error="boom", verified=False,
    )


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------


def test_build_report_totals_sum_correctly() -> None:
    pairs = [
        (_loaded("rule-a"), _success(_loaded("rule-a"))),
        (_loaded("rule-b"), _success(_loaded("rule-b"))),
        (_loaded("rule-c"), _failure(_loaded("rule-c"))),
        (_loaded("rule-d"), ActionResult(
            asset_id="rule-d", asset_kind="sentinel_analytic",
            action=PlanAction.SKIP, status="skipped",
        )),
    ]
    started = datetime(2026, 5, 7, 10, 0, 0, tzinfo=timezone.utc)
    finished = datetime(2026, 5, 7, 10, 0, 30, tzinfo=timezone.utc)
    rep = ar.build_report(
        tenant="prod", started_at=started, finished_at=finished,
        sha="abc123", actor="me", workflow_run=None, dry_run=False,
        pairs=pairs,
    )
    assert rep.totals.total == 4
    assert rep.totals.success == 2
    assert rep.totals.failed == 1
    assert rep.totals.skipped == 1
    assert rep.totals.verified == 2
    assert rep.totals.unverified == 1
    assert rep.duration_s == 30.0


def test_build_report_audit_pointer_is_relative_with_line(
    tmp_path: Path, monkeypatch,
) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    audit_file = audit_dir / "2026-05-07.jsonl"
    audit_file.write_text("", encoding="utf-8")

    pairs = [(_loaded("rule-a"), _success(_loaded("rule-a")))]
    started = datetime(2026, 5, 7, 10, 0, 0, tzinfo=timezone.utc)
    finished = datetime(2026, 5, 7, 10, 0, 1, tzinfo=timezone.utc)
    monkeypatch.chdir(tmp_path)
    rep = ar.build_report(
        tenant="prod", started_at=started, finished_at=finished,
        sha="x", actor="me", workflow_run=None, dry_run=False,
        pairs=pairs, audit_path=audit_file, audit_first_line=42,
    )
    assert rep.results[0].audit_pointer == "audit/2026-05-07.jsonl#L42"


def test_build_report_audit_pointer_omitted_when_no_path() -> None:
    pairs = [(_loaded("rule-a"), _success(_loaded("rule-a")))]
    rep = ar.build_report(
        tenant="prod",
        started_at=datetime(2026, 5, 7, tzinfo=timezone.utc),
        finished_at=datetime(2026, 5, 7, tzinfo=timezone.utc),
        sha="x", actor="me", workflow_run=None, dry_run=False,
        pairs=pairs,
    )
    assert rep.results[0].audit_pointer is None


def test_build_report_audit_pointer_increments_per_row(
    tmp_path: Path, monkeypatch,
) -> None:
    audit_file = tmp_path / "audit" / "2026-05-07.jsonl"
    audit_file.parent.mkdir()
    audit_file.write_text("", encoding="utf-8")
    pairs = [
        (_loaded(f"r{i}"), _success(_loaded(f"r{i}")))
        for i in range(3)
    ]
    monkeypatch.chdir(tmp_path)
    rep = ar.build_report(
        tenant="prod",
        started_at=datetime(2026, 5, 7, tzinfo=timezone.utc),
        finished_at=datetime(2026, 5, 7, tzinfo=timezone.utc),
        sha="x", actor="me", workflow_run=None, dry_run=False,
        pairs=pairs, audit_path=audit_file, audit_first_line=10,
    )
    pointers = [r.audit_pointer for r in rep.results]
    assert pointers == [
        "audit/2026-05-07.jsonl#L10",
        "audit/2026-05-07.jsonl#L11",
        "audit/2026-05-07.jsonl#L12",
    ]


def test_build_report_classifies_unverified_success_as_failed() -> None:
    """An ActionResult with status='success' but verified=False should
    classify as 'failed' to match the audit-record convention."""
    la = _loaded("rule-a")
    pairs = [(la, ActionResult(
        asset_id="rule-a", asset_kind=la.envelope.asset.value,
        action=PlanAction.UPDATE, status="success", verified=False,
    ))]
    rep = ar.build_report(
        tenant="prod",
        started_at=datetime(2026, 5, 7, tzinfo=timezone.utc),
        finished_at=datetime(2026, 5, 7, tzinfo=timezone.utc),
        sha="x", actor="me", workflow_run=None, dry_run=False,
        pairs=pairs,
    )
    assert rep.results[0].status == "failed"
    assert rep.totals.failed == 1


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def test_to_json_is_parseable_and_contains_expected_keys() -> None:
    rep = ar.build_report(
        tenant="prod",
        started_at=datetime(2026, 5, 7, tzinfo=timezone.utc),
        finished_at=datetime(2026, 5, 7, tzinfo=timezone.utc),
        sha="abc123", actor="me", workflow_run="9123",
        dry_run=False, pairs=[],
    )
    parsed = json.loads(ar.to_json(rep))
    assert parsed["tenant"] == "prod"
    assert parsed["sha"] == "abc123"
    assert parsed["workflow_run"] == "9123"
    assert parsed["dry_run"] is False
    assert "totals" in parsed
    assert "results" in parsed


def test_write_report_creates_file(tmp_path: Path) -> None:
    rep = ar.build_report(
        tenant="t",
        started_at=datetime(2026, 5, 7, tzinfo=timezone.utc),
        finished_at=datetime(2026, 5, 7, tzinfo=timezone.utc),
        sha="x", actor="me", workflow_run=None, dry_run=False, pairs=[],
    )
    target = tmp_path / "subdir" / "report.json"
    written = ar.write_report(rep, target)
    assert written == target
    assert target.exists()
    parsed = json.loads(target.read_text(encoding="utf-8"))
    assert parsed["tenant"] == "t"


def test_write_report_stdout_marker_returns_dash() -> None:
    rep = ar.build_report(
        tenant="t",
        started_at=datetime(2026, 5, 7, tzinfo=timezone.utc),
        finished_at=datetime(2026, 5, 7, tzinfo=timezone.utc),
        sha="x", actor="me", workflow_run=None, dry_run=False, pairs=[],
    )
    written = ar.write_report(rep, "-")
    assert str(written) == "-"


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_apply_dry_run_writes_json_report(
    tmp_path: Path, monkeypatch,
) -> None:
    """End-to-end: apply --dry-run --json-report writes a parseable JSON file."""
    from click.testing import CliRunner
    from contentops.cli import cli

    detections = tmp_path / "detections"
    (detections / "sentinel_analytic").mkdir(parents=True)
    (detections / "sentinel_analytic" / "rule.yml").write_text(
        """\
id: sentinel-rule
version: 1.0.0
asset: sentinel_analytic
status: production
payload:
  kind: Scheduled
  displayName: x
  severity: Low
  query: print 1
  queryFrequency: PT5M
  queryPeriod: PT5M
  triggerOperator: GreaterThan
  triggerThreshold: 0
""",
        encoding="utf-8",
    )

    out = tmp_path / "report.json"
    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli, [
        "apply", "--path", str(detections),
        "--dry-run", "--no-audit",
        "--json-report", str(out),
        "--skip-deps-check",
    ])
    assert result.exit_code == 0, result.output
    assert out.exists()
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert parsed["dry_run"] is True
    assert parsed["totals"]["total"] >= 1
    # Dry-run never touches audit, so audit_pointer is omitted.
    assert all(r.get("audit_pointer") is None for r in parsed["results"])


def test_cli_apply_json_report_stdout_marker(
    tmp_path: Path, monkeypatch,
) -> None:
    """`--json-report -` writes the JSON to stdout after the human summary."""
    from click.testing import CliRunner
    from contentops.cli import cli

    detections = tmp_path / "detections"
    (detections / "sentinel_analytic").mkdir(parents=True)
    (detections / "sentinel_analytic" / "rule.yml").write_text(
        """\
id: sentinel-rule
version: 1.0.0
asset: sentinel_analytic
status: production
payload:
  kind: Scheduled
  displayName: x
  severity: Low
  query: print 1
  queryFrequency: PT5M
  queryPeriod: PT5M
  triggerOperator: GreaterThan
  triggerThreshold: 0
""",
        encoding="utf-8",
    )

    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli, [
        "apply", "--path", str(detections),
        "--dry-run", "--no-audit",
        "--json-report", "-",
        "--skip-deps-check",
    ])
    assert result.exit_code == 0, result.output
    # The JSON appears after the human summary; find the first '{' line and
    # parse from there.
    json_start = result.output.find("{\n")
    assert json_start >= 0, f"no JSON object in output:\n{result.output}"
    parsed = json.loads(result.output[json_start:])
    assert parsed["dry_run"] is True
    assert "totals" in parsed
