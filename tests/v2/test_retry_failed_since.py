# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops retry-failed --since/--run-id` (F14).

Two layers:
* ``contentops.audit_filter`` pure functions — parse_since,
  collect_failed_pairs, iter_records.
* CLI integration via CliRunner — assert --since and --run-id
  narrow the audit scope correctly, and that they're mutually
  exclusive.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.audit_filter import (
    AuditFilterError,
    collect_failed_pairs,
    iter_records,
    parse_since,
)
from contentops.cli import cli


# ---------------------------------------------------------------------------
# parse_since
# ---------------------------------------------------------------------------


def test_parse_since_duration_hours() -> None:
    now = datetime(2026, 5, 7, 12, 0, tzinfo=timezone.utc)
    got = parse_since("4h", now=now)
    assert got == now - timedelta(hours=4)


def test_parse_since_duration_minutes() -> None:
    now = datetime(2026, 5, 7, 12, 0, tzinfo=timezone.utc)
    assert parse_since("30m", now=now) == now - timedelta(minutes=30)


def test_parse_since_duration_days() -> None:
    now = datetime(2026, 5, 7, 12, 0, tzinfo=timezone.utc)
    assert parse_since("7d", now=now) == now - timedelta(days=7)


def test_parse_since_iso_with_z_suffix() -> None:
    got = parse_since("2026-05-07T08:00:00Z")
    assert got == datetime(2026, 5, 7, 8, 0, tzinfo=timezone.utc)


def test_parse_since_iso_with_offset() -> None:
    got = parse_since("2026-05-07T10:00:00+02:00")
    assert got == datetime(2026, 5, 7, 8, 0, tzinfo=timezone.utc)


def test_parse_since_naive_iso_treated_as_utc() -> None:
    got = parse_since("2026-05-07T08:00:00")
    assert got == datetime(2026, 5, 7, 8, 0, tzinfo=timezone.utc)


def test_parse_since_garbage_raises() -> None:
    with pytest.raises(AuditFilterError):
        parse_since("yesterday")


def test_parse_since_empty_raises() -> None:
    with pytest.raises(AuditFilterError):
        parse_since("")


# ---------------------------------------------------------------------------
# collect_failed_pairs
# ---------------------------------------------------------------------------


def _record(
    *, asset: str, id: str, status: str, ts: str, run: str | None = None,
) -> str:
    return json.dumps({
        "timestamp": ts,
        "asset": asset, "id": id, "action": "update",
        "status": status, "sha": "x", "actor": "me",
        "workflow_run": run, "message": None, "metadata_owner": None,
        "prev_hash": "0" * 64, "record_hash": "x" * 64,
    })


def _write_audit(dir_: Path, name: str, records: list[str]) -> Path:
    f = dir_ / name
    f.write_text("\n".join(records) + "\n", encoding="utf-8")
    return f


def test_collect_failed_pairs_default_picks_all_failed(tmp_path: Path) -> None:
    a = _write_audit(tmp_path, "2026-05-05.jsonl", [
        _record(asset="sentinel_analytic", id="rule-1", status="failed",
                ts="2026-05-05T08:00:00Z"),
        _record(asset="sentinel_analytic", id="rule-2", status="success",
                ts="2026-05-05T08:00:01Z"),
    ])
    pairs = collect_failed_pairs([a])
    assert pairs == {("sentinel_analytic", "rule-1")}


def test_collect_failed_pairs_since_excludes_older_records(tmp_path: Path) -> None:
    f = _write_audit(tmp_path, "2026-05-07.jsonl", [
        _record(asset="sentinel_analytic", id="old-rule", status="failed",
                ts="2026-05-07T06:00:00Z"),
        _record(asset="sentinel_analytic", id="recent-rule", status="failed",
                ts="2026-05-07T11:00:00Z"),
    ])
    cutoff = datetime(2026, 5, 7, 10, 0, tzinfo=timezone.utc)
    pairs = collect_failed_pairs([f], predicate=("since", cutoff))
    assert pairs == {("sentinel_analytic", "recent-rule")}


def test_collect_failed_pairs_run_id_filters_correctly(tmp_path: Path) -> None:
    f = _write_audit(tmp_path, "2026-05-07.jsonl", [
        _record(asset="sentinel_analytic", id="run-9-rule", status="failed",
                ts="2026-05-07T08:00:00Z", run="9123"),
        _record(asset="sentinel_analytic", id="run-10-rule", status="failed",
                ts="2026-05-07T09:00:00Z", run="9456"),
    ])
    pairs = collect_failed_pairs([f], predicate=("run_id", "9123"))
    assert pairs == {("sentinel_analytic", "run-9-rule")}


def test_collect_failed_pairs_skips_records_without_timestamp_when_since(
    tmp_path: Path,
) -> None:
    f = _write_audit(tmp_path, "2026-05-07.jsonl", [
        # Record with no timestamp field at all
        json.dumps({"asset": "sentinel_analytic", "id": "no-ts-rule",
                    "status": "failed", "workflow_run": None}),
        _record(asset="sentinel_analytic", id="ok-rule", status="failed",
                ts="2026-05-07T11:00:00Z"),
    ])
    cutoff = datetime(2026, 5, 7, 10, 0, tzinfo=timezone.utc)
    pairs = collect_failed_pairs([f], predicate=("since", cutoff))
    assert pairs == {("sentinel_analytic", "ok-rule")}


def test_collect_failed_pairs_spans_multiple_files(tmp_path: Path) -> None:
    a = _write_audit(tmp_path, "2026-05-06.jsonl", [
        _record(asset="sentinel_analytic", id="file-a-rule", status="failed",
                ts="2026-05-06T11:00:00Z"),
    ])
    b = _write_audit(tmp_path, "2026-05-07.jsonl", [
        _record(asset="sentinel_analytic", id="file-b-rule", status="failed",
                ts="2026-05-07T11:00:00Z"),
    ])
    pairs = collect_failed_pairs([a, b])
    assert pairs == {
        ("sentinel_analytic", "file-a-rule"),
        ("sentinel_analytic", "file-b-rule"),
    }


def test_iter_records_skips_malformed_lines(tmp_path: Path) -> None:
    f = tmp_path / "audit.jsonl"
    f.write_text(
        json.dumps({"asset": "x", "id": "y", "status": "ok"})
        + "\n{not-json}\n"
        + json.dumps({"asset": "x", "id": "z", "status": "ok"})
        + "\n",
        encoding="utf-8",
    )
    rows = list(iter_records([f]))
    assert [r["id"] for r in rows] == ["y", "z"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _setup_repo(tmp_path: Path) -> Path:
    """Build a synthetic detections + audit dir for CLI tests."""
    detections = tmp_path / "detections"
    (detections / "sentinel").mkdir(parents=True)
    (detections / "sentinel" / "rule.yml").write_text(
        """\
id: sentinel-rule
version: 1.0.0
platform: sentinel
status: production
sentinel:
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
    return detections


def test_cli_since_and_run_id_mutually_exclusive(tmp_path: Path) -> None:
    detections = _setup_repo(tmp_path)
    audit = tmp_path / "audit"
    audit.mkdir()
    runner = CliRunner()
    result = runner.invoke(cli, [
        "retry-failed", "--path", str(detections),
        "--audit-dir", str(audit),
        "--since", "1h", "--run-id", "9123",
    ])
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


def test_cli_since_garbage_value_exits_2(tmp_path: Path) -> None:
    detections = _setup_repo(tmp_path)
    audit = tmp_path / "audit"
    audit.mkdir()
    audit_file = audit / "2026-05-07.jsonl"
    audit_file.write_text(_record(
        asset="sentinel_analytic", id="rule-x", status="failed",
        ts="2026-05-07T08:00:00Z",
    ) + "\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(cli, [
        "retry-failed", "--path", str(detections),
        "--audit-dir", str(audit),
        "--since", "yesterday",
    ])
    assert result.exit_code == 2
    assert "yesterday" in result.output


def test_cli_default_uses_only_latest_file(tmp_path: Path) -> None:
    detections = _setup_repo(tmp_path)
    audit = tmp_path / "audit"
    audit.mkdir()
    # Old file: failed
    _write_audit(audit, "2026-05-06.jsonl", [
        _record(asset="sentinel_analytic", id="old-failed",
                status="failed", ts="2026-05-06T08:00:00Z"),
    ])
    # New file: success — the default behaviour ignores the old failure.
    _write_audit(audit, "2026-05-07.jsonl", [
        _record(asset="sentinel_analytic", id="new-success",
                status="success", ts="2026-05-07T08:00:00Z"),
    ])
    runner = CliRunner()
    result = runner.invoke(cli, [
        "retry-failed", "--path", str(detections),
        "--audit-dir", str(audit), "--dry-run",
    ])
    assert result.exit_code == 0
    assert "no failed records" in result.output


def test_cli_since_widens_scope_to_old_failure(tmp_path: Path) -> None:
    detections = _setup_repo(tmp_path)
    audit = tmp_path / "audit"
    audit.mkdir()
    _write_audit(audit, "2026-05-06.jsonl", [
        _record(asset="sentinel_analytic", id="old-failed",
                status="failed", ts="2026-05-06T08:00:00Z"),
    ])
    _write_audit(audit, "2026-05-07.jsonl", [
        _record(asset="sentinel_analytic", id="new-success",
                status="success", ts="2026-05-07T08:00:00Z"),
    ])
    runner = CliRunner()
    # ISO timestamp far enough back that both files are in scope.
    result = runner.invoke(cli, [
        "retry-failed", "--path", str(detections),
        "--audit-dir", str(audit),
        "--since", "2026-05-05T00:00:00Z",
        "--dry-run",
    ])
    assert result.exit_code == 0
    # The old-failed pair has no matching local YAML; surfaced as a warning.
    assert "old-failed" in result.output


def test_cli_run_id_filters_to_one_run(tmp_path: Path) -> None:
    detections = _setup_repo(tmp_path)
    audit = tmp_path / "audit"
    audit.mkdir()
    _write_audit(audit, "2026-05-07.jsonl", [
        _record(asset="sentinel_analytic", id="run-9-rule",
                status="failed", ts="2026-05-07T08:00:00Z", run="9123"),
        _record(asset="sentinel_analytic", id="run-10-rule",
                status="failed", ts="2026-05-07T09:00:00Z", run="9456"),
    ])
    runner = CliRunner()
    result = runner.invoke(cli, [
        "retry-failed", "--path", str(detections),
        "--audit-dir", str(audit),
        "--run-id", "9123", "--dry-run",
    ])
    assert result.exit_code == 0
    assert "run-9-rule" in result.output
    assert "run-10-rule" not in result.output
