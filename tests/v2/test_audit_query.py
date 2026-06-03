# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Tests for `contentops audit query <subcommand>` (F18).

Layered:
* Pure-function tests for ``contentops.audit_query`` query_*.
* Render tests (table / json / csv shapes).
* CLI integration via CliRunner.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops import audit_query as aq
from contentops.cli import cli


# ---------------------------------------------------------------------------
# Fixture: a synthetic audit chain
# ---------------------------------------------------------------------------


def _record(
    *, asset: str = "sentinel_analytic", id: str, action: str = "update",
    status: str = "success", ts: str, sha: str = "abc",
    actor: str = "alice", run: str | None = None,
    message: str | None = None,
) -> str:
    return json.dumps({
        "timestamp": ts, "asset": asset, "id": id, "action": action,
        "status": status, "sha": sha, "actor": actor,
        "workflow_run": run, "message": message, "metadata_owner": None,
        "prev_hash": "0" * 64, "record_hash": "x" * 64,
    })


@pytest.fixture
def audit_dir(tmp_path: Path) -> Path:
    """Three audit files spanning several days, with a known mix of records."""
    d = tmp_path / "audit"
    d.mkdir()

    (d / "2026-05-05.jsonl").write_text("\n".join([
        _record(id="brute-force-ssh-001", ts="2026-05-05T08:00:00Z",
                actor="alice", run="9000"),
        _record(id="brute-force-ssh-001", ts="2026-05-05T08:00:01Z",
                status="failed", actor="alice", run="9000",
                message="ARM 429 rate limited"),
    ]) + "\n", encoding="utf-8")

    (d / "2026-05-06.jsonl").write_text("\n".join([
        _record(id="o365-anomaly", ts="2026-05-06T10:00:00Z",
                actor="bob", run="9100"),
        _record(id="brute-force-ssh-001", ts="2026-05-06T10:30:00Z",
                action="update", status="success",
                actor="github-actions", run="9100",
                message="rollback to 0123456789abcdef"),
    ]) + "\n", encoding="utf-8")

    (d / "2026-05-07.jsonl").write_text("\n".join([
        _record(id="brute-force-ssh-001", ts="2026-05-07T11:00:00Z",
                actor="alice", run="9200"),
        _record(id="another-rule", ts="2026-05-07T11:00:01Z",
                status="failed", actor="bob", run="9200",
                message="ETag conflict"),
    ]) + "\n", encoding="utf-8")

    return d


# ---------------------------------------------------------------------------
# query_latest
# ---------------------------------------------------------------------------


def test_query_latest_picks_most_recent_across_files(audit_dir: Path) -> None:
    rows = aq.query_latest(audit_dir, "brute-force-ssh-001")
    assert len(rows) == 1
    assert rows[0].timestamp == "2026-05-07T11:00:00Z"
    assert rows[0].actor == "alice"


def test_query_latest_unknown_id_returns_empty(audit_dir: Path) -> None:
    assert aq.query_latest(audit_dir, "no-such-id") == []


# ---------------------------------------------------------------------------
# query_failures
# ---------------------------------------------------------------------------


def test_query_failures_returns_only_failed_oldest_first(audit_dir: Path) -> None:
    rows = aq.query_failures(audit_dir)
    assert [r.id for r in rows] == ["brute-force-ssh-001", "another-rule"]
    assert all(r.status == "failed" for r in rows)


def test_query_failures_since_excludes_old_records(audit_dir: Path) -> None:
    rows = aq.query_failures(audit_dir, since_spec="2026-05-07T00:00:00Z")
    assert [r.id for r in rows] == ["another-rule"]


# ---------------------------------------------------------------------------
# query_by_actor
# ---------------------------------------------------------------------------


def test_query_by_actor_matches_exact_actor(audit_dir: Path) -> None:
    rows = aq.query_by_actor(audit_dir, "bob")
    assert {r.id for r in rows} == {"o365-anomaly", "another-rule"}


def test_query_by_actor_since_window(audit_dir: Path) -> None:
    rows = aq.query_by_actor(audit_dir, "alice",
                              since_spec="2026-05-06T00:00:00Z")
    # Alice's records are on 5/5 and 5/7; only 5/7 should pass.
    assert [r.timestamp for r in rows] == ["2026-05-07T11:00:00Z"]


# ---------------------------------------------------------------------------
# query_rollbacks
# ---------------------------------------------------------------------------


def test_query_rollbacks_matches_message_marker(audit_dir: Path) -> None:
    rows = aq.query_rollbacks(audit_dir)
    assert len(rows) == 1
    assert rows[0].id == "brute-force-ssh-001"
    assert rows[0].message and rows[0].message.startswith("rollback to ")


# ---------------------------------------------------------------------------
# query_timeline
# ---------------------------------------------------------------------------


def test_query_timeline_returns_all_records_oldest_first(audit_dir: Path) -> None:
    rows = aq.query_timeline(audit_dir, "brute-force-ssh-001")
    timestamps = [r.timestamp for r in rows]
    assert timestamps == sorted(timestamps)
    assert len(rows) == 4  # 2 from 5/5, 1 from 5/6, 1 from 5/7


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_render_table_handles_empty() -> None:
    assert aq.render_table([]) == "(no records)\n"


def test_render_table_columns_present(audit_dir: Path) -> None:
    rows = aq.query_failures(audit_dir)
    text = aq.render_table(rows)
    # Header line should contain every standard column.
    for col in ("timestamp", "asset", "id", "action", "status", "actor"):
        assert col in text


def test_render_json_is_parseable(audit_dir: Path) -> None:
    rows = aq.query_failures(audit_dir)
    parsed = json.loads(aq.render_json(rows))
    assert isinstance(parsed, list)
    assert len(parsed) == 2
    assert {p["status"] for p in parsed} == {"failed"}


def test_render_csv_has_header_and_rows(audit_dir: Path) -> None:
    rows = aq.query_failures(audit_dir)
    text = aq.render_csv(rows)
    reader = csv.reader(io.StringIO(text))
    header = next(reader)
    assert header[0] == "timestamp"
    body = list(reader)
    assert len(body) == 2


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_query_latest_prints_one_record(audit_dir: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, [
        "audit", "query", "latest", "brute-force-ssh-001",
        "--audit-dir", str(audit_dir),
    ])
    assert result.exit_code == 0, result.output
    assert "2026-05-07T11:00:00Z" in result.output


def test_cli_query_failures_json(audit_dir: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, [
        "audit", "query", "failures",
        "--audit-dir", str(audit_dir),
        "--format", "json",
    ])
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert len(parsed) == 2


def test_cli_query_by_actor_csv(audit_dir: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, [
        "audit", "query", "by-actor", "alice",
        "--audit-dir", str(audit_dir),
        "--format", "csv",
    ])
    assert result.exit_code == 0, result.output
    reader = csv.reader(io.StringIO(result.output))
    header = next(reader)
    body = list(reader)
    assert "actor" in header
    assert all(r[header.index("actor")] == "alice" for r in body)


def test_cli_query_rollbacks_finds_marker(audit_dir: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, [
        "audit", "query", "rollbacks",
        "--audit-dir", str(audit_dir),
    ])
    assert result.exit_code == 0, result.output
    assert "rollback to" in result.output


def test_cli_query_timeline(audit_dir: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, [
        "audit", "query", "timeline", "brute-force-ssh-001",
        "--audit-dir", str(audit_dir),
    ])
    assert result.exit_code == 0, result.output
    # Four records of brute-force-ssh-001 in the fixture.
    assert result.output.count("brute-force-ssh-001") >= 4


def test_cli_query_garbage_since_exits_2(audit_dir: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, [
        "audit", "query", "failures",
        "--audit-dir", str(audit_dir),
        "--since", "yesterday",
    ])
    assert result.exit_code == 2
    assert "yesterday" in result.output


def test_cli_query_writes_to_out_file(audit_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "audit", "query", "failures",
        "--audit-dir", str(audit_dir),
        "--format", "json", "--out", str(out),
    ])
    assert result.exit_code == 0, result.output
    assert out.exists()
    parsed = json.loads(out.read_text(encoding="utf-8"))
    assert len(parsed) == 2
