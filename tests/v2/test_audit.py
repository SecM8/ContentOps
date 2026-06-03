# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""M4: append-only JSONL audit trail tests."""

from __future__ import annotations

import json
import subprocess
from datetime import date
from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.audit import AuditRecord, _resolve_actor, _resolve_sha, write_records
from contentops.cli import cli
from contentops.core.asset import Asset
from contentops.core.handler import LoadedAsset
from contentops.core.registry import default_registry
from contentops.core.result import ActionResult, PlanAction


@pytest.fixture(autouse=True)
def _restore_registry():
    saved_factories = dict(default_registry._factories)
    saved_instances = dict(default_registry._instances)
    yield
    default_registry._factories.clear()
    default_registry._factories.update(saved_factories)
    default_registry._instances.clear()
    default_registry._instances.update(saved_instances)


SAMPLE_WATCHLIST = """\
id: audit-wl
version: 0.1.0
asset: sentinel_watchlist
status: production
payload:
  displayName: Audit Test
  provider: Custom
  source: Local file
  contentType: text/csv
  itemsSearchKey: AssetName
  rawContent: |
    AssetName,Tier
    a,0
"""


SAMPLE_ANALYTIC_V2 = """\
id: audit-analytic
version: 0.1.0
asset: sentinel_analytic
status: production
metadata:
  owner: alice@example.com
  runbookUrl: https://runbook.example/x
  tactics: [Execution]
  severity: medium
  expectedAlertsPerDay: 1
  fpHandling: triage in queue
payload:
  kind: Scheduled
  displayName: Audit
  severity: Low
  query: |
    SecurityEvent | take 1
  queryFrequency: PT5M
  queryPeriod: PT5M
  triggerOperator: GreaterThan
  triggerThreshold: 0
"""


class _StubHandler:
    """Minimal Handler-protocol-compatible stub."""

    asset = Asset.SENTINEL_WATCHLIST

    def __init__(self, scripted: dict[str, ActionResult] | None = None) -> None:
        self.scripted = scripted or {}

    def validate(self, loaded: LoadedAsset) -> None:
        return None

    def plan(self, loaded: LoadedAsset) -> ActionResult:
        return self._result_for(loaded)

    def apply(self, loaded: LoadedAsset, *, dry_run: bool = False) -> ActionResult:
        return self._result_for(loaded)

    def _result_for(self, loaded: LoadedAsset) -> ActionResult:
        if loaded.envelope.id in self.scripted:
            return self.scripted[loaded.envelope.id]
        return ActionResult(
            asset_id=loaded.envelope.id,
            asset_kind=loaded.envelope.asset.value,
            action=PlanAction.CREATE,
            status="ok",
        )


def _register_stub(scripted: dict[str, ActionResult] | None = None) -> _StubHandler:
    handler = _StubHandler(scripted)
    default_registry.register(Asset.SENTINEL_WATCHLIST, lambda: handler)
    default_registry.reset()
    return handler


# ---- AuditRecord.to_json ----

def test_audit_record_to_json_is_single_line_stable_order() -> None:
    rec = AuditRecord(
        timestamp="2025-01-02T03:04:05.000000Z",
        asset="sentinel_analytic",
        id="rule-1",
        action="create",
        status="success",
        sha="abc123",
        actor="alice",
        workflow_run="42",
        message=None,
        metadata_owner="alice@example.com",
    )
    out = rec.to_json()
    assert "\n" not in out
    expected = (
        '{"timestamp":"2025-01-02T03:04:05.000000Z",'
        '"asset":"sentinel_analytic",'
        '"id":"rule-1",'
        '"action":"create",'
        '"status":"success",'
        '"sha":"abc123",'
        '"actor":"alice",'
        '"workflow_run":"42",'
        '"message":null,'
        '"metadata_owner":"alice@example.com",'
        # Phase 4 added workspace + snippet_digest. Defaults to null
        # when AuditRecord is constructed without the kwargs.
        '"workspace":null,'
        '"snippet_digest":null,'
        '"prev_hash":"' + ("0" * 64) + '",'
        '"record_hash":""}'
    )
    assert out == expected


# ---- write_records ----

def _make_record(rid: str = "r1") -> AuditRecord:
    return AuditRecord(
        timestamp="2025-01-02T03:04:05.000000Z",
        asset="sentinel_analytic",
        id=rid,
        action="create",
        status="success",
        sha="abc",
        actor="alice",
        workflow_run=None,
        message=None,
        metadata_owner=None,
    )


def test_write_records_creates_dated_file(tmp_path: Path) -> None:
    path = write_records(tmp_path, [_make_record("a")])
    assert path == tmp_path / "audit" / f"{date.today():%Y-%m-%d}.jsonl"
    assert path.exists()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["id"] == "a"


def test_write_records_appends_on_second_call(tmp_path: Path) -> None:
    write_records(tmp_path, [_make_record("a"), _make_record("b")])
    path = write_records(tmp_path, [_make_record("c")])
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    assert [json.loads(line)["id"] for line in lines] == ["a", "b", "c"]


def test_write_records_creates_audit_dir_if_missing(tmp_path: Path) -> None:
    target = tmp_path / "fresh"
    target.mkdir()
    assert not (target / "audit").exists()
    write_records(target, [_make_record()])
    assert (target / "audit").is_dir()


# ---- _resolve_sha ----

def test_resolve_sha_falls_back_to_unknown_outside_git(tmp_path: Path) -> None:
    assert _resolve_sha(tmp_path) == "unknown"


def test_resolve_sha_returns_head_inside_git(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=tmp_path, check=True)
    (tmp_path / "f.txt").write_text("x")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "init"], cwd=tmp_path, check=True,
    )
    sha = _resolve_sha(tmp_path)
    assert sha != "unknown"
    assert len(sha) == 40


# ---- _resolve_actor ----

def test_resolve_actor_uses_github_actor_env(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_ACTOR", "octocat")
    monkeypatch.setenv("USER", "ignored")
    monkeypatch.setenv("USERNAME", "ignored")
    assert _resolve_actor() == "octocat"


def test_resolve_actor_falls_back_to_unknown(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_ACTOR", raising=False)
    monkeypatch.delenv("USER", raising=False)
    monkeypatch.delenv("USERNAME", raising=False)
    assert _resolve_actor() == "unknown"


# ---- apply_cmd integration ----

def _seed_watchlist(root: Path, body: str = SAMPLE_WATCHLIST) -> None:
    (root / "sentinel_watchlist").mkdir()
    (root / "sentinel_watchlist" / "wl.yml").write_text(body)


def test_apply_cmd_writes_audit_records(tmp_path: Path, monkeypatch) -> None:
    _register_stub()
    monkeypatch.setenv("GITHUB_ACTOR", "octocat")
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")
    _seed_watchlist(tmp_path)

    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli, ["apply", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "[audit] wrote 1 records" in result.output

    audit_file = tmp_path / "audit" / f"{date.today():%Y-%m-%d}.jsonl"
    assert audit_file.exists()
    payload = json.loads(audit_file.read_text(encoding="utf-8").splitlines()[0])
    assert payload["id"] == "audit-wl"
    assert payload["asset"] == "sentinel_watchlist"
    assert payload["action"] == "create"
    assert payload["status"] == "success"
    assert payload["actor"] == "octocat"
    assert payload["workflow_run"] == "12345"
    assert payload["message"] is None


def test_apply_cmd_no_audit_flag_skips_writing(tmp_path: Path, monkeypatch) -> None:
    _register_stub()
    _seed_watchlist(tmp_path)

    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli, ["apply", "--path", str(tmp_path), "--no-audit"])
    assert result.exit_code == 0, result.output
    assert "[audit]" not in result.output
    assert not (tmp_path / "audit").exists()


def test_apply_cmd_dry_run_skips_writing(tmp_path: Path, monkeypatch) -> None:
    _register_stub()
    _seed_watchlist(tmp_path)

    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli, ["apply", "--path", str(tmp_path), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "[audit]" not in result.output
    assert not (tmp_path / "audit").exists()


def test_apply_cmd_failed_record_has_failed_status_and_message(
    tmp_path: Path, monkeypatch,
) -> None:
    scripted = {
        "audit-wl": ActionResult(
            asset_id="audit-wl",
            asset_kind="sentinel_watchlist",
            action=PlanAction.UPDATE,
            status="error-apply",
            detail="boom",
        ),
    }
    _register_stub(scripted)
    _seed_watchlist(tmp_path)

    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli, ["apply", "--path", str(tmp_path)])
    assert result.exit_code == 1, result.output

    audit_file = tmp_path / "audit" / f"{date.today():%Y-%m-%d}.jsonl"
    payload = json.loads(audit_file.read_text(encoding="utf-8").splitlines()[0])
    assert payload["status"] == "failed"
    assert payload["action"] == "update"
    assert payload["message"] == "boom"


def test_audit_record_includes_metadata_owner_when_present(
    tmp_path: Path, monkeypatch,
) -> None:
    # Override the analytic handler with a stub so no real API is called.
    class _AnalyticStub(_StubHandler):
        asset = Asset.SENTINEL_ANALYTIC

    handler = _AnalyticStub()
    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: handler)
    default_registry.reset()

    (tmp_path / "sentinel").mkdir()
    (tmp_path / "sentinel" / "rule.yml").write_text(SAMPLE_ANALYTIC_V2)

    runner = CliRunner()
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(cli, ["apply", "--path", str(tmp_path)])
    assert result.exit_code == 0, result.output

    audit_file = tmp_path / "audit" / f"{date.today():%Y-%m-%d}.jsonl"
    payload = json.loads(audit_file.read_text(encoding="utf-8").splitlines()[0])
    assert payload["metadata_owner"] == "alice@example.com"
    assert payload["id"] == "audit-analytic"
