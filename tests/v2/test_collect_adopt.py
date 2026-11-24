# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``collect --asset sentinel_playbook --adopt <name>``: the one write
``collect`` makes (it tags an existing Logic App as managed).

Its help text promised a write "still gated by writeAllowed" and
"audited"; neither was done: a read-only workspace was tagged anyway and
no audit record was written.
"""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.core.registry import default_registry
from contentops.handlers.sentinel_playbook import SentinelPlaybookHandler


def _tenant(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, write_allowed: bool) -> None:
    cfg = tmp_path / "tenant.yml"
    cfg.write_text(dedent(f"""
        tenant:
          name: t
          tenantId: "00000000-0000-0000-0000-000000000000"
          sentinelWorkspaces:
            - role: prod
              subscriptionId: "00000000-0000-0000-0000-000000000001"
              resourceGroup: rg
              workspaceName: law-one
              location: westeurope
              writeAllowed: {str(write_allowed).lower()}
    """), encoding="utf-8")
    monkeypatch.setattr("contentops.config.CONFIG_PATH", cfg)
    monkeypatch.delenv("PIPELINE_ENV", raising=False)
    # collect sets it for the run; restored (removed) after the test.
    monkeypatch.delenv("PIPELINE_WORKSPACE_NAME", raising=False)


@pytest.fixture
def adopted(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def fake_adopt(self, name: str) -> dict:
        calls.append(name)
        return {"name": name, "tags": {}}

    monkeypatch.setattr(SentinelPlaybookHandler, "adopt", fake_adopt)
    monkeypatch.setattr(SentinelPlaybookHandler, "list_remote", lambda self: [])
    default_registry.reset_all()
    yield calls
    default_registry.reset_all()


def _collect_adopt(tmp_path: Path):
    return CliRunner().invoke(cli, [
        "collect", "--path", str(tmp_path / "detections"),
        "--asset", "sentinel_playbook", "--adopt", "legacy",
    ])


def test_adopt_refuses_a_read_only_workspace_before_any_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, adopted: list[str],
) -> None:
    _tenant(tmp_path, monkeypatch, write_allowed=False)
    monkeypatch.chdir(tmp_path)
    result = _collect_adopt(tmp_path)
    assert result.exit_code == 2, result.output
    assert "writeAllowed" in result.output
    assert adopted == []
    assert not (tmp_path / "audit").exists()


def test_adopt_writes_an_audit_record_for_each_tag_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, adopted: list[str],
) -> None:
    _tenant(tmp_path, monkeypatch, write_allowed=True)
    monkeypatch.chdir(tmp_path)
    result = _collect_adopt(tmp_path)
    assert result.exit_code == 0, result.output
    assert adopted == ["legacy"]
    records = [
        json.loads(line)
        for f in sorted((tmp_path / "audit").glob("*.jsonl"))
        for line in f.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    assert [(r["asset"], r["id"], r["action"], r["status"]) for r in records] == [
        ("sentinel_playbook", "legacy", "adopt", "ok"),
    ]
    assert records[0]["workspace"] == "law-one"
