# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""``contentops rollback`` runs apply's safety gates.

Rollback used to replay the target SHA's YAML straight into the
handlers, skipping what ``apply`` enforces:

* the tenant.yml ``writeAllowed`` safeguard;
* the env-status filter (e.g. ``experimental`` never reaches prod);
* snippet substitution — ``{{overrides/...}}`` placeholders were PUT
  verbatim;
* and the ``localCustomization`` lock was read from the copy
  materialised at SHA, so a lock added since was ignored.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from contentops.cli import cli
from contentops.core.asset import Asset
from contentops.core.registry import default_registry
from contentops.core.result import ActionResult, PlanAction


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


class _FakeHandler:
    """Records what rollback hands the handler; never touches Azure."""

    asset = Asset.SENTINEL_ANALYTIC

    def __init__(self) -> None:
        self.planned: list[str] = []
        self.applied: list[dict] = []

    def validate(self, loaded) -> None:
        return None

    def plan(self, loaded) -> ActionResult:
        self.planned.append(loaded.envelope.id)
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.UPDATE, status="planned",
        )

    def apply(self, loaded, *, dry_run: bool = False) -> ActionResult:
        self.applied.append(dict(loaded.payload))
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.UPDATE, status="success", verified=True,
        )


@pytest.fixture
def fake(monkeypatch) -> _FakeHandler:
    saved_factories = dict(default_registry._factories)
    saved_instances = dict(default_registry._instances)
    default_registry._factories.clear()
    default_registry._instances.clear()
    handler = _FakeHandler()
    monkeypatch.setattr(
        "contentops.cli.commands.rollback.register_default_handlers",
        lambda: default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: handler),
    )
    monkeypatch.delenv("PIPELINE_WORKSPACE_NAME", raising=False)
    yield handler
    default_registry._factories.clear()
    default_registry._instances.clear()
    default_registry._factories.update(saved_factories)
    default_registry._instances.update(saved_instances)


def _tenant(monkeypatch, *, write_allowed: bool = True) -> None:
    from contentops.config import SentinelWorkspaceConfig, TenantConfig
    cfg = TenantConfig(
        name="test-tenant",
        tenantId="aad-test-guid",
        sentinelWorkspaces=[
            SentinelWorkspaceConfig(
                role="prod",
                subscriptionId="sub-1", resourceGroup="rg-1",
                workspaceName="ws-prod",
                writeAllowed=write_allowed,
            ),
        ],
    )
    monkeypatch.setattr(
        "contentops.config.load_tenant_config", lambda *_a, **_kw: cfg,
    )


def _repo(tmp_path: Path, *, status: str = "production") -> tuple[Path, str, Path]:
    """One loadable rule whose query carries a snippet placeholder."""
    from contentops.devex.scaffold import scaffold

    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "test")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    det = tmp_path / "detections" / "sentinel_analytic"
    det.mkdir(parents=True)
    rule = det / "rule-a.yml"
    scaffold("sentinel_analytic", "rule-a", out=rule)
    text = rule.read_text(encoding="utf-8")
    text = text.replace("status: experimental", f"status: {status}", 1)
    text = text.replace(
        "    | where TimeGenerated > ago(1h)\n",
        "    {{exclusions/admins.yml}}\n",
    )
    rule.write_text(text, encoding="utf-8")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "rule-a")
    return tmp_path, _git(tmp_path, "rev-parse", "HEAD"), rule


def _invoke(args: list[str], cwd: Path):
    prev = os.getcwd()
    try:
        os.chdir(cwd)
        return CliRunner().invoke(cli, args)
    finally:
        os.chdir(prev)


def test_rollback_refuses_write_when_write_not_allowed(
    tmp_path: Path, monkeypatch, fake: _FakeHandler,
) -> None:
    root, sha, _ = _repo(tmp_path)
    _tenant(monkeypatch, write_allowed=False)

    result = _invoke(
        ["rollback", sha, "--role", "prod", "--no-dry-run", "--yes", "--no-audit"],
        root,
    )

    assert result.exit_code == 2, result.output
    assert "writeAllowed=False" in result.output
    assert fake.applied == []


def test_rollback_dry_run_previews_a_write_locked_workspace(
    tmp_path: Path, monkeypatch, fake: _FakeHandler,
) -> None:
    root, sha, _ = _repo(tmp_path)
    _tenant(monkeypatch, write_allowed=False)

    result = _invoke(["rollback", sha, "--role", "prod"], root)

    assert result.exit_code == 0, result.output
    assert "writeAllowed=False" not in result.output
    assert fake.planned == ["rule-a"]


def test_rollback_filters_by_env_status(
    tmp_path: Path, monkeypatch, fake: _FakeHandler,
) -> None:
    root, sha, _ = _repo(tmp_path, status="experimental")
    _tenant(monkeypatch)

    result = _invoke(
        ["rollback", sha, "--role", "prod", "--no-dry-run", "--yes", "--no-audit"],
        root,
    )

    assert "env-status filter" in result.output, result.output
    assert fake.applied == []


def test_rollback_honours_lock_added_after_target_sha(
    tmp_path: Path, fake: _FakeHandler,
) -> None:
    root, sha, rule = _repo(tmp_path)
    # Locked in today's checkout only; the copy at SHA carries no lock.
    rule.write_text(
        "localCustomization: true\n" + rule.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    result = _invoke(["rollback", sha], root)

    assert "skipped (locked): rule-a" in result.output, result.output
    assert fake.planned == []


def test_rollback_substitutes_snippets_before_put(
    tmp_path: Path, fake: _FakeHandler,
) -> None:
    root, sha, _ = _repo(tmp_path)
    snippet = root / "overrides" / "exclusions" / "admins.yml"
    snippet.parent.mkdir(parents=True)
    snippet.write_text(
        "content: '| where Account !in (\"svc-backup\")'\n", encoding="utf-8",
    )

    result = _invoke(["rollback", sha, "--no-dry-run", "--yes", "--no-audit"], root)

    assert result.exit_code == 0, result.output
    assert len(fake.applied) == 1
    query = fake.applied[0]["query"]
    assert "{{" not in query
    assert '| where Account !in ("svc-backup")' in query
