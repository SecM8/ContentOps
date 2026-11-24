# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""retry-failed and prune write like apply does.

* retry-failed sent the envelope as it is on disk: no snippet
  substitution (``{{...}}`` placeholders reached the tenant), no
  ``localCustomization`` lock, and its results never reached the state
  file the workflow then pushed.
* prune deleted tenant objects but left their entries in the state file,
  although the workflow comment said ``state.forget()`` removed them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from contentops.cli import cli
from contentops.core.asset import Asset
from contentops.core.registry import default_registry
from contentops.core.result import ActionResult, PlanAction
from contentops.state import EnvState, save_state, state_path

ENV = "test-tenant"


class _Fake:
    asset = Asset.SENTINEL_ANALYTIC

    def __init__(self, remote: list[dict] | None = None) -> None:
        self.applied: list[dict] = []
        self.deleted: list[str] = []
        self.remote = remote or []

    def validate(self, loaded) -> None:
        return None

    def plan(self, loaded) -> ActionResult:
        return ActionResult(asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                            action=PlanAction.UPDATE, status="planned")

    def apply(self, loaded, *, dry_run: bool = False) -> ActionResult:
        self.applied.append(dict(loaded.payload))
        return ActionResult(asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                            action=PlanAction.UPDATE, status="success", verified=True)

    def list_remote(self) -> list[dict]:
        return list(self.remote)

    def to_envelope(self, remote: dict) -> dict | None:
        return {"id": remote["name"], "version": "0.1.0", "asset": self.asset.value,
                "status": "production", "metadata": {"arm_name": remote["name"]},
                "payload": {"displayName": remote["name"]}}

    def delete(self, remote_id: str) -> ActionResult:
        self.deleted.append(remote_id)
        return ActionResult(asset_id=remote_id, asset_kind=self.asset.value,
                            action=PlanAction.DELETE, status="success", detail="deleted")

    def close(self) -> None:
        return None


@pytest.fixture
def fake(monkeypatch):
    saved_f, saved_i = dict(default_registry._factories), dict(default_registry._instances)
    default_registry._factories.clear()
    default_registry._instances.clear()
    handler = _Fake()

    def register(**_kw) -> None:
        if not default_registry.has(Asset.SENTINEL_ANALYTIC):
            default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: handler)

    for mod in ("lifecycle", "prune"):
        monkeypatch.setattr(f"contentops.cli.commands.{mod}.register_default_handlers", register)
    monkeypatch.delenv("PIPELINE_WORKSPACE_NAME", raising=False)
    yield handler
    default_registry._factories.clear()
    default_registry._instances.clear()
    default_registry._factories.update(saved_f)
    default_registry._instances.update(saved_i)


@pytest.fixture
def tenant(monkeypatch):
    from contentops.config import SentinelWorkspaceConfig, TenantConfig
    cfg = TenantConfig(
        name=ENV, tenantId="aad-test-guid",
        sentinelWorkspaces=[SentinelWorkspaceConfig(
            role="prod", subscriptionId="sub-1", resourceGroup="rg-1", workspaceName="ws-prod",
            purgeAllowed=True,
        )],
    )
    monkeypatch.setattr("contentops.config.load_tenant_config", lambda *_a, **_kw: cfg)
    return cfg


def _rule(detections: Path, rule_id: str, *, query: str = "SecurityEvent\n| take 1",
          locked: bool = False) -> None:
    folder = detections / "sentinel_analytic"
    folder.mkdir(parents=True, exist_ok=True)
    body = {
        "id": rule_id, "version": "1.0.0", "asset": "sentinel_analytic", "status": "production",
        "metadata": {"arm_name": rule_id},
        "payload": {"kind": "Scheduled", "displayName": rule_id, "severity": "Low", "query": query,
                    "queryFrequency": "PT5M", "queryPeriod": "PT5M",
                    "triggerOperator": "GreaterThan", "triggerThreshold": 0},
    }
    if locked:
        body["localCustomization"] = True
    (folder / f"{rule_id}.yml").write_text(yaml.safe_dump(body), encoding="utf-8")


def _failed(input_dir: Path, *ids: str) -> None:
    input_dir.mkdir(exist_ok=True)
    rows = [{"timestamp": "2026-11-24T08:00:00Z", "asset": "sentinel_analytic", "id": rid,
             "action": "update", "status": "failed"} for rid in ids]
    (input_dir / "2026-11-24.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8",
    )


def _retry(tmp_path: Path):
    return CliRunner().invoke(cli, [
        "retry-failed", "--path", str(tmp_path / "detections"),
        "--audit-dir", str(tmp_path / "retry-input"), "--role", "prod",
    ])


def test_retry_failed_sends_the_snippet_substituted_payload(tmp_path, monkeypatch, fake, tenant) -> None:
    monkeypatch.chdir(tmp_path)
    _rule(tmp_path / "detections", "rule-a",
          query="SecurityEvent\n{{exclusions/admins.yml}}\n| take 1")
    _failed(tmp_path / "retry-input", "rule-a")
    result = _retry(tmp_path)
    assert result.exit_code == 0, result.output
    [payload] = fake.applied
    assert "{{" not in payload["query"]


def test_retry_failed_leaves_a_locked_rule_alone(tmp_path, monkeypatch, fake, tenant) -> None:
    monkeypatch.chdir(tmp_path)
    _rule(tmp_path / "detections", "rule-a", locked=True)
    _failed(tmp_path / "retry-input", "rule-a")
    result = _retry(tmp_path)
    assert fake.applied == []
    assert "skipped (locked" in result.output


def test_retry_failed_records_its_results_in_the_state_file(tmp_path, monkeypatch, fake, tenant) -> None:
    monkeypatch.chdir(tmp_path)
    _rule(tmp_path / "detections", "rule-a")
    _failed(tmp_path / "retry-input", "rule-a")
    result = _retry(tmp_path)
    assert result.exit_code == 0, result.output
    state = json.loads(state_path(env=ENV, root=tmp_path).read_text(encoding="utf-8"))
    assert state["managed_assets"]["sentinel_analytic"]["rule-a"]["status"] == "success"


def test_a_write_records_the_tenant_name_and_prune_forgets_by_it(tmp_path, monkeypatch, fake, tenant) -> None:
    """State is keyed by the file's own id; prune knows an orphan by the id
    derived from its tenant name. An authored id (``defender-x-001``) or a
    suffixed one never matched, and the deleted rule stayed in state. A
    write now records the tenant name, and prune forgets by either."""
    monkeypatch.chdir(tmp_path)
    _rule(tmp_path / "detections", "authored-id-001")
    # The file's tenant name differs from its id.
    path = tmp_path / "detections" / "sentinel_analytic" / "authored-id-001.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["metadata"]["arm_name"] = "guid-1"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    _failed(tmp_path / "retry-input", "authored-id-001")
    assert _retry(tmp_path).exit_code == 0
    state = json.loads(state_path(env=ENV, root=tmp_path).read_text(encoding="utf-8"))
    assert state["managed_assets"]["sentinel_analytic"]["authored-id-001"]["remote_id"] == "guid-1"

    path.unlink()  # the rule is deleted from the repository ...
    _rule(tmp_path / "detections", "kept")
    fake.remote = [{"name": "kept"}, {"name": "guid-1"}]  # ... and pruned
    result = CliRunner().invoke(cli, [
        "prune", "--path", str(tmp_path / "detections"), "--asset", "sentinel_analytic",
        "--role", "prod", "--no-dry-run", "--yes",
    ])
    assert result.exit_code == 0, result.output
    assert fake.deleted == ["guid-1"]
    after = json.loads(state_path(env=ENV, root=tmp_path).read_text(encoding="utf-8"))
    assert "authored-id-001" not in after["managed_assets"].get("sentinel_analytic", {})


def test_prune_forgets_what_it_deleted(tmp_path, monkeypatch, fake, tenant) -> None:
    monkeypatch.chdir(tmp_path)
    _rule(tmp_path / "detections", "kept")
    fake.remote = [{"name": "kept"}, {"name": "gone"}]
    state = EnvState(env=ENV)
    state.remember("sentinel_analytic", "kept", sha="a")
    state.remember("sentinel_analytic", "gone", sha="a")
    save_state(state, root=tmp_path)

    result = CliRunner().invoke(cli, [
        "prune", "--path", str(tmp_path / "detections"), "--asset", "sentinel_analytic",
        "--role", "prod", "--no-dry-run", "--yes",
    ])
    assert result.exit_code == 0, result.output
    assert fake.deleted == ["gone"]
    after = json.loads(state_path(env=ENV, root=tmp_path).read_text(encoding="utf-8"))
    assert set(after["managed_assets"]["sentinel_analytic"]) == {"kept"}
