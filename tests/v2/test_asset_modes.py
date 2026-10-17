# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Per-kind management modes (``assetModes``), the code-level defaults,
the kill switch, apply ordering and the prune guards.

The load-bearing property: an upgraded fork whose tenant secret
pre-dates the support kinds must get ``monitor`` for them, so a
post-upgrade ``prune`` can never delete portal-created automation
rules or playbooks and ``apply`` cannot write them until opted in.
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
import yaml
from click.testing import CliRunner
from pydantic import ValidationError

from contentops.cli import cli
from contentops.cli.commands._shared import asset_mode_for
from contentops.cli.commands.apply_support import (
    WorkspaceRunContext,
    _build_audit_record,
    _process_apply_asset,
    _process_plan_asset,
    ordered_for_apply,
)
from contentops.cli.handler_factories import (
    DISABLED_KINDS_ENV,
    disabled_kinds,
    register_default_handlers,
)
from contentops.config import DefenderConfig, SentinelWorkspaceConfig, WorkspaceSafeguards
from contentops.core.asset import (
    ASSET_MODE_MANAGED,
    ASSET_MODE_MONITOR,
    DEFAULT_ASSET_MODES,
    NON_DETECTION_ASSETS,
    Asset,
)
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.core.registry import default_registry
from contentops.core.result import ActionResult, PlanAction


# ---------------------------------------------------------------------------
# Config model + defaults
# ---------------------------------------------------------------------------


def test_default_modes_cover_every_kind_and_new_kinds_default_to_monitor() -> None:
    assert set(DEFAULT_ASSET_MODES) == set(Asset)
    for kind in NON_DETECTION_ASSETS:
        assert DEFAULT_ASSET_MODES[kind] == ASSET_MODE_MONITOR
    for kind in set(Asset) - NON_DETECTION_ASSETS:
        assert DEFAULT_ASSET_MODES[kind] == ASSET_MODE_MANAGED


def test_workspace_asset_mode_explicit_beats_default() -> None:
    ws = SentinelWorkspaceConfig(subscriptionId="s", resourceGroup="rg", workspaceName="w")
    assert ws.asset_mode(Asset.SENTINEL_PLAYBOOK) == "monitor"
    assert ws.asset_mode("sentinel_analytic") == "managed"
    ws2 = SentinelWorkspaceConfig(
        subscriptionId="s", resourceGroup="rg", workspaceName="w",
        assetModes={"sentinel_playbook": "managed", "sentinel_analytic": "monitor"},
    )
    assert ws2.asset_mode(Asset.SENTINEL_PLAYBOOK) == "managed"
    assert ws2.asset_mode(Asset.SENTINEL_ANALYTIC) == "monitor"


def test_asset_modes_reject_unknown_kind_cross_engine_and_bad_value() -> None:
    with pytest.raises(ValidationError, match="unknown asset kind"):
        SentinelWorkspaceConfig(subscriptionId="s", resourceGroup="rg", workspaceName="w",
                                assetModes={"sentinel_workbook": "managed"})
    with pytest.raises(ValidationError, match="different engine"):
        SentinelWorkspaceConfig(subscriptionId="s", resourceGroup="rg", workspaceName="w",
                                assetModes={"defender_custom_detection": "managed"})
    with pytest.raises(ValidationError, match="different engine"):
        DefenderConfig(assetModes={"sentinel_playbook": "managed"})
    with pytest.raises(ValidationError):
        DefenderConfig(assetModes={"defender_custom_detection": "paused"})
    assert WorkspaceSafeguards().asset_mode(Asset.DEFENDER_CUSTOM_DETECTION) == "managed"


def test_playbooks_resource_group_defaults_to_workspace_rg() -> None:
    ws = SentinelWorkspaceConfig(subscriptionId="s", resourceGroup="rg", workspaceName="w")
    assert ws.effective_playbooks_resource_group == "rg"
    ws2 = SentinelWorkspaceConfig(subscriptionId="s", resourceGroup="rg", workspaceName="w",
                                  playbooksResourceGroup="rg-pb")
    assert ws2.effective_playbooks_resource_group == "rg-pb"


def _tenant_yml(tmp_path: Path, monkeypatch, *, modes: str = "") -> Path:
    cfg = tmp_path / "tenant.yml"
    cfg.write_text(dedent(f"""
        tenant:
          name: t
          tenantId: "00000000-0000-0000-0000-000000000000"
          defender:
            enabled: true
          sentinelWorkspaces:
            - role: prod
              subscriptionId: "00000000-0000-0000-0000-000000000001"
              resourceGroup: rg
              workspaceName: law-one
              location: westeurope
              {modes}
    """), encoding="utf-8")
    monkeypatch.setattr("contentops.config.CONFIG_PATH", cfg)
    monkeypatch.delenv("PIPELINE_ENV", raising=False)
    return cfg


def test_asset_mode_for_reads_tenant_yml_and_falls_back_without_it(tmp_path: Path, monkeypatch) -> None:
    # No tenant.yml: code defaults.
    assert asset_mode_for(Asset.SENTINEL_PLAYBOOK) == "monitor"
    assert asset_mode_for(Asset.SENTINEL_ANALYTIC) == "managed"
    # tenant.yml without assetModes (an upgraded fork): still monitor.
    _tenant_yml(tmp_path, monkeypatch)
    assert asset_mode_for(Asset.SENTINEL_AUTOMATION_RULE) == "monitor"
    assert asset_mode_for(Asset.DEFENDER_CUSTOM_DETECTION) == "managed"
    # Explicit opt-in.
    _tenant_yml(tmp_path, monkeypatch, modes="assetModes: {sentinel_automation_rule: managed}")
    assert asset_mode_for(Asset.SENTINEL_AUTOMATION_RULE) == "managed"
    assert asset_mode_for(Asset.SENTINEL_AUTOMATION_RULE, "law-one") == "managed"
    assert asset_mode_for(Asset.SENTINEL_PLAYBOOK, "law-one") == "monitor"


# ---------------------------------------------------------------------------
# Kill switch
# ---------------------------------------------------------------------------


def test_kill_switch_unregisters_listed_kinds(monkeypatch) -> None:
    monkeypatch.setenv(DISABLED_KINDS_ENV, "sentinel_playbook, sentinel_automation_rule")
    assert disabled_kinds() == frozenset({Asset.SENTINEL_PLAYBOOK, Asset.SENTINEL_AUTOMATION_RULE})
    register_default_handlers()
    try:
        assert not default_registry.has(Asset.SENTINEL_PLAYBOOK)
        assert not default_registry.has(Asset.SENTINEL_AUTOMATION_RULE)
        assert default_registry.has(Asset.SENTINEL_ANALYTIC)
    finally:
        default_registry.close_all()


def test_kill_switch_rejects_unknown_values(monkeypatch) -> None:
    monkeypatch.setenv(DISABLED_KINDS_ENV, "sentinel_playbok")
    with pytest.raises(ValueError, match="unknown asset kind"):
        disabled_kinds()


# ---------------------------------------------------------------------------
# Apply ordering + monitor gate
# ---------------------------------------------------------------------------


def _la(kind: Asset, env_id: str, path: str) -> LoadedAsset:
    env = EnvelopeV2(id=env_id, version="1.0.0", asset=kind, status="production")
    return LoadedAsset(path=Path(path), envelope=env, payload={})


def test_ordered_for_apply_playbooks_first_automation_rules_last() -> None:
    loaded = [
        _la(Asset.SENTINEL_AUTOMATION_RULE, "ar", "detections/sentinel_automation_rule/ar.yml"),
        _la(Asset.SENTINEL_ANALYTIC, "an", "detections/sentinel_analytic/an.yml"),
        _la(Asset.DEFENDER_CUSTOM_DETECTION, "dc", "detections/defender_custom_detection/dc.yml"),
        _la(Asset.SENTINEL_PLAYBOOK, "pb", "detections/sentinel_playbook/pb.yml"),
        _la(Asset.SENTINEL_WATCHLIST, "wl", "detections/sentinel_watchlist/wl.yml"),
    ]
    assert [la.envelope.id for la in ordered_for_apply(loaded)] == ["pb", "dc", "an", "wl", "ar"]


class _Recording:
    def __init__(self, asset: Asset) -> None:
        self.asset = asset
        self.applied: list[str] = []

    def validate(self, loaded) -> None: ...

    def plan(self, loaded) -> ActionResult:
        return ActionResult(asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                            action=PlanAction.UPDATE, status="planned")

    def apply(self, loaded, *, dry_run: bool = False) -> ActionResult:
        self.applied.append(loaded.envelope.id)
        return ActionResult(asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                            action=PlanAction.UPDATE, status="success", verified=True)

    def delete(self, remote_id: str) -> ActionResult:
        raise AssertionError("not used")

    def close(self) -> None: ...


def test_monitor_mode_skips_apply_and_audits_as_skipped(tmp_path: Path) -> None:
    pb = _Recording(Asset.SENTINEL_PLAYBOOK)
    an = _Recording(Asset.SENTINEL_ANALYTIC)
    default_registry.register(Asset.SENTINEL_PLAYBOOK, lambda: pb)
    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: an)
    ctx = WorkspaceRunContext(command="apply", detections_path=tmp_path / "detections",
                              audit_pairs=[])
    try:
        _process_apply_asset(_la(Asset.SENTINEL_PLAYBOOK, "pb", "x/pb.yml"), None, ctx)
        _process_apply_asset(_la(Asset.SENTINEL_ANALYTIC, "an", "x/an.yml"), None, ctx)
    finally:
        default_registry.close_all()
    assert pb.applied == [] and an.applied == ["an"]
    monitor_result = ctx.results[0]
    assert monitor_result.action is PlanAction.SKIP and monitor_result.status == "monitor"
    assert "assetModes[sentinel_playbook]=monitor" in monitor_result.detail
    assert not monitor_result.is_failure
    rec = _build_audit_record(monitor_result, loaded=_la(Asset.SENTINEL_PLAYBOOK, "pb", "x/pb.yml"))
    assert rec.status == "skipped" and "monitor" in (rec.message or "")


def test_monitor_mode_shows_in_plan(tmp_path: Path) -> None:
    pb = _Recording(Asset.SENTINEL_PLAYBOOK)
    default_registry.register(Asset.SENTINEL_PLAYBOOK, lambda: pb)
    ctx = WorkspaceRunContext(command="plan", detections_path=tmp_path / "detections")
    try:
        _process_plan_asset(_la(Asset.SENTINEL_PLAYBOOK, "pb", "x/pb.yml"), None, ctx)
    finally:
        default_registry.close_all()
    assert ctx.results[0].action is PlanAction.SKIP and ctx.results[0].status == "planned"


# ---------------------------------------------------------------------------
# Prune guards
# ---------------------------------------------------------------------------


class _RemoteOnly:
    """A drift-capable fake listing one remote item that has no local file."""

    def __init__(self, asset: Asset) -> None:
        self.asset = asset
        self.deleted: list[str] = []

    def validate(self, loaded) -> None: ...
    def plan(self, loaded): ...
    def apply(self, loaded, *, dry_run=False): ...

    def delete(self, remote_id: str) -> ActionResult:
        self.deleted.append(remote_id)
        return ActionResult(asset_id=remote_id, asset_kind=self.asset.value,
                            action=PlanAction.DELETE, status="success")

    def list_remote(self) -> list[dict]:
        return [{"name": "remote-only", "properties": {"displayName": "Remote Only"}}]

    def to_envelope(self, remote: dict) -> dict | None:
        return {"id": "remote-only", "version": "1.0.0", "asset": self.asset.value,
                "status": "production", "payload": {}}

    def close(self) -> None: ...


def test_prune_refuses_kind_with_empty_local_set_unless_overridden(tmp_path: Path) -> None:
    fake = _RemoteOnly(Asset.SENTINEL_ANALYTIC)
    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: fake)
    detections = tmp_path / "detections"
    detections.mkdir()
    runner = CliRunner()
    refused = runner.invoke(cli, ["prune", "--path", str(detections), "--no-dry-run", "--yes",
                                  "--asset", "sentinel_analytic"])
    assert refused.exit_code == 2, refused.output
    assert "refused: no local sentinel_analytic envelopes" in refused.output
    assert fake.deleted == []

    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: fake)
    allowed = runner.invoke(cli, ["prune", "--path", str(detections), "--no-dry-run", "--yes",
                                  "--asset", "sentinel_analytic", "--allow-empty-kind"])
    assert allowed.exit_code == 0, allowed.output
    assert fake.deleted == ["remote-only"]


def test_prune_never_touches_a_kind_in_monitor_mode(tmp_path: Path) -> None:
    fake = _RemoteOnly(Asset.SENTINEL_PLAYBOOK)  # default mode: monitor
    default_registry.register(Asset.SENTINEL_PLAYBOOK, lambda: fake)
    detections = tmp_path / "detections"
    detections.mkdir()
    result = CliRunner().invoke(cli, ["prune", "--path", str(detections), "--no-dry-run", "--yes",
                                      "--asset", "sentinel_playbook", "--allow-empty-kind"])
    assert result.exit_code == 0, result.output
    assert "not pruned" in result.output and "monitor" in result.output
    assert fake.deleted == []


def test_apply_order_integration_via_cli(tmp_path: Path, monkeypatch) -> None:
    """Files on disk sort automation rules before playbooks; apply runs
    playbooks first and automation rules last."""
    order: list[str] = []

    class _Seq(_Recording):
        def apply(self, loaded, *, dry_run: bool = False) -> ActionResult:
            order.append(loaded.envelope.id)
            return super().apply(loaded, dry_run=dry_run)

    _tenant_yml(tmp_path, monkeypatch,
                modes="assetModes: {sentinel_playbook: managed, sentinel_automation_rule: managed}")
    monkeypatch.setenv("CONTENTOPS_DISABLED_KINDS", "")
    detections = tmp_path / "detections"
    for kind, env_id in (("sentinel_automation_rule", "ar-one"), ("sentinel_analytic", "an-one"),
                         ("sentinel_playbook", "pb-one")):
        (detections / kind).mkdir(parents=True)
        (detections / kind / f"{env_id}.yml").write_text(yaml.safe_dump({
            "id": env_id, "version": "1.0.0", "asset": kind, "status": "production",
            "metadata": {"arm_name": env_id}, "payload": {},
        }), encoding="utf-8")
    handlers = {k: _Seq(k) for k in (Asset.SENTINEL_AUTOMATION_RULE, Asset.SENTINEL_ANALYTIC, Asset.SENTINEL_PLAYBOOK)}
    import contentops.cli.handler_factories as hf

    def fake_register() -> None:
        for k, h in handlers.items():
            if not default_registry.has(k):
                default_registry.register(k, lambda h=h: h)

    monkeypatch.setattr(hf, "register_default_handlers", fake_register)
    monkeypatch.setattr("contentops.cli.commands.apply_support.register_default_handlers", fake_register)
    monkeypatch.setattr("contentops.cli.commands.apply.register_default_handlers", fake_register, raising=False)
    fake_register()
    result = CliRunner().invoke(cli, ["apply", "--path", str(detections), "--no-audit",
                                      "--skip-deps-check", "--asset-order-check"] if False else
                                ["apply", "--path", str(detections), "--no-audit", "--skip-deps-check"])
    assert result.exit_code == 0, result.output
    assert order == ["pb-one", "an-one", "ar-one"], (order, result.output)
