# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""A locked rule set to deprecated is switched off as it is in the tenant.

``contentops disable`` on a locked rule (``localCustomization: true``, tuned
in the portal) kept the rule in the run, and the handler then sent the
repository's whole body with the rule switched off: the portal tuning was
overwritten, and re-enabling brought the repository's version back. Now the
handler reads the tenant's object and changes only its on/off state.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import pytest
import yaml

from contentops.config import SentinelConfig
from contentops.core.asset import Asset
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.core.result import ActionResult, PlanAction
from contentops.providers import sentinel_arm
from contentops.providers.sentinel_arm import SentinelArmProvider


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(sentinel_arm.time, "sleep", lambda *_: None)


def _provider(transport) -> SentinelArmProvider:
    cfg = SentinelConfig(subscriptionId="sub", resourceGroup="rg", workspaceName="ws",
                         playbooksResourceGroup="rg-pb")
    p = SentinelArmProvider(cfg, token="t")
    p._client.close()
    p._client = httpx.Client(base_url=sentinel_arm.ARM_BASE_URL, transport=httpx.MockTransport(transport))
    return p


def _loaded(asset: Asset, payload: dict, *, arm_name: str = "remote-1") -> LoadedAsset:
    env = EnvelopeV2(id="rule-a", version="1.0.0", asset=asset, status="deprecated", arm_name=arm_name)
    return LoadedAsset(path=Path("rule-a.yml"), envelope=env, payload=payload)


class _Arm:
    """GET returns the stored object; PUT stores the body; POST .../disable
    switches a workflow off. Records every request."""

    def __init__(self, stored: dict | None) -> None:
        self.stored = copy.deepcopy(stored)
        self.calls: list[tuple[str, str, dict | None, str | None]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, request.url.path, body, request.headers.get("If-Match")))
        if request.method == "GET":
            return httpx.Response(404, json={}) if self.stored is None else httpx.Response(200, json=self.stored)
        if request.method == "PUT":
            self.stored = {**body, "etag": 'W/"new"'}
            return httpx.Response(200, json=self.stored)
        if request.method == "POST" and request.url.path.endswith("/disable"):
            self.stored["properties"]["state"] = "Disabled"
            return httpx.Response(200)
        return httpx.Response(405)


def test_an_analytic_is_switched_off_with_its_tenant_query() -> None:
    from contentops.handlers.sentinel_analytic import SentinelAnalyticHandler

    arm = _Arm({"kind": "Scheduled", "etag": 'W/"e1"', "name": "remote-1", "properties": {
        "displayName": "Rule", "query": "Tuned | where x > 5", "enabled": True,
        "severity": "High", "lastModifiedUtc": "2026-11-24T08:00:00Z",
    }})
    handler = SentinelAnalyticHandler(lambda: _provider(arm))
    result = handler.disable_in_place(_loaded(Asset.SENTINEL_ANALYTIC, {"query": "Repo | take 1"}))
    assert (result.action, result.status, result.verified) == (PlanAction.DISABLE, "success", True)
    [put] = [c for c in arm.calls if c[0] == "PUT"]
    props = put[2]["properties"]
    assert props["query"] == "Tuned | where x > 5" and props["enabled"] is False
    assert "lastModifiedUtc" not in props
    assert put[3] == 'W/"e1"'


def test_an_analytic_already_off_or_absent_is_not_written() -> None:
    from contentops.handlers.sentinel_analytic import SentinelAnalyticHandler

    off = _Arm({"kind": "Scheduled", "properties": {"enabled": False}})
    r = SentinelAnalyticHandler(lambda: _provider(off)).disable_in_place(_loaded(Asset.SENTINEL_ANALYTIC, {}))
    assert r.verified is True and not [c for c in off.calls if c[0] == "PUT"]
    absent = _Arm(None)
    r = SentinelAnalyticHandler(lambda: _provider(absent)).disable_in_place(_loaded(Asset.SENTINEL_ANALYTIC, {}))
    assert r.action is PlanAction.SKIP


def test_an_automation_rule_is_switched_off_with_its_tenant_actions() -> None:
    from contentops.handlers.sentinel_automation_rule import SentinelAutomationRuleHandler

    tenant_actions = [{"order": 1, "actionType": "ModifyProperties",
                       "actionConfiguration": {"severity": "Low"}}]
    arm = _Arm({"etag": 'W/"e1"', "name": "remote-1", "properties": {
        "displayName": "Tuned", "order": 3, "actions": tenant_actions,
        "triggeringLogic": {"isEnabled": True, "triggersOn": "Incidents", "triggersWhen": "Created",
                            "conditions": []},
        "createdTimeUtc": "2026-01-01T00:00:00Z", "lastModifiedTimeUtc": "2026-11-24T00:00:00Z",
    }})
    handler = SentinelAutomationRuleHandler(lambda: _provider(arm))
    result = handler.disable_in_place(_loaded(Asset.SENTINEL_AUTOMATION_RULE, {"displayName": "Repo"}))
    assert (result.action, result.verified) == (PlanAction.DISABLE, True)
    [put] = [c for c in arm.calls if c[0] == "PUT"]
    props = put[2]["properties"]
    assert props["actions"] == tenant_actions and props["displayName"] == "Tuned"
    assert props["triggeringLogic"]["isEnabled"] is False
    assert "createdTimeUtc" not in props and "lastModifiedTimeUtc" not in props
    assert put[3] == 'W/"e1"'


def test_a_playbook_is_switched_off_through_the_disable_action() -> None:
    from contentops.handlers.sentinel_playbook import SentinelPlaybookHandler

    arm = _Arm({"name": "remote-1", "properties": {"state": "Enabled", "definition": {"tuned": True}}})
    handler = SentinelPlaybookHandler(lambda: _provider(arm))
    result = handler.disable_in_place(_loaded(Asset.SENTINEL_PLAYBOOK, {"definition": {}}))
    assert (result.action, result.verified) == (PlanAction.DISABLE, True)
    assert [c[0] for c in arm.calls] == ["GET", "POST", "GET"]
    assert arm.calls[1][1].endswith("/workflows/remote-1/disable")


def test_a_defender_rule_is_switched_off_with_a_status_only_patch() -> None:
    from contentops.handlers.defender_custom_detection import DefenderCustomDetectionHandler
    from tests.v2.defender_shapes import FakeGraph, current_payload

    tuned = current_payload()
    tuned["queryCondition"]["queryText"] = "DeviceEvents | where Tuned == 1"
    stored = FakeGraph().create_rule(copy.deepcopy(tuned)).json()
    graph = FakeGraph(rules=[stored])
    handler = DefenderCustomDetectionHandler(lambda: graph)
    result = handler.disable_in_place(_loaded(Asset.DEFENDER_CUSTOM_DETECTION, current_payload(),
                                              arm_name=stored["id"]))
    assert (result.action, result.verified) == (PlanAction.DISABLE, True)
    assert [(c[0], c[2]) for c in graph.writes()] == [("PATCH", {"status": "disabled"})]


# --- routing in apply ---------------------------------------------------------


class _Recorder:
    asset = Asset.SENTINEL_ANALYTIC

    def __init__(self, *, in_place: bool = True) -> None:
        self.applied: list[str] = []
        self.disabled: list[str] = []
        if not in_place:
            self.disable_in_place = None  # type: ignore[assignment]

    def validate(self, loaded) -> None:
        return None

    def apply(self, loaded, *, dry_run=False):
        self.applied.append(loaded.envelope.id)
        return ActionResult(asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                            action=PlanAction.DISABLE, status="success", verified=True)

    def disable_in_place(self, loaded):  # noqa: F811 — replaced per instance above
        self.disabled.append(loaded.envelope.id)
        return ActionResult(asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                            action=PlanAction.DISABLE, status="success", verified=True)


def _locked_deprecated(tmp_path: Path) -> LoadedAsset:
    path = tmp_path / "rule-a.yml"
    path.write_text(yaml.safe_dump({"id": "rule-a", "localCustomization": True}), encoding="utf-8")
    env = EnvelopeV2(id="rule-a", version="1.0.0", asset=Asset.SENTINEL_ANALYTIC, status="deprecated")
    return LoadedAsset(path=path, envelope=env, payload={"query": "Repo"})


def _run(tmp_path: Path, handler, *, force: bool = False):
    from contentops.cli.commands.apply_support import WorkspaceRunContext, _process_apply_asset
    from contentops.core.registry import default_registry

    saved_f, saved_i = dict(default_registry._factories), dict(default_registry._instances)
    default_registry._factories.clear()
    default_registry._instances.clear()
    default_registry.register(Asset.SENTINEL_ANALYTIC, lambda: handler)
    try:
        ctx = WorkspaceRunContext(command="apply", detections_path=tmp_path, audit_pairs=[],
                                  force_overwrite=force)
        _process_apply_asset(_locked_deprecated(tmp_path), None, ctx)
    finally:
        default_registry._factories.clear()
        default_registry._instances.clear()
        default_registry._factories.update(saved_f)
        default_registry._instances.update(saved_i)
    return ctx.results


def test_apply_switches_a_locked_deprecated_rule_off_in_place(tmp_path: Path) -> None:
    handler = _Recorder()
    [result] = _run(tmp_path, handler)
    assert handler.disabled == ["rule-a"] and handler.applied == []
    assert result.verified is True


def test_force_overwrite_sends_the_file_as_before(tmp_path: Path) -> None:
    handler = _Recorder()
    _run(tmp_path, handler, force=True)
    assert handler.applied == ["rule-a"] and handler.disabled == []


def test_a_kind_that_cannot_switch_off_in_place_leaves_a_locked_rule_alone(tmp_path: Path) -> None:
    handler = _Recorder(in_place=False)
    [result] = _run(tmp_path, handler)
    assert handler.applied == []
    assert result.action is PlanAction.SKIP and "portal" in result.detail
