# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""SentinelAutomationRuleHandler against a mocked ARM provider.

Covers apply (create / update / etag / 412 / hash mismatch / expired /
dry-run), reference resolution (``playbook:`` and ``analytic:`` sugar),
delete, list_remote pagination and the collect-side reverse mapping.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import yaml

from contentops.config import SentinelConfig
from contentops.core.asset import Asset
from contentops.core.drift import DriftCapable
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.core.result import PlanAction
from contentops.handlers._verify import ETAG_CONFLICT_MESSAGE
from contentops.handlers.sentinel_automation_rule import (
    EXPIRED_DETAIL,
    SentinelAutomationRuleHandler,
    _automation_projection,
    _strip_server_fields,
)
from contentops.handlers.sentinel_automation_rule_models import (
    AUTOMATION_API_VERSION,
    envelope_id_to_guid,
)
from contentops.providers import sentinel_arm
from contentops.providers.sentinel_arm import SentinelArmProvider

WS_PATH = (
    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(sentinel_arm.time, "sleep", lambda *_: None)


def _future() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _payload(**overrides) -> dict:
    base = {
        "displayName": "Auto-close informational",
        "order": 1,
        "triggeringLogic": {
            "isEnabled": True, "triggersOn": "Incidents", "triggersWhen": "Created",
            "conditions": [],
        },
        "actions": [{
            "order": 1, "actionType": "ModifyProperties",
            "actionConfiguration": {"severity": "Informational"},
        }],
    }
    base.update(overrides)
    return base


def _loaded(status: str = "production", aid: str = "auto-close-info",
            payload: dict | None = None, arm_name: str | None = None) -> LoadedAsset:
    env = EnvelopeV2(
        id=aid, version="1.0.0", asset=Asset.SENTINEL_AUTOMATION_RULE, status=status,
        arm_name=arm_name,
    )
    return LoadedAsset(path=Path("test.yml"), envelope=env, payload=payload or _payload())


def _provider_with(transport: httpx.MockTransport) -> SentinelArmProvider:
    cfg = SentinelConfig(
        subscriptionId="sub", resourceGroup="rg", workspaceName="ws",
        playbooksResourceGroup="rg-pb",
    )
    p = SentinelArmProvider(cfg, token="t")
    p._client.close()
    p._client = httpx.Client(
        base_url=sentinel_arm.ARM_BASE_URL, transport=transport,
        headers={"Authorization": "Bearer t"},
    )
    return p


class _Echo:
    """GET-before-PUT returns ``existing`` (or 404); PUT stores the body and
    returns it; later GETs return the stored body."""

    def __init__(self, existing: dict | None = None, *, put_status: int = 201,
                 mutate=None) -> None:
        self.existing = existing
        self.put_status = put_status
        self.mutate = mutate
        self.calls: list[tuple[str, str, dict | None]] = []
        self.headers: list[httpx.Headers] = []
        self.stored: dict | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, str(request.url), body))
        self.headers.append(request.headers)
        if request.method == "GET":
            current = self.stored or self.existing
            if current is None:
                return httpx.Response(404, json={})
            return httpx.Response(200, json=current)
        if request.method == "PUT":
            if self.put_status >= 400:
                return httpx.Response(self.put_status, text="bad rule")
            stored = {"name": request.url.path.rsplit("/", 1)[-1], "etag": 'W/"new"', **body}
            if self.mutate:
                stored = self.mutate(stored)
            self.stored = stored
            return httpx.Response(self.put_status, json=stored)
        if request.method == "DELETE":
            return httpx.Response(200)
        return httpx.Response(405)


def test_validate_ok_and_rejects_bad_payload() -> None:
    h = SentinelAutomationRuleHandler(lambda: None)
    h.validate(_loaded())
    with pytest.raises(Exception, match="actions"):
        h.validate(_loaded(payload={"displayName": "x", "order": 1, "triggeringLogic": {}, "actions": []}))


def test_plan_skips_experimental_and_expired_and_disables_deprecated() -> None:
    h = SentinelAutomationRuleHandler(lambda: None)
    assert h.plan(_loaded(status="experimental")).action is PlanAction.SKIP
    assert h.plan(_loaded(status="deprecated")).action is PlanAction.DISABLE
    expired = _payload(triggeringLogic={"expirationTimeUtc": "2020-01-01T00:00:00Z", "conditions": []})
    r = h.plan(_loaded(payload=expired))
    assert r.action is PlanAction.SKIP and r.detail == EXPIRED_DETAIL
    assert h.plan(_loaded()).action is PlanAction.UPDATE


def test_apply_dry_run_makes_no_request() -> None:
    called = {"n": 0}

    def factory():
        called["n"] += 1
        return None

    r = SentinelAutomationRuleHandler(factory).apply(_loaded(), dry_run=True)
    assert r.status == "dry-run" and called["n"] == 0


def test_apply_create_uses_uuid5_guid_and_stable_api_version() -> None:
    echo = _Echo()
    h = SentinelAutomationRuleHandler(lambda: _provider_with(httpx.MockTransport(echo)))
    r = h.apply(_loaded())
    assert r.status == "success" and r.action is PlanAction.CREATE and r.verified is True
    methods = [m for m, _, _ in echo.calls]
    assert methods == ["GET", "PUT", "GET"]
    put_url = echo.calls[1][1]
    guid = envelope_id_to_guid("auto-close-info")
    assert f"Microsoft.SecurityInsights/automationRules/{guid}" in put_url
    assert f"api-version={AUTOMATION_API_VERSION}" in put_url
    # First create: the GET found nothing, so the PUT carries no etag.
    assert "If-Match" not in echo.headers[1]
    assert r.extra["arm_name"] == guid
    h.close()


def test_apply_prefers_metadata_arm_name_over_uuid5() -> None:
    echo = _Echo()
    h = SentinelAutomationRuleHandler(lambda: _provider_with(httpx.MockTransport(echo)))
    h.apply(_loaded(arm_name="11111111-2222-3333-4444-555555555555"))
    assert "/automationRules/11111111-2222-3333-4444-555555555555?" in echo.calls[1][1]
    h.close()


def test_apply_sends_if_match_when_remote_exists_and_200_is_update() -> None:
    existing = {"name": "g", "etag": 'W/"e1"', "properties": _payload()}
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            seen["if_match"] = request.headers.get("If-Match")
            return httpx.Response(200, json=existing)
        return httpx.Response(200, json=existing)

    h = SentinelAutomationRuleHandler(lambda: _provider_with(httpx.MockTransport(handler)))
    r = h.apply(_loaded())
    assert r.action is PlanAction.UPDATE and r.verified is True
    assert seen["if_match"] == 'W/"e1"'
    h.close()


def test_apply_412_returns_etag_conflict() -> None:
    existing = {"name": "g", "etag": 'W/"e1"', "properties": _payload()}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT":
            return httpx.Response(412, text="precondition failed")
        return httpx.Response(200, json=existing)

    r = SentinelAutomationRuleHandler(lambda: _provider_with(httpx.MockTransport(handler))).apply(_loaded())
    assert r.status == "error-412" and r.verified is False and r.error == ETAG_CONFLICT_MESSAGE


def test_apply_surfaces_api_error() -> None:
    r = SentinelAutomationRuleHandler(
        lambda: _provider_with(httpx.MockTransport(_Echo(put_status=400))),
    ).apply(_loaded())
    assert r.status == "error-400" and "bad rule" in r.detail and r.verified is False


def test_apply_hash_mismatch_when_remote_drops_an_action() -> None:
    def mutate(stored: dict) -> dict:
        stored = dict(stored)
        stored["properties"] = {**stored["properties"], "actions": []}
        return stored

    r = SentinelAutomationRuleHandler(
        lambda: _provider_with(httpx.MockTransport(_Echo(mutate=mutate))),
    ).apply(_loaded())
    assert r.status == "success" and r.verified is False and "hash mismatch" in r.detail


def test_apply_resolves_playbook_sugar_into_playbooks_rg_and_tenant() -> None:
    echo = _Echo()
    payload = _payload(actions=[{
        "order": 1, "actionType": "RunPlaybook", "actionConfiguration": {"playbook": "notify-soc"},
    }])
    h = SentinelAutomationRuleHandler(
        lambda: _provider_with(httpx.MockTransport(echo)), tenant_id="tenant-guid",
    )
    r = h.apply(_loaded(payload=payload))
    assert r.verified is True
    cfg = echo.calls[1][2]["properties"]["actions"][0]["actionConfiguration"]
    assert cfg == {
        "logicAppResourceId": "/subscriptions/sub/resourceGroups/rg-pb/providers/Microsoft.Logic/workflows/notify-soc",
        "tenantId": "tenant-guid",
    }
    h.close()


def test_apply_resolves_analytic_sugar_from_local_index(tmp_path: Path) -> None:
    (tmp_path / "sentinel_analytic").mkdir()
    (tmp_path / "sentinel_analytic" / "my-rule.yml").write_text(yaml.safe_dump({
        "id": "my-rule", "version": "1.0.0", "asset": "sentinel_analytic", "status": "production",
        "metadata": {"arm_name": "1840b991-aaaa-bbbb-cccc-dddddddddddd"},
        "payload": {"displayName": "x", "kind": "Scheduled", "query": "T"},
    }), encoding="utf-8")
    echo = _Echo()
    payload = _payload(triggeringLogic={"conditions": [{
        "conditionType": "Property", "conditionProperties": {
            "propertyName": "IncidentRelatedAnalyticRuleIds", "operator": "Contains",
            "propertyValues": ["analytic:my-rule"]},
    }]})
    h = SentinelAutomationRuleHandler(
        lambda: _provider_with(httpx.MockTransport(echo)), detections_root=tmp_path,
    )
    r = h.apply(_loaded(payload=payload))
    assert r.verified is True
    values = echo.calls[1][2]["properties"]["triggeringLogic"]["conditions"][0]["conditionProperties"]["propertyValues"]
    assert values == [f"{WS_PATH}/providers/Microsoft.SecurityInsights/alertRules/1840b991-aaaa-bbbb-cccc-dddddddddddd"]
    h.close()


def test_apply_unknown_analytic_reference_raises(tmp_path: Path) -> None:
    payload = _payload(triggeringLogic={"conditions": [{
        "conditionType": "Property", "conditionProperties": {
            "propertyName": "AlertAnalyticRuleIds", "operator": "Contains",
            "propertyValues": ["analytic:nope"]},
    }]})
    h = SentinelAutomationRuleHandler(
        lambda: _provider_with(httpx.MockTransport(_Echo())), detections_root=tmp_path,
    )
    with pytest.raises(ValueError, match="analytic:'nope'"):
        h.apply(_loaded(payload=payload))


def test_projection_detects_swapped_playbook_but_tolerates_casing_and_reordering() -> None:
    def body(actions: list) -> dict:
        return {"properties": {**_payload(), "actions": actions}}

    a = body([{"order": 1, "actionType": "RunPlaybook",
               "actionConfiguration": {"logicAppResourceId": "/subscriptions/S/resourceGroups/RG/providers/Microsoft.Logic/workflows/A"}}])
    a_lower = body([{"order": 1, "actionType": "RunPlaybook",
                     "actionConfiguration": {"logicAppResourceId": "/subscriptions/s/resourcegroups/rg/providers/microsoft.logic/workflows/a"}}])
    b = body([{"order": 1, "actionType": "RunPlaybook",
               "actionConfiguration": {"logicAppResourceId": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Logic/workflows/b"}}])
    assert _automation_projection(a) == _automation_projection(a_lower)
    assert _automation_projection(a) != _automation_projection(b)
    two = body([{"order": 1, "actionType": "AddIncidentTask", "actionConfiguration": {"title": "t"}},
                {"order": 2, "actionType": "ModifyProperties", "actionConfiguration": {"severity": "Low"}}])
    two_rev = body(list(reversed(two["properties"]["actions"])))
    assert _automation_projection(two) == _automation_projection(two_rev)
    # An action's settings are compared: a suppression that closes with
    # another status or classification is not the rule that was sent.
    sev = body([{"order": 1, "actionType": "ModifyProperties", "actionConfiguration": {"severity": "High"}}])
    assert _automation_projection(sev) != _automation_projection(
        body([{"order": 1, "actionType": "ModifyProperties", "actionConfiguration": {"severity": "Low"}}]))


def test_projection_compares_settings_but_tolerates_what_arm_adds() -> None:
    """Seen against a workspace: ARM returns every ModifyProperties field
    we left out as null, adds ``labelType: "User"`` to labels, and changes
    the casing of an analytic resource id in a scope condition. None of that
    is a different rule; another close status or another scope is."""
    rid = "/subscriptions/S/resourceGroups/RG/providers/Microsoft.OperationalInsights/workspaces/WS/providers/Microsoft.SecurityInsights/alertRules/abc"

    def body(cfg: dict, scope: str, title: str = "zz-a") -> dict:
        return {"properties": {**_payload(), "triggeringLogic": {
            "isEnabled": True, "triggersOn": "Incidents", "triggersWhen": "Created",
            "conditions": [
                {"conditionType": "Property", "conditionProperties": {
                    "propertyName": "IncidentTitle", "operator": "Contains", "propertyValues": [title, "zz-b"]}},
                {"conditionType": "Property", "conditionProperties": {
                    "propertyName": "IncidentRelatedAnalyticRuleIds", "operator": "Contains", "propertyValues": [scope]}},
            ]}, "actions": [{"order": 1, "actionType": "ModifyProperties", "actionConfiguration": cfg}]}}

    sent = body({"status": "Closed", "classification": "BenignPositive",
                 "classificationReason": "SuspiciousButExpected", "labels": [{"labelName": "zz"}]}, rid)
    returned = body({"status": "Closed", "classification": "BenignPositive",
                     "classificationReason": "SuspiciousButExpected", "classificationComment": None,
                     "owner": None, "severity": None, "labels": [{"labelName": "zz", "labelType": "User"}]},
                    rid.lower())
    assert _automation_projection(sent) == _automation_projection(returned)
    other_status = body({"status": "Active", "labels": [{"labelName": "zz"}]}, rid)
    assert _automation_projection(sent) != _automation_projection(other_status)
    other_scope = body({"status": "Closed", "classification": "BenignPositive",
                        "classificationReason": "SuspiciousButExpected", "labels": [{"labelName": "zz"}]},
                       rid.replace("/abc", "/xyz"))
    assert _automation_projection(sent) != _automation_projection(other_scope)
    other_title = body({"status": "Closed", "classification": "BenignPositive",
                        "classificationReason": "SuspiciousButExpected", "labels": [{"labelName": "zz"}]},
                       rid, title="zz-other")
    assert _automation_projection(sent) != _automation_projection(other_title)

def test_delete_passes_api_version_and_treats_404_as_success() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(404)

    h = SentinelAutomationRuleHandler(lambda: _provider_with(httpx.MockTransport(handler)))
    r = h.delete("guid-1")
    assert r.status == "success" and r.action is PlanAction.DELETE
    assert f"api-version={AUTOMATION_API_VERSION}" in seen["url"]
    assert "/automationRules/guid-1?" in seen["url"]


def test_list_remote_follows_nextlink() -> None:
    page2 = "https://management.azure.com/automationRules-page2"

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == page2:
            return httpx.Response(200, json={"value": [{"name": "g2", "properties": {"displayName": "B"}}]})
        assert "automationRules" in url and f"api-version={AUTOMATION_API_VERSION}" in url
        return httpx.Response(200, json={
            "value": [{"name": "g1", "properties": {"displayName": "A"}}], "nextLink": page2,
        })

    h = SentinelAutomationRuleHandler(lambda: _provider_with(httpx.MockTransport(handler)))
    assert {i["name"] for i in h.list_remote()} == {"g1", "g2"}


def _remote(**props) -> dict:
    base = {
        "displayName": "Auto-close Informational!",
        "order": 5,
        "triggeringLogic": {"isEnabled": True, "triggersOn": "Incidents", "triggersWhen": "Created",
                            "conditions": [], "expirationTimeUtc": "2099-01-01T00:00:00.000+00:00"},
        "actions": [],
        "createdBy": {"name": "someone"}, "lastModifiedTimeUtc": "2026-01-01T00:00:00Z",
    }
    base.update(props)
    return {"name": "guid-1", "etag": 'W/"x"', "type": "Microsoft.SecurityInsights/automationRules",
            "properties": base}


def test_to_envelope_sets_arm_name_slug_id_and_strips_server_fields() -> None:
    env = SentinelAutomationRuleHandler(lambda: None).to_envelope(_remote())
    assert env is not None
    assert env["id"] == "auto-close-informational"
    assert env["metadata"] == {"arm_name": "guid-1"}
    assert env["status"] == "production"
    assert env["payload"]["order"] == 5
    assert env["payload"]["triggeringLogic"]["expirationTimeUtc"] == "2099-01-01T00:00:00Z"
    assert "createdBy" not in env["payload"] and "etag" not in env
    EnvelopeV2(id=env["id"], version=env["version"], asset=Asset(env["asset"]), status=env["status"])
    stripped = _strip_server_fields(_remote())
    assert "etag" not in stripped and "lastModifiedTimeUtc" not in stripped["properties"]


def test_to_envelope_expired_rule_lands_as_deprecated() -> None:
    env = SentinelAutomationRuleHandler(lambda: None).to_envelope(
        _remote(triggeringLogic={"isEnabled": True, "triggersOn": "Incidents", "triggersWhen": "Created",
                                 "conditions": [], "expirationTimeUtc": "2020-01-01T00:00:00Z"}),
    )
    assert env is not None and env["status"] == "deprecated"


def test_to_envelope_falls_back_to_name_when_displayname_unsluggable() -> None:
    h = SentinelAutomationRuleHandler(lambda: None)
    env = h.to_envelope({"name": "guid-1", "properties": {"displayName": "***"}})
    assert env is not None and env["id"] == "guid-1"
    assert h.to_envelope({"properties": {"displayName": "x"}}) is None


def _write_playbook_envelope(root: Path, envelope_id: str) -> None:
    (root / "sentinel_playbook").mkdir(exist_ok=True)
    (root / "sentinel_playbook" / f"{envelope_id}.yml").write_text(yaml.safe_dump({
        "id": envelope_id, "version": "1.0.0", "asset": "sentinel_playbook", "status": "production",
        "payload": {"definition": {"triggers": {}, "actions": {}}},
    }), encoding="utf-8")


def test_to_envelope_reverse_maps_playbook_and_analytic_sugar(tmp_path: Path) -> None:
    (tmp_path / "sentinel_analytic").mkdir()
    (tmp_path / "sentinel_analytic" / "my-rule.yml").write_text(yaml.safe_dump({
        "id": "my-rule", "version": "1.0.0", "asset": "sentinel_analytic", "status": "production",
        "metadata": {"arm_name": "1840b991"}, "payload": {"displayName": "x", "kind": "Scheduled", "query": "T"},
    }), encoding="utf-8")
    _write_playbook_envelope(tmp_path, "notify-soc")
    provider = _provider_with(httpx.MockTransport(lambda r: httpx.Response(404)))
    h = SentinelAutomationRuleHandler(lambda: provider, tenant_id="TENANT-GUID", detections_root=tmp_path)
    remote = _remote(
        actions=[
            {"order": 1, "actionType": "RunPlaybook", "actionConfiguration": {
                "logicAppResourceId": "/subscriptions/SUB/resourceGroups/RG-PB/providers/Microsoft.Logic/workflows/Notify-SOC",
                "tenantId": "tenant-guid"}},
            {"order": 2, "actionType": "RunPlaybook", "actionConfiguration": {
                "logicAppResourceId": "/subscriptions/other/resourceGroups/x/providers/Microsoft.Logic/workflows/foreign",
                "tenantId": "t2"}},
        ],
        triggeringLogic={"isEnabled": True, "triggersOn": "Incidents", "triggersWhen": "Created", "conditions": [{
            "conditionType": "Property", "conditionProperties": {
                "propertyName": "IncidentRelatedAnalyticRuleIds", "operator": "Contains",
                "propertyValues": [f"{WS_PATH}/providers/Microsoft.SecurityInsights/alertRules/1840b991",
                                   "/elsewhere/alertRules/zzz"]}}]},
    )
    env = h.to_envelope(remote)
    assert env is not None
    actions = env["payload"]["actions"]
    assert actions[0]["actionConfiguration"] == {"playbook": "notify-soc"}
    assert actions[1]["actionConfiguration"]["logicAppResourceId"].endswith("/foreign")
    assert actions[1]["actionConfiguration"]["tenantId"] == "t2"
    values = env["payload"]["triggeringLogic"]["conditions"][0]["conditionProperties"]["propertyValues"]
    assert values == ["analytic:my-rule", "/elsewhere/alertRules/zzz"]
    h.close()


def test_to_envelope_names_an_unmanaged_logic_app_without_its_resource_id(tmp_path: Path) -> None:
    """A rule in the tenant may run a Logic App that ContentOps does not
    manage. ``playbook:`` means a playbook envelope in the repo, so lint
    (PAYLOAD007) and the plan's dependency check rejected the collected
    file and every later pull request was red. The raw resource id is no
    way out: it holds the subscription GUID, which gitleaks blocks in
    this directory. Collect writes ``logicApp: <name>`` instead, the
    Logic App's exact name in the configured playbook resource group."""
    provider = _provider_with(httpx.MockTransport(lambda r: httpx.Response(404)))
    h = SentinelAutomationRuleHandler(lambda: provider, tenant_id="TENANT-GUID", detections_root=tmp_path)
    remote = _remote(actions=[{"order": 1, "actionType": "RunPlaybook", "actionConfiguration": {
        "logicAppResourceId": "/subscriptions/SUB/resourceGroups/RG-PB/providers/Microsoft.Logic/workflows/Notify_SOC.Teams",
        "tenantId": "tenant-guid"}}])
    env = h.to_envelope(remote)
    assert env is not None
    assert env["payload"]["actions"][0]["actionConfiguration"] == {"logicApp": "Notify_SOC.Teams"}
    h.close()


def test_apply_resolves_an_unmanaged_logic_app_into_playbooks_rg_and_tenant() -> None:
    echo = _Echo()
    payload = _payload(actions=[{
        "order": 1, "actionType": "RunPlaybook", "actionConfiguration": {"logicApp": "Notify_SOC.Teams"},
    }])
    h = SentinelAutomationRuleHandler(
        lambda: _provider_with(httpx.MockTransport(echo)), tenant_id="tenant-guid",
    )
    r = h.apply(_loaded(payload=payload))
    assert r.verified is True
    cfg = echo.calls[1][2]["properties"]["actions"][0]["actionConfiguration"]
    assert cfg == {
        "logicAppResourceId": "/subscriptions/sub/resourceGroups/rg-pb/providers/Microsoft.Logic/workflows/Notify_SOC.Teams",
        "tenantId": "tenant-guid",
    }
    h.close()


def test_handler_satisfies_drift_protocol() -> None:
    assert isinstance(SentinelAutomationRuleHandler(lambda: None), DriftCapable)


def _write_named_playbook(root: Path, envelope_id: str, arm_name: str) -> None:
    (root / "sentinel_playbook").mkdir(exist_ok=True)
    (root / "sentinel_playbook" / f"{envelope_id}.yml").write_text(yaml.safe_dump({
        "id": envelope_id, "version": "1.0.0", "asset": "sentinel_playbook", "status": "production",
        "metadata": {"arm_name": arm_name},
        "payload": {"definition": {"triggers": {}, "actions": {}}},
    }), encoding="utf-8")


def test_apply_resolves_playbook_to_its_workflow_name_not_its_envelope_id(tmp_path: Path) -> None:
    """A collected Logic App ``Notify_SOC`` becomes envelope ``notify-soc``
    with ``arm_name: Notify_SOC``, and the playbook handler deploys it under
    that name. ``playbook: notify-soc`` was resolved to
    ``.../workflows/notify-soc``, a Logic App that does not exist."""
    _write_named_playbook(tmp_path, "notify-soc", "Notify_SOC")
    echo = _Echo()
    payload = _payload(actions=[{
        "order": 1, "actionType": "RunPlaybook", "actionConfiguration": {"playbook": "notify-soc"},
    }])
    h = SentinelAutomationRuleHandler(
        lambda: _provider_with(httpx.MockTransport(echo)), tenant_id="tenant-guid", detections_root=tmp_path,
    )
    r = h.apply(_loaded(payload=payload))
    assert r.verified is True
    cfg = echo.calls[1][2]["properties"]["actions"][0]["actionConfiguration"]
    assert cfg["logicAppResourceId"].endswith("/providers/Microsoft.Logic/workflows/Notify_SOC")
    h.close()


def test_to_envelope_names_a_playbook_by_the_envelope_that_deploys_it(tmp_path: Path) -> None:
    _write_named_playbook(tmp_path, "notify-soc", "Notify_SOC")
    provider = _provider_with(httpx.MockTransport(lambda r: httpx.Response(404)))
    h = SentinelAutomationRuleHandler(lambda: provider, tenant_id="TENANT-GUID", detections_root=tmp_path)
    remote = _remote(actions=[{"order": 1, "actionType": "RunPlaybook", "actionConfiguration": {
        "logicAppResourceId": "/subscriptions/SUB/resourceGroups/RG-PB/providers/Microsoft.Logic/workflows/Notify_SOC",
        "tenantId": "tenant-guid"}}])
    env = h.to_envelope(remote)
    assert env["payload"]["actions"][0]["actionConfiguration"] == {"playbook": "notify-soc"}
    h.close()


def test_to_envelope_writes_playbook_only_when_its_envelope_exists(tmp_path: Path) -> None:
    """The managed tag alone used to be enough. When no playbook file comes
    with it (collect of rules only, playbooks switched off, the playbook
    skipped), the rule named an envelope that does not exist: PAYLOAD007
    and the dependency check failed every later run. ``logicApp:`` deploys
    the same way and needs no envelope."""
    tagged = {"name": "Notify_SOC", "tags": {"contentops-managed": "true"}, "properties": {}}
    provider = _provider_with(httpx.MockTransport(lambda r: httpx.Response(200, json=tagged)))
    h = SentinelAutomationRuleHandler(lambda: provider, tenant_id="TENANT-GUID", detections_root=tmp_path)
    remote = _remote(actions=[{"order": 1, "actionType": "RunPlaybook", "actionConfiguration": {
        "logicAppResourceId": "/subscriptions/SUB/resourceGroups/RG-PB/providers/Microsoft.Logic/workflows/Notify_SOC",
        "tenantId": "tenant-guid"}}])
    env = h.to_envelope(remote)
    assert env["payload"]["actions"][0]["actionConfiguration"] == {"logicApp": "Notify_SOC"}
    h.close()


def test_apply_switches_a_deprecated_rule_off() -> None:
    """``contentops disable`` (emergency disable) sets ``status: deprecated``.
    The handler only skipped it ("use prune"), and prune never deletes a rule
    whose file still exists, so a suppression rule kept closing incidents.
    It is now PUT with ``isEnabled: false``, like a deprecated analytic."""
    echo = _Echo()
    h = SentinelAutomationRuleHandler(lambda: _provider_with(httpx.MockTransport(echo)))
    r = h.apply(_loaded(status="deprecated"))
    assert r.action is PlanAction.DISABLE and r.verified is True
    put = next(body for method, _, body in echo.calls if method == "PUT")
    assert put["properties"]["triggeringLogic"]["isEnabled"] is False
    h.close()


def test_a_deprecated_rule_that_already_expired_is_left_alone() -> None:
    """Collect imports an expired rule as deprecated; it does nothing any
    more, and a PUT with an expiry in the past can be refused."""
    echo = _Echo()
    expired = _payload(triggeringLogic={"expirationTimeUtc": "2020-01-01T00:00:00Z", "conditions": []})
    h = SentinelAutomationRuleHandler(lambda: _provider_with(httpx.MockTransport(echo)))
    r = h.apply(_loaded(status="deprecated", payload=expired))
    assert r.action is PlanAction.SKIP
    assert not any(method == "PUT" for method, _, _ in echo.calls)
    h.close()
