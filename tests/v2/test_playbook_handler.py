# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""SentinelPlaybookHandler against a mocked ARM provider.

Connections deploy before the workflow and abort on failure; the
playbook lands in the configured playbooks resource group; role
assignments are verified and reported, never assigned; list_remote is
managed-tag only; delete removes only tagged connections.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
import pytest

from contentops.config import SentinelConfig
from contentops.core.asset import Asset
from contentops.core.drift import DriftCapable
from contentops.core.envelope import EnvelopeV2
from contentops.core.handler import LoadedAsset
from contentops.core.result import PlanAction
from contentops.handlers._verify import ETAG_CONFLICT_MESSAGE
from contentops.handlers.sentinel_playbook import (
    SentinelPlaybookHandler,
    _playbook_projection,
    _strip_server_fields,
)
from contentops.handlers.sentinel_playbook_models import (
    MANAGED_TAG,
    PLAYBOOK_TAG,
    canonical_connections_param,
)
from contentops.providers import sentinel_arm
from contentops.providers.sentinel_arm import SentinelArmProvider

_SENTINEL_REF = "@parameters('$connections')['azuresentinel']['connectionId']"
ARM = "https://management.azure.com"


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(sentinel_arm.time, "sleep", lambda *_: None)


def _definition() -> dict:
    return {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "triggers": {"When_incident_created": {
            "type": "ApiConnectionWebhook",
            "inputs": {"host": {"connection": {"name": _SENTINEL_REF}}, "path": "/incident-creation"},
        }},
        "actions": {"Post": {"type": "Http", "inputs": {"method": "POST", "uri": "https://hooks.example.com"}}},
    }


def _payload(**overrides) -> dict:
    base = {
        "connections": [{"name": "azuresentinel"}],
        "roleAssignments": [{"role": "Microsoft Sentinel Responder", "scope": "workspace"}],
        "definition": _definition(),
    }
    base.update(overrides)
    return base


def _loaded(status: str = "production", aid: str = "notify-soc",
            payload: dict | None = None) -> LoadedAsset:
    env = EnvelopeV2(id=aid, version="1.0.0", asset=Asset.SENTINEL_PLAYBOOK, status=status)
    return LoadedAsset(path=Path("test.yml"), envelope=env,
                       payload=payload if payload is not None else _payload())


def _provider_with(transport: httpx.MockTransport, *, location: str = "westeurope",
                   playbooks_rg: str | None = "rg-pb") -> SentinelArmProvider:
    cfg = SentinelConfig(
        subscriptionId="sub", resourceGroup="rg", workspaceName="ws", location=location,
        playbooksResourceGroup=playbooks_rg,
    )
    p = SentinelArmProvider(cfg, token="t")
    p._client.close()
    p._client = httpx.Client(base_url=sentinel_arm.ARM_BASE_URL, transport=transport,
                             headers={"Authorization": "Bearer t"})
    return p


class _Tenant:
    """A tiny ARM fake: stores connections + workflows by URL path, echoes
    PUT bodies back on GET (adding an identity principalId on workflows),
    answers role-assignment and resources queries."""

    def __init__(self, *, role_present: bool = False, connection_put_status: int = 201,
                 workflow_put_status: int = 201, existing_workflow: dict | None = None,
                 roles_status: int = 200) -> None:
        self.store: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.bodies: dict[str, dict] = {}
        self.role_present = role_present
        self.connection_put_status = connection_put_status
        self.workflow_put_status = workflow_put_status
        self.roles_status = roles_status
        self.tagged_connections: list[dict] = []
        self.managed_workflows: list[dict] = []
        self.patched_tags: dict | None = None
        if existing_workflow is not None:
            self.store["/subscriptions/sub/resourceGroups/rg-pb/providers/Microsoft.Logic/workflows/notify-soc"] = existing_workflow

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method
        self.calls.append((method, path))
        if "/providers/Microsoft.Authorization/roleAssignments" in path:
            if self.roles_status != 200:
                return httpx.Response(self.roles_status, json={})
            value = [{"properties": {"roleDefinitionId":
                      "/subscriptions/sub/providers/Microsoft.Authorization/roleDefinitions/3e150937-b8fe-4cfb-8069-0eaf05ecd056"}}] \
                if self.role_present else []
            return httpx.Response(200, json={"value": value})
        if path.endswith("/resources"):
            flt = request.url.params.get("$filter", "")
            # Real ARM rejects a tag filter combined with resourceType.
            if "resourceType eq" in flt and "tagName eq" in flt:
                return httpx.Response(400, json={"error": {"code": "InvalidFilter"}})
            if "contentops-playbook" in flt:
                return httpx.Response(200, json={"value": [
                    {**c, "type": "Microsoft.Web/connections"} for c in self.tagged_connections
                ]})
            return httpx.Response(200, json={"value": [
                {**w, "type": "Microsoft.Logic/workflows"} for w in self.managed_workflows
            ]})
        is_workflow = "/Microsoft.Logic/workflows/" in path
        if method == "GET":
            body = self.store.get(path)
            return httpx.Response(200, json=body) if body else httpx.Response(404, json={})
        if method == "PUT":
            body = json.loads(request.content)
            self.bodies[path] = body
            status = self.workflow_put_status if is_workflow else self.connection_put_status
            if status >= 400:
                return httpx.Response(status, text="boom")
            stored = {"id": path, "name": path.rsplit("/", 1)[-1], "etag": 'W/"1"', **body}
            if is_workflow:
                stored["identity"] = {**stored.get("identity", {}), "principalId": "pid-123", "tenantId": "t"}
                stored["properties"] = {**stored["properties"], "provisioningState": "Succeeded"}
            self.store[path] = stored
            return httpx.Response(status, json=stored)
        if method == "PATCH":
            self.patched_tags = json.loads(request.content).get("tags")
            cur = self.store.get(path, {"name": path.rsplit("/", 1)[-1], "properties": {}})
            cur = {**cur, "tags": self.patched_tags}
            self.store[path] = cur
            return httpx.Response(200, json=cur)
        if method == "DELETE":
            existed = self.store.pop(path, None) is not None
            return httpx.Response(200 if existed else 404)
        return httpx.Response(405)


def _handler(tenant: _Tenant, **provider_kwargs) -> SentinelPlaybookHandler:
    return SentinelPlaybookHandler(lambda: _provider_with(httpx.MockTransport(tenant), **provider_kwargs))


def test_validate_ok_and_rejects_long_id_and_missing_definition() -> None:
    h = SentinelPlaybookHandler(lambda: None)
    h.validate(_loaded())
    with pytest.raises(ValueError, match="longer than"):
        h.validate(_loaded(aid="a" * 70))
    with pytest.raises(Exception, match="definition"):
        h.validate(_loaded(payload={"connections": []}))


def test_plan_skips_non_production() -> None:
    h = SentinelPlaybookHandler(lambda: None)
    assert h.plan(_loaded(status="experimental")).action is PlanAction.SKIP
    assert h.plan(_loaded(status="deprecated")).action is PlanAction.SKIP
    assert h.plan(_loaded()).action is PlanAction.UPDATE


def test_apply_dry_run_makes_no_request() -> None:
    called = {"n": 0}

    def factory():
        called["n"] += 1
        return None

    r = SentinelPlaybookHandler(factory).apply(_loaded(), dry_run=True)
    assert r.status == "dry-run" and called["n"] == 0


def test_apply_puts_connections_before_workflow_in_playbooks_rg() -> None:
    tenant = _Tenant()
    h = _handler(tenant)
    r = h.apply(_loaded())
    assert r.status == "success" and r.action is PlanAction.CREATE and r.verified is True

    puts = [p for m, p in tenant.calls if m == "PUT"]
    assert puts == [
        "/subscriptions/sub/resourceGroups/rg-pb/providers/Microsoft.Web/connections/notify-soc-azuresentinel",
        "/subscriptions/sub/resourceGroups/rg-pb/providers/Microsoft.Logic/workflows/notify-soc",
    ]
    assert not any("Microsoft.SecurityInsights" in p or "workspaces/ws" in p for _, p in tenant.calls if "roleAssignments" not in p)

    conn_body = tenant.bodies[puts[0]]
    assert conn_body["properties"]["parameterValueType"] == "Alternative"
    assert conn_body["tags"] == {MANAGED_TAG: "true", PLAYBOOK_TAG: "notify-soc"}
    assert conn_body["location"] == "westeurope"

    wf_body = tenant.bodies[puts[1]]
    assert wf_body["identity"] == {"type": "SystemAssigned"}
    assert wf_body["tags"][MANAGED_TAG] == "true"
    refs = wf_body["properties"]["parameters"]["$connections"]["value"]
    assert refs["azuresentinel"]["connectionName"] == "notify-soc-azuresentinel"
    assert refs["azuresentinel"]["connectionId"] == puts[0]
    assert refs["azuresentinel"]["id"].endswith("/managedApis/azuresentinel")
    assert wf_body["properties"]["definition"]["parameters"]["$connections"] == canonical_connections_param()

    # Role verification: principal captured, missing role reported as an az command.
    assert r.extra["principalId"] == "pid-123"
    assert r.extra["arm_name"] == "notify-soc"
    missing = r.extra["missingRoleAssignments"]
    assert len(missing) == 1
    assert "az role assignment create" in missing[0]
    assert "--assignee-object-id pid-123" in missing[0]
    assert '--role "Microsoft Sentinel Responder"' in missing[0]
    assert "workspaces/ws" in missing[0]
    assert "missing declared role" in r.detail
    h.close()


def test_apply_reports_roles_present_and_unverifiable() -> None:
    r = _handler(_Tenant(role_present=True)).apply(_loaded())
    assert "missingRoleAssignments" not in r.extra and r.detail == "declared role assignments present"
    r2 = _handler(_Tenant(roles_status=403)).apply(_loaded())
    assert "could not read role assignments" in r2.detail and r2.verified is True


def test_apply_defaults_to_workspace_rg_and_location_when_not_configured() -> None:
    tenant = _Tenant()
    h = _handler(tenant, playbooks_rg=None, location="northeurope")
    h.apply(_loaded())
    puts = [p for m, p in tenant.calls if m == "PUT"]
    assert all("/resourceGroups/rg/" in p for p in puts)
    assert tenant.bodies[puts[1]]["location"] == "northeurope"


def test_apply_payload_location_overrides_config() -> None:
    tenant = _Tenant()
    _handler(tenant).apply(_loaded(payload=_payload(location="eastus", state="Disabled")))
    wf = [b for p, b in tenant.bodies.items() if "/workflows/" in p][0]
    assert wf["location"] == "eastus" and wf["properties"]["state"] == "Disabled"


def test_apply_connection_failure_aborts_before_workflow_put() -> None:
    tenant = _Tenant(connection_put_status=400)
    r = _handler(tenant).apply(_loaded())
    assert r.status == "error-400" and r.verified is False
    assert "connection 'azuresentinel'" in r.detail
    assert not any(m == "PUT" and "/workflows/" in p for m, p in tenant.calls)


def test_apply_connection_verify_mismatch_aborts() -> None:
    tenant = _Tenant()
    original = tenant.__call__

    def tampered(request: httpx.Request) -> httpx.Response:
        resp = original(request)
        if request.method == "GET" and "/connections/" in request.url.path and resp.status_code == 200:
            body = resp.json()
            body["properties"]["parameterValueType"] = "None"
            return httpx.Response(200, json=body)
        return resp

    h = SentinelPlaybookHandler(lambda: _provider_with(httpx.MockTransport(tampered)))
    r = h.apply(_loaded())
    assert r.status == "error-verify" and "not managed-identity" in r.detail
    assert not any(m == "PUT" and "/workflows/" in p for m, p in tenant.calls)


def test_apply_workflow_412_and_api_error() -> None:
    existing = {"name": "notify-soc", "etag": 'W/"old"', "location": "westeurope",
                "properties": {"definition": _definition(), "state": "Enabled"}}
    tenant = _Tenant(existing_workflow=existing)
    seen: dict = {}
    original = tenant.__call__

    def with_412(request: httpx.Request) -> httpx.Response:
        if request.method == "PUT" and "/workflows/" in request.url.path:
            seen["if_match"] = request.headers.get("If-Match")
            return httpx.Response(412, text="conflict")
        return original(request)

    r = SentinelPlaybookHandler(lambda: _provider_with(httpx.MockTransport(with_412))).apply(_loaded())
    assert r.status == "error-412" and r.error == ETAG_CONFLICT_MESSAGE
    assert seen["if_match"] == 'W/"old"'

    r2 = _handler(_Tenant(workflow_put_status=400)).apply(_loaded())
    assert r2.status == "error-400" and "boom" in r2.detail


def test_apply_update_when_workflow_exists() -> None:
    existing = {"name": "notify-soc", "location": "westeurope",
                "properties": {"definition": _definition(), "state": "Enabled"}}
    r = _handler(_Tenant(existing_workflow=existing)).apply(_loaded())
    assert r.action is PlanAction.UPDATE and r.verified is True


def test_projection_detects_added_action_or_swapped_connector_but_ignores_inputs() -> None:
    def body(definition: dict, conns: dict | None = None) -> dict:
        props = {"definition": definition, "state": "Enabled"}
        if conns is not None:
            props["parameters"] = {"$connections": {"value": conns}}
        return {"location": "westeurope", "identity": {"type": "SystemAssigned"}, "properties": props}

    base = body(_definition(), {"azuresentinel": {"id": "/x/managedApis/azuresentinel"}})
    extra = _definition(); extra["actions"]["Second"] = {"type": "Http", "inputs": {}}
    assert _playbook_projection(base) != _playbook_projection(body(extra, {"azuresentinel": {"id": "/x/managedApis/azuresentinel"}}))
    assert _playbook_projection(base) != _playbook_projection(body(_definition(), {"azuresentinel": {"id": "/x/managedApis/office365"}}))
    mutated = _definition(); mutated["actions"]["Post"]["inputs"]["uri"] = "https://evil.example"
    assert _playbook_projection(base) == _playbook_projection(body(mutated, {"azuresentinel": {"id": "/x/managedApis/azuresentinel"}}))
    # Server-added parameters block with the same connections compares equal.
    assert _playbook_projection(body(_definition(), None)) == _playbook_projection(body(_definition(), {}))


def test_delete_removes_workflow_then_only_tagged_connections() -> None:
    tenant = _Tenant()
    tenant.store["/subscriptions/sub/resourceGroups/rg-pb/providers/Microsoft.Logic/workflows/notify-soc"] = {"name": "notify-soc"}
    tenant.store["/subscriptions/sub/resourceGroups/rg-pb/providers/Microsoft.Web/connections/notify-soc-azuresentinel"] = {"name": "x"}
    tenant.tagged_connections = [{"name": "notify-soc-azuresentinel"}]
    r = _handler(tenant).delete("notify-soc")
    assert r.status == "success" and r.action is PlanAction.DELETE
    deletes = [p for m, p in tenant.calls if m == "DELETE"]
    assert deletes == [
        "/subscriptions/sub/resourceGroups/rg-pb/providers/Microsoft.Logic/workflows/notify-soc",
        "/subscriptions/sub/resourceGroups/rg-pb/providers/Microsoft.Web/connections/notify-soc-azuresentinel",
    ]
    assert "notify-soc-azuresentinel: deleted" in r.detail


def test_list_remote_is_managed_tag_only_and_fetches_each_workflow() -> None:
    tenant = _Tenant()
    tenant.managed_workflows = [{"name": "pb-one"}, {"name": "pb-two"}]
    for n in ("pb-one", "pb-two"):
        tenant.store[f"/subscriptions/sub/resourceGroups/rg-pb/providers/Microsoft.Logic/workflows/{n}"] = {
            "name": n, "tags": {MANAGED_TAG: "true"}, "properties": {"definition": _definition()},
        }
    h = _handler(tenant)
    items = h.list_remote()
    assert {i["name"] for i in items} == {"pb-one", "pb-two"}
    resources_calls = [(m, p) for m, p in tenant.calls if p.endswith("/resources")]
    assert len(resources_calls) == 1
    # The filter asks ARM for tagged Logic Apps only.
    assert not any("/workflows/" in p and m == "GET" and "pb-three" in p for m, p in tenant.calls)


def test_adopt_patches_managed_tag() -> None:
    tenant = _Tenant()
    path = "/subscriptions/sub/resourceGroups/rg-pb/providers/Microsoft.Logic/workflows/legacy"
    tenant.store[path] = {"name": "legacy", "tags": {"team": "soc"}, "properties": {}}
    remote = _handler(tenant).adopt("legacy")
    assert tenant.patched_tags == {"team": "soc", MANAGED_TAG: "true"}
    assert remote["tags"][MANAGED_TAG] == "true"
    assert [m for m, p in tenant.calls if p == path] == ["GET", "PATCH", "GET"]


def test_to_envelope_emits_connections_and_strips_canonical_param_and_server_fields() -> None:
    definition = _definition()
    definition["parameters"] = {"$connections": canonical_connections_param()}
    remote = {
        "id": "/x", "name": "notify-soc", "type": "Microsoft.Logic/workflows", "etag": 'W/"1"',
        "location": "westeurope",
        "identity": {"type": "SystemAssigned", "principalId": "pid", "tenantId": "t"},
        "tags": {MANAGED_TAG: "true", "team": "soc"},
        "properties": {
            "definition": definition, "state": "Enabled", "provisioningState": "Succeeded",
            "createdTime": "2026-01-01T00:00:00Z",
            "parameters": {
                "$connections": {"value": {"azuresentinel": {
                    "connectionId": "/c", "connectionName": "notify-soc-azuresentinel",
                    "id": "/x/managedApis/azuresentinel"}}},
                "webhook": {"value": "https://x"},
            },
        },
    }
    env = SentinelPlaybookHandler(lambda: None).to_envelope(remote)
    assert env is not None
    assert env["id"] == "notify-soc" and env["metadata"] == {"arm_name": "notify-soc"}
    p = env["payload"]
    assert p["connections"] == [{"name": "azuresentinel"}]
    assert p["identity"] == "SystemAssigned" and p["tags"] == {"team": "soc"}
    assert p["parameters"] == {"webhook": {"value": "https://x"}}
    assert "parameters" not in p["definition"]
    assert "createdTime" not in p and "provisioningState" not in p
    stripped = _strip_server_fields(remote)
    assert "principalId" not in stripped["identity"] and "etag" not in stripped
    EnvelopeV2(id=env["id"], version=env["version"], asset=Asset(env["asset"]), status=env["status"])


def test_to_envelope_skips_without_definition_or_with_malformed_connection() -> None:
    h = SentinelPlaybookHandler(lambda: None)
    assert h.to_envelope({"name": "wf", "properties": {}}) is None
    assert h.to_envelope({"name": "wf", "properties": {
        "definition": _definition(),
        "parameters": {"$connections": {"value": {"x": "not-a-dict"}}},
    }}) is None


def test_handler_satisfies_drift_protocol() -> None:
    assert isinstance(SentinelPlaybookHandler(lambda: None), DriftCapable)


def test_list_remote_uses_tag_only_server_filter_and_type_client_side() -> None:
    """ARM returns 400 for `resourceType eq ... and tagName eq ...` in one
    $filter (seen live). The handler sends the tag filter only and drops
    non-workflow summaries itself."""
    tenant = _Tenant()
    tenant.managed_workflows = [{"name": "pb-one"}]
    tenant.store["/subscriptions/sub/resourceGroups/rg-pb/providers/Microsoft.Logic/workflows/pb-one"] = {
        "name": "pb-one", "tags": {MANAGED_TAG: "true"}, "properties": {"definition": _definition()},
    }
    original = tenant.__call__
    seen: dict = {}

    def capture(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/resources"):
            seen["filter"] = request.url.params.get("$filter", "")
            flt = seen["filter"]
            return httpx.Response(200, json={"value": [
                {"name": "pb-one", "type": "Microsoft.Logic/workflows", "tags": {MANAGED_TAG: "true"}},
                {"name": "pb-one-azuresentinel", "type": "Microsoft.Web/connections", "tags": {MANAGED_TAG: "true"}},
            ]}) if "resourceType" not in flt else httpx.Response(400, text="InvalidFilter")
        return original(request)

    h = SentinelPlaybookHandler(lambda: _provider_with(httpx.MockTransport(capture)))
    items = h.list_remote()
    assert "resourceType" not in seen["filter"]
    assert f"tagName eq '{MANAGED_TAG}'" in seen["filter"]
    assert [i["name"] for i in items] == ["pb-one"]
