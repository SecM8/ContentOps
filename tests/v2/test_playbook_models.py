# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Payload model, ARM body builders and sidecar split for ``sentinel_playbook``."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from contentops.handlers.sentinel_playbook_models import (
    MANAGED_TAG,
    PLAYBOOK_TAG,
    PlaybookConnection,
    RoleAssignmentDecl,
    SentinelPlaybookPayload,
    canonical_connections_param,
    connection_arm_name,
    connections_from_remote,
    is_managed_workflow,
    referenced_connection_names,
    split_sidecars,
    to_connection_arm_body,
    to_workflow_arm_body,
)

_SENTINEL_REF = "@parameters('$connections')['azuresentinel']['connectionId']"


def _definition(**extra) -> dict:
    d = {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "triggers": {"When_incident_created": {
            "type": "ApiConnectionWebhook",
            "inputs": {"host": {"connection": {"name": _SENTINEL_REF}}, "path": "/incident-creation"},
        }},
        "actions": {"Post": {"type": "Http", "inputs": {"method": "POST", "uri": "https://hooks.example.com"}}},
    }
    d.update(extra)
    return d


def _payload(**overrides) -> dict:
    base = {
        "connections": [{"name": "azuresentinel"}],
        "definition": _definition(),
    }
    base.update(overrides)
    return base


def test_connection_defaults_api_name_and_auth_mode_from_table() -> None:
    c = PlaybookConnection(name="azuresentinel")
    assert c.effective_api_name == "azuresentinel"
    assert c.effective_auth_mode == "alternative"
    c2 = PlaybookConnection(name="logs", apiName="azuremonitorlogs")
    assert c2.effective_auth_mode == "parameterValueSet"


def test_oauth_only_connector_rejected() -> None:
    with pytest.raises(ValidationError, match="interactive OAuth consent"):
        PlaybookConnection(name="office365")


def test_unknown_connector_requires_explicit_auth_mode() -> None:
    with pytest.raises(ValidationError, match="authMode"):
        PlaybookConnection(name="myconnector")
    PlaybookConnection(name="myconnector", authMode="parameterValueSet")


def test_definition_reference_to_undeclared_connection_rejected() -> None:
    with pytest.raises(ValidationError, match="not\n?.*declared|not declared"):
        SentinelPlaybookPayload(**_payload(connections=[]))


def test_parameters_may_not_contain_connections_key() -> None:
    with pytest.raises(ValidationError, match=r"\$connections"):
        SentinelPlaybookPayload(**_payload(parameters={"$connections": {"value": {}}}))


def test_definition_required_and_must_have_triggers_and_actions() -> None:
    with pytest.raises(ValidationError, match="definitionFile"):
        SentinelPlaybookPayload(connections=[])
    with pytest.raises(ValidationError, match="not inlined"):
        SentinelPlaybookPayload(definitionFile="x.workflow.json")
    with pytest.raises(ValidationError, match="definition.actions"):
        SentinelPlaybookPayload(definition={"triggers": {}, "actions": "no"})


def test_definition_file_must_be_bare_name() -> None:
    with pytest.raises(ValidationError, match="bare file name"):
        SentinelPlaybookPayload(definition=_definition(), connections=[{"name": "azuresentinel"}],
                                definitionFile="../x.workflow.json")


def test_connection_names_unique() -> None:
    with pytest.raises(ValidationError, match="unique"):
        SentinelPlaybookPayload(**_payload(connections=[{"name": "azuresentinel"}, {"name": "azuresentinel"}]))


def test_role_assignment_declaration() -> None:
    r = RoleAssignmentDecl(role="Microsoft Sentinel Responder")
    assert r.scope == "workspace"
    assert r.role_definition_id == "3e150937-b8fe-4cfb-8069-0eaf05ecd056"
    g = RoleAssignmentDecl(role="3E150937-B8FE-4CFB-8069-0EAF05ECD056", scope="/subscriptions/s/resourceGroups/r")
    assert g.role_definition_id == "3e150937-b8fe-4cfb-8069-0eaf05ecd056"
    with pytest.raises(ValidationError, match="unknown role"):
        RoleAssignmentDecl(role="Owner Of Everything")
    with pytest.raises(ValidationError, match="scope"):
        RoleAssignmentDecl(role="Reader", scope="everywhere")


def test_referenced_connection_names_dedupes() -> None:
    assert referenced_connection_names(_definition()) == ["azuresentinel"]


def test_connection_arm_name_default_and_override() -> None:
    assert connection_arm_name("notify-soc", PlaybookConnection(name="azuresentinel")) == "notify-soc-azuresentinel"
    assert connection_arm_name("notify-soc", PlaybookConnection(name="azuresentinel", connectionName="shared")) == "shared"


def test_connection_body_alternative_vs_parameter_value_set() -> None:
    alt = to_connection_arm_body(
        PlaybookConnection(name="azuresentinel"), envelope_id="pb", location="westeurope", subscription_id="sub",
    )
    assert alt["kind"] == "V1"
    assert alt["tags"] == {MANAGED_TAG: "true", PLAYBOOK_TAG: "pb"}
    assert alt["properties"]["parameterValueType"] == "Alternative"
    assert alt["properties"]["api"]["id"] == "/subscriptions/sub/providers/Microsoft.Web/locations/westeurope/managedApis/azuresentinel"
    pvs = to_connection_arm_body(
        PlaybookConnection(name="kv", apiName="keyvault"), envelope_id="pb", location="westeurope", subscription_id="sub",
    )
    assert pvs["properties"]["parameterValueSet"] == {"name": "managedIdentityAuth", "values": {}}
    assert "parameterValueType" not in pvs["properties"]


def test_workflow_body_rewrites_connections_and_injects_parameter_declaration() -> None:
    payload = SentinelPlaybookPayload(**_payload(parameters={"webhook": {"value": "https://x"}}, tags={"team": "soc"}))
    refs = {"azuresentinel": {"connectionId": "/c/1", "connectionName": "pb-azuresentinel", "id": "/api/azuresentinel"}}
    body = to_workflow_arm_body(payload, location="westeurope", connection_refs=refs)
    assert body["identity"] == {"type": "SystemAssigned"}
    assert body["tags"] == {"team": "soc", MANAGED_TAG: "true"}
    assert body["properties"]["state"] == "Enabled"
    assert body["properties"]["parameters"]["$connections"] == {"value": refs}
    assert body["properties"]["parameters"]["webhook"] == {"value": "https://x"}
    assert body["properties"]["definition"]["parameters"]["$connections"] == canonical_connections_param()
    # Input payload definition is untouched.
    assert "parameters" not in payload.definition


def test_is_managed_workflow_by_tag() -> None:
    assert is_managed_workflow({"tags": {MANAGED_TAG: "true"}})
    assert not is_managed_workflow({"tags": {}})
    assert not is_managed_workflow({})


def test_connections_from_remote_round_trips_defaults() -> None:
    remote = {"name": "pb", "properties": {"parameters": {"$connections": {"value": {
        "azuresentinel": {"connectionId": "/c", "connectionName": "pb-azuresentinel", "id": "/x/managedApis/azuresentinel"},
        "logs": {"connectionId": "/c2", "connectionName": "custom-name", "id": "/x/managedApis/azuremonitorlogs"},
    }}}}}
    assert connections_from_remote(remote) == [
        {"name": "azuresentinel"},
        {"name": "logs", "apiName": "azuremonitorlogs", "connectionName": "custom-name"},
    ]
    assert connections_from_remote({"name": "pb", "properties": {}}) == []
    assert connections_from_remote({"name": "pb", "properties": {"parameters": {"$connections": {"value": {"x": "bad"}}}}}) is None


def test_split_sidecars_moves_definition_to_stable_json() -> None:
    env = {"id": "pb", "asset": "sentinel_playbook", "payload": {"state": "Enabled", "definition": _definition()}}
    on_disk, files = split_sidecars(env)
    assert on_disk["payload"]["definitionFile"] == "pb.workflow.json"
    assert "definition" not in on_disk["payload"]
    assert list(files) == ["pb.workflow.json"]
    text = files["pb.workflow.json"]
    assert text.endswith("\n")
    assert json.loads(text) == _definition()
    # keys sorted for stable diffs
    assert text == json.dumps(_definition(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    # idempotent on the on-disk form
    again, files2 = split_sidecars(on_disk)
    assert again == on_disk and files2 == {}
