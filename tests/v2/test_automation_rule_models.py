# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Payload model + ARM body builder for ``sentinel_automation_rule``."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from contentops.handlers.sentinel_automation_rule_models import (
    SentinelAutomationRulePayload,
    analytic_arm_name_from_resource_id,
    analytic_refs,
    closes_incidents,
    envelope_id_to_guid,
    is_expired,
    normalize_expiration,
    playbook_id_from_resource_id,
    playbook_refs,
    to_automation_rule_arm_body,
)


def _future() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _payload(**overrides) -> dict:
    base = {
        "displayName": "Auto-close informational",
        "order": 1,
        "triggeringLogic": {
            "isEnabled": True,
            "triggersOn": "Incidents",
            "triggersWhen": "Created",
            "conditions": [],
        },
        "actions": [
            {"order": 1, "actionType": "ModifyProperties",
             "actionConfiguration": {"severity": "Informational"}},
        ],
    }
    base.update(overrides)
    return base


def _scoped_close(**overrides) -> dict:
    actions = overrides.pop("actions", None) or [{
        "order": 1, "actionType": "ModifyProperties",
        "actionConfiguration": {
            "status": "Closed", "classification": "BenignPositive",
            "classificationReason": "SuspiciousButExpected",
            "classificationComment": "approved",
        },
    }]
    return _payload(
        actions=actions,
        triggeringLogic={
            "isEnabled": True, "triggersOn": "Incidents", "triggersWhen": "Created",
            "expirationTimeUtc": _future(),
            "conditions": [{
                "conditionType": "Property",
                "conditionProperties": {
                    "propertyName": "IncidentRelatedAnalyticRuleIds",
                    "operator": "Contains",
                    "propertyValues": ["analytic:my-rule"],
                },
            }],
        },
        **overrides,
    )


def test_minimal_modify_properties_accepted() -> None:
    SentinelAutomationRulePayload(**_payload())


@pytest.mark.parametrize("order", [0, 1001])
def test_order_out_of_range_rejected(order: int) -> None:
    with pytest.raises(ValidationError):
        SentinelAutomationRulePayload(**_payload(order=order))


def test_display_name_over_500_rejected() -> None:
    with pytest.raises(ValidationError):
        SentinelAutomationRulePayload(**_payload(displayName="x" * 501))


def test_unparseable_expiration_rejected_but_past_is_accepted() -> None:
    with pytest.raises(ValidationError, match="expirationTimeUtc"):
        SentinelAutomationRulePayload(**_payload(triggeringLogic={
            "expirationTimeUtc": "next tuesday", "conditions": [],
        }))
    # Past values must still parse: collected expired rules land as deprecated.
    SentinelAutomationRulePayload(**_payload(triggeringLogic={
        "expirationTimeUtc": "2020-01-01T00:00:00Z", "conditions": [],
    }))
    assert is_expired("2020-01-01T00:00:00Z")
    assert not is_expired(_future())


def test_expiration_is_normalised_to_seconds_z() -> None:
    assert normalize_expiration("2026-12-31T23:59:59.000+00:00") == "2026-12-31T23:59:59Z"
    assert normalize_expiration("2026-12-31T23:59:59Z") == "2026-12-31T23:59:59Z"
    assert normalize_expiration(None) is None


def test_alert_trigger_requires_created_and_only_run_playbook() -> None:
    with pytest.raises(ValidationError, match="triggersWhen: Created"):
        SentinelAutomationRulePayload(**_payload(triggeringLogic={
            "triggersOn": "Alerts", "triggersWhen": "Updated", "conditions": [],
        }))
    with pytest.raises(ValidationError, match="only run playbooks"):
        SentinelAutomationRulePayload(**_payload(triggeringLogic={
            "triggersOn": "Alerts", "triggersWhen": "Created", "conditions": [],
        }))


def test_run_playbook_requires_exactly_one_of_playbook_or_resource_id() -> None:
    def _with(cfg: dict) -> dict:
        return _payload(actions=[{"order": 1, "actionType": "RunPlaybook", "actionConfiguration": cfg}])

    with pytest.raises(ValidationError, match="exactly one"):
        SentinelAutomationRulePayload(**_with({}))
    with pytest.raises(ValidationError, match="exactly one"):
        SentinelAutomationRulePayload(**_with({
            "playbook": "x", "logicAppResourceId": "/subscriptions/s/resourceGroups/r/providers/Microsoft.Logic/workflows/x",
        }))
    with pytest.raises(ValidationError, match="not a Microsoft.Logic"):
        SentinelAutomationRulePayload(**_with({"logicAppResourceId": "/subscriptions/s/nope"}))
    SentinelAutomationRulePayload(**_with({"playbook": "notify-soc"}))
    SentinelAutomationRulePayload(**_with({
        "logicAppResourceId": "/subscriptions/s/resourceGroups/r/providers/Microsoft.Logic/workflows/x",
    }))


def test_closed_status_requires_classification_and_vice_versa() -> None:
    with pytest.raises(ValidationError, match="classification"):
        SentinelAutomationRulePayload(**_payload(
            triggeringLogic={"conditions": [{"conditionType": "Property", "conditionProperties": {}}]},
            actions=[{"order": 1, "actionType": "ModifyProperties",
                      "actionConfiguration": {"status": "Closed"}}],
        ))
    with pytest.raises(ValidationError, match="status: Closed"):
        SentinelAutomationRulePayload(**_payload(actions=[{
            "order": 1, "actionType": "ModifyProperties",
            "actionConfiguration": {"classification": "BenignPositive"},
        }]))


def test_duplicate_action_order_rejected() -> None:
    with pytest.raises(ValidationError, match="unique"):
        SentinelAutomationRulePayload(**_payload(actions=[
            {"order": 1, "actionType": "AddIncidentTask", "actionConfiguration": {"title": "a"}},
            {"order": 1, "actionType": "AddIncidentTask", "actionConfiguration": {"title": "b"}},
        ]))


def test_close_action_with_zero_conditions_is_refused() -> None:
    """The blast-radius guard: a close rule with no conditions would
    auto-close every incident in the workspace."""
    bad = _scoped_close()
    bad["triggeringLogic"]["conditions"] = []
    with pytest.raises(ValidationError, match="every incident"):
        SentinelAutomationRulePayload(**bad)
    assert closes_incidents(bad)
    assert not closes_incidents(_payload())


def test_scoped_close_rule_is_a_valid_suppression() -> None:
    SentinelAutomationRulePayload(**_scoped_close())


def test_to_arm_body_resolves_both_sugars_and_normalises_expiry() -> None:
    payload = _scoped_close(actions=[
        {"order": 1, "actionType": "RunPlaybook",
         "actionConfiguration": {"playbook": "notify-soc"}},
    ])
    payload["triggeringLogic"]["expirationTimeUtc"] = "2026-12-31T23:59:59+00:00"

    body = to_automation_rule_arm_body(
        payload,
        resolve_playbook=lambda pid: (f"/subscriptions/s/resourceGroups/rg-pb/providers/Microsoft.Logic/workflows/{pid}", "tenant-guid"),
        resolve_analytic=lambda aid: f"/ws/providers/Microsoft.SecurityInsights/alertRules/{aid}-arm",
    )
    props = body["properties"]
    assert props["triggeringLogic"]["expirationTimeUtc"] == "2026-12-31T23:59:59Z"
    cond = props["triggeringLogic"]["conditions"][0]["conditionProperties"]
    assert cond["propertyValues"] == ["/ws/providers/Microsoft.SecurityInsights/alertRules/my-rule-arm"]
    cfg = props["actions"][0]["actionConfiguration"]
    assert "playbook" not in cfg
    assert cfg["logicAppResourceId"].endswith("/workflows/notify-soc")
    assert cfg["tenantId"] == "tenant-guid"
    # The input payload is not mutated (the envelope on disk keeps its sugar).
    assert payload["actions"][0]["actionConfiguration"] == {"playbook": "notify-soc"}


def test_to_arm_body_keeps_raw_ids_untouched() -> None:
    raw_id = "/subscriptions/other/resourceGroups/x/providers/Microsoft.Logic/workflows/foreign"
    payload = _payload(actions=[{
        "order": 1, "actionType": "RunPlaybook",
        "actionConfiguration": {"logicAppResourceId": raw_id, "tenantId": "t"},
    }])
    body = to_automation_rule_arm_body(
        payload, resolve_playbook=lambda _: (_ for _ in ()).throw(AssertionError("not called")),
        resolve_analytic=lambda _: (_ for _ in ()).throw(AssertionError("not called")),
    )
    assert body["properties"]["actions"][0]["actionConfiguration"] == {
        "logicAppResourceId": raw_id, "tenantId": "t",
    }


def test_reference_extractors() -> None:
    payload = _scoped_close(actions=[
        {"order": 1, "actionType": "RunPlaybook", "actionConfiguration": {"playbook": "a"}},
        {"order": 2, "actionType": "RunPlaybook",
         "actionConfiguration": {"logicAppResourceId": "/subscriptions/s/resourceGroups/r/providers/Microsoft.Logic/workflows/b"}},
    ])
    assert playbook_refs(payload) == ["a"]
    assert analytic_refs(payload) == ["my-rule"]


def test_envelope_id_to_guid_is_deterministic() -> None:
    a = envelope_id_to_guid("auto-close-info")
    assert a == envelope_id_to_guid("auto-close-info")
    assert a != envelope_id_to_guid("different-id")
    assert len(a.split("-")) == 5


def test_playbook_id_from_resource_id_matches_case_insensitively_and_rejects_other_rg() -> None:
    rid = "/subscriptions/SUB/resourceGroups/RG-PB/providers/Microsoft.Logic/workflows/Notify_SOC"
    assert playbook_id_from_resource_id(rid, subscription_id="sub", resource_group="rg-pb") == "notify-soc"
    assert playbook_id_from_resource_id(rid, subscription_id="sub", resource_group="other") is None
    assert playbook_id_from_resource_id("/nope", subscription_id="sub", resource_group="rg-pb") is None


def test_analytic_arm_name_from_resource_id() -> None:
    ws = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
    rid = f"{ws}/providers/Microsoft.SecurityInsights/alertRules/1840b991"
    assert analytic_arm_name_from_resource_id(rid, workspace_path=ws) == "1840b991"
    assert analytic_arm_name_from_resource_id(rid.upper(), workspace_path=ws) == "1840B991"
    assert analytic_arm_name_from_resource_id(rid, workspace_path="/other") is None
