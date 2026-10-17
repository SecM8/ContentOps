# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""PAYLOAD007-014 support-asset lint rules + the META filter for support kinds."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from contentops.lint.runner import lint_assets

_FUTURE = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
_SENTINEL_REF = "@parameters('$connections')['azuresentinel']['connectionId']"


def _write(root: Path, kind: str, env_id: str, payload: dict, *, metadata: dict | None = None) -> Path:
    d = root / kind
    d.mkdir(parents=True, exist_ok=True)
    doc = {
        "id": env_id, "version": "1.0.0", "asset": kind, "status": "production",
        "metadata": metadata or {
            "owner": "soc@example.com", "runbookUrl": "https://wiki/x",
            "description": "d", "lastValidatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        },
        "payload": payload,
    }
    p = d / f"{env_id}.yml"
    p.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return p


def _rule(order: int = 1, *, conditions: list | None = None, actions: list | None = None,
          expiry: str | None = None, trigger: tuple[str, str] = ("Incidents", "Created")) -> dict:
    logic = {"isEnabled": True, "triggersOn": trigger[0], "triggersWhen": trigger[1],
             "conditions": conditions if conditions is not None else [{
                 "conditionType": "Property",
                 "conditionProperties": {"propertyName": "IncidentSeverity", "operator": "Equals",
                                         "propertyValues": ["Low"]},
             }]}
    if expiry:
        logic["expirationTimeUtc"] = expiry
    return {
        "displayName": f"rule {order}", "order": order, "triggeringLogic": logic,
        "actions": actions or [{"order": 1, "actionType": "ModifyProperties",
                                "actionConfiguration": {"severity": "Low"}}],
    }


def _findings(root: Path, path: Path) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for lf in lint_assets(root):
        if lf.path == path:
            for f in lf.findings:
                out.setdefault(f.rule_id, []).append(f.severity)
    return out


def test_payload007_dangling_playbook_and_analytic_references(tmp_path: Path) -> None:
    p = _write(tmp_path, "sentinel_automation_rule", "r1", _rule(
        conditions=[{"conditionType": "Property", "conditionProperties": {
            "propertyName": "IncidentRelatedAnalyticRuleIds", "operator": "Contains",
            "propertyValues": ["analytic:missing-rule"]}}],
        actions=[{"order": 1, "actionType": "RunPlaybook", "actionConfiguration": {"playbook": "missing-pb"}}],
    ))
    f = _findings(tmp_path, p)
    assert f["PAYLOAD007"] == ["error", "error"]


def test_payload007_silent_when_references_resolve(tmp_path: Path) -> None:
    _write(tmp_path, "sentinel_analytic", "my-rule", {"displayName": "x", "kind": "Scheduled", "query": "SecurityEvent | take 1"},
           metadata={"owner": "a@b.co", "runbookUrl": "https://w", "severity": "low", "tactics": ["Execution"],
                     "techniques": [], "expectedAlertsPerDay": 1, "fpHandling": "x"})
    d = tmp_path / "sentinel_playbook"; d.mkdir()
    (d / "pb.workflow.json").write_text(json.dumps({"triggers": {"t": {"type": "Request"}}, "actions": {}}), encoding="utf-8")
    _write(tmp_path, "sentinel_playbook", "pb", {"definitionFile": "pb.workflow.json", "connections": []})
    p = _write(tmp_path, "sentinel_automation_rule", "r1", _rule(
        conditions=[{"conditionType": "Property", "conditionProperties": {
            "propertyName": "IncidentRelatedAnalyticRuleIds", "operator": "Contains",
            "propertyValues": ["analytic:my-rule"]}}],
        actions=[{"order": 1, "actionType": "RunPlaybook", "actionConfiguration": {"playbook": "pb"}}],
    ))
    assert "PAYLOAD007" not in _findings(tmp_path, p)


def test_payload008_expired_rule_warns(tmp_path: Path) -> None:
    p = _write(tmp_path, "sentinel_automation_rule", "r1", _rule(expiry="2020-01-01T00:00:00Z"))
    assert _findings(tmp_path, p)["PAYLOAD008"] == ["warning"]
    p2 = _write(tmp_path, "sentinel_automation_rule", "r2", _rule(order=2, expiry=_FUTURE))
    assert "PAYLOAD008" not in _findings(tmp_path, p2)


def test_payload009_duplicate_order_same_trigger_only(tmp_path: Path) -> None:
    a = _write(tmp_path, "sentinel_automation_rule", "rule-a", _rule(order=5))
    b = _write(tmp_path, "sentinel_automation_rule", "rule-b", _rule(order=5))
    c = _write(tmp_path, "sentinel_automation_rule", "rule-c", _rule(order=5, trigger=("Incidents", "Updated")))
    assert _findings(tmp_path, a)["PAYLOAD009"] == ["warning"]
    assert _findings(tmp_path, b)["PAYLOAD009"] == ["warning"]
    assert "PAYLOAD009" not in _findings(tmp_path, c)


def test_payload014_close_without_conditions_is_error_and_unscoped_is_warning(tmp_path: Path) -> None:
    close = {"order": 1, "actionType": "ModifyProperties",
             "actionConfiguration": {"status": "Closed", "classification": "BenignPositive"}}
    # No conditions: the envelope still parses (lint reads raw payload),
    # the handler's validate refuses it, lint reports an error.
    p = _write(tmp_path, "sentinel_automation_rule", "r1", _rule(conditions=[], actions=[close]))
    assert _findings(tmp_path, p)["PAYLOAD014"] == ["error"]
    # Entity-scoped but not analytics-scoped: warning.
    p2 = _write(tmp_path, "sentinel_automation_rule", "r2", _rule(order=2, actions=[close]))
    assert _findings(tmp_path, p2)["PAYLOAD014"] == ["warning"]
    # Analytics-scoped: silent.
    p3 = _write(tmp_path, "sentinel_automation_rule", "r3", _rule(order=3, actions=[close], conditions=[{
        "conditionType": "Property", "conditionProperties": {
            "propertyName": "IncidentRelatedAnalyticRuleIds", "operator": "Contains",
            "propertyValues": ["/subscriptions/x/alertRules/y"]}}]))
    assert "PAYLOAD014" not in _findings(tmp_path, p3)


def _playbook(tmp_path: Path, env_id: str, payload: dict) -> Path:
    d = tmp_path / "sentinel_playbook"; d.mkdir(parents=True, exist_ok=True)
    (d / f"{env_id}.workflow.json").write_text(json.dumps({
        "triggers": {"t": {"type": "ApiConnectionWebhook", "inputs": {"host": {"connection": {"name": _SENTINEL_REF}}}}},
        "actions": {},
    }), encoding="utf-8")
    return _write(tmp_path, "sentinel_playbook", env_id, {"definitionFile": f"{env_id}.workflow.json", **payload})


def test_payload010_and_012_for_playbooks(tmp_path: Path) -> None:
    p = _playbook(tmp_path, "pb", {"connections": [
        {"name": "azuresentinel"},
        {"name": "custom", "apiName": "somevendor", "authMode": "parameterValueSet"},
    ]})
    f = _findings(tmp_path, p)
    assert f["PAYLOAD010"] == ["warning"]
    assert f["PAYLOAD012"] == ["warning"]
    p2 = _playbook(tmp_path, "pb2", {"connections": [{"name": "azuresentinel"}],
                                     "roleAssignments": [{"role": "Microsoft Sentinel Responder"}]})
    f2 = _findings(tmp_path, p2)
    assert "PAYLOAD012" not in f2 and "PAYLOAD010" not in f2


def test_support_kinds_only_get_the_reduced_meta_rule_set(tmp_path: Path) -> None:
    """META003-007/009 (attack narrative, FP catalogue, ...) must not fire
    on automation rules / playbooks; META001/002/008 still do."""
    p = _write(tmp_path, "sentinel_automation_rule", "r1", _rule(),
               metadata={"owner": "soc@example.com", "runbookUrl": "https://wiki/x"})
    f = _findings(tmp_path, p)
    assert "META001" in f and "META002" in f
    for rid in ("META003", "META004", "META005", "META006", "META007", "META009"):
        assert rid not in f, rid


def test_no_kql_rules_run_on_support_kinds(tmp_path: Path) -> None:
    p = _write(tmp_path, "sentinel_automation_rule", "r1", _rule())
    f = _findings(tmp_path, p)
    assert not any(k.startswith("KQL") for k in f)
