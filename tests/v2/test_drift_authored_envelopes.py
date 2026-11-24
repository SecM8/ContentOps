# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Drift against objects that were authored in the repo and deployed.

A collected file holds everything the tenant returns, so it compares
field for field. A file written with ``contentops new`` holds what its
author declared: it leaves service defaults to the service, and it
carries fields a deploy sends that the tenant never returns (a
watchlist's CSV). Seen in a deployment repo right after a successful
deploy: every authored object was reported as changed, and importing
the report would have emptied the watchlist and marked the disabled
analytic deprecated.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from contentops.core.asset import Asset
from contentops.core.drift import detect_drift, write_drift
from contentops.handlers.sentinel_automation_rule_models import envelope_id_to_guid


class _Tenant:
    """A drift handler whose tenant holds exactly the given objects."""

    def __init__(self, asset: Asset, remotes: list[tuple[dict, dict]]) -> None:
        self.asset = asset
        self._remotes = remotes

    def list_remote(self) -> list[dict]:
        return [r for r, _ in self._remotes]

    def to_envelope(self, remote: dict) -> dict | None:
        return next(dict(e) for r, e in self._remotes if r is remote)


def _write(root: Path, asset: Asset, env_id: str, payload: dict, **top) -> Path:
    d = root / asset.value
    d.mkdir(parents=True, exist_ok=True)
    doc = {"id": env_id, "version": "0.1.0", "asset": asset.value, "status": "production",
           **top, "metadata": {"owner": "soc@example.com"}, "payload": payload}
    p = d / f"{env_id}.yml"
    p.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return p


def _collected(env_id: str, asset: Asset, payload: dict, *, name: str | None = None,
               status: str = "production") -> tuple[dict, dict]:
    remote = {"name": name or env_id}
    envelope = {"id": env_id, "version": "1.0.0", "asset": asset.value, "status": status,
                "metadata": {"arm_name": name or env_id}, "payload": payload}
    return remote, envelope


_WATCHLIST_FILE = {
    "displayName": "zz watchlist", "provider": "Custom", "source": "Local file",
    "contentType": "text/csv", "itemsSearchKey": "AssetName", "numberOfLinesToSkip": 0,
    "rawContent": "AssetName,Tier\nexample-asset,1\n",
}
_WATCHLIST_SERVED = {
    "displayName": "zz watchlist", "provider": "Custom", "source": "Local file",
    "sourceType": "Local", "itemsSearchKey": "AssetName", "labels": [],
    "watchlistCategory": "General", "watchlistKind": "Regular", "watchlistType": "watchlist",
}


def test_an_authored_watchlist_is_in_sync_with_what_the_tenant_serves(tmp_path: Path) -> None:
    _write(tmp_path, Asset.SENTINEL_WATCHLIST, "wl", _WATCHLIST_FILE)
    tenant = _Tenant(Asset.SENTINEL_WATCHLIST, [_collected("wl", Asset.SENTINEL_WATCHLIST, _WATCHLIST_SERVED)])
    report = detect_drift([tenant], tmp_path)
    assert [e.kind for e in report.entries] == ["in-sync"]


def test_a_real_change_to_an_authored_watchlist_is_still_drift(tmp_path: Path) -> None:
    _write(tmp_path, Asset.SENTINEL_WATCHLIST, "wl", _WATCHLIST_FILE)
    served = {**_WATCHLIST_SERVED, "displayName": "renamed in the portal"}
    tenant = _Tenant(Asset.SENTINEL_WATCHLIST, [_collected("wl", Asset.SENTINEL_WATCHLIST, served)])
    report = detect_drift([tenant], tmp_path)
    assert [e.kind for e in report.entries] == ["changed"]


def test_importing_a_watchlist_change_keeps_its_content_and_authored_fields(tmp_path: Path) -> None:
    path = _write(tmp_path, Asset.SENTINEL_WATCHLIST, "wl", _WATCHLIST_FILE,
                  lifecycleStage="concept", legacy=False)
    served = {**_WATCHLIST_SERVED, "displayName": "renamed in the portal"}
    tenant = _Tenant(Asset.SENTINEL_WATCHLIST, [_collected("wl", Asset.SENTINEL_WATCHLIST, served)])
    write_drift(detect_drift([tenant], tmp_path), tmp_path)
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert doc["payload"]["displayName"] == "renamed in the portal"
    assert doc["payload"]["rawContent"].rstrip("\n") == _WATCHLIST_FILE["rawContent"].rstrip("\n")
    assert doc["payload"]["contentType"] == "text/csv"
    assert doc["lifecycleStage"] == "concept" and doc["legacy"] is False
    # Imported back, the file is in sync.
    assert [e.kind for e in detect_drift([tenant], tmp_path).entries] == ["in-sync"]


def test_an_empty_value_and_an_absent_key_are_the_same(tmp_path: Path) -> None:
    _write(tmp_path, Asset.SENTINEL_PARSER, "zz-parser", {
        "displayName": "p", "category": "Function", "functionAlias": "p",
        "functionParameters": "", "query": "T | take 1",
    })
    served = {"displayName": "p", "category": "Function", "functionAlias": "p",
              "query": "T | take 1", "tags": [], "description": None}
    tenant = _Tenant(Asset.SENTINEL_PARSER, [_collected("zz-parser", Asset.SENTINEL_PARSER, served)])
    assert [e.kind for e in detect_drift([tenant], tmp_path).entries] == ["in-sync"]


def test_service_defaults_of_an_analytic_and_a_playbook_are_not_drift(tmp_path: Path) -> None:
    _write(tmp_path, Asset.SENTINEL_ANALYTIC, "zz-analytic", {
        "displayName": "a", "kind": "Scheduled", "enabled": False, "query": "T", "severity": "Low",
    })
    _write(tmp_path, Asset.SENTINEL_PLAYBOOK, "pb", {
        "state": "Enabled", "parameters": {},
        "roleAssignments": [{"role": "Microsoft Sentinel Responder", "scope": "workspace"}],
        "definition": {"triggers": {}, "actions": {}, "parameters": {}},
    })
    analytic = _Tenant(Asset.SENTINEL_ANALYTIC, [_collected("zz-analytic", Asset.SENTINEL_ANALYTIC, {
        "displayName": "a", "kind": "Scheduled", "enabled": False, "query": "T", "severity": "Low",
        "incidentConfiguration": {"createIncident": True,
                                  "groupingConfiguration": {"enabled": False}},
        "subTechniques": None,
    })])
    playbook = _Tenant(Asset.SENTINEL_PLAYBOOK, [_collected("pb", Asset.SENTINEL_PLAYBOOK, {
        "state": "Enabled", "identity": "SystemAssigned", "location": "westeurope",
        "definition": {"triggers": {}, "actions": {}},
    })])
    report = detect_drift([analytic, playbook], tmp_path)
    assert [e.kind for e in report.entries] == ["in-sync", "in-sync"]


def test_importing_keeps_the_status_of_a_rule_deployed_disabled(tmp_path: Path) -> None:
    """A rule authored as ``status: production`` with ``enabled: false``
    is collected as ``deprecated`` (the tenant only knows it is off).
    Importing an unrelated change must not retire it."""
    path = _write(tmp_path, Asset.SENTINEL_ANALYTIC, "zz-analytic", {
        "displayName": "a", "kind": "Scheduled", "enabled": False, "query": "T", "severity": "Low",
    })
    tenant = _Tenant(Asset.SENTINEL_ANALYTIC, [_collected("zz-analytic", Asset.SENTINEL_ANALYTIC, {
        "displayName": "a", "kind": "Scheduled", "enabled": False, "query": "T", "severity": "High",
    }, status="deprecated")])
    write_drift(detect_drift([tenant], tmp_path), tmp_path)
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert doc["payload"]["severity"] == "High"
    assert doc["status"] == "production"


def test_a_deprecated_analytic_is_compared_as_switched_off(tmp_path: Path) -> None:
    """Deploy switches a ``deprecated`` analytic off whatever its payload
    says (emergency disable only flips the status). The tenant then
    reports ``enabled: false``, which is what the repo asked for; drift
    reported it as a change. A production rule that is off is still one."""
    payload = {"displayName": "zz", "kind": "Scheduled", "enabled": True, "query": "T", "severity": "Low"}
    _write(tmp_path, Asset.SENTINEL_ANALYTIC, "zz-retired", payload, status="deprecated")
    _write(tmp_path, Asset.SENTINEL_ANALYTIC, "zz-live", payload)
    served = {**payload, "enabled": False}
    tenant = _Tenant(Asset.SENTINEL_ANALYTIC, [
        _collected("zz-retired", Asset.SENTINEL_ANALYTIC, served, status="deprecated"),
        _collected("zz-live", Asset.SENTINEL_ANALYTIC, served, status="deprecated"),
    ])
    kinds = {e.asset_id: e.kind for e in detect_drift([tenant], tmp_path).entries}
    assert kinds == {"zz-retired": "in-sync", "zz-live": "changed"}


def test_old_defender_keys_the_tenant_mirrors_are_not_drift(tmp_path: Path) -> None:
    """Graph returns every rule with the deprecated keys filled in next to
    the current ones (``scopeNames`` / ``scopeType`` next to
    ``deviceGroups``, ``responseActions`` next to ``automatedActions``).
    A file that holds the current keys only was reported as changed right
    after a verified deploy. Seen against a tenant. Both sides are now
    compared in the current shape; a real change still is drift."""
    payload = {
        "displayName": "zz rule", "status": "disabled",
        "queryCondition": {"queryText": "DeviceProcessEvents | take 1"},
        "schedule": {"frequency": "PT1H"},
        "detectionAction": {
            "organizationalScope": {"deviceGroups": ["group-a"]},
            "automatedActions": {"runAntivirusScans": [{"deviceIdColumn": "DeviceId"}]},
        },
    }
    served = {
        **payload,
        "schedule": {"frequency": "PT1H", "period": "1H"},
        "detectionAction": {
            "organizationalScope": {"deviceGroups": ["group-a"], "scopeType": "deviceGroup",
                                    "scopeNames": ["group-a"]},
            "automatedActions": {"runAntivirusScans": [{"deviceIdColumn": "DeviceId"}]},
            "responseActions": [{"@odata.type": "#microsoft.graph.security.runAntivirusScanResponseAction",
                                 "identifier": "deviceId"}],
        },
    }
    _write(tmp_path, Asset.DEFENDER_CUSTOM_DETECTION, "zz-rule", payload)
    tenant = _Tenant(Asset.DEFENDER_CUSTOM_DETECTION, [
        _collected("zz-rule", Asset.DEFENDER_CUSTOM_DETECTION, served, name="42")])
    assert [e.kind for e in detect_drift([tenant], tmp_path).entries] == ["in-sync"]

    renamed = {**served, "displayName": "renamed in the portal"}
    tenant = _Tenant(Asset.DEFENDER_CUSTOM_DETECTION, [
        _collected("zz-rule", Asset.DEFENDER_CUSTOM_DETECTION, renamed, name="42")])
    assert [e.kind for e in detect_drift([tenant], tmp_path).entries] == ["changed"]


def test_importing_keeps_the_status_of_a_defender_rule_deployed_disabled(tmp_path: Path) -> None:
    """A Defender rule says it is off with ``payload.status: disabled``; the
    tenant then lists it as ``deprecated``. An unrelated import must not
    retire a ``production`` file (same rule as for analytics)."""
    payload = {"displayName": "zz rule", "status": "disabled",
               "queryCondition": {"queryText": "DeviceProcessEvents | take 1"}}
    path = _write(tmp_path, Asset.DEFENDER_CUSTOM_DETECTION, "zz-rule", payload)
    tenant = _Tenant(Asset.DEFENDER_CUSTOM_DETECTION, [_collected(
        "zz-rule", Asset.DEFENDER_CUSTOM_DETECTION, {**payload, "displayName": "renamed"},
        name="42", status="deprecated")])
    write_drift(detect_drift([tenant], tmp_path), tmp_path)
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert doc["payload"]["displayName"] == "renamed"
    assert doc["status"] == "production"


def test_defaults_graph_fills_into_a_new_defender_rule_are_not_drift(tmp_path: Path) -> None:
    """A rule written on the current properties leaves the lookback, the
    event grouping and the incident setting to the service; Graph then
    returns ``lookback: PT4H``, ``eventGroupingKind: alertPerEvent`` and
    ``incidentConfiguration``. Drift reported the new rule as changed
    right after its verified create. Seen against a tenant. A value the
    file does set is still compared."""
    payload = {
        "displayName": "zz rule", "status": "disabled",
        "queryCondition": {"queryText": "DeviceProcessEvents | take 1"},
        "schedule": {"frequency": "PT1H"},
        "detectionAction": {"alertTemplate": {"title": "zz", "severity": "medium"}},
    }
    served = {
        **payload,
        "schedule": {"frequency": "PT1H", "lookback": "PT4H"},
        "detectionAction": {
            "alertTemplate": {"title": "zz", "severity": "medium", "eventGroupingKind": "alertPerEvent"},
            "incidentConfiguration": {"isExcludedFromIncidentCorrelation": False},
        },
    }
    _write(tmp_path, Asset.DEFENDER_CUSTOM_DETECTION, "zz-new", payload)
    explicit = {**payload, "schedule": {"frequency": "PT1H", "lookback": "PT12H"}}
    _write(tmp_path, Asset.DEFENDER_CUSTOM_DETECTION, "zz-explicit", explicit)
    tenant = _Tenant(Asset.DEFENDER_CUSTOM_DETECTION, [
        _collected("zz-new", Asset.DEFENDER_CUSTOM_DETECTION, served, name="41"),
        _collected("zz-explicit", Asset.DEFENDER_CUSTOM_DETECTION, served, name="42"),
    ])
    kinds = {e.asset_id: e.kind for e in detect_drift([tenant], tmp_path).entries}
    assert kinds == {"zz-new": "in-sync", "zz-explicit": "changed"}


def test_a_re_created_defender_rule_is_matched_to_its_file_by_name(tmp_path: Path) -> None:
    """Restored after a prune, a Defender rule comes back under a new Graph
    id; its file still records the deleted one, and the file's id is not
    the slug of the (renamed) display name. Drift reported the live rule as
    new, and collect would have written a second file for it. Seen against
    a tenant. Deploy matches by recorded id, then by display name (unique
    in a tenant); drift now does the same, and the import records the new
    id in the existing file."""
    payload = {"displayName": "zz rule renamed", "status": "disabled",
               "queryCondition": {"queryText": "DeviceProcessEvents | take 1"}}
    path = _write(tmp_path, Asset.DEFENDER_CUSTOM_DETECTION, "zz-rule", payload)
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["metadata"]["arm_name"] = "111"  # the deleted rule
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    tenant = _Tenant(Asset.DEFENDER_CUSTOM_DETECTION, [_collected(
        "zz-rule-renamed", Asset.DEFENDER_CUSTOM_DETECTION, payload, name="222")])
    report = detect_drift([tenant], tmp_path)
    assert [(e.kind, e.local_path.name if e.local_path else None) for e in report.entries] == [
        ("changed", "zz-rule.yml"),
    ]
    write_drift(report, tmp_path)
    assert sorted(p.name for p in (tmp_path / "defender_custom_detection").iterdir()) == ["zz-rule.yml"]
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert doc["metadata"]["arm_name"] == "222" and doc["id"] == "zz-rule"


def test_the_default_label_type_is_not_drift_on_either_side(tmp_path: Path) -> None:
    """The tenant returns every label with ``labelType: User``, the
    default. A file that adds a label does not say so; a collected file
    does. Both are in sync with the tenant; another type is not."""
    def _rule(labels: list) -> dict:
        return {"displayName": "zz rule", "order": 1, "actions": [{
            "order": 1, "actionType": "ModifyProperties", "actionConfiguration": {"labels": labels}}]}

    _write(tmp_path, Asset.SENTINEL_AUTOMATION_RULE, "zz-authored", _rule([{"labelName": "a"}]))
    _write(tmp_path, Asset.SENTINEL_AUTOMATION_RULE, "zz-collected", _rule([{"labelName": "a", "labelType": "User"}]))
    _write(tmp_path, Asset.SENTINEL_AUTOMATION_RULE, "zz-system", _rule([{"labelName": "a"}]))
    served = _rule([{"labelName": "a", "labelType": "User"}])
    tenant = _Tenant(Asset.SENTINEL_AUTOMATION_RULE, [
        _collected("zz-authored", Asset.SENTINEL_AUTOMATION_RULE, served),
        _collected("zz-collected", Asset.SENTINEL_AUTOMATION_RULE, served),
        _collected("zz-system", Asset.SENTINEL_AUTOMATION_RULE, _rule([{"labelName": "a", "labelType": "System"}])),
    ])
    kinds = {e.asset_id: e.kind for e in detect_drift([tenant], tmp_path).entries}
    assert kinds == {"zz-authored": "in-sync", "zz-collected": "in-sync", "zz-system": "changed"}


def test_a_deployed_automation_rule_renamed_in_the_tenant_is_a_change_not_a_new_rule(tmp_path: Path) -> None:
    """Deploy names an automation rule it creates after its envelope id
    (``envelope_id_to_guid``); the file records no ARM name. Drift looked
    the rule up by its new display name only and reported a second rule."""
    _write(tmp_path, Asset.SENTINEL_AUTOMATION_RULE, "zz-rule", {"displayName": "zz rule", "order": 1})
    guid = envelope_id_to_guid("zz-rule")
    tenant = _Tenant(Asset.SENTINEL_AUTOMATION_RULE, [_collected(
        "zz-rule-renamed", Asset.SENTINEL_AUTOMATION_RULE,
        {"displayName": "zz rule renamed", "order": 1}, name=guid,
    )])
    report = detect_drift([tenant], tmp_path)
    assert [(e.kind, e.local_path.name if e.local_path else None) for e in report.entries] == [
        ("changed", "zz-rule.yml"),
    ]


# --- Defender: drift compares as deploy does ---------------------------------


def _defender(**template) -> dict:
    tpl = {"title": "T", "severity": "low", "description": "d", "recommendedActions": "r",
           "tactics": [{"tactic": "Discovery", "techniques": []}],
           "entityMappings": {"hosts": [{"deviceIdColumn": "DeviceId"}]}}
    tpl.update(template)
    return {"displayName": "D", "status": "enabled", "queryCondition": {"queryText": "DeviceEvents"},
            "schedule": {"frequency": "PT1H", "lookback": "PT4H"},
            "detectionAction": {"alertTemplate": tpl}}


def test_defender_drift_reads_what_a_verified_deploy_left_as_in_sync() -> None:
    """Drift compared Defender payloads more strictly than deploy, so some
    differences a verified deploy can never clear stayed "changed": OData
    annotations the tenant adds, ``PT60M`` for ``PT1H``, list order."""
    from contentops.core.asset import Asset
    from contentops.core.drift import _payloads_match

    local = _defender(tactics=[{"tactic": "Discovery", "techniques": []},
                               {"tactic": "Execution", "techniques": []}])
    local["schedule"]["frequency"] = "PT60M"
    remote = _defender(
        tactics=[{"tactic": "Execution", "techniques": []}, {"tactic": "Discovery", "techniques": []}],
        entityMappings={"hosts": [{"@odata.type": "#microsoft.graph.security.hostEntityMapping",
                                   "deviceIdColumn": "DeviceId"}]},
    )
    assert _payloads_match(local, remote, Asset.DEFENDER_CUSTOM_DETECTION)


def test_defender_drift_still_sees_a_portal_edit_and_a_portal_added_value() -> None:
    from contentops.core.asset import Asset
    from contentops.core.drift import _payloads_match

    assert not _payloads_match(_defender(), _defender(title="Edited in the portal"),
                               Asset.DEFENDER_CUSTOM_DETECTION)
    left_empty = _defender()
    left_empty["detectionAction"]["alertTemplate"]["recommendedActions"] = ""
    assert not _payloads_match(left_empty, _defender(), Asset.DEFENDER_CUSTOM_DETECTION)


def test_a_disabled_defender_rule_file_is_in_sync_with_the_switched_off_rule(tmp_path: Path) -> None:
    """``contentops disable`` sets ``status: deprecated`` and leaves
    ``payload.status: enabled``; deploy sends ``disabled``. Drift reported
    the switched-off rule as changed until the file was imported."""
    import yaml

    from contentops.core.asset import Asset
    from contentops.core.drift import _local_index, _payloads_match

    folder = tmp_path / "defender_custom_detection"
    folder.mkdir()
    (folder / "rule-r.yml").write_text(yaml.safe_dump({
        "id": "rule-r", "version": "1.0.0", "asset": "defender_custom_detection", "status": "deprecated",
        "payload": _defender(),
    }), encoding="utf-8")
    local_payload = _local_index(tmp_path, Asset.DEFENDER_CUSTOM_DETECTION)["rule-r"][1]
    switched_off = {**_defender(), "status": "disabled"}
    assert _payloads_match(local_payload, switched_off, Asset.DEFENDER_CUSTOM_DETECTION)


def test_an_expired_automation_rule_is_not_drift_every_run(tmp_path: Path) -> None:
    """Collect imports an expired rule as ``deprecated`` and keeps the
    tenant's ``isEnabled: true``. Drift compared a deprecated rule as
    switched off, but deploy skips an expired rule (it never sends the
    disable), so the rule read as changed on every run."""
    logic = {"isEnabled": True, "triggersOn": "Incidents", "triggersWhen": "Created",
             "conditions": [], "expirationTimeUtc": "2020-01-01T00:00:00Z"}
    payload = {"displayName": "zz expired", "order": 1, "triggeringLogic": logic}
    _write(tmp_path, Asset.SENTINEL_AUTOMATION_RULE, "zz-expired", payload, status="deprecated")
    tenant = _Tenant(Asset.SENTINEL_AUTOMATION_RULE, [_collected(
        "zz-expired", Asset.SENTINEL_AUTOMATION_RULE, payload, status="deprecated",
    )])
    assert [e.kind for e in detect_drift([tenant], tmp_path).entries] == ["in-sync"]


def test_a_defender_field_added_in_the_portal_is_drift_when_the_file_leaves_it_out() -> None:
    """Drift compared only the fields a file carries (as deploy does), so a
    response action, a description or custom details added in the portal
    to a rule written from the template read as in sync, and collect never
    imported them. A field is drift when neither it nor its old/new partner
    is in the file and the tenant holds a value."""
    from contentops.core.drift import _payloads_match

    local = _defender()
    action = {"@odata.type": "#microsoft.graph.security.isolateDeviceResponseAction",
              "identifier": "deviceId", "isolationType": "full"}
    with_action = _defender()
    with_action["detectionAction"]["responseActions"] = [action]
    assert not _payloads_match(local, with_action, Asset.DEFENDER_CUSTOM_DETECTION)

    with_description = {**_defender(), "description": "added in the portal"}
    assert not _payloads_match(local, with_description, Asset.DEFENDER_CUSTOM_DETECTION)

    with_details = _defender(customDetails=[{"key": "k", "value": "Column"}])
    assert not _payloads_match(local, with_details, Asset.DEFENDER_CUSTOM_DETECTION)


def test_the_old_keys_graph_fills_next_to_the_file_keys_are_not_drift() -> None:
    """Graph returns ``category`` / ``mitreTechniques`` next to ``tactics``
    and ``impactedAssets`` next to ``entityMappings`` (seen in every
    collected rule), plus empty action lists."""
    from contentops.core.drift import _payloads_match

    served = _defender(category="Discovery", mitreTechniques=["T1082"],
                       impactedAssets=[{"@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
                                        "identifier": "deviceId"}])
    served["detectionAction"].update({"automatedActions": [], "responseActions": []})
    assert _payloads_match(_defender(), served, Asset.DEFENDER_CUSTOM_DETECTION)


def test_two_logic_app_names_that_differ_only_in_punctuation_are_drift(tmp_path: Path) -> None:
    """With no playbook files the comparison fell back to slugs, so
    ``Notify_SOC`` and ``Notify-SOC`` (two different Logic Apps) compared
    equal and a switch between them was invisible."""
    def _rule(app: str) -> dict:
        return {"displayName": "zz rule", "order": 1, "triggeringLogic": {
            "isEnabled": True, "triggersOn": "Incidents", "triggersWhen": "Created", "conditions": []},
            "actions": [{"order": 1, "actionType": "RunPlaybook", "actionConfiguration": {"logicApp": app}}]}

    _write(tmp_path, Asset.SENTINEL_AUTOMATION_RULE, "zz-rule", _rule("Notify_SOC"))
    tenant = _Tenant(Asset.SENTINEL_AUTOMATION_RULE, [_collected(
        "zz-rule", Asset.SENTINEL_AUTOMATION_RULE, _rule("Notify-SOC"))])
    assert [e.kind for e in detect_drift([tenant], tmp_path).entries] == ["changed"]
    # ARM names are case-insensitive: only the case differs, same Logic App.
    tenant = _Tenant(Asset.SENTINEL_AUTOMATION_RULE, [_collected(
        "zz-rule", Asset.SENTINEL_AUTOMATION_RULE, _rule("notify_soc"))])
    assert [e.kind for e in detect_drift([tenant], tmp_path).entries] == ["in-sync"]
