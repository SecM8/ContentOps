# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Synthetic Defender custom detection shapes and an in-memory Graph.

Test helper, not a test module. ``FakeGraph`` stands in for
``contentops.defender.client.DefenderClient`` and imitates what the
Graph beta ``detectionRules`` endpoint is documented or observed to do:

* it stores one rule in both shapes and mirrors whichever side a request
  carried into the other (``period`` <-> ``frequency``, ``category`` and
  ``mitreTechniques`` <-> ``tactics``, ``impactedAssets`` <->
  ``entityMappings``, ``responseActions`` <-> ``automatedActions``,
  ``scopeNames`` <-> ``deviceGroups``);
* it returns the expanded form: every entity collection and action list,
  every column of a mapping, a derived ``lookback``, default event
  grouping and incident configuration.

Constructor flags switch single behaviours to the opposite, so a test
can show that code under test notices when the service misbehaves.
Everything here is made up; no value comes from a real tenant.
"""

from __future__ import annotations

import copy
import json
from typing import Any

ENTITY_COLUMNS: dict[str, tuple[str, ...]] = {
    "hosts": ("deviceIdColumn", "dnsDomainColumn", "nameColumn", "netBiosNameColumn", "ntDomainColumn"),
    "accounts": (
        "aadUserIdColumn", "dnsDomainColumn", "nameColumn", "ntDomainColumn",
        "sidColumn", "upnColumn", "upnSuffixColumn",
    ),
    "ips": ("addressColumn", "scopeColumn"),
    "files": ("nameColumn", "sha1Column", "sha256Column"),
    "processes": ("sha1Column", "sha256Column"),
    "cloudApplications": ("appIdColumn", "nameColumn"),
    "dns": ("domainNameColumn", "hostIpAddressColumn", "serverIpColumn"),
    "azureResources": ("resourceIdColumn",),
    "amazonResources": ("amazonResourceIdColumn",),
    "googleCloudResources": ("fullResourceNameColumn",),
    "registryValues": ("keyColumn", "valueNameColumn"),
    "securityGroups": ("distinguishedNameColumn", "objectIdColumn", "sidColumn"),
    "oAuthApplications": ("oAuthAppIdColumn",),
    "urls": ("addressColumn",),
    "mailboxes": ("primaryAddressColumn",),
    "mailMessages": ("networkMessageIdColumn", "recipientColumn", "senderColumn", "subjectColumn"),
    "mailClusters": ("queryColumn", "sourceColumn"),
}

ACTION_LISTS: tuple[str, ...] = (
    "isolateDevices", "stopAndQuarantineFiles", "blockFiles", "allowFiles",
    "disableUsers", "forceUserPasswordResets", "markUsersAsCompromised",
    "collectInvestigationPackages", "initiateInvestigations",
    "restrictAppExecutions", "runAntivirusScans", "hardDeleteEmails",
    "softDeleteEmails", "moveEmailsToInbox", "moveEmailsToDeletedItems",
    "moveEmailsToJunk",
)

PERIOD_TO_FREQUENCY = {"0": "PT0S", "1H": "PT1H", "3H": "PT3H", "12H": "PT12H", "24H": "P1D"}
FREQUENCY_TO_PERIOD = {v: k for k, v in PERIOD_TO_FREQUENCY.items()}
DEFAULT_LOOKBACK = {"PT1H": "PT4H", "PT3H": "PT12H", "PT12H": "P2D", "P1D": "P30D"}
_DURATION_ALIASES = {"PT60M": "PT1H", "PT24H": "P1D", "PT180M": "PT3H"}

_OLD_ASSET_TYPE = "#microsoft.graph.security.impactedDeviceAsset"
_OLD_SCAN_ACTION = "#microsoft.graph.security.runAntivirusScanResponseAction"


class FakeResponse:
    """The subset of ``httpx.Response`` the Defender client callers use."""

    def __init__(self, status_code: int, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = "" if payload is None else json.dumps(payload)

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no JSON body")
        return self._payload


def _error(status: int, code: str, message: str) -> FakeResponse:
    return FakeResponse(status, {"error": {"code": code, "message": message}})


def _is_empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


class FakeGraph:
    """In-memory stand-in for the Graph beta detectionRules endpoint."""

    def __init__(
        self,
        *,
        rules: list[dict] | None = None,
        create_status: str | None = None,
        reject_new_only: bool = False,
        merge_on_patch: bool = False,
        clearing_forms: tuple[str, ...] = ("null", "''", "{}"),
        lose_scope_on_patch: bool = False,
        lose_actions_on_patch: bool = False,
        list_differs: bool = False,
        stale_reads: int = 0,
        raise_on_patch_number: int | None = None,
        delete_lag_reads: int = 0,
        annotate_mappings: bool = False,
        drop_omitted_action_parts: bool = False,
        reject_schedule_values: tuple[str, ...] = (),
        annotate_single_reads: bool = False,
        list_raises_times: int = 0,
    ) -> None:
        #: The last ``list_raises_times`` list calls raise (throttling past
        #: the client's retries), counted from the first list after a
        #: delete.
        self._list_raises_left = list_raises_times
        #: A single-rule read carries ``@odata.context``, as Graph's does.
        self._annotate_single_reads = annotate_single_reads
        #: Every create and update stamps ``lastModifiedDateTime``.
        self._clock = 0
        #: An update that carries ``detectionAction`` clears the scope and
        #: the automated actions it does not mention.
        self._drop_omitted_action_parts = drop_omitted_action_parts
        #: ``schedule.frequency`` / ``lookback`` values answered with 400.
        self._reject_schedule_values = reject_schedule_values
        self._rules: dict[str, dict] = {}
        self._next_id = 5000
        self._create_status = create_status
        self._reject_new_only = reject_new_only
        self._merge_on_patch = merge_on_patch
        self._clearing_forms = clearing_forms
        self._lose_scope = lose_scope_on_patch
        self._lose_actions = lose_actions_on_patch
        self._list_differs = list_differs
        self._stale_reads = stale_reads
        self._stale: dict[str, tuple[int, dict]] = {}
        self._raise_on_patch_number = raise_on_patch_number
        self._patches = 0
        self._delete_lag_reads = delete_lag_reads
        self._annotate_mappings = annotate_mappings
        self._deleted_lag: dict[str, tuple[int, dict]] = {}
        #: Every call as ``(method, rule id or None, request body or None)``.
        self.calls: list[tuple[str, str | None, dict | None]] = []
        for rule in rules or []:
            stored = copy.deepcopy(rule)
            stored.setdefault("id", str(self._next_id))
            self._next_id += 1
            self._rules[str(stored["id"])] = stored

    # -- client surface -------------------------------------------------

    def create_rule(self, body: dict) -> FakeResponse:
        self.calls.append(("POST", None, copy.deepcopy(body)))
        if self._reject_new_only and "period" not in (body.get("schedule") or {}):
            return _error(400, "BadRequest", "The request body is not valid.")
        rule = self._merge({}, body)
        rule["id"] = str(self._next_id)
        self._next_id += 1
        rule["lastModifiedDateTime"] = self._tick()
        if self._create_status is not None:
            rule["status"] = self._create_status
        self._rules[rule["id"]] = rule
        return FakeResponse(201, copy.deepcopy(rule))

    def update_rule(self, graph_id: str, body: dict) -> FakeResponse:
        self.calls.append(("PATCH", str(graph_id), copy.deepcopy(body)))
        self._patches += 1
        if self._raise_on_patch_number == self._patches:
            raise RuntimeError("simulated transport failure")
        current = self._rules.get(str(graph_id))
        if current is None:
            return _error(404, "NotFound", "Rule not found.")
        schedule_in = body.get("schedule") if isinstance(body.get("schedule"), dict) else {}
        if any(schedule_in.get(key) in self._reject_schedule_values for key in ("frequency", "lookback")):
            return _error(400, "BadRequest", "The schedule value is not supported.")
        if self._stale_reads:
            self._stale[str(graph_id)] = (self._stale_reads, copy.deepcopy(current))
        updated = self._merge(current, body)
        action = updated.get("detectionAction") or {}
        action_in = body.get("detectionAction") if isinstance(body.get("detectionAction"), dict) else None
        omitted = self._drop_omitted_action_parts and action_in is not None
        if (self._lose_scope or omitted) and "organizationalScope" not in (action_in or {}):
            action["organizationalScope"] = None
        if (self._lose_actions or omitted) and "automatedActions" not in (action_in or {}):
            action["automatedActions"] = {name: [] for name in ACTION_LISTS}
            action["responseActions"] = []
        updated["lastModifiedDateTime"] = self._tick()
        self._rules[str(graph_id)] = updated
        return FakeResponse(200, copy.deepcopy(updated))

    def get_rule(self, graph_id: str) -> dict | None:
        self.calls.append(("GET", str(graph_id), None))
        key = str(graph_id)
        if key in self._deleted_lag:
            left, snapshot = self._deleted_lag[key]
            if left > 0:
                self._deleted_lag[key] = (left - 1, snapshot)
                return copy.deepcopy(snapshot)
            del self._deleted_lag[key]
        if key in self._stale:
            left, snapshot = self._stale[key]
            if left > 0:
                self._stale[key] = (left - 1, snapshot)
                return copy.deepcopy(snapshot)
            del self._stale[key]
        rule = self._rules.get(key)
        if rule is None:
            return None
        rule = copy.deepcopy(rule)
        if self._annotate_single_reads:
            rule = {"@odata.context": "https://graph.example/$metadata#detectionRules/$entity", **rule}
        return rule

    def _tick(self) -> str:
        """A later ``lastModifiedDateTime`` on every write, in Graph's form."""
        self._clock += 1
        minute, second = divmod(self._clock, 60)
        return f"2026-01-01T00:{minute:02d}:{second:02d}.1234567Z"

    def list_rules(self) -> list[dict]:
        self.calls.append(("LIST", None, None))
        if self._list_raises_left and any(call[0] == "DELETE" for call in self.calls):
            self._list_raises_left -= 1
            raise RuntimeError("simulated throttling past the client's retries")
        out = [copy.deepcopy(rule) for rule in self._rules.values()]
        if self._list_differs:
            for rule in out:
                template = (rule.get("detectionAction") or {}).get("alertTemplate") or {}
                template["customDetails"] = None
        return out

    def delete_rule(self, graph_id: str) -> FakeResponse:
        self.calls.append(("DELETE", str(graph_id), None))
        rule = self._rules.pop(str(graph_id), None)
        if rule is None:
            return _error(404, "NotFound", "Rule not found.")
        if self._delete_lag_reads:
            self._deleted_lag[str(graph_id)] = (self._delete_lag_reads, rule)
        return FakeResponse(204)

    def close(self) -> None:  # parity with DefenderClient
        return None

    # -- test conveniences ----------------------------------------------

    def rule(self, graph_id: str) -> dict | None:
        """The stored rule, without recording a call."""
        rule = self._rules.get(str(graph_id))
        return copy.deepcopy(rule) if rule is not None else None

    def all_rules(self) -> list[dict]:
        return [copy.deepcopy(rule) for rule in self._rules.values()]

    def writes(self) -> list[tuple[str, str | None, dict | None]]:
        return [call for call in self.calls if call[0] in ("POST", "PATCH", "DELETE")]

    # -- service behaviour ----------------------------------------------

    def _clears(self, value: Any) -> bool:
        if value is None:
            return "null" in self._clearing_forms
        if value == "":
            return "''" in self._clearing_forms
        if value == {} or value == []:
            return "{}" in self._clearing_forms
        return False

    def _assign(self, target: dict, key: str, value: Any) -> None:
        """PATCH semantics for one leaf: a value replaces, an empty form
        clears only when the service honours that form."""
        if _is_empty(value) and key in target and not _is_empty(target[key]):
            if self._clears(value):
                target[key] = None
            return
        target[key] = copy.deepcopy(value)

    def _merge(self, current: dict, body: dict) -> dict:
        rule = copy.deepcopy(current)
        for key, value in body.items():
            if key in ("schedule", "queryCondition", "detectionAction"):
                continue
            self._assign(rule, key, value)
        if isinstance(body.get("queryCondition"), dict):
            rule.setdefault("queryCondition", {}).update(copy.deepcopy(body["queryCondition"]))

        schedule_in = body.get("schedule") if isinstance(body.get("schedule"), dict) else {}
        schedule = dict(rule.get("schedule") or {})
        if schedule_in.get("frequency"):
            frequency = _DURATION_ALIASES.get(schedule_in["frequency"], schedule_in["frequency"])
            schedule["frequency"] = frequency
            schedule["period"] = FREQUENCY_TO_PERIOD.get(frequency, schedule.get("period"))
            schedule.pop("lookback", None)
        elif "period" in schedule_in:
            schedule["period"] = schedule_in["period"]
            schedule["frequency"] = PERIOD_TO_FREQUENCY.get(str(schedule_in["period"]))
            schedule.pop("lookback", None)
        if schedule_in.get("lookback"):
            schedule["lookback"] = _DURATION_ALIASES.get(schedule_in["lookback"], schedule_in["lookback"])
        if schedule.get("frequency") == "PT0S":
            schedule["lookback"] = None
        elif not schedule.get("lookback"):
            schedule["lookback"] = DEFAULT_LOOKBACK.get(schedule.get("frequency") or "", schedule.get("frequency"))
        if schedule:
            rule["schedule"] = schedule

        action_in = body.get("detectionAction") if isinstance(body.get("detectionAction"), dict) else {}
        action = dict(rule.get("detectionAction") or {})
        template_in = action_in.get("alertTemplate") if isinstance(action_in.get("alertTemplate"), dict) else {}
        template = dict(action.get("alertTemplate") or {})
        for key, value in template_in.items():
            if key in ("tactics", "category", "mitreTechniques", "entityMappings", "impactedAssets"):
                continue
            self._assign(template, key, value)
        self._merge_tactics(template, template_in)
        self._merge_entities(template, template_in)
        template.setdefault("eventGroupingKind", "alertPerEvent")
        if template.get("eventGroupingKind") is None:
            template["eventGroupingKind"] = "alertPerEvent"
        action["alertTemplate"] = template

        self._merge_actions(action, action_in)
        self._merge_scope(action, action_in)
        if _is_empty(action.get("incidentConfiguration")) or _is_empty(action_in.get("incidentConfiguration", True)):
            action["incidentConfiguration"] = {"isExcludedFromIncidentCorrelation": False}
        if isinstance(action_in.get("incidentConfiguration"), dict) and action_in["incidentConfiguration"]:
            action["incidentConfiguration"] = copy.deepcopy(action_in["incidentConfiguration"])
        rule["detectionAction"] = action
        rule.setdefault("status", "enabled")
        return rule

    @staticmethod
    def _merge_tactics(template: dict, incoming: dict) -> None:
        if "tactics" in incoming and incoming["tactics"]:
            tactics = copy.deepcopy(incoming["tactics"])
            for tactic in tactics:
                tactic.setdefault("techniques", [])
                for technique in tactic["techniques"]:
                    technique.setdefault("subTechniques", [])
            template["tactics"] = tactics
        elif "category" in incoming or "mitreTechniques" in incoming:
            category = incoming.get("category") or template.get("category")
            ids = list(incoming.get("mitreTechniques") or [])
            parents = [i for i in ids if "." not in i]
            techniques = [
                {"technique": parent, "subTechniques": [i for i in ids if i.startswith(parent + ".")]}
                for parent in parents
            ]
            template["tactics"] = [{"tactic": category, "techniques": techniques}] if category else []
        elif "tactics" in incoming:
            template["tactics"] = []
        template.setdefault("tactics", [])
        tactics = template["tactics"]
        template["category"] = tactics[0]["tactic"] if tactics else None
        flat: list[str] = []
        for tactic in tactics:
            for technique in tactic.get("techniques") or []:
                flat.append(technique["technique"])
                flat.extend(technique.get("subTechniques") or [])
        template["mitreTechniques"] = flat

    def _merge_entities(self, template: dict, incoming: dict) -> None:
        existing = template.get("entityMappings") or {}
        if "entityMappings" in incoming and isinstance(incoming["entityMappings"], dict):
            mappings = incoming["entityMappings"]
            merged: dict[str, list] = {}
            for name in ENTITY_COLUMNS:
                entries = list(copy.deepcopy(mappings.get(name) or []))
                if self._merge_on_patch:
                    entries = list(copy.deepcopy(existing.get(name) or [])) + [
                        e for e in entries if e not in (existing.get(name) or [])
                    ]
                merged[name] = entries
        elif "impactedAssets" in incoming:
            merged = {name: [] for name in ENTITY_COLUMNS}
            for asset in incoming.get("impactedAssets") or []:
                if asset.get("identifier") == "deviceId":
                    merged["hosts"].append({"deviceIdColumn": "DeviceId"})
        else:
            merged = {name: list(copy.deepcopy(existing.get(name) or [])) for name in ENTITY_COLUMNS}
        for name, columns in ENTITY_COLUMNS.items():
            merged[name] = [{column: entry.get(column) or "" for column in columns} for entry in merged[name]]
            if self._annotate_mappings:
                for entry in merged[name]:
                    entry["@odata.type"] = f"#microsoft.graph.security.{name}EntityMapping"
        template["entityMappings"] = merged
        template["impactedAssets"] = [
            {"@odata.type": _OLD_ASSET_TYPE, "identifier": "deviceId"}
            for entry in merged["hosts"] if entry.get("deviceIdColumn")
        ]

    @staticmethod
    def _merge_actions(action: dict, incoming: dict) -> None:
        existing = action.get("automatedActions") or {}
        if "automatedActions" in incoming and isinstance(incoming["automatedActions"], dict):
            actions = {name: list(copy.deepcopy(incoming["automatedActions"].get(name) or [])) for name in ACTION_LISTS}
        elif "responseActions" in incoming:
            actions = {name: [] for name in ACTION_LISTS}
            for old in incoming.get("responseActions") or []:
                if old.get("@odata.type") == _OLD_SCAN_ACTION:
                    actions["runAntivirusScans"].append({"deviceIdColumn": "DeviceId"})
        else:
            actions = {name: list(copy.deepcopy(existing.get(name) or [])) for name in ACTION_LISTS}
        action["automatedActions"] = actions
        action["responseActions"] = [
            {"@odata.type": _OLD_SCAN_ACTION, "identifier": "deviceId"}
            for _ in actions["runAntivirusScans"]
        ]

    def _merge_scope(self, action: dict, incoming: dict) -> None:
        if "organizationalScope" not in incoming:
            action.setdefault("organizationalScope", None)
            return
        scope = incoming["organizationalScope"]
        if _is_empty(scope):
            if _is_empty(action.get("organizationalScope")) or self._clears(scope):
                action["organizationalScope"] = None
            return
        groups = list(scope.get("deviceGroups") or scope.get("scopeNames") or [])
        action["organizationalScope"] = (
            {"scopeType": "deviceGroup", "scopeNames": list(groups), "deviceGroups": list(groups)}
            if groups else None
        )


def current_payload(**overrides: Any) -> dict:
    """A rule payload with new keys only, in the short hand-written form."""
    payload: dict[str, Any] = {
        "displayName": "Synthetic rule",
        "status": "enabled",
        "description": "synthetic description",
        "queryCondition": {"queryText": "DeviceProcessEvents | take 1"},
        "schedule": {"frequency": "PT1H", "lookback": "PT4H"},
        "detectionAction": {
            "organizationalScope": {"deviceGroups": ["group-a", "group-b"]},
            "alertTemplate": {
                "title": "Synthetic alert",
                "description": "synthetic alert description",
                "severity": "medium",
                "recommendedActions": "synthetic actions",
                "tactics": [
                    {"tactic": "Persistence", "techniques": [
                        {"technique": "T1136", "subTechniques": ["T1136.001"]},
                    ]},
                ],
                "entityMappings": {"hosts": [{"deviceIdColumn": "DeviceId"}]},
                "customDetails": {"Key": "DeviceName"},
            },
            "automatedActions": {"runAntivirusScans": [{"deviceIdColumn": "DeviceId"}]},
        },
    }
    payload.update(overrides)
    return payload


def two_shape_payload() -> dict:
    """The same rule as Graph beta returns it and collect wrote it until
    now: old and new keys side by side, expanded, without server fields."""
    stored = FakeGraph().create_rule(current_payload()).json()
    stored.pop("id", None)
    return stored


def legacy_only_payload() -> dict:
    """The same rule written by hand from the old template: old keys only."""
    return {
        "displayName": "Synthetic rule",
        "status": "enabled",
        "queryCondition": {"queryText": "DeviceProcessEvents | take 1"},
        "schedule": {"period": "1H"},
        "detectionAction": {
            "organizationalScope": {"scopeType": "deviceGroup", "scopeNames": ["group-a", "group-b"]},
            "alertTemplate": {
                "title": "Synthetic alert",
                "description": "synthetic alert description",
                "severity": "medium",
                "category": "Persistence",
                "recommendedActions": "synthetic actions",
                "mitreTechniques": ["T1136", "T1136.001"],
                "impactedAssets": [{"@odata.type": _OLD_ASSET_TYPE, "identifier": "deviceId"}],
            },
            "responseActions": [{"@odata.type": _OLD_SCAN_ACTION, "identifier": "deviceId"}],
        },
    }


def scoped_tenant_rule(*, groups: list[str], name: str = "Existing scoped rule") -> dict:
    """A rule that already exists in the fake tenant, scoped to ``groups``."""
    graph = FakeGraph()
    response = graph.create_rule({
        "displayName": name,
        "status": "enabled",
        "queryCondition": {"queryText": "DeviceProcessEvents | take 1"},
        "schedule": {"frequency": "PT1H"},
        "detectionAction": {
            "alertTemplate": {
                "title": name, "severity": "low",
                "entityMappings": {"hosts": [{"deviceIdColumn": "DeviceId"}]},
            },
            "organizationalScope": {"deviceGroups": list(groups)},
        },
    })
    return response.json()
