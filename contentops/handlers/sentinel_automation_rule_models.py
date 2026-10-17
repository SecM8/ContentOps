# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pydantic payload model + ARM body builder for ``sentinel_automation_rule``.

The on-disk payload mirrors the ARM ``properties`` block of
``Microsoft.SecurityInsights/automationRules`` one-to-one, plus two
pieces of repo-side sugar that keep subscription / tenant GUIDs out of
``detections/``:

* a ``RunPlaybook`` action may say ``playbook: <sentinel_playbook id>``
  instead of a raw ``logicAppResourceId``; the handler resolves it to
  ``/subscriptions/.../Microsoft.Logic/workflows/<name>`` at apply
  time from ``tenant.yml`` and ``to_envelope`` reverses it on collect;
* a condition value for ``IncidentRelatedAnalyticRuleIds`` /
  ``AlertAnalyticRuleIds`` may be ``analytic:<sentinel_analytic id>``;
  resolved to ``<workspace>/providers/Microsoft.SecurityInsights/
  alertRules/<arm_name>`` and reversed the same way.

Raw resource ids stay accepted for references outside the configured
workspace / playbook resource group.

Sentinel "incident suppression" is an automation rule whose
``ModifyProperties`` action closes the incident with a classification;
it needs no separate kind.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from contentops.utils.slug import displayname_slug

# Stable (non-preview) automationRules API surface. Collect and apply
# must use the same constant; the provider default is a preview version.
AUTOMATION_API_VERSION = "2025-09-01"

ANALYTIC_REF_PREFIX = "analytic:"
# Condition properties whose values are analytics-rule ARM resource ids.
ANALYTIC_RULE_ID_PROPERTIES: frozenset[str] = frozenset({
    "IncidentRelatedAnalyticRuleIds",
    "AlertAnalyticRuleIds",
})

TriggersOn = Literal["Incidents", "Alerts"]
TriggersWhen = Literal["Created", "Updated"]
ActionType = Literal["ModifyProperties", "RunPlaybook", "AddIncidentTask"]
ConditionType = Literal[
    "Boolean", "Property", "PropertyArray", "PropertyArrayChanged", "PropertyChanged",
]

_LOGIC_APP_ID_RE = re.compile(
    r"^/subscriptions/(?P<sub>[^/]+)/resourceGroups/(?P<rg>[^/]+)"
    r"/providers/Microsoft\.Logic/workflows/(?P<name>[^/]+)$",
    re.IGNORECASE,
)
_ALERT_RULE_ID_RE = re.compile(
    r"^(?P<workspace>.+)/providers/Microsoft\.SecurityInsights/alertRules/(?P<name>[^/]+)$",
    re.IGNORECASE,
)
_EXPIRATION_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


# ---------------------------------------------------------------------------
# Action configurations
# ---------------------------------------------------------------------------


class RunPlaybookConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    playbook: str | None = None
    logicAppResourceId: str | None = None
    tenantId: str | None = None

    @model_validator(mode="after")
    def _exactly_one_target(self) -> "RunPlaybookConfig":
        has_sugar = bool(self.playbook)
        has_raw = bool(self.logicAppResourceId)
        if has_sugar == has_raw:
            raise ValueError(
                "RunPlaybook actionConfiguration needs exactly one of "
                "`playbook: <sentinel_playbook envelope id>` or "
                "`logicAppResourceId: /subscriptions/.../Microsoft.Logic/workflows/<name>`"
            )
        if has_raw and not _LOGIC_APP_ID_RE.match(self.logicAppResourceId or ""):
            raise ValueError(
                f"logicAppResourceId {self.logicAppResourceId!r} is not a "
                "Microsoft.Logic/workflows resource id"
            )
        return self


class ModifyPropertiesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity: Literal["Informational", "Low", "Medium", "High"] | None = None
    status: Literal["New", "Active", "Closed"] | None = None
    classification: Literal[
        "Undetermined", "TruePositive", "BenignPositive", "FalsePositive",
    ] | None = None
    classificationReason: Literal[
        "SuspiciousActivity", "SuspiciousButExpected", "IncorrectAlertLogic", "InaccurateData",
    ] | None = None
    classificationComment: str | None = None
    owner: dict[str, Any] | None = None
    labels: list[dict[str, Any]] | None = None

    @model_validator(mode="after")
    def _closing_is_well_formed(self) -> "ModifyPropertiesConfig":
        if self.status == "Closed" and not self.classification:
            raise ValueError(
                "ModifyProperties with `status: Closed` must set `classification` "
                "(BenignPositive / FalsePositive / TruePositive / Undetermined)"
            )
        if self.classification and self.status != "Closed":
            raise ValueError("`classification` is only valid together with `status: Closed`")
        if not any(
            v is not None for v in (
                self.severity, self.status, self.classification, self.owner, self.labels,
            )
        ):
            raise ValueError("ModifyProperties actionConfiguration sets nothing")
        return self


class AddIncidentTaskConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1)
    description: str | None = None


_CONFIG_MODELS: dict[str, type[BaseModel]] = {
    "ModifyProperties": ModifyPropertiesConfig,
    "RunPlaybook": RunPlaybookConfig,
    "AddIncidentTask": AddIncidentTaskConfig,
}


class AutomationAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    order: int = Field(ge=1)
    actionType: ActionType
    actionConfiguration: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _config_matches_type(self) -> "AutomationAction":
        _CONFIG_MODELS[self.actionType](**self.actionConfiguration)
        return self


class AutomationCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    conditionType: ConditionType
    conditionProperties: dict[str, Any] = Field(default_factory=dict)


class TriggeringLogic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    isEnabled: bool = True
    triggersOn: TriggersOn = "Incidents"
    triggersWhen: TriggersWhen = "Created"
    conditions: list[AutomationCondition] = Field(default_factory=list)
    # ISO-8601 UTC. A past value is ACCEPTED here (collected rules must
    # still parse); lint PAYLOAD008 warns and apply skips expired rules
    # because ARM rejects them on PUT.
    expirationTimeUtc: str | None = None

    @model_validator(mode="after")
    def _expiration_parses(self) -> "TriggeringLogic":
        if self.expirationTimeUtc is not None and parse_expiration(self.expirationTimeUtc) is None:
            raise ValueError(
                f"expirationTimeUtc {self.expirationTimeUtc!r} is not an ISO-8601 "
                "timestamp (e.g. 2026-12-31T23:59:59Z)"
            )
        if self.triggersOn == "Alerts" and self.triggersWhen != "Created":
            raise ValueError("alert-triggered automation rules only support triggersWhen: Created")
        return self


class SentinelAutomationRulePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    displayName: str = Field(min_length=1, max_length=500)
    order: int = Field(ge=1, le=1000)
    triggeringLogic: TriggeringLogic
    actions: list[AutomationAction] = Field(min_length=1)

    @model_validator(mode="after")
    def _cross_field(self) -> "SentinelAutomationRulePayload":
        orders = [a.order for a in self.actions]
        if len(orders) != len(set(orders)):
            raise ValueError(f"action `order` values must be unique, got {orders}")
        if self.triggeringLogic.triggersOn == "Alerts":
            bad = [a.actionType for a in self.actions if a.actionType != "RunPlaybook"]
            if bad:
                raise ValueError(
                    "alert-triggered automation rules can only run playbooks; "
                    f"found {bad}"
                )
        # A close action with no conditions auto-closes EVERY incident in
        # the workspace (Defender XDR incidents included once onboarded).
        # Refuse at validate time so apply can never ship it; lint
        # PAYLOAD014 reports the same thing at PR time.
        if closes_incidents(self.model_dump()) and not self.triggeringLogic.conditions:
            raise ValueError(
                "this automation rule closes incidents but has no "
                "triggeringLogic.conditions — it would auto-close every incident. "
                "Scope it with at least one condition (e.g. "
                "IncidentRelatedAnalyticRuleIds)."
            )
        return self


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def envelope_id_to_guid(envelope_id: str) -> str:
    """Stable GUID derived from a human envelope id.

    Same input always yields the same UUID, so PUTs are idempotent
    upserts against the Sentinel ARM endpoint.
    """
    return str(uuid.uuid5(uuid.NAMESPACE_URL, envelope_id))


def parse_expiration(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp into an aware UTC datetime, or None."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_expiration(value: str | None) -> str | None:
    """Canonical ``YYYY-MM-DDTHH:MM:SSZ`` form (ARM reformats on PUT; keep
    local and remote identical so drift doesn't flap)."""
    parsed = parse_expiration(value)
    if parsed is None:
        return value
    return parsed.strftime(_EXPIRATION_FORMAT)


def is_expired(value: str | None, *, now: datetime | None = None) -> bool:
    parsed = parse_expiration(value)
    if parsed is None:
        return False
    current = now or datetime.now(timezone.utc)
    return parsed <= current


def closes_incidents(payload: dict) -> bool:
    """True when any ModifyProperties action sets ``status: Closed``."""
    for action in payload.get("actions") or []:
        if not isinstance(action, dict):
            continue
        if action.get("actionType") != "ModifyProperties":
            continue
        cfg = action.get("actionConfiguration") or {}
        if isinstance(cfg, dict) and cfg.get("status") == "Closed":
            return True
    return False


def analytic_scope_conditions(payload: dict) -> list[dict]:
    """Conditions that scope the rule to specific analytics / detection rules."""
    out: list[dict] = []
    logic = payload.get("triggeringLogic") or {}
    for cond in logic.get("conditions") or []:
        if not isinstance(cond, dict):
            continue
        props = cond.get("conditionProperties") or {}
        name = props.get("propertyName") if isinstance(props, dict) else None
        if name in ANALYTIC_RULE_ID_PROPERTIES or name == "IncidentCustomDetectionRuleIds":
            out.append(cond)
    return out


def logic_app_resource_id(subscription_id: str, resource_group: str, workflow_name: str) -> str:
    return (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Logic/workflows/{workflow_name}"
    )


def playbook_id_from_resource_id(
    resource_id: str, *, subscription_id: str, resource_group: str,
) -> str | None:
    """Reverse a Logic App resource id to a playbook envelope id.

    Only ids inside the configured subscription + playbook RG map back;
    anything else returns None so the collector keeps the raw id.
    """
    m = _LOGIC_APP_ID_RE.match(resource_id or "")
    if m is None:
        return None
    if m.group("sub").lower() != subscription_id.lower():
        return None
    if m.group("rg").lower() != resource_group.lower():
        return None
    name = m.group("name")
    slug = displayname_slug(name, fallback_id=name)
    return slug or None


def analytic_rule_resource_id(workspace_path: str, arm_name: str) -> str:
    """``<workspace>/providers/Microsoft.SecurityInsights/alertRules/<arm_name>``.

    ``workspace_path`` is the Log Analytics workspace resource id (the
    provider's ``loganalytics_workspace_path``).
    """
    return f"{workspace_path}/providers/Microsoft.SecurityInsights/alertRules/{arm_name}"


def analytic_arm_name_from_resource_id(
    resource_id: str, *, workspace_path: str,
) -> str | None:
    """Return the alertRules ARM name when ``resource_id`` sits under
    ``workspace_path`` (case-insensitive), else None."""
    m = _ALERT_RULE_ID_RE.match(resource_id or "")
    if m is None:
        return None
    if m.group("workspace").lower() != workspace_path.lower():
        return None
    return m.group("name")


PlaybookResolver = Callable[[str], tuple[str, str | None]]
AnalyticResolver = Callable[[str], str]


def to_automation_rule_arm_body(
    payload: dict,
    *,
    resolve_playbook: PlaybookResolver,
    resolve_analytic: AnalyticResolver,
) -> dict:
    """Build the ARM PUT body: ``{"properties": {...}}`` with the repo-side
    sugar replaced by real resource ids and the expiration normalised.

    ``resolve_playbook(envelope_id) -> (logicAppResourceId, tenantId)`` and
    ``resolve_analytic(envelope_id) -> alertRules resource id`` raise
    ``ValueError`` for unknown ids.
    """
    props: dict = {
        "displayName": payload["displayName"],
        "order": payload["order"],
    }
    logic = dict(payload.get("triggeringLogic") or {})
    if logic.get("expirationTimeUtc"):
        logic["expirationTimeUtc"] = normalize_expiration(logic["expirationTimeUtc"])
    conditions: list[dict] = []
    for cond in logic.get("conditions") or []:
        conditions.append(_resolve_condition(cond, resolve_analytic))
    logic["conditions"] = conditions
    props["triggeringLogic"] = logic

    actions: list[dict] = []
    for action in payload.get("actions") or []:
        action = dict(action)
        cfg = dict(action.get("actionConfiguration") or {})
        if action.get("actionType") == "RunPlaybook" and cfg.get("playbook"):
            resource_id, tenant_id = resolve_playbook(str(cfg.pop("playbook")))
            cfg["logicAppResourceId"] = resource_id
            if tenant_id and not cfg.get("tenantId"):
                cfg["tenantId"] = tenant_id
        action["actionConfiguration"] = cfg
        actions.append(action)
    props["actions"] = actions
    return {"properties": props}


def _resolve_condition(cond: dict, resolve_analytic: AnalyticResolver) -> dict:
    cond = dict(cond)
    props = cond.get("conditionProperties")
    if not isinstance(props, dict):
        return cond
    props = dict(props)
    # Nested Boolean / PropertyArray conditions carry their own lists.
    for key in ("innerConditions", "itemConditions"):
        inner = props.get(key)
        if isinstance(inner, list):
            props[key] = [
                _resolve_condition(c, resolve_analytic) if isinstance(c, dict) else c
                for c in inner
            ]
    if props.get("propertyName") in ANALYTIC_RULE_ID_PROPERTIES:
        values = props.get("propertyValues")
        if isinstance(values, list):
            props["propertyValues"] = [
                resolve_analytic(v[len(ANALYTIC_REF_PREFIX):])
                if isinstance(v, str) and v.startswith(ANALYTIC_REF_PREFIX) else v
                for v in values
            ]
    cond["conditionProperties"] = props
    return cond


def analytic_refs(payload: dict) -> list[str]:
    """Every ``analytic:<id>`` reference in the payload's conditions."""
    out: list[str] = []

    def _walk(cond: dict) -> None:
        props = cond.get("conditionProperties") or {}
        if not isinstance(props, dict):
            return
        if props.get("propertyName") in ANALYTIC_RULE_ID_PROPERTIES:
            for v in props.get("propertyValues") or []:
                if isinstance(v, str) and v.startswith(ANALYTIC_REF_PREFIX):
                    out.append(v[len(ANALYTIC_REF_PREFIX):])
        for key in ("innerConditions", "itemConditions"):
            for inner in props.get(key) or []:
                if isinstance(inner, dict):
                    _walk(inner)

    for cond in (payload.get("triggeringLogic") or {}).get("conditions") or []:
        if isinstance(cond, dict):
            _walk(cond)
    return out


def playbook_refs(payload: dict) -> list[str]:
    """Every ``playbook: <id>`` reference in the payload's actions."""
    out: list[str] = []
    for action in payload.get("actions") or []:
        if not isinstance(action, dict) or action.get("actionType") != "RunPlaybook":
            continue
        cfg = action.get("actionConfiguration") or {}
        if isinstance(cfg, dict) and cfg.get("playbook"):
            out.append(str(cfg["playbook"]))
    return out


__all__ = [
    "AUTOMATION_API_VERSION",
    "ANALYTIC_REF_PREFIX",
    "ANALYTIC_RULE_ID_PROPERTIES",
    "SentinelAutomationRulePayload",
    "analytic_arm_name_from_resource_id",
    "analytic_refs",
    "analytic_rule_resource_id",
    "analytic_scope_conditions",
    "closes_incidents",
    "envelope_id_to_guid",
    "is_expired",
    "logic_app_resource_id",
    "normalize_expiration",
    "parse_expiration",
    "playbook_id_from_resource_id",
    "playbook_refs",
    "to_automation_rule_arm_body",
]
