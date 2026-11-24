# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Sentinel automation rule handler — ARM upsert via SentinelArmProvider.

ARM resource type: ``Microsoft.SecurityInsights/automationRules``
API version:       ``2025-09-01`` (stable; pinned in the models module)

Envelope shape (see ``sentinel_automation_rule_models`` for the full
schema and the ``playbook:`` / ``analytic:`` sugar)::

    id: suppress-admin-role-additions-iam-migration
    version: 1.0.0
    asset: sentinel_automation_rule
    status: production
    metadata: {owner: ..., runbookUrl: ..., description: ...}
    payload:
      displayName: "Suppress: ..."
      order: 5
      triggeringLogic:
        isEnabled: true
        triggersOn: Incidents
        triggersWhen: Created
        expirationTimeUtc: "2026-12-31T23:59:59Z"
        conditions: [...]
      actions:
        - order: 1
          actionType: ModifyProperties
          actionConfiguration: {status: Closed, classification: BenignPositive, ...}

ARM naming
----------
Automation rules are addressed by GUID. A collected rule keeps its
portal GUID in ``metadata.arm_name``; an authored rule gets a stable
``uuid5(NAMESPACE_URL, envelope.id)`` so PUTs are idempotent.

Verification
------------
``_automation_projection`` hashes a derived view: trigger flags, action
types and settings, condition keys and values, playbook ids, expiration
presence. It is order-independent and ignores what ARM adds on the way
back (``canonical_for_verify``; checked against a workspace: null for
fields left out, ``labelType: "User"``, re-cased resource ids), so a
rule that closes with another status or matches another scope fails
the check, while the rule that was sent passes it.

Expired rules
-------------
ARM rejects a PUT whose ``expirationTimeUtc`` is in the past, so apply
skips those with a clear detail; collect imports them as
``status: deprecated`` so the active set stays honest.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

import click

from contentops.core.asset import Asset, COLLECT_BASELINE_VERSION
from contentops.core.handler import LoadedAsset
from contentops.core.result import ActionResult, PlanAction
from contentops.handlers._verify import (
    ETAG_CONFLICT_MESSAGE,
    canonical_for_verify,
    compute_projection_hash,
    extract_etag,
    hash_mismatch_error,
)
from contentops.handlers.sentinel_automation_rule_models import (
    ANALYTIC_REF_PREFIX,
    ANALYTIC_RULE_ID_PROPERTIES,
    AUTOMATION_API_VERSION,
    SentinelAutomationRulePayload,
    analytic_arm_name_from_resource_id,
    analytic_rule_resource_id,
    envelope_id_to_guid,
    is_expired,
    logic_app_name_from_resource_id,
    logic_app_resource_id,
    normalize_expiration,
    to_automation_rule_arm_body,
)
from contentops.providers.sentinel_arm import SentinelArmProvider
from contentops.utils.slug import displayname_slug

logger = logging.getLogger(__name__)

AUTOMATION_RULES = "automationRules"

_SERVER_FIELDS = ("id", "type", "etag", "systemData")
_SERVER_PROPERTY_FIELDS = (
    "createdBy", "createdTimeUtc", "lastModifiedBy", "lastModifiedTimeUtc",
)

EXPIRED_DETAIL = (
    "expirationTimeUtc is in the past; ARM rejects expired automation rules — "
    "bump or remove expirationTimeUtc, or mark the envelope deprecated"
)


def _strip_server_fields(remote: dict) -> dict:
    """Return ``remote`` without server-managed top-level + properties.* fields.

    Pure (defensive copy); used by the ``sentinel-roundtrip-diff`` diagnostic.
    """
    cleaned = {k: v for k, v in remote.items() if k not in _SERVER_FIELDS}
    block = cleaned.get("properties")
    if isinstance(block, dict):
        cleaned["properties"] = {
            k: v for k, v in block.items() if k not in _SERVER_PROPERTY_FIELDS
        }
    return cleaned


def _automation_projection(body: dict) -> dict:
    """Order-independent projection of the security-relevant fields."""
    props = body.get("properties") or {}
    triggering_logic = props.get("triggeringLogic") or {}
    actions = props.get("actions") or []
    conditions = triggering_logic.get("conditions") or []

    def _action_types(items: list) -> list[str]:
        return sorted(str((a or {}).get("actionType") or "") for a in items)

    def _condition_keys(items: list) -> list[str]:
        keys: list[str] = []
        for c in items:
            cp = (c or {}).get("conditionProperties") or {}
            keys.append(
                f"{(c or {}).get('conditionType') or ''}:"
                f"{cp.get('propertyName') or ''}:"
                f"{cp.get('operator') or ''}"
            )
        return sorted(keys)

    def _playbook_ids(items: list) -> list[str]:
        out: list[str] = []
        for a in items:
            if (a or {}).get("actionType") != "RunPlaybook":
                continue
            cfg = (a or {}).get("actionConfiguration") or {}
            rid = cfg.get("logicAppResourceId")
            if rid:
                out.append(str(rid).lower())
        return sorted(out)

    return {
        "displayName": props.get("displayName"),
        "order": props.get("order"),
        "isEnabled": triggering_logic.get("isEnabled"),
        "triggersOn": triggering_logic.get("triggersOn"),
        "triggersWhen": triggering_logic.get("triggersWhen"),
        "hasExpiration": bool(triggering_logic.get("expirationTimeUtc")),
        "actionCount": len(actions),
        "actionTypes": _action_types(actions),
        "playbookIds": _playbook_ids(actions),
        "conditionCount": len(conditions),
        "conditionKeys": _condition_keys(conditions),
        # What the rule does, not only its shape: each action's settings
        # (a close status, a classification, a severity, a playbook) and
        # each condition's values (a title match, an analytic scope), in
        # the form that ignores what ARM adds or re-cases on the way back.
        "actions": canonical_for_verify([
            {"order": (a or {}).get("order"), "actionType": (a or {}).get("actionType"),
             "actionConfiguration": (a or {}).get("actionConfiguration")}
            for a in actions
        ]),
        "conditions": canonical_for_verify(conditions),
    }


class SentinelAutomationRuleHandler:
    asset = Asset.SENTINEL_AUTOMATION_RULE

    def __init__(
        self,
        provider_factory: Callable[[], SentinelArmProvider | None],
        *,
        tenant_id: str | None = None,
        detections_root: Path | None = None,
    ) -> None:
        self._provider_factory = provider_factory
        self._provider: SentinelArmProvider | None = None
        self._tenant_id = tenant_id
        self._detections_root = detections_root
        self._analytic_index: dict[str, str] | None = None
        self._playbook_index: dict[str, str] | None = None

    def _provider_or_create(self) -> SentinelArmProvider | None:
        if self._provider is None:
            self._provider = self._provider_factory()
        return self._provider

    # --- reference resolution -------------------------------------------

    def _analytics(self) -> dict[str, str]:
        """``envelope id -> ARM name`` for every local ``sentinel_analytic``."""
        if self._analytic_index is None:
            from contentops.core.discovery import iter_loaded_assets
            root = self._detections_root or Path("detections")
            index: dict[str, str] = {}
            for la in iter_loaded_assets(root):
                if la.envelope.asset is Asset.SENTINEL_ANALYTIC:
                    index[la.envelope.id] = la.envelope.arm_name or la.envelope.id
            self._analytic_index = index
        return self._analytic_index

    def _playbooks(self) -> dict[str, str]:
        """``envelope id -> workflow name`` for every local ``sentinel_playbook``.

        The workflow name is the one the playbook handler deploys under:
        ``metadata.arm_name`` (a collected Logic App keeps its own name,
        e.g. ``Notify_SOC`` for envelope ``notify-soc``), else the id.
        """
        if self._playbook_index is None:
            from contentops.core.discovery import iter_loaded_assets
            root = self._detections_root or Path("detections")
            self._playbook_index = {
                la.envelope.id: la.envelope.arm_name or la.envelope.id
                for la in iter_loaded_assets(root)
                if la.envelope.asset is Asset.SENTINEL_PLAYBOOK
            }
        return self._playbook_index

    def add_collected(self, *, analytics: dict[str, str], playbooks: dict[str, str]) -> None:
        """Envelopes the same collect / drift run writes as new
        (``envelope id -> ARM name`` / ``-> workflow name``), for the reverse
        mapping: on a first collect the analytic and playbook files are not
        on disk yet, and the rule would keep the raw resource id (with the
        subscription GUID) and ``logicApp:``. A file on disk for the same
        object wins; its id is the one the run keeps."""
        index = self._analytics()
        known = set(index.values())
        for envelope_id, arm_name in analytics.items():
            if arm_name not in known and envelope_id not in index:
                index[envelope_id] = arm_name
        pb_index = self._playbooks()
        known_pb = {name.lower() for name in pb_index.values()}
        for envelope_id, workflow_name in playbooks.items():
            if workflow_name.lower() not in known_pb and envelope_id not in pb_index:
                pb_index[envelope_id] = workflow_name

    def _playbook_envelope_for(self, workflow_name: str) -> str | None:
        """The local playbook envelope that deploys ``workflow_name`` (ARM
        names are case-insensitive), or None.

        ``playbook:`` names an envelope (lint and the dependency check hold
        it to one), so collect writes it only when that envelope exists.
        Otherwise the rule keeps ``logicApp: <name>``, which deploys the
        same way and needs no envelope. The managed tag alone is not
        enough: the playbook's own file may not be written (collect of
        rules only, playbooks switched off, the playbook skipped).
        """
        wanted = workflow_name.lower()
        for envelope_id, name in self._playbooks().items():
            if name.lower() == wanted:
                return envelope_id
        return None

    def _resolve_playbook(self, playbook_id: str) -> tuple[str, str | None]:
        provider = self._provider_or_create()
        if provider is None:
            raise ValueError("resolving `playbook:` references requires a Sentinel provider")
        cfg = provider.config
        workflow_name = self._playbooks().get(playbook_id, playbook_id)
        return (
            logic_app_resource_id(
                cfg.subscriptionId, cfg.effective_playbooks_resource_group, workflow_name,
            ),
            self._tenant_id,
        )

    def _resolve_analytic(self, envelope_id: str) -> str:
        provider = self._provider_or_create()
        if provider is None:
            raise ValueError("resolving `analytic:` references requires a Sentinel provider")
        arm_name = self._analytics().get(envelope_id)
        if arm_name is None:
            raise ValueError(
                f"condition references analytic:{envelope_id!r} but no "
                f"detections/sentinel_analytic/{envelope_id}.yml exists"
            )
        return analytic_rule_resource_id(provider.loganalytics_workspace_path, arm_name)

    # --- Handler protocol -------------------------------------------------

    def validate(self, loaded: LoadedAsset) -> None:
        SentinelAutomationRulePayload(**loaded.payload)

    def plan(self, loaded: LoadedAsset) -> ActionResult:
        if loaded.envelope.status == "experimental":
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.SKIP, status="planned",
                detail="experimental status — skipped",
            )
        logic = loaded.payload.get("triggeringLogic") or {}
        if is_expired(logic.get("expirationTimeUtc")):
            # Also when deprecated: collect imports an expired rule as
            # deprecated; it does nothing any more, and a PUT with an
            # expiry in the past can be refused.
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.SKIP, status="planned", detail=EXPIRED_DETAIL,
            )
        if loaded.envelope.status == "deprecated":
            # Switched off, like a deprecated analytic (``contentops
            # disable`` sets this status). Deleting stays with ``prune``.
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.DISABLE, status="planned",
                detail="deprecated — deployed with isEnabled: false",
            )
        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=PlanAction.UPDATE, status="planned",
        )

    def apply(self, loaded: LoadedAsset, *, dry_run: bool = False) -> ActionResult:
        plan = self.plan(loaded)
        if plan.action is PlanAction.SKIP:
            click.echo(f"  skipped ({plan.detail}): {loaded.envelope.id}")
            return ActionResult(
                asset_id=plan.asset_id, asset_kind=plan.asset_kind,
                action=plan.action, status="skipped", detail=plan.detail,
            )

        if dry_run:
            click.echo(f"  [DRY-RUN] Would PUT automationRule: {loaded.envelope.id}")
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE, status="dry-run",
            )

        provider = self._provider_or_create()
        assert provider is not None
        body = to_automation_rule_arm_body(
            loaded.payload,
            resolve_playbook=self._resolve_playbook,
            resolve_analytic=self._resolve_analytic,
        )
        disabling = plan.action is PlanAction.DISABLE
        if disabling:
            body["properties"]["triggeringLogic"] = {
                **(body["properties"].get("triggeringLogic") or {}), "isEnabled": False,
            }
        guid = loaded.envelope.arm_name or envelope_id_to_guid(loaded.envelope.id)
        url = provider.resource_url(AUTOMATION_RULES, guid, api_version=AUTOMATION_API_VERSION)

        existing = provider.get_resource(
            AUTOMATION_RULES, guid, api_version=AUTOMATION_API_VERSION,
        )
        etag = extract_etag(existing)

        sent_hash = compute_projection_hash(_automation_projection(body))
        headers = {"If-Match": etag} if etag else None
        response = provider.request("PUT", url, json=body, headers=headers)

        if response.status_code == 412:
            click.echo(f"  etag-conflict: {loaded.envelope.id}", err=True)
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE, status="error-412",
                detail=ETAG_CONFLICT_MESSAGE,
                verified=False, error=ETAG_CONFLICT_MESSAGE,
            )

        if response.status_code not in (200, 201):
            logger.error(
                "Failed to deploy automation rule %s: %s %s",
                loaded.envelope.id, response.status_code, response.text,
            )
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE, status=f"error-{response.status_code}",
                detail=response.text[:200],
                verified=False, error=response.text[:200],
            )

        if disabling:
            action = PlanAction.DISABLE
        else:
            action = PlanAction.CREATE if response.status_code == 201 else PlanAction.UPDATE
        click.echo(f"  {action.value}: {loaded.envelope.id}")

        verified_remote = provider.get_resource(
            AUTOMATION_RULES, guid, api_version=AUTOMATION_API_VERSION,
        )
        if verified_remote is None:
            err = "post-apply GET returned 404"
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=action, status="success", detail=err,
                verified=False, error=err,
            )
        got_hash = compute_projection_hash(_automation_projection(verified_remote))
        if got_hash != sent_hash:
            err = hash_mismatch_error(sent_hash, got_hash)
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=action, status="success", detail=err,
                verified=False, error=err,
            )

        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=action, status="success", verified=True,
            extra={"arm_name": guid},
        )

    def close(self) -> None:
        if self._provider is not None:
            self._provider.close()
            self._provider = None

    def delete(self, remote_id: str) -> ActionResult:
        """DELETE one automation rule by ARM resource name (GUID)."""
        from contentops.core.result import NotSupportedError
        from contentops.handlers._delete import (
            delete_result_from_exception, delete_result_from_response,
        )
        provider = self._provider_or_create()
        if provider is None:
            raise NotSupportedError(
                "sentinel_automation_rule delete requires a SentinelArmProvider"
            )
        try:
            response = provider.delete_resource(
                AUTOMATION_RULES, remote_id, api_version=AUTOMATION_API_VERSION,
            )
        except Exception as exc:  # pragma: no cover
            return delete_result_from_exception(remote_id, self.asset, exc)
        return delete_result_from_response(remote_id, self.asset, response)

    def disable_in_place(self, loaded: LoadedAsset) -> ActionResult:
        """Switch the tenant's rule off as it is (a locked rule set to
        deprecated): its conditions and actions go back unchanged; only
        ``isEnabled`` changes. An expired rule no longer runs: it counts as
        off and is not written."""
        from contentops.handlers._disable_in_place import disable_existing

        provider = self._provider_or_create()
        if provider is None:
            raise RuntimeError("sentinel_automation_rule disable_in_place requires a SentinelArmProvider")
        guid = loaded.envelope.arm_name or envelope_id_to_guid(loaded.envelope.id)
        url = provider.resource_url(AUTOMATION_RULES, guid, api_version=AUTOMATION_API_VERSION)

        def read() -> dict | None:
            return provider.get_resource(AUTOMATION_RULES, guid, api_version=AUTOMATION_API_VERSION)

        def is_off(obj: dict) -> bool:
            logic = (obj.get("properties") or {}).get("triggeringLogic") or {}
            return logic.get("isEnabled") is False or is_expired(logic.get("expirationTimeUtc"))

        def switch_off(existing: dict):
            props = dict(_strip_server_fields(existing).get("properties") or {})
            props["triggeringLogic"] = {**(props.get("triggeringLogic") or {}), "isEnabled": False}
            etag = extract_etag(existing)
            headers = {"If-Match": etag} if etag else None
            return provider.request("PUT", url, json={"properties": props}, headers=headers)

        result = disable_existing(
            asset_kind=self.asset.value, envelope_id=loaded.envelope.id,
            existing=read(), is_off=is_off, switch_off=switch_off, read_back=read,
        )
        click.echo(f"  {result.action.value}: {loaded.envelope.id} ({result.detail})")
        return result

    # --- Drift support -------------------------------------------------

    def list_remote(self) -> list[dict]:
        provider = self._provider_or_create()
        if provider is None:
            return []
        return provider.list_resource(AUTOMATION_RULES, api_version=AUTOMATION_API_VERSION)

    def to_envelope(self, remote: dict) -> dict | None:
        name = remote.get("name")
        if not name:
            return None
        properties: dict = dict(_strip_server_fields(remote).get("properties") or {})
        display_name = properties.get("displayName") or ""
        env_id = displayname_slug(display_name, fallback_id=str(name))
        if not env_id:
            logger.debug(
                "Skipping automation rule %r — displayName %r yields no valid id",
                name, display_name,
            )
            return None

        logic: dict = dict(properties.get("triggeringLogic") or {})
        if logic.get("expirationTimeUtc"):
            logic["expirationTimeUtc"] = normalize_expiration(logic["expirationTimeUtc"])
        logic["conditions"] = [
            self._reverse_condition(c) for c in (logic.get("conditions") or [])
        ]
        actions = [self._reverse_action(a) for a in (properties.get("actions") or [])]

        payload: dict = {
            "displayName": display_name,
            "order": properties.get("order", 1),
            "triggeringLogic": logic,
            "actions": actions,
        }
        status = "deprecated" if is_expired(logic.get("expirationTimeUtc")) else "production"
        return {
            "id": env_id,
            "version": COLLECT_BASELINE_VERSION,
            "asset": Asset.SENTINEL_AUTOMATION_RULE.value,
            "status": status,
            "metadata": {"arm_name": str(name)},
            "payload": payload,
        }

    # --- reverse mapping (collect) ----------------------------------------

    def _reverse_action(self, action: dict) -> dict:
        action = dict(action or {})
        if action.get("actionType") != "RunPlaybook":
            return action
        cfg = dict(action.get("actionConfiguration") or {})
        rid = cfg.get("logicAppResourceId")
        provider = self._provider_or_create()
        if rid and provider is not None:
            cfgw = provider.config
            where = {
                "subscription_id": cfgw.subscriptionId,
                "resource_group": cfgw.effective_playbooks_resource_group,
            }
            name = logic_app_name_from_resource_id(str(rid), **where)
            if name:
                # ``playbook:`` names an envelope (lint and the dependency
                # check hold it to one); a Logic App ContentOps does not
                # manage keeps its exact name under ``logicApp:``. Either
                # way the subscription GUID stays out of the file.
                cfg.pop("logicAppResourceId", None)
                pid = self._playbook_envelope_for(name)
                if pid:
                    cfg["playbook"] = pid
                else:
                    cfg["logicApp"] = name
                if self._tenant_id and str(cfg.get("tenantId", "")).lower() == self._tenant_id.lower():
                    cfg.pop("tenantId", None)
        action["actionConfiguration"] = cfg
        return action

    def _reverse_condition(self, cond: dict) -> dict:
        cond = dict(cond or {})
        props = cond.get("conditionProperties")
        if not isinstance(props, dict):
            return cond
        props = dict(props)
        for key in ("innerConditions", "itemConditions"):
            inner = props.get(key)
            if isinstance(inner, list):
                props[key] = [
                    self._reverse_condition(c) if isinstance(c, dict) else c for c in inner
                ]
        provider = self._provider_or_create()
        if provider is not None and props.get("propertyName") in ANALYTIC_RULE_ID_PROPERTIES:
            by_arm = {arm: eid for eid, arm in self._analytics().items()}
            values = props.get("propertyValues")
            if isinstance(values, list):
                reversed_values: list = []
                for v in values:
                    arm = (
                        analytic_arm_name_from_resource_id(
                            v, workspace_path=provider.loganalytics_workspace_path,
                        ) if isinstance(v, str) else None
                    )
                    eid = by_arm.get(arm) if arm else None
                    reversed_values.append(f"{ANALYTIC_REF_PREFIX}{eid}" if eid else v)
                props["propertyValues"] = reversed_values
        cond["conditionProperties"] = props
        return cond
