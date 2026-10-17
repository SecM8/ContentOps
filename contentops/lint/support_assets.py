# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Lint rules for the support-asset kinds (automation rules, playbooks).

These kinds carry no KQL, so the KQL / strict rules never run on them.
What can go wrong is referential and operational instead, and that is
what this module checks:

* **PAYLOAD007** (error, automation rule) — a ``playbook:`` action or
  an ``analytic:`` scope condition references an envelope id that does
  not exist in the repo. Apply would fail against ARM (400) or scope
  nothing; the dependency validator refuses the same thing at
  plan-time, this surfaces it at PR-time.
* **PAYLOAD008** (warning, automation rule) — ``expirationTimeUtc`` is
  in the past: the rule is dormant in the tenant and apply skips it.
* **PAYLOAD009** (warning, automation rule) — two rules with the same
  trigger share an ``order``. ARM accepts duplicates and runs them in
  an unspecified order; execution sequence is security-relevant.
* **PAYLOAD010** (warning, playbook) — a connection declares an
  ``authMode`` for a connector outside the known managed-identity
  table (it may need interactive consent after deploy).
* **PAYLOAD012** (warning, playbook) — the playbook uses the Sentinel
  connector but declares no ``roleAssignments`` for its managed
  identity, so nothing will tell the operator which roles to grant.
* **PAYLOAD014** (error, automation rule) — a ``ModifyProperties``
  action sets ``status: Closed`` and the rule has NO conditions: it
  would auto-close every incident in the workspace. Also warns when a
  close rule has no analytics-rule / custom-detection scope condition.

PAYLOAD007 and PAYLOAD009 need the whole repo (cross-envelope), so
``lint_support_assets_repo`` runs once after the per-envelope loop;
the rest run per envelope via ``lint_support_asset_payload``.
"""

from __future__ import annotations

from typing import Any, Iterable

from contentops.core.asset import Asset
from contentops.core.handler import LoadedAsset
from contentops.handlers.sentinel_automation_rule_models import (
    analytic_refs,
    analytic_scope_conditions,
    closes_incidents,
    is_expired,
    playbook_refs,
)
from contentops.handlers.sentinel_playbook_models import MANAGED_IDENTITY_APIS
from contentops.lint.kql import LintFinding


def lint_support_asset_payload(
    payload: dict[str, Any], *, asset: Asset,
) -> list[LintFinding]:
    """Per-envelope rules: PAYLOAD008 / 010 / 012 / 014."""
    findings: list[LintFinding] = []
    if asset is Asset.SENTINEL_AUTOMATION_RULE:
        findings.extend(_check_expired(payload))
        findings.extend(_check_unscoped_close(payload))
    elif asset is Asset.SENTINEL_PLAYBOOK:
        findings.extend(_check_connection_auth(payload))
        findings.extend(_check_role_assignments_declared(payload))
    return findings


def lint_support_assets_repo(loaded: Iterable[LoadedAsset]) -> dict[Any, list[LintFinding]]:
    """Repo-wide rules: PAYLOAD007 / 009. Returns ``{path: findings}``."""
    loaded = list(loaded)
    playbooks = {la.envelope.id for la in loaded if la.envelope.asset is Asset.SENTINEL_PLAYBOOK}
    analytics = {la.envelope.id for la in loaded if la.envelope.asset is Asset.SENTINEL_ANALYTIC}
    rules = [la for la in loaded if la.envelope.asset is Asset.SENTINEL_AUTOMATION_RULE]
    out: dict[Any, list[LintFinding]] = {}

    for la in rules:
        found: list[LintFinding] = []
        for pb in playbook_refs(la.payload):
            if pb not in playbooks:
                found.append(LintFinding(
                    rule_id="PAYLOAD007", severity="error",
                    message=(
                        f"RunPlaybook action references playbook {pb!r} but no "
                        f"detections/sentinel_playbook/{pb}.yml exists."
                    ),
                ))
        for an in analytic_refs(la.payload):
            if an not in analytics:
                found.append(LintFinding(
                    rule_id="PAYLOAD007", severity="error",
                    message=(
                        f"condition references analytic:{an} but no "
                        f"detections/sentinel_analytic/{an}.yml exists."
                    ),
                ))
        if found:
            out.setdefault(la.path, []).extend(found)

    # PAYLOAD009 — duplicate order within a trigger.
    by_trigger: dict[tuple[str, str, Any], list[LoadedAsset]] = {}
    for la in rules:
        logic = la.payload.get("triggeringLogic") or {}
        key = (
            str(logic.get("triggersOn", "Incidents")),
            str(logic.get("triggersWhen", "Created")),
            la.payload.get("order"),
        )
        by_trigger.setdefault(key, []).append(la)
    for (on, when, order), group in by_trigger.items():
        if order is None or len(group) < 2:
            continue
        ids = sorted(la.envelope.id for la in group)
        for la in group:
            others = [i for i in ids if i != la.envelope.id]
            out.setdefault(la.path, []).append(LintFinding(
                rule_id="PAYLOAD009", severity="warning",
                message=(
                    f"order {order} is shared with {others} on the same trigger "
                    f"({on}/{when}); Sentinel runs same-order rules in an "
                    "unspecified sequence. Give each rule a distinct order."
                ),
            ))
    return out


# ---------------------------------------------------------------------------
# per-envelope checks
# ---------------------------------------------------------------------------


def _check_expired(payload: dict[str, Any]) -> list[LintFinding]:
    logic = payload.get("triggeringLogic") or {}
    exp = logic.get("expirationTimeUtc") if isinstance(logic, dict) else None
    if exp and is_expired(exp):
        return [LintFinding(
            rule_id="PAYLOAD008", severity="warning",
            message=(
                f"expirationTimeUtc={exp!r} is in the past; the rule is dormant in "
                "the tenant and apply skips it. Extend the expiry or mark the "
                "envelope `status: deprecated`."
            ),
        )]
    return []


def _check_unscoped_close(payload: dict[str, Any]) -> list[LintFinding]:
    if not closes_incidents(payload):
        return []
    logic = payload.get("triggeringLogic") or {}
    conditions = logic.get("conditions") if isinstance(logic, dict) else None
    if not conditions:
        return [LintFinding(
            rule_id="PAYLOAD014", severity="error",
            message=(
                "this rule closes incidents and has NO conditions — it would "
                "auto-close every incident in the workspace. Add at least one "
                "scope condition (e.g. IncidentRelatedAnalyticRuleIds)."
            ),
        )]
    if not analytic_scope_conditions(payload):
        return [LintFinding(
            rule_id="PAYLOAD014", severity="warning",
            message=(
                "this rule closes incidents but is not scoped to specific "
                "analytics / custom-detection rules; confirm the entity "
                "conditions are narrow enough."
            ),
        )]
    return []


def _check_connection_auth(payload: dict[str, Any]) -> list[LintFinding]:
    findings: list[LintFinding] = []
    for conn in payload.get("connections") or []:
        if not isinstance(conn, dict):
            continue
        api = str(conn.get("apiName") or conn.get("name") or "").lower()
        if api and api not in MANAGED_IDENTITY_APIS and conn.get("authMode"):
            findings.append(LintFinding(
                rule_id="PAYLOAD010", severity="warning",
                message=(
                    f"connection {conn.get('name')!r}: connector {api!r} is not in the "
                    "known managed-identity table; if it needs interactive consent "
                    "the playbook will not run after deploy. Verify in the designer."
                ),
            ))
    return findings


def _check_role_assignments_declared(payload: dict[str, Any]) -> list[LintFinding]:
    uses_sentinel = any(
        isinstance(c, dict)
        and str(c.get("apiName") or c.get("name") or "").lower() == "azuresentinel"
        for c in payload.get("connections") or []
    )
    if uses_sentinel and not payload.get("roleAssignments"):
        return [LintFinding(
            rule_id="PAYLOAD012", severity="warning",
            message=(
                "playbook uses the azuresentinel connector but declares no "
                "roleAssignments; declare e.g. {role: Microsoft Sentinel "
                "Responder, scope: workspace} so apply/conformance can report "
                "what the managed identity still needs."
            ),
        )]
    return []


__all__ = ["lint_support_asset_payload", "lint_support_assets_repo"]
