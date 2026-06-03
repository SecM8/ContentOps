# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Microsoft-shipped Alert Rule Template fetch / scaffold helpers.

Backs the ``contentops new --from-template <template-name>`` flow. The
template list is large (500+ rules in production) so we always do a
targeted GET-by-name rather than walking the full catalog.

Templates expose roughly the same property shape as Scheduled /
NRT / MicrosoftSecurityIncidentCreation alert rules; we map the
fields that exist into a YAML envelope ready for ``contentops plan``
and ``contentops apply``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from contentops.core.asset import Asset, COLLECT_BASELINE_VERSION
from contentops.providers.sentinel_arm import SentinelArmProvider


_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$")
_SLUG_RE = re.compile(r"[^a-z0-9]+")


class TemplateError(Exception):
    """Raised when a template can't be resolved."""

    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _slugify(name: str) -> str:
    slug = _SLUG_RE.sub("-", (name or "").lower()).strip("-")
    return slug if _ID_RE.match(slug) else ""


def fetch_template(provider: SentinelArmProvider, template_name: str) -> dict:
    """Fetch a single alertRuleTemplate by ARM ``name`` (a GUID).

    Raises ``TemplateError`` on 404 / other non-200 responses.
    """
    response = provider.request(
        "GET", provider.resource_url("alertRuleTemplates", template_name),
    )
    if response.status_code == 404:
        raise TemplateError(
            f"alertRuleTemplate {template_name!r} not found in this workspace. "
            "Templates are workspace-scoped — install the appropriate Content "
            "Hub solution before using its templates."
        )
    response.raise_for_status()
    return response.json()


def search_templates(
    provider: SentinelArmProvider,
    query: str,
    *,
    limit: int = 20,
) -> list[dict]:
    """List templates whose name or displayName contains ``query``.

    Case-insensitive substring match. Returns up to ``limit`` items.
    """
    query_lower = query.lower()
    items = provider.list_resource("alertRuleTemplates")
    matches: list[dict] = []
    for item in items:
        name = (item.get("name") or "").lower()
        properties = item.get("properties") or {}
        display_name = (properties.get("displayName") or "").lower()
        if query_lower in name or query_lower in display_name:
            matches.append(item)
            if len(matches) >= limit:
                break
    return matches


_DEFAULT_METADATA: dict = {
    "owner": "detection-engineering@example.com",
    "runbookUrl": "https://example.com/runbooks/REPLACE-ME",
    "severity": "medium",
    "tactics": ["InitialAccess"],
    "techniques": [],
    "expectedAlertsPerDay": 1,
    "fpHandling": (
        "TODO: review FP rate over the next 7 days and tune threshold / "
        "filters before promoting to production."
    ),
}

_TACTIC_TO_METADATA = {
    "Reconnaissance": "InitialAccess",
    "ResourceDevelopment": "InitialAccess",
    "InitialAccess": "InitialAccess",
    "Execution": "Execution",
    "Persistence": "Persistence",
    "PrivilegeEscalation": "PrivilegeEscalation",
    "DefenseEvasion": "DefenseEvasion",
    "CredentialAccess": "CredentialAccess",
    "Discovery": "Discovery",
    "LateralMovement": "LateralMovement",
    "Collection": "Collection",
    "CommandAndControl": "CommandAndControl",
    "Exfiltration": "Exfiltration",
    "Impact": "Impact",
}


def _project_metadata(template_props: dict) -> dict:
    """Build a metadata block from the template's known fields."""
    severity = (template_props.get("severity") or "Medium").lower()
    if severity not in {"informational", "low", "medium", "high"}:
        severity = "medium"

    template_tactics = template_props.get("tactics") or []
    metadata_tactics = []
    for t in template_tactics:
        mapped = _TACTIC_TO_METADATA.get(t)
        if mapped and mapped not in metadata_tactics:
            metadata_tactics.append(mapped)
    if not metadata_tactics:
        metadata_tactics = ["InitialAccess"]

    techniques = list(template_props.get("techniques") or [])
    return {
        **_DEFAULT_METADATA,
        "severity": severity,
        "tactics": metadata_tactics,
        "techniques": techniques,
    }


def _project_payload(template: dict) -> dict:
    """Pull the writable fields out of a template into an alertRule payload."""
    kind = template.get("kind") or "Scheduled"
    template_props = template.get("properties") or {}
    template_name = template.get("name") or ""
    template_version = template_props.get("version")

    if kind in ("Fusion", "MLBehaviorAnalytics", "ThreatIntelligence"):
        # Toggle-only kinds — payload is just the template reference + enable.
        return {
            "kind": kind,
            "alertRuleTemplateName": template_name,
            "enabled": True,
        }

    if kind == "MicrosoftSecurityIncidentCreation":
        return {
            "kind": kind,
            "displayName": template_props.get("displayName") or "",
            "description": template_props.get("description"),
            "enabled": True,
            "productFilter": template_props.get("productFilter") or "Microsoft Cloud App Security",
            "alertRuleTemplateName": template_name,
            "templateVersion": template_version,
        }

    # Scheduled or NRT — copy the rich set of fields.
    payload: dict = {
        "kind": kind,
        "displayName": template_props.get("displayName") or "",
        "description": template_props.get("description"),
        "enabled": True,
        "severity": template_props.get("severity") or "Medium",
        "query": template_props.get("query") or "// TODO: paste KQL",
        "tactics": template_props.get("tactics") or [],
        "techniques": template_props.get("techniques") or [],
        "alertRuleTemplateName": template_name,
        "templateVersion": template_version,
    }
    if kind == "Scheduled":
        payload.update({
            "queryFrequency": template_props.get("queryFrequency") or "PT1H",
            "queryPeriod": template_props.get("queryPeriod") or "PT1H",
            "triggerOperator": template_props.get("triggerOperator") or "GreaterThan",
            "triggerThreshold": template_props.get("triggerThreshold") or 0,
        })
    if template_props.get("entityMappings"):
        payload["entityMappings"] = template_props["entityMappings"]
    return {k: v for k, v in payload.items() if v is not None}


def envelope_from_template(
    template: dict, *, override_id: str | None = None,
) -> dict:
    """Convert a remote alertRuleTemplate dict into a v2 envelope dict."""
    template_props = template.get("properties") or {}
    display_name = template_props.get("displayName") or template.get("name", "")
    derived_id = _slugify(display_name)
    if override_id:
        if not _ID_RE.match(override_id):
            raise TemplateError(
                f"override id {override_id!r} fails the envelope id regex"
            )
        env_id = override_id
    elif derived_id:
        env_id = derived_id
    else:
        raise TemplateError(
            "could not derive a valid envelope id from the template displayName "
            f"({display_name!r}) — pass --id to override"
        )

    return {
        "id": env_id,
        "version": COLLECT_BASELINE_VERSION,
        "asset": Asset.SENTINEL_ANALYTIC.value,
        "status": "experimental",
        "metadata": _project_metadata(template_props),
        "payload": _project_payload(template),
    }


def scaffold_from_template(
    provider: SentinelArmProvider,
    template_name: str,
    *,
    override_id: str | None = None,
    out_path: Path | None = None,
    force: bool = False,
) -> Path:
    """Resolve, project, and write an envelope from a template GUID.

    Returns the absolute path to the YAML file on disk.
    """
    template = fetch_template(provider, template_name)
    envelope = envelope_from_template(template, override_id=override_id)
    target = out_path or Path("detections") / envelope["asset"] / f"{envelope['id']}.yml"
    target = Path(target)
    if target.exists() and not force:
        raise TemplateError(
            f"refusing to overwrite existing file: {target} (pass --force to replace)",
            exit_code=1,
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        yaml.safe_dump(envelope, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return target
