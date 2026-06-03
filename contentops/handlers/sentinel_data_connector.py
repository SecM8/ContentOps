# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Sentinel data connector handler.

ARM resource: ``Microsoft.SecurityInsights/dataConnectors``
API version:  ``2025-07-01-preview``

Connectors are kind-discriminated. ARM lists ~21 ``kind`` values today
(AzureActiveDirectory, Office365, MicrosoftDefenderAdvancedThreatProtection,
RestApiPoller, GenericUI, ...), and Microsoft adds more. The pipeline
treats connectors as **declarative desired state** (DESIGN §5.7):
the YAML says "this connector should be enabled" and the handler
reconciles it against the workspace state.

Two important caveats — both flagged in handler output:
1. Many connector kinds require a one-time interactive consent in the
   portal that can't be scripted. We PUT what we can; if the connector
   ends up in a "not connected" state, that's a manual-step warning,
   not a hard apply failure.
2. Codeless Connector Platform (CCP) connectors live alongside the
   classic ones but follow a different shape. Both are accepted via
   the permissive Pydantic model (``extra='allow'``).
"""

from __future__ import annotations

import logging
import re
from typing import Callable

import click
from pydantic import BaseModel, ConfigDict, Field

# Inlined from the deleted ``contentops/handlers/sentinel_readonly`` module
# Same shape as the validator on EnvelopeV2.id.
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]*[a-z0-9]$")

from contentops.core.asset import Asset, COLLECT_BASELINE_VERSION
from contentops.core.handler import LoadedAsset
from contentops.core.result import ActionResult, PlanAction
from contentops.handlers._verify import (
    ETAG_CONFLICT_MESSAGE,
    compute_projection_hash,
    extract_etag,
    hash_mismatch_error,
)
from contentops.providers.sentinel_arm import SentinelArmProvider

logger = logging.getLogger(__name__)

DATA_CONNECTORS = "dataConnectors"

# Known connector kinds per ARM 2025-07-01-preview. Pinned as a tuple
# for visibility — the model uses extra='allow' so a new kind landing
# upstream doesn't immediately break PRs.
KNOWN_CONNECTOR_KINDS = (
    "AzureActiveDirectory",
    "AzureSecurityCenter",
    "MicrosoftCloudAppSecurity",
    "ThreatIntelligence",
    "ThreatIntelligenceTaxii",
    "Office365",
    "AmazonWebServicesCloudTrail",
    "AmazonWebServicesS3",
    "MicrosoftDefenderAdvancedThreatProtection",
    "OfficeATP",
    "OfficeIRM",
    "Dynamics365",
    "MicrosoftThreatProtection",
    "MicrosoftThreatIntelligence",
    "GenericUI",
    "IOT",
    "GCP",
    "APIPolling",
    "RestApiPoller",
    "Codeless",
    "OfficePowerBI",
)


class SentinelDataConnectorPayload(BaseModel):
    """Permissive connector payload.

    The ARM ``kind`` discriminator is enforced; everything else passes
    through. Each ``kind`` carries its own ``properties.dataTypes``
    shape and we document those in the asset doc rather than encoding
    them as Python types — the schema churns and a tight model would
    be wrong inside a quarter.
    """

    model_config = ConfigDict(extra="allow")

    kind: str = Field(min_length=1)
    requiresManualConsent: bool = False


def to_connector_arm_body(payload: dict) -> dict:
    SentinelDataConnectorPayload(**payload)
    body = dict(payload)
    kind = body.pop("kind")
    body.pop("requiresManualConsent", None)
    return {"kind": kind, "properties": body}


# Server-managed fields stripped before round-trip diff so the
# diagnostic shows the same canonical view ``apply`` would hash. Data
# connectors use ``_projection()`` (not ``_HASHED_FIELDS``) for hash
# compare; the diagnostic reaches into ``_projection`` directly.
_SERVER_FIELDS = ("etag", "type", "systemData")
_SERVER_PROPERTY_FIELDS: dict[str, frozenset[str]] = {
    "properties": frozenset({"connectorUiConfig", "lastModifiedUtc", "etag"}),
}


def _strip_server_fields(remote: dict) -> dict:
    """Return ``remote`` with server-managed fields removed (defensive copy)."""
    cleaned = {k: v for k, v in remote.items() if k not in _SERVER_FIELDS}
    for parent, nested in _SERVER_PROPERTY_FIELDS.items():
        block = cleaned.get(parent)
        if isinstance(block, dict):
            cleaned[parent] = {k: v for k, v in block.items() if k not in nested}
    return cleaned


def _projection(body: dict) -> dict:
    """Order-independent projection for hash compare."""
    properties = body.get("properties") or {}
    data_types = properties.get("dataTypes") or {}
    enabled_types = sorted(
        name for name, cfg in data_types.items()
        if isinstance(cfg, dict) and (cfg.get("state") == "enabled")
    )
    return {
        "kind": body.get("kind"),
        "tenantId": properties.get("tenantId"),
        "enabledDataTypes": enabled_types,
        "dataTypeCount": len(data_types),
    }


class SentinelDataConnectorHandler:
    asset = Asset.SENTINEL_DATA_CONNECTOR

    def __init__(self, provider_factory: Callable[[], SentinelArmProvider | None]) -> None:
        self._provider_factory = provider_factory
        self._provider: SentinelArmProvider | None = None

    def _provider_or_create(self) -> SentinelArmProvider | None:
        if self._provider is None:
            self._provider = self._provider_factory()
        return self._provider

    def validate(self, loaded: LoadedAsset) -> None:
        SentinelDataConnectorPayload(**loaded.payload)

    def plan(self, loaded: LoadedAsset) -> ActionResult:
        if loaded.envelope.status == "experimental":
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.SKIP, status="planned",
                detail="experimental status — skipped",
            )
        if loaded.envelope.status == "deprecated":
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.SKIP, status="planned",
                detail="deprecated connectors are not deleted by deploy; use `prune`",
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
            click.echo(f"  [DRY-RUN] Would PUT dataConnector: {loaded.envelope.id}")
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE, status="dry-run",
            )

        provider = self._provider_or_create()
        assert provider is not None
        body = to_connector_arm_body(loaded.payload)

        existing = provider.get_resource(DATA_CONNECTORS, loaded.envelope.id)
        # H-2: use the shared extract_etag so we pick up the nested
        # properties.etag form too (some preview API versions place it
        # there). Without this the data-connector PUT silently dropped
        # If-Match in those cases, overwriting concurrent edits.
        etag = extract_etag(existing)
        sent_hash = compute_projection_hash(_projection(body))
        headers = {"If-Match": etag} if etag else None
        response = provider.request(
            "PUT",
            provider.resource_url(DATA_CONNECTORS, loaded.envelope.id),
            json=body, headers=headers,
        )

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
                "Failed to deploy data connector %s: %s %s",
                loaded.envelope.id, response.status_code, response.text,
            )
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE,
                status=f"error-{response.status_code}",
                detail=response.text[:200],
                verified=False, error=response.text[:200],
            )

        action = PlanAction.CREATE if response.status_code == 201 else PlanAction.UPDATE
        click.echo(f"  {action.value}: {loaded.envelope.id}")

        verified = provider.get_resource(DATA_CONNECTORS, loaded.envelope.id)
        if verified is None:
            err = "post-apply GET returned 404"
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=action, status="success", detail=err,
                verified=False, error=err,
            )
        got_hash = compute_projection_hash(_projection(verified))
        if got_hash != sent_hash:
            err = hash_mismatch_error(sent_hash, got_hash)
            # H-3: a hash mismatch is still a real divergence between
            # what we sent and what ARM stored — the manual-consent
            # caveat affects whether the connector is *active*, not
            # whether the content matches. Surface verified=False so
            # the deploy gate catches body-rewrite bugs (e.g. ARM
            # stripping a connectorUiConfig field on validation), and
            # mention the manual-consent state in the detail string
            # so operators reading the report know it may be expected.
            consent_note = (
                " (manual portal consent still required for this kind)"
                if loaded.payload.get("requiresManualConsent") else ""
            )
            if consent_note:
                click.echo(
                    f"  [warn] {loaded.envelope.id}: connector body diverges; "
                    "manual portal consent also required",
                    err=True,
                )
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=action, status="success",
                detail=err + consent_note,
                verified=False, error=err,
            )

        return ActionResult(
            asset_id=loaded.envelope.id, asset_kind=self.asset.value,
            action=action, status="success", verified=True,
        )

    def close(self) -> None:
        if self._provider is not None:
            self._provider.close()
            self._provider = None

    def delete(self, remote_id: str) -> ActionResult:
        """DELETE one dataConnector by ARM resource name."""
        from contentops.core.result import NotSupportedError
        from contentops.handlers._delete import (
            delete_result_from_exception, delete_result_from_response,
        )
        provider = self._provider_or_create()
        if provider is None:
            raise NotSupportedError("sentinel_data_connector delete requires a SentinelArmProvider")
        try:
            response = provider.delete_resource(DATA_CONNECTORS, remote_id)
        except Exception as exc:  # pragma: no cover
            return delete_result_from_exception(remote_id, self.asset, exc)
        return delete_result_from_response(remote_id, self.asset, response)

    # --- Drift support -------------------------------------------------

    def list_remote(self) -> list[dict]:
        provider = self._provider_or_create()
        if provider is None:
            return []
        return provider.list_resource(DATA_CONNECTORS)

    def to_envelope(self, remote: dict) -> dict | None:
        name = remote.get("name")
        kind = remote.get("kind")
        if not name or not kind:
            return None
        if not _ID_RE.match(name):
            return None
        # GUID-named connectors aren't authored — they're whatever the
        # portal/API generated. Drift round-trip skips them so they
        # don't pollute the local YAML inventory.
        if re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            name,
        ):
            return None
        properties = dict(remote.get("properties") or {})
        # Drop server audit fields.
        for k in ("connectorUiConfig", "lastModifiedUtc", "etag"):
            properties.pop(k, None)
        payload = {"kind": kind, **properties}
        return {
            "id": name,
            "version": COLLECT_BASELINE_VERSION,
            "asset": Asset.SENTINEL_DATA_CONNECTOR.value,
            "status": "production",
            "payload": payload,
        }
