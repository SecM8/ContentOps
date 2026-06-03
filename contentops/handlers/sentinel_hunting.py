# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Sentinel hunting query handler — savedSearches via SentinelArmProvider.

Performs ETag-protected PUTs (the savedSearches 2023-09-01 API surface
does include ``etag`` in the GET response body) and a post-apply
content-hash check. A 412 conflict is reported as a per-asset failure.
"""

from __future__ import annotations

import logging
from typing import Callable

import click

from contentops.core.asset import Asset, COLLECT_BASELINE_VERSION
from contentops.core.handler import LoadedAsset
from contentops.core.result import ActionResult, PlanAction
from contentops.handlers._verify import (
    ETAG_CONFLICT_MESSAGE,
    compute_content_hash,
    hash_mismatch_error,
)
from contentops.handlers.sentinel_hunting_models import (
    HUNTING_CATEGORY,
    SentinelHuntingPayload,
    to_savedsearch_arm_body,
)
from contentops.providers.sentinel_arm import SentinelArmProvider

logger = logging.getLogger(__name__)

SAVED_SEARCHES = "savedSearches"

_SERVER_PROPERTY_FIELDS = ("etag", "provisioningState")
_SERVER_RESOURCE_FIELDS = ("etag", "type", "systemData")
# Aliases for the cross-handler ``_strip_server_fields`` API so the
# new ``sentinel-roundtrip-diff`` diagnostic dispatches uniformly
# across all 5 Sentinel handlers.
_SERVER_FIELDS = _SERVER_RESOURCE_FIELDS


def _strip_server_fields(remote: dict) -> dict:
    """Return ``remote`` with server-managed top-level + properties.* fields removed.

    Pure (defensive copy); never mutates the input. Used by the
    ``sentinel-roundtrip-diff`` diagnostic.
    """
    cleaned = {k: v for k, v in remote.items() if k not in _SERVER_FIELDS}
    block = cleaned.get("properties")
    if isinstance(block, dict):
        cleaned["properties"] = {
            k: v for k, v in block.items() if k not in _SERVER_PROPERTY_FIELDS
        }
    return cleaned


_HASHED_FIELDS = [
    "properties.displayName",
    "properties.query",
    "properties.category",
    "properties.tags",
]


class SentinelHuntingHandler:
    asset = Asset.SENTINEL_HUNTING

    def __init__(self, provider_factory: Callable[[], SentinelArmProvider | None]) -> None:
        self._provider_factory = provider_factory
        self._provider: SentinelArmProvider | None = None

    def _provider_or_create(self) -> SentinelArmProvider | None:
        if self._provider is None:
            self._provider = self._provider_factory()
        return self._provider

    def validate(self, loaded: LoadedAsset) -> None:
        SentinelHuntingPayload(**loaded.payload)

    def plan(self, loaded: LoadedAsset) -> ActionResult:
        if loaded.envelope.status == "experimental":
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.SKIP, status="planned",
                detail="experimental status — skipped",
            )
        # Hunting queries have no enable/disable concept on Sentinel side.
        # Deprecation removal is handled by a separate `prune` workflow.
        if loaded.envelope.status == "deprecated":
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.SKIP, status="planned",
                detail="deprecated hunting queries are not deleted by deploy; use `prune`",
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

        body = to_savedsearch_arm_body(loaded.payload)
        if dry_run:
            click.echo(f"  [DRY-RUN] Would PUT savedSearch: {loaded.envelope.id}")
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE, status="dry-run",
            )

        provider = self._provider_or_create()
        assert provider is not None
        url = provider.la_resource_url(SAVED_SEARCHES, loaded.envelope.id)

        # GET first to capture etag for optimistic concurrency.
        existing_resp = provider.request("GET", url)
        etag: str | None = None
        if existing_resp.status_code == 200:
            existing = existing_resp.json()
            etag = existing.get("etag") or (existing.get("properties") or {}).get("etag")

        sent_hash = compute_content_hash(body, _HASHED_FIELDS)
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
                "Failed to deploy hunting query %s: %s %s",
                loaded.envelope.id, response.status_code, response.text,
            )
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE, status=f"error-{response.status_code}",
                detail=response.text[:200],
                verified=False, error=response.text[:200],
            )

        action = PlanAction.CREATE if response.status_code == 201 else PlanAction.UPDATE
        click.echo(f"  {action.value}: {loaded.envelope.id}")

        # Read back and verify content hash.
        verify_resp = provider.request("GET", url)
        if verify_resp.status_code != 200:
            err = f"post-apply GET returned {verify_resp.status_code}"
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=action, status="success", detail=err,
                verified=False, error=err,
            )
        got_hash = compute_content_hash(verify_resp.json(), _HASHED_FIELDS)
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
        )

    def close(self) -> None:
        if self._provider is not None:
            self._provider.close()
            self._provider = None

    def delete(self, remote_id: str) -> ActionResult:
        """DELETE one hunting savedSearch by LA-workspace resource name."""
        from contentops.core.result import NotSupportedError
        from contentops.handlers._delete import (
            delete_result_from_exception, delete_result_from_response,
        )
        provider = self._provider_or_create()
        if provider is None:
            raise NotSupportedError("sentinel_hunting delete requires a SentinelArmProvider")
        url = provider.la_resource_url(SAVED_SEARCHES, remote_id)
        try:
            response = provider.request("DELETE", url)
        except Exception as exc:  # pragma: no cover
            return delete_result_from_exception(remote_id, self.asset, exc)
        return delete_result_from_response(remote_id, self.asset, response)

    # --- Drift support -------------------------------------------------

    def list_remote(self) -> list[dict]:
        provider = self._provider_or_create()
        if provider is None:
            return []
        url = provider.la_resource_url(SAVED_SEARCHES)
        response = provider.request("GET", url)
        response.raise_for_status()
        items = response.json().get("value", []) or []
        return [
            item for item in items
            if (item.get("properties") or {}).get("category") == HUNTING_CATEGORY
        ]

    def to_envelope(self, remote: dict) -> dict | None:
        rule_id = remote.get("name")
        if not rule_id:
            return None
        properties: dict = dict(remote.get("properties") or {})
        if properties.get("category") != HUNTING_CATEGORY:
            return None

        tags = properties.get("tags") or []
        description: str | None = None
        tactics: list[str] | None = None
        techniques: list[str] | None = None
        extra_tags: list[dict] = []
        for tag in tags:
            name = tag.get("name")
            value = tag.get("value", "")
            if name == "description":
                description = value
            elif name == "tactics":
                tactics = [t for t in value.split(",") if t]
            elif name == "techniques":
                techniques = [t for t in value.split(",") if t]
            else:
                extra_tags.append({"name": name, "value": value})

        payload: dict = {
            "displayName": properties.get("displayName", ""),
            "query": properties.get("query", ""),
            "category": HUNTING_CATEGORY,
        }
        if "version" in properties:
            payload["version"] = properties["version"]
        if properties.get("functionAlias"):
            payload["functionAlias"] = properties["functionAlias"]
        if properties.get("functionParameters"):
            payload["functionParameters"] = properties["functionParameters"]
        if description:
            payload["description"] = description
        if tactics:
            payload["tactics"] = tactics
        if techniques:
            payload["techniques"] = techniques
        if extra_tags:
            payload["tags"] = extra_tags

        return {
            "id": rule_id,
            "version": COLLECT_BASELINE_VERSION,
            "asset": Asset.SENTINEL_HUNTING.value,
            "status": "production",
            "metadata": {"arm_name": rule_id},
            "payload": payload,
        }
