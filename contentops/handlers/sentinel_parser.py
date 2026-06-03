# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Sentinel parser handler — savedSearches with category="Function".

ARM resource: ``Microsoft.OperationalInsights/workspaces/savedSearches``
API version:  ``2023-09-01``

A "parser" in Sentinel terms is a savedSearch whose ``category`` is
``"Function"`` — the same resource family that Hunting Queries
(category ``"Hunting Queries"``) live in. Parsers expose a reusable
KQL function under a ``functionAlias`` that other queries can call.

The handler is structurally identical to ``SentinelHuntingHandler``:
it builds an ARM body, ETag-protects the PUT, and content-hash
verifies the read-back. The category discriminator is what keeps
parsers and hunting queries from polluting each other's drift inventory.
"""

from __future__ import annotations

import logging
from typing import Callable, Literal

import click
from pydantic import BaseModel, Field

from contentops.core.asset import Asset, COLLECT_BASELINE_VERSION
from contentops.core.handler import LoadedAsset
from contentops.core.result import ActionResult, PlanAction
from contentops.handlers._verify import (
    ETAG_CONFLICT_MESSAGE,
    compute_content_hash,
    hash_mismatch_error,
)
from contentops.providers.sentinel_arm import SentinelArmProvider

logger = logging.getLogger(__name__)

PARSER_CATEGORY = "Function"
SAVED_SEARCHES = "savedSearches"

_HASHED_FIELDS = [
    "properties.displayName",
    "properties.query",
    "properties.category",
    "properties.functionAlias",
    "properties.functionParameters",
    "properties.tags",
]

# Server-managed fields stripped before round-trip diff so the
# diagnostic shows the same canonical view ``apply`` would hash.
# Parser is a savedSearch under the hood, same shape as hunting.
_SERVER_FIELDS = ("etag", "type", "systemData")
_SERVER_PROPERTY_FIELDS: dict[str, frozenset[str]] = {
    "properties": frozenset({"etag", "version", "provisioningState"}),
}


def _strip_server_fields(remote: dict) -> dict:
    """Return ``remote`` with server-managed fields removed (defensive copy)."""
    cleaned = {k: v for k, v in remote.items() if k not in _SERVER_FIELDS}
    for parent, nested in _SERVER_PROPERTY_FIELDS.items():
        block = cleaned.get(parent)
        if isinstance(block, dict):
            cleaned[parent] = {k: v for k, v in block.items() if k not in nested}
    return cleaned


class SavedSearchTag(BaseModel):
    name: str = Field(min_length=1)
    value: str


class SentinelParserPayload(BaseModel):
    """KQL parser/function modelled as a Function-category savedSearch."""

    displayName: str = Field(min_length=1, max_length=255)
    query: str = Field(min_length=1, description="KQL function body.")
    category: Literal["Function"] = PARSER_CATEGORY
    functionAlias: str = Field(
        min_length=1,
        description="Identifier other queries call this function by.",
    )
    functionParameters: str | None = None
    description: str | None = None
    version: int = Field(default=2, ge=1)
    tags: list[SavedSearchTag] | None = None


def _tags_for(payload: SentinelParserPayload) -> list[dict]:
    tags: list[dict] = []
    if payload.description:
        tags.append({"name": "description", "value": payload.description})
    if payload.tags:
        tags.extend(t.model_dump() for t in payload.tags)
    return tags


def to_parser_arm_body(payload: dict) -> dict:
    model = SentinelParserPayload(**payload)
    properties: dict = {
        "category": model.category,
        "displayName": model.displayName,
        "query": model.query,
        "version": model.version,
        "functionAlias": model.functionAlias,
    }
    if model.functionParameters:
        properties["functionParameters"] = model.functionParameters
    tags = _tags_for(model)
    if tags:
        properties["tags"] = tags
    return {"properties": properties}


class SentinelParserHandler:
    asset = Asset.SENTINEL_PARSER

    def __init__(self, provider_factory: Callable[[], SentinelArmProvider | None]) -> None:
        self._provider_factory = provider_factory
        self._provider: SentinelArmProvider | None = None

    def _provider_or_create(self) -> SentinelArmProvider | None:
        if self._provider is None:
            self._provider = self._provider_factory()
        return self._provider

    def validate(self, loaded: LoadedAsset) -> None:
        SentinelParserPayload(**loaded.payload)

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
                detail="deprecated parsers are not deleted by deploy; use `prune`",
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

        body = to_parser_arm_body(loaded.payload)
        if dry_run:
            click.echo(f"  [DRY-RUN] Would PUT parser: {loaded.envelope.id}")
            return ActionResult(
                asset_id=loaded.envelope.id, asset_kind=self.asset.value,
                action=PlanAction.UPDATE, status="dry-run",
            )

        provider = self._provider_or_create()
        assert provider is not None
        url = provider.la_resource_url(SAVED_SEARCHES, loaded.envelope.id)

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
                "Failed to deploy parser %s: %s %s",
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
        """DELETE one parser savedSearch by LA-workspace resource name."""
        from contentops.core.result import NotSupportedError
        from contentops.handlers._delete import (
            delete_result_from_exception, delete_result_from_response,
        )
        provider = self._provider_or_create()
        if provider is None:
            raise NotSupportedError("sentinel_parser delete requires a SentinelArmProvider")
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
            if (item.get("properties") or {}).get("category") == PARSER_CATEGORY
        ]

    def to_envelope(self, remote: dict) -> dict | None:
        rule_id = remote.get("name")
        if not rule_id:
            return None
        properties: dict = dict(remote.get("properties") or {})
        if properties.get("category") != PARSER_CATEGORY:
            return None

        tags = properties.get("tags") or []
        description: str | None = None
        extra_tags: list[dict] = []
        for tag in tags:
            name = tag.get("name")
            value = tag.get("value", "")
            if name == "description":
                description = value
            else:
                extra_tags.append({"name": name, "value": value})

        payload: dict = {
            "displayName": properties.get("displayName", ""),
            "query": properties.get("query", ""),
            "category": PARSER_CATEGORY,
            "functionAlias": properties.get("functionAlias") or rule_id,
        }
        if "version" in properties:
            payload["version"] = properties["version"]
        if properties.get("functionParameters"):
            payload["functionParameters"] = properties["functionParameters"]
        if description:
            payload["description"] = description
        if extra_tags:
            payload["tags"] = extra_tags

        return {
            "id": rule_id,
            "version": COLLECT_BASELINE_VERSION,
            "asset": Asset.SENTINEL_PARSER.value,
            "status": "production",
            "payload": payload,
        }
