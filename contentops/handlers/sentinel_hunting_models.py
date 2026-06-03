# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pydantic models for Sentinel hunting queries.

ARM resource type: Microsoft.OperationalInsights/workspaces/savedSearches
API version: 2023-09-01

A "hunting query" in Sentinel terms is a savedSearch with
`category == "Hunting Queries"`. The same resource family also stores
non-hunting queries (e.g. Log Analytics dashboards), so the category
discriminator is what makes Sentinel surface it under Hunting.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


HUNTING_CATEGORY = "Hunting Queries"


class SavedSearchTag(BaseModel):
    name: str = Field(min_length=1)
    value: str


class SentinelHuntingPayload(BaseModel):
    """Sentinel hunting query payload (LA savedSearch shape)."""

    displayName: str = Field(min_length=1, max_length=255)
    query: str = Field(min_length=1, description="KQL query body.")
    # Locked to the canonical Sentinel category so the asset shows up
    # under Hunting in the portal. Other categories are a different
    # asset class and should not be deployed via this handler.
    category: Literal["Hunting Queries"] = HUNTING_CATEGORY
    description: str | None = None
    tactics: list[str] | None = None
    techniques: list[str] | None = None
    version: int = Field(default=2, ge=1)
    functionAlias: str | None = None
    functionParameters: str | None = None
    tags: list[SavedSearchTag] | None = None


def _tags_for(payload: SentinelHuntingPayload) -> list[dict]:
    """Encode tactics/techniques/description as savedSearch tags.

    Sentinel surfaces these via well-known tag names. The user-supplied
    `tags` list is appended verbatim.
    """
    tags: list[dict] = []
    if payload.description:
        tags.append({"name": "description", "value": payload.description})
    if payload.tactics:
        tags.append({"name": "tactics", "value": ",".join(payload.tactics)})
    if payload.techniques:
        tags.append({"name": "techniques", "value": ",".join(payload.techniques)})
    if payload.tags:
        tags.extend([t.model_dump() for t in payload.tags])
    return tags


def to_savedsearch_arm_body(payload: dict) -> dict:
    """Convert validated payload dict into the ARM PUT body."""
    model = SentinelHuntingPayload(**payload)
    properties: dict = {
        "category": model.category,
        "displayName": model.displayName,
        "query": model.query,
        "version": model.version,
    }
    if model.functionAlias:
        properties["functionAlias"] = model.functionAlias
    if model.functionParameters:
        properties["functionParameters"] = model.functionParameters
    tags = _tags_for(model)
    if tags:
        properties["tags"] = tags
    return {"properties": properties}
