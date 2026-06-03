# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Fetch + normalise the Sentinel Content Packages catalog (G3 watcher).

`contentPackages` is the ARM resource type that lists every Microsoft
Content Hub solution installed (or available, depending on the API
version) in the workspace. We normalise each entry to a small stable
shape so the manifest diff doesn't churn on unrelated server-side
fields.
"""

from __future__ import annotations

from typing import Any

from contentops.providers.sentinel_arm import SentinelArmProvider


def _normalise(entry: dict[str, Any]) -> dict[str, Any]:
    """Project a raw `contentPackages` entry into the stable manifest shape."""
    properties = entry.get("properties") or {}
    return {
        "name": str(entry.get("name") or "")[:512],
        "displayName": str(properties.get("displayName") or "")[:512],
        "version": str(properties.get("version") or "")[:64],
        "contentKind": str(properties.get("contentKind") or "")[:64],
        "source": str((properties.get("source") or {}).get("kind") or "")[:64],
        "lastPublishDate": str(properties.get("lastPublishDate") or ""),
    }


def fetch_packages(provider: SentinelArmProvider) -> list[dict[str, Any]]:
    """List every content package in the workspace and normalise it.

    Pagination is handled by ``provider.list_resource``; entries without
    a ``name`` are dropped (defensive against partial server responses).
    """
    raw = provider.list_resource("contentPackages")
    out: list[dict[str, Any]] = []
    for entry in raw:
        normalised = _normalise(entry)
        if normalised["name"]:
            out.append(normalised)
    return out


__all__ = ["fetch_packages"]
