# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Fetch + normalise the Sentinel Alert Rule Templates catalog (G4 watcher).

Reuses the ARM provider that ``contentops.devex.templates_remote`` already
uses for ``contentops new --search-template``; the difference here is
that the watcher always pulls the *full* catalog (paginated) and reduces
each entry to a small stable shape suitable for diffing.
"""

from __future__ import annotations

from typing import Any

from contentops.providers.sentinel_arm import SentinelArmProvider


def _normalise(entry: dict[str, Any]) -> dict[str, Any]:
    """Project a raw `alertRuleTemplates` entry into the stable manifest shape."""
    properties = entry.get("properties") or {}
    return {
        "name": str(entry.get("name") or "")[:512],
        "displayName": str(properties.get("displayName") or "")[:512],
        "kind": str(entry.get("kind") or "")[:64],
        "version": str(properties.get("version") or "")[:64],
        "lastUpdatedDateTime": str(properties.get("lastUpdatedDateTime") or ""),
        "source": str((properties.get("source") or {}).get("kind") or "")[:64],
    }


def fetch_templates(provider: SentinelArmProvider) -> list[dict[str, Any]]:
    """List every alert rule template and normalise it.

    Pagination is handled by ``provider.list_resource``; entries without
    a ``name`` are dropped (defensive against partial server responses).
    """
    raw = provider.list_resource("alertRuleTemplates")
    out: list[dict[str, Any]] = []
    for entry in raw:
        normalised = _normalise(entry)
        if normalised["name"]:
            out.append(normalised)
    return out


__all__ = ["fetch_templates"]
