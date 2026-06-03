# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Pure renderer for the MITRE Navigator layer JSON.

Deterministic: same input -> byte-identical output. The Navigator UI
(https://mitre-attack.github.io/attack-navigator/) expects the schema
captured here -- field names must stay verbatim or the UI silently
ignores the layer.
"""

from __future__ import annotations

from typing import Any

from contentops.navigator.extract import ScoredTechnique

# Pinned to a known-good combination. The Navigator UI is permissive
# about minor version drift; we surface these constants so callers
# can override per-PR without touching this module.
ATTACK_VERSION = "14"
NAVIGATOR_LAYER_VERSION = "4.5"
NAVIGATOR_TOOL_VERSION = "4.9.1"
DOMAIN = "enterprise-attack"

_DEFAULT_GRADIENT = [
    "#FFD6AB",
    "#FBB983",
    "#F99B5B",
    "#F77D33",
    "#F69325",
]


def render_layer(
    techniques: list[ScoredTechnique],
    *,
    name: str = "Microsoft Security Coverage",
    description: str = "MITRE ATT&CK coverage rendered by `contentops navigator`.",
    attack_version: str = ATTACK_VERSION,
    layer_version: str = NAVIGATOR_LAYER_VERSION,
    tool_version: str = NAVIGATOR_TOOL_VERSION,
) -> dict[str, Any]:
    """Build the Navigator layer dict.

    Output shape mirrors the operator's original script template
    (Microsoft2ATT&CK) so anyone already familiar with that layer in
    the Navigator UI sees the same tile rendering here.

    The ``maxValue`` of the gradient floats to the actual top score
    so a small detection corpus doesn't render every tile dark; a
    minimum of 5 keeps the gradient meaningful for empty / tiny
    inputs.
    """
    max_score = max((t.score for t in techniques), default=0)
    return {
        "name": name,
        "versions": {
            "attack": attack_version,
            "layer": layer_version,
            "navigator": tool_version,
        },
        "description": description,
        "domain": DOMAIN,
        "sorting": 0,
        "layout": {
            "layout": "side",
            "showName": True,
            "showID": True,
            "showAggregateScores": True,
            "aggregateFunction": "sum",
            "expandedSubtechniques": "all",
        },
        "techniques": [
            {
                "techniqueID": t.technique_id,
                "score": t.score,
                "enabled": True,
                "showSubtechniques": True,
                "metadata": [
                    {"name": "repo_count", "value": str(t.repo_count)},
                    {"name": "deployed_count", "value": str(t.deployed_count)},
                    {"name": "firings_count", "value": str(t.firings_count)},
                ],
                "comment": (
                    f"{len(t.contributing_rules)} rule(s)"
                    if t.contributing_rules else ""
                ),
            }
            for t in techniques
        ],
        "gradient": {
            "colors": list(_DEFAULT_GRADIENT),
            "minValue": 0,
            "maxValue": max(max_score, 5),
        },
        "legendItems": [
            {
                "label": "Distinct rules per technique",
                "color": _DEFAULT_GRADIENT[-1],
            }
        ],
        "selectSubtechniquesWithParent": True,
    }


__all__ = [
    "ATTACK_VERSION",
    "DOMAIN",
    "NAVIGATOR_LAYER_VERSION",
    "NAVIGATOR_TOOL_VERSION",
    "render_layer",
]
