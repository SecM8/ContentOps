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

from contentops.coverage.matrix import load_matrix
from contentops.navigator.extract import ScoredTechnique

# Used only when the bundled matrix predates the recorded release.
_FALLBACK_ATTACK_VERSION = "14"


def default_attack_version() -> str:
    """Major ATT&CK release of the bundled matrix (e.g. ``"19"``).

    The layer must name the release its technique ids come from: the
    matrix is refreshed weekly, and ids revoked since an older release
    (T1562.x -> T1685 in v19) would otherwise point at the wrong tiles.
    """
    return load_matrix().attack_major or _FALLBACK_ATTACK_VERSION


# Layer/Navigator schema versions are pinned to a known-good combination;
# the ATT&CK version follows the bundled matrix.
ATTACK_VERSION = default_attack_version()
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
    attack_version: str | None = None,
    layer_version: str = NAVIGATOR_LAYER_VERSION,
    tool_version: str = NAVIGATOR_TOOL_VERSION,
    metadata: list[tuple[str, str]] | None = None,
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
    layer: dict[str, Any] = {
        "name": name,
        "versions": {
            "attack": attack_version or default_attack_version(),
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
    if metadata:
        # Layer-level metadata (Navigator 4.x): shown in the layer's
        # information panel, e.g. which detections the repo axis counted.
        layer["metadata"] = [{"name": k, "value": v} for k, v in metadata]
    return layer


__all__ = [
    "ATTACK_VERSION",
    "DOMAIN",
    "default_attack_version",
    "NAVIGATOR_LAYER_VERSION",
    "NAVIGATOR_TOOL_VERSION",
    "render_layer",
]
