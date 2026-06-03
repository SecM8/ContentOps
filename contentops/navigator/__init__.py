# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""MITRE ATT&CK Navigator layer generator.

Produces a Navigator-compatible JSON file
(https://mitre-attack.github.io/attack-navigator/) that an operator
can open in the hosted Navigator UI to visualise MITRE coverage.

Three data axes, each independently selectable on the command line:

* **Repo** -- ``metadata.techniques`` on every envelope under
  ``detections/``. The "claimed coverage" view.
* **Deployed** -- techniques on every Sentinel analytic rule (ARM)
  + Defender custom detection (Graph beta). The "deployed surface"
  view.
* **Firings** -- ``SecurityAlert.Techniques`` over the last N days.
  The "what actually fires" view, sourced from the same workspace
  KQL helper that powers ``silent-rules`` (no extra permissions
  required when the M365 Defender connector is installed in the
  Sentinel workspace).

Scoring per technique is the count of *unique rule display names*
contributing across the selected axes. Parent techniques without a
direct match still appear at score 0 when any sub-technique is
covered, so the Navigator UI renders the parent tile.

SVG export is intentionally NOT shipped -- the hosted Navigator UI
renders the JSON for free, and ``mitreattack-python`` would balloon
the runtime dependency surface.
"""

from __future__ import annotations

from contentops.navigator.extract import (
    TechniqueHit,
    extract_defender_rule_techniques,
    extract_firing_techniques,
    extract_repo_techniques,
    extract_sentinel_rule_techniques,
    score_techniques,
)
from contentops.navigator.render import (
    NAVIGATOR_LAYER_VERSION,
    ATTACK_VERSION,
    render_layer,
)

__all__ = [
    "ATTACK_VERSION",
    "NAVIGATOR_LAYER_VERSION",
    "TechniqueHit",
    "extract_defender_rule_techniques",
    "extract_firing_techniques",
    "extract_repo_techniques",
    "extract_sentinel_rule_techniques",
    "render_layer",
    "score_techniques",
]
