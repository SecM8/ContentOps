# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""Guards on the committed MITRE ATT&CK matrix data file.

The full matrix (``contentops/coverage/data/mitre_attack_full.json``) is
refreshed weekly from MITRE by ``attack-matrix-refresh.yml`` and read at
runtime by ``coverage.extract`` (heatmap + badge) and ``coverage.gaps``.

MITRE's upstream STIX surfaces "Defense Evasion" under non-Sentinel
short-names (``stealth`` / ``defense-impairment``); the refresh generator
normalises them back to the canonical ``DefenseEvasion`` that every
deployed detection and the ARM ``alertRules`` enum use. These tests are
the load-bearing guard: if the committed file ever drifts off the
canonical tactic set again (the way it had before 2026-06-01), CI fails
here rather than the heatmap/badge silently under-counting a whole tactic.
"""

from __future__ import annotations

import json
from importlib import resources

from contentops.coverage.extract import _CANONICAL_TACTICS, _technique_to_tactics
from contentops.coverage.report import ALL_TACTICS


def _load_full_matrix() -> dict:
    path = resources.files("contentops.coverage.data") / "mitre_attack_full.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _referenced_tactics(doc: dict) -> set[str]:
    out: set[str] = set()
    for key in ("techniques", "sub_techniques"):
        for t in doc.get(key) or []:
            out.update(t.get("tactics") or [])
    return out


def test_full_matrix_tactics_are_canonical() -> None:
    referenced = _referenced_tactics(_load_full_matrix())
    off_all = referenced - set(ALL_TACTICS)
    assert not off_all, f"tactics not in report.ALL_TACTICS: {sorted(off_all)}"
    off_extract = referenced - set(_CANONICAL_TACTICS)
    assert not off_extract, (
        f"tactics not in extract._CANONICAL_TACTICS: {sorted(off_extract)}"
    )
    # The specific historic defect must never come back.
    assert "Stealth" not in referenced
    assert "DefenseImpairment" not in referenced


def test_full_matrix_has_defense_evasion() -> None:
    assert "DefenseEvasion" in _referenced_tactics(_load_full_matrix())


def test_full_matrix_tactics_table_is_canonical_fourteen() -> None:
    ids = [t["id"] for t in _load_full_matrix()["tactics"]]
    assert "DefenseEvasion" in ids
    assert set(ids) <= set(ALL_TACTICS)
    assert len(ids) == len(set(ids)) == 14  # the canonical Enterprise tactics


def test_full_matrix_counts_are_full_enterprise() -> None:
    doc = _load_full_matrix()
    assert len(doc["techniques"]) >= 200   # parents
    assert len(doc["sub_techniques"]) >= 400  # sub-techniques


def test_defense_evasion_technique_resolves_at_runtime() -> None:
    """Regression for the live heatmap/badge under-count: a parent
    technique MITRE files under defense-evasion must resolve to
    ``DefenseEvasion`` via the runtime lookup ``extract`` uses."""
    doc = _load_full_matrix()
    tid = next(
        t["id"] for t in doc["techniques"]
        if "DefenseEvasion" in (t.get("tactics") or [])
    )
    lookup = _technique_to_tactics()
    assert "DefenseEvasion" in lookup.get(tid, ())
