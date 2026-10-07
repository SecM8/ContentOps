# SPDX-FileCopyrightText: 2026 KustoKing / SecM8
# SPDX-License-Identifier: Apache-2.0

"""scripts/refresh_attack_matrix.py -- extraction from a synthetic STIX bundle.

Network-free: the generator's ``extract()`` is pure, so a hand-built bundle
pins the version, the revoked-by chain resolution and the deprecated list.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "refresh_attack_matrix", REPO_ROOT / "scripts" / "refresh_attack_matrix.py",
)
ram = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(ram)


def _technique(stix_id: str, tid: str, *, phase: str = "execution",
               sub: bool = False, **flags) -> dict:
    return {
        "type": "attack-pattern", "id": stix_id, "name": f"name {tid}",
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": phase}],
        "x_mitre_is_subtechnique": sub, **flags,
    }


def _revoked_by(src: str, dst: str, **flags) -> dict:
    return {"type": "relationship", "id": f"relationship--{src}-{dst}",
            "relationship_type": "revoked-by", "source_ref": src, "target_ref": dst,
            **flags}


def _bundle() -> dict:
    return {"objects": [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1",
         "name": "Enterprise ATT&CK", "x_mitre_version": "19.2"},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--1", "name": "Execution",
         "x_mitre_shortname": "execution"},
        {"type": "x-mitre-tactic", "id": "x-mitre-tactic--2", "name": "Stealth",
         "x_mitre_shortname": "stealth"},
        _technique("attack-pattern--cur1", "T1059"),
        _technique("attack-pattern--cur2", "T1685", phase="stealth"),
        _technique("attack-pattern--cur3", "T1547.011", sub=True),
        # Direct revocation.
        _technique("attack-pattern--old1", "T1562.001", phase="stealth", sub=True, revoked=True),
        _revoked_by("attack-pattern--old1", "attack-pattern--cur2"),
        # Chain: T1150 -> T1647 (itself revoked) -> T1547.011.
        _technique("attack-pattern--old2", "T1150", revoked=True),
        _technique("attack-pattern--mid2", "T1647", revoked=True),
        _revoked_by("attack-pattern--old2", "attack-pattern--mid2"),
        _revoked_by("attack-pattern--mid2", "attack-pattern--cur3"),
        # Cycle with no current end -> deprecated.
        _technique("attack-pattern--cyc1", "T1001", revoked=True),
        _technique("attack-pattern--cyc2", "T1002", revoked=True),
        _revoked_by("attack-pattern--cyc1", "attack-pattern--cyc2"),
        _revoked_by("attack-pattern--cyc2", "attack-pattern--cyc1"),
        # Deprecated outright; a revoked relationship is ignored.
        _technique("attack-pattern--dep", "T1043", x_mitre_deprecated=True),
        _revoked_by("attack-pattern--dep", "attack-pattern--cur1", revoked=True),
    ]}


def test_extract_records_version_and_tables() -> None:
    out = ram.extract(_bundle())
    assert out["schema_version"] == 3
    assert out["attack_version"] == "19.2"
    assert [t["id"] for t in out["techniques"]] == ["T1059", "T1685"]
    assert [t["id"] for t in out["sub_techniques"]] == ["T1547.011"]
    # Stealth keeps folding into the canonical DefenseEvasion tactic.
    assert out["techniques"][1]["tactics"] == ["DefenseEvasion"]
    assert {t["id"] for t in out["tactics"]} == {"Execution", "DefenseEvasion"}


def test_revocations_resolve_chains_to_current_ids() -> None:
    out = ram.extract(_bundle())
    assert out["revoked"] == {
        "T1150": "T1547.011",
        "T1562.001": "T1685",
        "T1647": "T1547.011",
    }
    assert out["deprecated"] == ["T1001", "T1002", "T1043"]


def test_extract_is_deterministic() -> None:
    assert ram.extract(_bundle()) == ram.extract(_bundle())
